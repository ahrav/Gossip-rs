//! Runtime durability integration tests for translation, commit, and
//! receipt-driven checkpoint aggregation.
//!
//! Covered invariant families:
//! 1. Ordered-content writes advance checkpoint progress only after a durable
//!    receipt is explicitly recorded.
//! 2. Clean scans and pipeline-drain boundaries preserve the same
//!    receipt-before-checkpoint rule as finding-producing scans.
//! 3. Crash and replay paths stay idempotent across findings, done-ledger, and
//!    stale-fence recovery windows.
//! 4. Repo-frontier durable receipts use repo-key-authoritative cursors and do
//!    not let partial finalize outcomes fabricate outer progress.

use std::{
    convert::Infallible,
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::Duration,
};

use gossip_contracts::{
    connector::{Cursor, git::RepoKey},
    identity::LogicalTime,
    persistence::{
        CheckpointCommitReceipt, CommitAdvanceError, DoneLedgerCommitReceipt, DoneLedgerStatus,
        FindingsCommitReceipt,
    },
};
use gossip_persistence_inmemory::{
    CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
    InMemoryStoreKind,
};
use scanner_git::FinalizeOutcome;

use crate::{
    CancellationToken,
    checkpoint_aggregator::{
        PrefixCheckpointAggregator, PrefixCheckpointError, ReceiptRecordOutcome,
    },
    commit_model::CheckpointAggregatorInput,
    commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput, QueuedCommit},
    git_persistence::{GitPersistenceAdapter, GitPersistenceBackend, GitPersistenceOp},
    result_committer::{ResultCommitError, ResultCommitter},
    test_fixtures::{
        clean_scanned_translation, completed_unit, item_key, scanned_translation, wait_until,
        write_context_with_epoch,
    },
};

fn assert_sink_counts(sink: &InMemoryFindingsSink, expected: usize) {
    assert_eq!(sink.findings_snapshot().expect("snapshot").len(), expected);
    assert_eq!(
        sink.occurrences_snapshot().expect("snapshot").len(),
        expected
    );
    assert_eq!(
        sink.observations_snapshot().expect("snapshot").len(),
        expected
    );
}

fn assert_single_done_row(
    done_ledger: &InMemoryDoneLedger,
    expected_status: DoneLedgerStatus,
    expected_findings_count: u32,
) {
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "done-ledger should contain exactly one row");
    let row = rows
        .into_iter()
        .next()
        .expect("exactly one done-ledger record");
    assert_eq!(row.status(), expected_status);
    assert_eq!(row.findings_count(), expected_findings_count);
}

#[derive(Clone, Copy, Debug, Default)]
struct NoopGitBackend;

impl GitPersistenceBackend for NoopGitBackend {
    type Error = Infallible;

    fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(None)
    }

    fn apply_batch(&self, _ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Claims atomicity so the adapter takes the single-phase commit path,
    /// keeping the test focused on the receipt/checkpoint aggregation layer.
    fn supports_atomic_batches(&self) -> bool {
        true
    }
}

fn repo_frontier_adapter() -> GitPersistenceAdapter<NoopGitBackend> {
    GitPersistenceAdapter::new(NoopGitBackend, 17, [0xA7; 32])
}

fn repo_frontier_key() -> RepoKey {
    RepoKey::for_local_path(b"/var/lib/gossip/repos/acme/repo.git").expect("repo key")
}

#[test]
fn no_checkpoint_without_receipt_even_when_done_ledger_is_durable() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(100);
    let unit = completed_unit(0, 0x41);
    let translation = scanned_translation(context, 0x41, 1);

    let receipt = committer
        .commit_translation(context, &unit, &translation)
        .expect("durable commit should succeed");

    // Preconditions: both stores are durable.
    assert_sink_counts(&findings_sink, 2);
    assert_single_done_row(&done_ledger, DoneLedgerStatus::ScannedWithFindings, 2);

    // Negative path: without recording the receipt, no checkpoint.
    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no(), 4);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no checkpoint can be prepared until a durable receipt is explicitly recorded"
    );
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert_eq!(aggregator.buffered_receipt_count(), 0);

    // Positive control: recording the receipt enables checkpoint progress.
    let input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one recorded receipt should yield one checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 0);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x41)),
        "checkpoint cursor must point to the committed item key"
    );

    let checkpoint_scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9_001),
        ))
        .expect("acknowledging the receipt-gated checkpoint should succeed");
    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no pending receipts should remain after acknowledging the single-unit checkpoint"
    );
}

#[test]
fn clean_scan_with_zero_findings_is_receipt_gated_normally() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(500);
    let unit = completed_unit(0, 0x81);
    let translation = clean_scanned_translation(context, 0x81, 1);

    let receipt = committer
        .commit_translation(context, &unit, &translation)
        .expect("clean-scan durable commit should succeed");

    // Preconditions: findings sink is empty, done-ledger has one clean row.
    assert_sink_counts(&findings_sink, 0);
    assert_single_done_row(&done_ledger, DoneLedgerStatus::ScannedClean, 0);

    // Receipt reflects the zero-findings commit.
    assert_eq!(receipt.completed_unit().sequence_no(), 0);
    assert_eq!(receipt.durable().scope().committed_units().get(), 1);
    assert_eq!(receipt.durable().findings().finding_count(), 0);
    assert_eq!(receipt.durable().findings().occurrence_count(), 0);
    assert_eq!(receipt.durable().findings().observation_count(), 0);
    assert_eq!(receipt.durable().done_ledger().record_count(), 1);
    assert_eq!(receipt.durable().done_ledger().findings_count(), 0);

    // Verify receipt-gating invariant holds for zero-findings commits.
    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no(), 4);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "zero-findings commit must still require an explicit receipt for checkpoint progress"
    );
    assert_eq!(aggregator.buffered_receipt_count(), 0);

    // Aggregator accepts the receipt and produces a checkpoint.
    let input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("clean-scan receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one committed receipt should yield one checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 0);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x81)),
        "checkpoint cursor must point to the clean-scan item key"
    );

    let checkpoint_scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9_501),
        ))
        .expect("acknowledging the clean-scan checkpoint should succeed");
    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no pending receipts should remain after acknowledging the clean-scan checkpoint"
    );
}

#[test]
fn repo_frontier_complete_finalize_is_receipt_gated_and_uses_repo_key_cursor() {
    let context = write_context_with_epoch(550);
    let repo_key = repo_frontier_key();
    let adapter = repo_frontier_adapter();
    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 4);

    // If outer progress ever keys off "scan returned Ok" instead of the
    // durable repo receipt, this would incorrectly fabricate a checkpoint.
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "repo-frontier progress must remain receipt-gated until finalize is durably recorded"
    );

    let input = adapter
        .repo_frontier_checkpoint_input(
            context,
            0,
            &repo_key,
            FinalizeOutcome::Complete,
            FindingsCommitReceipt::new(0, 0, 0),
            DoneLedgerCommitReceipt::new(1, 1, 0),
        )
        .expect("complete finalize should build checkpoint input")
        .expect("complete finalize should yield checkpoint input");

    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("repo-frontier receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one repo-frontier receipt should yield one checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 0);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(repo_key.clone().into_item_key()),
        "repo-frontier checkpoint cursor must stay authoritative to the durable repo key"
    );

    let checkpoint_scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9_551),
        ))
        .expect("acknowledging the repo-frontier checkpoint should succeed");
    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
}

#[test]
fn repo_frontier_partial_finalize_produces_no_receipt_or_checkpoint_input() {
    let context = write_context_with_epoch(551);
    let repo_key = repo_frontier_key();
    let adapter = repo_frontier_adapter();
    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 4);

    // Partial finalize keeps watermark progress non-authoritative, so the outer
    // repo frontier must not observe any checkpointable receipt at all.
    assert!(
        adapter
            .repo_frontier_receipt(
                context,
                0,
                &repo_key,
                FinalizeOutcome::Partial { skipped_count: 2 },
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            )
            .expect("partial finalize receipt construction should succeed")
            .is_none(),
        "partial finalize must not synthesize a durable repo-frontier receipt"
    );
    assert!(
        adapter
            .repo_frontier_checkpoint_input(
                context,
                0,
                &repo_key,
                FinalizeOutcome::Partial { skipped_count: 2 },
                FindingsCommitReceipt::new(0, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            )
            .expect("partial checkpoint-input construction should succeed")
            .is_none(),
        "partial finalize must not manufacture outer checkpoint progress"
    );

    // Aggregator state must be unperturbed by the partial finalize path.
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert_eq!(aggregator.next_sequence_no(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "aggregator must have no checkpointable prefix after partial finalize"
    );
}

#[test]
fn repo_frontier_replay_receipt_is_deterministic_and_buffers_once() {
    let context = write_context_with_epoch(552);
    let repo_key = repo_frontier_key();
    let adapter = repo_frontier_adapter();
    let mut aggregator = PrefixCheckpointAggregator::new(context, 3, 4);

    let first = adapter
        .repo_frontier_receipt(
            context,
            3,
            &repo_key,
            FinalizeOutcome::Complete,
            FindingsCommitReceipt::new(0, 0, 0),
            DoneLedgerCommitReceipt::new(1, 1, 0),
        )
        .expect("first receipt construction should succeed")
        .expect("complete finalize should yield a receipt");
    let replay = adapter
        .repo_frontier_receipt(
            context,
            3,
            &repo_key,
            FinalizeOutcome::Complete,
            FindingsCommitReceipt::new(0, 0, 0),
            DoneLedgerCommitReceipt::new(1, 1, 0),
        )
        .expect("replay receipt construction should succeed")
        .expect("replay should converge to the same durable receipt");
    assert_eq!(
        first, replay,
        "replaying the same repo-frontier finalize must converge to the same durable receipt"
    );

    let first_input =
        CheckpointAggregatorInput::new(first.completed_unit().checkpoint_boundary_kind(), first)
            .expect("repo-frontier receipt kind should match the stream");
    assert_eq!(
        aggregator
            .record_receipt(first_input)
            .expect("first repo-frontier receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    // If replay ever changed receipt identity, this second record would either
    // buffer twice or advance to a different cursor instead of collapsing.
    let replay_input =
        CheckpointAggregatorInput::new(replay.completed_unit().checkpoint_boundary_kind(), replay)
            .expect("replayed repo-frontier receipt kind should still match the stream");
    assert_eq!(
        aggregator
            .record_receipt(replay_input)
            .expect("replayed repo-frontier receipt should be accepted"),
        ReceiptRecordOutcome::DuplicateBuffered
    );
    assert_eq!(
        aggregator.buffered_receipt_count(),
        1,
        "replayed repo-frontier receipts must not inflate the checkpoint buffer"
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one unique repo-frontier receipt should remain checkpointable");
    assert_eq!(pending.first_sequence_no(), 3);
    assert_eq!(pending.last_sequence_no(), 3);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(repo_key.into_item_key()),
        "replayed repo-frontier receipts must preserve the authoritative repo-key cursor"
    );
}

#[test]
fn real_receipts_only_advance_the_contiguous_prefix() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(300);
    let unit_zero = completed_unit(0, 0x61);
    let unit_one = completed_unit(1, 0x62);
    let translation_zero = scanned_translation(context, 0x61, 1);
    let translation_one = scanned_translation(context, 0x62, 2);

    let receipt_one = committer
        .commit_translation(context, &unit_one, &translation_one)
        .expect("sequence 1 should commit");
    let receipt_zero = committer
        .commit_translation(context, &unit_zero, &translation_zero)
        .expect("sequence 0 should commit");

    // Both commits wrote durable data: 2 findings per item, 1 done-ledger row per item.
    assert_sink_counts(&findings_sink, 4);
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        2,
        "each committed item should produce one done-ledger row"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(context, unit_zero.sequence_no(), 4);
    let receipt_one_input =
        CheckpointAggregatorInput::new(unit_one.checkpoint_boundary_kind(), receipt_one)
            .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(receipt_one_input)
            .expect("out-of-order receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "sequence 1 alone must not advance the committed prefix"
    );
    assert_eq!(aggregator.next_sequence_no(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert_eq!(
        aggregator.buffered_receipt_count(),
        1,
        "out-of-order receipt must be buffered, not silently dropped"
    );

    let receipt_zero_input =
        CheckpointAggregatorInput::new(unit_zero.checkpoint_boundary_kind(), receipt_zero)
            .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(receipt_zero_input)
            .expect("gap-closing receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("contiguous prefix should now exist");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 1);
    assert_eq!(pending.committed_units(), 2);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x62)),
        "checkpoint cursor must reflect the last item in the contiguous prefix"
    );

    let checkpoint_scope = pending.scope().clone();

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9_101),
        ))
        .expect("durable checkpoint receipt should advance the full prefix");

    assert_eq!(aggregator.next_sequence_no(), 2);
    assert_eq!(aggregator.checkpointed_units(), 2);
    assert_eq!(
        aggregator.buffered_receipt_count(),
        0,
        "buffer must drain after acknowledging the full prefix"
    );
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed after acknowledgement")
            .is_none(),
        "no pending receipts should remain after acknowledging the full prefix"
    );
}

#[test]
fn pending_prefix_does_not_widen_until_the_previous_checkpoint_is_acked() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(550);
    let unit_zero = completed_unit(0, 0x81);
    let unit_one = completed_unit(1, 0x82);
    let unit_two = completed_unit(2, 0x83);
    let translation_zero = scanned_translation(context, 0x81, 1);
    let translation_one = scanned_translation(context, 0x82, 2);
    let translation_two = scanned_translation(context, 0x83, 3);

    let receipt_one = committer
        .commit_translation(context, &unit_one, &translation_one)
        .expect("sequence 1 should commit");
    let receipt_zero = committer
        .commit_translation(context, &unit_zero, &translation_zero)
        .expect("sequence 0 should commit");
    let receipt_two = committer
        .commit_translation(context, &unit_two, &translation_two)
        .expect("sequence 2 should commit");

    assert_sink_counts(&findings_sink, 6);
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        3,
        "each committed item should produce one done-ledger row"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 4);
    let receipt_one_input =
        CheckpointAggregatorInput::new(unit_one.checkpoint_boundary_kind(), receipt_one)
            .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(receipt_one_input)
            .expect("out-of-order receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    // Seq 1 is buffered but seq 0 is still missing — no contiguous prefix yet.
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "seq 1 alone must not produce a checkpointable prefix"
    );
    assert_eq!(aggregator.next_sequence_no(), 0);
    assert_eq!(aggregator.buffered_receipt_count(), 1);

    let receipt_zero_input =
        CheckpointAggregatorInput::new(unit_zero.checkpoint_boundary_kind(), receipt_zero)
            .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(receipt_zero_input)
            .expect("gap-closing receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let first_scope = {
        let first_pending = aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .expect("contiguous prefix should exist");
        assert_eq!(first_pending.first_sequence_no(), 0);
        assert_eq!(first_pending.last_sequence_no(), 1);
        assert_eq!(first_pending.committed_units(), 2);
        assert_eq!(
            first_pending.checkpoint_cursor(),
            &Cursor::with_last_key(item_key(0x82)),
            "checkpoint cursor must reflect the end of the prepared prefix"
        );
        first_pending.scope().clone()
    };

    let receipt_two_input =
        CheckpointAggregatorInput::new(unit_two.checkpoint_boundary_kind(), receipt_two)
            .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(receipt_two_input)
            .expect("later receipt should buffer behind the pending prefix"),
        ReceiptRecordOutcome::Buffered
    );

    let still_pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("pending prefix should remain prepared");
    assert_eq!(still_pending.first_sequence_no(), 0);
    assert_eq!(still_pending.last_sequence_no(), 1);
    assert_eq!(still_pending.committed_units(), 2);
    assert_eq!(
        still_pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x82)),
        "pending prefix must stay frozen until acknowledgement"
    );
    assert_eq!(
        aggregator.next_sequence_no(),
        0,
        "prepare_checkpoint must not advance the committed position"
    );
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert_eq!(aggregator.buffered_receipt_count(), 3);

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            first_scope,
            LogicalTime::from_raw(9_301),
        ))
        .expect("durable checkpoint receipt should advance the first prefix");

    let second_scope = {
        let second_pending = aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .expect("the buffered tail receipt should now become checkpointable");
        assert_eq!(second_pending.first_sequence_no(), 2);
        assert_eq!(second_pending.last_sequence_no(), 2);
        assert_eq!(second_pending.committed_units(), 1);
        assert_eq!(
            second_pending.checkpoint_cursor(),
            &Cursor::with_last_key(item_key(0x83)),
            "checkpoint cursor must advance to the buffered tail receipt after acknowledgement"
        );
        second_pending.scope().clone()
    };

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            second_scope,
            LogicalTime::from_raw(9_302),
        ))
        .expect("durable checkpoint receipt should advance the remaining tail receipt");

    assert_eq!(aggregator.next_sequence_no(), 3);
    assert_eq!(aggregator.checkpointed_units(), 3);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no receipts remain; the aggregator should be fully drained"
    );
}

#[test]
fn slow_sink_causes_backpressure_in_bounded_pipeline() {
    let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
    let done_ledger = InMemoryDoneLedger::new();
    let cancel = CancellationToken::new();
    let pipeline = CommitPipeline::start(
        findings_sink.clone(),
        done_ledger.clone(),
        CommitPipelineConfig {
            execution_queue_capacity: 1,
            outcome_queue_capacity: 4,
        },
        cancel,
    )
    .expect("pipeline should start");

    let sender = pipeline.sender();
    let (ack_tx, ack_rx) = mpsc::channel();
    let (entering_third_tx, entering_third_rx) = mpsc::channel::<()>();
    let context = write_context_with_epoch(600);
    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 8);

    let mut producer = Some(thread::spawn(move || {
        sender
            .submit(QueuedCommit::new(
                context,
                completed_unit(0, 0x81),
                scanned_translation(context, 0x81, 11),
            ))
            .expect("first submit should succeed");
        ack_tx.send(1u8).expect("first ack");

        sender
            .submit(QueuedCommit::new(
                context,
                completed_unit(1, 0x82),
                scanned_translation(context, 0x82, 12),
            ))
            .expect("second submit should succeed");
        ack_tx.send(2u8).expect("second ack");

        entering_third_tx
            .send(())
            .expect("rendezvous: producer reached third submit");
        sender
            .submit(QueuedCommit::new(
                context,
                completed_unit(2, 0x83),
                scanned_translation(context, 0x83, 13),
            ))
            .expect("third submit should succeed once backpressure clears");
        ack_tx.send(3u8).expect("third ack");
    }));

    /// Receives an ack from the producer, surfacing the producer's panic on
    /// channel disconnect instead of reporting a confusing `Disconnected` error.
    fn recv_ack(
        rx: &mpsc::Receiver<u8>,
        producer: &mut Option<thread::JoinHandle<()>>,
        expected: u8,
        timeout: Duration,
    ) {
        match rx.recv_timeout(timeout) {
            Ok(val) => assert_eq!(val, expected, "ack value mismatch"),
            Err(RecvTimeoutError::Disconnected) => {
                if let Some(h) = producer.take()
                    && let Err(payload) = h.join()
                {
                    std::panic::resume_unwind(payload);
                }
                panic!(
                    "ack channel disconnected — producer completed without sending ack {expected}"
                );
            }
            Err(RecvTimeoutError::Timeout) => {
                panic!("timed out waiting for producer ack {expected}")
            }
        }
    }

    recv_ack(&ack_rx, &mut producer, 1, Duration::from_secs(1));
    recv_ack(&ack_rx, &mut producer, 2, Duration::from_secs(1));
    // Wait for the producer to reach the third submit call. Without this
    // rendezvous the timeout below could pass vacuously if the producer thread
    // were descheduled after sending ack 2 but before entering `submit()`.
    entering_third_rx
        .recv_timeout(Duration::from_secs(1))
        .expect("producer should reach the third submit");
    // The worker is blocked inside `StoreHandle::wait()` on a non-auto-completing
    // findings sink — the condvar cannot fire until `release_next` is called, so
    // 200ms is far longer than any scheduling jitter while still keeping the test
    // fast. This proves the producer is structurally blocked, not merely slow.
    assert!(
        matches!(
            ack_rx.recv_timeout(Duration::from_millis(200)),
            Err(RecvTimeoutError::Timeout)
        ),
        "third submit should remain blocked while the slow sink stalls the worker and the bounded execution queue is full"
    );
    assert!(
        matches!(
            pipeline.recv_timeout(Duration::from_millis(200)),
            Err(RecvTimeoutError::Timeout)
        ),
        "no durable receipt should be emitted while the first findings write is still pending"
    );

    wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger must remain empty until the blocked findings write is released"
    );

    findings_sink
        .release_next(CompletionOrder::OldestFirst)
        .expect("release first findings write")
        .expect("first pending findings write");
    recv_ack(&ack_rx, &mut producer, 3, Duration::from_secs(1));

    for _ in 0..2 {
        wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release remaining findings writes")
            .expect("pending findings write should exist");
    }

    for _ in 0..3 {
        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("committed outcome should arrive")
        {
            CommitStageOutput::Committed {
                write_context,
                checkpoint_input,
            } => {
                assert_eq!(
                    write_context, context,
                    "every committed outcome must preserve the originating write context"
                );
                assert_eq!(
                    aggregator
                        .record_receipt(checkpoint_input)
                        .expect("receipt should buffer"),
                    ReceiptRecordOutcome::Buffered
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected durable commit success, got failure: {error}")
            }
        }
    }

    producer
        .take()
        .expect("producer handle should still exist")
        .join()
        .expect("producer should join");
    pipeline.shutdown().expect("worker should join");

    assert_eq!(
        findings_sink.pending_count().expect("pending count"),
        0,
        "all delayed findings writes must drain after the releases"
    );
    assert_sink_counts(&findings_sink, 6);

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        3,
        "each committed item should produce one durable done-ledger row"
    );
    assert!(
        rows.iter()
            .all(|row| row.status() == DoneLedgerStatus::ScannedWithFindings),
        "all rows should reflect scanned items with findings"
    );
    assert!(
        rows.iter().all(|row| row.findings_count() == 2),
        "each durable done-ledger row should account for the two committed findings"
    );
    assert!(
        rows.iter().all(|row| row.write_context() == context),
        "every durable row must preserve the shared write context"
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("three committed receipts should yield one contiguous checkpoint prefix");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 2);
    assert_eq!(pending.committed_units(), 3);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x83)),
        "the checkpoint cursor must advance to the final durably committed item"
    );

    let checkpoint_scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9_601),
        ))
        .expect("acknowledging the fully drained prefix should succeed");
    assert_eq!(aggregator.next_sequence_no(), 3);
    assert_eq!(aggregator.checkpointed_units(), 3);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
}

#[test]
fn crash_after_findings_before_ledger_write_does_not_checkpoint_and_retry_is_safe() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .fail_next_commits(1)
        .expect("fault injection should succeed");
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(200);
    let unit = completed_unit(0, 0x51);
    let translation = scanned_translation(context, 0x51, 1);

    let error = committer
        .commit_translation(context, &unit, &translation)
        .expect_err("done-ledger commit should fail on first attempt (findings already durable)");

    match error {
        ResultCommitError::DoneLedgerAdvance(CommitAdvanceError::Wait(
            InMemoryPersistenceError::InjectedCommitFailure { store },
        )) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
        other => panic!("expected injected done-ledger commit failure, got {other:?}"),
    }
    assert_sink_counts(&findings_sink, 2);
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger must remain empty after the injected crash-before-ledger outcome"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no(), 4);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "without a receipt, the runtime must not fabricate checkpoint progress"
    );
    assert_eq!(aggregator.buffered_receipt_count(), 0);

    // Re-derive translation from identical inputs rather than reusing the same
    // object. This implicitly asserts that `translate_item_result` is
    // deterministic: same scan outputs produce byte-identical persistence
    // batches, so the retry succeeds via upsert idempotency.
    let retry_translation = scanned_translation(context, 0x51, 1);
    let receipt = committer
        .commit_translation(context, &unit, &retry_translation)
        .expect("retry with re-derived translation should succeed idempotently");

    // Receipt validates the full commit pipeline executed on retry.
    assert_eq!(receipt.completed_unit().sequence_no(), 0);
    assert_eq!(receipt.durable().scope().committed_units().get(), 1);
    assert_eq!(receipt.durable().findings().finding_count(), 2);
    assert_eq!(receipt.durable().findings().occurrence_count(), 2);
    assert_eq!(receipt.durable().findings().observation_count(), 2);
    assert_eq!(receipt.durable().done_ledger().record_count(), 1);
    assert_eq!(receipt.durable().done_ledger().findings_count(), 2);

    assert_sink_counts(&findings_sink, 2);
    assert_single_done_row(&done_ledger, DoneLedgerStatus::ScannedWithFindings, 2);

    let input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("successful retry receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one committed receipt should yield one checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 0);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x51)),
        "checkpoint cursor must point to the committed item key"
    );

    // Extract scope before mutable borrow for acknowledge_checkpoint.
    let checkpoint_scope = pending.scope().clone();

    // Acknowledge the prepared checkpoint, completing the recovery cycle.
    // After acknowledgement the aggregator advances past the committed unit
    // and is ready for the next shard assignment.
    let _page_receipt = aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            checkpoint_scope,
            LogicalTime::from_raw(9999),
        ))
        .expect("acknowledge should finalize the prepared prefix");

    assert_eq!(
        aggregator.next_sequence_no(),
        1,
        "next_sequence_no must advance from 0 to 1 after acknowledgement"
    );
    assert_eq!(
        aggregator.buffered_receipt_count(),
        0,
        "all buffered receipts must drain after acknowledgement"
    );
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no pending receipts remain after acknowledgement"
    );
}

#[test]
fn crash_before_findings_durability_leaves_both_stores_empty_and_retry_recovers() {
    let findings_sink = InMemoryFindingsSink::new();
    findings_sink
        .fail_next_commits(1)
        .expect("fault injection should succeed");
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(300);
    let unit = completed_unit(0, 0x61);
    let translation = scanned_translation(context, 0x61, 2);

    let error = committer
        .commit_translation(context, &unit, &translation)
        .expect_err("findings commit should fail on first attempt (injected fault)");

    match error {
        ResultCommitError::FindingsWait(InMemoryPersistenceError::InjectedCommitFailure {
            store,
        }) => assert_eq!(store, InMemoryStoreKind::Findings),
        other => panic!("expected injected findings commit failure, got {other:?}"),
    }

    // Both stores must be empty after a findings-stage crash.
    assert_sink_counts(&findings_sink, 0);
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger must remain empty when findings never became durable"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no(), 4);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no receipt means no checkpoint progress"
    );

    // Retry succeeds after the transient fault clears.
    let retry_translation = scanned_translation(context, 0x61, 2);
    let receipt = committer
        .commit_translation(context, &unit, &retry_translation)
        .expect("retry should succeed after transient findings fault clears");

    assert_eq!(receipt.completed_unit().sequence_no(), 0);
    assert_eq!(receipt.durable().scope().committed_units().get(), 1);
    assert_eq!(receipt.durable().findings().finding_count(), 2);
    assert_eq!(receipt.durable().findings().occurrence_count(), 2);
    assert_eq!(receipt.durable().findings().observation_count(), 2);
    assert_eq!(receipt.durable().done_ledger().record_count(), 1);
    assert_eq!(receipt.durable().done_ledger().findings_count(), 2);

    assert_sink_counts(&findings_sink, 2);
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        1
    );

    let input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("retry receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one committed receipt should yield one checkpointable prefix");
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x61)),
    );
}

#[test]
fn crash_after_ledger_before_checkpoint_allows_reassignment_retry_and_rejects_stale_fence() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let stale_context = write_context_with_epoch(400);
    let current_context = write_context_with_epoch(401);
    let unit = completed_unit(7, 0x71);

    let stale_translation = scanned_translation(stale_context, 0x71, 5);
    let stale_receipt = committer
        .commit_translation(stale_context, &unit, &stale_translation)
        .expect("first worker should durably write findings and done-ledger");

    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        1,
        "durable done-ledger state should contain exactly one row before checkpoint recovery"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(current_context, unit.sequence_no(), 4);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "durable done-ledger state alone must not move the checkpoint without a recorded receipt"
    );

    let stale_input =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), stale_receipt)
            .expect("stale receipt boundary kind should still match the shard stream");
    let stale_error = aggregator
        .record_receipt(stale_input)
        .expect_err("stale-fence receipt must be rejected after reassignment");
    assert_eq!(
        stale_error,
        PrefixCheckpointError::OwnershipMismatch {
            sequence_no: 7,
            expected: Box::new(current_context),
            actual: Box::new(stale_context),
        }
    );
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should still succeed after stale rejection")
            .is_none(),
        "rejecting the stale receipt must not leave behind a checkpointable prefix"
    );

    let retry_translation = scanned_translation(current_context, 0x71, 100);
    let retry_receipt = committer
        .commit_translation(current_context, &unit, &retry_translation)
        .expect("reassignment retry should be idempotent and succeed");

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "retry must not create duplicate done-ledger rows"
    );
    let row = rows
        .into_iter()
        .next()
        .expect("exactly one done-ledger row should remain");
    assert_eq!(
        row.write_context(),
        current_context,
        "the higher-fence retry should win done-ledger provenance"
    );

    let observations = findings_sink
        .observations_snapshot()
        .expect("observations snapshot");
    assert_eq!(
        observations.len(),
        2,
        "reassignment retry must upsert observations rather than duplicating them"
    );
    assert!(
        observations
            .iter()
            .all(|observation| observation.write_context() == current_context),
        "later retry should win observation provenance as well"
    );

    let retry_input =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), retry_receipt)
            .expect("retry receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(retry_input)
            .expect("current-fence receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("current-fence retry should re-establish a checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 7);
    assert_eq!(pending.last_sequence_no(), 7);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x71)),
        "checkpoint cursor must point at the retried unit"
    );

    let pending_scope = pending.scope().clone();
    let _page_receipt = aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending_scope,
            LogicalTime::from_raw(9_201),
        ))
        .expect("acknowledging the recovered checkpoint should succeed");

    assert_eq!(aggregator.next_sequence_no(), 8);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed after acknowledgement")
            .is_none(),
        "no pending receipts should remain after acknowledging the recovered checkpoint"
    );
}

#[test]
fn stale_fence_receipts_are_rejected_and_leave_no_side_effect() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let stale_context_100 = write_context_with_epoch(100);
    let stale_context_200 = write_context_with_epoch(200);
    let current_context_300 = write_context_with_epoch(300);
    let unit = completed_unit(7, 0x73);

    let stale_receipt_100 = committer
        .commit_translation(
            stale_context_100,
            &unit,
            &scanned_translation(stale_context_100, 0x73, 10),
        )
        .expect("epoch-100 commit should succeed");
    let stale_receipt_200 = committer
        .commit_translation(
            stale_context_200,
            &unit,
            &scanned_translation(stale_context_200, 0x73, 20),
        )
        .expect("epoch-200 commit should succeed");
    let current_receipt_300 = committer
        .commit_translation(
            current_context_300,
            &unit,
            &scanned_translation(current_context_300, 0x73, 30),
        )
        .expect("epoch-300 commit should succeed");

    let mut aggregator = PrefixCheckpointAggregator::new(current_context_300, 7, 4);

    for (label, stale_context, stale_receipt) in [
        ("epoch-100", stale_context_100, stale_receipt_100),
        ("epoch-200", stale_context_200, stale_receipt_200),
    ] {
        let stale_input =
            CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), stale_receipt)
                .expect("stale receipt boundary kind should match the shard stream");
        let stale_error = aggregator
            .record_receipt(stale_input)
            .expect_err("stale receipt must be rejected");
        assert_eq!(
            stale_error,
            PrefixCheckpointError::OwnershipMismatch {
                sequence_no: 7,
                expected: Box::new(current_context_300),
                actual: Box::new(stale_context),
            }
        );
        assert_eq!(
            aggregator.buffered_receipt_count(),
            0,
            "{label}: buffer side effect"
        );
        assert_eq!(
            aggregator.checkpointed_units(),
            0,
            "{label}: checkpointed side effect"
        );
        assert!(
            aggregator
                .prepare_checkpoint()
                .expect("checkpoint preparation should succeed after stale rejection")
                .is_none(),
            "{label}: rejection must not leave behind a checkpointable prefix"
        );
    }

    let current_input_300 =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), current_receipt_300)
            .expect("epoch-300 receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(current_input_300)
            .expect("current receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    assert_eq!(aggregator.buffered_receipt_count(), 1);

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("current receipt should establish a checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 7);
    assert_eq!(pending.last_sequence_no(), 7);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x73)),
    );

    let pending_scope = pending.scope().clone();
    let page_receipt = aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending_scope,
            LogicalTime::from_raw(9_301),
        ))
        .expect("acknowledging the current-epoch checkpoint should succeed");
    assert_eq!(
        page_receipt.checkpoint().checkpointed_at(),
        LogicalTime::from_raw(9_301),
        "page receipt must echo the committed logical time"
    );

    assert_eq!(aggregator.next_sequence_no(), 8);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed after acknowledgement")
            .is_none(),
        "no pending receipts should remain after acknowledging the stale-fence checkpoint"
    );
}

#[test]
fn stale_fence_with_same_run_id_but_different_epoch_is_rejected() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let stale_context = write_context_with_epoch(300);
    let current_context = write_context_with_epoch(301);
    // Precondition: both contexts share tenant/policy/run/shard — only the
    // epoch differs. These guards document that intent so the test remains
    // valid if the fixture is ever parameterized further.
    assert_eq!(stale_context.tenant_id(), current_context.tenant_id());
    assert_eq!(stale_context.policy_hash(), current_context.policy_hash());
    assert_eq!(stale_context.run_id(), current_context.run_id());
    assert_eq!(stale_context.shard_id(), current_context.shard_id());
    assert_ne!(stale_context.fence_epoch(), current_context.fence_epoch());

    let unit = completed_unit(11, 0x74);
    let stale_receipt = committer
        .commit_translation(
            stale_context,
            &unit,
            &scanned_translation(stale_context, 0x74, 40),
        )
        .expect("stale commit should succeed");

    let mut aggregator = PrefixCheckpointAggregator::new(current_context, 11, 4);
    let stale_input =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), stale_receipt)
            .expect("stale receipt boundary kind should match the shard stream");
    let stale_error = aggregator
        .record_receipt(stale_input)
        .expect_err("different fence epoch must be rejected even when run and shard match");
    assert_eq!(
        stale_error,
        PrefixCheckpointError::OwnershipMismatch {
            sequence_no: 11,
            expected: Box::new(current_context),
            actual: Box::new(stale_context),
        }
    );
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert_eq!(
        aggregator.next_sequence_no(),
        11,
        "stale rejection must not advance the sequence counter"
    );
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed after epoch mismatch")
            .is_none(),
        "rejecting the stale receipt must not create checkpointable progress"
    );

    // Positive control: a receipt from the current epoch for the same unit must
    // succeed, proving that the aggregator rejects only the epoch mismatch and
    // not the unit or sequence number itself.
    let current_receipt = committer
        .commit_translation(
            current_context,
            &unit,
            &scanned_translation(current_context, 0x74, 41),
        )
        .expect("current-epoch commit should succeed");

    let current_input =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), current_receipt)
            .expect("current receipt boundary kind should match the shard stream");
    assert_eq!(
        aggregator
            .record_receipt(current_input)
            .expect("current-epoch receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("current-epoch receipt should yield a checkpointable prefix");
    assert_eq!(pending.first_sequence_no(), 11);
    assert_eq!(pending.last_sequence_no(), 11);
    assert_eq!(pending.committed_units(), 1);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x74)),
    );

    let pending_scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending_scope,
            LogicalTime::from_raw(9_401),
        ))
        .expect("acknowledging the current-epoch checkpoint should succeed");
    assert_eq!(aggregator.next_sequence_no(), 12);
    assert_eq!(aggregator.checkpointed_units(), 1);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
}

#[test]
fn multi_item_crash_on_second_item_yields_partial_prefix_after_retry() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let context = write_context_with_epoch(400);
    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 8);

    // Item 1 commits successfully.
    let unit1 = completed_unit(0, 0x71);
    let translation1 = scanned_translation(context, 0x71, 3);
    let receipt1 = committer
        .commit_translation(context, &unit1, &translation1)
        .expect("item 1 commit should succeed");

    // Inject done-ledger fault before item 2.
    done_ledger
        .fail_next_commits(1)
        .expect("fault injection should succeed");

    let unit2 = completed_unit(1, 0x72);
    let translation2 = scanned_translation(context, 0x72, 4);
    let _error = committer
        .commit_translation(context, &unit2, &translation2)
        .expect_err("item 2 done-ledger commit should fail (injected fault)");

    // Feed receipt 1 to the aggregator — partial prefix of 1 item.
    let input1 = CheckpointAggregatorInput::new(unit1.checkpoint_boundary_kind(), receipt1)
        .expect("receipt boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(input1)
            .expect("receipt 1 should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let partial = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("one committed receipt should yield a checkpointable prefix");
    assert_eq!(partial.first_sequence_no(), 0);
    assert_eq!(partial.last_sequence_no(), 0);
    assert_eq!(partial.committed_units(), 1);
    assert_eq!(
        partial.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x71)),
    );

    // Acknowledge the partial checkpoint so the aggregator advances.
    let partial_scope = partial.scope().clone();
    let _page = aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            partial_scope,
            LogicalTime::from_raw(10_001),
        ))
        .expect("partial acknowledge should succeed");
    assert_eq!(aggregator.next_sequence_no(), 1);

    // Retry item 2 after the transient fault clears.
    let retry_translation2 = scanned_translation(context, 0x72, 4);
    let receipt2 = committer
        .commit_translation(context, &unit2, &retry_translation2)
        .expect("item 2 retry should succeed");

    assert_eq!(receipt2.completed_unit().sequence_no(), 1);
    assert_eq!(receipt2.durable().findings().finding_count(), 2);
    assert_eq!(receipt2.durable().done_ledger().record_count(), 1);

    let input2 = CheckpointAggregatorInput::new(unit2.checkpoint_boundary_kind(), receipt2)
        .expect("receipt boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(input2)
            .expect("receipt 2 should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let full = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("second receipt should extend the prefix");
    assert_eq!(full.first_sequence_no(), 1);
    assert_eq!(full.last_sequence_no(), 1);
    assert_eq!(full.committed_units(), 1);
    assert_eq!(
        full.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x72)),
    );
}

#[test]
fn duplicate_receipt_returns_duplicate_buffered_without_side_effect() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let context = write_context_with_epoch(500);
    let unit = completed_unit(0, 0x90);
    let receipt = committer
        .commit_translation(context, &unit, &scanned_translation(context, 0x90, 1))
        .expect("commit should succeed");

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 4);

    let input_first =
        CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt.clone())
            .expect("boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(input_first)
            .expect("first record should succeed"),
        ReceiptRecordOutcome::Buffered
    );

    let input_dup = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(input_dup)
            .expect("duplicate record should succeed without error"),
        ReceiptRecordOutcome::DuplicateBuffered
    );
    assert_eq!(
        aggregator.buffered_receipt_count(),
        1,
        "duplicate must not inflate the buffer"
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("single receipt should yield a prefix");
    assert_eq!(pending.committed_units(), 1);
}

#[test]
fn receipt_for_already_checkpointed_sequence_returns_already_checkpointed() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let context = write_context_with_epoch(501);
    let unit = completed_unit(0, 0x91);
    let receipt = committer
        .commit_translation(context, &unit, &scanned_translation(context, 0x91, 2))
        .expect("commit should succeed");

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0, 4);

    let input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt.clone())
        .expect("boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(input)
            .expect("record should succeed"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("receipt should yield a prefix");
    let scope = pending.scope().clone();
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            scope,
            LogicalTime::from_raw(10_501),
        ))
        .expect("acknowledge should succeed");
    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);

    // Re-record the same receipt after it has been checkpointed.
    let replayed_input = CheckpointAggregatorInput::new(unit.checkpoint_boundary_kind(), receipt)
        .expect("boundary kind should match");
    assert_eq!(
        aggregator
            .record_receipt(replayed_input)
            .expect("replayed record should succeed without error"),
        ReceiptRecordOutcome::AlreadyCheckpointed
    );
    assert_eq!(
        aggregator.buffered_receipt_count(),
        0,
        "already-checkpointed receipt must not re-enter the buffer"
    );
    assert_eq!(
        aggregator.checkpointed_units(),
        1,
        "checkpointed count must not change"
    );
    assert_eq!(
        aggregator.next_sequence_no(),
        1,
        "sequence watermark must not regress"
    );
}
