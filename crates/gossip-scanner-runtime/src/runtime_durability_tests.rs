//! Runtime durability integration tests for translation, commit, and
//! receipt-driven checkpoint aggregation.

use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{LogicalTime, ObjectVersionId, StableItemId},
    persistence::{CheckpointCommitReceipt, CommitAdvanceError, DoneLedgerStatus, WriteContext},
};
use gossip_persistence_inmemory::{
    InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError, InMemoryStoreKind,
};

use scanner_scheduler::store::FsFindingRecord;

use crate::{
    checkpoint_aggregator::{
        PrefixCheckpointAggregator, PrefixCheckpointError, ReceiptRecordOutcome,
    },
    commit_model::{CheckpointAggregatorInput, CompletedUnit},
    result_committer::{ResultCommitError, ResultCommitter},
    result_translation::{ItemResult, PersistenceTranslation, translate_item_result},
    test_fixtures::{
        finding, tenant_secret_key, test_rule_fingerprint, timing_with_offset,
        write_context_with_epoch,
    },
};

fn item_key(item_suffix: u8) -> ItemKey {
    ItemKey::try_from_slice(&[b't', b'/', item_suffix]).unwrap()
}

fn scan_item(item_suffix: u8) -> ScanItem {
    let item_ref = ItemRef::try_from_vec(vec![b'r', item_suffix]).unwrap();
    let path = format!("tenant/repo/file-{item_suffix}.txt");
    let url = format!("https://example.invalid/{item_suffix}");

    ScanItem::new(
        item_key(item_suffix),
        item_ref,
        StableItemId::from_bytes([item_suffix; 32]),
        VersionId::Strong(ObjectVersionId::from_bytes(
            [item_suffix.wrapping_add(1); 32],
        )),
    )
    .with_location(Location::try_new(path, Some(url)).unwrap())
}

fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
    CompletedUnit::ordered_content(sequence_no, Cursor::with_last_key(item_key(item_suffix)))
}

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

fn scanned_translation_with(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
    findings: &[FsFindingRecord],
) -> PersistenceTranslation {
    let item = scan_item(item_suffix);
    translate_item_result(
        write_context,
        &tenant_secret_key(),
        &item,
        128,
        timing_with_offset(timing_offset),
        ItemResult::Scanned { findings },
        &test_rule_fingerprint,
    )
    .expect("translation should succeed")
}

fn scanned_translation(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
) -> PersistenceTranslation {
    scanned_translation_with(
        write_context,
        item_suffix,
        timing_offset,
        &[
            finding(7, 10, 20, item_suffix),
            finding(9, 30, 45, item_suffix.wrapping_add(10)),
        ],
    )
}

fn clean_scanned_translation(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
) -> PersistenceTranslation {
    scanned_translation_with(write_context, item_suffix, timing_offset, &[])
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
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "done-ledger row should already be durable");
    let done_record = rows
        .into_iter()
        .next()
        .expect("exactly one done-ledger record");
    assert_eq!(
        done_record.status(),
        DoneLedgerStatus::ScannedWithFindings,
        "done-ledger status must reflect the two committed findings"
    );
    assert_eq!(
        done_record.findings_count(),
        2,
        "done-ledger findings_count must match committed findings"
    );

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
}

#[test]
fn clean_scan_with_zero_findings_commits_and_checkpoints_normally() {
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
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "done-ledger should contain exactly one row");
    let done_record = rows
        .into_iter()
        .next()
        .expect("exactly one done-ledger record");
    assert_eq!(
        done_record.status(),
        DoneLedgerStatus::ScannedClean,
        "done-ledger status must be ScannedClean for zero findings"
    );
    assert_eq!(
        done_record.findings_count(),
        0,
        "done-ledger findings_count must be zero for a clean scan"
    );

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
    assert_eq!(pending.first_sequence_no(), 0);
    assert_eq!(pending.last_sequence_no(), 0);
    assert_eq!(
        pending.checkpoint_cursor(),
        &Cursor::with_last_key(item_key(0x81)),
        "checkpoint cursor must point to the clean-scan item key"
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
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "sequence 1 alone must not advance the committed prefix"
    );
    assert_eq!(aggregator.next_sequence_no(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);

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
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        1
    );
    let done_record = done_ledger
        .snapshot()
        .expect("done-ledger snapshot")
        .into_iter()
        .next()
        .expect("exactly one done-ledger record");
    assert_eq!(
        done_record.status(),
        DoneLedgerStatus::ScannedWithFindings,
        "done-ledger status must reflect the two committed findings"
    );
    assert_eq!(
        done_record.findings_count(),
        2,
        "done-ledger findings_count must match committed findings"
    );

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
