//! Runtime-primitive crash / ordering / fence tests for Epic 2.8.
//!
//! These tests stitch together the shared runtime durability primitives built
//! in EP2.1–EP2.7:
//!
//! - deterministic result translation;
//! - [`ResultCommitter`](crate::result_committer::ResultCommitter);
//! - receipt-driven prefix checkpoint aggregation.
//!
//! The goal is to prove the core runtime durability invariants with *real*
//! durable receipts rather than only synthetic module-local fixtures:
//!
//! - findings durable without done-ledger does not yield checkpoint progress;
//! - done-ledger durable without a recorded receipt does not yield checkpoint
//!   progress;
//! - only the contiguous committed prefix can checkpoint; and
//! - stale fence epochs cannot make progress look authoritative after
//!   reassignment.

use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, TokenBytes, VersionId},
    identity::{
        FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RunId, ShardId,
        StableItemId, TenantId, TenantSecretKey,
    },
    persistence::{CheckpointBoundaryKind, CheckpointCommitReceipt, WriteContext},
};
use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
use scanner_scheduler::FsFindingRecord;

use crate::{
    checkpoint_aggregator::{
        PrefixCheckpointAggregator, PrefixCheckpointError, ReceiptRecordOutcome,
        ReceiptOwner,
    },
    commit_model::CompletedUnit,
    result_committer::{ResultCommitError, ResultCommitter},
    result_translation::{ItemResult, PersistenceTranslation, ScanTiming, translate_item_result},
};

fn write_context(fence_epoch_raw: u64) -> WriteContext {
    WriteContext::new(
        TenantId::from_bytes([0x11; 32]),
        PolicyHash::from_bytes([0x22; 32]),
        RunId::from_raw(33),
        ShardId::from_raw(44),
        FenceEpoch::from_raw(fence_epoch_raw),
    )
}

fn tenant_secret_key() -> TenantSecretKey {
    TenantSecretKey::from_bytes([0x99; 32])
}

fn item_key(item_suffix: u8) -> ItemKey {
    ItemKey::try_from_slice(&[b't', b'/', item_suffix]).expect("item key")
}

fn scan_item(item_suffix: u8) -> ScanItem {
    let item_ref = ItemRef::try_from_vec(vec![b'r', item_suffix]).expect("item ref");
    let path = format!("tenant/repo/file-{item_suffix}.txt");
    let url = format!("https://example.invalid/{item_suffix}");

    ScanItem::new(
        item_key(item_suffix),
        item_ref,
        StableItemId::from_bytes([item_suffix; 32]),
        VersionId::Strong(ObjectVersionId::from_bytes([
            item_suffix.wrapping_add(1);
            32
        ])),
    )
    .with_location(Location::try_new(path, Some(url)).expect("location"))
}

fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
    CompletedUnit::ordered_content(sequence_no, Cursor::with_last_key(item_key(item_suffix)))
}

fn repo_frontier_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
    CompletedUnit::repo_frontier(
        sequence_no,
        Cursor::with_token(
            item_key(item_suffix),
            TokenBytes::try_from_slice(b"repo-frontier-token").expect("token"),
        ),
    )
}

fn timing(offset: u64) -> ScanTiming {
    ScanTiming::new(
        LogicalTime::from_raw(1_000 + offset),
        LogicalTime::from_raw(2_000 + offset),
    )
}

fn finding(rule_id: u32, span_start: u64, span_end: u64, hash_seed: u8) -> FsFindingRecord {
    FsFindingRecord {
        rule_id,
        root_hint_start: span_start,
        root_hint_end: span_end,
        span_start,
        span_end,
        norm_hash: [hash_seed; 32],
        confidence_score: 7,
    }
}

fn scanned_translation(
    write_context: WriteContext,
    item_suffix: u8,
    timing_offset: u64,
) -> PersistenceTranslation {
    let item = scan_item(item_suffix);
    let findings = [
        finding(7, 10, 20, item_suffix),
        finding(9, 30, 45, item_suffix.wrapping_add(10)),
    ];

    translate_item_result(
        write_context,
        &tenant_secret_key(),
        &item,
        128,
        timing(timing_offset),
        ItemResult::Scanned {
            findings: &findings,
        },
    )
    .expect("translation")
}

fn acknowledge_pending(
    aggregator: &mut PrefixCheckpointAggregator,
    checkpointed_at: u64,
) {
    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("checkpoint prefix should be pending");
    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(checkpointed_at),
        ))
        .expect("checkpoint acknowledgement should succeed");
}

#[test]
fn no_checkpoint_without_receipt_even_when_done_ledger_is_durable() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger.clone());

    let context = write_context(100);
    let unit = completed_unit(0, 0x41);
    let translation = scanned_translation(context, 0x41, 1);

    let _receipt = committer
        .commit_translation(context, unit.clone(), &translation)
        .expect("durable commit should succeed");

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "done-ledger row should already be durable");

    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no());
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "no checkpoint can be prepared until a durable receipt is explicitly recorded"
    );
    assert_eq!(aggregator.checkpointed_units(), 0);
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

    let context = write_context(200);
    let unit = completed_unit(0, 0x51);
    let translation = scanned_translation(context, 0x51, 1);

    let error = committer
        .commit_translation(context, unit.clone(), &translation)
        .expect_err("the first attempt should fail after findings durability");

    assert!(matches!(error, ResultCommitError::DoneLedgerAdvance(_)));
    assert_eq!(findings_sink.findings_snapshot().expect("snapshot").len(), 2);
    assert_eq!(findings_sink.occurrences_snapshot().expect("snapshot").len(), 2);
    assert_eq!(findings_sink.observations_snapshot().expect("snapshot").len(), 2);
    assert!(
        done_ledger.snapshot().expect("done-ledger snapshot").is_empty(),
        "done-ledger must remain empty after the injected crash-before-ledger outcome"
    );

    let mut aggregator = PrefixCheckpointAggregator::new(context, unit.sequence_no());
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "without a receipt, the runtime must not fabricate checkpoint progress"
    );

    let receipt = committer
        .commit_translation(context, unit, &translation)
        .expect("retry should succeed idempotently");

    assert_eq!(findings_sink.findings_snapshot().expect("snapshot").len(), 2);
    assert_eq!(findings_sink.occurrences_snapshot().expect("snapshot").len(), 2);
    assert_eq!(findings_sink.observations_snapshot().expect("snapshot").len(), 2);
    assert_eq!(done_ledger.snapshot().expect("done-ledger snapshot").len(), 1);

    assert_eq!(
        aggregator
            .record_receipt(receipt)
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

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(9_001),
        ))
        .expect("durable checkpoint receipt should advance progress");

    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);
}

#[test]
fn real_receipts_only_advance_the_contiguous_prefix() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let context = write_context(300);
    let unit_zero = completed_unit(0, 0x61);
    let unit_one = completed_unit(1, 0x62);
    let translation_zero = scanned_translation(context, 0x61, 1);
    let translation_one = scanned_translation(context, 0x62, 2);

    let receipt_one = committer
        .commit_translation(context, unit_one, &translation_one)
        .expect("sequence 1 should commit");
    let receipt_zero = committer
        .commit_translation(context, unit_zero, &translation_zero)
        .expect("sequence 0 should commit");

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0);
    assert_eq!(
        aggregator
            .record_receipt(receipt_one)
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

    assert_eq!(
        aggregator
            .record_receipt(receipt_zero)
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
    assert_eq!(pending.checkpoint_cursor().last_key(), Some(&item_key(0x62)));

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(9_101),
        ))
        .expect("durable checkpoint receipt should advance the full prefix");

    assert_eq!(aggregator.next_sequence_no(), 2);
    assert_eq!(aggregator.checkpointed_units(), 2);
}

#[test]
fn repo_frontier_uses_the_same_committer_and_checkpoint_aggregator_primitives() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let context = write_context(450);
    let unit = repo_frontier_unit(0, 0x71);
    let translation = scanned_translation(context, 0x71, 7);

    let receipt = committer
        .commit_translation(context, unit, &translation)
        .expect("repo-frontier unit should commit through the shared committer");

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0);
    assert_eq!(
        aggregator
            .record_receipt(receipt)
            .expect("repo-frontier receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("repo-frontier receipt should prepare a checkpoint");
    assert_eq!(
        pending.checkpoint_boundary_kind(),
        CheckpointBoundaryKind::RepoFrontier
    );
    assert_eq!(pending.checkpoint_cursor().last_key(), Some(&item_key(0x71)));
    assert!(
        pending.checkpoint_cursor().token().is_none(),
        "prepared prefix should drop connector tokens even for repo-frontier progress"
    );

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(9_101),
        ))
        .expect("repo-frontier checkpoint acknowledgement should advance progress");

    assert_eq!(aggregator.next_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 1);
}

#[test]
fn crash_after_ledger_before_checkpoint_allows_reassignment_retry_and_rejects_stale_fence() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

    let stale_context = write_context(400);
    let current_context = write_context(401);
    let unit = completed_unit(7, 0x71);

    let stale_translation = scanned_translation(stale_context, 0x71, 1);
    let stale_receipt = committer
        .commit_translation(stale_context, unit.clone(), &stale_translation)
        .expect("first worker should durably write findings and done-ledger");

    assert_eq!(done_ledger.snapshot().expect("done-ledger snapshot").len(), 1);

    let mut aggregator = PrefixCheckpointAggregator::new(current_context, unit.sequence_no());
    assert!(
        aggregator
            .prepare_checkpoint()
            .expect("checkpoint preparation should succeed")
            .is_none(),
        "durable ledger state alone must not move the checkpoint without a recorded receipt"
    );

    let stale_error = aggregator
        .record_receipt(stale_receipt)
        .expect_err("stale-fence receipt must be rejected after reassignment");
    assert_eq!(
        stale_error,
        PrefixCheckpointError::OwnershipMismatch {
            sequence_no: 7,
            expected: ReceiptOwner::from_write_context(current_context),
            actual: ReceiptOwner::from_write_context(stale_context),
        }
    );
    assert_eq!(aggregator.buffered_receipt_count(), 0);
    assert_eq!(aggregator.checkpointed_units(), 0);

    let retry_translation = scanned_translation(current_context, 0x71, 100);
    let retry_receipt = committer
        .commit_translation(current_context, unit, &retry_translation)
        .expect("reassignment retry should be idempotent and succeed");

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "retry must not create duplicate done-ledger rows");
    assert_eq!(
        rows[0].write_context(),
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

    assert_eq!(
        aggregator
            .record_receipt(retry_receipt)
            .expect("current-fence receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    acknowledge_pending(&mut aggregator, 9_201);

    assert_eq!(aggregator.next_sequence_no(), 8);
    assert_eq!(aggregator.checkpointed_units(), 1);
}


#[test]
fn pending_prefix_does_not_widen_until_the_previous_checkpoint_is_acked() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let committer = ResultCommitter::new(findings_sink, done_ledger);

    let context = write_context(500);
    let unit_zero = completed_unit(0, 0x81);
    let unit_one = completed_unit(1, 0x82);
    let unit_two = completed_unit(2, 0x83);
    let translation_zero = scanned_translation(context, 0x81, 1);
    let translation_one = scanned_translation(context, 0x82, 2);
    let translation_two = scanned_translation(context, 0x83, 3);

    let receipt_one = committer
        .commit_translation(context, unit_one, &translation_one)
        .expect("sequence 1 should commit");
    let receipt_zero = committer
        .commit_translation(context, unit_zero, &translation_zero)
        .expect("sequence 0 should commit");
    let receipt_two = committer
        .commit_translation(context, unit_two, &translation_two)
        .expect("sequence 2 should commit");

    let mut aggregator = PrefixCheckpointAggregator::new(context, 0);
    assert_eq!(
        aggregator
            .record_receipt(receipt_one)
            .expect("out-of-order receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );
    assert_eq!(
        aggregator
            .record_receipt(receipt_zero)
            .expect("gap-closing receipt should buffer"),
        ReceiptRecordOutcome::Buffered
    );

    let first_pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("contiguous prefix should exist");
    assert_eq!(first_pending.first_sequence_no(), 0);
    assert_eq!(first_pending.last_sequence_no(), 1);
    assert_eq!(first_pending.checkpoint_cursor().last_key(), Some(&item_key(0x82)));

    assert_eq!(
        aggregator
            .record_receipt(receipt_two)
            .expect("later receipt should buffer behind the pending prefix"),
        ReceiptRecordOutcome::Buffered
    );

    let still_pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("pending prefix should remain prepared");
    assert_eq!(still_pending.first_sequence_no(), 0);
    assert_eq!(still_pending.last_sequence_no(), 1);
    assert_eq!(aggregator.checkpointed_units(), 0);
    assert_eq!(aggregator.buffered_receipt_count(), 3);

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            first_pending.scope().clone(),
            LogicalTime::from_raw(9_301),
        ))
        .expect("durable checkpoint receipt should advance the first prefix");

    let second_pending = aggregator
        .prepare_checkpoint()
        .expect("checkpoint preparation should succeed")
        .expect("the buffered tail receipt should now become checkpointable");
    assert_eq!(second_pending.first_sequence_no(), 2);
    assert_eq!(second_pending.last_sequence_no(), 2);
    assert_eq!(second_pending.checkpoint_cursor().last_key(), Some(&item_key(0x83)));

    aggregator
        .acknowledge_checkpoint(CheckpointCommitReceipt::new(
            second_pending.scope().clone(),
            LogicalTime::from_raw(9_302),
        ))
        .expect("durable checkpoint receipt should advance the remaining tail receipt");

    assert_eq!(aggregator.next_sequence_no(), 3);
    assert_eq!(aggregator.checkpointed_units(), 3);
    assert_eq!(aggregator.buffered_receipt_count(), 0);
}
