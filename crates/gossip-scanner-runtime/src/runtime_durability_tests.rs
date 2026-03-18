//! Runtime durability integration tests for translation, commit, and
//! receipt-driven checkpoint aggregation.

use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{
        FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RuleFingerprint, RunId, ShardId,
        StableItemId, TenantId, TenantSecretKey, derive_rule_fingerprint,
    },
    persistence::{CommitAdvanceError, WriteContext},
};
use gossip_persistence_inmemory::{
    InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError, InMemoryStoreKind,
};
use scanner_scheduler::store::FsFindingRecord;

use crate::{
    checkpoint_aggregator::{PrefixCheckpointAggregator, ReceiptRecordOutcome},
    commit_model::{CheckpointAggregatorInput, CompletedUnit},
    result_committer::{ResultCommitError, ResultCommitter},
    result_translation::{ItemResult, PersistenceTranslation, ScanTiming, translate_item_result},
};

fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
    let name = format!("test-rule-{rule_id}");
    derive_rule_fingerprint(&name)
}

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
        VersionId::Strong(ObjectVersionId::from_bytes(
            [item_suffix.wrapping_add(1); 32],
        )),
    )
    .with_location(Location::try_new(path, Some(url)).expect("location"))
}

fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
    CompletedUnit::ordered_content(sequence_no, Cursor::with_last_key(item_key(item_suffix)))
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
        &test_rule_fingerprint,
    )
    .expect("translation")
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
        .commit_translation(context, &unit, &translation)
        .expect_err("the first attempt should fail after findings durability");

    match error {
        ResultCommitError::DoneLedgerAdvance(CommitAdvanceError::Wait(
            InMemoryPersistenceError::InjectedCommitFailure { store },
        )) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
        other => panic!("expected injected done-ledger commit failure, got {other:?}"),
    }
    assert_eq!(
        findings_sink.findings_snapshot().expect("snapshot").len(),
        2
    );
    assert_eq!(
        findings_sink
            .occurrences_snapshot()
            .expect("snapshot")
            .len(),
        2
    );
    assert_eq!(
        findings_sink
            .observations_snapshot()
            .expect("snapshot")
            .len(),
        2
    );
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

    let receipt = committer
        .commit_translation(context, &unit, &translation)
        .expect("retry should succeed idempotently");

    assert_eq!(
        findings_sink.findings_snapshot().expect("snapshot").len(),
        2
    );
    assert_eq!(
        findings_sink
            .occurrences_snapshot()
            .expect("snapshot")
            .len(),
        2
    );
    assert_eq!(
        findings_sink
            .observations_snapshot()
            .expect("snapshot")
            .len(),
        2
    );
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        1
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
}
