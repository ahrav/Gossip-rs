use std::{num::NonZeroU64, sync::mpsc, thread, time::Duration};

use gossip_contracts::{
    connector::Location,
    identity::{
        FenceEpoch, FindingId, LogicalTime, NormHash, ObjectVersionId, ObservationId, OccurrenceId,
        RuleFingerprint, RunId, ShardId, StableItemId, TenantSecretKey, key_secret_hash,
    },
    persistence::{
        CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
        DoneLedgerRecord, DoneLedgerStatus, FindingRecord, FindingsSink, FindingsUpsertBatch,
        ObservationRecord, OccurrenceRecord,
    },
    test_util::{ovid, policy, tenant},
};

use crate::{
    CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
    InMemoryStoreKind,
};

use gossip_contracts::persistence::PersistenceInputError;

use DoneLedgerStatus::{FailedPermanent, FailedRetryable, ScannedClean, ScannedWithFindings};

fn provenance(
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    started_at: u64,
    finished_at: u64,
) -> DoneLedgerProvenance {
    DoneLedgerProvenance::new(
        RunId::from_raw(run_id),
        ShardId::from_raw(shard_id),
        FenceEpoch::from_raw(fence_epoch),
        LogicalTime::from_raw(started_at),
        LogicalTime::from_raw(finished_at),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the flat done-ledger durable row shape"
)]
fn done_record(
    tenant_seed: u8,
    policy_seed: u8,
    ovid_seed: u8,
    status: DoneLedgerStatus,
    bytes_scanned: u64,
    findings_count: u32,
    provenance: DoneLedgerProvenance,
    error_code: Option<&str>,
) -> DoneLedgerRecord {
    DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant(tenant_seed), policy(policy_seed), ovid(ovid_seed)),
        status,
        bytes_scanned,
        findings_count,
        provenance,
        error_code.map(|code| DoneLedgerErrorCode::try_new(code).unwrap()),
    )
    .unwrap()
}

fn finding_record(tenant_seed: u8, seed: u8) -> FindingRecord {
    FindingRecord::new(
        tenant(tenant_seed),
        StableItemId::from_bytes([seed; 32]),
        RuleFingerprint::from_bytes([seed.wrapping_add(1); 32]),
        key_secret_hash(
            &TenantSecretKey::from_bytes([tenant_seed; 32]),
            &NormHash::from_digest([seed.wrapping_add(2); 32]),
        ),
    )
}

fn occurrence_record(
    tenant_seed: u8,
    finding: &FindingRecord,
    version_seed: u8,
    byte_offset: u64,
) -> OccurrenceRecord {
    OccurrenceRecord::new(
        tenant(tenant_seed),
        finding.finding_id(),
        ObjectVersionId::from_bytes([version_seed; 32]),
        byte_offset,
        NonZeroU64::new((version_seed as u64) + 1).unwrap(),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "test helper mirrors the flat observation durable row shape"
)]
fn observation_record(
    tenant_seed: u8,
    occurrence: &OccurrenceRecord,
    policy_seed: u8,
    ovid_seed: u8,
    run_id: u64,
    shard_id: u64,
    fence_epoch: u64,
    seen_at: u64,
) -> ObservationRecord {
    ObservationRecord::new(
        tenant(tenant_seed),
        occurrence.occurrence_id(),
        policy(policy_seed),
        ovid(ovid_seed),
        RunId::from_raw(run_id),
        ShardId::from_raw(shard_id),
        FenceEpoch::from_raw(fence_epoch),
        LogicalTime::from_raw(seen_at),
    )
}

#[test]
fn done_ledger_merge_is_monotonic_and_batch_get_is_positional() {
    let store = InMemoryDoneLedger::new();

    let initial = done_record(
        1,
        2,
        3,
        FailedRetryable,
        100,
        0,
        provenance(10, 11, 12, 20, 30),
        Some("TIMEOUT"),
    );
    store.batch_upsert(&[initial]).unwrap().wait().unwrap();

    let scanned = done_record(
        1,
        2,
        3,
        ScannedClean,
        90,
        0,
        provenance(20, 21, 22, 40, 50),
        None,
    );
    store
        .batch_upsert(std::slice::from_ref(&scanned))
        .unwrap()
        .wait()
        .unwrap();

    let downgrade_attempt = done_record(
        1,
        2,
        3,
        FailedPermanent,
        200,
        0,
        provenance(30, 31, 32, 60, 70),
        Some("FATAL"),
    );
    store
        .batch_upsert(&[downgrade_attempt])
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.get_record(scanned.key()).unwrap().unwrap();
    assert_eq!(stored.status(), ScannedClean);
    assert_eq!(stored.bytes_scanned(), 200);
    assert_eq!(stored.findings_count(), 0);
    assert_eq!(stored.provenance(), scanned.provenance());
    assert_eq!(stored.error_code(), None);

    let rows = store
        .batch_get(tenant(1), policy(2), &[ovid(3), ovid(9)])
        .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0], Some(stored));
    assert_eq!(rows[1], None);
}

#[test]
fn done_ledger_snapshot_is_sorted_for_deterministic_assertions() {
    let store = InMemoryDoneLedger::new();
    let later_key = done_record(
        1,
        2,
        9,
        ScannedWithFindings,
        123,
        2,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let earlier_key = done_record(
        1,
        2,
        1,
        ScannedClean,
        45,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );

    store
        .batch_upsert(&[later_key, earlier_key])
        .unwrap()
        .wait()
        .unwrap();

    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].key().ovid_hash(), ovid(1));
    assert_eq!(snapshot[1].key().ovid_hash(), ovid(9));
}

#[test]
fn done_ledger_handles_block_until_release_and_support_manual_controls() {
    let store = InMemoryDoneLedger::with_auto_complete(false);

    let first = done_record(
        1,
        2,
        3,
        ScannedClean,
        10,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let second = done_record(
        1,
        2,
        4,
        ScannedWithFindings,
        20,
        1,
        provenance(6, 7, 8, 9, 10),
        None,
    );

    let handle1 = store.batch_upsert(&[first]).unwrap();
    let handle2 = store.batch_upsert(&[second]).unwrap();
    let op1 = handle1.operation_id();
    let op2 = handle2.operation_id();

    assert_eq!(store.pending_ids().unwrap(), vec![op1, op2]);

    let (tx, rx) = mpsc::channel();
    let waiter = thread::spawn(move || tx.send(handle1.wait()).unwrap());
    assert!(rx.recv_timeout(Duration::from_millis(100)).is_err());

    assert_eq!(
        store.release_next(CompletionOrder::NewestFirst).unwrap(),
        Some(op2)
    );
    assert_eq!(handle2.wait().unwrap().record_count(), 1);
    assert_eq!(store.pending_count().unwrap(), 1);

    assert!(store.release_specific(op1).unwrap());
    assert_eq!(
        rx.recv_timeout(Duration::from_secs(1))
            .unwrap()
            .unwrap()
            .record_count(),
        1
    );
    waiter.join().unwrap();
    assert!(!store.release_specific(op1).unwrap());

    store.fail_next_commits(1).unwrap();
    let failing = done_record(
        1,
        2,
        5,
        FailedPermanent,
        30,
        0,
        provenance(11, 12, 13, 14, 15),
        Some("UPSTREAM"),
    );
    let failing_handle = store.batch_upsert(&[failing]).unwrap();
    let failing_op = failing_handle.operation_id();
    assert!(store.release_specific(failing_op).unwrap());
    assert_eq!(
        failing_handle.wait().unwrap_err(),
        InMemoryPersistenceError::InjectedCommitFailure {
            store: InMemoryStoreKind::DoneLedger,
        }
    );
    assert_eq!(store.pending_count().unwrap(), 0);
}

#[test]
fn findings_upsert_is_idempotent_and_merges_observation_provenance() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);
    let first_observation = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 80);

    let findings = [finding.clone()];
    let occurrences = [occurrence.clone()];
    let observations = [first_observation.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap()
        .wait()
        .unwrap();

    let updated_observation = observation_record(1, &occurrence, 30, 40, 90, 91, 92, 100)
        .with_location(
            Location::try_new("repo/path".into(), Some("https://example.test".into())).unwrap(),
        );
    let updated_observations = [updated_observation.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &updated_observations))
        .unwrap()
        .wait()
        .unwrap();

    store
        .upsert_batch(FindingsUpsertBatch::new(&findings, &occurrences, &[]))
        .unwrap()
        .wait()
        .unwrap();

    assert_eq!(store.findings_snapshot().unwrap(), vec![finding.clone()]);
    assert_eq!(
        store.occurrences_snapshot().unwrap(),
        vec![occurrence.clone()]
    );

    let observations = store.observations_snapshot().unwrap();
    assert_eq!(observations.len(), 1);
    let stored = &observations[0];
    assert_eq!(stored.observation_id(), first_observation.observation_id());
    assert_eq!(stored.seen_at(), LogicalTime::from_raw(100));
    assert_eq!(stored.run_id(), RunId::from_raw(90));
    assert_eq!(stored.shard_id(), ShardId::from_raw(91));
    assert_eq!(stored.fence_epoch(), FenceEpoch::from_raw(92));
    assert_eq!(stored.location().unwrap().display(), "repo/path");

    assert_eq!(
        store
            .get_finding(finding.tenant_id(), finding.finding_id())
            .unwrap(),
        Some(finding)
    );
    assert_eq!(
        store
            .get_occurrence(occurrence.tenant_id(), occurrence.occurrence_id())
            .unwrap(),
        Some(occurrence)
    );
    assert_eq!(
        store
            .get_observation(
                first_observation.tenant_id(),
                first_observation.observation_id(),
            )
            .unwrap()
            .unwrap()
            .seen_at(),
        LogicalTime::from_raw(100)
    );
}

#[test]
fn findings_upsert_rejects_missing_finding_without_partial_commit() {
    let store = InMemoryFindingsSink::new();
    let durable_candidate = finding_record(1, 10);
    let missing_parent = finding_record(1, 11);
    let bad_occurrence = occurrence_record(1, &missing_parent, 12, 200);

    let findings = [durable_candidate];
    let occurrences = [bad_occurrence.clone()];
    let error = store
        .upsert_batch(FindingsUpsertBatch::new(&findings, &occurrences, &[]))
        .unwrap()
        .wait()
        .unwrap_err();

    assert_eq!(
        error,
        InMemoryPersistenceError::MissingFinding {
            tenant_id: tenant(1),
            finding_id: missing_parent.finding_id(),
            occurrence_id: bad_occurrence.occurrence_id(),
        }
    );
    assert!(store.findings_snapshot().unwrap().is_empty());
    assert!(store.occurrences_snapshot().unwrap().is_empty());
    assert!(store.observations_snapshot().unwrap().is_empty());
}

#[test]
fn findings_upsert_rejects_missing_occurrence_without_partial_commit() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let missing_occurrence = occurrence_record(1, &finding, 12, 200);
    let observation = observation_record(1, &missing_occurrence, 30, 40, 50, 60, 70, 80);

    let observations = [observation.clone()];
    let error = store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &observations))
        .unwrap()
        .wait()
        .unwrap_err();

    assert_eq!(
        error,
        InMemoryPersistenceError::MissingOccurrence {
            tenant_id: tenant(1),
            occurrence_id: missing_occurrence.occurrence_id(),
            observation_id: observation.observation_id(),
        }
    );
    assert!(store.findings_snapshot().unwrap().is_empty());
    assert!(store.occurrences_snapshot().unwrap().is_empty());
    assert!(store.observations_snapshot().unwrap().is_empty());
}

#[test]
fn findings_submission_failures_and_release_all_are_deterministic() {
    let store = InMemoryFindingsSink::with_auto_complete(false);
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);
    let observation = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 80);

    let findings = [finding];
    let occurrences = [occurrence];
    let observations = [observation];

    store.fail_next_submissions(1).unwrap();
    let error = store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap_err();
    assert_eq!(
        error,
        InMemoryPersistenceError::InjectedSubmissionFailure {
            store: InMemoryStoreKind::Findings,
        }
    );
    assert_eq!(store.pending_count().unwrap(), 0);

    let handle1 = store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap();
    let handle2 = store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap();

    assert_eq!(
        store.pending_ids().unwrap(),
        vec![handle1.operation_id(), handle2.operation_id()]
    );
    assert_eq!(store.release_all(CompletionOrder::OldestFirst).unwrap(), 2);
    assert_eq!(handle1.wait().unwrap().finding_count(), 1);
    assert_eq!(handle2.wait().unwrap().observation_count(), 1);
    assert_eq!(store.pending_count().unwrap(), 0);
}

// ---------------------------------------------------------------------------
// Consistency and correctness edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn release_specific_does_not_leave_stale_order_entries() {
    let store = InMemoryDoneLedger::with_auto_complete(false);
    let mut handles = Vec::new();
    let mut op_ids = Vec::new();

    for i in 0u8..5 {
        let record = done_record(
            1,
            2,
            i + 10,
            ScannedClean,
            10,
            0,
            provenance(1, 2, 3, 4, 5),
            None,
        );
        let handle = store.batch_upsert(&[record]).unwrap();
        op_ids.push(handle.operation_id());
        handles.push(handle);
    }

    assert_eq!(store.pending_count().unwrap(), 5);

    for &op_id in &op_ids {
        assert!(store.release_specific(op_id).unwrap());
    }

    for handle in handles {
        handle.wait().unwrap();
    }

    assert_eq!(store.pending_count().unwrap(), 0);
    assert!(store.pending_ids().unwrap().is_empty());

    let new_record = done_record(
        1,
        2,
        99,
        ScannedClean,
        10,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );
    let new_handle = store.batch_upsert(&[new_record]).unwrap();
    let new_op = new_handle.operation_id();

    let pending = store.pending_ids().unwrap();
    assert_eq!(pending, vec![new_op]);

    assert_eq!(
        store.release_next(CompletionOrder::OldestFirst).unwrap(),
        Some(new_op)
    );
    new_handle.wait().unwrap();
}

#[test]
fn findings_receipt_counts_deduplicated_rows_not_raw_input() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);

    let findings = [finding.clone(), finding.clone()];
    let receipt = store
        .upsert_batch(FindingsUpsertBatch::new(&findings, &[], &[]))
        .unwrap()
        .wait()
        .unwrap();

    assert_eq!(
        receipt.finding_count(),
        1,
        "receipt should count deduplicated findings, not raw input length"
    );
    assert_eq!(store.findings_snapshot().unwrap().len(), 1);
}

// ---------------------------------------------------------------------------
// Empty-batch handling and identity-conflict edge cases
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_empty_batch_returns_zero_receipt() {
    let store = InMemoryDoneLedger::new();
    let receipt = store.batch_upsert(&[]).unwrap().wait().unwrap();
    assert_eq!(receipt.record_count(), 0);
    assert_eq!(receipt.scanned_count(), 0);
    assert_eq!(receipt.findings_count(), 0);
    assert!(store.snapshot().unwrap().is_empty());
}

#[test]
fn findings_empty_batch_returns_zero_receipt() {
    let store = InMemoryFindingsSink::new();
    let receipt = store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &[]))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(receipt.finding_count(), 0);
    assert_eq!(receipt.occurrence_count(), 0);
    assert_eq!(receipt.observation_count(), 0);
}

#[test]
fn observation_conflict_on_mismatched_identity_fields() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    let obs_a = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 80);
    let obs_b = observation_record(1, &occurrence, 30, 41, 50, 60, 70, 90);
    assert_eq!(
        obs_a.observation_id(),
        obs_b.observation_id(),
        "precondition: observations must share the same derived ID"
    );

    let findings = [finding];
    let occurrences = [occurrence];

    let obs_a_arr = [obs_a.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &obs_a_arr,
        ))
        .unwrap()
        .wait()
        .unwrap();

    let obs_b_arr = [obs_b.clone()];
    let error = store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &obs_b_arr))
        .unwrap()
        .wait()
        .unwrap_err();

    assert_eq!(
        error,
        InMemoryPersistenceError::ObservationConflict {
            tenant_id: obs_b.tenant_id(),
            observation_id: obs_b.observation_id(),
        }
    );

    let stored = store.observations_snapshot().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].seen_at(), obs_a.seen_at());
}

#[test]
fn observation_conflict_within_single_batch() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    let obs_a = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 80);
    let obs_b = observation_record(1, &occurrence, 30, 41, 50, 60, 70, 90);

    let findings = [finding];
    let occurrences = [occurrence];
    let observations = [obs_a, obs_b];

    let error = store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap()
        .wait()
        .unwrap_err();

    assert!(matches!(
        error,
        InMemoryPersistenceError::ObservationConflict { .. }
    ));
    assert!(store.findings_snapshot().unwrap().is_empty());
}

#[test]
fn delay_next_writes_overrides_auto_complete_for_exact_count() {
    let store = InMemoryDoneLedger::new();

    store.delay_next_writes(1).unwrap();

    let delayed = done_record(
        1,
        2,
        3,
        ScannedClean,
        10,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let delayed_handle = store.batch_upsert(&[delayed]).unwrap();

    assert_eq!(
        store.pending_count().unwrap(),
        1,
        "first write should be delayed"
    );

    let auto = done_record(
        1,
        2,
        4,
        ScannedWithFindings,
        20,
        1,
        provenance(6, 7, 8, 9, 10),
        None,
    );
    let auto_receipt = store
        .batch_upsert(std::slice::from_ref(&auto))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(auto_receipt.record_count(), 1);
    assert!(store.get_record(auto.key()).unwrap().is_some());

    assert_eq!(store.pending_count().unwrap(), 1);
    store.release_all(CompletionOrder::OldestFirst).unwrap();
    delayed_handle.wait().unwrap();
    assert_eq!(store.pending_count().unwrap(), 0);
}

#[test]
fn done_ledger_intra_batch_duplicate_keys_merge_correctly() {
    let store = InMemoryDoneLedger::new();

    let first = done_record(
        1,
        2,
        3,
        FailedRetryable,
        100,
        0,
        provenance(1, 2, 3, 4, 5),
        Some("TIMEOUT"),
    );
    let second = done_record(
        1,
        2,
        3,
        ScannedClean,
        200,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );

    let receipt = store
        .batch_upsert(&[first.clone(), second])
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(receipt.record_count(), 2);

    let stored = store.get_record(first.key()).unwrap().unwrap();
    assert_eq!(stored.status(), ScannedClean);
    assert_eq!(stored.bytes_scanned(), 200);
    assert_eq!(stored.error_code(), None);
}

// ---------------------------------------------------------------------------
// Merge transition clears stale metadata
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_merge_failure_to_scanned_clean_clears_findings_count() {
    let store = InMemoryDoneLedger::new();

    // Existing: FailedRetryable with findings_count=3 (valid — failure statuses
    // accept any count).
    let failure = done_record(
        1,
        2,
        3,
        FailedRetryable,
        100,
        3,
        provenance(10, 11, 12, 20, 30),
        Some("TIMEOUT"),
    );
    store
        .batch_upsert(std::slice::from_ref(&failure))
        .unwrap()
        .wait()
        .unwrap();

    // Incoming: ScannedClean with findings_count=0 (valid — ScannedClean
    // requires 0). The lattice join promotes to ScannedClean (rank 10 > rank 1).
    // A naive max(3, 0) would pair findings_count=3 with ScannedClean, violating
    // the status/count invariant. The merge must reset findings_count to 0.
    let clean = done_record(
        1,
        2,
        3,
        ScannedClean,
        200,
        0,
        provenance(20, 21, 22, 40, 50),
        None,
    );
    store
        .batch_upsert(std::slice::from_ref(&clean))
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.get_record(failure.key()).unwrap().unwrap();
    assert_eq!(stored.status(), ScannedClean);
    assert_eq!(stored.findings_count(), 0);
    assert_eq!(stored.bytes_scanned(), 200);
    assert_eq!(stored.error_code(), None);
}

// ---------------------------------------------------------------------------
// Delay injection and concurrent write ordering
// ---------------------------------------------------------------------------

#[test]
fn done_ledger_delay_next_writes_delays_exact_count() {
    let store = InMemoryDoneLedger::new();
    store.delay_next_writes(2).unwrap();

    let r1 = done_record(
        1,
        2,
        10,
        ScannedClean,
        10,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let r2 = done_record(
        1,
        2,
        11,
        ScannedClean,
        20,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );
    let r3 = done_record(
        1,
        2,
        12,
        ScannedWithFindings,
        30,
        1,
        provenance(11, 12, 13, 14, 15),
        None,
    );

    let h1 = store.batch_upsert(std::slice::from_ref(&r1)).unwrap();
    let h2 = store.batch_upsert(std::slice::from_ref(&r2)).unwrap();

    assert_eq!(store.pending_count().unwrap(), 2);

    let receipt3 = store
        .batch_upsert(std::slice::from_ref(&r3))
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(receipt3.record_count(), 1);
    assert!(store.get_record(r3.key()).unwrap().is_some());

    assert_eq!(store.pending_count().unwrap(), 2);

    assert_eq!(store.release_all(CompletionOrder::OldestFirst).unwrap(), 2);
    h1.wait().unwrap();
    h2.wait().unwrap();
    assert_eq!(store.pending_count().unwrap(), 0);
    assert!(store.get_record(r1.key()).unwrap().is_some());
    assert!(store.get_record(r2.key()).unwrap().is_some());
}

#[test]
fn multiple_threads_wait_on_different_handles() {
    let store = InMemoryDoneLedger::with_auto_complete(false);

    let r1 = done_record(
        1,
        2,
        10,
        ScannedClean,
        10,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let r2 = done_record(
        1,
        2,
        11,
        ScannedClean,
        20,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );

    let h1 = store.batch_upsert(std::slice::from_ref(&r1)).unwrap();
    let h2 = store.batch_upsert(std::slice::from_ref(&r2)).unwrap();

    let (tx1, rx1) = mpsc::channel();
    let (tx2, rx2) = mpsc::channel();

    let t1 = thread::spawn(move || tx1.send(h1.wait()).unwrap());
    let t2 = thread::spawn(move || tx2.send(h2.wait()).unwrap());

    assert!(rx1.recv_timeout(Duration::from_millis(50)).is_err());
    assert!(rx2.recv_timeout(Duration::from_millis(50)).is_err());

    store.release_all(CompletionOrder::OldestFirst).unwrap();

    let receipt1 = rx1.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    let receipt2 = rx2.recv_timeout(Duration::from_secs(2)).unwrap().unwrap();
    assert_eq!(receipt1.record_count(), 1);
    assert_eq!(receipt2.record_count(), 1);

    t1.join().unwrap();
    t2.join().unwrap();
}

// ---------------------------------------------------------------------------
// Release queue edge cases
// ---------------------------------------------------------------------------

#[test]
fn release_next_returns_none_on_empty_queue() {
    let store = InMemoryDoneLedger::with_auto_complete(false);

    assert_eq!(
        store.release_next(CompletionOrder::OldestFirst).unwrap(),
        None
    );
    assert_eq!(
        store.release_next(CompletionOrder::NewestFirst).unwrap(),
        None
    );

    let findings_store = InMemoryFindingsSink::with_auto_complete(false);
    assert_eq!(
        findings_store
            .release_next(CompletionOrder::OldestFirst)
            .unwrap(),
        None
    );
    assert_eq!(
        findings_store
            .release_next(CompletionOrder::NewestFirst)
            .unwrap(),
        None
    );
}

#[test]
fn observation_merge_preserves_location_from_either_record() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    // First observation: later seen_at, no location.
    let obs_no_loc = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 100);

    let findings = [finding.clone()];
    let occurrences = [occurrence.clone()];
    let observations = [obs_no_loc.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &observations,
        ))
        .unwrap()
        .wait()
        .unwrap();

    // Second observation: earlier seen_at, but with location.
    let obs_with_loc = observation_record(1, &occurrence, 30, 40, 90, 91, 92, 80).with_location(
        Location::try_new("repo/path".into(), Some("https://example.test".into())).unwrap(),
    );
    let observations2 = [obs_with_loc];
    store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &observations2))
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.observations_snapshot().unwrap();
    assert_eq!(stored.len(), 1);
    // Provenance from the winner (higher seen_at = 100).
    assert_eq!(stored[0].seen_at(), LogicalTime::from_raw(100));
    assert_eq!(stored[0].run_id(), RunId::from_raw(50));
    // Location adopted from the fallback chain (incoming had it).
    assert!(
        stored[0].location().is_some(),
        "location should be preserved from the record that has it"
    );
    assert_eq!(stored[0].location().unwrap().display(), "repo/path");
}

#[test]
fn combined_failure_modes_are_independent() {
    let store = InMemoryDoneLedger::with_auto_complete(false);

    store.fail_next_submissions(1).unwrap();
    store.fail_next_commits(1).unwrap();

    let r1 = done_record(
        1,
        2,
        10,
        ScannedClean,
        10,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    );
    let r2 = done_record(
        1,
        2,
        11,
        ScannedClean,
        20,
        0,
        provenance(6, 7, 8, 9, 10),
        None,
    );
    let r3 = done_record(
        1,
        2,
        12,
        ScannedWithFindings,
        30,
        1,
        provenance(11, 12, 13, 14, 15),
        None,
    );

    // First submission hits the submission failure.
    let err = store.batch_upsert(std::slice::from_ref(&r1)).unwrap_err();
    assert_eq!(
        err,
        InMemoryPersistenceError::InjectedSubmissionFailure {
            store: InMemoryStoreKind::DoneLedger,
        }
    );

    // Second submission succeeds (submission counter exhausted), but commit fails.
    let h2 = store.batch_upsert(std::slice::from_ref(&r2)).unwrap();
    store.release_specific(h2.operation_id()).unwrap();
    let err = h2.wait().unwrap_err();
    assert_eq!(
        err,
        InMemoryPersistenceError::InjectedCommitFailure {
            store: InMemoryStoreKind::DoneLedger,
        }
    );

    // Third submission succeeds completely (both counters exhausted).
    let h3 = store.batch_upsert(std::slice::from_ref(&r3)).unwrap();
    store.release_specific(h3.operation_id()).unwrap();
    let receipt = h3.wait().unwrap();
    assert_eq!(receipt.record_count(), 1);
    assert!(store.get_record(r3.key()).unwrap().is_some());
}

#[test]
fn get_record_and_get_finding_return_none_for_missing_keys() {
    let done_store = InMemoryDoneLedger::new();
    let key = DoneLedgerKey::new(tenant(1), policy(2), ovid(3));
    assert_eq!(done_store.get_record(key).unwrap(), None);

    let findings_store = InMemoryFindingsSink::new();
    assert_eq!(
        findings_store
            .get_finding(tenant(1), FindingId::from_bytes([1; 32]))
            .unwrap(),
        None
    );
    assert_eq!(
        findings_store
            .get_occurrence(tenant(1), OccurrenceId::from_bytes([1; 32]))
            .unwrap(),
        None
    );
    assert_eq!(
        findings_store
            .get_observation(tenant(1), ObservationId::from_bytes([1; 32]))
            .unwrap(),
        None
    );
}

// ---------------------------------------------------------------------------
// Batch validation rejects cross-tenant submissions
// ---------------------------------------------------------------------------

/// Submit a findings batch containing records from two different tenants.
/// The pre-lock tenant consistency check should reject it immediately with
/// `BatchValidation(InconsistentTenant)`, and no durable state should be
/// mutated.
///
/// `UnknownOperation` and `Poisoned` are defensive-only variants that are
/// unreachable through the public API under correct usage — they guard against
/// internal misuse (double-wait, mutex poisoning) and are not tested here.
#[test]
fn inconsistent_tenant_batch_is_rejected_before_lock() {
    let store = InMemoryFindingsSink::new();
    let finding_a = finding_record(1, 10);
    let finding_b = finding_record(2, 11);

    let findings = [finding_a, finding_b];
    let error = store
        .upsert_batch(FindingsUpsertBatch::new(&findings, &[], &[]))
        .unwrap_err();

    assert_eq!(
        error,
        InMemoryPersistenceError::BatchValidation(PersistenceInputError::InconsistentTenant),
    );

    // Durable state must be empty — validation fires before the lock is acquired.
    assert!(store.findings_snapshot().unwrap().is_empty());
    assert!(store.occurrences_snapshot().unwrap().is_empty());
    assert!(store.observations_snapshot().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// Observation merge tie-breaking and replay stability
// ---------------------------------------------------------------------------

/// Equal `seen_at`, both have location → existing wins (stable under replay).
#[test]
fn observation_merge_equal_seen_at_both_with_location_keeps_existing() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    let existing_obs = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 100).with_location(
        Location::try_new("existing/path".into(), Some("https://existing.test".into())).unwrap(),
    );

    let findings = [finding.clone()];
    let occurrences = [occurrence.clone()];
    let existing_arr = [existing_obs.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &existing_arr,
        ))
        .unwrap()
        .wait()
        .unwrap();

    // Same seen_at (100), both with location → existing provenance wins.
    let incoming_obs = observation_record(1, &occurrence, 30, 40, 90, 91, 92, 100).with_location(
        Location::try_new("incoming/path".into(), Some("https://incoming.test".into())).unwrap(),
    );
    let incoming_arr = [incoming_obs];
    store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &incoming_arr))
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.observations_snapshot().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].seen_at(), LogicalTime::from_raw(100));
    // Existing provenance wins → run_id from existing record.
    assert_eq!(stored[0].run_id(), RunId::from_raw(50));
    assert_eq!(stored[0].location().unwrap().display(), "existing/path");
}

/// Earlier incoming `seen_at` → existing provenance preserved.
#[test]
fn observation_merge_earlier_incoming_keeps_existing_provenance() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    // Existing has seen_at=200.
    let existing_obs = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 200);

    let findings = [finding.clone()];
    let occurrences = [occurrence.clone()];
    let existing_arr = [existing_obs.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &existing_arr,
        ))
        .unwrap()
        .wait()
        .unwrap();

    // Incoming has earlier seen_at=100 → existing wins entirely.
    let incoming_obs = observation_record(1, &occurrence, 30, 40, 90, 91, 92, 100).with_location(
        Location::try_new("incoming/path".into(), Some("https://incoming.test".into())).unwrap(),
    );
    let incoming_arr = [incoming_obs];
    store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &incoming_arr))
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.observations_snapshot().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].seen_at(), LogicalTime::from_raw(200));
    assert_eq!(stored[0].run_id(), RunId::from_raw(50));
    // Location from incoming is adopted through the fallback chain even though
    // existing won provenance (existing has no location).
    assert!(
        stored[0].location().is_some(),
        "location should be recovered from the fallback chain"
    );
    assert_eq!(stored[0].location().unwrap().display(), "incoming/path");
}

/// Equal `seen_at`, existing has location, incoming does not → existing wins.
#[test]
fn observation_merge_equal_seen_at_existing_has_location_keeps_existing() {
    let store = InMemoryFindingsSink::new();
    let finding = finding_record(1, 10);
    let occurrence = occurrence_record(1, &finding, 20, 100);

    let existing_obs = observation_record(1, &occurrence, 30, 40, 50, 60, 70, 100).with_location(
        Location::try_new("existing/path".into(), Some("https://existing.test".into())).unwrap(),
    );

    let findings = [finding.clone()];
    let occurrences = [occurrence.clone()];
    let existing_arr = [existing_obs.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(
            &findings,
            &occurrences,
            &existing_arr,
        ))
        .unwrap()
        .wait()
        .unwrap();

    // Same seen_at (100), existing has location, incoming does not.
    // The `else` branch fires (existing wins), keeping existing provenance.
    let incoming_obs = observation_record(1, &occurrence, 30, 40, 90, 91, 92, 100);
    let incoming_arr = [incoming_obs];
    store
        .upsert_batch(FindingsUpsertBatch::new(&[], &[], &incoming_arr))
        .unwrap()
        .wait()
        .unwrap();

    let stored = store.observations_snapshot().unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].seen_at(), LogicalTime::from_raw(100));
    assert_eq!(stored[0].run_id(), RunId::from_raw(50));
    assert_eq!(stored[0].location().unwrap().display(), "existing/path");
}
