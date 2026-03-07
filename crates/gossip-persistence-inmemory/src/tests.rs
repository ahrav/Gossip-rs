use std::{num::NonZeroU64, sync::mpsc, thread, time::Duration};

use gossip_contracts::{
    connector::Location,
    identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, RuleFingerprint, RunId, ShardId,
        StableItemId, TenantSecretKey, key_secret_hash,
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
