use std::num::NonZeroU64;

use gossip_contracts::identity::LogicalTime;
use gossip_contracts::{
    identity::{
        FenceEpoch, NormHash, ObjectVersionId, RuleFingerprint, RunId, ShardId, StableItemId,
        TenantSecretKey, key_secret_hash,
    },
    persistence::{
        self, CommitHandle, DoneLedger, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
        DoneLedgerStatus, FindingRecord, FindingsSink, FindingsUpsertBatch, ObservationRecord,
        OccurrenceRecord, run_conformance,
    },
    test_util::{ovid, policy, tenant},
};
use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};

#[test]
fn in_memory_backends_pass_persistence_conformance() {
    let done_ledger = InMemoryDoneLedger::new();
    let findings = InMemoryFindingsSink::new();

    let report = run_conformance(&done_ledger, &findings)
        .unwrap_or_else(|err| panic!("in-memory persistence conformance failed: {err}"));

    assert_eq!(report.done_ledger_checks, 4);
    assert_eq!(report.findings_checks, 4);
    assert_eq!(report.redaction_checks, 3);
    assert_eq!(report.total_checks(), 11);
}

/// The reference in-memory backend intentionally accepts batches of any size.
/// Real persistence backends may enforce `RECOMMENDED_MAX_BATCH_SIZE` as a hard
/// limit, but the test-support backend deliberately omits this constraint so
/// that conformance tests and simulations can submit arbitrarily large batches
/// without tripping resource guards.
///
/// This test documents that design choice by asserting the constant exists and
/// has the expected value — a compile-time canary that fires if the contract
/// constant is ever removed or renamed.
#[test]
fn recommended_max_batch_size_constant_is_documented() {
    assert_eq!(
        persistence::RECOMMENDED_MAX_BATCH_SIZE,
        10_000,
        "RECOMMENDED_MAX_BATCH_SIZE should remain at 10,000; \
         in-memory backends intentionally do not enforce it"
    );
}

// ---------------------------------------------------------------------------
// Multi-tenant isolation tests
// ---------------------------------------------------------------------------

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

/// Two tenants write done-ledger records sharing the same policy/ovid seeds.
/// `batch_get` for each tenant must return only that tenant's rows.
#[test]
fn done_ledger_batch_get_isolates_tenants() {
    let store = InMemoryDoneLedger::new();

    let record_a = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant(1), policy(2), ovid(3)),
        DoneLedgerStatus::ScannedClean,
        100,
        0,
        provenance(1, 2, 3, 4, 5),
        None,
    )
    .unwrap();

    let record_b = DoneLedgerRecord::try_new(
        DoneLedgerKey::new(tenant(2), policy(2), ovid(3)),
        DoneLedgerStatus::ScannedWithFindings,
        200,
        1,
        provenance(6, 7, 8, 9, 10),
        None,
    )
    .unwrap();

    store
        .batch_upsert(&[record_a.clone(), record_b.clone()])
        .unwrap()
        .wait()
        .unwrap();

    // Tenant 1 sees only its own row.
    let rows_a = store.batch_get(tenant(1), policy(2), &[ovid(3)]).unwrap();
    assert_eq!(rows_a.len(), 1);
    assert_eq!(
        rows_a[0].as_ref().unwrap().status(),
        DoneLedgerStatus::ScannedClean
    );

    // Tenant 2 sees only its own row.
    let rows_b = store.batch_get(tenant(2), policy(2), &[ovid(3)]).unwrap();
    assert_eq!(rows_b.len(), 1);
    assert_eq!(
        rows_b[0].as_ref().unwrap().status(),
        DoneLedgerStatus::ScannedWithFindings
    );

    // A third, non-existent tenant sees nothing.
    let rows_c = store.batch_get(tenant(3), policy(2), &[ovid(3)]).unwrap();
    assert_eq!(rows_c, vec![None]);
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

/// Two tenants each write a finding/occurrence/observation triple. Snapshots
/// and per-key lookups must return only the queried tenant's data.
#[test]
fn findings_snapshots_isolate_tenants() {
    let store = InMemoryFindingsSink::new();

    let finding_a = finding_record(1, 10);
    let occurrence_a = occurrence_record(1, &finding_a, 20, 100);
    let observation_a = observation_record(1, &occurrence_a, 30, 40, 50, 60, 70, 80);

    let finding_b = finding_record(2, 10);
    let occurrence_b = occurrence_record(2, &finding_b, 20, 100);
    let observation_b = observation_record(2, &occurrence_b, 30, 40, 90, 91, 92, 93);

    // Each tenant's batch is submitted independently (single-tenant batches).
    let fa = [finding_a.clone()];
    let oa = [occurrence_a.clone()];
    let obsa = [observation_a.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(&fa, &oa, &obsa))
        .unwrap()
        .wait()
        .unwrap();

    let fb = [finding_b.clone()];
    let ob = [occurrence_b.clone()];
    let obsb = [observation_b.clone()];
    store
        .upsert_batch(FindingsUpsertBatch::new(&fb, &ob, &obsb))
        .unwrap()
        .wait()
        .unwrap();

    // Snapshots contain both tenants' data (2 each).
    assert_eq!(store.findings_snapshot().unwrap().len(), 2);
    assert_eq!(store.occurrences_snapshot().unwrap().len(), 2);
    assert_eq!(store.observations_snapshot().unwrap().len(), 2);

    // Per-key lookups return only the matching tenant's record.
    assert_eq!(
        store
            .get_finding(tenant(1), finding_a.finding_id())
            .unwrap(),
        Some(finding_a.clone())
    );
    assert_eq!(
        store
            .get_finding(tenant(2), finding_a.finding_id())
            .unwrap(),
        None,
        "tenant 2 should not see tenant 1's finding even with same finding_id"
    );

    assert_eq!(
        store
            .get_occurrence(tenant(2), occurrence_b.occurrence_id())
            .unwrap(),
        Some(occurrence_b.clone())
    );
    assert_eq!(
        store
            .get_occurrence(tenant(1), occurrence_b.occurrence_id())
            .unwrap(),
        None,
        "tenant 1 should not see tenant 2's occurrence"
    );
}
