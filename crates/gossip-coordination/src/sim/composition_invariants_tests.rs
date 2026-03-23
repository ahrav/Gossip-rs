//! Targeted unit tests for [`CompositionInvariantChecker`].
//!
//! Tests the checker in isolation using fabricated coordinator state
//! (`InMemoryCoordinator` with `seed_shard`), oracle state
//! (`DoneLedgerOracle` with `submit`/`commit`), and write-log entries
//! (built directly). This complements the integration-level coverage
//! from `CompositionSim` tests that run the checker implicitly through
//! `step()`.
//!
//! # Coverage by invariant
//!
//! | Invariant | Tests |
//! |---|---|
//! | C1 (ProvenanceOrphan) | `c1_detects_provenance_orphan`, `c1_valid_provenance_no_violation` |
//! | C2 (FenceExceeded) | `c2_detects_fence_exceeded`, `c2_accepts_equal_fence`, `c2_accepts_stale_fence` |
//! | C3 (WriteAfterTerminal) | `c3_detects_write_after_terminal`, `c3_allows_write_in_same_lifecycle`, `c3_stale_epoch_not_flagged` |
//! | C4 (FencePropagationMismatch) | `c4_detects_fence_mismatch`, `c4_no_violation_when_fences_match`, `c4_uncommitted_entry_not_checked` |
//! | Cross-cutting | `smoke_no_violations_for_valid_state`, `incremental_processing_skips_old_entries` |
//!
//! # Test strategy
//!
//! Each negative test: (1) set up coordinator/oracle/write-log with a
//! specific violation condition, (2) call `check_all`, (3) assert exactly
//! the expected violation variant is returned. Positive tests assert empty
//! violation vectors.

use super::*;
use crate::in_memory::InMemoryCoordinator;
use crate::sim::test_util::{TestRecordBuilder, LEASE_DUR, TENANT};

use gossip_contracts::identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, WorkerId};
use gossip_contracts::persistence::{
    DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
};
use gossip_persistence_inmemory::sim::DoneLedgerOracle;
use gossip_persistence_inmemory::PendingWriteId;

use super::super::composition::ProvenanceEntry;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const RUN: RunId = RunId::from_raw(1);
const SHARD: ShardId = ShardId::from_raw(1);
const SHARD_2: ShardId = ShardId::from_raw(2);
const WORKER: WorkerId = WorkerId::from_raw(1);
const POLICY: PolicyHash = PolicyHash::from_bytes([0x22; 32]);

fn ovid(byte: u8) -> OvidHash {
    OvidHash::from_bytes([byte; 32])
}

fn make_key(byte: u8) -> DoneLedgerKey {
    DoneLedgerKey::new(TENANT, POLICY, ovid(byte))
}

fn make_provenance(run: RunId, shard: ShardId, fence: FenceEpoch) -> DoneLedgerProvenance {
    DoneLedgerProvenance::new(
        run,
        shard,
        fence,
        LogicalTime::from_raw(1),
        LogicalTime::from_raw(2),
    )
}

fn make_record(key: DoneLedgerKey, prov: DoneLedgerProvenance) -> DoneLedgerRecord {
    DoneLedgerRecord::try_new(key, DoneLedgerStatus::ScannedClean, 100, 0, prov, None)
        .expect("valid record")
}

/// Build a coordinator with a single active shard at the given fence epoch.
fn make_coordinator(run: RunId, shard: ShardId, fence: FenceEpoch) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(fence)
        .build(coord.slab_mut());
    coord.seed_shard(record);
    coord
}

/// Build an oracle with one committed record.
fn make_oracle_with_record(record: DoneLedgerRecord) -> DoneLedgerOracle {
    let mut oracle = DoneLedgerOracle::new();
    oracle.submit(PendingWriteId::from_raw(1), vec![record]);
    assert!(oracle.commit(PendingWriteId::from_raw(1)));
    oracle
}

fn make_write_log_entry(
    run: RunId,
    shard: ShardId,
    fence_epoch: FenceEpoch,
    lease_fence: FenceEpoch,
    committed: bool,
    coordinator_completed: bool,
) -> ProvenanceEntry {
    ProvenanceEntry {
        worker: WORKER,
        run_id: run,
        shard_id: shard,
        fence_epoch,
        lease_fence,
        record_count: 1,
        committed,
        coordinator_completed,
    }
}

// ---------------------------------------------------------------------------
// Smoke
// ---------------------------------------------------------------------------

#[test]
fn smoke_no_violations_for_valid_state() {
    let fence = FenceEpoch::from_raw(3);
    let coord = make_coordinator(RUN, SHARD, fence);

    let prov = make_provenance(RUN, SHARD, fence);
    let record = make_record(make_key(0xAA), prov);
    let oracle = make_oracle_with_record(record);

    let write_log = vec![make_write_log_entry(RUN, SHARD, fence, fence, true, false)];

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

// ---------------------------------------------------------------------------
// C1: Provenance referential integrity
// ---------------------------------------------------------------------------

/// Oracle has a committed record whose provenance references a shard that
/// does not exist in the coordinator.
#[test]
fn c1_detects_provenance_orphan() {
    // Coordinator has shard 1 only.
    let coord = make_coordinator(RUN, SHARD, FenceEpoch::from_raw(1));

    // Oracle has a record referencing shard 99 (not in coordinator).
    let orphan_shard = ShardId::from_raw(99);
    let prov = make_provenance(RUN, orphan_shard, FenceEpoch::from_raw(1));
    let record = make_record(make_key(0xBB), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::ProvenanceOrphan {
            run_id, shard_id, ..
        } => {
            assert_eq!(*run_id, RUN);
            assert_eq!(*shard_id, orphan_shard);
        }
        other => panic!("expected ProvenanceOrphan, got: {other:?}"),
    }
}

/// Oracle record provenance references a known shard — no C1 violation.
#[test]
fn c1_valid_provenance_no_violation() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);

    let prov = make_provenance(RUN, SHARD, fence);
    let record = make_record(make_key(0xCC), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

// ---------------------------------------------------------------------------
// C2: Fence consistency
// ---------------------------------------------------------------------------

/// Oracle record has fence_epoch greater than coordinator's current fence.
#[test]
fn c2_detects_fence_exceeded() {
    let coord_fence = FenceEpoch::from_raw(3);
    let coord = make_coordinator(RUN, SHARD, coord_fence);

    // Provenance claims fence 5, but coordinator only knows fence 3.
    let prov = make_provenance(RUN, SHARD, FenceEpoch::from_raw(5));
    let record = make_record(make_key(0xDD), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::FenceExceeded {
            provenance_fence,
            coordinator_fence,
            ..
        } => {
            assert_eq!(*provenance_fence, FenceEpoch::from_raw(5));
            assert_eq!(*coordinator_fence, coord_fence);
        }
        other => panic!("expected FenceExceeded, got: {other:?}"),
    }
}

/// Provenance fence equals coordinator fence — no violation.
#[test]
fn c2_accepts_equal_fence() {
    let fence = FenceEpoch::from_raw(4);
    let coord = make_coordinator(RUN, SHARD, fence);

    let prov = make_provenance(RUN, SHARD, fence);
    let record = make_record(make_key(0xEE), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);
    assert!(viols.is_empty());
}

/// Provenance fence less than coordinator fence (stale write) — no violation.
#[test]
fn c2_accepts_stale_fence() {
    let coord = make_coordinator(RUN, SHARD, FenceEpoch::from_raw(5));

    let prov = make_provenance(RUN, SHARD, FenceEpoch::from_raw(2));
    let record = make_record(make_key(0xFF), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);
    assert!(viols.is_empty());
}

// ---------------------------------------------------------------------------
// C3: No writes after terminal completion
// ---------------------------------------------------------------------------

/// A committed write appears after the same shard-epoch was completed.
#[test]
fn c3_detects_write_after_terminal() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    // First lifecycle: write + complete.
    let entry1 = make_write_log_entry(RUN, SHARD, fence, fence, true, true);
    // Second lifecycle: write for the same triple (should not happen).
    let entry2 = make_write_log_entry(RUN, SHARD, fence, fence, true, false);

    let write_log = vec![entry1, entry2];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::WriteAfterTerminal {
            run_id,
            shard_id,
            fence_epoch,
        } => {
            assert_eq!(*run_id, RUN);
            assert_eq!(*shard_id, SHARD);
            assert_eq!(*fence_epoch, fence);
        }
        other => panic!("expected WriteAfterTerminal, got: {other:?}"),
    }
}

/// The lifecycle that both writes and completes should not trigger C3
/// (the write happens before the completion within the same lifecycle).
#[test]
fn c3_allows_write_in_same_lifecycle() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    // Single lifecycle that writes AND completes — not a violation.
    let entry = make_write_log_entry(RUN, SHARD, fence, fence, true, true);

    let write_log = vec![entry];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

/// A stale-epoch write after completion of a different epoch should not
/// trigger C3 (different fence_epoch means different triple).
#[test]
fn c3_stale_epoch_not_flagged() {
    let fence_v1 = FenceEpoch::from_raw(1);
    let fence_v2 = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence_v2);
    let oracle = DoneLedgerOracle::new();

    // Lifecycle 1: complete at epoch 2.
    let entry1 = make_write_log_entry(RUN, SHARD, fence_v2, fence_v2, true, true);
    // Lifecycle 2: stale write at epoch 1 (different triple, zombie worker).
    let entry2 = make_write_log_entry(RUN, SHARD, fence_v1, fence_v1, true, false);

    let write_log = vec![entry1, entry2];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

// ---------------------------------------------------------------------------
// C4: Fence propagation mismatch
// ---------------------------------------------------------------------------

/// Stale-lease write: lease_fence differs from fence_epoch.
#[test]
fn c4_detects_fence_mismatch() {
    let lease_fence = FenceEpoch::from_raw(3);
    let stale_fence = FenceEpoch::from_raw(1);
    let coord = make_coordinator(RUN, SHARD, lease_fence);
    let oracle = DoneLedgerOracle::new();

    let entry = make_write_log_entry(RUN, SHARD, stale_fence, lease_fence, true, false);

    let write_log = vec![entry];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::FencePropagationMismatch {
            lease_fence: lf,
            provenance_fence: pf,
            shard_id,
        } => {
            assert_eq!(*lf, lease_fence);
            assert_eq!(*pf, stale_fence);
            assert_eq!(*shard_id, SHARD);
        }
        other => panic!("expected FencePropagationMismatch, got: {other:?}"),
    }
}

/// Normal lifecycle: lease_fence == fence_epoch — no C4 violation.
#[test]
fn c4_no_violation_when_fences_match() {
    let fence = FenceEpoch::from_raw(3);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    let entry = make_write_log_entry(RUN, SHARD, fence, fence, true, false);

    let write_log = vec![entry];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty());
}

/// Uncommitted entries are not checked for C4 (the write never landed).
#[test]
fn c4_uncommitted_entry_not_checked() {
    let lease_fence = FenceEpoch::from_raw(3);
    let stale_fence = FenceEpoch::from_raw(1);
    let coord = make_coordinator(RUN, SHARD, lease_fence);
    let oracle = DoneLedgerOracle::new();

    // Fence mismatch, but committed=false — should not fire C4.
    let entry = make_write_log_entry(RUN, SHARD, stale_fence, lease_fence, false, false);

    let write_log = vec![entry];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty());
}

// ---------------------------------------------------------------------------
// Cross-cutting: incremental processing
// ---------------------------------------------------------------------------

/// Calling check_all twice with the same write_log should not re-process
/// old entries (C3 should not double-fire).
#[test]
fn incremental_processing_skips_old_entries() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    let mut write_log = vec![make_write_log_entry(RUN, SHARD, fence, fence, true, true)];

    let mut checker = CompositionInvariantChecker::new();

    // First call: processes entry, adds to completed set.
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty());

    // Second call with same write_log: no new entries to process.
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty());

    // Third call with a new violating entry appended.
    write_log.push(make_write_log_entry(RUN, SHARD, fence, fence, true, false));
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert_eq!(viols.len(), 1);
    assert!(matches!(
        viols[0],
        CrossComponentViolation::WriteAfterTerminal { .. }
    ));
}

/// Multiple shards: violations are independent per shard.
#[test]
fn independent_per_shard() {
    let fence = FenceEpoch::from_raw(2);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed two shards.
    let r1 = TestRecordBuilder::new(TENANT, RUN, SHARD)
        .fence_epoch(fence)
        .build(coord.slab_mut());
    coord.seed_shard(r1);
    let r2 = TestRecordBuilder::new(TENANT, RUN, SHARD_2)
        .fence_epoch(fence)
        .build(coord.slab_mut());
    coord.seed_shard(r2);

    let oracle = DoneLedgerOracle::new();

    // Complete shard 1, then write again for shard 1 — violation.
    // Complete shard 2 only — no subsequent write, no violation.
    let write_log = vec![
        make_write_log_entry(RUN, SHARD, fence, fence, true, true),
        make_write_log_entry(RUN, SHARD_2, fence, fence, true, true),
        make_write_log_entry(RUN, SHARD, fence, fence, true, false), // C3 violation
    ];

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::WriteAfterTerminal { shard_id, .. } => {
            assert_eq!(*shard_id, SHARD);
        }
        other => panic!("expected WriteAfterTerminal for SHARD, got: {other:?}"),
    }
}
