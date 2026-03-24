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
//! | C1 (ProvenanceOrphan) | `c1_detects_provenance_orphan`, `c1_valid_provenance_no_violation`, `c1_detects_provenance_orphan_wrong_run_id` |
//! | C2 (FenceExceeded) | `c2_detects_fence_exceeded`, `c2_accepts_equal_fence`, `c2_accepts_stale_fence`, `c2_detects_fence_exceeded_at_initial` |
//! | C3 (WriteAfterTerminal) | `c3_detects_write_after_terminal`, `c3_allows_write_in_same_lifecycle`, `c3_stale_epoch_not_flagged`, `c3_uncommitted_write_after_terminal_no_violation`, `c3_different_run_not_flagged`, `c3_fires_after_crash_then_committed_write` |
//! | C4 (FencePropagationMismatch) | `c4_detects_fence_mismatch`, `c4_no_violation_when_fences_match`, `c4_uncommitted_entry_not_checked` |
//! | Cross-cutting | `smoke_no_violations_for_valid_state`, `incremental_processing_skips_old_entries`, `incremental_multi_round_with_interleaved_completions`, `multiple_violations_in_single_check`, `independent_per_shard`, `c1_c2_multiple_oracle_records`, `empty_state_no_violations` |
//!
//! # Test strategy
//!
//! Each negative test: (1) set up coordinator/oracle/write-log with a
//! specific violation condition, (2) call `check_all`, (3) assert exactly
//! the expected violation variant is returned. Positive tests assert empty
//! violation vectors.

use super::*;
use crate::in_memory::InMemoryCoordinator;
use crate::sim::test_util::{LEASE_DUR, TENANT, TestRecordBuilder};

use gossip_contracts::identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, WorkerId};
use gossip_contracts::persistence::{
    DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus, OvidHash,
};
use gossip_persistence_inmemory::PendingWriteId;
use gossip_persistence_inmemory::sim::DoneLedgerOracle;

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
    provenance_fence: FenceEpoch,
    lease_fence: FenceEpoch,
    committed: bool,
    coordinator_completed: bool,
) -> ProvenanceEntry {
    ProvenanceEntry {
        worker: WORKER,
        run_id: run,
        shard_id: shard,
        provenance_fence,
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
            record_key,
            run_id,
            shard_id,
        } => {
            assert_eq!(*record_key, make_key(0xBB));
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

/// Oracle record provenance references the correct shard but a run_id that
/// does not exist in the coordinator. The `shard_lookup` key includes
/// `run_id`, so a wrong run produces a `None` lookup even when the shard ID
/// is present under a different run.
#[test]
fn c1_detects_provenance_orphan_wrong_run_id() {
    // Coordinator has (run=1, shard=1).
    let coord = make_coordinator(RUN, SHARD, FenceEpoch::from_raw(1));

    // Oracle record: correct shard, wrong run.
    let wrong_run = RunId::from_raw(99);
    let prov = make_provenance(wrong_run, SHARD, FenceEpoch::from_raw(1));
    let record = make_record(make_key(0xAB), prov);
    let oracle = make_oracle_with_record(record);

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);

    assert_eq!(viols.len(), 1);
    match &viols[0] {
        CrossComponentViolation::ProvenanceOrphan {
            run_id, shard_id, ..
        } => {
            assert_eq!(*run_id, wrong_run);
            assert_eq!(*shard_id, SHARD);
        }
        other => panic!("expected ProvenanceOrphan, got: {other:?}"),
    }
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
            record_key,
            provenance_fence,
            coordinator_fence,
        } => {
            assert_eq!(*record_key, make_key(0xDD));
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

/// Coordinator fence at the INITIAL epoch (1) with a provenance fence that
/// exceeds it. Even the lowest non-initial fence triggers C2 when the
/// coordinator never advanced past its initial epoch.
#[test]
fn c2_detects_fence_exceeded_at_initial() {
    let coord = make_coordinator(RUN, SHARD, FenceEpoch::from_raw(1));

    let prov = make_provenance(RUN, SHARD, FenceEpoch::from_raw(2));
    let record = make_record(make_key(0xAB), prov);
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
            assert_eq!(*provenance_fence, FenceEpoch::from_raw(2));
            assert_eq!(*coordinator_fence, FenceEpoch::from_raw(1));
        }
        other => panic!("expected FenceExceeded, got: {other:?}"),
    }
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
            lease_fence: lf,
        } => {
            assert_eq!(*run_id, RUN);
            assert_eq!(*shard_id, SHARD);
            assert_eq!(*lf, fence);
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
/// trigger C3 (different lease_fence means different triple).
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

/// An uncommitted write after terminal completion should NOT trigger C3.
/// The checker only flags committed writes that follow a completed triple;
/// uncommitted entries never landed in the done-ledger and are harmless.
#[test]
fn c3_uncommitted_write_after_terminal_no_violation() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    // Complete the triple.
    let complete = make_write_log_entry(RUN, SHARD, fence, fence, true, true);
    // Subsequent uncommitted write for the same triple.
    let uncommitted = make_write_log_entry(RUN, SHARD, fence, fence, false, false);

    let write_log = vec![complete, uncommitted];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

/// A committed write under a different run_id should not trigger C3 even
/// when the shard_id and lease_fence match. The completed-set key is the
/// full `(run_id, shard_id, lease_fence)` triple, so a different run is a
/// distinct lifecycle.
#[test]
fn c3_different_run_not_flagged() {
    let fence = FenceEpoch::from_raw(2);
    let run2 = RunId::from_raw(2);

    // Seed coordinator with two runs for the same shard.
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);
    let r1 = TestRecordBuilder::new(TENANT, RUN, SHARD)
        .fence_epoch(fence)
        .build(coord.slab_mut());
    coord.seed_shard(r1);
    let r2 = TestRecordBuilder::new(TENANT, run2, SHARD)
        .fence_epoch(fence)
        .build(coord.slab_mut());
    coord.seed_shard(r2);

    let oracle = DoneLedgerOracle::new();

    // Complete run 1's triple.
    let complete_r1 = make_write_log_entry(RUN, SHARD, fence, fence, true, true);
    // Committed write under run 2 — different triple, should not fire C3.
    let write_r2 = make_write_log_entry(run2, SHARD, fence, fence, true, false);

    let write_log = vec![complete_r1, write_r2];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

// ---------------------------------------------------------------------------
// C4: Fence propagation mismatch
// ---------------------------------------------------------------------------

/// Stale-lease write: lease_fence differs from provenance_fence.
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
            run_id,
            lease_fence: lf,
            provenance_fence: pf,
            shard_id,
        } => {
            assert_eq!(*run_id, RUN);
            assert_eq!(*lf, lease_fence);
            assert_eq!(*pf, stale_fence);
            assert_eq!(*shard_id, SHARD);
        }
        other => panic!("expected FencePropagationMismatch, got: {other:?}"),
    }
}

/// Normal lifecycle: lease_fence == provenance_fence — no C4 violation.
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

/// Crash-after-complete (coordinator_completed=true, committed=false)
/// should poison the completed set. A subsequent committed write for the
/// same triple must trigger C3.
#[test]
fn c3_fires_after_crash_then_committed_write() {
    let fence = FenceEpoch::from_raw(2);
    let coord = make_coordinator(RUN, SHARD, fence);
    let oracle = DoneLedgerOracle::new();

    // Entry 1: crash-after-complete — coordinator says done, ledger write skipped.
    let crash_entry = make_write_log_entry(RUN, SHARD, fence, fence, false, true);
    // Entry 2: subsequent committed write for the same triple.
    let late_write = make_write_log_entry(RUN, SHARD, fence, fence, true, false);

    let write_log = vec![crash_entry, late_write];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);

    assert_eq!(viols.len(), 1);
    assert!(matches!(
        viols[0],
        CrossComponentViolation::WriteAfterTerminal { .. }
    ));
}

/// A single write-log entry can trigger both C3 and C4 simultaneously:
/// committed write for an already-completed triple with a stale fence.
#[test]
fn multiple_violations_in_single_check() {
    let lease_fence = FenceEpoch::from_raw(3);
    let stale_fence = FenceEpoch::from_raw(1);
    let coord = make_coordinator(RUN, SHARD, lease_fence);
    let oracle = DoneLedgerOracle::new();

    // Entry 1: complete the shard normally.
    let complete = make_write_log_entry(RUN, SHARD, lease_fence, lease_fence, true, true);
    // Entry 2: committed write with stale fence for the same triple.
    // Triggers C3 (write after terminal) AND C4 (fence mismatch).
    let stale_write = make_write_log_entry(RUN, SHARD, stale_fence, lease_fence, true, false);

    let write_log = vec![complete, stale_write];
    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);

    assert_eq!(viols.len(), 2, "expected 2 violations, got: {viols:?}");

    let has_c3 = viols
        .iter()
        .any(|v| matches!(v, CrossComponentViolation::WriteAfterTerminal { .. }));
    let has_c4 = viols
        .iter()
        .any(|v| matches!(v, CrossComponentViolation::FencePropagationMismatch { .. }));
    assert!(has_c3, "expected WriteAfterTerminal in {viols:?}");
    assert!(has_c4, "expected FencePropagationMismatch in {viols:?}");
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

/// Degenerate case: empty coordinator, empty oracle, empty write log.
#[test]
fn empty_state_no_violations() {
    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let oracle = DoneLedgerOracle::new();

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);
    assert!(viols.is_empty(), "expected no violations, got: {viols:?}");
}

/// Multiple oracle records: one valid, one C1 orphan, one C2 fence-exceeded.
/// Verifies the sweep processes all records rather than short-circuiting.
#[test]
fn c1_c2_multiple_oracle_records() {
    let fence = FenceEpoch::from_raw(3);
    let coord = make_coordinator(RUN, SHARD, fence);

    // Record 1: valid — known shard, fence within bounds.
    let valid_prov = make_provenance(RUN, SHARD, fence);
    let valid_record = make_record(make_key(0x01), valid_prov);

    // Record 2: C1 orphan — references shard 99 (not in coordinator).
    let orphan_shard = ShardId::from_raw(99);
    let orphan_prov = make_provenance(RUN, orphan_shard, FenceEpoch::from_raw(1));
    let orphan_record = make_record(make_key(0x02), orphan_prov);

    // Record 3: C2 fence exceeded — fence 10 > coordinator fence 3.
    let exceeded_prov = make_provenance(RUN, SHARD, FenceEpoch::from_raw(10));
    let exceeded_record = make_record(make_key(0x03), exceeded_prov);

    let mut oracle = DoneLedgerOracle::new();
    oracle.submit(
        PendingWriteId::from_raw(1),
        vec![valid_record, orphan_record, exceeded_record],
    );
    assert!(oracle.commit(PendingWriteId::from_raw(1)));

    let mut checker = CompositionInvariantChecker::new();
    let viols = checker.check_all(&coord, &oracle, &[], TENANT);

    assert_eq!(viols.len(), 2, "expected 2 violations, got: {viols:?}");
    let has_c1 = viols
        .iter()
        .any(|v| matches!(v, CrossComponentViolation::ProvenanceOrphan { .. }));
    let has_c2 = viols
        .iter()
        .any(|v| matches!(v, CrossComponentViolation::FenceExceeded { .. }));
    assert!(has_c1, "expected ProvenanceOrphan in {viols:?}");
    assert!(has_c2, "expected FenceExceeded in {viols:?}");
}

/// Multi-round incremental processing: completions and writes span
/// multiple `check_all` calls with different triples.
#[test]
fn incremental_multi_round_with_interleaved_completions() {
    let fence_a = FenceEpoch::from_raw(2);
    let fence_b = FenceEpoch::from_raw(3);

    let mut coord = InMemoryCoordinator::new(LEASE_DUR);
    let r1 = TestRecordBuilder::new(TENANT, RUN, SHARD)
        .fence_epoch(fence_a)
        .build(coord.slab_mut());
    coord.seed_shard(r1);
    let r2 = TestRecordBuilder::new(TENANT, RUN, SHARD_2)
        .fence_epoch(fence_b)
        .build(coord.slab_mut());
    coord.seed_shard(r2);

    let oracle = DoneLedgerOracle::new();
    let mut checker = CompositionInvariantChecker::new();

    // Round 1: complete shard A, write shard B (no violation).
    let mut write_log = vec![
        make_write_log_entry(RUN, SHARD, fence_a, fence_a, true, true),
        make_write_log_entry(RUN, SHARD_2, fence_b, fence_b, true, false),
    ];
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "round 1: {viols:?}");

    // Round 2: complete shard B.
    write_log.push(make_write_log_entry(
        RUN, SHARD_2, fence_b, fence_b, true, true,
    ));
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert!(viols.is_empty(), "round 2: {viols:?}");

    // Round 3: write again for shard B's completed triple — must fire C3.
    write_log.push(make_write_log_entry(
        RUN, SHARD_2, fence_b, fence_b, true, false,
    ));
    let viols = checker.check_all(&coord, &oracle, &write_log, TENANT);
    assert_eq!(viols.len(), 1, "round 3: {viols:?}");
    match &viols[0] {
        CrossComponentViolation::WriteAfterTerminal { shard_id, .. } => {
            assert_eq!(*shard_id, SHARD_2);
        }
        other => panic!("expected WriteAfterTerminal for SHARD_2, got: {other:?}"),
    }
}
