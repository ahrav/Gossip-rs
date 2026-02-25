//! Targeted unit tests for [`InvariantChecker`](super::InvariantChecker).
//!
//! The simulation harness already runs `check_all` after every operation
//! across many seeds. This file complements that coverage with explicit,
//! deterministic fixtures for edge cases that are hard to force
//! probabilistically (for example split referential-integrity failures,
//! Parked->Active fence-bump rules, and cooldown spacing math).
//!
//! Scope is intentionally checker-centric: several fixtures use
//! `seed_shard_unchecked` to construct states production code would reject,
//! because the goal here is validating checker detection logic, not backend
//! mutation-path legality.

use super::*;
use crate::coordination::cursor::Cursor;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::ShardRecord;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::test_fixtures::derived_shard_id;
use crate::identity::{LogicalTime, RunId, ShardId, ShardKey, WorkerId};
use crate::sim::test_util::{LEASE_DUR, TENANT, TestRecordBuilder};

/// Build a coordinator pre-seeded with one valid active shard.
///
/// Used by smoke tests that assert checker pass-through on healthy state.
fn make_coordinator_with_shard(shard_raw: u64) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);
    let key = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(shard_raw));
    let record = ShardRecord::new_active(
        TENANT,
        key.run(),
        key.shard(),
        &ShardSpec::with_range(vec![b'a'], vec![b'z']),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .expect("slab large enough for test");
    coord.seed_shard(record);
    coord
}

// -- Smoke (happy-path documentation anchor) ----------------------------
//
// All other happy-path tests (mutual exclusion with single holder, fence
// increase, terminal stability, cursor forward progress, cursor in-range)
// are strictly subsumed by the simulation harness which runs check_all()
// after every operation under 20+ seeds and multiple fault levels.

#[test]
fn smoke_no_violations_for_valid_state() {
    let coord = make_coordinator_with_shard(1);
    let now = LogicalTime::from_raw(1);
    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    assert!(v.is_empty());
}

// -- Negative tests: verify the checker detects each violation ----------
//
// S1 (MutualExclusion) is not testable with the in-memory backend: the
// HashMap<(TenantId, ShardKey), ShardRecord> enforces at most one record
// per shard per tenant, making multiple active leases structurally
// impossible. The check is defensive for future backends where concurrent
// writes could produce duplicate lease holders.

/// S2: Checker detects fence epoch regression.
#[test]
fn detects_fence_epoch_regression() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed with epoch 5.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(FenceEpoch::from_raw(5))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed with lower epoch — S2 violation.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(FenceEpoch::from_raw(3))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(&v[0], InvariantViolation::FenceMonotonicity { prev, current, .. }
            if prev.as_raw() == 5 && current.as_raw() == 3)
    );
}

/// S3: Checker detects terminal state reverting to non-terminal.
#[test]
fn detects_terminal_state_reversion() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed as Done (terminal).
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Done)
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed as Active — S3 violation (terminal reverted).
    let record = TestRecordBuilder::new(TENANT, run, shard).build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(&v[0], InvariantViolation::TerminalIrreversibility { was, now: cur, .. }
            if *was == ShardStatus::Done && *cur == ShardStatus::Active)
    );
}

/// S4: Checker detects a record that fails `assert_invariants()`.
#[test]
fn detects_record_invariant_violation() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Parked without park_reason — violates INV-1 in assert_invariants.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Parked)
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(&v[0], InvariantViolation::RecordInvariant { message, .. }
            if message.contains("park_reason"))
    );
}

/// S5: Checker detects cursor regression (last_key decreased).
#[test]
fn detects_cursor_regression() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed with cursor at 'h'.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .cursor(Cursor::with_last_key(vec![b'h']))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed with cursor regressed to 'd' — S5 violation.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .cursor(Cursor::with_last_key(vec![b'd']))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(matches!(
        &v[0],
        InvariantViolation::CursorMonotonicity { .. }
    ));
}

/// S5: Checker detects cursor reset from Some to None (back to initial).
#[test]
fn detects_cursor_reset_to_initial() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed with cursor at 'h'.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .cursor(Cursor::with_last_key(vec![b'h']))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed with initial cursor (None) — S5 violation.
    let record = TestRecordBuilder::new(TENANT, run, shard).build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(matches!(
        &v[0],
        InvariantViolation::CursorMonotonicity { .. }
    ));
}

/// S6: Checker detects cursor above shard spec range.
#[test]
fn detects_cursor_above_range() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Cursor at '{' (ASCII 123) is above spec range [a=97, z=122).
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .cursor(Cursor::with_last_key(vec![b'{']))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(matches!(
        &v[0],
        InvariantViolation::CursorOutOfBounds { .. }
    ));
}

/// S6: Checker detects cursor below shard spec range.
#[test]
fn detects_cursor_below_range() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Cursor at 0x01 is below spec range [a=97, z=122).
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .cursor(Cursor::with_last_key(vec![0x01]))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(matches!(
        &v[0],
        InvariantViolation::CursorOutOfBounds { .. }
    ));
}

/// S7: Checker detects a Split shard with no spawned children.
#[test]
fn detects_split_no_children() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Split with empty spawned vec — S7 violation.
    // Also triggers S4 (assert_invariants panics on empty spawned for Split),
    // so we filter for only SplitCoverage below.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Split)
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    let s7: Vec<_> = v
        .iter()
        .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
        .collect();
    assert_eq!(s7.len(), 1);
    assert!(matches!(
        s7[0],
        InvariantViolation::SplitCoverage {
            detail: SplitCoverageDetail::EmptySpawned,
            ..
        }
    ));
}

/// S7: Checker detects a Split shard whose spawned child does not exist.
#[test]
fn detects_split_missing_child() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Parent is Split, references derived child 99 that doesn't exist
    // in the coordinator.
    let missing_child = derived_shard_id(99);
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Split)
        .spawned([missing_child])
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    let s7: Vec<_> = v
        .iter()
        .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
        .collect();
    assert_eq!(s7.len(), 1);
    assert!(matches!(
        s7[0],
        InvariantViolation::SplitCoverage {
            detail: SplitCoverageDetail::MissingChildren { .. },
            ..
        }
    ));
}

/// S7: Checker detects a spawned child with an incorrect parent reference.
#[test]
fn detects_split_wrong_parent_ref() {
    let run = RunId::from_raw(1);
    let parent_shard = ShardId::from_raw(1);
    let child_shard = derived_shard_id(2);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Parent shard 1 is Split, references derived child shard.
    let record = TestRecordBuilder::new(TENANT, run, parent_shard)
        .status(ShardStatus::Split)
        .spawned([child_shard])
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);

    // Child shard exists but points to wrong parent (derived 999 instead of 1).
    let record = TestRecordBuilder::new(TENANT, run, child_shard)
        .spec(ShardSpec::with_range(vec![b'a'], vec![b'm']))
        .parent(ShardId::from_raw(999))
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    let s7: Vec<_> = v
        .iter()
        .filter(|v| matches!(v, InvariantViolation::SplitCoverage { .. }))
        .collect();
    assert_eq!(s7.len(), 1);
    assert!(matches!(
        s7[0],
        InvariantViolation::SplitCoverage {
            detail: SplitCoverageDetail::WrongParent { .. },
            ..
        }
    ));
}

/// S3: Checker detects Split->Active reversion.
#[test]
fn detects_split_to_active_reversion() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    let child = ShardId::from_raw((1u64 << 63) | 10);

    // Seed as Split (terminal) with one child.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Split)
        .spawned([child])
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);
    // Seed the child so S7 doesn't fire on the parent.
    let record = TestRecordBuilder::new(TENANT, run, child)
        .spec(ShardSpec::with_range(vec![b'a'], vec![b'm']))
        .parent(shard)
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed as Active — S3 violation (terminal reverted).
    let record = TestRecordBuilder::new(TENANT, run, shard).build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(&v[0], InvariantViolation::TerminalIrreversibility { was, now: cur, .. }
            if *was == ShardStatus::Split && *cur == ShardStatus::Active)
    );
}

/// S3: Parked->Active is a legitimate unpark transition, not an S3 violation.
#[test]
fn parked_to_active_not_flagged_as_terminal_reversion() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed as Parked (terminal per is_terminal()).
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Parked)
        .park_reason(crate::coordination::record::ParkReason::Other)
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed as Active — simulates unpark_shard.
    // Bump fence epoch to match what unpark_shard does.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(FenceEpoch::INITIAL.increment())
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert!(
        v.is_empty(),
        "Parked->Active should not trigger S3 TerminalIrreversibility, got: {v:?}"
    );
}

/// Parked->Active without bumping fence_epoch triggers UnparkWithoutFenceBump.
#[test]
fn detects_unpark_without_fence_bump() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed as Parked with fence epoch 3.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Parked)
        .park_reason(crate::coordination::record::ParkReason::Other)
        .fence_epoch(FenceEpoch::from_raw(3))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed as Active with SAME fence epoch — missing fence bump.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(FenceEpoch::from_raw(3))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(
            &v[0],
            InvariantViolation::UnparkWithoutFenceBump {
                fence_at_park,
                fence_at_unpark,
                ..
            } if fence_at_park.as_raw() == 3 && fence_at_unpark.as_raw() == 3
        ),
        "expected UnparkWithoutFenceBump, got: {v:?}"
    );
}

/// A fence regression during Parked->Active (epoch 5->3) must fire only S2
/// (FenceMonotonicity), not the S3 sub-property (UnparkWithoutFenceBump).
#[test]
fn fence_regression_during_unpark_does_not_double_report() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed as Parked with fence epoch 5.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .status(ShardStatus::Parked)
        .park_reason(crate::coordination::record::ParkReason::Other)
        .fence_epoch(FenceEpoch::from_raw(5))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let mut checker = InvariantChecker::new();
    assert!(checker.check_all(&coord, TENANT, now).is_empty());

    // Re-seed as Active with LOWER fence epoch (regression: 5->3).
    // S2 should fire (fence regression), but S3 sub-property
    // (UnparkWithoutFenceBump) should NOT also fire for the same event.
    let record = TestRecordBuilder::new(TENANT, run, shard)
        .fence_epoch(FenceEpoch::from_raw(3))
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let v = checker.check_all(&coord, TENANT, now);

    let s2_count = v
        .iter()
        .filter(|v| matches!(v, InvariantViolation::FenceMonotonicity { .. }))
        .count();
    let s3_count = v
        .iter()
        .filter(|v| matches!(v, InvariantViolation::UnparkWithoutFenceBump { .. }))
        .count();

    assert_eq!(s2_count, 1, "S2 (FenceMonotonicity) should fire");
    assert_eq!(
        s3_count, 0,
        "S3 sub (UnparkWithoutFenceBump) should NOT also fire for fence regression"
    );
}

// -- Pruning: prev_* maps shrink for permanently terminal shards ----------

/// Permanently terminal shards (Done, Split) have their epoch and cursor
/// history pruned after check_all. `prev_terminal` is retained so S3 can
/// still catch illegal reversions. Parked shards are never pruned.
#[test]
fn prunes_permanently_terminal_shards_from_history() {
    let run = RunId::from_raw(1);
    let done_shard = ShardId::from_raw(1);
    let split_shard = ShardId::from_raw(2);
    let parked_shard = ShardId::from_raw(3);
    let active_shard = ShardId::from_raw(4);
    let now = LogicalTime::from_raw(1);

    let mut coord = InMemoryCoordinator::new(LEASE_DUR);

    // Seed four shards in different states.
    let record = TestRecordBuilder::new(TENANT, run, done_shard)
        .status(ShardStatus::Done)
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let child = ShardId::from_raw((1u64 << 63) | 10);
    let record = TestRecordBuilder::new(TENANT, run, split_shard)
        .status(ShardStatus::Split)
        .spawned([child])
        .build(coord.slab_mut());
    coord.seed_shard_unchecked(record);
    let record = TestRecordBuilder::new(TENANT, run, child)
        .spec(ShardSpec::with_range(vec![b'a'], vec![b'm']))
        .parent(split_shard)
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let record = TestRecordBuilder::new(TENANT, run, parked_shard)
        .status(ShardStatus::Parked)
        .park_reason(crate::coordination::record::ParkReason::Other)
        .build(coord.slab_mut());
    coord.seed_shard(record);

    let record = TestRecordBuilder::new(TENANT, run, active_shard).build(coord.slab_mut());
    coord.seed_shard(record);

    let mut checker = InvariantChecker::new();
    let v = checker.check_all(&coord, TENANT, now);
    assert!(v.is_empty(), "unexpected violations: {v:?}");

    // Done and Split should have epoch/cursor history pruned.
    let done_id = (TENANT, run, done_shard);
    let split_id = (TENANT, run, split_shard);
    assert!(
        !checker.prev_epochs.contains_key(&done_id),
        "Done shard should be pruned from prev_epochs"
    );
    assert!(
        !checker.prev_epochs.contains_key(&split_id),
        "Split shard should be pruned from prev_epochs"
    );
    assert!(
        !checker.prev_cursors.contains_key(&done_id),
        "Done shard should be pruned from prev_cursors"
    );
    assert!(
        !checker.prev_cursors.contains_key(&split_id),
        "Split shard should be pruned from prev_cursors"
    );

    // prev_terminal is intentionally kept for S3 reversion detection.
    assert!(
        checker.prev_terminal.contains_key(&done_id),
        "Done shard should be kept in prev_terminal for S3"
    );
    assert!(
        checker.prev_terminal.contains_key(&split_id),
        "Split shard should be kept in prev_terminal for S3"
    );

    // Parked and Active should still be in all maps.
    let parked_id = (TENANT, run, parked_shard);
    let active_id = (TENANT, run, active_shard);
    assert!(
        checker.prev_epochs.contains_key(&parked_id),
        "Parked shard should be kept in prev_epochs"
    );
    assert!(
        checker.prev_epochs.contains_key(&active_id),
        "Active shard should be kept in prev_epochs"
    );
}

// -- Cross-tenant isolation -----------------------------------------------

/// Two tenants sharing the same (RunId, ShardId) must not have their
/// fence histories cross-contaminate. Advancing tenant A's epoch must
/// not affect the checker's view of tenant B.
#[test]
fn cross_tenant_isolation_in_temporal_checks() {
    let run = RunId::from_raw(1);
    let shard = ShardId::from_raw(1);
    let now = LogicalTime::from_raw(1);
    let tenant_a = TenantId::from_bytes([0xAA; 32]);
    let tenant_b = TenantId::from_bytes([0xBB; 32]);

    let mut coord = InMemoryCoordinator::new(LEASE_DUR);
    let mut checker = InvariantChecker::new();

    // Tenant A: seed shard with fence epoch 5.
    let record = TestRecordBuilder::new(tenant_a, run, shard)
        .fence_epoch(FenceEpoch::from_raw(5))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    assert!(checker.check_all(&coord, tenant_a, now).is_empty());

    // Tenant B: seed same (run, shard) with fence epoch 2.
    // If keys were only (RunId, ShardId), this would look like a
    // regression from 5->2 and trigger an S2 violation.
    let record = TestRecordBuilder::new(tenant_b, run, shard)
        .fence_epoch(FenceEpoch::from_raw(2))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let v = checker.check_all(&coord, tenant_b, now);
    assert!(
        v.is_empty(),
        "cross-tenant contamination: tenant B got violations from tenant A's history: {v:?}"
    );

    // Verify tenant A's history is still intact — advancing A's epoch
    // from 5 to 6 should not violate.
    let record = TestRecordBuilder::new(tenant_a, run, shard)
        .fence_epoch(FenceEpoch::from_raw(6))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    assert!(checker.check_all(&coord, tenant_a, now).is_empty());

    // Regressing tenant A from 6 to 4 SHOULD trigger S2.
    let record = TestRecordBuilder::new(tenant_a, run, shard)
        .fence_epoch(FenceEpoch::from_raw(4))
        .build(coord.slab_mut());
    coord.seed_shard(record);
    let v = checker.check_all(&coord, tenant_a, now);
    assert_eq!(v.len(), 1);
    assert!(
        matches!(&v[0], InvariantViolation::FenceMonotonicity { prev, current, .. }
            if prev.as_raw() == 6 && current.as_raw() == 4),
        "expected FenceMonotonicity for tenant A, got: {v:?}"
    );
}

// -- S9 cooldown spacing ---------------------------------------------------

#[test]
fn s9_detects_cooldown_violation() {
    let mut checker = InvariantChecker::with_cooldown_interval(10);
    let worker = WorkerId::from_raw(1);
    checker.record_claim_success(worker, LogicalTime::from_raw(100));
    checker.record_claim_success(worker, LogicalTime::from_raw(105));

    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let v = checker.check_all(&coord, TENANT, LogicalTime::from_raw(105));

    assert_eq!(v.len(), 1, "expected one S9 violation, got: {v:?}");
    assert!(matches!(
        &v[0],
        InvariantViolation::CooldownViolation {
            worker: w,
            this_claim,
            prev_claim,
            min_interval
        } if *w == worker
            && this_claim.as_raw() == 105
            && prev_claim.as_raw() == 100
            && *min_interval == 10
    ));
}

#[test]
fn s9_vacuously_true_when_disabled() {
    let mut checker = InvariantChecker::new();
    let worker = WorkerId::from_raw(1);
    checker.record_claim_success(worker, LogicalTime::from_raw(100));
    checker.record_claim_success(worker, LogicalTime::from_raw(101));

    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let v = checker.check_all(&coord, TENANT, LogicalTime::from_raw(101));
    assert!(
        v.is_empty(),
        "disabled cooldown should be vacuously true: {v:?}"
    );
}

#[test]
fn s9_allows_claims_beyond_interval() {
    let mut checker = InvariantChecker::with_cooldown_interval(10);
    let worker = WorkerId::from_raw(1);
    checker.record_claim_success(worker, LogicalTime::from_raw(100));
    checker.record_claim_success(worker, LogicalTime::from_raw(110));

    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let v = checker.check_all(&coord, TENANT, LogicalTime::from_raw(110));
    assert!(
        v.is_empty(),
        "gap >= cooldown interval should not violate S9: {v:?}"
    );
}

#[test]
fn s9_independent_per_worker() {
    let mut checker = InvariantChecker::with_cooldown_interval(10);
    let worker1 = WorkerId::from_raw(1);
    let worker2 = WorkerId::from_raw(2);

    checker.record_claim_success(worker1, LogicalTime::from_raw(100));
    checker.record_claim_success(worker2, LogicalTime::from_raw(101));
    checker.record_claim_success(worker1, LogicalTime::from_raw(105));

    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let v = checker.check_all(&coord, TENANT, LogicalTime::from_raw(105));
    assert_eq!(v.len(), 1, "expected only worker1 violation: {v:?}");
    assert!(matches!(
        &v[0],
        InvariantViolation::CooldownViolation { worker, .. } if *worker == worker1
    ));
}

#[test]
fn s9_set_cooldown_interval_activates_checking() {
    let mut checker = InvariantChecker::new();
    let worker = WorkerId::from_raw(1);

    // Disabled mode: no history updates and no violations.
    checker.record_claim_success(worker, LogicalTime::from_raw(10));
    checker.record_claim_success(worker, LogicalTime::from_raw(11));

    checker.set_cooldown_interval(5);
    checker.record_claim_success(worker, LogicalTime::from_raw(20));
    checker.record_claim_success(worker, LogicalTime::from_raw(22));

    let coord = InMemoryCoordinator::new(LEASE_DUR);
    let v = checker.check_all(&coord, TENANT, LogicalTime::from_raw(22));
    assert_eq!(v.len(), 1, "expected one S9 violation after enable: {v:?}");
    assert!(matches!(
        &v[0],
        InvariantViolation::CooldownViolation {
            min_interval,
            prev_claim,
            this_claim,
            ..
        } if *min_interval == 5
            && prev_claim.as_raw() == 20
            && this_claim.as_raw() == 22
    ));
}
