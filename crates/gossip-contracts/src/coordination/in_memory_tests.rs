//! Unit tests for [`InMemoryCoordinator`], the in-memory reference
//! implementation of the coordination backend.
//!
//! # Testing strategy
//!
//! Each test targets **one operation or one edge case** of the
//! `CoordinationBackend` trait. Tests are deterministic: logical time is
//! advanced manually via [`now(t)`](crate::coordination::test_fixtures::now),
//! and shared fixtures from [`test_fixtures`] supply canonical identities
//! (tenant, run, shard, worker) so every test starts from the same baseline.
//!
//! Property-based tests (proptest) complement the unit tests by generating
//! random operation sequences and verifying structural invariants that must
//! hold regardless of order.
//!
//! # Relationship to other test modules
//!
//! | Module | Focus |
//! |--------|-------|
//! | **This module** | Unit tests: one backend operation per test |
//! | [`conformance_tests`] | Invariant interactions: two or more safety invariants composed |
//! | [`scenario_tests`] | End-to-end multi-step workflows |
//!
//! # Section organization
//!
//! Deterministic unit tests are grouped by the operation they exercise:
//! acquire, renew, checkpoint, complete, park, split (replace and residual),
//! fencing, op-log eviction, idempotent replay, tenant isolation, shard
//! count limits, run lifecycle, unpark, and list_shards filtering. Two
//! integration tests (`full_lifecycle_*`) chain multiple operations to
//! verify end-to-end shard progression.
//!
//! The final section contains property-based tests that fuzz random
//! operation sequences against the coordinator, asserting structural
//! invariants (record consistency, fence monotonicity, cursor monotonicity,
//! idempotent replay) after every step.

use super::*;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::coordination::test_fixtures::{
    LEASE_DURATION, acquire_shard, now, seeded_coordinator, test_cursor, test_key, test_run,
    test_shard, test_spec, test_tenant, test_worker,
};
use crate::identity::{FenceEpoch, RunId};
use gossip_stdx::RingBuffer;

// -- acquire_and_restore tests ----------------------------------------
//
// Validates the shard acquisition contract: successful acquire returns a
// valid lease (correct owner, fence bumped from INITIAL, deadline =
// now + LEASE_DURATION), the shard snapshot is Active, and the operation
// rejects non-existent shards, already-leased shards, and terminal shards.
// Also verifies that a lease can be stolen after expiry.

#[test]
fn acquire_basic() {
    let mut coord = seeded_coordinator();
    let result = coord
        .acquire_and_restore(now(1), test_tenant(), test_key(), test_worker(1))
        .unwrap();

    assert_eq!(result.lease.owner(), test_worker(1));
    assert_eq!(result.lease.fence(), FenceEpoch::INITIAL.increment());
    assert_eq!(
        result.lease.deadline(),
        now(1).checked_add(LEASE_DURATION).unwrap(),
    );
    assert_eq!(result.snapshot.status(), ShardStatus::Active);
}

#[test]
fn acquire_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let err = coord
        .acquire_and_restore(now(1), test_tenant(), test_key(), test_worker(1))
        .unwrap_err();
    assert!(matches!(err, AcquireError::ShardNotFound { .. }));
}

#[test]
fn acquire_already_leased() {
    let mut coord = seeded_coordinator();
    let _lease = acquire_shard(&mut coord, 1, 1);

    let err = coord
        .acquire_and_restore(now(2), test_tenant(), test_key(), test_worker(2))
        .unwrap_err();
    assert!(matches!(err, AcquireError::AlreadyLeased { .. }));
}

#[test]
fn acquire_after_lease_expiry() {
    let mut coord = seeded_coordinator();
    let _lease = acquire_shard(&mut coord, 1, 1);

    // Advance past lease deadline.
    let result = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 2),
            test_tenant(),
            test_key(),
            test_worker(2),
        )
        .unwrap();
    assert_eq!(result.lease.owner(), test_worker(2));
}

#[test]
fn acquire_terminal_rejected() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Drive shard to terminal (Done) so we can test that acquire rejects it.
    let cursor = test_cursor(b"m");
    let _ = coord
        .complete(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
        .unwrap();

    let err = coord
        .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
        .unwrap_err();
    assert!(matches!(err, AcquireError::ShardTerminal { .. }));
}

// -- renew tests -------------------------------------------------------
//
// Lease renewal extends the deadline without bumping the fence. A stale
// fence (from a superseded lease) is rejected.

#[test]
fn renew_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let result = coord.renew(now(50), test_tenant(), &lease).unwrap();
    assert_eq!(
        result.new_deadline,
        now(50).checked_add(LEASE_DURATION).unwrap(),
    );
}

#[test]
fn renew_stale_fence() {
    let mut coord = seeded_coordinator();
    let old_lease = acquire_shard(&mut coord, 1, 1);

    // Another worker acquires, bumping the fence.
    let _new_lease = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 2),
            test_tenant(),
            test_key(),
            test_worker(2),
        )
        .unwrap();

    let err = coord
        .renew(now(LEASE_DURATION + 3), test_tenant(), &old_lease)
        .unwrap_err();
    assert!(matches!(err, RenewError::StaleFence { .. }));
}

// -- checkpoint tests --------------------------------------------------
//
// Checkpointing persists a cursor position. Verifies basic execution
// and that reusing the same OpId with a different payload triggers
// OpIdConflict (bounded idempotency).

#[test]
fn checkpoint_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let cursor = test_cursor(b"b");
    let result = coord
        .checkpoint(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());
}

#[test]
fn checkpoint_op_id_conflict() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let op = OpId::from_raw(1);
    let _ = coord
        .checkpoint(now(2), test_tenant(), &lease, test_cursor(b"b"), op)
        .unwrap();

    // Same op_id, different payload -> OpIdConflict.
    let err = coord
        .checkpoint(now(3), test_tenant(), &lease, test_cursor(b"c"), op)
        .unwrap_err();
    assert!(matches!(err, CheckpointError::OpIdConflict { .. }));
}

// -- complete tests ----------------------------------------------------
//
// Completing a shard transitions it to Done (terminal). Subsequent
// acquire attempts must fail with ShardTerminal.

#[test]
fn complete_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let cursor = test_cursor(b"m");
    let result = coord
        .complete(now(2), test_tenant(), &lease, cursor, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());

    // Shard is now terminal.
    let err = coord
        .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
        .unwrap_err();
    assert!(matches!(err, AcquireError::ShardTerminal { .. }));
}

// -- park tests --------------------------------------------------------
//
// Parking a shard transitions it to Parked (terminal from the worker's
// perspective, but reversible via unpark_shard admin op).

#[test]
fn park_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let result = coord
        .park_shard(
            now(2),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(result.is_executed());
}

// -- split_replace tests -----------------------------------------------
//
// split_replace atomically retires the parent shard (terminal, status=Split)
// and spawns N child shards. Tests cover: basic execution, idempotent
// replay (same OpId+payload returns Replayed with identical child IDs),
// and deterministic child ID generation across independent coordinators.

#[test]
fn split_replace_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let child_a_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let child_b_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());

    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(child_a_spec, Cursor::initial()),
        SplitReplaceChild::new(child_b_spec, Cursor::initial()),
    ])
    .unwrap();

    let result = coord
        .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());
    assert_eq!(result.as_ref().children.len(), 2);

    // All children should be derived (bit 63 set).
    for id in &result.as_ref().children {
        assert!(id.is_derived());
    }

    // Parent should be terminal.
    let err = coord
        .acquire_and_restore(now(3), test_tenant(), test_key(), test_worker(2))
        .unwrap_err();
    assert!(matches!(err, AcquireError::ShardTerminal { .. }));
}

#[test]
fn split_replace_replay() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let child_a_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let child_b_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());

    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(child_a_spec.clone(), Cursor::initial()),
        SplitReplaceChild::new(child_b_spec.clone(), Cursor::initial()),
    ])
    .unwrap();

    let op = OpId::from_raw(1);
    let first = coord
        .split_replace(now(2), test_tenant(), &lease, plan.clone(), op)
        .unwrap();
    assert!(first.is_executed());

    // Replay with same OpId + payload.
    let second = coord
        .split_replace(now(3), test_tenant(), &lease, plan, op)
        .unwrap();
    assert!(second.is_replay());
    assert_eq!(first.as_ref().children, second.as_ref().children);
}

#[test]
fn split_replace_child_id_determinism() {
    // Same inputs produce same child IDs.
    let mut coord1 = seeded_coordinator();
    let lease1 = acquire_shard(&mut coord1, 1, 1);

    let mut coord2 = seeded_coordinator();
    let lease2 = acquire_shard(&mut coord2, 1, 1);

    let make_plan = || {
        let a = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let b = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        SplitReplacePlan::try_new(vec![
            SplitReplaceChild::new(a, Cursor::initial()),
            SplitReplaceChild::new(b, Cursor::initial()),
        ])
        .unwrap()
    };

    let op = OpId::from_raw(42);
    let r1 = coord1
        .split_replace(now(2), test_tenant(), &lease1, make_plan(), op)
        .unwrap();
    let r2 = coord2
        .split_replace(now(2), test_tenant(), &lease2, make_plan(), op)
        .unwrap();
    assert_eq!(r1.into_inner().children, r2.into_inner().children);
}

// -- split_residual tests ----------------------------------------------
//
// split_residual shrinks the parent's key range and spawns a residual
// child for the remainder. Unlike split_replace, the parent stays Active.
// Tests cover: basic execution, cursor-out-of-bounds rejection (cursor
// must fall within the new parent range), and parent continuity after split.

#[test]
fn split_residual_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set a cursor within the new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();

    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

    let result = coord
        .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());
    assert!(result.as_ref().residual.is_derived());

    // Parent should still be acquirable (not terminal).
    // But current lease is still active, so we must wait for expiry.
    let new_result = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 4),
            test_tenant(),
            test_key(),
            test_worker(2),
        )
        .unwrap();
    assert_eq!(new_result.snapshot.status(), ShardStatus::Active);
}

#[test]
fn split_residual_cursor_out_of_bounds() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to "r" — outside the new parent range [a, m).
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"r"),
            OpId::from_raw(10),
        )
        .unwrap();

    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

    let err = coord
        .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, SplitResidualError::SplitInvalid(_)));
}

// -- Op-log eviction edge case ----------------------------------------
//
// The per-shard op-log is a 16-entry FIFO ring buffer. Once an entry is
// evicted, a retry of that OpId is treated as a fresh operation (no
// replay detection). This test pushes 17 ops to evict the first, then
// retries it and verifies it is rejected on semantic grounds (cursor
// regression) rather than recognized as a replay.

#[test]
fn op_log_eviction_treats_old_op_as_new() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Push 17 ops (cap is 16) to evict the first one.
    let mut cursor_key = b"b".to_vec();
    for i in 1..=17u64 {
        let cursor = Cursor::with_last_key(cursor_key.clone());
        let _ = coord
            .checkpoint(now(i + 1), test_tenant(), &lease, cursor, OpId::from_raw(i))
            .unwrap();
        cursor_key[0] = b'b' + (i as u8).min(23); // advance monotonically, clamped to stay within [a, z)
    }

    // Retry the first op — it was evicted, so it's treated as a new op
    // rather than a replay. It will fail because its cursor (b"b") would
    // regress from the current position.
    let old_cursor = Cursor::with_last_key(b"b".to_vec());
    let err = coord
        .checkpoint(
            now(20),
            test_tenant(),
            &lease,
            old_cursor,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(matches!(err, CheckpointError::CursorRegression { .. }));
}

// -- Fencing mutual exclusion -----------------------------------------
//
// Validates the Kleppmann-style fencing invariant: once a new worker
// acquires a shard (bumping the fence epoch), the previous lease holder
// is locked out of all mutations (checkpoint, complete, park), while the
// current holder can proceed.

#[test]
fn only_latest_fence_holder_can_mutate() {
    let mut coord = seeded_coordinator();
    let old_lease = acquire_shard(&mut coord, 1, 1);

    // New worker acquires.
    let new_lease = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 2),
            test_tenant(),
            test_key(),
            test_worker(2),
        )
        .unwrap()
        .lease;

    // Old lease: all mutations rejected.
    assert!(
        coord
            .checkpoint(
                now(LEASE_DURATION + 3),
                test_tenant(),
                &old_lease,
                test_cursor(b"b"),
                OpId::from_raw(1),
            )
            .is_err()
    );
    assert!(
        coord
            .complete(
                now(LEASE_DURATION + 3),
                test_tenant(),
                &old_lease,
                test_cursor(b"b"),
                OpId::from_raw(2),
            )
            .is_err()
    );
    assert!(
        coord
            .park_shard(
                now(LEASE_DURATION + 3),
                test_tenant(),
                &old_lease,
                ParkReason::TooManyErrors,
                OpId::from_raw(3),
            )
            .is_err()
    );

    // New lease: mutation succeeds.
    let result = coord
        .checkpoint(
            now(LEASE_DURATION + 3),
            test_tenant(),
            &new_lease,
            test_cursor(b"b"),
            OpId::from_raw(4),
        )
        .unwrap();
    assert!(result.is_executed());
}

// -- split_residual replay via spawned.contains() ---------------------
//
// split_residual has a two-tier replay detection: (1) the op-log, and
// (2) the `spawned` set on the shard record. If the op-log entry has
// been evicted, the coordinator can still detect a replay by checking
// whether the residual ShardId is already in `spawned`. This test
// forces eviction of the op-log entry and verifies the fallback path.

#[test]
fn split_residual_replay_via_spawned_after_eviction() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set cursor within new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"d"),
            OpId::from_raw(100),
        )
        .unwrap();

    // Split residual.
    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();
    let split_op = OpId::from_raw(200);

    let first = coord
        .split_residual(now(3), test_tenant(), &lease, plan.clone(), split_op)
        .unwrap();
    assert!(first.is_executed());

    // Push 16+ checkpoint ops to evict the split_residual op_log entry.
    let mut key_byte = b'e';
    for i in 1..=17u64 {
        let cursor = Cursor::with_last_key(vec![key_byte]);
        let _ = coord
            .checkpoint(
                now(10 + i),
                test_tenant(),
                &lease,
                cursor,
                OpId::from_raw(300 + i),
            )
            .unwrap();
        if key_byte < b'l' {
            key_byte += 1;
        }
    }

    // Retry split_residual — op_log entry is evicted, but spawned.contains()
    // detects the replay.
    let second = coord
        .split_residual(now(30), test_tenant(), &lease, plan, split_op)
        .unwrap();
    assert!(second.is_replay());
    assert_eq!(first.as_ref().residual, second.as_ref().residual);
}

// -- spawn-cap guard tests -----------------------------------------------
//
// Each shard tracks a `spawned` set of child ShardIds. When this set
// reaches MAX_SPAWNED_PER_SHARD, further splits are rejected with
// SplitInvalid. This prevents unbounded recursive splitting.

/// Creates a derived `ShardId` by setting bit 63 on `base`.
///
/// Derived IDs are what the coordinator generates for split children.
/// This helper constructs them directly for pre-populating the `spawned`
/// set in [`coordinator_with_spawned_count`].
fn derived_shard_id(base: u64) -> ShardId {
    ShardId::from_raw(base | (1u64 << 63))
}

/// Builds a coordinator whose single shard already has `spawned_count`
/// derived entries in its `spawned` set.
///
/// The shard is Active with spec `[a, z)` and cursor at `"d"` (within
/// the standard `[a, m)` split range used by split tests). This setup
/// lets spawn-cap tests start at an exact distance from the limit
/// without performing actual split operations.
fn coordinator_with_spawned_count(spawned_count: usize) -> InMemoryCoordinator {
    let spawned: Vec<ShardId> = (0..spawned_count as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    let record = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        test_shard(),
        ShardStatus::Active,
        None,
        test_spec(), // [a, z)
        test_cursor(b"d"),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        spawned,
        RingBuffer::new(),
    );
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord.seed_shard(record);
    coord
}

#[test]
fn split_residual_at_spawn_cap_returns_error() {
    let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD);
    let lease = acquire_shard(&mut coord, 1, 1);

    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

    let err = coord
        .split_residual(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::SplitInvalid(_)),
        "expected SplitInvalid for spawn cap exceeded, got: {err:?}",
    );
}

#[test]
fn split_replace_at_spawn_cap_returns_error() {
    let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD);
    let lease = acquire_shard(&mut coord, 1, 1);

    let child_a = SplitReplaceChild::new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        Cursor::initial(),
    );
    let child_b = SplitReplaceChild::new(
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    );
    let plan = SplitReplacePlan::try_new(vec![child_a, child_b]).unwrap();

    let err = coord
        .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitReplaceError::SplitInvalid(_)),
        "expected SplitInvalid for spawn cap exceeded, got: {err:?}",
    );
}

#[test]
fn split_residual_below_cap_succeeds() {
    // One below the cap — should succeed.
    let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD - 1);
    let lease = acquire_shard(&mut coord, 1, 1);

    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();

    let result = coord
        .split_residual(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());
}

// -- Idempotent replay after terminal state --------------------------------
//
// A terminal shard (Done or Parked) must still honor idempotent replay
// for the operation that caused the terminal transition. Without this,
// a client retry after a network timeout would get ShardTerminal instead
// of the expected Replayed acknowledgment.

#[test]
fn complete_replay_after_terminal() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let cursor = test_cursor(b"m");
    let op = OpId::from_raw(1);
    let first = coord
        .complete(now(2), test_tenant(), &lease, cursor.clone(), op)
        .unwrap();
    assert!(first.is_executed());

    // Replay same op_id + payload after shard is terminal (Done).
    let second = coord
        .complete(now(3), test_tenant(), &lease, cursor, op)
        .unwrap();
    assert!(
        second.is_replay(),
        "replay of complete after terminal should return Replayed, not ShardTerminal",
    );
}

#[test]
fn park_replay_after_terminal() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let op = OpId::from_raw(1);
    let first = coord
        .park_shard(now(2), test_tenant(), &lease, ParkReason::TooManyErrors, op)
        .unwrap();
    assert!(first.is_executed());

    // Replay same op_id + payload after shard is terminal (Parked).
    let second = coord
        .park_shard(now(3), test_tenant(), &lease, ParkReason::TooManyErrors, op)
        .unwrap();
    assert!(
        second.is_replay(),
        "replay of park after terminal should return Replayed, not ShardTerminal",
    );
}

// -- OpIdConflict tests for split operations --------------------------------
//
// Reusing the same OpId with a different split plan (different split
// point) must trigger OpIdConflict, not silently apply the new plan.
// This is the bounded-idempotency safety check for split operations.

#[test]
fn split_replace_op_id_conflict() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let plan_a = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();

    let op = OpId::from_raw(1);
    let _ = coord
        .split_replace(now(2), test_tenant(), &lease, plan_a, op)
        .unwrap();

    // Same op_id, different plan (different split point).
    let plan_b = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"p".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();

    let err = coord
        .split_replace(now(3), test_tenant(), &lease, plan_b, op)
        .unwrap_err();
    assert!(
        matches!(err, SplitReplaceError::OpIdConflict { .. }),
        "expected OpIdConflict, got: {err:?}",
    );
}

#[test]
fn split_residual_op_id_conflict() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set cursor within the new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(100),
        )
        .unwrap();

    let plan_a = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();

    let op = OpId::from_raw(1);
    let _ = coord
        .split_residual(now(3), test_tenant(), &lease, plan_a, op)
        .unwrap();

    // Same op_id, different plan (different split point).
    let plan_b = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"p".to_vec()),
        ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
    )
    .unwrap();

    let err = coord
        .split_residual(now(4), test_tenant(), &lease, plan_b, op)
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::OpIdConflict { .. }),
        "expected OpIdConflict, got: {err:?}",
    );
}

// -- Lease deadline saturation ------------------------------------------------
//
// Exercises the u64 overflow edge case for lease deadlines. When
// now + lease_duration would exceed u64::MAX, the deadline must
// saturate rather than panic. The resulting very-long lease is safe
// because fence bumps can still supersede it.
#[test]
fn acquire_saturates_on_lease_deadline_overflow() {
    let mut coord = seeded_coordinator();
    let result = coord.acquire_and_restore(
        LogicalTime::from_raw(u64::MAX),
        test_tenant(),
        test_key(),
        test_worker(1),
    );
    assert!(
        result.is_ok(),
        "acquire should succeed with saturated deadline"
    );
    let lease = result.unwrap().lease;
    assert_eq!(
        lease.deadline(),
        LogicalTime::from_raw(u64::MAX),
        "deadline should saturate to u64::MAX"
    );
}

// -- Shard count limit tests -----------------------------------------------
//
// The coordinator enforces two independent shard count limits: per-tenant
// and global. split_replace and split_residual must reject the operation
// when adding children would breach either limit. Limits are configured
// via `InMemoryCoordinator::with_limits`.

/// Returns a tenant distinct from [`test_tenant()`] for isolation tests.
///
/// Uses `[0x02; 32]` so it is deterministic and visually distinguishable
/// from `test_tenant()` (`[0x01; 32]`).
fn other_tenant() -> TenantId {
    TenantId::from_bytes([0x02; 32])
}

#[test]
fn split_replace_exceeds_per_tenant_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 3, 100);

    // Seed the target shard.
    let record = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        test_shard(),
        test_spec(),
        CursorSemantics::Completed,
    );
    coord.seed_shard(record);

    // Seed two additional shards to fill tenant to limit.
    let record2 = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(20),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
    );
    coord.seed_shard(record2);
    let record3 = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(30),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
    );
    coord.seed_shard(record3);

    let lease = acquire_shard(&mut coord, 1, 1);

    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();

    let err = coord
        .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitReplaceError::SplitInvalid(ref e)
            if matches!(e.as_ref(),
                SplitValidationError::ShardLimitExceeded { scope: ShardLimitScope::PerTenant, .. })),
        "expected ShardLimitExceeded(PerTenant), got: {err:?}",
    );
}

#[test]
fn split_residual_exceeds_global_limit() {
    // Global limit of 2: seed 2 shards, then split_residual wants to add 1 more.
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 100, 2);

    let record = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        test_shard(),
        test_spec(),
        CursorSemantics::Completed,
    );
    coord.seed_shard(record);

    // Seed a second shard (different tenant) to fill global limit.
    let record2 = ShardRecord::new_active(
        other_tenant(),
        test_run(),
        ShardId::from_raw(20),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
    );
    coord.seed_shard(record2);

    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set cursor within the new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(100),
        )
        .unwrap();

    let plan = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();

    let err = coord
        .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::SplitInvalid(ref e)
            if matches!(e.as_ref(),
                SplitValidationError::ShardLimitExceeded { scope: ShardLimitScope::Global, .. })),
        "expected ShardLimitExceeded(Global), got: {err:?}",
    );
}

// -- Tenant isolation tests -----------------------------------------------
//
// The coordinator uses a composite key `(TenantId, ShardKey)` for the
// shard map. A wrong tenant simply doesn't find the record, returning
// `ShardNotFound`. This is the correct security behavior: the wrong
// tenant never learns the shard exists. The `TenantMismatch` variant
// in `validate_lease` is a defense-in-depth check for internal
// corruption, not the primary isolation mechanism.

#[test]
fn acquire_wrong_tenant_returns_not_found() {
    let mut coord = seeded_coordinator();
    let err = coord
        .acquire_and_restore(now(1), other_tenant(), test_key(), test_worker(1))
        .unwrap_err();
    assert!(
        matches!(err, AcquireError::ShardNotFound { .. }),
        "wrong tenant should see ShardNotFound, got: {err:?}",
    );
}

#[test]
fn checkpoint_wrong_tenant_returns_not_found() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let err = coord
        .checkpoint(
            now(2),
            other_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::ShardNotFound { .. }),
        "wrong tenant should see ShardNotFound, got: {err:?}",
    );
}

#[test]
fn complete_wrong_tenant_returns_not_found() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let err = coord
        .complete(
            now(2),
            other_tenant(),
            &lease,
            test_cursor(b"m"),
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(err, CompleteError::ShardNotFound { .. }),
        "wrong tenant should see ShardNotFound, got: {err:?}",
    );
}

#[test]
fn split_replace_wrong_tenant_returns_not_found() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();

    let err = coord
        .split_replace(now(2), other_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitReplaceError::ShardNotFound { .. }),
        "wrong tenant should see ShardNotFound, got: {err:?}",
    );
}

#[test]
fn split_residual_wrong_tenant_returns_not_found() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set cursor within the new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(100),
        )
        .unwrap();

    let plan = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();

    let err = coord
        .split_residual(now(3), other_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::ShardNotFound { .. }),
        "wrong tenant should see ShardNotFound, got: {err:?}",
    );
}

// -- split_residual replay via op-log (before eviction) --------------------
//
// Exercises the primary replay path for split_residual: the op-log entry
// is still present (no eviction). Verifies that same OpId+plan returns
// Replayed with the same residual ShardId, and that same OpId+different
// plan returns OpIdConflict.

#[test]
fn split_residual_replay_via_oplog_returns_replayed() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    // Checkpoint to set cursor within the new parent range.
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"d"),
            OpId::from_raw(100),
        )
        .unwrap();

    let new_parent_spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
    let residual_spec = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
    let plan = SplitResidualPlan::try_new(new_parent_spec, residual_spec).unwrap();
    let op = OpId::from_raw(1);

    // First execution.
    let first = coord
        .split_residual(now(3), test_tenant(), &lease, plan.clone(), op)
        .unwrap();
    assert!(first.is_executed());

    // Immediate replay (op-log still has the entry) — same op_id + plan.
    let second = coord
        .split_residual(now(4), test_tenant(), &lease, plan.clone(), op)
        .unwrap();
    assert!(
        second.is_replay(),
        "immediate replay should return Replayed, got: {second:?}",
    );
    assert_eq!(first.as_ref().residual, second.as_ref().residual);

    // Same op_id, different plan (different split point) — OpIdConflict.
    let plan_b = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"p".to_vec()),
        ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
    )
    .unwrap();
    let err = coord
        .split_residual(now(5), test_tenant(), &lease, plan_b, op)
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::OpIdConflict { .. }),
        "same op_id + different plan should return OpIdConflict, got: {err:?}",
    );
}

// -- split_residual then continued parent ops ---------------------------
//
// After split_residual, the parent's key range is shrunk. Operations on
// the parent must respect the new bounds: checkpoints within the shrunk
// range succeed, checkpoints outside it fail with CursorOutOfBounds,
// and complete within the shrunk range succeeds.

#[test]
fn split_residual_parent_continues_with_shrunk_range() {
    let mut coord = seeded_coordinator(); // [a, z)
    let lease = acquire_shard(&mut coord, 1, 1);

    // Step 1: Checkpoint to "d" (within [a, z)).
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"d"),
            OpId::from_raw(100),
        )
        .unwrap();

    // Step 2: Split residual — shrink parent to [a, m), residual [m, z).
    let plan = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();
    let split_result = coord
        .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(200))
        .unwrap();
    assert!(split_result.is_executed());

    // Step 3: Checkpoint at "f" (within [a, m)) — should succeed.
    let cp = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            test_cursor(b"f"),
            OpId::from_raw(300),
        )
        .unwrap();
    assert!(cp.is_executed());

    // Step 4: Checkpoint at "n" (within [m, z), outside new parent) — should fail.
    let err = coord
        .checkpoint(
            now(5),
            test_tenant(),
            &lease,
            test_cursor(b"n"),
            OpId::from_raw(400),
        )
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::CursorOutOfBounds { .. }),
        "cursor outside shrunk parent range should fail, got: {err:?}",
    );

    // Step 5: Complete at "g" (within [a, m)) — should succeed.
    let complete = coord
        .complete(
            now(6),
            test_tenant(),
            &lease,
            test_cursor(b"g"),
            OpId::from_raw(500),
        )
        .unwrap();
    assert!(complete.is_executed());
}

// -- Lifecycle integration tests -----------------------------------------------
//
// Multi-step tests that chain operations into complete shard lifecycles.
// These verify that the coordinator's state machine transitions compose
// correctly across acquire, checkpoint, split, re-acquire, and complete.
// The first test exercises a single split_residual; the second performs
// two successive splits to verify iterative parent narrowing.

#[test]
fn full_lifecycle_acquire_checkpoint_split_residual_complete() {
    let mut coord = seeded_coordinator(); // [a, z)

    // Step 1: Acquire shard (worker 1, t=1).
    let lease_w1 = acquire_shard(&mut coord, 1, 1);

    // Step 2: Checkpoint to "f" (t=2, op_id=10).
    let cp_result = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease_w1,
            test_cursor(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();
    assert!(cp_result.is_executed());

    // Step 3: Split residual [a,m) + [m,z) (t=3, op_id=20).
    let plan = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();
    let split_result = coord
        .split_residual(now(3), test_tenant(), &lease_w1, plan, OpId::from_raw(20))
        .unwrap();
    assert!(split_result.is_executed());
    let residual_id = split_result.into_inner().residual;

    // Step 4: Parent still Active — re-acquire after lease expiry (worker 2).
    let lease_w2 = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 4),
            test_tenant(),
            test_key(),
            test_worker(2),
        )
        .unwrap()
        .lease;

    // Step 5: Complete parent (t=LEASE_DURATION+5, op_id=30).
    let complete_result = coord
        .complete(
            now(LEASE_DURATION + 5),
            test_tenant(),
            &lease_w2,
            test_cursor(b"l"), // within [a, m)
            OpId::from_raw(30),
        )
        .unwrap();
    assert!(complete_result.is_executed());

    // Step 6: Acquire residual child (worker 3).
    let residual_key = ShardKey::new(test_run(), residual_id);
    let child_result = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 6),
            test_tenant(),
            residual_key,
            test_worker(3),
        )
        .unwrap();
    // Verify snapshot has the residual range [m, z).
    assert_eq!(
        child_result.snapshot.spec().key_range_start(),
        b"m".as_slice(),
    );
    assert_eq!(
        child_result.snapshot.spec().key_range_end(),
        b"z".as_slice(),
    );
    let child_lease = child_result.lease;

    // Step 7: Checkpoint residual child to "p".
    let _ = coord
        .checkpoint(
            now(LEASE_DURATION + 7),
            test_tenant(),
            &child_lease,
            test_cursor(b"p"),
            OpId::from_raw(40),
        )
        .unwrap();

    // Step 8: Complete residual child.
    let child_complete = coord
        .complete(
            now(LEASE_DURATION + 8),
            test_tenant(),
            &child_lease,
            test_cursor(b"y"), // within [m, z)
            OpId::from_raw(50),
        )
        .unwrap();
    assert!(child_complete.is_executed());

    // Step 9: Verify both parent and child are terminal.
    let parent_err = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 9),
            test_tenant(),
            test_key(),
            test_worker(4),
        )
        .unwrap_err();
    assert!(
        matches!(parent_err, AcquireError::ShardTerminal { .. }),
        "parent should be terminal, got: {parent_err:?}",
    );

    let child_err = coord
        .acquire_and_restore(
            now(LEASE_DURATION + 10),
            test_tenant(),
            residual_key,
            test_worker(4),
        )
        .unwrap_err();
    assert!(
        matches!(child_err, AcquireError::ShardTerminal { .. }),
        "child should be terminal, got: {child_err:?}",
    );
}

#[test]
fn lifecycle_split_residual_twice_then_complete_children() {
    let mut coord = seeded_coordinator(); // [a, z)

    // Step 1: Acquire, checkpoint to "d".
    let lease = acquire_shard(&mut coord, 1, 1);
    let _ = coord
        .checkpoint(
            now(2),
            test_tenant(),
            &lease,
            test_cursor(b"d"),
            OpId::from_raw(10),
        )
        .unwrap();

    // Step 2: split_residual [a,m) + [m,z) — capture residual_1.
    let plan1 = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();
    let r1 = coord
        .split_residual(now(3), test_tenant(), &lease, plan1, OpId::from_raw(20))
        .unwrap();
    let residual_1 = r1.into_inner().residual;

    // Step 3: Checkpoint parent further to "g" (within [a, m)).
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            test_cursor(b"g"),
            OpId::from_raw(30),
        )
        .unwrap();

    // Step 4: split_residual again [a,j) + [j,m) — capture residual_2.
    let plan2 = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"j".to_vec()),
        ShardSpec::with_range(b"j".to_vec(), b"m".to_vec()),
    )
    .unwrap();
    let r2 = coord
        .split_residual(now(5), test_tenant(), &lease, plan2, OpId::from_raw(40))
        .unwrap();
    let residual_2 = r2.into_inner().residual;

    // Step 5: Complete parent [a, j).
    let _ = coord
        .complete(
            now(6),
            test_tenant(),
            &lease,
            test_cursor(b"i"), // within [a, j)
            OpId::from_raw(50),
        )
        .unwrap();

    // Step 6: Acquire + complete residual_1 [m, z).
    let r1_key = ShardKey::new(test_run(), residual_1);
    let r1_acq = coord
        .acquire_and_restore(now(7), test_tenant(), r1_key, test_worker(2))
        .unwrap();
    assert_eq!(r1_acq.snapshot.spec().key_range_start(), b"m".as_slice());
    assert_eq!(r1_acq.snapshot.spec().key_range_end(), b"z".as_slice());
    let _ = coord
        .complete(
            now(8),
            test_tenant(),
            &r1_acq.lease,
            test_cursor(b"y"),
            OpId::from_raw(60),
        )
        .unwrap();

    // Step 7: Acquire + complete residual_2 [j, m).
    let r2_key = ShardKey::new(test_run(), residual_2);
    let r2_acq = coord
        .acquire_and_restore(now(9), test_tenant(), r2_key, test_worker(3))
        .unwrap();
    assert_eq!(r2_acq.snapshot.spec().key_range_start(), b"j".as_slice());
    assert_eq!(r2_acq.snapshot.spec().key_range_end(), b"m".as_slice());
    let _ = coord
        .complete(
            now(10),
            test_tenant(),
            &r2_acq.lease,
            test_cursor(b"l"),
            OpId::from_raw(70),
        )
        .unwrap();

    // Step 8: All three are terminal.
    let parent_err = coord
        .acquire_and_restore(now(11), test_tenant(), test_key(), test_worker(4))
        .unwrap_err();
    assert!(matches!(parent_err, AcquireError::ShardTerminal { .. }));

    let r1_err = coord
        .acquire_and_restore(now(12), test_tenant(), r1_key, test_worker(4))
        .unwrap_err();
    assert!(matches!(r1_err, AcquireError::ShardTerminal { .. }));

    let r2_err = coord
        .acquire_and_restore(now(13), test_tenant(), r2_key, test_worker(4))
        .unwrap_err();
    assert!(matches!(r2_err, AcquireError::ShardTerminal { .. }));
}

// -- RunManagement tests --------------------------------------------------
//
// Tests for the RunManagement trait: create_run, register_shards,
// complete_run, fail_run, cancel_run, unpark_shard, list_shards, and
// create_run_with_shards. Covers the run state machine
// (Initializing -> Active -> Done|Failed|Cancelled), idempotent replay,
// OpIdConflict, wrong-status rejections, terminal irreversibility,
// shard count limits on register_shards, and split-index visibility
// (children appear in list_shards and get_run_progress after split).

use crate::coordination::run::{InitialShard, RunConfig, RunManagement, RunStatus, ShardFilter};
use crate::coordination::shard_spec::ShardLimitScope;

/// Standard [`RunConfig`] for run-management tests.
///
/// Uses `CursorSemantics::Completed`, a 30-tick checkpoint interval,
/// and an error threshold of 5. The specific values are not critical;
/// what matters is that they are valid and consistent across tests.
fn test_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
}

// -- Split index consistency tests --
//
// After a split, child shards must be visible through the run-level
// APIs (get_run_progress, list_shards). These tests verify the
// coordinator's split index is updated atomically with the split.

/// Creates a coordinator with a fully initialized run and an acquired lease.
///
/// Performs: `create_run` -> `register_shards` (one shard `[a,z)`) ->
/// `acquire_and_restore`. Returns `(coordinator, lease)` ready for
/// split, park, or completion tests. Time advances through t=1..3;
/// callers should start at t=4.
fn coordinator_with_run_and_lease() -> (InMemoryCoordinator, Lease) {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));
    let lease = coord
        .acquire_and_restore(now(3), test_tenant(), key, test_worker(1))
        .unwrap()
        .lease;
    (coord, lease)
}

/// Performs the canonical `split_replace` on `[a,z)` into `[a,m)` and `[m,z)`.
///
/// Uses t=4 and OpId=2. Panics on failure. Intended to be called after
/// [`coordinator_with_run_and_lease`] to set up a post-split state for
/// index-consistency and filter tests.
fn do_split_replace(coord: &mut InMemoryCoordinator, lease: &Lease) {
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();
    let _ = coord
        .split_replace(now(4), test_tenant(), lease, plan, OpId::from_raw(2))
        .unwrap();
}

#[test]
fn split_replace_children_visible_in_run_progress() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    let progress = coord
        .get_run_progress(now(5), test_tenant(), test_run())
        .unwrap();
    assert!(
        progress.total() >= 3,
        "expected total >= 3 (parent + 2 children), got {}",
        progress.total(),
    );
    assert_eq!(progress.split(), 1, "parent should be Split");
    assert_eq!(progress.active(), 2, "two children should be Active");
}

#[test]
fn split_replace_children_visible_in_list_shards() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    let all = coord
        .list_shards(now(5), test_tenant(), test_run(), ShardFilter::all())
        .unwrap();
    assert!(
        all.len() >= 3,
        "expected >= 3 shards in listing (parent + 2 children), got {}",
        all.len(),
    );

    let starts: Vec<&[u8]> = all.iter().map(|s| s.key_range_start()).collect();
    assert!(
        starts.contains(&b"a".as_slice()) && starts.contains(&b"m".as_slice()),
        "children [a,m) and [m,z) should be in listing; starts = {starts:?}",
    );
}

#[test]
fn split_residual_child_visible_in_list_shards() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // Checkpoint to set cursor within new parent range.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            Cursor::with_last_key(b"f".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();

    // Split residual: parent shrinks to [a,m), residual gets [m,z).
    let plan = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap();
    let _ = coord
        .split_residual(now(5), test_tenant(), &lease, plan, OpId::from_raw(2))
        .unwrap();

    let all = coord
        .list_shards(now(6), test_tenant(), test_run(), ShardFilter::all())
        .unwrap();
    assert!(
        all.len() >= 2,
        "expected >= 2 shards (parent + residual), got {}",
        all.len(),
    );

    let has_residual = all
        .iter()
        .any(|s| s.key_range_start() == b"m" && s.key_range_end() == b"z");
    assert!(has_residual, "residual [m,z) should be in listing");
}

// -- Shard count limit tests for register_shards --
//
// register_shards is subject to the same per-tenant and global shard
// count limits as split operations. These tests verify that bulk
// registration rejects the entire batch when limits would be breached.

#[test]
fn register_shards_exceeds_per_tenant_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 3, 1_000_000);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards: Vec<InitialShard> = (0..4)
        .map(|i| {
            let start = vec![b'a' + (i * 5) as u8];
            let end = vec![b'a' + (i * 5 + 4) as u8];
            InitialShard::new(
                ShardId::from_raw(i),
                ShardSpec::with_range(start, end),
                Cursor::initial(),
            )
        })
        .collect();

    let err = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::PerTenant,
                ..
            }
        ),
        "expected ShardLimitExceeded(PerTenant), got: {err:?}",
    );
}

#[test]
fn register_shards_exceeds_global_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 1000, 3);

    // Seed 2 existing shards from a different tenant.
    let other = TenantId::from_bytes([0x02; 32]);
    coord.seed_shard(ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(90),
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        CursorSemantics::Completed,
    ));
    coord.seed_shard(ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(91),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
    ));

    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards = vec![
        InitialShard::new(
            ShardId::from_raw(10),
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(11),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];

    let err = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::Global,
                ..
            }
        ),
        "expected ShardLimitExceeded(Global), got: {err:?}",
    );
}

#[test]
fn register_shards_within_limits_succeeds() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 10, 100);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards = vec![
        InitialShard::new(
            ShardId::from_raw(10),
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(11),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];

    let result = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(result.is_executed());
}

// -- register_shards cursor preservation (regression guard) --
//
// Shards can be registered with a non-initial cursor (e.g., resuming a
// previous run). The coordinator must preserve the cursor as-is rather
// than resetting it to initial.

#[test]
fn register_shards_preserves_non_initial_cursors() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::with_last_key(b"f".to_vec()),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    let key = ShardKey::new(test_run(), ShardId::from_raw(10));
    let result = coord
        .acquire_and_restore(now(3), test_tenant(), key, test_worker(1))
        .unwrap();
    assert_eq!(
        result.snapshot.cursor().last_key(),
        Some(b"f".as_slice()),
        "non-initial cursor must be preserved after register_shards",
    );
}

// -- complete_run tests -------------------------------------------------------
//
// Transitions a run from Active to Done. Verifies: happy path, rejection
// from Initializing state, terminal irreversibility (Done -> Done fails),
// not-found error, and idempotent replay.

/// Creates a coordinator with a run in Active state (one shard registered).
///
/// Performs: `create_run` -> `register_shards`. Unlike
/// [`coordinator_with_run_and_lease`], this does **not** acquire a lease,
/// making it suitable for run-level operation tests (complete_run,
/// fail_run, cancel_run) that do not need a shard lease. Time advances
/// through t=1..2; callers should start at t=3.
fn active_run_coordinator() -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    coord
}

#[test]
fn complete_run_happy_path() {
    let mut coord = active_run_coordinator();
    let result = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Done);
    assert_eq!(record.completed_at(), Some(now(3)));
}

#[test]
fn complete_run_wrong_status_initializing() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let err = coord
        .complete_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CompleteRunError::WrongStatus {
                status: RunStatus::Initializing
            }
        ),
        "expected WrongStatus(Initializing), got: {err:?}",
    );
}

#[test]
fn complete_run_terminal_already_done() {
    let mut coord = active_run_coordinator();
    let _ = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();

    let err = coord
        .complete_run(now(4), test_tenant(), test_run(), OpId::from_raw(3))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CompleteRunError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got: {err:?}",
    );
}

#[test]
fn complete_run_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let err = coord
        .complete_run(now(1), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, CompleteRunError::RunNotFound));
}

#[test]
fn complete_run_idempotent_replay() {
    let mut coord = active_run_coordinator();
    let op = OpId::from_raw(2);
    let first = coord
        .complete_run(now(3), test_tenant(), test_run(), op)
        .unwrap();
    assert!(first.is_executed());

    let second = coord
        .complete_run(now(4), test_tenant(), test_run(), op)
        .unwrap();
    assert!(second.is_replay());
}

// -- fail_run tests -----------------------------------------------------------
//
// Transitions a run from Active to Failed. Mirrors complete_run tests:
// happy path, wrong-status rejection, terminal irreversibility, and
// idempotent replay.

#[test]
fn fail_run_happy_path() {
    let mut coord = active_run_coordinator();
    let result = coord
        .fail_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Failed);
    assert_eq!(record.completed_at(), Some(now(3)));
}

#[test]
fn fail_run_wrong_status_initializing() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let err = coord
        .fail_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(
            err,
            FailRunError::WrongStatus {
                status: RunStatus::Initializing
            }
        ),
        "expected WrongStatus(Initializing), got: {err:?}",
    );
}

#[test]
fn fail_run_terminal() {
    let mut coord = active_run_coordinator();
    let _ = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();

    let err = coord
        .fail_run(now(4), test_tenant(), test_run(), OpId::from_raw(3))
        .unwrap_err();
    assert!(
        matches!(
            err,
            FailRunError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got: {err:?}",
    );
}

#[test]
fn fail_run_idempotent_replay() {
    let mut coord = active_run_coordinator();
    let op = OpId::from_raw(2);
    let first = coord
        .fail_run(now(3), test_tenant(), test_run(), op)
        .unwrap();
    assert!(first.is_executed());

    let second = coord
        .fail_run(now(4), test_tenant(), test_run(), op)
        .unwrap();
    assert!(second.is_replay());
}

// -- cancel_run tests ---------------------------------------------------------
//
// cancel_run is the only terminal transition allowed from Initializing
// (in addition to Active). Covers both source states, terminal
// irreversibility, and idempotent replay.

#[test]
fn cancel_run_from_initializing() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let result = coord
        .cancel_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Cancelled);
    assert_eq!(record.completed_at(), Some(now(2)));
}

#[test]
fn cancel_run_from_active() {
    let mut coord = active_run_coordinator();
    let result = coord
        .cancel_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Cancelled);
}

#[test]
fn cancel_run_terminal() {
    let mut coord = active_run_coordinator();
    let _ = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();

    let err = coord
        .cancel_run(now(4), test_tenant(), test_run(), OpId::from_raw(3))
        .unwrap_err();
    assert!(
        matches!(
            err,
            CancelRunError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got: {err:?}",
    );
}

#[test]
fn cancel_run_idempotent_replay() {
    let mut coord = active_run_coordinator();
    let op = OpId::from_raw(2);
    let first = coord
        .cancel_run(now(3), test_tenant(), test_run(), op)
        .unwrap();
    assert!(first.is_executed());

    let second = coord
        .cancel_run(now(4), test_tenant(), test_run(), op)
        .unwrap();
    assert!(second.is_replay());
}

// -- Terminal ops timestamp tests ---------------------------------------------
//
// All three terminal run transitions (complete, fail, cancel) must
// persist the timestamp of the transition in `completed_at`.

#[test]
fn terminal_ops_set_completed_at() {
    // complete_run sets completed_at
    let mut c1 = active_run_coordinator();
    let _ = c1
        .complete_run(now(10), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert_eq!(
        c1.get_run(test_tenant(), test_run())
            .unwrap()
            .completed_at(),
        Some(now(10)),
    );

    // fail_run sets completed_at
    let mut c2 = active_run_coordinator();
    let _ = c2
        .fail_run(now(20), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert_eq!(
        c2.get_run(test_tenant(), test_run())
            .unwrap()
            .completed_at(),
        Some(now(20)),
    );

    // cancel_run from Active sets completed_at
    let mut c3 = active_run_coordinator();
    let _ = c3
        .cancel_run(now(30), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();
    assert_eq!(
        c3.get_run(test_tenant(), test_run())
            .unwrap()
            .completed_at(),
        Some(now(30)),
    );
}

// -- OpIdConflict across run operations ---------------------------------------
//
// Run-level operations share a single per-run op-log. An OpId used by
// register_shards cannot be reused by complete_run (different payload
// hash), even though they are different operation types.

#[test]
fn run_op_id_conflict_across_ops() {
    let mut coord = active_run_coordinator();
    // register_shards used op_id=1. Now complete_run with same op_id=1 but
    // different payload hash → OpIdConflict.
    let err = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, CompleteRunError::OpIdConflict(_)),
        "expected OpIdConflict when reusing register_shards op_id for complete_run, got: {err:?}",
    );
}

// -- unpark_shard tests -------------------------------------------------------
//
// unpark_shard is an admin operation that transitions Parked -> Active,
// bumps the fence epoch (invalidating any stale leases), clears the
// park_reason, and preserves the cursor. Tests cover: happy path,
// fence bump verification, cursor preservation, idempotent replay,
// not-parked rejection, not-found error, full park->unpark->reacquire
// workflow, and rejection when the owning run is terminal.

#[test]
fn unpark_shard_happy_path() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Park the shard.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Unpark.
    let result = coord
        .unpark_shard(now(5), test_tenant(), key, OpId::from_raw(11))
        .unwrap();
    assert!(result.is_executed());

    // Verify shard is Active again.
    let record = coord.shard_lookup(&test_tenant(), &key).unwrap();
    assert_eq!(record.status, ShardStatus::Active);
    assert!(record.park_reason.is_none());
    assert!(record.lease.is_none());
}

#[test]
fn unpark_shard_fence_epoch_bumped() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    let before_park = coord
        .shard_lookup(&test_tenant(), &key)
        .unwrap()
        .fence_epoch;

    // Park.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Unpark.
    let _ = coord
        .unpark_shard(now(5), test_tenant(), key, OpId::from_raw(11))
        .unwrap();

    let after_unpark = coord
        .shard_lookup(&test_tenant(), &key)
        .unwrap()
        .fence_epoch;
    assert!(
        after_unpark > before_park,
        "fence_epoch must increase after unpark: {before_park:?} vs {after_unpark:?}",
    );
}

#[test]
fn unpark_shard_cursor_preserved() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Checkpoint to set cursor.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            Cursor::with_last_key(b"f".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();

    // Park.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(11),
        )
        .unwrap();

    // Unpark.
    let _ = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap();

    let record = coord.shard_lookup(&test_tenant(), &key).unwrap();
    assert_eq!(
        record.cursor.last_key(),
        Some(b"f".as_slice()),
        "cursor must be preserved through park→unpark",
    );
}

#[test]
fn unpark_shard_idempotent_replay() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    let op = OpId::from_raw(11);
    let first = coord.unpark_shard(now(5), test_tenant(), key, op).unwrap();
    assert!(first.is_executed());

    let second = coord.unpark_shard(now(6), test_tenant(), key, op).unwrap();
    assert!(second.is_replay());
}

#[test]
fn unpark_shard_not_parked() {
    let (mut coord, _lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Shard is Active, not Parked.
    let err = coord
        .unpark_shard(now(4), test_tenant(), key, OpId::from_raw(10))
        .unwrap_err();
    assert!(
        matches!(err, UnparkError::NotParked { .. }),
        "expected NotParked, got: {err:?}",
    );
}

#[test]
fn unpark_shard_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let key = ShardKey::new(test_run(), ShardId::from_raw(99));
    let err = coord
        .unpark_shard(now(1), test_tenant(), key, OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, UnparkError::ShardNotFound));
}

#[test]
fn unpark_then_reacquire_and_checkpoint() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Checkpoint → Park → Unpark → Re-acquire → Checkpoint works.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            Cursor::with_last_key(b"d".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(11),
        )
        .unwrap();
    let _ = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap();

    // Re-acquire with a new worker.
    let new_result = coord
        .acquire_and_restore(now(7), test_tenant(), key, test_worker(2))
        .unwrap();
    let new_lease = new_result.lease;
    assert_eq!(
        new_result.snapshot.cursor().last_key(),
        Some(b"d".as_slice()),
        "cursor must survive park→unpark→reacquire",
    );

    // Checkpoint from the resumed position.
    let cp = coord
        .checkpoint(
            now(8),
            test_tenant(),
            &new_lease,
            Cursor::with_last_key(b"g".to_vec()),
            OpId::from_raw(13),
        )
        .unwrap();
    assert!(cp.is_executed());
}

// -- unpark_shard run-status check tests -----------------------------------
//
// Unparking must be blocked when the owning run has reached a terminal
// state (Cancelled or Done). Reactivating a shard in a dead run would
// violate the run lifecycle contract.

#[test]
fn unpark_shard_rejected_when_run_cancelled() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Park the shard.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Cancel the run.
    let _ = coord
        .cancel_run(now(5), test_tenant(), test_run(), OpId::from_raw(11))
        .unwrap();

    // Attempt unpark → should fail with RunTerminal.
    let err = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap_err();
    assert!(
        matches!(
            err,
            UnparkError::RunTerminal {
                status: RunStatus::Cancelled
            }
        ),
        "expected RunTerminal(Cancelled), got: {err:?}",
    );
}

#[test]
fn unpark_shard_rejected_when_run_done() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Park the shard.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Complete the run.
    let _ = coord
        .complete_run(now(5), test_tenant(), test_run(), OpId::from_raw(11))
        .unwrap();

    // Attempt unpark → should fail with RunTerminal.
    let err = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap_err();
    assert!(
        matches!(
            err,
            UnparkError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got: {err:?}",
    );
}

// -- register_shards error path tests -----------------------------------------
//
// Covers register_shards edge cases: idempotent replay (same OpId +
// payload returns Replayed with identical shard IDs), OpIdConflict
// (same OpId + different shard list), wrong-status rejection (run
// already Active), and not-found error.

#[test]
fn register_shards_idempotent_replay() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let op = OpId::from_raw(1);

    let first = coord
        .register_shards(now(2), test_tenant(), test_run(), &shards, op)
        .unwrap();
    assert!(first.is_executed());
    let first_ids = first.into_inner();

    let second = coord
        .register_shards(now(3), test_tenant(), test_run(), &shards, op)
        .unwrap();
    assert!(second.is_replay());
    assert_eq!(second.into_inner(), first_ids);
}

#[test]
fn register_shards_op_id_conflict() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();

    let shards_a = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let op = OpId::from_raw(1);
    let _ = coord
        .register_shards(now(2), test_tenant(), test_run(), &shards_a, op)
        .unwrap();

    // Same op_id, different payload (different shard IDs).
    let shards_b = vec![InitialShard::new(
        ShardId::from_raw(20),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let err = coord
        .register_shards(now(3), test_tenant(), test_run(), &shards_b, op)
        .unwrap_err();
    assert!(
        matches!(err, RegisterShardsError::OpIdConflict(_)),
        "expected OpIdConflict, got: {err:?}",
    );
}

#[test]
fn register_shards_wrong_status_active() {
    let mut coord = active_run_coordinator();
    // Run is already Active.
    let shards = vec![InitialShard::new(
        ShardId::from_raw(20),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let err = coord
        .register_shards(
            now(3),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(99),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::WrongStatus {
                status: RunStatus::Active
            }
        ),
        "expected WrongStatus(Active), got: {err:?}",
    );
}

#[test]
fn register_shards_run_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let err = coord
        .register_shards(
            now(1),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(matches!(err, RegisterShardsError::RunNotFound));
}

// -- create_run_with_shards tests ---------------------------------------------
//
// Atomic create+register convenience method. Covers: fresh creation
// (run lands in Active immediately), idempotent retry with same config
// and OpId, and config mismatch detection on retry with different
// RunConfig.

#[test]
fn create_run_with_shards_fresh() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let result = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            test_run_config(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(result.is_executed());
    let record = result.into_inner();
    assert_eq!(record.status(), RunStatus::Active);
}

#[test]
fn create_run_with_shards_retry_same_config() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let op = OpId::from_raw(1);

    // First call.
    let _ = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            test_run_config(),
            &shards,
            op,
        )
        .unwrap();

    // Retry with same config and op_id → replayed.
    let second = coord
        .create_run_with_shards(
            now(2),
            test_tenant(),
            test_run(),
            test_run_config(),
            &shards,
            op,
        )
        .unwrap();
    assert!(second.is_replay());
}

#[test]
fn create_run_with_shards_config_mismatch() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let shards = vec![InitialShard::new(
        ShardId::from_raw(10),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];

    let _ = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            test_run_config(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    // Retry with different config.
    let different_config = RunConfig::try_new(CursorSemantics::Completed, 60, Some(10)).unwrap();
    let err = coord
        .create_run_with_shards(
            now(2),
            test_tenant(),
            test_run(),
            different_config,
            &shards,
            OpId::from_raw(2),
        )
        .unwrap_err();
    assert!(
        matches!(err, CreateRunError::ConfigMismatch { .. }),
        "expected ConfigMismatch, got: {err:?}",
    );
}

// -- Full run lifecycle end-to-end test ----------------------------------------
//
// Exercises the complete run lifecycle: create_run -> register_shards ->
// acquire -> checkpoint -> complete (per shard) -> verify progress ->
// complete_run. Verifies that all state transitions compose correctly
// and that run progress reflects shard completion accurately.

#[test]
fn full_run_lifecycle_create_register_process_complete() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);

    // Step 1: Create run.
    let _ = coord
        .create_run(now(1), test_tenant(), test_run(), test_run_config())
        .unwrap();
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Initializing);

    // Step 2: Register two shards [a,m) and [m,z).
    let shards = vec![
        InitialShard::new(
            ShardId::from_raw(10),
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(11),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];
    let reg_result = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(reg_result.is_executed());
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Active);
    assert_eq!(record.root_shards().len(), 2);

    // Step 3: Acquire + checkpoint + complete shard 10.
    let key_10 = ShardKey::new(test_run(), ShardId::from_raw(10));
    let lease_10 = coord
        .acquire_and_restore(now(3), test_tenant(), key_10, test_worker(1))
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease_10,
            Cursor::with_last_key(b"f".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(5),
            test_tenant(),
            &lease_10,
            Cursor::with_last_key(b"l".to_vec()),
            OpId::from_raw(11),
        )
        .unwrap();

    // Step 4: Acquire + complete shard 11.
    let key_11 = ShardKey::new(test_run(), ShardId::from_raw(11));
    let lease_11 = coord
        .acquire_and_restore(now(6), test_tenant(), key_11, test_worker(2))
        .unwrap()
        .lease;
    let _ = coord
        .complete(
            now(7),
            test_tenant(),
            &lease_11,
            Cursor::with_last_key(b"y".to_vec()),
            OpId::from_raw(12),
        )
        .unwrap();

    // Step 5: Verify progress — all done.
    let progress = coord
        .get_run_progress(now(8), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.total(), 2);
    assert_eq!(progress.done(), 2);
    assert_eq!(progress.active(), 0);
    assert!(progress.is_success());

    // Step 6: Complete the run.
    let run_result = coord
        .complete_run(now(9), test_tenant(), test_run(), OpId::from_raw(20))
        .unwrap();
    assert!(run_result.is_executed());
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Done);
    assert_eq!(record.completed_at(), Some(now(9)));
}

// -- list_shards filter correctness tests -------------------------------------
//
// list_shards supports predicate-based filtering (active, available,
// parked, root_only). Tests verify each filter correctly includes or
// excludes shards based on status, lease state, and parentage.

#[test]
fn list_shards_filter_active() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // Shard is Active + leased.
    let active_all = coord
        .list_shards(now(4), test_tenant(), test_run(), ShardFilter::active())
        .unwrap();
    assert_eq!(
        active_all.len(),
        1,
        "active filter should include leased Active shard"
    );

    // Park it.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    let active_after_park = coord
        .list_shards(now(6), test_tenant(), test_run(), ShardFilter::active())
        .unwrap();
    assert!(
        active_after_park.is_empty(),
        "active filter should exclude Parked shard",
    );
}

#[test]
fn list_shards_filter_available() {
    let (coord, _lease) = coordinator_with_run_and_lease();

    // Shard is Active + leased → available() requires is_leased=false.
    let available = coord
        .list_shards(now(4), test_tenant(), test_run(), ShardFilter::available())
        .unwrap();
    assert!(
        available.is_empty(),
        "available filter should exclude leased Active shard",
    );

    // After lease expiry, shard becomes available.
    let available_after = coord
        .list_shards(
            now(LEASE_DURATION + 10),
            test_tenant(),
            test_run(),
            ShardFilter::available(),
        )
        .unwrap();
    assert_eq!(
        available_after.len(),
        1,
        "shard should be available after lease expiry"
    );
}

#[test]
fn list_shards_filter_parked() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // No parked shards initially.
    let parked = coord
        .list_shards(now(4), test_tenant(), test_run(), ShardFilter::parked())
        .unwrap();
    assert!(parked.is_empty());

    // Park the shard.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    let parked_after = coord
        .list_shards(now(6), test_tenant(), test_run(), ShardFilter::parked())
        .unwrap();
    assert_eq!(parked_after.len(), 1);
    assert_eq!(parked_after[0].status(), ShardStatus::Parked);
}

#[test]
fn list_shards_filter_root_only() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    // root_only should exclude split children.
    let root_filter = ShardFilter {
        root_only: true,
        ..ShardFilter::default()
    };
    let roots = coord
        .list_shards(now(5), test_tenant(), test_run(), root_filter)
        .unwrap();
    // The parent (root) is Split, children are derived (have parent).
    // root_only excludes shards with parent.is_some().
    for s in &roots {
        assert!(
            s.parent().is_none(),
            "root_only filter should exclude children; found shard with parent: {:?}",
            s.parent(),
        );
    }

    // Without root_only, we get all (parent + children).
    let all = coord
        .list_shards(now(5), test_tenant(), test_run(), ShardFilter::all())
        .unwrap();
    assert!(
        all.len() > roots.len(),
        "all filter should include more shards than root_only: all={} vs roots={}",
        all.len(),
        roots.len(),
    );
}

// ============================================================================
// Property tests
// ============================================================================
//
// These tests use proptest to generate random operation sequences and verify
// that structural invariants hold after every step. They complement the
// deterministic unit tests above by exploring operation orderings and
// parameter combinations that a human would not enumerate by hand.

use crate::test_util::miri_proptest_config;
use proptest::prelude::*;

/// The universe of operations that can be applied to a coordinator in the
/// property tests. Each variant maps to one `CoordinationBackend` or
/// `RunManagement` method. `TimeAdvance` simulates the passage of logical
/// time (enabling lease expiry between operations).
#[derive(Debug, Clone)]
enum Op {
    Acquire {
        worker: u8,
    },
    Checkpoint {
        cursor_key: u8,
    },
    Complete {
        cursor_key: u8,
    },
    Park,
    Renew,
    SplitReplace,
    SplitResidual,
    TimeAdvance {
        ticks: u64,
    },
    /// Run-level: complete the run (Active → Done).
    CompleteRun,
    /// Run-level: fail the run (Active → Failed).
    FailRun,
    /// Run-level: cancel the run (any non-terminal → Cancelled).
    CancelRun,
    /// Run-level: unpark a parked shard.
    UnparkShard,
}

/// Proptest strategy that generates random coordinator operations.
///
/// Weights are tuned to produce realistic mixes: Checkpoint is most
/// common (4x) because it is the most frequent production operation;
/// Acquire (3x) and Renew/TimeAdvance (2x each) ensure frequent lease
/// churn; terminal and split operations are rare (1x each) to avoid
/// sequences that immediately deadlock on a terminal shard.
fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..4).prop_map(|w| Op::Acquire { worker: w }),
        4 => (b'a'..b'y').prop_map(|k| Op::Checkpoint { cursor_key: k }),
        2 => (b'a'..b'y').prop_map(|k| Op::Complete { cursor_key: k }),
        1 => Just(Op::Park),
        2 => Just(Op::Renew),
        1 => Just(Op::SplitReplace),
        1 => Just(Op::SplitResidual),
        2 => (1u64..200).prop_map(|t| Op::TimeAdvance { ticks: t }),
        1 => Just(Op::CompleteRun),
        1 => Just(Op::FailRun),
        1 => Just(Op::CancelRun),
        1 => Just(Op::UnparkShard),
    ]
}

/// Applies a single [`Op`] to the coordinator, threading time and op counter.
///
/// Returns `(new_time, new_op_counter)`. Operations that consume an OpId
/// increment the counter; operations that fail or do not use an OpId
/// leave it unchanged. All errors are silently discarded because the
/// property tests assert invariants *after* each op, not individual
/// success/failure outcomes.
fn apply_op(
    coord: &mut InMemoryCoordinator,
    op: &Op,
    time: u64,
    oc: u64,
    last_lease: &mut Option<Lease>,
) -> (u64, u64) {
    let now = LogicalTime::from_raw(time);
    let ten = test_tenant();
    match op {
        Op::Acquire { worker } => {
            if let Ok(r) =
                coord.acquire_and_restore(now, ten, test_key(), WorkerId::from_raw(*worker as u64))
            {
                *last_lease = Some(r.lease);
            }
            (time, oc)
        }
        Op::Checkpoint { cursor_key } => {
            if let Some(lease) = last_lease.as_ref()
                && let Ok(c) = Cursor::try_with_last_key(vec![*cursor_key])
            {
                let _ = coord.checkpoint(now, ten, lease, c, OpId::from_raw(oc));
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Complete { cursor_key } => {
            if let Some(lease) = last_lease.as_ref()
                && let Ok(c) = Cursor::try_with_last_key(vec![*cursor_key])
            {
                let _ = coord.complete(now, ten, lease, c, OpId::from_raw(oc));
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Park => {
            if let Some(lease) = last_lease.as_ref() {
                let _ = coord.park_shard(
                    now,
                    ten,
                    lease,
                    ParkReason::TooManyErrors,
                    OpId::from_raw(oc),
                );
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Renew => {
            if let Some(lease) = last_lease.as_ref() {
                let _ = coord.renew(now, ten, lease);
            }
            (time, oc)
        }
        Op::SplitReplace => {
            if let Some(lease) = last_lease.as_ref() {
                let child_a = SplitReplaceChild::new(
                    ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
                    Cursor::initial(),
                );
                let child_b = SplitReplaceChild::new(
                    ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
                    Cursor::initial(),
                );
                if let Ok(plan) = SplitReplacePlan::try_new(vec![child_a, child_b]) {
                    let _ = coord.split_replace(now, ten, lease, plan, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
            }
            (time, oc)
        }
        Op::SplitResidual => {
            if let Some(lease) = last_lease.as_ref() {
                let new_parent = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
                let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
                if let Ok(plan) = SplitResidualPlan::try_new(new_parent, residual) {
                    let _ = coord.split_residual(now, ten, lease, plan, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
            }
            (time, oc)
        }
        Op::TimeAdvance { ticks } => (time.saturating_add(*ticks), oc),
        Op::CompleteRun => {
            let _ = coord.complete_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::FailRun => {
            let _ = coord.fail_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::CancelRun => {
            let _ = coord.cancel_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::UnparkShard => {
            let _ = coord.unpark_shard(now, ten, test_key(), OpId::from_raw(oc));
            (time, oc + 1)
        }
    }
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// Fuzz test: random operation sequences must preserve shard record invariants.
    ///
    /// Generates 1..100 random operations and applies them to a seeded
    /// coordinator. After *every* operation (whether it succeeds or fails),
    /// every shard record's `assert_invariants()` must pass. This catches
    /// state-machine corruption that only manifests under unusual operation
    /// orderings.
    #[test]
    fn random_ops_preserve_invariants(ops in proptest::collection::vec(arb_op(), 1..100)) {
        let mut coord = seeded_coordinator();
        // Start time after seeded_coordinator setup (which uses t=1, t=2).
        let mut time = 3u64;
        let mut op_counter = 1u64;
        let mut last_lease: Option<Lease> = None;

        for op in ops {
            (time, op_counter) = apply_op(&mut coord, &op, time, op_counter, &mut last_lease);

            // After every op, all records must satisfy invariants.
            for (_, record) in coord.shards() {
                record.assert_invariants();
            }
        }
    }

    /// Fence epoch strictly increases across successive acquisitions.
    ///
    /// Generates 2..20 worker IDs, each acquiring the shard after the
    /// previous lease expires. The fence epoch must be strictly greater
    /// than the previous maximum after every successful acquisition.
    #[test]
    fn fence_monotonicity_property(
        worker_ids in proptest::collection::vec(0u8..4, 2..20),
    ) {
        let mut coord = seeded_coordinator();
        let mut time = 1u64;
        let mut max_fence = FenceEpoch::INITIAL;

        for worker in worker_ids {
            time += LEASE_DURATION + 1; // ensure lease expired
            if let Ok(result) = coord.acquire_and_restore(
                LogicalTime::from_raw(time),
                test_tenant(),
                test_key(),
                WorkerId::from_raw(worker as u64),
            ) {
                let fence = result.lease.fence();
                prop_assert!(
                    fence > max_fence,
                    "fence must strictly increase: {fence:?} <= {max_fence:?}",
                );
                max_fence = fence;
            }
        }
    }

    /// Idempotent replay: any mutating operation (checkpoint, complete, park),
    /// when replayed with the same OpId and identical payload, returns
    /// `Replayed` rather than executing a second time or returning an error.
    ///
    /// Parameterized over random cursor keys, OpId values, and operation
    /// kinds to exercise the replay path with diverse inputs.
    #[test]
    fn idempotent_replay_across_operations(
        cursor_key in b'b'..b'y',
        op_raw in 1u64..1000,
        op_kind in 0u8..3,
    ) {
        let mut coord = seeded_coordinator();
        let ten = test_tenant();
        let lease = coord
            .acquire_and_restore(
                LogicalTime::from_raw(1),
                ten,
                test_key(),
                WorkerId::from_raw(1),
            )
            .unwrap()
            .lease;
        let op = OpId::from_raw(op_raw);
        let cursor = Cursor::with_last_key(vec![cursor_key]);

        match op_kind {
            0 => {
                let first = coord
                    .checkpoint(LogicalTime::from_raw(2), ten, &lease, cursor.clone(), op)
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .checkpoint(LogicalTime::from_raw(3), ten, &lease, cursor, op)
                    .unwrap();
                prop_assert!(second.is_replay());
            }
            1 => {
                let first = coord
                    .complete(LogicalTime::from_raw(2), ten, &lease, cursor.clone(), op)
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .complete(LogicalTime::from_raw(3), ten, &lease, cursor, op)
                    .unwrap();
                prop_assert!(second.is_replay());
            }
            _ => {
                let first = coord
                    .park_shard(
                        LogicalTime::from_raw(2),
                        ten,
                        &lease,
                        ParkReason::TooManyErrors,
                        op,
                    )
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .park_shard(
                        LogicalTime::from_raw(3),
                        ten,
                        &lease,
                        ParkReason::TooManyErrors,
                        op,
                    )
                    .unwrap();
                prop_assert!(second.is_replay());
            }
        }
    }

    /// Cursor monotonicity: within a single lease, checkpoint succeeds only
    /// when the cursor advances (or stays equal), and is rejected with
    /// `CursorRegression` when it would move backwards.
    ///
    /// Generates 2..20 random key bytes and attempts checkpoints in order.
    /// Verifies that success implies `key >= max_seen` and regression
    /// rejection implies `key < max_seen`.
    #[test]
    fn cursor_monotonicity_property(
        keys in proptest::collection::vec(b'a'..b'y', 2..20),
    ) {
        let mut coord = seeded_coordinator();
        let lease = coord
            .acquire_and_restore(
                LogicalTime::from_raw(1),
                test_tenant(),
                test_key(),
                WorkerId::from_raw(1),
            )
            .unwrap()
            .lease;

        let mut max_key: Option<u8> = None;
        let mut op_counter = 1u64;

        for &key_byte in &keys {
            let cursor = Cursor::with_last_key(vec![key_byte]);
            let result = coord.checkpoint(
                LogicalTime::from_raw(op_counter + 1),
                test_tenant(),
                &lease,
                cursor,
                OpId::from_raw(op_counter),
            );
            op_counter += 1;

            match result {
                Ok(_) => {
                    // Checkpoint succeeded — key must be >= max_key.
                    if let Some(prev) = max_key {
                        prop_assert!(key_byte >= prev);
                    }
                    max_key = Some(key_byte);
                }
                Err(CheckpointError::CursorRegression { .. }) => {
                    // Expected: key_byte < max_key, regression rejected.
                    if let Some(prev) = max_key {
                        prop_assert!(key_byte < prev);
                    }
                }
                Err(other) => {
                    prop_assert!(
                        false,
                        "unexpected checkpoint error: {other:?}",
                    );
                }
            }
        }
    }
}
