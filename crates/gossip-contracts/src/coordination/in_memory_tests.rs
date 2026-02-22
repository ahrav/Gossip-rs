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
    LEASE_DURATION, acquire_shard, derived_shard_id, now, other_tenant, seeded_coordinator,
    test_cursor, test_key, test_run, test_shard, test_spec, test_split_replace_plan,
    test_split_residual_plan, test_tenant, test_worker,
};
use crate::identity::FenceEpoch;
use crate::sim::backend::SimIntrospection;
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

    let plan = test_split_replace_plan();

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

    let plan = test_split_replace_plan();

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

    let op = OpId::from_raw(42);
    let r1 = coord1
        .split_replace(
            now(2),
            test_tenant(),
            &lease1,
            test_split_replace_plan(),
            op,
        )
        .unwrap();
    let r2 = coord2
        .split_replace(
            now(2),
            test_tenant(),
            &lease2,
            test_split_replace_plan(),
            op,
        )
        .unwrap();
    assert_eq!(r1.into_inner().children, r2.into_inner().children);
}

/// Three-child split: exercises non-binary fan-out and child ID sorting.
///
/// Splits `[a,z)` into `[m,s)`, `[a,m)`, `[s,z)` — deliberately submitted
/// in non-sorted order to verify the coordinator sorts children by key range.
#[test]
fn split_replace_three_children() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 1, 1);

    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"s".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"s".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();

    let result = coord
        .split_replace(now(2), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());
    assert_eq!(result.as_ref().children.len(), 3);

    // Parent should be terminal (Split).
    let parent = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(parent.status, ShardStatus::Split);

    // All children should exist and be Active.
    for &child_id in &result.as_ref().children {
        let key = ShardKey::new(test_run(), child_id);
        let rec = coord.shard_lookup(&test_tenant(), &key).unwrap();
        assert_eq!(
            rec.status,
            ShardStatus::Active,
            "child {child_id:?} must be Active"
        );
    }
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

    let plan = test_split_residual_plan();

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

    let plan = test_split_residual_plan();

    let err = coord
        .split_residual(now(3), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, SplitResidualError::SplitInvalid(_)));
}

#[test]
fn split_residual_parent_update_failure_deallocates_residual_fields() {
    // Regression guard for the phase-2/phase-3 boundary in split_residual.
    // Capacity math (16-byte min blocks):
    // - Parent spec [a,z): 2 slots => 32 bytes
    // - Residual spec [m,z): 2 slots => 32 bytes (total 64)
    // - Parent update [a,m) needs +32 before releasing old parent slots
    // With slab=64, residual build succeeds, parent update fails.
    let mut runtime = CoordinatorRuntimeConfig::with_limits(LEASE_DURATION, 100, 100);
    runtime.slab_capacity = 64;
    let mut coord = InMemoryCoordinator::with_runtime_config(runtime);

    let config = RunConfig::try_new(CursorSemantics::Completed, LEASE_DURATION, Some(5)).unwrap();
    coord
        .create_run(now(1), test_tenant(), test_run(), config)
        .unwrap();
    let shards = vec![InitialShard::new(
        test_shard(),
        test_spec(),
        Cursor::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(11),
        )
        .unwrap();

    let lease = acquire_shard(&mut coord, 3, 1);
    let live_before = coord.slab().live_count();

    let err = coord
        .split_residual(
            now(4),
            test_tenant(),
            &lease,
            test_split_residual_plan(),
            OpId::from_raw(22),
        )
        .unwrap_err();
    assert!(
        matches!(err, SplitResidualError::ResourceExhausted(_)),
        "expected ResourceExhausted, got: {err:?}"
    );

    // Residual slots must be deallocated on parent-update failure.
    assert_eq!(
        coord.slab().live_count(),
        live_before,
        "residual fields leaked on split_residual failure"
    );
    assert_eq!(
        coord.shard_count(),
        1,
        "failed split must not insert residual"
    );

    let parent = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    let slab = coord.slab();
    assert_eq!(parent.spec.key_range_start(slab), b"a");
    assert_eq!(parent.spec.key_range_end(slab), b"z");
    assert!(
        parent.spawned.is_empty(),
        "parent spawned list must be unchanged"
    );
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

    // Old lease: all mutations rejected with StaleFence.
    let err = coord
        .checkpoint(
            now(LEASE_DURATION + 3),
            test_tenant(),
            &old_lease,
            test_cursor(b"b"),
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::StaleFence { .. }),
        "old lease checkpoint must produce StaleFence, got: {err:?}"
    );

    let err = coord
        .complete(
            now(LEASE_DURATION + 3),
            test_tenant(),
            &old_lease,
            test_cursor(b"b"),
            OpId::from_raw(2),
        )
        .unwrap_err();
    assert!(
        matches!(err, CompleteError::StaleFence { .. }),
        "old lease complete must produce StaleFence, got: {err:?}"
    );

    let err = coord
        .park_shard(
            now(LEASE_DURATION + 3),
            test_tenant(),
            &old_lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(3),
        )
        .unwrap_err();
    assert!(
        matches!(err, ParkError::StaleFence { .. }),
        "old lease park must produce StaleFence, got: {err:?}"
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
    let plan = test_split_residual_plan();
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

/// Builds a coordinator whose single shard already has `spawned_count`
/// derived entries in its `spawned` set.
///
/// The shard is Active with spec `[a, z)` and cursor at `"d"` (within
/// the standard `[a, m)` split range used by split tests). This setup
/// lets spawn-cap tests start at an exact distance from the limit
/// without performing actual split operations.
fn coordinator_with_spawned_count(spawned_count: usize) -> InMemoryCoordinator {
    let spawned: crate::coordination::record::SpawnedList = (0..spawned_count as u64)
        .map(|i| derived_shard_id(i + 1))
        .collect();
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let record = ShardRecord::from_raw_parts(
        test_tenant(),
        test_run(),
        test_shard(),
        ShardStatus::Active,
        None,
        &test_spec(), // [a, z)
        &test_cursor(b"d"),
        CursorSemantics::Completed,
        None,
        FenceEpoch::INITIAL,
        None,
        spawned,
        RingBuffer::new(),
        coord.slab_mut(),
    );
    coord.seed_shard(record);
    coord
}

#[test]
fn split_residual_at_spawn_cap_returns_error() {
    let mut coord = coordinator_with_spawned_count(MAX_SPAWNED_PER_SHARD);
    let lease = acquire_shard(&mut coord, 1, 1);

    let plan = test_split_residual_plan();

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

    let plan = test_split_replace_plan();

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

    let plan = test_split_residual_plan();

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

    let plan_a = test_split_replace_plan();

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

    let plan_a = test_split_residual_plan();

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

#[test]
fn split_replace_exceeds_per_tenant_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 3, 100);

    // Seed the target shard.
    let record = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        test_shard(),
        &test_spec(),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(record);

    // Seed two additional shards to fill tenant to limit.
    let record2 = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(20),
        &ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(record2);
    let record3 = ShardRecord::new_active(
        test_tenant(),
        test_run(),
        ShardId::from_raw(30),
        &ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(record3);

    let lease = acquire_shard(&mut coord, 1, 1);

    let plan = test_split_replace_plan();

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
        &test_spec(),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(record);

    // Seed a second shard (different tenant) to fill global limit.
    let record2 = ShardRecord::new_active(
        other_tenant(),
        test_run(),
        ShardId::from_raw(20),
        &ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
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

    let plan = test_split_residual_plan();

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

    let plan = test_split_replace_plan();

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

    let plan = test_split_residual_plan();

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

    let plan = test_split_residual_plan();
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
    let plan = test_split_residual_plan();
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
    let plan = test_split_residual_plan();
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
    let plan1 = test_split_residual_plan();
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
