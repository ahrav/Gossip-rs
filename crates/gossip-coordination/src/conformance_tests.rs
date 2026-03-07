//! Conformance tests for the coordination protocol.
//!
//! Where `in_memory_tests` exercises each backend operation in isolation and
//! `scenario_tests` follows multi-step workflows, this module sits in the
//! middle: it verifies that the protocol's safety invariants hold when two or
//! more concerns interact. The focus is on invariant *combinations*, not on
//! individual operations or end-to-end stories.
//!
//! # Test Groups
//!
//! - **Group A — Cross-Cutting Invariant Interactions.** Each test composes
//!   two or more invariants (e.g. fence monotonicity + cursor bounds after a
//!   split, or idempotency + terminal irreversibility) and proves they do not
//!   conflict. These are the tests most likely to catch regressions where a
//!   fix for one invariant violates another.
//!
//! - **Group B — Gap-Filling Tests.** Edge cases and code paths with zero or
//!   minimal coverage in other modules: `CursorSemantics::Dispatched`
//!   propagation, exact-boundary lease expiry, split-coverage key-range
//!   partitioning, op-log eviction/replay interactions, the full
//!   unpark lifecycle, and same-worker reacquire fence bumps.
//!
//! - **Group C — Run-Level Conformance.** Run lifecycle state machine:
//!   terminal irreversibility (Done, Failed, and Cancelled all share the
//!   `apply_terminal_run_transition` code path), registration preconditions,
//!   `completed_at` consistency, and run-terminal blocking of shard-level
//!   admin operations (unpark).
//!
//! # Assertion Style
//!
//! Tests assert both the expected outcome *and* the absence of unexpected
//! side effects where applicable (Tiger Style). For example, after a
//! checkpoint the test verifies the cursor advanced *and* that the fence
//! epoch did not change.

use crate::error::{CheckpointError, IdempotentOutcome};
use crate::lease::Lease;
use crate::record::{ParkReason, ShardRecord, ShardStatus};
use crate::run::{RunManagement, RunStatus};
use crate::run_errors::{RunTransitionError, UnparkError};
use crate::sim::backend::SimIntrospection as _;
use crate::test_fixtures::{
    LEASE_DURATION, acquire_shard, checkpoint_ok, complete_ok, now, park_ok, seeded_coordinator,
    seeded_coordinator_with_semantics, test_cursor, test_key, test_run, test_run_config,
    test_shard, test_split_replace_plan, test_split_residual_plan, test_tenant, test_worker,
};
use crate::traits::CoordinationBackend;
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::limits::MAX_SPAWNED_PER_SHARD;
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
use gossip_contracts::identity::{OpId, RunId, ShardId, ShardKey};

// -- Compile-time assertions -------------------------------------------------
// Guard against silent constant changes that would invalidate test assumptions.

const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);
const _: () = assert!(MAX_SPAWNED_PER_SHARD == 1024);
const _: () = assert!(LEASE_DURATION == 100);

// Production-only allocation-contract guards.
//
// These pin the hot-path API surface to borrowed inputs and caller-owned
// scratch/output forms in default-feature (production-like) builds.
// `test-support` builds intentionally skip these guards so simulation paths
// can remain allocation-friendly.
#[cfg(not(feature = "test-support"))]
const _: for<'a> fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    gossip_contracts::identity::ShardKey,
    gossip_contracts::identity::WorkerId,
    &'a mut crate::AcquireScratch,
) -> Result<crate::AcquireResultView<'a>, crate::AcquireError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::acquire_and_restore_into;

#[cfg(not(feature = "test-support"))]
const _: fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    &crate::Lease,
    &crate::CursorUpdate<'_>,
    gossip_contracts::identity::OpId,
) -> Result<crate::IdempotentOutcome<()>, crate::CheckpointError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::checkpoint;

#[cfg(not(feature = "test-support"))]
const _: fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    &crate::Lease,
    &crate::CursorUpdate<'_>,
    gossip_contracts::identity::OpId,
) -> Result<crate::IdempotentOutcome<()>, crate::CompleteError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::complete;

// ============================================================================
// Group A: Cross-Cutting Invariant Interactions
//
// Each test in this group composes two or more of the protocol's safety
// invariants and verifies they hold simultaneously. The goal is to catch
// regressions where satisfying one invariant accidentally violates another.
// ============================================================================

/// Fence monotonicity holds across an ownership transfer.
///
/// Exercises the full lifecycle: acquire, checkpoint, lease expiry,
/// re-acquire by a different worker, checkpoint, complete. At every step
/// the test asserts that the fence epoch either stayed the same (within
/// one ownership period) or strictly increased (at the ownership boundary),
/// and that it *never* decreased.
///
/// Invariants under test: fence monotonicity, lease expiry enables
/// re-acquisition, checkpoint and complete do not mutate the fence.
#[test]
fn fence_monotonicity_across_full_lifecycle() {
    let mut coord = seeded_coordinator();

    // Worker 1: acquire -> checkpoint (no complete, so shard stays Active).
    let lease1 = acquire_shard(&mut coord, 10, 1);
    let f1 = lease1.fence();

    checkpoint_ok(&mut coord, 11, &lease1, b"d", 1);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.fence_epoch, f1, "checkpoint must not change fence");
    assert_eq!(rec.status, ShardStatus::Active);

    // Worker 2: re-acquire after worker 1's lease expires.
    let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 2);
    let f2 = lease2.fence();
    assert!(f2 > f1, "re-acquire fence must exceed worker 1's fence");

    // Worker 2: checkpoint -> complete.
    checkpoint_ok(&mut coord, LEASE_DURATION + 12, &lease2, b"p", 3);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.fence_epoch, f2, "checkpoint must not change fence");

    complete_ok(&mut coord, LEASE_DURATION + 13, &lease2, b"y", 4);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.fence_epoch, f2, "complete must not change fence");
    assert_eq!(rec.status, ShardStatus::Done);
}

/// Cursor bounds enforcement tracks a narrowed spec after split_residual.
///
/// Split-residual changes the parent's key range without changing its cursor.
/// This test verifies the interaction of two invariants: (1) the cursor from
/// before the split is preserved, and (2) subsequent checkpoints are
/// bounds-checked against the *new* (narrower) spec, not the original one.
///
/// Invariants under test: cursor bounds, split-residual spec narrowing,
/// cursor preservation across splits.
#[test]
fn cursor_monotonicity_combined_with_split_residual() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);

    // Checkpoint at "d" (within original [a,z)).
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    // Split residual: parent narrows to [a,m), residual gets [m,z).
    let plan = test_split_residual_plan();
    let result = coord
        .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
        .unwrap();
    assert!(result.is_executed(), "split_residual must be Executed");

    // Cursor "d" is preserved within new range [a,m).
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.cursor.last_key(coord.slab()), Some(b"d".as_slice()));
    assert_eq!(rec.spec.key_range_start(coord.slab()), b"a");
    assert_eq!(rec.spec.key_range_end(coord.slab()), b"m");

    // Checkpoint "f" succeeds (in bounds [a,m)).
    let ck_ok = coord.checkpoint(
        now(13),
        test_tenant(),
        &lease,
        &test_cursor(b"f"),
        OpId::from_raw(3),
    );
    assert!(ck_ok.is_ok(), "checkpoint at 'f' must succeed within [a,m)");

    // Checkpoint "n" fails (out of bounds [a,m)).
    let ck_err = coord.checkpoint(
        now(14),
        test_tenant(),
        &lease,
        &test_cursor(b"n"),
        OpId::from_raw(4),
    );
    assert!(
        matches!(ck_err, Err(CheckpointError::CursorOutOfBounds(_))),
        "checkpoint at 'n' must fail with CursorOutOfBounds, got: {ck_err:?}"
    );
}

/// Idempotency takes precedence over terminal-state rejection.
///
/// When a shard is terminal (Done) and a worker replays an operation with
/// the same op_id that produced the terminal transition, the backend must
/// return `Replayed` rather than `ShardTerminal`. This ordering matters
/// for crash recovery: a worker that completed a shard but crashed before
/// processing the response will retry with the same op_id.
///
/// Invariants under test: OpId idempotency, terminal irreversibility,
/// and their relative priority in the validation pipeline.
#[test]
fn idempotency_before_terminal_state_rejection() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);

    // Checkpoint then complete.
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);
    let complete_cursor = test_cursor(b"m");
    let complete_op = OpId::from_raw(2);
    let outcome = coord
        .complete(
            now(12),
            test_tenant(),
            &lease,
            &complete_cursor,
            complete_op,
        )
        .unwrap();
    assert!(
        outcome.is_executed(),
        "first-time complete must be Executed"
    );

    // Shard is now Done. Replay complete with the same lease, cursor, and op_id.
    let replay = coord.complete(
        now(13),
        test_tenant(),
        &lease,
        &complete_cursor,
        complete_op,
    );
    assert!(
        matches!(replay, Ok(IdempotentOutcome::Replayed(()))),
        "replay on terminal shard must return Replayed, got: {replay:?}"
    );

    // Tiger Style: verify replay did not mutate shard state.
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(
        rec.status,
        ShardStatus::Done,
        "replay must not change terminal status"
    );
    assert_eq!(
        rec.cursor.last_key(coord.slab()),
        Some(b"m".as_slice()),
        "replay must not mutate cursor"
    );
}

/// Split-residual narrowing is preserved through a park/unpark round-trip.
///
/// Performs split_residual (narrowing [a,z) to [a,m)), parks the shard,
/// unparks it, and re-acquires. Verifies three properties across all
/// transitions: (1) the narrowed key range [a,m) persists, (2) the cursor
/// from before the split is preserved, and (3) fence monotonicity holds
/// at every step.
///
/// Invariants under test: split-residual spec narrowing, cursor
/// preservation across park/unpark, fence monotonicity through admin ops.
#[test]
fn split_residual_preserved_through_park_unpark() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);
    let f0 = lease.fence();

    // Checkpoint at "d" within original [a,z).
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    // Split residual: parent narrows to [a,m).
    let plan = test_split_residual_plan();
    let result = coord
        .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
        .unwrap();
    assert!(result.is_executed(), "split_residual must be Executed");

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.fence_epoch, f0, "split_residual must not change fence");

    // Park the shard.
    park_ok(&mut coord, 13, &lease, ParkReason::TooManyErrors, 3);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.status, ShardStatus::Parked);
    assert_eq!(rec.fence_epoch, f0, "park must not change fence");
    assert_eq!(
        rec.cursor.last_key(coord.slab()),
        Some(b"d".as_slice()),
        "park must preserve cursor"
    );
    assert_eq!(
        rec.spec.key_range_start(coord.slab()),
        b"a",
        "park must preserve narrowed range start"
    );
    assert_eq!(
        rec.spec.key_range_end(coord.slab()),
        b"m",
        "park must preserve narrowed range end"
    );

    // Unpark.
    let outcome = coord
        .unpark_shard(now(14), test_tenant(), test_key(), OpId::from_raw(4))
        .unwrap();
    assert!(outcome.is_executed(), "first-time unpark must be Executed");

    let fence_after_unpark = {
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.status, ShardStatus::Active);
        assert!(
            rec.fence_epoch > f0,
            "unpark must bump fence above pre-park value"
        );
        assert_eq!(
            rec.cursor.last_key(coord.slab()),
            Some(b"d".as_slice()),
            "unpark must preserve cursor through park round-trip"
        );
        assert_eq!(
            rec.spec.key_range_start(coord.slab()),
            b"a",
            "unpark must preserve narrowed range start"
        );
        assert_eq!(
            rec.spec.key_range_end(coord.slab()),
            b"m",
            "unpark must preserve narrowed range end"
        );
        rec.fence_epoch
    };

    // Re-acquire by a new worker — can checkpoint within narrowed [a,m).
    let lease2 = acquire_shard(&mut coord, 15, 2);
    assert!(
        lease2.fence() > fence_after_unpark,
        "re-acquire must bump fence again"
    );

    checkpoint_ok(&mut coord, 16, &lease2, b"f", 5);
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.cursor.last_key(coord.slab()), Some(b"f".as_slice()));
}

/// Lease validation rejects a forged lease whose fence matches but owner diverges.
///
/// Constructs a lease that has the correct fence epoch but a different
/// worker id. The backend must detect the owner mismatch and reject the
/// operation with `StaleFence`, not silently accept it. This proves that
/// fence-based fencing checks the *full* lease identity, not just the epoch.
///
/// Invariants under test: lease validation (fence + owner), tenant isolation.
#[test]
fn owner_divergence_with_matching_fence() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);
    let fence = lease.fence();

    // Forge a lease with the same fence but a different worker.
    let forged = Lease::new(
        test_tenant(),
        test_run(),
        test_shard(),
        test_worker(99),
        fence,
        lease.deadline(),
    );

    let err = coord
        .checkpoint(
            now(11),
            test_tenant(),
            &forged,
            &test_cursor(b"d"),
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::StaleFence { .. }),
        "wrong owner with matching fence must produce StaleFence, got: {err:?}"
    );

    // Tiger Style: verify the rejected operation did not corrupt shard state.
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(
        rec.fence_epoch, fence,
        "rejected checkpoint must not change fence"
    );
    assert_eq!(
        rec.cursor.last_key(coord.slab()),
        None,
        "rejected checkpoint must not advance cursor"
    );
    assert_eq!(
        rec.status,
        ShardStatus::Active,
        "rejected checkpoint must not change status"
    );
}

/// All terminal operations release the lease (clear owner and deadline).
///
/// Exercises complete, park_shard, and split_replace in separate
/// sub-tests. After each terminal transition the test verifies that
/// `lease_owner` and `lease_deadline` are `None` and the shard is in
/// the expected terminal status. This prevents a stale lease from blocking
/// future admin operations (e.g. unpark) on the shard.
///
/// Invariants under test: terminal transitions clear leases, correct
/// terminal status per operation.
#[test]
fn terminal_clears_lease() {
    // -- Complete --
    {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        complete_ok(&mut coord, 11, &lease, b"m", 1);
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert!(
            rec.lease_owner().is_none(),
            "complete must clear lease owner"
        );
        assert!(
            rec.lease_deadline().is_none(),
            "complete must clear lease deadline"
        );
        assert_eq!(rec.fence_epoch, fence, "complete must not change fence");
        assert_eq!(rec.status, ShardStatus::Done);
    }

    // -- Park --
    {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert!(rec.lease_owner().is_none(), "park must clear lease owner");
        assert!(
            rec.lease_deadline().is_none(),
            "park must clear lease deadline"
        );
        assert_eq!(rec.fence_epoch, fence, "park must not change fence");
        assert_eq!(rec.status, ShardStatus::Parked);
    }

    // -- SplitReplace --
    {
        let mut coord = seeded_coordinator();
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        let plan = test_split_replace_plan();
        let outcome = coord
            .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time split_replace must be Executed"
        );
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert!(
            rec.lease_owner().is_none(),
            "split_replace must clear lease owner"
        );
        assert!(
            rec.lease_deadline().is_none(),
            "split_replace must clear lease deadline"
        );
        assert_eq!(
            rec.fence_epoch, fence,
            "split_replace must not change fence"
        );
        assert_eq!(rec.status, ShardStatus::Split);
    }
}

// ============================================================================
// Group B: Boundary Conditions and Variant Coverage
//
// Edge cases and code paths with minimal coverage in the unit tests and
// scenario tests: untested enum variants, boundary conditions, and
// interactions that only manifest under particular timing or sequencing.
// ============================================================================

/// `CursorSemantics::Dispatched` propagates through the full operation chain.
///
/// All other tests use `CursorSemantics::Completed` (via `seeded_coordinator`).
/// This test creates a coordinator with `Dispatched` semantics and verifies
/// the variant is faithfully stored in the shard record, surfaced in the
/// acquisition snapshot, and preserved through checkpoint and complete.
#[test]
fn cursor_semantics_dispatched_through_coordinator() {
    let mut coord = seeded_coordinator_with_semantics(CursorSemantics::Dispatched);

    let mut scratch = crate::AcquireScratch::new();
    let result = coord
        .acquire_and_restore_into(
            now(10),
            test_tenant(),
            test_key(),
            test_worker(1),
            &mut scratch,
        )
        .unwrap();
    assert_eq!(
        result.snapshot.cursor_semantics(),
        CursorSemantics::Dispatched,
        "snapshot must reflect Dispatched semantics"
    );

    let lease = result.lease;

    // Record-level check.
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.cursor_semantics, CursorSemantics::Dispatched);

    // Operations work normally.
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);
    complete_ok(&mut coord, 12, &lease, b"m", 2);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.status, ShardStatus::Done);
    assert_eq!(rec.cursor_semantics, CursorSemantics::Dispatched);
}

/// Lease expiry uses a half-open interval: `now < deadline` is active, `now == deadline` is expired.
///
/// Tests the exact boundary where `now` equals the lease deadline. At
/// `deadline - 1` a checkpoint succeeds; at exactly `deadline` it fails
/// with `LeaseExpired`. This pins the half-open convention so that
/// implementations cannot accidentally use `<=`.
#[test]
fn lease_deadline_at_exact_boundary() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);
    // Deadline = 10 + LEASE_DURATION = 110.
    let deadline = 10 + LEASE_DURATION;
    assert_eq!(lease.deadline(), now(deadline));

    // At now == deadline-1 (109): lease is still active.
    let ok = coord.checkpoint(
        now(deadline - 1),
        test_tenant(),
        &lease,
        &test_cursor(b"d"),
        OpId::from_raw(1),
    );
    assert!(ok.is_ok(), "checkpoint at deadline-1 must succeed");

    // At now == deadline (110): lease is expired.
    let err = coord.checkpoint(
        now(deadline),
        test_tenant(),
        &lease,
        &test_cursor(b"e"),
        OpId::from_raw(2),
    );
    assert!(
        matches!(err, Err(CheckpointError::LeaseExpired { .. })),
        "checkpoint at exact deadline must fail with LeaseExpired, got: {err:?}"
    );
}

/// Split-replace children's key ranges partition the parent range with no gaps.
///
/// After splitting [a,z) into [a,m) and [m,z), verifies that child key
/// ranges are contiguous (child_a.end == child_b.start), that the union
/// covers the original range, and that both children are Active.
#[test]
fn split_coverage_key_range_partition() {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);
    let plan = test_split_replace_plan();

    let result = coord
        .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
        .unwrap();
    let children = result.into_inner().children;
    assert_eq!(children.len(), 2, "must produce exactly 2 children");
    let children = children.as_slice();
    let child_a = children[0];
    let child_b = children[1];

    // Look up each child and verify key ranges.
    let key_a = ShardKey::new(test_run(), child_a);
    let key_b = ShardKey::new(test_run(), child_b);

    let rec_a = coord.shard_lookup(&test_tenant(), &key_a).unwrap();
    let rec_b = coord.shard_lookup(&test_tenant(), &key_b).unwrap();

    let slab = coord.slab();
    assert_eq!(rec_a.spec.key_range_start(slab), b"a");
    assert_eq!(rec_a.spec.key_range_end(slab), b"m");
    assert_eq!(rec_b.spec.key_range_start(slab), b"m");
    assert_eq!(rec_b.spec.key_range_end(slab), b"z");

    // No gap: child_a.end == child_b.start.
    assert_eq!(
        rec_a.spec.key_range_end(slab),
        rec_b.spec.key_range_start(slab)
    );
    // Both children are Active.
    assert_eq!(rec_a.status, ShardStatus::Active);
    assert_eq!(rec_b.status, ShardStatus::Active);

    // Acquire child_a and checkpoint within its range [a,m).
    let mut scratch = crate::AcquireScratch::new();
    let child_lease = coord
        .acquire_and_restore_into(now(12), test_tenant(), key_a, test_worker(1), &mut scratch)
        .expect("child acquire must succeed")
        .lease;
    let outcome = coord
        .checkpoint(
            now(13),
            test_tenant(),
            &child_lease,
            &test_cursor(b"f"),
            OpId::from_raw(2),
        )
        .expect("child checkpoint must succeed");
    assert!(
        outcome.is_executed(),
        "first-time child checkpoint must be Executed"
    );
    let rec_a = coord.shard_lookup(&test_tenant(), &key_a).unwrap();
    assert_eq!(
        rec_a.cursor.last_key(coord.slab()),
        Some(b"f".as_slice()),
        "child checkpoint must advance cursor"
    );
}

/// Op-log eviction interacts correctly with idempotency on a terminal shard.
///
/// Fills the ring-buffer op-log to its capacity (16 entries), pushes one
/// more to evict op_id=1, then completes the shard (terminal). Replaying
/// the surviving complete op (op_id=18, still in the log) returns `Replayed`.
/// Replaying the evicted checkpoint op (op_id=1, no longer in the log)
/// hits the terminal-state check instead, returning `ShardTerminal`.
///
/// This proves that op-log eviction does not create a false-positive
/// replay window: once an op is evicted and the shard is terminal, the
/// backend rejects the operation rather than silently re-executing it.
#[test]
fn oplog_eviction_then_replay() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 10, 1);

    // Fill the op-log with 16 checkpoints (op_ids 1..=16).
    for i in 1..=ShardRecord::OP_LOG_CAP as u64 {
        let key = vec![b'a' + i as u8]; // "b", "c", ..., "q"
        let update = CursorUpdate::new(key.as_slice());
        let outcome = coord
            .checkpoint(
                now(10 + i),
                test_tenant(),
                &lease,
                &update,
                OpId::from_raw(i),
            )
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time checkpoint must be Executed"
        );
    }

    // One more checkpoint to evict op_id=1.
    checkpoint_ok(&mut coord, 27, &lease, b"s", 17);

    // Complete the shard (terminal). Op_id=18.
    complete_ok(&mut coord, 28, &lease, b"y", 18);

    // Replay surviving op (op_id=18, the complete) -> Replayed.
    let replay_surviving = coord.complete(
        now(29),
        test_tenant(),
        &lease,
        &test_cursor(b"y"),
        OpId::from_raw(18),
    );
    assert!(
        matches!(replay_surviving, Ok(IdempotentOutcome::Replayed(()))),
        "surviving op must return Replayed, got: {replay_surviving:?}"
    );

    // Replay evicted op (op_id=1, a checkpoint) on terminal shard.
    // The op was evicted so it's not found in the log. The shard is
    // terminal, so the terminal check rejects it.
    let replay_evicted = coord.checkpoint(
        now(30),
        test_tenant(),
        &lease,
        &CursorUpdate::new(b"b"),
        OpId::from_raw(1),
    );
    assert!(
        matches!(replay_evicted, Err(CheckpointError::ShardTerminal { .. })),
        "evicted op on terminal shard must return ShardTerminal, got: {replay_evicted:?}"
    );
}

/// Full unpark lifecycle: park preserves cursor, unpark bumps fence, and
/// a new worker can resume from the checkpointed position.
///
/// Walks through acquire -> checkpoint("d") -> park -> unpark and verifies
/// three properties: (1) the cursor is preserved through the park/unpark
/// round-trip, (2) unpark increments the fence epoch (invalidating any
/// zombie leases from before the park), and (3) a subsequent acquire by a
/// new worker succeeds and can checkpoint forward from the preserved cursor.
///
/// Invariants under test: cursor preservation across park/unpark, fence
/// monotonicity through admin operations, lease clearing on park.
#[test]
fn unpark_lifecycle_fence_and_cursor_preserved() {
    let mut coord = seeded_coordinator();

    // Acquire and checkpoint at "d".
    let lease = acquire_shard(&mut coord, 10, 1);
    let f_before_park = lease.fence();
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    // Park the shard.
    park_ok(&mut coord, 12, &lease, ParkReason::TooManyErrors, 2);

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.status, ShardStatus::Parked);

    // Unpark via RunManagement.
    let outcome = coord
        .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(3))
        .unwrap();
    assert!(outcome.is_executed(), "first-time unpark must be Executed");

    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.status, ShardStatus::Active);
    assert!(rec.fence_epoch > f_before_park, "unpark must bump fence");
    assert_eq!(
        rec.cursor.last_key(coord.slab()),
        Some(b"d".as_slice()),
        "unpark must preserve cursor"
    );
    let fence_after_unpark = rec.fence_epoch;

    // New worker can acquire and checkpoint from "d".
    let lease2 = acquire_shard(&mut coord, 14, 2);
    assert!(
        lease2.fence() > fence_after_unpark,
        "acquire after unpark must bump fence again"
    );

    checkpoint_ok(&mut coord, 15, &lease2, b"f", 4);
    let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
    assert_eq!(rec.cursor.last_key(coord.slab()), Some(b"f".as_slice()));
}

/// Re-acquisition by the same worker bumps the fence, invalidating the old lease.
///
/// A worker's own stale lease must be rejected just as firmly as another
/// worker's. After re-acquire, the old lease (carrying the previous fence)
/// produces `StaleFence` on checkpoint, while the new lease succeeds.
/// This protects against a "zombie write" from an old thread or async task
/// that still holds the previous lease handle.
///
/// Invariants under test: fence monotonicity on same-worker reacquire,
/// stale-fence rejection regardless of worker identity.
#[test]
fn same_worker_reacquire_bumps_fence() {
    let mut coord = seeded_coordinator();

    let lease1 = acquire_shard(&mut coord, 10, 1);
    let f1 = lease1.fence();

    // Lease expires, same worker re-acquires.
    let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 1);
    let f2 = lease2.fence();

    assert_eq!(f2, f1.increment(), "re-acquire must bump fence by 1");
    assert!(f2 > f1, "new fence must exceed old fence");

    // Old lease (f1) must be rejected on checkpoint.
    let err = coord
        .checkpoint(
            now(LEASE_DURATION + 12),
            test_tenant(),
            &lease1,
            &test_cursor(b"d"),
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::StaleFence { .. }),
        "old lease must produce StaleFence, got: {err:?}"
    );

    // New lease works.
    let ok = coord.checkpoint(
        now(LEASE_DURATION + 12),
        test_tenant(),
        &lease2,
        &test_cursor(b"d"),
        OpId::from_raw(2),
    );
    assert!(ok.is_ok(), "new lease checkpoint must succeed");
}

// ============================================================================
// Group C: Run-Level Conformance
//
// Tests for the RunManagement state machine. Verifies terminal irreversibility
// across Done/Failed/Cancelled, registration-phase preconditions, timestamp
// consistency (completed_at), and cross-concern interactions where a terminal
// run blocks shard-level admin operations.
// ============================================================================

/// Once a run reaches a terminal state, all further state transitions are
/// rejected.
///
/// Parametrized over Done and Cancelled to cover both terminal paths that
/// share the `apply_terminal_run_transition` code path. Done requires
/// completing all shards first; Cancelled can be reached directly from
/// Active.
#[rstest::rstest]
#[case::done(RunStatus::Done)]
#[case::cancelled(RunStatus::Cancelled)]
fn run_terminal_irreversibility(#[case] expected_status: RunStatus) {
    let mut coord = seeded_coordinator();

    let lease = acquire_shard(&mut coord, 10, 1);

    // Drive the run to the expected terminal state.
    match expected_status {
        RunStatus::Done => {
            complete_ok(&mut coord, 11, &lease, b"y", 1);
            let outcome = coord
                .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
                .unwrap();
            assert!(
                outcome.is_executed(),
                "first-time complete_run must be Executed"
            );
        }
        RunStatus::Cancelled => {
            let outcome = coord
                .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
                .unwrap();
            assert!(
                outcome.is_executed(),
                "first-time cancel_run must be Executed"
            );
        }
        _ => unreachable!("test only covers Done and Cancelled"),
    }

    let rec = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(rec.status(), expected_status);

    // All three transition attempts must fail with RunTerminal.
    let err = coord
        .complete_run(now(13), test_tenant(), test_run(), OpId::from_raw(101))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "complete_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );

    let err = coord
        .fail_run(now(14), test_tenant(), test_run(), OpId::from_raw(102))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "fail_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );

    let err = coord
        .cancel_run(now(15), test_tenant(), test_run(), OpId::from_raw(103))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "cancel_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );
}

/// `register_shards` is rejected on an Active run (requires Initializing).
///
/// The seeded coordinator has already called `register_shards` during setup,
/// which transitions the run from Initializing to Active. A second call
/// must fail with `WrongStatus`, enforcing the one-shot registration
/// invariant.
#[test]
fn register_shards_on_non_initializing_rejected() {
    let mut coord = seeded_coordinator();

    // Run is already Active (seeded_coordinator calls register_shards).
    let rec = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(rec.status(), RunStatus::Active);

    // Try to register more shards -> WrongStatus.
    let spec = ShardSpec::with_range(b"aa", b"bb");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(999),
        spec.as_ref(),
        cursor,
    )];
    let err = coord
        .register_shards(
            now(10),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(200),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            crate::run_errors::RegisterShardsError::WrongStatus { .. }
        ),
        "register_shards on Active run must return WrongStatus, got: {err:?}"
    );
}

/// `completed_at` is `Some` if and only if the run is in a terminal state.
///
/// Tests both directions of the biconditional: Active and Initializing runs
/// have `completed_at == None`, while Done and Cancelled runs have it set.
/// Uses two separate runs to cover two terminal paths (Done via complete_run,
/// Cancelled via cancel_run on an Initializing run). Failed is not tested
/// here but follows the same shared `apply_terminal_run_transition` code path.
#[test]
fn run_completed_at_consistency() {
    // -- Initializing -> Active -> Done --
    let mut coord = seeded_coordinator();

    let rec = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(rec.status(), RunStatus::Active);
    assert!(
        rec.completed_at().is_none(),
        "Active run must have completed_at == None"
    );

    // Complete the shard, then complete the run.
    let lease = acquire_shard(&mut coord, 10, 1);
    complete_ok(&mut coord, 11, &lease, b"y", 1);
    let outcome = coord
        .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .unwrap();
    assert!(
        outcome.is_executed(),
        "first-time complete_run must be Executed"
    );

    let rec = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(rec.status(), RunStatus::Done);
    assert!(
        rec.completed_at().is_some(),
        "Done run must have completed_at"
    );

    // -- Separate run: Cancelled --
    let run2 = RunId::from_raw(2);
    let config = test_run_config();
    coord
        .create_run(now(20), test_tenant(), run2, config)
        .unwrap();

    let rec = coord.get_run(test_tenant(), run2).unwrap();
    assert!(
        rec.completed_at().is_none(),
        "Initializing run must have completed_at == None"
    );

    let outcome = coord
        .cancel_run(now(21), test_tenant(), run2, OpId::from_raw(200))
        .unwrap();
    assert!(
        outcome.is_executed(),
        "first-time cancel_run must be Executed"
    );

    let rec = coord.get_run(test_tenant(), run2).unwrap();
    assert_eq!(rec.status(), RunStatus::Cancelled);
    assert!(
        rec.completed_at().is_some(),
        "Cancelled run must have completed_at"
    );
}

/// Unpark is blocked when the parent run is in a terminal state.
///
/// Parks a shard, then cancels the run. An unpark attempt must fail with
/// `RunTerminal`, not succeed. This is a cross-concern test: shard-level
/// admin operations respect run-level terminal state, preventing a parked
/// shard from being reactivated after its run has been cancelled.
#[test]
fn unpark_after_run_terminal_rejected() {
    let mut coord = seeded_coordinator();

    // Acquire and park the shard.
    let lease = acquire_shard(&mut coord, 10, 1);
    park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);

    // Cancel the run (run becomes Cancelled).
    let outcome = coord
        .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .unwrap();
    assert!(
        outcome.is_executed(),
        "first-time cancel_run must be Executed"
    );

    let rec = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(rec.status(), RunStatus::Cancelled);

    // Try unpark_shard -> RunTerminal.
    let err = coord
        .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(2))
        .unwrap_err();
    assert!(
        matches!(err, UnparkError::RunTerminal { .. }),
        "unpark on terminal run must return RunTerminal, got: {err:?}"
    );
}
