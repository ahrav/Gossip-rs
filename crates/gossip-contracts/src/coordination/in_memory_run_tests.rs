// -- RunManagement tests --------------------------------------------------
//
// Tests for the RunManagement trait: create_run, register_shards,
// complete_run, fail_run, cancel_run, unpark_shard, list_shards, and
// create_run_with_shards. Covers the run state machine
// (Initializing -> Active -> Done|Failed|Cancelled), idempotent replay,
// OpIdConflict, wrong-status rejections, terminal irreversibility,
// shard count limits on register_shards, and split-index visibility
// (children appear in list_shards and get_run_progress after split).

use super::*;
use crate::coordination::run::{InitialShard, RunConfig, RunManagement, RunStatus, ShardFilter};
use crate::coordination::shard_spec::{CursorSemantics, ShardLimitScope, ShardSpec};
use crate::coordination::test_fixtures::{
    LEASE_DURATION, coordinator_with_run_and_lease, do_split_replace, now, short_lease_run_config,
    test_run, test_split_residual_plan, test_tenant, test_worker,
};
use crate::identity::{OpId, RunId, ShardId, ShardKey};
use crate::sim::backend::SimIntrospection;

// -- Split index consistency tests --
//
// After a split, child shards must be visible through the run-level
// APIs (get_run_progress, list_shards). These tests verify the
// coordinator's split index is updated atomically with the split.

#[test]
fn split_replace_children_visible_in_run_progress() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    let progress = coord
        .get_run_progress(now(5), test_tenant(), test_run())
        .unwrap();
    assert!(
        progress.total() == 3,
        "expected total == 3 (parent + 2 children), got {}",
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
        all.len() == 3,
        "expected 3 shards in listing (parent + 2 children), got {}",
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
    let plan = test_split_residual_plan();
    let _ = coord
        .split_residual(now(5), test_tenant(), &lease, plan, OpId::from_raw(2))
        .unwrap();

    let all = coord
        .list_shards(now(6), test_tenant(), test_run(), ShardFilter::all())
        .unwrap();
    assert!(
        all.len() == 2,
        "expected 2 shards (parent + residual), got {}",
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
    let sr1 = ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(90),
        &ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(sr1);
    let sr2 = ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(91),
        &ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(sr2);

    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = coord
        .complete_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: RunStatus::Done,
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
            RunTransitionError::RunTerminal {
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
    assert!(matches!(err, RunTransitionError::RunNotFound));
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = coord
        .fail_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: RunStatus::Failed,
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
            RunTransitionError::RunTerminal {
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
            RunTransitionError::RunTerminal {
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
    // different payload hash -> OpIdConflict.
    let err = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, RunTransitionError::OpIdConflict(_)),
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
        record.cursor.last_key(coord.slab()),
        Some(b"f".as_slice()),
        "cursor must be preserved through park->unpark",
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

    // Checkpoint -> Park -> Unpark -> Re-acquire -> Checkpoint works.
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
        "cursor must survive park->unpark->reacquire",
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

    // Attempt unpark -> should fail with RunTerminal.
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

    // Attempt unpark -> should fail with RunTerminal.
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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

#[test]
fn register_shards_resource_exhausted_returns_error_without_partial_inserts() {
    // Two shards with bounded ranges need 4 non-empty spec slots total.
    // With 16-byte minimum block size, that is 64 bytes. A 32-byte slab can
    // allocate at most one shard spec before returning SlabFull.
    let mut runtime = CoordinatorRuntimeConfig::with_limits(LEASE_DURATION, 10, 10);
    runtime.slab_capacity = 32;
    let mut coord = InMemoryCoordinator::with_runtime_config(runtime);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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
        matches!(err, RegisterShardsError::ResourceExhausted(_)),
        "expected ResourceExhausted, got: {err:?}"
    );

    // Run must stay Initializing with no registered roots on failure.
    let run = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(run.status(), RunStatus::Initializing);
    assert!(run.root_shards().is_empty());

    // No shards should have been inserted.
    let summaries = coord
        .list_shards(now(3), test_tenant(), test_run(), ShardFilter::all())
        .unwrap();
    assert!(summaries.is_empty(), "failed registration inserted shards");
    assert_eq!(
        coord.shard_count(),
        0,
        "failed registration changed shard count"
    );
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
            short_lease_run_config(),
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
            short_lease_run_config(),
            &shards,
            op,
        )
        .unwrap();

    // Retry with same config and op_id -> replayed.
    let second = coord
        .create_run_with_shards(
            now(2),
            test_tenant(),
            test_run(),
            short_lease_run_config(),
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
            short_lease_run_config(),
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

// -- create_run duplicate rejection -------------------------------------------
//
// create_run is not idempotent -- calling it twice with the same RunId
// must return RunAlreadyExists, not silently succeed.

#[test]
fn create_run_duplicate_rejected() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = coord
        .create_run(now(2), test_tenant(), test_run(), short_lease_run_config())
        .unwrap_err();
    assert!(
        matches!(err, CreateRunError::RunAlreadyExists { .. }),
        "duplicate create_run must return RunAlreadyExists, got: {err:?}"
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
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
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

    // Step 5: Verify progress -- all done.
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
