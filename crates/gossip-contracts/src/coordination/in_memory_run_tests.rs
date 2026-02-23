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
use crate::identity::{FenceEpoch, OpId, RunId, ShardId, ShardKey};
use crate::sim::backend::SimIntrospection;
use rstest::rstest;

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

// -- get_run_progress watermark tests ---------------------------------------

#[test]
fn all_active_initial_cursors_watermark_none() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let shards = vec![
        InitialShard::new(
            ShardId::from_raw(10),
            ShardSpec::with_range(b"a".to_vec(), b"g".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(11),
            ShardSpec::with_range(b"g".to_vec(), b"n".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(12),
            ShardSpec::with_range(b"n".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(3), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.active(), 3);
    assert_eq!(progress.watermark(), None);
}

#[test]
fn mixed_progressed_and_initial_active_watermark_is_min_progressed() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let shards = vec![
        InitialShard::new(
            ShardId::from_raw(10),
            ShardSpec::with_range(b"a".to_vec(), b"g".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(11),
            ShardSpec::with_range(b"g".to_vec(), b"n".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            ShardId::from_raw(12),
            ShardSpec::with_range(b"n".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    let shard_10 = ShardKey::new(test_run(), ShardId::from_raw(10));
    let lease_10 = coord
        .acquire_and_restore(now(3), test_tenant(), shard_10, test_worker(1))
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease_10,
            Cursor::with_last_key(b"c".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();

    let shard_11 = ShardKey::new(test_run(), ShardId::from_raw(11));
    let lease_11 = coord
        .acquire_and_restore(now(5), test_tenant(), shard_11, test_worker(2))
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(6),
            test_tenant(),
            &lease_11,
            Cursor::with_last_key(b"k".to_vec()),
            OpId::from_raw(11),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(7), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.active(), 3);
    assert_eq!(progress.watermark(), Some(b"c".as_slice()));
}

#[test]
fn done_split_parked_excluded_from_watermark() {
    let (mut coord, root_lease) = coordinator_with_run_and_lease();

    // Set parent cursor before split so Split parent carries a small key.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &root_lease,
            Cursor::with_last_key(b"b".to_vec()),
            OpId::from_raw(10),
        )
        .unwrap();

    let split_plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"t".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"t".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap();
    let _ = coord
        .split_replace(
            now(5),
            test_tenant(),
            &root_lease,
            split_plan,
            OpId::from_raw(11),
        )
        .unwrap();

    let active_children = coord
        .list_shards(now(6), test_tenant(), test_run(), ShardFilter::active())
        .unwrap();
    assert_eq!(active_children.len(), 3);

    let child_done = active_children
        .iter()
        .find(|s| s.key_range_start() == b"a")
        .unwrap()
        .shard();
    let child_parked = active_children
        .iter()
        .find(|s| s.key_range_start() == b"m")
        .unwrap()
        .shard();
    let child_active = active_children
        .iter()
        .find(|s| s.key_range_start() == b"t")
        .unwrap()
        .shard();

    let lease_done = coord
        .acquire_and_restore(
            now(7),
            test_tenant(),
            ShardKey::new(test_run(), child_done),
            test_worker(2),
        )
        .unwrap()
        .lease;
    let _ = coord
        .complete(
            now(8),
            test_tenant(),
            &lease_done,
            Cursor::with_last_key(b"d".to_vec()),
            OpId::from_raw(12),
        )
        .unwrap();

    let lease_parked = coord
        .acquire_and_restore(
            now(9),
            test_tenant(),
            ShardKey::new(test_run(), child_parked),
            test_worker(3),
        )
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(10),
            test_tenant(),
            &lease_parked,
            Cursor::with_last_key(b"n".to_vec()),
            OpId::from_raw(13),
        )
        .unwrap();
    let _ = coord
        .park_shard(
            now(11),
            test_tenant(),
            &lease_parked,
            ParkReason::TooManyErrors,
            OpId::from_raw(14),
        )
        .unwrap();

    let lease_active = coord
        .acquire_and_restore(
            now(12),
            test_tenant(),
            ShardKey::new(test_run(), child_active),
            test_worker(4),
        )
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(13),
            test_tenant(),
            &lease_active,
            Cursor::with_last_key(b"x".to_vec()),
            OpId::from_raw(15),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(14), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.total(), 4);
    assert_eq!(progress.split(), 1);
    assert_eq!(progress.done(), 1);
    assert_eq!(progress.parked(), 1);
    assert_eq!(progress.active(), 1);
    assert_eq!(
        progress.watermark(),
        Some(b"x".as_slice()),
        "watermark must ignore Done/Split/Parked cursor keys",
    );
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

// -- Run terminal operation tests (complete_run / fail_run / cancel_run) ------
//
// All three terminal transitions share identical structure: happy path,
// wrong-status rejection, terminal irreversibility, and idempotent
// replay. A small dispatch enum + helper avoids repeating each scenario
// three times. `cancel_run_from_initializing` and `complete_run_not_found`
// remain individual tests because they have no parallel in other ops.

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

#[derive(Debug, Clone, Copy)]
enum TerminalOp {
    Complete,
    Fail,
    Cancel,
}

impl TerminalOp {
    fn expected_status(self) -> RunStatus {
        match self {
            Self::Complete => RunStatus::Done,
            Self::Fail => RunStatus::Failed,
            Self::Cancel => RunStatus::Cancelled,
        }
    }
}

fn apply_terminal_op(
    coord: &mut InMemoryCoordinator,
    op: TerminalOp,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    op_id: OpId,
) -> Result<IdempotentOutcome<()>, RunTransitionError> {
    match op {
        TerminalOp::Complete => coord.complete_run(now, tenant, run, op_id),
        TerminalOp::Fail => coord.fail_run(now, tenant, run, op_id),
        TerminalOp::Cancel => coord.cancel_run(now, tenant, run, op_id),
    }
}

#[rstest]
#[case::complete(TerminalOp::Complete)]
#[case::fail(TerminalOp::Fail)]
#[case::cancel(TerminalOp::Cancel)]
fn terminal_op_happy_path(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let result = apply_terminal_op(
        &mut coord,
        op,
        now(3),
        test_tenant(),
        test_run(),
        OpId::from_raw(2),
    )
    .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), op.expected_status());
    assert_eq!(record.completed_at(), Some(now(3)));
}

#[rstest]
#[case::complete(TerminalOp::Complete, RunStatus::Done)]
#[case::fail(TerminalOp::Fail, RunStatus::Failed)]
fn terminal_op_wrong_status_initializing(#[case] op: TerminalOp, #[case] target: RunStatus) {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = apply_terminal_op(
        &mut coord,
        op,
        now(2),
        test_tenant(),
        test_run(),
        OpId::from_raw(1),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: t,
            } if t == target
        ),
        "expected WrongStatus(Initializing -> {target:?}), got: {err:?}",
    );
}

#[rstest]
#[case::complete_after_done(TerminalOp::Complete)]
#[case::fail_after_done(TerminalOp::Fail)]
#[case::cancel_after_done(TerminalOp::Cancel)]
fn terminal_op_rejected_when_already_terminal(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let _ = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();

    let err = apply_terminal_op(
        &mut coord,
        op,
        now(4),
        test_tenant(),
        test_run(),
        OpId::from_raw(3),
    )
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

#[rstest]
#[case::complete(TerminalOp::Complete)]
#[case::fail(TerminalOp::Fail)]
#[case::cancel(TerminalOp::Cancel)]
fn terminal_op_idempotent_replay(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let op_id = OpId::from_raw(2);
    let first =
        apply_terminal_op(&mut coord, op, now(3), test_tenant(), test_run(), op_id).unwrap();
    assert!(first.is_executed());

    let second =
        apply_terminal_op(&mut coord, op, now(4), test_tenant(), test_run(), op_id).unwrap();
    assert!(second.is_replay());
}

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
fn complete_run_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let err = coord
        .complete_run(now(1), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, RunTransitionError::RunNotFound));
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

#[rstest]
#[case::run_cancelled(TerminalOp::Cancel, RunStatus::Cancelled)]
#[case::run_done(TerminalOp::Complete, RunStatus::Done)]
fn unpark_shard_rejected_when_run_terminal(
    #[case] op: TerminalOp,
    #[case] expected_status: RunStatus,
) {
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

    // Terminate the run.
    let _ = apply_terminal_op(
        &mut coord,
        op,
        now(5),
        test_tenant(),
        test_run(),
        OpId::from_raw(11),
    )
    .unwrap();

    // Attempt unpark -> should fail with RunTerminal.
    let err = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap_err();
    assert!(
        matches!(
            err,
            UnparkError::RunTerminal { status } if status == expected_status
        ),
        "expected RunTerminal({expected_status:?}), got: {err:?}",
    );
}

// -- register_shards error path tests -----------------------------------------
//
// Covers register_shards edge cases: idempotent replay (same OpId +
// payload returns Replayed with identical shard IDs), OpIdConflict
// (same OpId + different shard list), wrong-status rejection (run
// already Active), not-found error, and staged-build rollback on
// allocation failure (no partial inserts).

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
    // allocate at most one shard spec before returning SlabFull. The
    // coordinator stages record builds, so this should roll back to zero
    // inserted shards instead of leaving a partially registered run.
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

mod prop_progress_watermark {
    use super::*;
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    fn arb_active_cursor_keys() -> impl Strategy<Value = Vec<Option<Vec<u8>>>> {
        proptest::collection::vec(
            proptest::option::of(proptest::collection::vec(0u8..=254u8, 1..16)),
            1..32,
        )
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn watermark_bounds_and_none_condition_for_active_shards(
            cursor_keys in arb_active_cursor_keys(),
        ) {
            let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
            let shard_ids: Vec<ShardId> = (0..cursor_keys.len())
                .map(|i| ShardId::from_raw((i as u64) + 1))
                .collect();
            coord.seed_run(test_tenant(), test_run(), shard_ids.clone(), LEASE_DURATION);

            for (shard_id, key) in shard_ids.into_iter().zip(cursor_keys.iter()) {
                let cursor = key
                    .as_ref()
                    .map_or_else(Cursor::initial, |k| Cursor::with_last_key(k.clone()));
                let record = ShardRecord::from_raw_parts(
                    test_tenant(),
                    test_run(),
                    shard_id,
                    ShardStatus::Active,
                    None,
                    &ShardSpec::with_range(vec![0x00], vec![0xFF]),
                    &cursor,
                    CursorSemantics::Completed,
                    None,
                    FenceEpoch::INITIAL,
                    None,
                    gossip_stdx::InlineVec::new(),
                    RingBuffer::new(),
                    coord.slab_mut(),
                );
                coord.seed_shard(record);
            }

            let progress = coord
                .get_run_progress(now(10), test_tenant(), test_run())
                .unwrap();
            let expected_min = cursor_keys.iter().filter_map(|k| k.as_deref()).min();

            match (progress.watermark(), expected_min) {
                (None, None) => {}
                (Some(actual), Some(min_key)) => {
                    prop_assert_eq!(actual, min_key);
                    for key in cursor_keys.iter().filter_map(|k| k.as_deref()) {
                        prop_assert!(actual <= key);
                    }
                }
                (None, Some(_)) => {
                    prop_assert!(false, "watermark must be Some when any active shard progressed");
                }
                (Some(_), None) => {
                    prop_assert!(
                        false,
                        "watermark must be None when no active shard has a last_key"
                    );
                }
            }
        }
    }
}
