//! Behavioral conformance tests for the real etcd-backed coordinator.
//!
//! These scenarios mirror the shared coordination conformance suite while
//! observing the backend only through public protocol operations and the
//! persisted read-back helpers from `test_support.rs`.

use crate::test_support::test_coordinator;
use crate::{EtcdCoordinator, EtcdTestShardSnapshot};
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
use gossip_coordination::test_fixtures::{
    LEASE_DURATION, acquire_result, acquire_shard, checkpoint_ok, complete_ok, now, park_ok,
    seed_conformance_fixture, test_cursor, test_key, test_run, test_run_config, test_shard,
    test_split_replace_plan, test_split_residual_plan, test_tenant, test_worker,
};
use gossip_coordination::{
    CheckpointError, CoordinationBackend, IdempotentOutcome, Lease, ParkReason,
    RegisterShardsError, RunManagement, RunRecord, RunStatus, RunTransitionError, ShardRecord,
    ShardStatus, UnparkError,
};
use gossip_coordination::{OpId, RunId, ShardId, ShardKey};

fn seeded_etcd_coordinator(semantics: CursorSemantics) -> EtcdCoordinator {
    let mut coord = test_coordinator();
    seed_conformance_fixture(&mut coord, semantics);
    coord
}

fn shard_snapshot(coord: &EtcdCoordinator, key: ShardKey) -> EtcdTestShardSnapshot {
    coord
        .test_load_shard_snapshot(test_tenant(), key)
        .expect("shard lookup should succeed")
        .expect("shard must exist")
}

fn default_shard_snapshot(coord: &EtcdCoordinator) -> EtcdTestShardSnapshot {
    shard_snapshot(coord, test_key())
}

fn run_snapshot(coord: &EtcdCoordinator, run: RunId) -> RunRecord {
    coord
        .test_load_run_snapshot(test_tenant(), run)
        .expect("run lookup should succeed")
        .expect("run must exist")
}

fn cursor_last_key(snapshot: &EtcdTestShardSnapshot) -> Option<&[u8]> {
    snapshot.cursor.last_key(snapshot.slab())
}

fn spec_bounds(snapshot: &EtcdTestShardSnapshot) -> (&[u8], &[u8]) {
    (
        snapshot.spec.key_range_start(snapshot.slab()),
        snapshot.spec.key_range_end(snapshot.slab()),
    )
}

fn assert_owner_binding_absent(coord: &EtcdCoordinator, key: ShardKey) {
    assert!(
        coord
            .test_load_owner_binding(test_tenant(), key)
            .expect("owner lookup should succeed")
            .is_none(),
        "owner binding must be removed from etcd",
    );
}

fn assert_active_index_absent(coord: &EtcdCoordinator, key: ShardKey) {
    assert!(
        !coord
            .test_active_shard_index_exists(test_tenant(), key)
            .expect("active index lookup should succeed"),
        "active-shard index must be removed from etcd",
    );
}

fn assert_terminal_cleanup(coord: &EtcdCoordinator, key: ShardKey) {
    let snapshot = shard_snapshot(coord, key);
    assert!(
        snapshot.lease_owner().is_none(),
        "terminal transition must clear lease owner",
    );
    assert!(
        snapshot.lease_deadline().is_none(),
        "terminal transition must clear lease deadline",
    );
    assert_owner_binding_absent(coord, key);
    assert_active_index_absent(coord, key);
}

fn assert_all_run_transitions_rejected(coord: &mut EtcdCoordinator, expected_status: RunStatus) {
    let err = coord
        .complete_run(now(13), test_tenant(), test_run(), OpId::from_raw(101))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "complete_run on {expected_status:?} run must return RunTerminal, got: {err:?}",
    );

    let err = coord
        .fail_run(now(14), test_tenant(), test_run(), OpId::from_raw(102))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "fail_run on {expected_status:?} run must return RunTerminal, got: {err:?}",
    );

    let err = coord
        .cancel_run(now(15), test_tenant(), test_run(), OpId::from_raw(103))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "cancel_run on {expected_status:?} run must return RunTerminal, got: {err:?}",
    );
}

/// Mirrors `fence_monotonicity_across_full_lifecycle` against persisted etcd
/// state.
#[test]
fn fence_monotonicity_across_full_lifecycle() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease1 = acquire_shard(&mut coord, 10, 1);
    let fence1 = lease1.fence();

    checkpoint_ok(&mut coord, 11, &lease1, b"d", 1);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.fence_epoch, fence1,
        "checkpoint must not change fence"
    );
    assert_eq!(snapshot.status, ShardStatus::Active);

    let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 2);
    let fence2 = lease2.fence();
    assert!(
        fence2 > fence1,
        "re-acquire fence must exceed worker 1's fence",
    );

    checkpoint_ok(&mut coord, LEASE_DURATION + 12, &lease2, b"p", 3);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.fence_epoch, fence2,
        "checkpoint must not change fence"
    );

    complete_ok(&mut coord, LEASE_DURATION + 13, &lease2, b"y", 4);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.fence_epoch, fence2,
        "complete must not change fence"
    );
    assert_eq!(snapshot.status, ShardStatus::Done);
}

/// Mirrors `cursor_monotonicity_combined_with_split_residual` against
/// persisted etcd state.
#[test]
fn cursor_monotonicity_combined_with_split_residual() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);

    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    let plan = test_split_residual_plan();
    let result = coord
        .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
        .expect("split_residual should succeed");
    assert!(result.is_executed(), "split_residual must be Executed");

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(cursor_last_key(&snapshot), Some(b"d".as_slice()));
    let (start, end) = spec_bounds(&snapshot);
    assert_eq!(start, b"a");
    assert_eq!(end, b"m");

    let ok = coord.checkpoint(
        now(13),
        test_tenant(),
        &lease,
        &test_cursor(b"f"),
        OpId::from_raw(3),
    );
    assert!(ok.is_ok(), "checkpoint at 'f' must succeed within [a,m)");

    let err = coord.checkpoint(
        now(14),
        test_tenant(),
        &lease,
        &test_cursor(b"n"),
        OpId::from_raw(4),
    );
    assert!(
        matches!(err, Err(CheckpointError::CursorOutOfBounds(_))),
        "checkpoint at 'n' must fail with CursorOutOfBounds, got: {err:?}",
    );
}

/// Mirrors `idempotency_before_terminal_state_rejection` against persisted etcd
/// state.
#[test]
fn idempotency_before_terminal_state_rejection() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);

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
        .expect("complete should succeed");
    assert!(
        outcome.is_executed(),
        "first-time complete must be Executed"
    );

    let replay = coord.complete(
        now(13),
        test_tenant(),
        &lease,
        &complete_cursor,
        complete_op,
    );
    assert!(
        matches!(replay, Ok(IdempotentOutcome::Replayed(()))),
        "replay on terminal shard must return Replayed, got: {replay:?}",
    );

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.status,
        ShardStatus::Done,
        "replay must not change terminal status",
    );
    assert_eq!(
        cursor_last_key(&snapshot),
        Some(b"m".as_slice()),
        "replay must not mutate cursor",
    );
}

/// Mirrors `split_residual_preserved_through_park_unpark` against persisted
/// etcd state.
#[test]
fn split_residual_preserved_through_park_unpark() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    let fence0 = lease.fence();

    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    let plan = test_split_residual_plan();
    let result = coord
        .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
        .expect("split_residual should succeed");
    assert!(result.is_executed(), "split_residual must be Executed");

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.fence_epoch, fence0,
        "split_residual must not change fence",
    );

    park_ok(&mut coord, 13, &lease, ParkReason::TooManyErrors, 3);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(snapshot.status, ShardStatus::Parked);
    assert_eq!(snapshot.fence_epoch, fence0, "park must not change fence");
    assert_eq!(
        cursor_last_key(&snapshot),
        Some(b"d".as_slice()),
        "park must preserve cursor",
    );
    let (start, end) = spec_bounds(&snapshot);
    assert_eq!(start, b"a", "park must preserve narrowed range start");
    assert_eq!(end, b"m", "park must preserve narrowed range end");

    let outcome = coord
        .unpark_shard(now(14), test_tenant(), test_key(), OpId::from_raw(4))
        .expect("unpark_shard should succeed");
    assert!(outcome.is_executed(), "first-time unpark must be Executed");

    let fence_after_unpark = {
        let snapshot = default_shard_snapshot(&coord);
        assert_eq!(snapshot.status, ShardStatus::Active);
        assert!(
            snapshot.fence_epoch > fence0,
            "unpark must bump fence above pre-park value",
        );
        assert_eq!(
            cursor_last_key(&snapshot),
            Some(b"d".as_slice()),
            "unpark must preserve cursor through park round-trip",
        );
        let (start, end) = spec_bounds(&snapshot);
        assert_eq!(start, b"a", "unpark must preserve narrowed range start");
        assert_eq!(end, b"m", "unpark must preserve narrowed range end");
        snapshot.fence_epoch
    };

    let lease2 = acquire_shard(&mut coord, 15, 2);
    assert!(
        lease2.fence() > fence_after_unpark,
        "re-acquire must bump fence again",
    );

    checkpoint_ok(&mut coord, 16, &lease2, b"f", 5);
    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(cursor_last_key(&snapshot), Some(b"f".as_slice()));
}

/// Mirrors `owner_divergence_with_matching_fence` against persisted etcd
/// state.
#[test]
fn owner_divergence_with_matching_fence() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    let fence = lease.fence();

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
        "wrong owner with matching fence must produce StaleFence, got: {err:?}",
    );

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.fence_epoch, fence,
        "rejected checkpoint must not change fence",
    );
    assert_eq!(
        cursor_last_key(&snapshot),
        None,
        "rejected checkpoint must not advance cursor",
    );
    assert_eq!(
        snapshot.status,
        ShardStatus::Active,
        "rejected checkpoint must not change status",
    );
}

/// Mirrors `terminal_clears_lease` against persisted etcd state.
#[test]
fn terminal_clears_lease() {
    {
        let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        complete_ok(&mut coord, 11, &lease, b"m", 1);
        let snapshot = default_shard_snapshot(&coord);
        assert_eq!(
            snapshot.fence_epoch, fence,
            "complete must not change fence"
        );
        assert_eq!(snapshot.status, ShardStatus::Done);
        assert_terminal_cleanup(&coord, test_key());
    }

    {
        let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);
        let snapshot = default_shard_snapshot(&coord);
        assert_eq!(snapshot.fence_epoch, fence, "park must not change fence");
        assert_eq!(snapshot.status, ShardStatus::Parked);
        assert_terminal_cleanup(&coord, test_key());
    }

    {
        let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);
        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();
        let plan = test_split_replace_plan();
        let outcome = coord
            .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
            .expect("split_replace should succeed");
        assert!(
            outcome.is_executed(),
            "first-time split_replace must be Executed",
        );
        let snapshot = default_shard_snapshot(&coord);
        assert_eq!(
            snapshot.fence_epoch, fence,
            "split_replace must not change fence",
        );
        assert_eq!(snapshot.status, ShardStatus::Split);
        assert_terminal_cleanup(&coord, test_key());
    }
}

/// Mirrors `cursor_semantics_dispatched_through_coordinator` against persisted
/// etcd state.
#[test]
fn cursor_semantics_dispatched_through_coordinator() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Dispatched);

    let acquired = acquire_result(
        &mut coord,
        now(10),
        test_tenant(),
        test_key(),
        test_worker(1),
    )
    .expect("acquire should succeed");
    assert_eq!(
        acquired.snapshot().cursor_semantics(),
        CursorSemantics::Dispatched,
        "snapshot must reflect Dispatched semantics",
    );
    let lease = acquired.lease;

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(snapshot.cursor_semantics, CursorSemantics::Dispatched);

    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);
    complete_ok(&mut coord, 12, &lease, b"m", 2);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(snapshot.status, ShardStatus::Done);
    assert_eq!(snapshot.cursor_semantics, CursorSemantics::Dispatched);
}

/// Mirrors `lease_deadline_at_exact_boundary` against persisted etcd state.
#[test]
fn lease_deadline_at_exact_boundary() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    let deadline = 10 + LEASE_DURATION;
    assert_eq!(lease.deadline(), now(deadline));

    let ok = coord.checkpoint(
        now(deadline - 1),
        test_tenant(),
        &lease,
        &test_cursor(b"d"),
        OpId::from_raw(1),
    );
    assert!(ok.is_ok(), "checkpoint at deadline-1 must succeed");

    let err = coord.checkpoint(
        now(deadline),
        test_tenant(),
        &lease,
        &test_cursor(b"e"),
        OpId::from_raw(2),
    );
    assert!(
        matches!(err, Err(CheckpointError::LeaseExpired { .. })),
        "checkpoint at exact deadline must fail with LeaseExpired, got: {err:?}",
    );
}

/// Mirrors `split_coverage_key_range_partition` against persisted etcd state.
#[test]
fn split_coverage_key_range_partition() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    let plan = test_split_replace_plan();

    let result = coord
        .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
        .expect("split_replace should succeed");
    let children = result.into_inner().children;
    assert_eq!(children.len(), 2, "must produce exactly 2 children");
    let children = children.as_slice();
    let child_a = children[0];
    let child_b = children[1];

    let key_a = ShardKey::new(test_run(), child_a);
    let key_b = ShardKey::new(test_run(), child_b);

    {
        let snapshot_a = shard_snapshot(&coord, key_a);
        let snapshot_b = shard_snapshot(&coord, key_b);
        let (a_start, a_end) = spec_bounds(&snapshot_a);
        let (b_start, b_end) = spec_bounds(&snapshot_b);
        assert_eq!(a_start, b"a");
        assert_eq!(a_end, b"m");
        assert_eq!(b_start, b"m");
        assert_eq!(b_end, b"z");
        assert_eq!(a_end, b_start);
        assert_eq!(snapshot_a.status, ShardStatus::Active);
        assert_eq!(snapshot_b.status, ShardStatus::Active);
    }

    let child_lease = acquire_shard_child(&mut coord, 12, key_a, 1);
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
        "first-time child checkpoint must be Executed",
    );
    let snapshot_a = shard_snapshot(&coord, key_a);
    assert_eq!(
        cursor_last_key(&snapshot_a),
        Some(b"f".as_slice()),
        "child checkpoint must advance cursor",
    );
}

fn acquire_shard_child(
    coord: &mut EtcdCoordinator,
    t: u64,
    key: ShardKey,
    worker_id: u64,
) -> Lease {
    let mut scratch = gossip_coordination::AcquireScratch::new();
    coord
        .acquire_and_restore_into(
            now(t),
            test_tenant(),
            key,
            test_worker(worker_id),
            &mut scratch,
        )
        .expect("acquire should succeed")
        .lease
}

/// Mirrors `oplog_eviction_then_replay` against persisted etcd state.
#[test]
fn oplog_eviction_then_replay() {
    const _: () = assert!(
        ShardRecord::OP_LOG_CAP + 6 < LEASE_DURATION as usize,
        "oplog eviction test timestamps exceed single lease window",
    );

    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);
    let lease = acquire_shard(&mut coord, 10, 1);

    let cap = ShardRecord::OP_LOG_CAP as u64;
    let base_t = 10;
    let key_for = |n: u64| -> [u8; 9] {
        let mut key = [b'a'; 9];
        key[1..].copy_from_slice(&n.to_be_bytes());
        key
    };

    for i in 1..=cap {
        let key = key_for(i);
        let update = CursorUpdate::new(&key);
        let outcome = coord
            .checkpoint(
                now(base_t + i),
                test_tenant(),
                &lease,
                &update,
                OpId::from_raw(i),
            )
            .expect("checkpoint should succeed");
        assert!(
            outcome.is_executed(),
            "first-time checkpoint must be Executed",
        );
    }

    let evict_key = key_for(cap + 1);
    checkpoint_ok(&mut coord, base_t + cap + 1, &lease, &evict_key, cap + 1);

    let surviving_key = key_for(cap);
    let replay_surviving = coord.checkpoint(
        now(base_t + cap + 2),
        test_tenant(),
        &lease,
        &CursorUpdate::new(&surviving_key),
        OpId::from_raw(cap),
    );
    assert!(
        matches!(replay_surviving, Ok(IdempotentOutcome::Replayed(()))),
        "surviving op in ring buffer must return Replayed, got: {replay_surviving:?}",
    );

    let fresh_key = key_for(cap + 2);
    let evicted_replay = coord.checkpoint(
        now(base_t + cap + 3),
        test_tenant(),
        &lease,
        &CursorUpdate::new(&fresh_key),
        OpId::from_raw(1),
    );
    assert!(
        matches!(evicted_replay, Ok(IdempotentOutcome::Executed(()))),
        "evicted op replayed with forward cursor on active shard must be Executed, got: {evicted_replay:?}",
    );

    let complete_key = key_for(cap + 3);
    complete_ok(&mut coord, base_t + cap + 4, &lease, &complete_key, cap + 2);

    let replay_on_terminal = coord.complete(
        now(base_t + cap + 5),
        test_tenant(),
        &lease,
        &test_cursor(&complete_key),
        OpId::from_raw(cap + 2),
    );
    assert!(
        matches!(replay_on_terminal, Ok(IdempotentOutcome::Replayed(()))),
        "surviving op on terminal shard must return Replayed, got: {replay_on_terminal:?}",
    );
}

/// Mirrors `unpark_lifecycle_fence_and_cursor_preserved` against persisted
/// etcd state.
#[test]
fn unpark_lifecycle_fence_and_cursor_preserved() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    let fence_before_park = lease.fence();
    checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

    park_ok(&mut coord, 12, &lease, ParkReason::TooManyErrors, 2);

    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(snapshot.status, ShardStatus::Parked);

    let outcome = coord
        .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(3))
        .expect("unpark_shard should succeed");
    assert!(outcome.is_executed(), "first-time unpark must be Executed");

    let fence_after_unpark = {
        let snapshot = default_shard_snapshot(&coord);
        assert_eq!(snapshot.status, ShardStatus::Active);
        assert!(
            snapshot.fence_epoch > fence_before_park,
            "unpark must bump fence",
        );
        assert_eq!(
            cursor_last_key(&snapshot),
            Some(b"d".as_slice()),
            "unpark must preserve cursor",
        );
        snapshot.fence_epoch
    };

    let lease2 = acquire_shard(&mut coord, 14, 2);
    assert!(
        lease2.fence() > fence_after_unpark,
        "acquire after unpark must bump fence again",
    );

    checkpoint_ok(&mut coord, 15, &lease2, b"f", 4);
    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(cursor_last_key(&snapshot), Some(b"f".as_slice()));
}

/// Mirrors `same_worker_reacquire_bumps_fence` against persisted etcd state.
#[test]
fn same_worker_reacquire_bumps_fence() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease1 = acquire_shard(&mut coord, 10, 1);
    let fence1 = lease1.fence();

    let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 1);
    let fence2 = lease2.fence();

    assert_eq!(
        fence2,
        fence1.increment(),
        "re-acquire must bump fence by 1"
    );
    assert!(fence2 > fence1, "new fence must exceed old fence");

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
        "old lease must produce StaleFence, got: {err:?}",
    );

    let ok = coord.checkpoint(
        now(LEASE_DURATION + 12),
        test_tenant(),
        &lease2,
        &test_cursor(b"d"),
        OpId::from_raw(2),
    );
    assert!(ok.is_ok(), "new lease checkpoint must succeed");
}

/// Mirrors `run_terminal_irreversibility [Done]` against persisted etcd state.
#[test]
fn run_terminal_irreversibility_done() {
    let expected_status = RunStatus::Done;
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    complete_ok(&mut coord, 11, &lease, b"y", 1);
    let outcome = coord
        .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .expect("complete_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time complete_run must be Executed"
    );

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), expected_status);

    assert_all_run_transitions_rejected(&mut coord, expected_status);
}

/// Mirrors `run_terminal_irreversibility [Cancelled]` against persisted etcd
/// state.
#[test]
fn run_terminal_irreversibility_cancelled() {
    let expected_status = RunStatus::Cancelled;
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let _lease = acquire_shard(&mut coord, 10, 1);
    let snapshot = default_shard_snapshot(&coord);
    assert_eq!(
        snapshot.status,
        ShardStatus::Active,
        "shard must be leased before cancel",
    );

    let outcome = coord
        .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .expect("cancel_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time cancel_run must be Executed"
    );

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), expected_status);

    assert_all_run_transitions_rejected(&mut coord, expected_status);
}

/// Mirrors `run_terminal_irreversibility [Failed]` against persisted etcd
/// state.
#[test]
fn run_terminal_irreversibility_failed() {
    let expected_status = RunStatus::Failed;
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let outcome = coord
        .fail_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .expect("fail_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time fail_run must be Executed"
    );

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), expected_status);

    assert_all_run_transitions_rejected(&mut coord, expected_status);
}

/// Mirrors `register_shards_on_non_initializing_rejected` against persisted
/// etcd state.
#[test]
fn register_shards_on_non_initializing_rejected() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), RunStatus::Active);

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
        matches!(err, RegisterShardsError::WrongStatus { .. }),
        "register_shards on Active run must return WrongStatus, got: {err:?}",
    );
}

/// Mirrors `run_completed_at_consistency` against persisted etcd state.
#[test]
fn run_completed_at_consistency() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), RunStatus::Active);
    assert!(
        record.completed_at().is_none(),
        "Active run must have completed_at == None",
    );

    let lease = acquire_shard(&mut coord, 10, 1);
    complete_ok(&mut coord, 11, &lease, b"y", 1);
    let outcome = coord
        .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .expect("complete_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time complete_run must be Executed"
    );

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), RunStatus::Done);
    assert!(
        record.completed_at().is_some(),
        "Done run must have completed_at",
    );

    let run2 = RunId::from_raw(2);
    let config = test_run_config();
    coord
        .create_run(now(20), test_tenant(), run2, config)
        .expect("create_run should succeed");

    let record = run_snapshot(&coord, run2);
    assert!(
        record.completed_at().is_none(),
        "Initializing run must have completed_at == None",
    );

    let outcome = coord
        .cancel_run(now(21), test_tenant(), run2, OpId::from_raw(200))
        .expect("cancel_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time cancel_run must be Executed"
    );

    let record = run_snapshot(&coord, run2);
    assert_eq!(record.status(), RunStatus::Cancelled);
    assert!(
        record.completed_at().is_some(),
        "Cancelled run must have completed_at",
    );
}

/// Mirrors `unpark_after_run_terminal_rejected` against persisted etcd state.
#[test]
fn unpark_after_run_terminal_rejected() {
    let mut coord = seeded_etcd_coordinator(CursorSemantics::Completed);

    let lease = acquire_shard(&mut coord, 10, 1);
    park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);

    let outcome = coord
        .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
        .expect("cancel_run should succeed");
    assert!(
        outcome.is_executed(),
        "first-time cancel_run must be Executed"
    );

    let record = run_snapshot(&coord, test_run());
    assert_eq!(record.status(), RunStatus::Cancelled);

    let err = coord
        .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(2))
        .unwrap_err();
    assert!(
        matches!(err, UnparkError::RunTerminal { .. }),
        "unpark on terminal run must return RunTerminal, got: {err:?}",
    );
}
