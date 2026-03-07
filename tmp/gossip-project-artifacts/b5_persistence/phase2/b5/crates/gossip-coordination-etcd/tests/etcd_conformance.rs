#![cfg(feature = "test-support")]

mod common;

use common::DockerComposeEtcd;
use gossip_coordination::{
    AcquireScratch, CheckpointError, CoordinationBackend, CursorUpdate, DerivedShardKind,
    IdempotentOutcome, InitialShardInput, OpId, RunManagement, ShardKey, ShardSpecRef,
    ShardStatus, SplitReplaceError, SplitResidualError, derive_split_shard_id,
};
use gossip_coordination::test_fixtures::{
    now, short_lease_run_config, test_key, test_run, test_shard, test_split_replace_plan,
    test_split_residual_plan, test_tenant, test_worker,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdTestFault};

fn seed_single_root_shard(backend: &mut EtcdCoordinator) {
    backend
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .expect("create_run should succeed");
    let manifest = [InitialShardInput::new(
        test_shard(),
        ShardSpecRef::new(b"a", b"z", b""),
        CursorUpdate::initial(),
    )];
    let outcome = backend
        .register_shards(now(2), test_tenant(), test_run(), &manifest, OpId::from_raw(1))
        .expect("register_shards should succeed");
    assert!(matches!(outcome, IdempotentOutcome::Executed(_)));
}

fn acquire_lease(backend: &mut EtcdCoordinator, t: u64, worker_id: u64) -> gossip_coordination::Lease {
    let mut scratch = AcquireScratch::new();
    let view = backend
        .acquire_and_restore_into(
            now(t),
            test_tenant(),
            test_key(),
            test_worker(worker_id),
            &mut scratch,
        )
        .expect("acquire should succeed");
    view.lease
}

#[test]
fn stale_fence_checkpoint_rejection_against_etcd() {
    let suite = DockerComposeEtcd::new();
    let mut backend = suite.backend("stale-fence");
    seed_single_root_shard(&mut backend);

    let lease1 = acquire_lease(&mut backend, 10, 1);
    let first = backend
        .checkpoint(
            now(11),
            test_tenant(),
            &lease1,
            &CursorUpdate::new(b"d"),
            OpId::from_raw(10),
        )
        .expect("initial checkpoint should succeed");
    assert!(first.is_executed());

    let reacquire_at = lease1.deadline().as_raw() + 1;
    let lease2 = acquire_lease(&mut backend, reacquire_at, 2);
    assert!(lease2.fence() > lease1.fence(), "fence must increase on reacquire");

    let err = backend
        .checkpoint(
            now(reacquire_at + 1),
            test_tenant(),
            &lease1,
            &CursorUpdate::new(b"k"),
            OpId::from_raw(11),
        )
        .expect_err("stale worker checkpoint must be rejected");

    match err {
        CheckpointError::StaleFence { presented, current } => {
            assert_eq!(presented, lease1.fence());
            assert_eq!(current, lease2.fence());
        }
        other => panic!("expected StaleFence, got {other:?}"),
    }

    let (parent, slab) = backend
        .test_load_shard_snapshot(test_tenant(), test_key())
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.cursor.last_key(&slab), Some(b"d".as_slice()));

    let owner = backend
        .test_load_owner_binding(test_tenant(), test_key())
        .expect("owner lookup should succeed")
        .expect("owner binding must exist");
    assert_eq!(owner.0, test_worker(2));
    assert_eq!(owner.1, lease2.fence());
}

#[test]
fn checkpoint_replay_is_idempotent_against_etcd() {
    let suite = DockerComposeEtcd::new();
    let mut backend = suite.backend("checkpoint-replay");
    seed_single_root_shard(&mut backend);

    let lease = acquire_lease(&mut backend, 10, 1);
    let op = OpId::from_raw(100);
    let cursor = CursorUpdate::new(b"m");

    let first = backend
        .checkpoint(now(11), test_tenant(), &lease, &cursor, op)
        .expect("initial checkpoint should succeed");
    assert!(first.is_executed());

    let replay = backend
        .checkpoint(now(12), test_tenant(), &lease, &cursor, op)
        .expect("checkpoint replay should succeed");
    assert!(replay.is_replay());

    let (shard, slab) = backend
        .test_load_shard_snapshot(test_tenant(), test_key())
        .expect("shard lookup should succeed")
        .expect("shard must exist");
    assert_eq!(shard.cursor.last_key(&slab), Some(b"m".as_slice()));

    let checkpoint_entries = shard
        .op_log
        .iter()
        .filter(|entry| entry.op_id() == op)
        .count();
    assert_eq!(checkpoint_entries, 1, "replay must not duplicate op-log entries");
}

#[test]
fn split_replace_replay_is_idempotent_against_etcd() {
    let suite = DockerComposeEtcd::new();
    let mut backend = suite.backend("split-replay");
    seed_single_root_shard(&mut backend);

    let lease = acquire_lease(&mut backend, 10, 1);
    let plan = test_split_replace_plan();
    let op = OpId::from_raw(200);

    let first = backend
        .split_replace(now(11), test_tenant(), &lease, plan.clone(), op)
        .expect("initial split_replace should succeed");
    assert!(first.is_executed());
    assert_eq!(first.as_ref().children.len(), 2);

    let replay = backend
        .split_replace(now(12), test_tenant(), &lease, plan, op)
        .expect("split_replace replay should succeed");
    assert!(replay.is_replay());
    assert_eq!(replay.as_ref().children, first.as_ref().children);

    let (parent, slab) = backend
        .test_load_shard_snapshot(test_tenant(), test_key())
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Split);
    let spawned: Vec<_> = parent.spawned.iter(&slab).collect();
    assert_eq!(spawned, first.as_ref().children.as_slice());
}

#[test]
fn split_replace_txn_abort_publishes_no_partial_children() {
    let suite = DockerComposeEtcd::new();
    let mut backend = suite.backend("split-replace-atomicity");
    seed_single_root_shard(&mut backend);

    let lease = acquire_lease(&mut backend, 10, 1);
    let plan = test_split_replace_plan();
    let op = OpId::from_raw(300);
    let child0 = derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Child, 0);
    let child1 = derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Child, 1);

    backend.test_arm_fault(EtcdTestFault::DropOwnerBeforeNextSplitReplaceTxn);
    let err = backend
        .split_replace(now(11), test_tenant(), &lease, plan, op)
        .expect_err("fault-injected split_replace must fail");
    assert!(matches!(err, SplitReplaceError::StaleFence { .. }));

    let (parent, slab) = backend
        .test_load_shard_snapshot(test_tenant(), test_key())
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(&slab), b"a");
    assert_eq!(parent.spec.key_range_end(&slab), b"z");
    assert_eq!(parent.spawned.len(), 0, "aborted split must not append spawned children");

    assert!(backend
        .test_load_shard_snapshot(test_tenant(), ShardKey::new(test_run(), child0))
        .expect("child lookup should succeed")
        .is_none());
    assert!(backend
        .test_load_shard_snapshot(test_tenant(), ShardKey::new(test_run(), child1))
        .expect("child lookup should succeed")
        .is_none());

    assert!(backend
        .test_active_shard_index_exists(test_tenant(), test_key())
        .expect("parent active-index lookup should succeed"));
    assert!(!backend
        .test_active_shard_index_exists(test_tenant(), ShardKey::new(test_run(), child0))
        .expect("child active-index lookup should succeed"));
    assert!(!backend
        .test_active_shard_index_exists(test_tenant(), ShardKey::new(test_run(), child1))
        .expect("child active-index lookup should succeed"));
}

#[test]
fn split_residual_txn_abort_publishes_no_partial_residual() {
    let suite = DockerComposeEtcd::new();
    let mut backend = suite.backend("split-residual-atomicity");
    seed_single_root_shard(&mut backend);

    let lease = acquire_lease(&mut backend, 10, 1);
    backend
        .checkpoint(
            now(11),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(400),
        )
        .expect("pre-split checkpoint should succeed");

    let plan = test_split_residual_plan();
    let op = OpId::from_raw(401);
    let residual = derive_split_shard_id(test_run(), test_shard(), op, DerivedShardKind::Residual, 0);

    backend.test_arm_fault(EtcdTestFault::DropOwnerBeforeNextSplitResidualTxn);
    let err = backend
        .split_residual(now(12), test_tenant(), &lease, plan, op)
        .expect_err("fault-injected split_residual must fail");
    assert!(matches!(err, SplitResidualError::StaleFence { .. }));

    let (parent, slab) = backend
        .test_load_shard_snapshot(test_tenant(), test_key())
        .expect("parent lookup should succeed")
        .expect("parent shard must exist");
    assert_eq!(parent.status, ShardStatus::Active);
    assert_eq!(parent.spec.key_range_start(&slab), b"a");
    assert_eq!(parent.spec.key_range_end(&slab), b"z");
    assert_eq!(parent.cursor.last_key(&slab), Some(b"f".as_slice()));
    assert_eq!(parent.spawned.len(), 0, "aborted residual split must not append spawned child");

    assert!(backend
        .test_load_shard_snapshot(test_tenant(), ShardKey::new(test_run(), residual))
        .expect("residual lookup should succeed")
        .is_none());
    assert!(backend
        .test_active_shard_index_exists(test_tenant(), test_key())
        .expect("parent active-index lookup should succeed"));
    assert!(!backend
        .test_active_shard_index_exists(test_tenant(), ShardKey::new(test_run(), residual))
        .expect("residual active-index lookup should succeed"));
}
