use std::env;

use crate::{
    EtcdCoordinator, EtcdCoordinatorConfig, EtcdKeyspace, decode_run_record_v1,
    decode_shard_record_v1, encode_run_record_v1, encode_shard_record_v1,
};
use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, PooledSpawned, ShardSpecRef};
use gossip_contracts::identity::{FenceEpoch, LogicalTime, RunId, ShardId, TenantId, WorkerId};
use gossip_coordination::{LeaseHolder, OpKind, OpLogEntry, OpResult, RunConfig, RunOpKind, RunOpLogEntry, RunOpResult, RunRecord, RunStatus, ShardRecord};
use gossip_stdx::{ByteSlab, RingBuffer};

#[test]
fn config_rejects_empty_endpoint_list() {
    let err = EtcdCoordinatorConfig::new(Vec::<String>::new(), "/gossip/v1")
        .expect_err("empty endpoints must fail validation");
    assert!(matches!(
        err,
        crate::EtcdCoordinatorConfigError::NoEndpoints
    ));
}

#[test]
fn config_rejects_invalid_namespace_prefix() {
    let err = EtcdCoordinatorConfig::new(["http://127.0.0.1:2379"], "gossip/v1")
        .expect_err("namespace prefix without leading slash must fail");
    assert!(matches!(
        err,
        crate::EtcdCoordinatorConfigError::NamespacePrefixMustStartWithSlash
    ));
}

#[test]
fn keyspace_builds_expected_paths() {
    let tenant = TenantId::from_bytes([0xAB; 32]);
    let run = RunId::from_raw(0x0123_4567_89ab_cdef);
    let shard = ShardId::from_raw(0x8000_0000_0000_0042);

    let keyspace = EtcdKeyspace::new("/gossip/v1").expect("valid keyspace prefix");
    assert_eq!(
        keyspace.run_record_key(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef"
    );
    assert_eq!(
        keyspace.shard_record_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042"
    );
    assert_eq!(
        keyspace.shard_owner_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards/8000000000000042/owner"
    );
    assert_eq!(
        keyspace.run_active_index_key(tenant, run),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs_active/0123456789abcdef"
    );
    assert_eq!(
        keyspace.active_shard_index_key(tenant, run, shard),
        "/gossip/v1/tenants/abababababababababababababababababababababababababababababababab/runs/0123456789abcdef/shards_active/8000000000000042"
    );
}

#[test]
fn run_record_v1_round_trips_losslessly() {
    let record = sample_run_record();
    let encoded = encode_run_record_v1(&record);
    let decoded = decode_run_record_v1(&encoded).expect("run record should decode");
    let reencoded = encode_run_record_v1(&decoded);

    assert_eq!(decoded, record);
    assert_eq!(reencoded, encoded);
}

#[test]
fn shard_record_v1_round_trips_losslessly() {
    let (record, slab) = sample_shard_record();
    let encoded = encode_shard_record_v1(&record, &slab);

    let mut decode_slab = ByteSlab::with_capacity(4096);
    let decoded = decode_shard_record_v1(&encoded, &mut decode_slab)
        .expect("shard record should decode");
    let reencoded = encode_shard_record_v1(&decoded, &decode_slab);

    assert_eq!(reencoded, encoded);
}

#[test]
#[ignore = "requires a local etcd on ETCD_ENDPOINTS or localhost:2379"]
fn connects_to_local_etcd_and_fetches_status() {
    let endpoints = env::var("ETCD_ENDPOINTS")
        .ok()
        .and_then(|raw| {
            let trimmed = raw.trim().to_owned();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed)
            }
        })
        .unwrap_or_else(|| "http://127.0.0.1:2379".to_owned());

    let config = EtcdCoordinatorConfig::from_endpoints_csv(&endpoints, "/gossip/v1")
        .expect("test endpoint configuration should be valid");

    let backend = EtcdCoordinator::connect(config).expect("local etcd should be reachable");
    let status = backend.status().expect("status call should succeed");

    assert!(
        !status.version.is_empty(),
        "connected member should report a version"
    );
}

fn sample_run_record() -> RunRecord {
    let tenant = TenantId::from_bytes([0x11; 32]);
    let run = RunId::from_raw(0x0102_0304_0506_0708);
    let root_a = ShardId::from_raw(1);
    let root_b = ShardId::from_raw(2);
    let config = RunConfig::try_new(CursorSemantics::Completed, 30, Some(7)).unwrap();

    let mut op_log = RingBuffer::<RunOpLogEntry, { RunRecord::OP_LOG_CAP }>::new();
    op_log.push_back_overwrite(RunOpLogEntry::new(
        gossip_contracts::identity::OpId::from_raw(99),
        RunOpKind::RegisterShards,
        0xdead_beef,
        LogicalTime::from_raw(10),
        RunOpResult::RegisteredShards {
            shard_ids: vec![root_a, root_b].into_boxed_slice(),
        },
    ));

    let record = RunRecord {
        tenant,
        run,
        config,
        status: RunStatus::Active,
        created_at: LogicalTime::from_raw(5),
        completed_at: None,
        root_shards: vec![root_a, root_b],
        op_log,
    };
    record.assert_invariants();
    record
}

fn sample_shard_record() -> (ShardRecord, ByteSlab) {
    let tenant = TenantId::from_bytes([0x22; 32]);
    let run = RunId::from_raw(0x9999);
    let shard = ShardId::from_raw(0x8000_0000_0000_0001);
    let parent = ShardId::from_raw(17);
    let spawned_child = ShardId::from_raw(0x8000_0000_0000_0002);

    let mut slab = ByteSlab::with_capacity(4096);
    let spec = ShardSpecRef::with_range_and_metadata(b"aa", b"zz", b"repo=alpha");
    let cursor = CursorUpdate::with_token(b"mm", b"tok-1");
    let mut record = ShardRecord::new_split_child(
        tenant,
        run,
        shard,
        spec,
        cursor,
        CursorSemantics::Dispatched,
        parent,
        &mut slab,
    )
    .expect("sample shard record should fit in slab");

    record.lease = Some(LeaseHolder::new(
        WorkerId::from_raw(7),
        LogicalTime::from_raw(100),
    ));
    record.fence_epoch = FenceEpoch::from_raw(9);

    let mut spawned = PooledSpawned::new();
    let (slot, len) = spawned
        .allocate_appended_slot(&[spawned_child], &mut slab)
        .expect("spawned child should fit");
    spawned.install_slot(slot, len, &mut slab);
    record.spawned = spawned;

    record.op_log.push_back_overwrite(OpLogEntry::new(
        gossip_contracts::identity::OpId::from_raw(1),
        OpKind::Checkpoint,
        OpResult::Completed,
        12345,
        LogicalTime::from_raw(11),
    ));
    record.op_log.push_back_overwrite(OpLogEntry::new(
        gossip_contracts::identity::OpId::from_raw(2),
        OpKind::SplitResidual,
        OpResult::Superseded,
        67890,
        LogicalTime::from_raw(12),
    ));

    record.assert_invariants(&slab);
    (record, slab)
}
