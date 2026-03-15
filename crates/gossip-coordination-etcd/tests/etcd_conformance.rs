#![cfg(feature = "test-support")]

//! Simulated etcd binding for the shared coordination conformance suite.
//!
//! This test mirrors the in-memory seeded fixture so the shared harness
//! exercises the etcd coordination logic against the in-memory KV model
//! with deterministic logical time and lease TTLs that outlive the
//! protocol lease duration.

use gossip_coordination::conformance::run_coordination_conformance;
use gossip_coordination::test_fixtures::{
    LEASE_DURATION, now, test_run, test_shard, test_spec, test_tenant,
};
use gossip_coordination::{
    CursorSemantics, CursorUpdate, InitialShardInput, OpId, RunConfig, RunManagement, ShardRecord,
};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, SimEtcdCoordinator};

const OWNER_LEASE_TTL_SECS: i64 = 200;
const OPTIMISTIC_TXN_RETRIES: usize = 8;
const MAX_CHILDREN_PER_OP: usize = 8;
const SEED: u64 = 42;

const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);
const _: () = assert!(LEASE_DURATION == 100);
const _: () = assert!(OWNER_LEASE_TTL_SECS >= LEASE_DURATION as i64);

#[test]
fn sim_etcd_conformance() {
    run_coordination_conformance(seed_sim_etcd_with_semantics);
}

/// Seed the canonical single-run, single-shard conformance fixture.
fn seed_sim_etcd_with_semantics(semantics: CursorSemantics) -> SimEtcdCoordinator {
    let config = EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        "/gossip/conformance",
        OWNER_LEASE_TTL_SECS,
        OPTIMISTIC_TXN_RETRIES,
        MAX_CHILDREN_PER_OP,
    )
    .expect("hard-coded simulated etcd config must remain valid");

    let mut coord =
        SimEtcdCoordinator::new(config, SEED).expect("simulated etcd coordinator must construct");
    let run_config = RunConfig::try_new(semantics, LEASE_DURATION, Some(5))
        .expect("conformance run config must be valid");
    coord
        .create_run(now(1), test_tenant(), test_run(), run_config)
        .expect("conformance seeding must create the run");

    let spec = test_spec();
    let shards = [InitialShardInput::new(
        test_shard(),
        spec.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(u64::MAX),
        )
        .expect("conformance seeding must register the root shard");

    coord
}
