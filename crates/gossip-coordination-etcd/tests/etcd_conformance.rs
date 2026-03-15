#![cfg(feature = "test-support")]

//! Simulated etcd binding for the shared coordination conformance suite.
//!
//! This test mirrors the in-memory seeded fixture so the shared harness
//! exercises the etcd coordination logic against the in-memory KV model
//! with deterministic logical time and lease TTLs that outlive the
//! protocol lease duration.

use gossip_coordination::conformance::run_coordination_conformance;
use gossip_coordination::test_fixtures::{LEASE_DURATION, seed_conformance_fixture};
use gossip_coordination::{CursorSemantics, MAX_SPAWNED_PER_SHARD, ShardRecord};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, SimEtcdCoordinator};

/// Etcd owner-lease TTL. Named `_SECS` to match the real etcd gRPC API
/// parameter, but `SimEtcdCoordinator` consumes this as logical ticks.
/// Must be >= LEASE_DURATION so the etcd owner key survives for the
/// full protocol lease period; each acquire issues a fresh lease_grant,
/// so a single-lease-duration bound is sufficient.
const OWNER_LEASE_TTL_SECS: i64 = 200;
const OPTIMISTIC_TXN_RETRIES: usize = 8;
const MAX_CHILDREN_PER_OP: usize = 8;
const SEED: u64 = 42;

const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);
const _: () = assert!(MAX_SPAWNED_PER_SHARD == 1024);
const _: () = assert!(LEASE_DURATION == 100);
// The etcd owner key must outlive one protocol lease so checkpoint/complete
// CAS guards find it. Each acquire creates a fresh etcd lease, so there is
// no need for the TTL to span multiple consecutive protocol leases.
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
    seed_conformance_fixture(&mut coord, semantics);
    coord
}
