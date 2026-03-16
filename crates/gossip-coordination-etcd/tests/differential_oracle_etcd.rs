#![cfg(feature = "test-support")]
//! Differential oracle: deterministic in-memory etcd model vs. live etcd.
//!
//! The fast CI oracle in `differential_oracle.rs` compares
//! `InMemoryCoordinator` with `SimEtcdCoordinator`. This companion test goes a
//! step farther by comparing `SimEtcdCoordinator` with a real etcd-backed
//! coordinator observed through test-only snapshot loaders. It stays `ignore`d
//! because it needs Docker or an external etcd cluster.

#[path = "support/oracle.rs"]
mod oracle;
mod support;

use gossip_contracts::test_util::selected_seeds_from_env;
use gossip_coordination::sim::{CoordinationSim, FaultLevel};
use gossip_coordination_etcd::SimEtcdCoordinator;
use gossip_coordination_etcd::test_support::test_coordinator_with_tuning;
use oracle::DifferentialOracle;
use support::ObservedEtcdCoordinator;

const CASES: usize = 50;

fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_COORD_DIFF_LIVE_SEED={seed} cargo test -p gossip-coordination-etcd \
         --features test-support no_model_drift_against_real_etcd \
         -- --ignored --exact --nocapture"
    )
}

fn build_oracle(seed: u64) -> DifferentialOracle<SimEtcdCoordinator, ObservedEtcdCoordinator> {
    let sim_backend = SimEtcdCoordinator::new(
        oracle::etcd_sim_config(&format!("/gossip/diff/live/{seed}")),
        seed,
    )
    .expect("simulated etcd backend must construct");
    let etcd_backend = ObservedEtcdCoordinator::new(test_coordinator_with_tuning(
        oracle::OWNER_LEASE_TTL_SECS,
        oracle::OPTIMISTIC_TXN_RETRIES,
        oracle::MAX_CHILDREN_PER_OP,
    ));

    let sim = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, sim_backend)
        .with_workers_and_shards(oracle::N_WORKERS, oracle::N_SHARDS);
    let etcd = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, etcd_backend)
        .with_workers_and_shards(oracle::N_WORKERS, oracle::N_SHARDS);

    DifferentialOracle::new(
        sim,
        "sim_etcd",
        etcd,
        "live_etcd",
        seed,
        repro_command(seed),
    )
}

#[test]
#[ignore]
fn no_model_drift_against_real_etcd() {
    for seed in selected_seeds_from_env(
        "GOSSIP_COORD_DIFF_LIVE_SEED",
        "GOSSIP_COORD_DIFF_LIVE_CASES",
        CASES,
    ) {
        let ops = oracle::generated_ops(seed);
        let mut oracle = build_oracle(seed);
        oracle.run_sequence(&ops);
    }
}
