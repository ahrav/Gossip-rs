#![cfg(feature = "test-support")]
//! Differential oracle: `InMemoryCoordinator` vs. `SimEtcdCoordinator`.
//!
//! This is the CI-friendly mock-drift check for the coordination subsystem.
//! Both backends run entirely in memory, so the test can compare 100+ random
//! `SimOp` sequences without Docker or a live etcd server.

#[path = "support/oracle.rs"]
mod oracle;

use gossip_contracts::test_util::selected_seeds_from_env;
use gossip_coordination::InMemoryCoordinator;
use gossip_coordination::sim::test_util::LEASE_DUR;
use gossip_coordination::sim::{CoordinationSim, FaultLevel};
use gossip_coordination_etcd::SimEtcdCoordinator;
use oracle::DifferentialOracle;

const CASES: usize = if cfg!(miri) { 4 } else { 128 };

/// Lease duration for in-memory coordinators. Sourced from `LEASE_DUR` so it
/// stays in sync with the harness's `DEFAULT_LEASE_DURATION`.
const COORDINATOR_LEASE_DURATION: u64 = LEASE_DUR;

fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_COORD_DIFF_SEED={seed} cargo test -p gossip-coordination-etcd \
         --features test-support in_memory_matches_sim_etcd_differential_oracle \
         -- --exact --nocapture"
    )
}

fn build_oracle(seed: u64) -> DifferentialOracle<InMemoryCoordinator, SimEtcdCoordinator> {
    let memory_backend = InMemoryCoordinator::new(COORDINATOR_LEASE_DURATION);
    let sim_etcd_backend = SimEtcdCoordinator::new(
        oracle::etcd_sim_config(&format!("/gossip/diff/ci/{seed}")),
        seed,
    )
    .expect("simulated etcd backend must construct");

    let memory = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, memory_backend)
        .with_workers_and_shards(oracle::N_WORKERS, oracle::N_SHARDS);
    let sim_etcd = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, sim_etcd_backend)
        .with_workers_and_shards(oracle::N_WORKERS, oracle::N_SHARDS);

    DifferentialOracle::new(
        memory,
        "in_memory",
        sim_etcd,
        "sim_etcd",
        seed,
        repro_command(seed),
    )
}

#[test]
fn in_memory_matches_sim_etcd_differential_oracle() {
    for seed in selected_seeds_from_env("GOSSIP_COORD_DIFF_SEED", "GOSSIP_COORD_DIFF_CASES", CASES)
    {
        let ops = oracle::generated_ops(seed);
        let mut oracle = build_oracle(seed);
        oracle.run_sequence(&ops);
    }
}
