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
use gossip_coordination::sim::test_util::{LEASE_DUR, arb_sim_op};
use gossip_coordination::sim::{CoordinationSim, FaultLevel};
use gossip_coordination_etcd::{EtcdCoordinatorConfig, SimEtcdCoordinator};
use oracle::DifferentialOracle;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config as ProptestConfig, RngAlgorithm, TestRng, TestRunner};

const CASES: usize = if cfg!(miri) { 4 } else { 128 };
const N_WORKERS: u64 = 4;
const N_SHARDS: u64 = 8;

/// Lease duration for in-memory coordinators. Sourced from `LEASE_DUR` so it
/// stays in sync with the harness's `DEFAULT_LEASE_DURATION`.
const COORDINATOR_LEASE_DURATION: u64 = LEASE_DUR;

fn proptest_seed(seed: u64) -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[..8].copy_from_slice(&seed.to_le_bytes());
    bytes
}

fn generated_ops(seed: u64) -> Vec<gossip_coordination::sim::SimOp> {
    let strategy = proptest::collection::vec(arb_sim_op(N_WORKERS, N_SHARDS), 15..50);
    let mut runner = TestRunner::new_with_rng(
        ProptestConfig {
            failure_persistence: None,
            ..ProptestConfig::default()
        },
        TestRng::from_seed(RngAlgorithm::ChaCha, &proptest_seed(seed)),
    );

    strategy
        .new_tree(&mut runner)
        .expect("SimOp strategy must generate a sequence")
        .current()
}

fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_COORD_DIFF_SEED={seed} cargo test -p gossip-coordination-etcd \
         --features test-support in_memory_matches_sim_etcd_differential_oracle \
         -- --exact --nocapture"
    )
}

fn sim_config(namespace: &str) -> EtcdCoordinatorConfig {
    EtcdCoordinatorConfig::new_with_tuning(
        ["http://127.0.0.1:2379"],
        namespace,
        300, // OWNER_LEASE_TTL_SECS
        8,   // OPTIMISTIC_TXN_RETRIES
        8,   // MAX_CHILDREN_PER_OP
    )
    .expect("differential oracle config must be valid")
}

fn build_oracle(seed: u64) -> DifferentialOracle<InMemoryCoordinator, SimEtcdCoordinator> {
    let memory_backend = InMemoryCoordinator::new(COORDINATOR_LEASE_DURATION);
    let sim_etcd_backend =
        SimEtcdCoordinator::new(sim_config(&format!("/gossip/diff/ci/{seed}")), seed)
            .expect("simulated etcd backend must construct");

    let memory = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, memory_backend)
        .with_workers_and_shards(N_WORKERS, N_SHARDS);
    let sim_etcd = CoordinationSim::with_backend(seed, FaultLevel::SunnyDay, sim_etcd_backend)
        .with_workers_and_shards(N_WORKERS, N_SHARDS);

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
        let ops = generated_ops(seed);
        let mut oracle = build_oracle(seed);
        oracle.run_sequence(&ops);
    }
}
