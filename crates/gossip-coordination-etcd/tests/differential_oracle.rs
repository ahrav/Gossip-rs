#![cfg(feature = "test-support")]
//! Differential oracle: `InMemoryCoordinator` vs. `SimEtcdCoordinator`.
//!
//! This is the CI-friendly mock-drift check for the coordination subsystem.
//! Both backends run entirely in memory, so the test can compare 100+ random
//! `SimOp` sequences without Docker or a live etcd server.
//!
//! Environment knobs used by this test:
//! - `GOSSIP_COORD_DIFF_SEED`: run one deterministic seed (handy for repro).
//! - `GOSSIP_COORD_DIFF_CASES`: override how many generated seeds to execute.
//!
//! On any mismatch, failures include a copy/paste repro command produced by
//! [`repro_command`], so a CI-only failure can be replayed locally verbatim.

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

/// Builds the exact `cargo test` command needed to replay a single failing seed.
///
/// The command pins the seed and uses `--exact`/`--nocapture` so local output
/// matches CI diagnostics closely.
fn repro_command(seed: u64) -> String {
    format!(
        "GOSSIP_COORD_DIFF_SEED={seed} cargo test -p gossip-coordination-etcd \
         --features test-support in_memory_matches_sim_etcd_differential_oracle \
         -- --exact --nocapture"
    )
}

/// Constructs the differential harness with aligned simulation settings.
///
/// Both coordinators use:
/// - identical seed,
/// - `FaultLevel::SunnyDay`,
/// - the same worker/shard topology from `tests/support/oracle.rs`.
///
/// This keeps comparisons focused on backend behavior rather than on test setup
/// differences.
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

/// Validates that in-memory and simulated-etcd coordinators remain behaviorally
/// equivalent across many generated operation sequences.
///
/// Seed selection is delegated to `selected_seeds_from_env`, so callers can run
/// either one targeted seed or a wider fuzz-like batch.
#[test]
fn in_memory_matches_sim_etcd_differential_oracle() {
    for seed in selected_seeds_from_env("GOSSIP_COORD_DIFF_SEED", "GOSSIP_COORD_DIFF_CASES", CASES)
    {
        let ops = oracle::generated_ops(seed);
        let mut oracle = build_oracle(seed);
        oracle.run_sequence(&ops);
    }
}
