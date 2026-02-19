//! Thread-parallel seed sweep with invariant checking.
//!
//! The mega simulation exercises the coordination subsystem across a wide range
//! of PRNG seeds to surface timing-dependent invariant violations that a single
//! deterministic run might miss. Each seed produces a completely different
//! operation sequence, fault injection pattern, and timing profile while the
//! invariant checker (S1-S7) validates every step.
//!
//! # Test structure
//!
//! Two complementary approaches sweep the seed space:
//!
//! 1. **Hand-rolled parallel sweep** ([`mega_sim_10k_steps`]) -- divides seeds
//!    across OS threads with static chunking, collects failures with
//!    reproduction commands, and asserts event-kind coverage across the
//!    aggregate. This is the primary CI gate.
//!
//! 2. **Proptest seed sweeper** ([`proptest_mega::proptest_mega_sim`]) --
//!    delegates seed generation to proptest, gaining automatic shrinking and
//!    `.proptest-regressions` file persistence. Useful for minimizing a failing
//!    seed range after the hand-rolled sweep detects a problem.
//!
//! Both tests are `#[ignore]` because they are too slow for the default
//! `cargo test` cycle (~100 seeds x 12K ops each). Run them explicitly:
//!
//! ```text
//! cargo test -p gossip-contracts mega_sim -- --ignored --nocapture
//! ```
//!
//! # Environment variables
//!
//! | Variable | Effect | Default |
//! |----------|--------|---------|
//! | `GOSSIP_SIM_SEEDS` | Number of seeds to sweep | 100 |
//! | `GOSSIP_SIM_SEED` | Single seed for failure reproduction (bypasses sweep) | -- |
//! | `GOSSIP_SIM_FAULT` | Fault level: `sunny`, `stormy`, `radioactive` | `stormy` |

use std::collections::BTreeMap;

use super::FaultLevel;
use super::harness::{CoordinationSim, SimEventKind};

/// Read `GOSSIP_SIM_SEEDS` from the environment, defaulting to 100.
///
/// Silently falls back to the default on parse errors so that an
/// accidentally empty or malformed variable does not panic.
fn parse_seed_count() -> usize {
    std::env::var("GOSSIP_SIM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100)
}

/// Read `GOSSIP_SIM_SEED` to enter single-seed reproduction mode.
///
/// When set, the mega sim skips the parallel sweep and runs only the
/// specified seed, making failure investigation fast and deterministic.
fn parse_single_seed() -> Option<u64> {
    std::env::var("GOSSIP_SIM_SEED")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Read `GOSSIP_SIM_FAULT` to override the default fault level.
///
/// Defaults to `Stormy` when unset or unrecognized, which provides a good
/// balance between fault pressure and convergence probability.
fn parse_fault_level() -> FaultLevel {
    match std::env::var("GOSSIP_SIM_FAULT")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "sunny" | "sunnyday" => FaultLevel::SunnyDay,
        "radioactive" => FaultLevel::Radioactive,
        _ => FaultLevel::Stormy,
    }
}

/// Thread-parallel seed sweep over the full coordination simulation.
///
/// Each seed runs 4 workers contending over 15 shards through 10K safety
/// ops (random operations under fault injection) followed by 2K liveness
/// ops (biased toward acquire + complete to test convergence).
///
/// # Execution model
///
/// Seeds are divided into equal-sized chunks across `available_parallelism()`
/// OS threads using `std::thread::scope`. Static chunking keeps load balanced
/// because every seed performs the same amount of work (12K ops). Each thread
/// accumulates failures and event counts locally, then the main thread merges
/// results to avoid contention.
///
/// # Assertions
///
/// 1. **Zero violations** -- any seed producing an invariant violation fails
///    the test with a reproduction command.
/// 2. **Event-kind coverage** -- the aggregate across all seeds must contain
///    the five core event kinds (AcquireOk, CheckpointOk, CompleteOk,
///    Rejected, TimeAdvanced). This catches harness regressions that silently
///    suppress entire code paths.
///
/// # Reproduction
///
/// ```text
/// GOSSIP_SIM_SEED=<seed> cargo test -p gossip-contracts mega_sim -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn mega_sim_10k_steps() {
    if cfg!(miri) {
        return;
    }

    let fault_level = parse_fault_level();

    // Single-seed repro mode.
    if let Some(seed) = parse_single_seed() {
        let report = CoordinationSim::new(seed, fault_level)
            .with_workers_and_shards(4, 15)
            .run(10_000, 2_000);
        assert!(
            report.violations.is_empty(),
            "Invariant violation at seed {seed}.\n\
             Reproduce: GOSSIP_SIM_SEED={seed} cargo test -p gossip-contracts mega_sim -- --ignored --nocapture\n\
             Violations: {:#?}",
            report.violations
        );
        return;
    }

    let seed_count = parse_seed_count();
    let parallelism = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);

    // Chunk seeds across threads.
    let seeds: Vec<u64> = (0..seed_count as u64).collect();
    let chunk_size = seeds.len().div_ceil(parallelism);

    let mut all_failures: Vec<(u64, String)> = Vec::new();
    let mut aggregate_counts: BTreeMap<SimEventKind, usize> = BTreeMap::new();

    std::thread::scope(|s| {
        let handles: Vec<_> = seeds
            .chunks(chunk_size)
            .map(|chunk| {
                let chunk = chunk.to_vec();
                let level = fault_level;
                s.spawn(move || {
                    let mut failures = Vec::new();
                    let mut local_counts: BTreeMap<SimEventKind, usize> = BTreeMap::new();

                    for seed in chunk {
                        let report = CoordinationSim::new(seed, level)
                            .with_workers_and_shards(4, 15)
                            .run(10_000, 2_000);

                        for (kind, count) in &report.event_counts {
                            *local_counts.entry(*kind).or_insert(0) += count;
                        }

                        if !report.violations.is_empty() {
                            failures.push((seed, format!("{:#?}", report.violations)));
                        }
                    }

                    (failures, local_counts)
                })
            })
            .collect();

        for handle in handles {
            let (failures, local_counts) = handle.join().expect("thread panicked");
            all_failures.extend(failures);
            for (kind, count) in local_counts {
                *aggregate_counts.entry(kind).or_insert(0) += count;
            }
        }
    });

    // Report failures with reproduction commands.
    assert!(
        all_failures.is_empty(),
        "Invariant violations in {}/{seed_count} seeds:\n{}",
        all_failures.len(),
        all_failures
            .iter()
            .map(|(seed, v)| format!(
                "  seed {seed}: {v}\n  \
                 Reproduce: GOSSIP_SIM_SEED={seed} cargo test -p gossip-contracts mega_sim -- --ignored --nocapture"
            ))
            .collect::<Vec<_>>()
            .join("\n\n")
    );

    // Coverage assertion: these five kinds represent the minimum viable
    // operation mix. If any is absent across *all* seeds, the harness has
    // a bug that suppresses an entire category of coordinator interaction.
    let required_kinds = [
        SimEventKind::AcquireOk,
        SimEventKind::CheckpointOk,
        SimEventKind::CompleteOk,
        SimEventKind::Rejected,
        SimEventKind::TimeAdvanced,
    ];
    for kind in &required_kinds {
        assert!(
            aggregate_counts.contains_key(kind),
            "event kind {kind:?} never observed across {seed_count} seeds"
        );
    }
}

// -- Proptest seed sweeper --------------------------------------------------
//
// Complements the hand-rolled sweep above by leveraging proptest's automatic
// shrinking and `.proptest-regressions` persistence. When a seed fails, proptest
// attempts to minimize it, and the failing seed is recorded to disk so it is
// replayed on every subsequent run without needing environment variables.

#[cfg(not(miri))]
mod proptest_mega {
    use super::*;
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config({
            let mut cfg = miri_proptest_config();
            cfg.cases = 100;
            cfg
        })]

        /// Proptest seed sweeper: same simulation config as [`mega_sim_10k_steps`]
        /// but with proptest-managed seed generation and regression persistence.
        #[test]
        #[ignore]
        fn proptest_mega_sim(seed in any::<u64>()) {
            let report = CoordinationSim::new(seed, FaultLevel::Stormy)
                .with_workers_and_shards(4, 15)
                .run(10_000, 2_000);
            prop_assert!(
                report.violations.is_empty(),
                "seed {}: {:#?}",
                seed,
                report.violations
            );
        }
    }
}
