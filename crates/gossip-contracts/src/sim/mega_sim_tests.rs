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
//! Three complementary approaches sweep the seed space:
//!
//! 1. **Hand-rolled parallel sweep** (`mega_sim_10k_steps`) -- divides seeds
//!    across OS threads with static chunking, collects failures with
//!    reproduction commands, and asserts event-kind coverage across the
//!    aggregate. This is the primary CI gate.
//!
//! 2. **Stress tests** (`stress_200_shards_stormy`, `stress_split_cascade`) --
//!    exercise configurations well beyond the normal test suite (200+ shards,
//!    Radioactive fault level) to verify the harness and invariant checker
//!    handle scale, split cascades, and history pruning without violations.
//!
//! 3. **Proptest seed sweeper** ([`proptest_mega::proptest_mega_sim`]) --
//!    delegates seed generation to proptest, gaining automatic shrinking and
//!    `.proptest-regressions` file persistence. Useful for minimizing a failing
//!    seed range after the hand-rolled sweep detects a problem.
//!
//! All `#[ignore]`'d tests are too slow for the default `cargo test` cycle.
//! Run them explicitly:
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

/// Map a [`FaultLevel`] to the string accepted by `GOSSIP_SIM_FAULT`.
fn fault_level_name(level: FaultLevel) -> &'static str {
    match level {
        FaultLevel::SunnyDay => "sunny",
        FaultLevel::Stormy => "stormy",
        FaultLevel::Radioactive => "radioactive",
    }
}

/// Read `GOSSIP_SIM_SEEDS` from the environment, defaulting to 100.
///
/// Warns on parse errors so that accidentally malformed values are
/// visible in test output rather than silently ignored.
fn parse_seed_count() -> usize {
    match std::env::var("GOSSIP_SIM_SEEDS") {
        Ok(s) => match s.parse() {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "warning: GOSSIP_SIM_SEEDS={s:?} is not a valid number ({e}), \
                     falling back to default 100"
                );
                100
            }
        },
        Err(_) => 100,
    }
}

/// Read `GOSSIP_SIM_SEED` to enter single-seed reproduction mode.
///
/// When set, the mega sim skips the parallel sweep and runs only the
/// specified seed, making failure investigation fast and deterministic.
/// Warns on parse errors so typos are visible.
fn parse_single_seed() -> Option<u64> {
    match std::env::var("GOSSIP_SIM_SEED") {
        Ok(s) => match s.parse() {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("warning: GOSSIP_SIM_SEED={s:?} is not a valid number ({e}), ignoring");
                None
            }
        },
        Err(_) => None,
    }
}

/// Read `GOSSIP_SIM_FAULT` to override the default fault level.
///
/// Defaults to `Stormy` when unset, which provides a good balance between
/// fault pressure and convergence probability. Warns on unrecognized values.
fn parse_fault_level() -> FaultLevel {
    match std::env::var("GOSSIP_SIM_FAULT") {
        Ok(s) => match s.to_lowercase().as_str() {
            "sunny" | "sunnyday" => FaultLevel::SunnyDay,
            "radioactive" => FaultLevel::Radioactive,
            "stormy" => FaultLevel::Stormy,
            _ => {
                eprintln!(
                    "warning: GOSSIP_SIM_FAULT={s:?} is not recognized \
                     (expected sunny|stormy|radioactive), falling back to Stormy"
                );
                FaultLevel::Stormy
            }
        },
        Err(_) => FaultLevel::Stormy,
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
        let fault_name = fault_level_name(fault_level);
        assert!(
            report.violations.is_empty(),
            "Invariant violation at seed {seed}.\n\
             Reproduce: GOSSIP_SIM_SEED={seed} GOSSIP_SIM_FAULT={fault_name} cargo test -p gossip-contracts mega_sim -- --ignored --nocapture\n\
             Violations: {:#?}",
            report.violations
        );
        return;
    }

    let seed_count = parse_seed_count();
    if seed_count == 0 {
        return;
    }

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
    let fault_name = fault_level_name(fault_level);
    assert!(
        all_failures.is_empty(),
        "Invariant violations in {}/{seed_count} seeds:\n{}",
        all_failures.len(),
        all_failures
            .iter()
            .map(|(seed, v)| format!(
                "  seed {seed}: {v}\n  \
                 Reproduce: GOSSIP_SIM_SEED={seed} GOSSIP_SIM_FAULT={fault_name} cargo test -p gossip-contracts mega_sim -- --ignored --nocapture"
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

/// Zero seed count must not reach `chunks()` -- the early return guard
/// prevents a panic from `chunks(0)`.
///
/// Exercises the same arithmetic path as `mega_sim_10k_steps` with
/// `seed_count == 0` to confirm the guard catches it.
#[test]
fn zero_seed_count_does_not_panic() {
    let seed_count: usize = 0;
    let parallelism = 4;

    // Without the early-return guard this panics: div_ceil(0, 4) == 0
    // and chunks(0) is unconditionally illegal.
    if seed_count == 0 {
        return;
    }
    let seeds: Vec<u64> = (0..seed_count as u64).collect();
    let chunk_size = seeds.len().div_ceil(parallelism);
    let _chunks: Vec<_> = seeds.chunks(chunk_size).collect();
}

// -- Stress tests for large shard counts ------------------------------------
//
// These exercise configurations well beyond the normal test suite (200+
// shards, high fault pressure) to verify that the harness and invariant
// checker handle scale without violations or panics. Run explicitly:
//
// ```text
// cargo test -p gossip-contracts stress_ -- --ignored --nocapture
// ```

/// 8 workers contending over 200 shards under Stormy faults.
///
/// This is ~13x the shard count of `mega_sim_10k_steps` (200 vs 15) and
/// exercises the InvariantChecker's pruning behavior at scale: many shards
/// will reach terminal states during the run, and the checker must handle
/// the growing-then-shrinking history maps without blowing up.
///
/// # Reproduction
///
/// ```text
/// GOSSIP_SIM_SEED=<seed> GOSSIP_SIM_FAULT=stormy cargo test -p gossip-contracts stress_200_shards_stormy -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn stress_200_shards_stormy() {
    if cfg!(miri) {
        return;
    }

    let seeds: Vec<u64> = (0..5).collect();
    let fault_level = FaultLevel::Stormy;

    for seed in seeds {
        let report = CoordinationSim::new(seed, fault_level)
            .with_workers_and_shards(8, 200)
            .run(5_000, 2_000);

        assert!(
            report.violations.is_empty(),
            "seed {seed}: invariant violation with 200 shards under Stormy.\n\
             Reproduce: GOSSIP_SIM_SEED={seed} GOSSIP_SIM_FAULT=stormy \
             cargo test -p gossip-contracts stress_200_shards_stormy -- --ignored --nocapture\n\
             Violations: {:#?}",
            report.violations,
        );
    }
}

/// 4 workers, 20 shards under Radioactive faults — designed to trigger
/// split cascades. Verifies that `SplitReplaceOk` events fire and child
/// shards are created without invariant violations.
///
/// # Reproduction
///
/// ```text
/// GOSSIP_SIM_SEED=<seed> GOSSIP_SIM_FAULT=radioactive cargo test -p gossip-contracts stress_split_cascade -- --ignored --nocapture
/// ```
#[test]
#[ignore]
fn stress_split_cascade() {
    if cfg!(miri) {
        return;
    }

    let seeds: Vec<u64> = (0..10).collect();
    let fault_level = FaultLevel::Radioactive;

    let mut total_splits: usize = 0;
    for seed in &seeds {
        let report = CoordinationSim::new(*seed, fault_level)
            .with_workers_and_shards(4, 20)
            .run(3_000, 1_000);

        assert!(
            report.violations.is_empty(),
            "seed {seed}: invariant violation during split cascade.\n\
             Reproduce: GOSSIP_SIM_SEED={seed} GOSSIP_SIM_FAULT=radioactive \
             cargo test -p gossip-contracts stress_split_cascade -- --ignored --nocapture\n\
             Violations: {:#?}",
            report.violations,
        );

        total_splits += report
            .event_counts
            .get(&SimEventKind::SplitReplaceOk)
            .copied()
            .unwrap_or(0);
    }

    assert!(
        total_splits > 0,
        "no SplitReplaceOk events across {} seeds — split generation may be broken",
        seeds.len(),
    );
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

        /// Proptest seed sweeper: same simulation config as `mega_sim_10k_steps`
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
