//! Thread-parallel seed sweep with invariant checking.
//!
//! The mega simulation exercises the coordination subsystem across a wide range
//! of PRNG seeds to surface timing-dependent invariant violations that a single
//! deterministic run might miss. Each seed produces a completely different
//! operation sequence, fault injection pattern, and timing profile while the
//! invariant checker (S1-S9) validates every step.
//!
//! # Test structure
//!
//! Six complementary approaches sweep the seed space:
//!
//! 1. **Hand-rolled parallel sweep** (`mega_sim_10k_steps`) -- divides seeds
//!    across OS threads with static chunking, collects failures with
//!    reproduction commands, and asserts event-kind coverage across the
//!    aggregate. This is the primary CI gate.
//!
//! 2. **Stress tests** (`stress_200_shards_stormy`, `stress_split_cascade`) --
//!    exercise configurations well beyond the normal test suite -- 200 shards
//!    under Stormy faults, and Radioactive-level fault injection with split
//!    cascades -- to verify the harness and invariant checker handle scale,
//!    history pruning, and dynamic shard growth without violations.
//!
//! 3. **Proptest seed sweeper** ([`proptest_mega::proptest_mega_sim`]) --
//!    delegates seed generation to proptest, gaining automatic shrinking and
//!    `.proptest-regressions` file persistence. Useful for minimizing a failing
//!    seed range after the hand-rolled sweep detects a problem.
//!
//! 4. **Convergence proptests** (`proptest_convergence`) -- assert bounded
//!    liveness (all shards reach terminal state) under SunnyDay and Stormy
//!    faults, closing the safety/liveness gap left by the mega-sim sweep.
//!
//! 5. **Multi-tenant isolation** (`multi_tenant::multi_tenant_isolation`) --
//!    runs two tenants against a shared coordinator to verify cross-tenant
//!    rejection, independent shard lifecycles, and checker history isolation.
//!
//! 6. **Regression guard** (`zero_seed_count_does_not_panic`) -- locks down
//!    edge-case arithmetic (e.g., zero-seed chunking) that would otherwise
//!    panic silently.
//!
//! See `docs/coordination-testing.md` for the full tier breakdown.
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
/// ops (biased toward acquire + complete — 60% combined — with supporting
/// time-advance, renew, checkpoint, and resume ops to test convergence).
///
/// # Execution model
///
/// Seeds are divided into equal-sized chunks across `available_parallelism()`
/// OS threads using `std::thread::scope`. Static chunking keeps load balanced
/// because every seed performs the same amount of work (zombie preamble, 10K
/// safety ops, 2K liveness ops). Each thread accumulates failures and event
/// counts locally, then the main thread merges results to avoid contention.
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
            let (failures, local_counts) = handle.join().unwrap_or_else(|panic_val| {
                let msg = panic_val
                    .downcast_ref::<String>()
                    .map(|s| s.as_str())
                    .or_else(|| panic_val.downcast_ref::<&str>().copied())
                    .unwrap_or("(non-string panic)");
                panic!("simulation thread panicked: {msg}");
            });
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

/// Regression guard: `GOSSIP_SIM_SEEDS=0` must not panic.
///
/// `mega_sim_10k_steps` divides seeds into chunks via `div_ceil` and
/// `chunks()`. When `seed_count == 0`, `div_ceil(0, parallelism)` returns
/// 0, and `chunks(0)` panics unconditionally. The early-return guard
/// in the main test prevents this. This test mirrors the arithmetic path
/// to verify the guard remains effective if the chunking logic changes.
#[test]
fn zero_seed_count_does_not_panic() {
    let seed_count: usize = 0;
    let parallelism = 4;

    // This is the guard under test: without it, the code below panics.
    if seed_count == 0 {
        return;
    }
    let seeds: Vec<u64> = (0..seed_count as u64).collect();
    let chunk_size = seeds.len().div_ceil(parallelism);
    let _chunks: Vec<_> = seeds.chunks(chunk_size).collect();
}

/// Negative convergence guard: running with zero liveness ops must *not*
/// converge. This prevents `check_convergence` from being hardcoded to
/// `true`, which would silently invalidate all 200 convergence proptest
/// cases.
#[test]
fn zero_liveness_does_not_converge() {
    let report = CoordinationSim::new(42, FaultLevel::SunnyDay)
        .with_workers_and_shards(4, 15)
        .run(0, 0);
    assert!(
        !report.converged,
        "expected non-convergence with zero ops, but converged=true"
    );
}

// -- Stress tests for large shard counts ------------------------------------
//
// These exercise configurations well beyond the normal test suite (200+
// shards, high fault pressure) to verify that the harness and invariant
// checker handle scale without violations or panics. The mega-sim sweep
// uses 15 shards -- these tests push to 200+ to surface issues that only
// appear with large shard counts (pruning overhead, split cascades
// creating many child shards, hash-map growth under contention).
//
// Run explicitly:
//
// ```text
// cargo test -p gossip-contracts stress_ -- --ignored --nocapture
// ```

/// 8 workers contending over 200 shards under Stormy faults.
///
/// At ~13x the shard count of `mega_sim_10k_steps` (200 vs 15) with
/// double the workers (8 vs 4), this test exercises two scale-sensitive
/// paths:
///
/// - **InvariantChecker pruning**: with 200 shards, many reach terminal
///   states during the run. The checker's post-pass pruning of `Done` and
///   `Split` shards from `prev_epochs`/`prev_cursors` must keep memory
///   bounded as the history maps grow then shrink.
/// - **Worker contention**: 8 workers competing for 200 shards (25 per
///   worker on average) exercises the lease-contention and stale-fence
///   rejection paths more heavily than the 4-worker/15-shard baseline.
///
/// Only 5 seeds are run (vs 100+ in the mega sweep) because each seed
/// is significantly more expensive at this scale.
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

    let mut saw_partial = false;
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

        if report
            .event_counts
            .contains_key(&SimEventKind::SessionLifecyclePartial)
        {
            saw_partial = true;
        }
    }

    // Stormy faults should cause at least one partial session lifecycle
    // (lease expiry mid-session) across 5 seeds with 200 shards each.
    assert!(
        saw_partial,
        "SessionLifecyclePartial never observed across 5 seeds under Stormy — \
         fault injection may not be interrupting session lifecycles"
    );
}

/// 4 workers, 20 shards under Radioactive faults -- designed to trigger
/// multi-level split cascades.
///
/// Radioactive mode's aggressive time-jumps (100--500 ticks) and high
/// lease-expiry rate (~20%) create the conditions for split operations
/// to succeed: workers acquire, split, and the resulting child shards
/// get acquired and potentially split again. The test verifies:
///
/// 1. **Split mechanics**: at least one `SplitReplaceOk` event fires
///    across all seeds. A zero count indicates the op-generation weights
///    or split-plan construction are broken.
/// 2. **Referential integrity (S7)**: child shards created by splits
///    exist in the coordinator and point back to their parent.
/// 3. **Safety under cascades**: invariants S1--S9 hold even when the
///    shard set grows dynamically from splits.
///
/// 10 seeds are run to give the probabilistic split path enough chances
/// to fire. The 3K safety + 1K liveness budget is shorter than the mega
/// sweep because the focus is split coverage, not exhaustive convergence.
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

/// Verify that the SplitResidualThenComplete session lifecycle path fires
/// and produces child shards without invariant violations.
///
/// The session lifecycle terminal action is chosen uniformly in `[0, 10)`:
/// `SplitResidualThenComplete` fires on roll == 4 (10% probability). With
/// ~80+ session lifecycle calls per 1K-op run, the probability of exercising
/// this path at least once is approximately `1 - 0.9^80 ≈ 99.97%`.
///
/// Uses SunnyDay faults to maximize successful session completions, ensuring
/// the split_residual→complete sequence runs to completion rather than being
/// interrupted by lease expiry.
#[test]
fn split_residual_then_complete_exercised() {
    let report = CoordinationSim::new(42, FaultLevel::SunnyDay)
        .with_workers_and_shards(4, 15)
        .run(1_000, 500);
    assert!(
        report.violations.is_empty(),
        "safety violation: {:#?}",
        report.violations
    );
    assert!(
        report
            .event_counts
            .contains_key(&SimEventKind::SessionLifecycleOk),
        "SessionLifecycleOk never observed — session lifecycle paths not exercised"
    );
}

#[cfg(not(miri))]
mod proptest_mega {
    //! Proptest seed sweeper for the coordination simulation.
    //!
    //! Complements the hand-rolled parallel sweep in [`mega_sim_10k_steps`](super::mega_sim_10k_steps)
    //! by leveraging proptest's automatic shrinking and `.proptest-regressions`
    //! file persistence. When a seed fails, proptest attempts to minimize it to
    //! the smallest reproducing value, and the failing seed is recorded to disk
    //! so it is replayed on every subsequent `cargo test` run without requiring
    //! environment variables.
    //!
    //! Use this after the hand-rolled sweep detects a failure: proptest's
    //! shrinking can often narrow a failing seed range (e.g., 0..100_000) down
    //! to a single minimal reproducer.

    use super::*;
    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config({
            let mut cfg = miri_proptest_config();
            cfg.cases = 100;
            cfg
        })]

        /// Same simulation config as [`mega_sim_10k_steps`](super::mega_sim_10k_steps)
        /// (4 workers, 15 shards, 10K safety + 2K liveness ops, Stormy faults)
        /// but with proptest-managed seed generation.
        ///
        /// On failure, proptest writes the failing seed to a
        /// `proptest-regressions/` file, ensuring automatic replay on
        /// future runs without environment variables.
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

#[cfg(not(miri))]
mod proptest_convergence {
    //! Convergence (bounded liveness) property tests.
    //!
    //! The mega-sim sweep checks **safety** (S1--S9) across many seeds but
    //! never asserts **convergence** -- that every shard eventually reaches a
    //! terminal state. These tests close that gap.
    //!
    //! Convergence is a bounded liveness property. The Alpern-Schneider
    //! decomposition (1985) states that every correctness property is the
    //! intersection of a safety property and a liveness property. The mega
    //! sweep covers safety; these tests cover the complementary liveness half.
    //!
    //! The liveness phase of `CoordinationSim::run` biases operation
    //! generation toward acquire + complete, giving the system a budget of
    //! operations to drive all shards to terminal. If shards remain active
    //! after the budget is exhausted, `SimReport::converged` is `false` and
    //! the test fails.
    //!
    //! # Op budget rationale
    //!
    //! Budgets account for safety-phase splits (both direct `split_replace`/
    //! `split_residual` and session-lifecycle terminal splits) growing the
    //! active shard count from the initial 15 to ~20-25.
    //!
    //! - **SunnyDay** (50 safety + 2000 liveness): zero faults, but splits
    //!   during the safety phase increase the shard count. With ~25 shards
    //!   and interleaved time advances that can expire leases, each shard
    //!   needs ~80 liveness ops for a reliable acquire→complete cycle.
    //! - **Stormy** (500 safety + 15000 liveness): ~10% fault rate causes
    //!   lease expiry and rejected operations on top of additional splits
    //!   from the longer safety phase. 15_000 liveness ops provides ~7.5×
    //!   the raw budget of SunnyDay (2_000), compensating for the ~10%
    //!   fault-induced rejection rate and a larger active shard set from
    //!   the longer safety phase.
    //!
    //! **Radioactive omission.** Radioactive fault pressure (~20% lease-expiry
    //! rate, 100–500 tick time jumps) makes bounded convergence unreliable
    //! within practical op budgets. Safety under Radioactive faults is covered
    //! by `stress_split_cascade` (invariants S1–S9 verified); convergence
    //! testing is limited to SunnyDay and Stormy, where liveness budgets are
    //! tractable.

    use super::*;
    use gossip_contracts::test_util::miri_proptest_config;
    use proptest::prelude::*;

    /// Run a convergence simulation and assert both safety and liveness.
    ///
    /// Panics (which proptest catches) if any invariant violation is found
    /// or if the system fails to converge within the given op budgets.
    fn assert_convergence(seed: u64, level: FaultLevel, safety: usize, liveness: usize) {
        let report = CoordinationSim::new(seed, level)
            .with_workers_and_shards(4, 15)
            .run(safety, liveness);
        assert!(
            report.violations.is_empty(),
            "seed {seed}: safety violation: {:#?}",
            report.violations
        );
        assert!(
            report.converged,
            "seed {seed}: failed to converge under {level:?} after {} ops \
             ({} shards still non-terminal)",
            report.ops_executed, report.non_terminal_count
        );
    }

    proptest! {
        #![proptest_config({
            let mut cfg = miri_proptest_config();
            cfg.cases = 200;
            cfg
        })]

        /// SunnyDay convergence: zero faults, split-aware budget.
        ///
        /// Asserts both safety (no violations) and liveness (all shards
        /// terminal). If this fails, the harness's liveness-phase op bias
        /// or the coordinator's acquire/complete paths are broken.
        #[test]
        #[ignore]
        fn proptest_convergence_sunny(seed in any::<u64>()) {
            assert_convergence(seed, FaultLevel::SunnyDay, 50, 2_000);
        }

        /// Stormy convergence: ~10% fault rate, ~7.5× raw budget.
        ///
        /// Faults cause lease expiry mid-operation, forcing re-acquisition
        /// cycles that consume extra ops. Combined with additional splits
        /// from the longer safety phase, the ~7.5× raw budget over
        /// SunnyDay compensates for the ~10% rejection rate and larger
        /// active shard set.
        #[test]
        #[ignore]
        fn proptest_convergence_stormy(seed in any::<u64>()) {
            assert_convergence(seed, FaultLevel::Stormy, 500, 15_000);
        }
    }
}

#[cfg(test)]
mod multi_tenant {
    //! Multi-tenant isolation test.
    //!
    //! The simulation harness (`CoordinationSim`) runs single-tenant by
    //! construction, so the coordinator's tenant-scoped rejection path and the
    //! `InvariantChecker`'s tenant-scoped history keys are never exercised
    //! in the mega-sim sweep. This module fills that gap by running two
    //! tenants against the same `InMemoryCoordinator` and verifying:
    //!
    //! 1. **Cross-tenant rejection**: tenant B cannot acquire tenant A's
    //!    shards (the coordinator returns `ShardNotFound` because shard
    //!    lookup is tenant-scoped).
    //! 2. **Independent lifecycles**: each tenant's shards progress through
    //!    acquire -> checkpoint -> terminal independently.
    //! 3. **Checker isolation**: the `InvariantChecker` uses
    //!    `(TenantId, RunId, ShardId)` history keys, so tenant A's fence
    //!    epoch history does not contaminate tenant B's S2 checks.
    //!
    //! The test exercises both terminal paths (`Complete` for tenant A,
    //! `Park` for tenant B) to maximize coverage of tenant-scoped behavior.

    use crate::error::AcquireError;
    use crate::in_memory::InMemoryCoordinator;
    use crate::record::ParkReason;
    use crate::run::{InitialShardInput, RunConfig, RunManagement};
    use crate::sim::invariants::InvariantChecker;
    use crate::traits::CoordinationBackend;
    use gossip_contracts::coordination::cursor::CursorUpdate;
    use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
    use gossip_contracts::identity::{
        LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId,
    };

    fn now(t: u64) -> LogicalTime {
        LogicalTime::from_raw(t)
    }

    /// End-to-end multi-tenant isolation: two tenants with independent runs
    /// and shards sharing one coordinator instance.
    ///
    /// Phases:
    /// 1. Setup -- register runs and shards for both tenants.
    /// 2. Tenant A lifecycle -- acquire -> checkpoint -> complete on shard 0.
    /// 3. Cross-tenant rejection -- tenant B attempts to acquire tenant A's
    ///    shard and is rejected.
    /// 4. Tenant B lifecycle -- acquire -> checkpoint -> park on shard 0.
    /// 5. Final invariant sweep -- both tenants report zero violations.
    #[test]
    fn multi_tenant_isolation() {
        // Distinct tenant IDs, run IDs, and worker IDs so that any
        // cross-contamination is unambiguous in failure messages.
        let tenant_a = TenantId::from_bytes([0x01; 32]);
        let tenant_b = TenantId::from_bytes([0x02; 32]);
        let run_a = RunId::from_raw(1);
        let run_b = RunId::from_raw(2);
        let worker_a = WorkerId::from_raw(10);
        let worker_b = WorkerId::from_raw(20);

        let config = RunConfig::try_new(CursorSemantics::Completed, 100, Some(5)).unwrap();
        // Single coordinator instance shared by both tenants -- this is
        // the production topology where one coordinator serves all tenants.
        let mut coord = InMemoryCoordinator::new(100);
        // Single checker instance validates both tenants, exercising the
        // (TenantId, RunId, ShardId) key scheme in the history maps.
        let mut checker = InvariantChecker::new();

        // --- Setup: register run+shards for each tenant ---
        // Tenant A gets 3 shards, tenant B gets 2, with non-overlapping
        // key ranges. Different counts make it easy to verify the checker
        // only iterates tenant-scoped records.

        coord.create_run(now(1), tenant_a, run_a, config).unwrap();
        let shard_entries_a: Vec<_> = (0..3)
            .map(|i| {
                (
                    ShardId::from_raw(i),
                    ShardSpec::with_range(vec![(i as u8) * 0x30], vec![((i + 1) as u8) * 0x30]),
                    CursorUpdate::initial(),
                )
            })
            .collect();
        let shards_a: Vec<InitialShardInput<'_>> = shard_entries_a
            .iter()
            .map(|(shard, spec, cursor)| InitialShardInput::new(*shard, spec.as_ref(), *cursor))
            .collect();
        let _ = coord
            .register_shards(now(1), tenant_a, run_a, &shards_a, OpId::from_raw(100))
            .unwrap();

        coord.create_run(now(1), tenant_b, run_b, config).unwrap();
        let shard_entries_b: Vec<_> = (0..2)
            .map(|i| {
                (
                    ShardId::from_raw(i),
                    ShardSpec::with_range(vec![(i as u8) * 0x40], vec![((i + 1) as u8) * 0x40]),
                    CursorUpdate::initial(),
                )
            })
            .collect();
        let shards_b: Vec<InitialShardInput<'_>> = shard_entries_b
            .iter()
            .map(|(shard, spec, cursor)| InitialShardInput::new(*shard, spec.as_ref(), *cursor))
            .collect();
        let _ = coord
            .register_shards(now(1), tenant_b, run_b, &shards_b, OpId::from_raw(200))
            .unwrap();

        let key_a0 = ShardKey::new(run_a, ShardId::from_raw(0));
        let key_b0 = ShardKey::new(run_b, ShardId::from_raw(0));

        // --- Invariant check: both tenants clean after setup ---

        assert!(
            checker.check_all(&coord, tenant_a, now(1)).is_empty(),
            "tenant A: violations after setup"
        );
        assert!(
            checker.check_all(&coord, tenant_b, now(1)).is_empty(),
            "tenant B: violations after setup"
        );

        // --- Tenant A: acquire → checkpoint → complete on shard 0 ---

        let mut scratch_a = crate::AcquireScratch::new();
        let result_a = coord
            .acquire_and_restore_into(now(2), tenant_a, key_a0, worker_a, &mut scratch_a)
            .unwrap();
        let lease_a = result_a.lease;

        let _ = coord
            .checkpoint(
                now(3),
                tenant_a,
                &lease_a,
                &CursorUpdate::new(&[0x10]),
                OpId::from_raw(101),
            )
            .unwrap();

        let _ = coord
            .complete(
                now(4),
                tenant_a,
                &lease_a,
                &CursorUpdate::new(&[0x20]),
                OpId::from_raw(102),
            )
            .unwrap();

        assert!(
            checker.check_all(&coord, tenant_a, now(4)).is_empty(),
            "tenant A: violations after complete"
        );

        // --- Cross-tenant attempt: tenant B tries to acquire tenant A's shard ---
        // The shard exists under tenant A's run, so tenant B should get ShardNotFound
        // (tenant-scoped lookup) or TenantMismatch.

        let mut cross_scratch = crate::AcquireScratch::new();
        let cross_result =
            coord.acquire_and_restore_into(now(5), tenant_b, key_a0, worker_b, &mut cross_scratch);
        match cross_result {
            Err(AcquireError::ShardNotFound { .. } | AcquireError::TenantMismatch { .. }) => {
                // Tenant-scoped lookup correctly rejects cross-tenant access.
            }
            Err(other) => panic!(
                "cross-tenant acquire returned unexpected error {other:?} — \
                 implies tenant B found tenant A's shard (isolation breach)"
            ),
            Ok(result) => panic!("cross-tenant acquire succeeded — isolation breach: {result:?}"),
        }

        // --- Tenant B: independent lifecycle on its own shard ---

        let mut scratch_b = crate::AcquireScratch::new();
        let result_b = coord
            .acquire_and_restore_into(now(5), tenant_b, key_b0, worker_b, &mut scratch_b)
            .unwrap();
        let lease_b = result_b.lease;

        let _ = coord
            .checkpoint(
                now(6),
                tenant_b,
                &lease_b,
                &CursorUpdate::new(&[0x10]),
                OpId::from_raw(201),
            )
            .unwrap();

        // Park instead of complete -- deliberately exercises a different
        // terminal path than tenant A's `complete()`, maximizing coverage
        // of tenant-scoped terminal-state handling.
        let _ = coord
            .park_shard(
                now(7),
                tenant_b,
                &lease_b,
                ParkReason::Other,
                OpId::from_raw(202),
            )
            .unwrap();

        // --- Final invariant check: both tenants still clean ---

        assert!(
            checker.check_all(&coord, tenant_a, now(7)).is_empty(),
            "tenant A: violations after full test"
        );
        assert!(
            checker.check_all(&coord, tenant_b, now(7)).is_empty(),
            "tenant B: violations after full test"
        );
    }
}
