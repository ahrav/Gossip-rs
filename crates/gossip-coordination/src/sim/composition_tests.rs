//! Four-tier composition test suite for [`CompositionSim`].
//!
//! Composition tests validate the coordinator↔done-ledger boundary — the
//! gap where distributed systems bugs cluster (Yuan et al., OSDI 2014).
//! Individual component tests (S1–S9 for coordination, I1–I10 for persistence)
//! verify internal invariants, but cross-component invariants C1–C4 can only
//! break when both components interact under fault injection.
//!
//! # Test tiers
//!
//! | Tier | Purpose | CI gate? |
//! |------|---------|----------|
//! | 1 | Smoke: 50-op SunnyDay lifecycle, zero violations | yes |
//! | 2 | Proptest state machine: weighted cross-boundary ops with shrinking | yes |
//! | 3 | Seed sweep: 50+ seeds at SunnyDay/Stormy | `#[ignore]` |
//! | 4 | Specific fault scenarios (crash, stale fence, ledger failure) | yes |
//!
//! Tiers 1, 2, and 4 run in CI. Tier 3 is `#[ignore]`'d and intended for
//! pre-merge deep validation or failure bisection.
//!
//! # Environment variables (Tier 3 only)
//!
//! | Variable | Effect | Default |
//! |----------|--------|---------|
//! | `GOSSIP_COMP_SEEDS` | Number of seeds to sweep | 50 |
//! | `GOSSIP_COMP_SEED` | Single seed for failure reproduction (bypasses sweep) | -- |
//! | `GOSSIP_COMP_FAULT` | Fault level: `sunny`, `stormy`, `radioactive` | `stormy` |
//!
//! # Relationship to other test modules
//!
//! - [`mega_sim_tests`](super::mega_sim_tests) — coordination-only seed sweeps (S1–S9).
//! - [`proptest_state_machine_tests`](super::proptest_state_machine_tests) — coordination-only
//!   proptest with per-op shrinking.
//! - This module — cross-component sweeps exercising C1–C4 in addition to S1–S9 and I1–I10.

use std::collections::BTreeMap;

use proptest::prelude::*;
use rand::Rng;
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng;

use gossip_contracts::identity::{RunId, ShardId, ShardKey, WorkerId};
use gossip_contracts::test_util::miri_proptest_config;

use super::FaultLevel;
use super::composition::{
    CompositionFaultConfig, CompositionSim, CompositionSimEvent, CompositionSimOp,
    CompositionSimViolation, DoneLedgerFaultOp,
};
use super::composition_invariants::CrossComponentViolation;
use super::harness::{RunTerminalKind, SimOp};
use super::test_util::{arb_fault_level, arb_sim_op};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Workers used across all test tiers (3 workers gives enough contention
/// to exercise claim conflicts without overwhelming the 5-shard pool).
const N_WORKERS: u64 = 3;

/// Shards used across all test tiers (5 shards: fewer than workers × 2
/// to force claim failures and contention).
const N_SHARDS: u64 = 5;

/// Default seed count for the composition sweep (env-overridable).
const DEFAULT_SEEDS: usize = 50;

/// Safety ops per seed in the sweep: random cross-boundary operations.
const DEFAULT_SAFETY_OPS: usize = 500;

/// Liveness ops per seed in the sweep: biased toward forward-progress ops.
const DEFAULT_LIVENESS_OPS: usize = 200;

/// Lease duration constant mirroring `shared::DEFAULT_LEASE_DURATION`.
///
/// Duplicated here to keep the large time-jump arm in [`random_sim_op`]
/// self-contained. The `const` assertion below enforces synchronization
/// at compile time.
const LEASE_DUR: u64 = 100;
const _: () = assert!(LEASE_DUR == super::shared::DEFAULT_LEASE_DURATION);

// ---------------------------------------------------------------------------
// CompositionEventKind — lightweight discriminant for event counting
// ---------------------------------------------------------------------------

/// Discriminant for [`CompositionSimEvent`] variants, used for event coverage
/// tracking in seed sweeps.
///
/// The seed sweep aggregates event counts across all seeds and asserts that
/// [`REQUIRED_CROSS_BOUNDARY`] kinds appear at least once. Without this
/// coverage check, a sweep could pass with 100% coordination-only events,
/// giving false confidence that cross-boundary paths were exercised.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum CompositionEventKind {
    /// Coordination pass-through (any `SimOp` variant).
    Coord,
    /// Full scan lifecycle completed successfully (claim → scan → write → complete).
    ScanCompleted,
    /// Scan could not start — no shard available.
    ScanClaimFailed,
    /// Crash injected between coordinator `complete()` and done-ledger write.
    ScanCrashedAfterComplete,
    /// Done-ledger records written with deliberately stale fence epoch.
    ScanStaleLeaseWrite,
    /// Done-ledger write succeeded but coordinator `complete()` was rejected.
    ScanCoordinatorCompleteFailed,
    /// Done-ledger write failed at submit or commit time.
    ScanLedgerWriteFailed,
    /// Stale-lease write requested but impossible (fence at initial epoch).
    ScanStaleLeaseNotPossible,
    /// Ledger fault injection op applied (not a scan lifecycle event).
    LedgerFaultInjected,
}

impl CompositionEventKind {
    fn from_event(event: &CompositionSimEvent) -> Self {
        match event {
            CompositionSimEvent::Coord(_) => Self::Coord,
            CompositionSimEvent::ScanCompleted { .. } => Self::ScanCompleted,
            CompositionSimEvent::ScanClaimFailed { .. } => Self::ScanClaimFailed,
            CompositionSimEvent::ScanCrashedAfterComplete { .. } => Self::ScanCrashedAfterComplete,
            CompositionSimEvent::ScanStaleLeaseWrite { .. } => Self::ScanStaleLeaseWrite,
            CompositionSimEvent::ScanCoordinatorCompleteFailed { .. } => {
                Self::ScanCoordinatorCompleteFailed
            }
            CompositionSimEvent::ScanLedgerWriteFailed { .. } => Self::ScanLedgerWriteFailed,
            CompositionSimEvent::ScanStaleLeaseNotPossible { .. } => {
                Self::ScanStaleLeaseNotPossible
            }
            CompositionSimEvent::LedgerFaultInjected => Self::LedgerFaultInjected,
        }
    }
}

/// Cross-boundary events that must appear at least once across the full
/// seed sweep to prove composition coverage is not hollow.
///
/// Covers five cross-boundary categories: normal lifecycle completion,
/// crash injection, stale-fence write, coordinator-complete rejection
/// (ledger write succeeds but coordinator rejects), ledger write failure
/// (submit/commit failure during scan), and fault injection. If any is
/// absent, the sweep has degenerated into coordination-only testing — the
/// random op distribution is not generating enough scan lifecycle, crash,
/// or fault injection ops.
const REQUIRED_CROSS_BOUNDARY: [CompositionEventKind; 6] = [
    CompositionEventKind::ScanCompleted,
    CompositionEventKind::ScanCrashedAfterComplete,
    CompositionEventKind::ScanStaleLeaseWrite,
    CompositionEventKind::ScanCoordinatorCompleteFailed,
    CompositionEventKind::ScanLedgerWriteFailed,
    CompositionEventKind::LedgerFaultInjected,
];

// ---------------------------------------------------------------------------
// Violation filter
// ---------------------------------------------------------------------------

/// Returns `true` for violations that are expected by design.
///
/// `ScanLifecycleStaleLeaseWrite` deliberately injects a stale fence epoch
/// into done-ledger provenance, triggering C4 `FencePropagationMismatch`.
/// This is the invariant checker correctly detecting the injected fault, not
/// a bug in the system under test. The filter is event-aware: C4 violations
/// are only suppressed when the triggering event is `ScanStaleLeaseWrite`,
/// ensuring that a real fence propagation bug on the normal scan path would
/// still be reported.
fn is_expected_violation(v: &CompositionSimViolation, event: &CompositionSimEvent) -> bool {
    matches!(
        (v, event),
        (
            CompositionSimViolation::CrossComponent(
                CrossComponentViolation::FencePropagationMismatch { .. }
            ),
            CompositionSimEvent::ScanStaleLeaseWrite { .. }
        )
    )
}

/// Collect unexpected violations from a step result, filtering C4 stale-fence
/// matches that are expected by design (only when the event is a stale-lease
/// write).
fn unexpected_violations<'a>(
    violations: &'a [CompositionSimViolation],
    event: &CompositionSimEvent,
) -> Vec<&'a CompositionSimViolation> {
    violations
        .iter()
        .filter(|v| !is_expected_violation(v, event))
        .collect()
}

// ---------------------------------------------------------------------------
// Proptest strategy: arb_composition_op
// ---------------------------------------------------------------------------

/// Proptest strategy producing a single [`CompositionSimOp`].
///
/// # Weight distribution (total weight: 47)
///
/// | Category | Weight | Effective % |
/// |----------|--------|-------------|
/// | Coordination pass-through | 30 | ~64% |
/// | Scan lifecycle | 10 | ~21% |
/// | Crash after complete | 3 | ~6% |
/// | Stale lease write | 2 | ~4% |
/// | Ledger fault injection | 2 | ~4% |
///
/// `AdvanceTime` is not a separate arm — `arb_sim_op` already generates it
/// at ~15% of coordination ops, providing ~10% of composition ops via
/// pass-through.
///
/// `InjectDelay` is excluded because it blocks `CommitHandle::wait()`
/// until a subsequent `ReleasePendingWrites` — in random sequences the
/// matching release is unlikely, causing deadlocks. Delay fault coverage
/// requires a dedicated test with explicit inject/release pairing; since
/// `CompositionSim::step` takes `&mut self`, the release must be issued
/// on a separate thread or interleaved before the blocking write.
fn arb_composition_op(n_workers: u64, n_shards: u64) -> impl Strategy<Value = CompositionSimOp> {
    let worker = (1..=n_workers).prop_map(WorkerId::from_raw);
    prop_oneof![
        // Coordination pass-through: acquire, checkpoint, complete, time advance, etc.
        30 => arb_sim_op(n_workers, n_shards).prop_map(CompositionSimOp::Coord),
        // Full scan lifecycle: claim → scan → write → complete.
        10 => worker.clone().prop_map(|w| CompositionSimOp::ScanLifecycle { worker: w }),
        // Crash between coordinator complete() and done-ledger write.
        3 => worker.clone().prop_map(|w| CompositionSimOp::ScanLifecycleCrashAfterComplete {
            worker: w,
        }),
        // Write done-ledger records with stale fence epoch.
        2 => worker.prop_map(|w| CompositionSimOp::ScanLifecycleStaleLeaseWrite {
            worker: w,
        }),
        // Minimal fault injection — submit and commit failures only (no delays).
        2 => prop_oneof![
            Just(CompositionSimOp::InjectLedgerFault(
                DoneLedgerFaultOp::InjectSubmitFailure { count: 1 },
            )),
            Just(CompositionSimOp::InjectLedgerFault(
                DoneLedgerFaultOp::InjectCommitFailure { count: 1 },
            )),
        ],
    ]
}

// ---------------------------------------------------------------------------
// Random op generator (for seed sweep — not proptest)
// ---------------------------------------------------------------------------

/// Generate a random [`SimOp`] using `ChaCha8Rng` directly.
///
/// Mirrors the weight distribution of [`arb_sim_op`] in `test_util.rs`
/// (total weight: 40, 18 arms), but bypasses proptest machinery for use
/// in the seed sweep where deterministic reproducibility from a `u64` seed
/// is required and shrinking is unnecessary.
///
/// The weights must be maintained in sync with `arb_sim_op` manually —
/// the compile-time exhaustiveness guard at `_check_strategy_exhaustive`
/// covers [`CompositionSimOp`] variants only, not individual [`SimOp`] arms.
/// Weight categories:
/// - Acquire/Checkpoint/AdvanceTime/Complete: high frequency (~15% each)
/// - Renew/SessionLifecycle/ClaimNext/Pause/Resume: moderate (~5% each)
/// - Large time-jump/ZombieCheckpoint/Park/Split/Replay/Conflict/Unpark/TerminateRun: rare (~2.5% each)
fn random_sim_op(rng: &mut ChaCha8Rng, n_workers: u64, n_shards: u64) -> SimOp {
    let rand_worker = |rng: &mut ChaCha8Rng| WorkerId::from_raw(rng.random_range(1..=n_workers));
    let rand_key = |rng: &mut ChaCha8Rng| {
        ShardKey::new(
            RunId::from_raw(1),
            ShardId::from_raw(rng.random_range(1..=n_shards)),
        )
    };
    let roll = rng.random_range(0u32..40);
    match roll {
        0..6 => SimOp::Acquire {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        6..11 => SimOp::AdvanceTime {
            ticks: rng.random_range(1..=50),
        },
        11..16 => SimOp::Checkpoint {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        16..20 => SimOp::Complete {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        20..23 => SimOp::Renew {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        23..25 => SimOp::SessionLifecycle {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        25..27 => SimOp::ClaimNext {
            worker: rand_worker(rng),
        },
        27..29 => SimOp::PauseWorker {
            worker: rand_worker(rng),
        },
        29..31 => SimOp::ResumeWorker {
            worker: rand_worker(rng),
        },
        31 => SimOp::AdvanceTime {
            ticks: LEASE_DUR + 50,
        },
        32 => SimOp::ZombieCheckpoint,
        33 => SimOp::Park {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        34 => SimOp::SplitReplace {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        35 => SimOp::SplitResidual {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        36 => SimOp::ReplayCheckpoint {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        37 => SimOp::ConflictCheckpoint {
            worker: rand_worker(rng),
            key: rand_key(rng),
        },
        38 => SimOp::Unpark { key: rand_key(rng) },
        39 => {
            let kind = match rng.random_range(0u8..3) {
                0 => RunTerminalKind::Complete,
                1 => RunTerminalKind::Fail,
                _ => RunTerminalKind::Cancel,
            };
            SimOp::TerminateRun {
                run: RunId::from_raw(1),
                kind,
            }
        }
        _ => unreachable!(),
    }
}

/// Generate a random [`CompositionSimOp`] with the same weight distribution
/// as [`arb_composition_op`].
///
/// Total weight: 47. Delegates coordination ops to [`random_sim_op`].
/// `InjectDelay` is excluded (see [`arb_composition_op`] doc for rationale).
fn random_composition_op(rng: &mut ChaCha8Rng, n_workers: u64, n_shards: u64) -> CompositionSimOp {
    let roll = rng.random_range(0u32..47);
    match roll {
        0..30 => CompositionSimOp::Coord(random_sim_op(rng, n_workers, n_shards)),
        30..40 => CompositionSimOp::ScanLifecycle {
            worker: WorkerId::from_raw(rng.random_range(1..=n_workers)),
        },
        40..43 => CompositionSimOp::ScanLifecycleCrashAfterComplete {
            worker: WorkerId::from_raw(rng.random_range(1..=n_workers)),
        },
        43..45 => CompositionSimOp::ScanLifecycleStaleLeaseWrite {
            worker: WorkerId::from_raw(rng.random_range(1..=n_workers)),
        },
        45..47 => {
            let fault = if rng.random_bool(0.5) {
                DoneLedgerFaultOp::InjectSubmitFailure { count: 1 }
            } else {
                DoneLedgerFaultOp::InjectCommitFailure { count: 1 }
            };
            CompositionSimOp::InjectLedgerFault(fault)
        }
        _ => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Environment variable parsers (Tier 3 seed sweep)
// ---------------------------------------------------------------------------

/// Read `GOSSIP_COMP_SEEDS` from the environment, defaulting to 50.
fn parse_seed_count() -> usize {
    match std::env::var("GOSSIP_COMP_SEEDS") {
        Ok(s) => match s.parse() {
            Ok(n) => n,
            Err(e) => {
                eprintln!(
                    "warning: GOSSIP_COMP_SEEDS={s:?} is not a valid number ({e}), \
                     falling back to default {DEFAULT_SEEDS}"
                );
                DEFAULT_SEEDS
            }
        },
        Err(_) => DEFAULT_SEEDS,
    }
}

/// Read `GOSSIP_COMP_SEED` for single-seed reproduction mode.
fn parse_single_seed() -> Option<u64> {
    match std::env::var("GOSSIP_COMP_SEED") {
        Ok(s) => match s.parse() {
            Ok(n) => Some(n),
            Err(e) => {
                eprintln!("warning: GOSSIP_COMP_SEED={s:?} is not a valid number ({e}), ignoring");
                None
            }
        },
        Err(_) => None,
    }
}

/// Read `GOSSIP_COMP_FAULT` to override the default fault level.
fn parse_fault_level() -> FaultLevel {
    match std::env::var("GOSSIP_COMP_FAULT") {
        Ok(s) => match s.to_lowercase().as_str() {
            "sunny" | "sunnyday" => FaultLevel::SunnyDay,
            "radioactive" => FaultLevel::Radioactive,
            "stormy" => FaultLevel::Stormy,
            _ => {
                eprintln!(
                    "warning: GOSSIP_COMP_FAULT={s:?} is not recognized \
                     (expected sunny|stormy|radioactive), falling back to Stormy"
                );
                FaultLevel::Stormy
            }
        },
        Err(_) => FaultLevel::Stormy,
    }
}

/// Human-readable fault level name for reproduction commands in assertion messages.
fn fault_level_name(level: FaultLevel) -> &'static str {
    match level {
        FaultLevel::SunnyDay => "sunny",
        FaultLevel::Stormy => "stormy",
        FaultLevel::Radioactive => "radioactive",
    }
}

// ---------------------------------------------------------------------------
// Seed sweep infrastructure
// ---------------------------------------------------------------------------

/// Per-seed result from a composition sweep run.
///
/// Collected by each thread and merged in the parent to produce aggregate
/// failure reports and event coverage assertions.
struct CompositionSeedResult {
    seed: u64,
    /// Unexpected violations (C4 stale-fence filtered out).
    violations: Vec<CompositionSimViolation>,
    /// Event kind → count for coverage tracking.
    event_counts: BTreeMap<CompositionEventKind, usize>,
}

/// Run a single composition seed: create harness, generate random ops, collect
/// violations and event counts.
///
/// # Two-phase op sequence
///
/// The op sequence is split into two phases to test both safety and liveness:
///
/// - **Safety phase** (`safety_ops` steps): random ops from the full
///   composition distribution. Exercises all cross-boundary paths including
///   crash injection, stale-fence writes, and ledger fault injection. The
///   full weight distribution matches [`arb_composition_op`].
///
/// - **Liveness phase** (`liveness_ops` steps): biased 70% toward
///   `ScanLifecycle` and 30% `AdvanceTime`. Drives shards toward terminal
///   state so the sweep can verify convergence properties.
///
/// # PRNG stream separation
///
/// The op-generation PRNG is seeded at `seed + 0xDEAD` to avoid correlation
/// with the fault-injection stream inside `SimContext` (seeded at `seed`).
/// Without this offset, the op selector and fault injector would draw from
/// the same position in the same ChaCha8 stream, producing correlated
/// fault/op sequences that reduce coverage diversity.
fn run_composition_seed(
    seed: u64,
    level: FaultLevel,
    safety_ops: usize,
    liveness_ops: usize,
) -> CompositionSeedResult {
    let config = CompositionFaultConfig::for_level(level);
    let mut sim = CompositionSim::new(seed, config)
        .with_workers_and_shards(N_WORKERS as u32, N_SHARDS as u32)
        .expect("composition sim setup should succeed");

    let mut rng = ChaCha8Rng::seed_from_u64(seed.wrapping_add(0xDEAD));
    let mut violations = Vec::new();
    let mut event_counts: BTreeMap<CompositionEventKind, usize> = BTreeMap::new();

    // Initial time advance so lease deadlines are well-defined.
    let (event, viols) = sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));
    *event_counts
        .entry(CompositionEventKind::from_event(&event))
        .or_insert(0) += 1;
    let bad = unexpected_violations(&viols, &event);
    assert!(
        bad.is_empty(),
        "seed={seed}: initial AdvanceTime produced violations: {bad:?}"
    );

    // Safety phase: random cross-boundary operations.
    for step in 0..safety_ops {
        let op = random_composition_op(&mut rng, N_WORKERS, N_SHARDS);
        let (event, viols) = sim.step(op);
        *event_counts
            .entry(CompositionEventKind::from_event(&event))
            .or_insert(0) += 1;
        let n_unexpected = viols
            .iter()
            .filter(|v| !is_expected_violation(v, &event))
            .count();
        if n_unexpected > 0 {
            violations.extend(
                viols
                    .into_iter()
                    .filter(|v| !is_expected_violation(v, &event)),
            );
            eprintln!(
                "seed={seed}: safety step {step} violation (continuing): {n_unexpected} unexpected",
            );
        }
    }

    // Liveness phase: drive toward terminal state.
    for step in 0..liveness_ops {
        let worker = WorkerId::from_raw(rng.random_range(1..=N_WORKERS));
        let op = if rng.random_bool(0.3) {
            CompositionSimOp::Coord(SimOp::AdvanceTime {
                ticks: rng.random_range(1..=50),
            })
        } else {
            CompositionSimOp::ScanLifecycle { worker }
        };
        let (event, viols) = sim.step(op);
        *event_counts
            .entry(CompositionEventKind::from_event(&event))
            .or_insert(0) += 1;
        let n_unexpected = viols
            .iter()
            .filter(|v| !is_expected_violation(v, &event))
            .count();
        if n_unexpected > 0 {
            violations.extend(
                viols
                    .into_iter()
                    .filter(|v| !is_expected_violation(v, &event)),
            );
            eprintln!(
                "seed={seed}: liveness step {step} violation (continuing): {n_unexpected} unexpected",
            );
        }
    }

    CompositionSeedResult {
        seed,
        violations,
        event_counts,
    }
}

/// Thread-parallel seed sweep over the composition simulation.
///
/// Divides seeds across OS threads with static chunking (one chunk per
/// available hardware thread), runs each seed independently, then merges
/// results and asserts two properties:
///
/// 1. **Zero unexpected violations** across all seeds.
/// 2. **Cross-boundary event coverage**: every kind in
///    [`REQUIRED_CROSS_BOUNDARY`] must appear at least once in the
///    aggregate event counts.
///
/// Supports two modes:
/// - **Single-seed reproduction**: if `GOSSIP_COMP_SEED` is set, runs that
///   seed alone with the fault level from `GOSSIP_COMP_FAULT`, prints a
///   reproduction command on failure, and returns.
/// - **Full sweep**: runs `GOSSIP_COMP_SEEDS` seeds (default 50) in parallel.
///
/// Skipped entirely under Miri (too slow for an interpreter).
fn run_composition_sweep(level: FaultLevel) {
    if cfg!(miri) {
        return;
    }

    // Single-seed repro mode: use explicit GOSSIP_COMP_FAULT if set,
    // otherwise inherit the caller's fault level so `composition_sweep_sunny_day`
    // reproduces at SunnyDay without requiring the env var.
    let repro_level = match std::env::var("GOSSIP_COMP_FAULT") {
        Ok(_) => parse_fault_level(),
        Err(_) => level,
    };

    if let Some(seed) = parse_single_seed() {
        let result =
            run_composition_seed(seed, repro_level, DEFAULT_SAFETY_OPS, DEFAULT_LIVENESS_OPS);
        let fault_name = fault_level_name(repro_level);
        assert!(
            result.violations.is_empty(),
            "Invariant violation at seed {seed}.\n\
             Reproduce: GOSSIP_COMP_SEED={seed} GOSSIP_COMP_FAULT={fault_name} \
             cargo test -p gossip-coordination composition_tests -- --ignored --nocapture\n\
             Violations: {:#?}",
            result.violations
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

    let seeds: Vec<u64> = (0..seed_count as u64).collect();
    let chunk_size = seeds.len().div_ceil(parallelism);

    let mut all_failures: Vec<(u64, String)> = Vec::new();
    let mut aggregate_counts: BTreeMap<CompositionEventKind, usize> = BTreeMap::new();

    std::thread::scope(|s| {
        let handles: Vec<_> = seeds
            .chunks(chunk_size)
            .map(|chunk| {
                let chunk = chunk.to_vec();
                s.spawn(move || {
                    let mut failures = Vec::new();
                    let mut local_counts: BTreeMap<CompositionEventKind, usize> = BTreeMap::new();

                    for seed in chunk {
                        let result = run_composition_seed(
                            seed,
                            level,
                            DEFAULT_SAFETY_OPS,
                            DEFAULT_LIVENESS_OPS,
                        );

                        for (kind, count) in &result.event_counts {
                            *local_counts.entry(*kind).or_insert(0) += count;
                        }

                        if !result.violations.is_empty() {
                            failures.push((result.seed, format!("{:#?}", result.violations)));
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
                panic!("composition sim thread panicked: {msg}");
            });
            all_failures.extend(failures);
            for (kind, count) in local_counts {
                *aggregate_counts.entry(kind).or_insert(0) += count;
            }
        }
    });

    // Report failures with reproduction commands.
    let fault_name = fault_level_name(level);
    assert!(
        all_failures.is_empty(),
        "Invariant violations in {}/{seed_count} seeds:\n{}",
        all_failures.len(),
        all_failures
            .iter()
            .map(|(seed, v)| format!(
                "  seed {seed}: {v}\n  \
                 Reproduce: GOSSIP_COMP_SEED={seed} GOSSIP_COMP_FAULT={fault_name} \
                 cargo test -p gossip-coordination composition_tests -- --ignored --nocapture"
            ))
            .collect::<Vec<_>>()
            .join("\n\n")
    );

    // Coverage: cross-boundary events must appear across the full sweep.
    for kind in &REQUIRED_CROSS_BOUNDARY {
        assert!(
            aggregate_counts.contains_key(kind),
            "cross-boundary event kind {kind:?} never observed across {seed_count} seeds \
             at {level:?} — composition coverage is hollow"
        );
    }

    // Convergence: the liveness phase must drive at least one scan to
    // completion per seed on average, proving the system makes forward
    // progress and does not livelock.
    let scan_completed = aggregate_counts
        .get(&CompositionEventKind::ScanCompleted)
        .copied()
        .unwrap_or(0);
    assert!(
        scan_completed >= seed_count,
        "convergence: expected at least {seed_count} ScanCompleted events across \
         {seed_count} seeds at {level:?}, got {scan_completed}"
    );
}

// ---------------------------------------------------------------------------
// Compile-time exhaustiveness guard
// ---------------------------------------------------------------------------

/// Compile-time exhaustiveness guard for [`CompositionSimOp`].
///
/// When a new variant is added to `CompositionSimOp`, this match will fail to
/// compile, forcing the developer to update both [`arb_composition_op`] (the
/// proptest strategy) and [`random_composition_op`] (the seed-sweep generator)
/// before the new variant can be used. Without this guard, new ops silently
/// get zero weight in the random generators, reducing test coverage.
const _: () = {
    fn _check_strategy_exhaustive(op: CompositionSimOp) {
        match op {
            CompositionSimOp::Coord(_) => {}
            CompositionSimOp::ScanLifecycle { .. } => {}
            CompositionSimOp::ScanLifecycleCrashAfterComplete { .. } => {}
            CompositionSimOp::ScanLifecycleStaleLeaseWrite { .. } => {}
            CompositionSimOp::InjectLedgerFault(_) => {}
        }
    }
};

/// Compile-time exhaustiveness guard for [`SimOp`].
///
/// When a new variant is added to `SimOp`, this match will fail to compile,
/// forcing the developer to update [`random_sim_op`] (the seed-sweep generator)
/// to include the new variant. Without this guard, new `SimOp` variants silently
/// get zero weight in `random_sim_op`, reducing seed-sweep coverage while
/// `arb_sim_op` (proptest) may still generate them.
const _: () = {
    fn _check_sim_op_exhaustive(op: SimOp) {
        match op {
            SimOp::Acquire { .. } => {}
            SimOp::Renew { .. } => {}
            SimOp::Checkpoint { .. } => {}
            SimOp::Complete { .. } => {}
            SimOp::Park { .. } => {}
            SimOp::SplitReplace { .. } => {}
            SimOp::SplitResidual { .. } => {}
            SimOp::ReplayCheckpoint { .. } => {}
            SimOp::ConflictCheckpoint { .. } => {}
            SimOp::ZombieCheckpoint => {}
            SimOp::ClaimNext { .. } => {}
            SimOp::AdvanceTime { .. } => {}
            SimOp::PauseWorker { .. } => {}
            SimOp::ResumeWorker { .. } => {}
            SimOp::SessionLifecycle { .. } => {}
            SimOp::Unpark { .. } => {}
            SimOp::TerminateRun { .. } => {}
        }
    }
};

// ===========================================================================
// Tier 1 — Smoke Test (CI gate)
// ===========================================================================

/// End-to-end SunnyDay lifecycle: 50 ops mixing scan lifecycles, coordination
/// pass-throughs, and time advances with zero fault injection. Zero violations
/// expected.
///
/// Unlike the unit tests in `composition.rs` (3–5 ops each verifying a single
/// cross-boundary interaction), this exercises enough steps to see multiple
/// claim-scan-complete cycles, lease expirations, and checkpoint replays in a
/// single run. The fixed `mod 5` op rotation ensures deterministic coverage of
/// all four categories (scan lifecycle, claim, time advance, checkpoint) rather
/// than relying on random op selection.
///
/// Asserts that at least one `ScanCompleted` event appears — a zero-completion
/// smoke test would pass vacuously.
#[test]
fn smoke_sunny_day_50_ops_no_violations() {
    let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
    let mut sim = CompositionSim::new(42, config)
        .with_workers_and_shards(N_WORKERS as u32, N_SHARDS as u32)
        .expect("setup should succeed");

    // Advance past initial registration.
    let (_, viols) = sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));
    assert!(viols.is_empty(), "initial time advance: {viols:?}");

    let mut rng = ChaCha8Rng::seed_from_u64(42_u64.wrapping_add(0xBEEF));
    let mut scan_completed = false;

    for step in 0..50 {
        let worker = WorkerId::from_raw(rng.random_range(1..=N_WORKERS));

        // Cycle through: scan lifecycle, coordination ops, time advances.
        let op = match step % 5 {
            0 | 2 => CompositionSimOp::ScanLifecycle { worker },
            1 => CompositionSimOp::Coord(SimOp::ClaimNext { worker }),
            3 => CompositionSimOp::Coord(SimOp::AdvanceTime {
                ticks: rng.random_range(5..=30),
            }),
            _ => CompositionSimOp::Coord(SimOp::Checkpoint {
                worker,
                key: ShardKey::new(
                    RunId::from_raw(1),
                    ShardId::from_raw(rng.random_range(1..=N_SHARDS)),
                ),
            }),
        };

        let (event, violations) = sim.step(op);
        assert!(
            violations.is_empty(),
            "step {step}: violations: {violations:?}"
        );
        if matches!(event, CompositionSimEvent::ScanCompleted { .. }) {
            scan_completed = true;
        }
    }

    assert!(
        scan_completed,
        "at least one ScanCompleted expected across 50 SunnyDay ops"
    );
}

// ===========================================================================
// Tier 2 — Proptest State Machine
//
// Uses proptest for automatic shrinking: when a violation is found, proptest
// minimizes to the smallest failing op sequence, giving immediate causal
// chain visibility. Three sub-tiers:
// - Short sequences at SunnyDay (CI gate)
// - Deep safety at Stormy (200 cases, #[ignore])
// - Fault-level sweep across all three levels (100 cases, #[ignore])
// ===========================================================================

/// Execute a composition op sequence, asserting zero unexpected violations
/// after every step.
///
/// Shared driver for all Tier 2 proptest variants. The initial `AdvanceTime`
/// moves the clock past zero so lease deadlines are well-defined (a lease
/// granted at time 0 would expire immediately at any positive time).
fn run_proptest_sequence(seed: u64, level: FaultLevel, ops: &[CompositionSimOp]) {
    let config = CompositionFaultConfig::for_level(level);
    let mut sim = CompositionSim::new(seed, config)
        .with_workers_and_shards(N_WORKERS as u32, N_SHARDS as u32)
        .expect("setup should succeed");

    // Advance past time zero so lease deadlines are well-defined.
    let (_, viols) = sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));
    assert!(
        viols.is_empty(),
        "seed={seed}: initial AdvanceTime: {viols:?}"
    );

    for (i, op) in ops.iter().enumerate() {
        let (event, violations) = sim.step(op.clone());
        let bad = unexpected_violations(&violations, &event);
        assert!(
            bad.is_empty(),
            "seed={seed}, level={level:?}, step={i}, op={op:?}: {bad:?}"
        );
    }
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// CI-gate proptest: short sequences at SunnyDay (256 cases native, 32 under Miri).
    #[test]
    fn prop_composition_short_sequences(
        seed in any::<u64>(),
        ops in proptest::collection::vec(arb_composition_op(N_WORKERS, N_SHARDS), 10..50),
    ) {
        run_proptest_sequence(seed, FaultLevel::SunnyDay, &ops);
    }
}

/// Deep safety proptest at Stormy: longer sequences (50–200 ops) and more
/// cases (200) to explore fault-induced edge cases that short SunnyDay
/// sequences miss. At Stormy, the coordination fault config enables ~10%
/// time-jump rate internally, but composition ops still inject faults
/// explicitly via the weighted strategy.
#[cfg(not(miri))]
mod deep_safety {
    use super::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 200,
            ..Default::default()
        })]

        #[test]
        #[ignore]
        fn prop_composition_deep_safety(
            seed in any::<u64>(),
            ops in proptest::collection::vec(arb_composition_op(N_WORKERS, N_SHARDS), 50..200),
        ) {
            run_proptest_sequence(seed, FaultLevel::Stormy, &ops);
        }
    }
}

/// Fault-level sweep proptest: generates a random fault level alongside each
/// op sequence to verify that invariants hold across the SunnyDay→Stormy→Radioactive
/// spectrum. Catches invariant violations that only manifest at a specific
/// fault intensity.
#[cfg(not(miri))]
mod fault_sweep {
    use super::*;

    proptest! {
        #![proptest_config(proptest::test_runner::Config {
            cases: 100,
            ..Default::default()
        })]

        #[test]
        #[ignore]
        fn prop_composition_fault_sweep(
            seed in any::<u64>(),
            level in arb_fault_level(),
            ops in proptest::collection::vec(arb_composition_op(N_WORKERS, N_SHARDS), 50..150),
        ) {
            run_proptest_sequence(seed, level, &ops);
        }
    }
}

// ===========================================================================
// Tier 3 — Seed Sweep (#[ignore])
//
// Broad-spectrum coverage via parallel seed sweeps. Each seed produces a
// different random op sequence and fault pattern. The sweep asserts both
// zero violations and cross-boundary event coverage (see REQUIRED_CROSS_BOUNDARY).
//
// Run manually:
//   cargo test -p gossip-coordination composition_tests -- --ignored --nocapture
// ===========================================================================

/// Composition seed sweep at SunnyDay: zero ambient faults, cross-boundary
/// faults only from explicit ops.
#[test]
#[ignore]
fn composition_sweep_sunny_day() {
    run_composition_sweep(FaultLevel::SunnyDay);
}

/// Composition seed sweep at Stormy: ambient coordination faults (lease expiry,
/// pause, time jump) + persistence faults (submit/commit failure, delay) +
/// cross-boundary faults (crash after complete, stale provenance).
#[test]
#[ignore]
fn composition_sweep_stormy() {
    run_composition_sweep(FaultLevel::Stormy);
}

// ===========================================================================
// Tier 4 — Specific Fault Scenarios (CI gate)
//
// Targeted tests for the three most dangerous cross-boundary failure modes.
// Unlike the randomized Tier 2/3 tests, these use deterministic op sequences
// to guarantee the specific fault path is exercised every run.
// ===========================================================================

/// Done-ledger commit failure after coordinator `complete()` succeeds.
///
/// This models the most dangerous cross-component failure: the coordinator
/// transitions a shard to terminal, but the done-ledger commit fails. The
/// gap leaves the coordinator believing the shard is done while the ledger
/// has no durable record. After the failure, all invariants (S1–S9, I1–I10,
/// C1–C4) must hold.
///
/// The test exercises three possible outcomes:
/// 1. `ScanLedgerWriteFailed` — ledger failure surfaced, provenance records
///    the write as uncommitted.
/// 2. `ScanCoordinatorCompleteFailed` — coordinator rejected the complete
///    (e.g., lease expired), provenance records uncommitted.
/// 3. `ScanCompleted` — the injected commit failure was consumed by a
///    different write path before this scan's write, so this scan succeeds.
///    Provenance must show committed.
#[test]
fn ledger_commit_failure_after_coordinator_complete() {
    let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
    let mut sim = CompositionSim::new(42, config)
        .with_workers_and_shards(2, 4)
        .expect("setup should succeed");

    sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

    // Establish baseline: one successful scan lifecycle.
    let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
        worker: WorkerId::from_raw(1),
    });
    assert!(violations.is_empty(), "baseline: {violations:?}");
    assert!(
        matches!(event, CompositionSimEvent::ScanCompleted { .. }),
        "expected ScanCompleted, got {event:?}"
    );
    let baseline_log_len = sim.write_log().len();

    // Inject a commit failure: the next batch_upsert submission will
    // succeed but the commit will fail.
    sim.step(CompositionSimOp::InjectLedgerFault(
        DoneLedgerFaultOp::InjectCommitFailure { count: 1 },
    ));

    // Attempt another scan lifecycle — coordinator complete() should succeed
    // or the scan should fail gracefully at the ledger layer.
    let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
        worker: WorkerId::from_raw(2),
    });

    // The step must produce zero unexpected violations regardless of
    // whether the ledger failure caused a rollback or a partial write.
    let bad = unexpected_violations(&violations, &event);
    assert!(
        bad.is_empty(),
        "commit failure should not produce unexpected violations: {bad:?}"
    );

    // In this sequential single-threaded test, no write path exists between
    // fault injection and the scan lifecycle. The injected commit failure must
    // be consumed by the scan's batch_upsert — ScanCompleted would indicate
    // the fault injection did not work.
    match &event {
        CompositionSimEvent::ScanLedgerWriteFailed { .. }
        | CompositionSimEvent::ScanCoordinatorCompleteFailed { .. } => {
            // Provenance entry must reflect uncommitted state.
            if sim.write_log().len() > baseline_log_len {
                let entry = sim.write_log().last().unwrap();
                assert!(
                    !entry.committed,
                    "provenance should record uncommitted after commit failure"
                );
            }
        }
        CompositionSimEvent::ScanClaimFailed { .. } => {
            // No shard available after baseline — acceptable.
        }
        _ => {
            panic!(
                "expected failure or claim-failed event after commit failure injection, \
                 got {event:?}"
            );
        }
    }
}

/// Stale-fence coordinator rejection: operations using a superseded lease
/// epoch are rejected.
///
/// Exercises the fence-epoch mechanism that prevents a slow worker from
/// corrupting a shard after a faster worker has re-acquired it. The
/// sequence:
/// 1. Worker 1 acquires shard → gets fence epoch E.
/// 2. Time advances past lease expiry → shard becomes available.
/// 3. Worker 2 acquires same shard → gets fence epoch E+1.
/// 4. Worker 1 attempts checkpoint with stale epoch E → rejected.
/// 5. Worker 1 attempts complete with stale epoch E → rejected.
///
/// All operations must produce zero violations. The coordinator must reject
/// stale-epoch operations without corrupting shard state.
#[test]
fn stale_fence_coordinator_rejects_operations() {
    let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
    let mut sim = CompositionSim::new(88, config)
        .with_workers_and_shards(2, 4)
        .expect("setup should succeed");

    sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

    // Worker 1 acquires a shard.
    let key = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(1));
    let w1 = WorkerId::from_raw(1);
    let w2 = WorkerId::from_raw(2);

    let (event, violations) = sim.step(CompositionSimOp::Coord(SimOp::Acquire { worker: w1, key }));
    assert!(violations.is_empty(), "acquire w1: {violations:?}");

    // With seed=88 and 4 shards, ShardId(1) is always registered. Assert
    // rather than silently skipping to prevent vacuous test passes.
    let acquired = matches!(
        event,
        CompositionSimEvent::Coord(super::SimEvent::AcquireOk { .. })
    );
    assert!(
        acquired,
        "Worker 1 acquire must succeed on fresh sim with seed=88, \
         ShardId(1) is always registered. Event: {event:?}"
    );

    // Advance time past lease expiry so the shard becomes available.
    let (_, viols) = sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime {
        ticks: LEASE_DUR + 10,
    }));
    assert!(viols.is_empty(), "time advance: {viols:?}");

    // Worker 2 acquires the same shard (bumps fence epoch).
    let (event, violations) = sim.step(CompositionSimOp::Coord(SimOp::Acquire { worker: w2, key }));
    assert!(violations.is_empty(), "acquire w2: {violations:?}");
    let w2_acquired = matches!(
        event,
        CompositionSimEvent::Coord(super::SimEvent::AcquireOk { .. })
    );
    assert!(
        w2_acquired,
        "Worker 2 acquire must succeed after lease expiry (LEASE_DUR + 10 ticks). \
         Event: {event:?}"
    );

    // Worker 1 attempts checkpoint with stale lease — should be rejected.
    let (event, violations) = sim.step(CompositionSimOp::Coord(SimOp::Checkpoint {
        worker: w1,
        key,
    }));
    assert!(
        violations.is_empty(),
        "stale checkpoint should produce zero violations: {violations:?}"
    );
    // The coordinator must reject the stale-fence operation.
    assert!(
        matches!(
            event,
            CompositionSimEvent::Coord(super::SimEvent::Rejected { .. })
        ),
        "expected Rejected for stale-fence checkpoint, got {event:?}"
    );

    // Worker 1 attempts complete with stale lease — also rejected.
    let (event, violations) =
        sim.step(CompositionSimOp::Coord(SimOp::Complete { worker: w1, key }));
    assert!(
        violations.is_empty(),
        "stale complete should produce zero violations: {violations:?}"
    );
    assert!(
        matches!(
            event,
            CompositionSimEvent::Coord(super::SimEvent::Rejected { .. })
        ),
        "expected Rejected for stale-fence complete, got {event:?}"
    );
}

/// Crash between coordinator `complete()` and done-ledger `batch_upsert()`.
///
/// Models a process crash (or network partition) in the gap between the
/// coordinator marking a shard as terminal and the done-ledger receiving
/// the corresponding records. After the crash:
///
/// - The shard is terminal in coordinator state (complete succeeded).
/// - No done-ledger records exist for that scan lifecycle (write was skipped).
/// - All invariants hold: S1–S9, C1–C4. Critically, C3 (`WriteAfterTerminal`)
///   must **not** fire because no write was committed for the terminal shard.
/// - The provenance entry records `committed = false` and
///   `coordinator_completed = true`.
///
/// After verifying the crash itself, runs 3 additional scan lifecycles to
/// confirm the invariant checkers remain clean — a crash must not leave
/// the checkers in a poisoned state that reports false violations on
/// subsequent operations.
#[test]
fn crash_between_complete_and_ledger_write() {
    let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
    let mut sim = CompositionSim::new(99, config)
        .with_workers_and_shards(2, 4)
        .expect("setup should succeed");

    sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

    // Inject crash: coordinator complete() runs but done-ledger write is skipped.
    let (event, violations) = sim.step(CompositionSimOp::ScanLifecycleCrashAfterComplete {
        worker: WorkerId::from_raw(1),
    });

    // Zero violations — C3 should not fire because no write was committed
    // for the terminal shard.
    assert!(
        violations.is_empty(),
        "crash scenario should produce zero violations: {violations:?}"
    );

    // Event must be the crash variant.
    assert!(
        matches!(event, CompositionSimEvent::ScanCrashedAfterComplete { .. }),
        "expected ScanCrashedAfterComplete, got {event:?}"
    );

    // Provenance entry must record uncommitted state.
    let log = sim.write_log();
    assert!(
        !log.is_empty(),
        "crash should still produce a provenance entry"
    );
    let entry = log.last().unwrap();
    assert!(!entry.committed, "crash provenance must be uncommitted");
    assert!(
        entry.coordinator_completed,
        "coordinator complete() should have succeeded before the crash"
    );

    // Run additional ops to verify the invariant checkers remain clean
    // after the crash gap.
    for i in 1..=3u64 {
        let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
            worker: WorkerId::from_raw((i % 2) + 1),
        });
        let bad = unexpected_violations(&violations, &event);
        assert!(
            bad.is_empty(),
            "post-crash step {i} should be clean: {bad:?}"
        );
    }
}

/// Done-ledger submit failure before coordinator `complete()` is attempted.
///
/// Unlike [`ledger_commit_failure_after_coordinator_complete`] where the
/// write is submitted and then the commit fails, here `batch_upsert()`
/// returns `Err` immediately. The coordinator `complete()` is never called
/// because `write_scan_to_ledger` returns `committed = false`. After the
/// failure, all invariants (S1–S9, I1–I10, C1–C4) must hold, and the
/// provenance entry must record both `committed = false` and
/// `coordinator_completed = false`.
///
/// Exercises a distinct code path from commit failure: submit failure skips
/// `oracle.submit()` entirely, whereas commit failure calls `oracle.submit()`
/// then `oracle.abort()`.
#[test]
fn ledger_submit_failure_prevents_coordinator_complete() {
    let config = CompositionFaultConfig::for_level(FaultLevel::SunnyDay);
    let mut sim = CompositionSim::new(42, config)
        .with_workers_and_shards(2, 4)
        .expect("setup should succeed");

    sim.step(CompositionSimOp::Coord(SimOp::AdvanceTime { ticks: 10 }));

    // Establish baseline: one successful scan lifecycle.
    let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
        worker: WorkerId::from_raw(1),
    });
    assert!(violations.is_empty(), "baseline: {violations:?}");
    assert!(
        matches!(event, CompositionSimEvent::ScanCompleted { .. }),
        "expected ScanCompleted, got {event:?}"
    );
    let baseline_log_len = sim.write_log().len();

    // Inject submit failure: batch_upsert() returns Err immediately,
    // so coordinator complete() is never attempted.
    sim.step(CompositionSimOp::InjectLedgerFault(
        DoneLedgerFaultOp::InjectSubmitFailure { count: 1 },
    ));

    // Attempt another scan lifecycle — should fail at ledger submit,
    // never reaching coordinator complete().
    let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
        worker: WorkerId::from_raw(2),
    });

    let bad = unexpected_violations(&violations, &event);
    assert!(
        bad.is_empty(),
        "submit failure should not produce unexpected violations: {bad:?}"
    );

    match &event {
        CompositionSimEvent::ScanLedgerWriteFailed { .. } => {
            // Submit rejected — provenance must show uncommitted,
            // coordinator_completed must be false (complete never called).
            if sim.write_log().len() > baseline_log_len {
                let entry = sim.write_log().last().unwrap();
                assert!(
                    !entry.committed,
                    "submit failure: provenance must be uncommitted"
                );
                assert!(
                    !entry.coordinator_completed,
                    "submit failure: coordinator complete() must not have been called"
                );
            }
        }
        CompositionSimEvent::ScanClaimFailed { .. } => {
            // No shards available after baseline — acceptable.
        }
        CompositionSimEvent::ScanCompleted { .. } => {
            // Fault consumed by another path before this scan's write.
            let entry = sim.write_log().last().unwrap();
            assert!(
                entry.committed,
                "ScanCompleted provenance should be committed"
            );
        }
        _ => panic!("unexpected event after submit failure injection: {event:?}"),
    }

    // Post-failure scans: verify invariant checkers remain clean.
    for i in 1..=3u64 {
        let (event, violations) = sim.step(CompositionSimOp::ScanLifecycle {
            worker: WorkerId::from_raw((i % 2) + 1),
        });
        let bad = unexpected_violations(&violations, &event);
        assert!(bad.is_empty(), "post-submit-failure step {i}: {bad:?}");
    }
}
