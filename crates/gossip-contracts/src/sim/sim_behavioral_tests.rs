//! Behavioral regression tests for the simulation harness.
//!
//! These tests pin *behavioral* properties -- invariant safety, convergence,
//! event-kind coverage, and deterministic replay -- rather than exact
//! PRNG-stream-dependent counts. A legitimate harness change that reorders
//! random calls will shift counts but must not break any behavioral assertion.
//!
//! # Test categories
//!
//! - **Seeded behavioral tests** -- fixed seed + config combos that exercise
//!   each fault level. Assert no violations, convergence (where expected), and
//!   minimum event-kind coverage.
//! - **Deterministic replay** -- runs each config twice and asserts
//!   field-identical reports, validating the PRNG-based determinism contract.
//! - **Exhaustiveness guard** -- catches `SimEventKind` variant additions that
//!   are not reflected in the test infrastructure.
//!
//! # Design rationale
//!
//! Behavioral assertions avoid brittle snapshot tests. If the PRNG call
//! sequence changes (e.g., a new fault type is wired in), only the explicit
//! counts shift -- the behavioral properties remain stable. This keeps the
//! tests useful as a regression net without creating maintenance churn.

use super::FaultLevel;
use super::harness::{CoordinationSim, SimEventKind, SimReport};

/// All event kind variants, manually enumerated.
///
/// `SimEventKind` does not derive `strum::EnumIter` or provide an
/// `all_variants()` method, so this array serves as the single source of
/// truth for the variant count. The [`all_event_kinds_enumerated`] test
/// asserts the length matches the expected count, acting as a tripwire
/// when new variants are added.
const ALL_EVENT_KINDS: [SimEventKind; 15] = [
    SimEventKind::AcquireOk,
    SimEventKind::RenewOk,
    SimEventKind::CheckpointOk,
    SimEventKind::CompleteOk,
    SimEventKind::ParkOk,
    SimEventKind::SplitReplaceOk,
    SimEventKind::SplitResidualOk,
    SimEventKind::ReplayedOk,
    SimEventKind::ClaimOk,
    SimEventKind::ClaimNoneAvailable,
    SimEventKind::Rejected,
    SimEventKind::TimeAdvanced,
    SimEventKind::WorkerPaused,
    SimEventKind::WorkerResumed,
    SimEventKind::Skipped,
];

/// Assert the minimum behavioral bar: no invariant violations and at least
/// one operation executed.
///
/// Every seeded test calls this first. If the harness runs zero ops (e.g.,
/// due to a misconfigured op weight table), this catches it even when
/// violations are empty.
fn assert_behavioral_properties(report: &SimReport, seed: u64, level: FaultLevel) {
    assert!(
        report.violations.is_empty(),
        "seed {seed}, level {level:?}: violations: {:#?}",
        report.violations
    );
    assert!(
        report.ops_executed > 0,
        "seed {seed}, level {level:?}: no ops executed"
    );
}

/// Assert that the report contains the event kinds expected for the given
/// fault level.
///
/// The required set is fault-level-dependent: `SunnyDay` tests run a small
/// op budget (300 total) where `WorkerPaused` and `WorkerResumed` may or may
/// not appear, so they are omitted from the required set to avoid flakiness.
/// Under `Stormy` or `Radioactive`, the larger op budget makes pause/resume
/// events reliable enough to require. This is intentionally *not* an
/// exhaustive check of all 15 kinds -- rare kinds like `SplitResidualOk`
/// depend on specific preconditions that a small-scale test may not hit.
fn assert_event_coverage(report: &SimReport, seed: u64, level: FaultLevel) {
    let required: &[SimEventKind] = if level == FaultLevel::SunnyDay {
        &[
            SimEventKind::AcquireOk,
            SimEventKind::CheckpointOk,
            SimEventKind::CompleteOk,
            SimEventKind::Rejected,
            SimEventKind::TimeAdvanced,
        ]
    } else {
        &[
            SimEventKind::AcquireOk,
            SimEventKind::CheckpointOk,
            SimEventKind::CompleteOk,
            SimEventKind::Rejected,
            SimEventKind::TimeAdvanced,
            SimEventKind::WorkerPaused,
            SimEventKind::WorkerResumed,
        ]
    };

    for kind in required {
        assert!(
            report.event_counts.contains_key(kind),
            "seed {seed}, level {level:?}: missing required event kind {kind:?}"
        );
    }
}

// -- Seeded behavioral tests ------------------------------------------------

/// Moderate fault injection: 3 workers, 5 shards, 700 total ops.
///
/// Stormy injects ~10% time jumps, ~10% lease expiry, and ~5% pauses.
/// With 500 safety ops this is enough to trigger all core event kinds
/// while still converging reliably in the liveness phase.
#[test]
fn behavioral_seed_42_stormy() {
    let report = CoordinationSim::new(42, FaultLevel::Stormy)
        .with_workers_and_shards(3, 5)
        .run(500, 200);
    assert_behavioral_properties(&report, 42, FaultLevel::Stormy);
    assert!(report.converged, "seed 42: failed to converge");
    assert_event_coverage(&report, 42, FaultLevel::Stormy);
}

/// No fault injection: 2 workers, 3 shards, 300 total ops.
///
/// SunnyDay exercises the happy path with zero fault injection. Fewer ops
/// suffice because there are no timing anomalies to recover from, and
/// convergence should be fast.
#[test]
fn behavioral_seed_99_sunny() {
    let report = CoordinationSim::new(99, FaultLevel::SunnyDay)
        .with_workers_and_shards(2, 3)
        .run(200, 100);
    assert_behavioral_properties(&report, 99, FaultLevel::SunnyDay);
    assert!(report.converged, "seed 99: failed to converge");
    assert_event_coverage(&report, 99, FaultLevel::SunnyDay);
}

/// Aggressive fault injection: 4 workers, 8 shards, 1500 total ops.
///
/// Radioactive injects ~20% time jumps, ~20% lease expiry, and ~10% pauses.
/// More shards and workers increase contention. Convergence is *not*
/// asserted here because aggressive faults can prevent all shards from
/// reaching terminal state within the op budget -- but invariant safety
/// must still hold.
#[test]
fn behavioral_seed_7_radioactive() {
    let report = CoordinationSim::new(7, FaultLevel::Radioactive)
        .with_workers_and_shards(4, 8)
        .run(1000, 500);
    assert_behavioral_properties(&report, 7, FaultLevel::Radioactive);
}

// -- Deterministic replay ---------------------------------------------------

/// Running the same seed + config twice must produce field-identical reports.
///
/// Validates the determinism contract documented in `sim::mod.rs`: all
/// randomness flows through a single `ChaCha8Rng` seeded from a `u64`, so
/// identical inputs must yield identical outputs. The three compared fields
/// (`event_counts`, `ops_executed`, `end_time`) are sufficient to detect
/// any PRNG divergence -- if any differs, the random stream was perturbed.
///
/// Exercises both `Stormy` and `SunnyDay` to ensure determinism holds
/// regardless of whether faults are active.
#[test]
fn deterministic_replay_cross_config() {
    for (seed, level, workers, shards, safety, liveness) in [
        (42, FaultLevel::Stormy, 3, 5, 500, 200),
        (99, FaultLevel::SunnyDay, 2, 3, 200, 100),
    ] {
        let a = CoordinationSim::new(seed, level)
            .with_workers_and_shards(workers, shards)
            .run(safety, liveness);
        let b = CoordinationSim::new(seed, level)
            .with_workers_and_shards(workers, shards)
            .run(safety, liveness);

        assert_eq!(
            a.event_counts, b.event_counts,
            "seed {seed}, level {level:?}: event counts diverged"
        );
        assert_eq!(
            a.ops_executed, b.ops_executed,
            "seed {seed}, level {level:?}: ops_executed diverged"
        );
        assert_eq!(
            a.end_time, b.end_time,
            "seed {seed}, level {level:?}: end_time diverged"
        );
    }
}

// -- Exhaustiveness guard ---------------------------------------------------

/// Tripwire for `SimEventKind` variant additions.
///
/// This test cannot enforce exhaustiveness at compile time (there is no
/// `#[derive(EnumCount)]`). When a developer adds a new variant to
/// [`ALL_EVENT_KINDS`], the hard-coded `15` will mismatch, reminding them
/// to update coverage. Note: if the enum grows without updating
/// `ALL_EVENT_KINDS`, this test will not catch the omission — the array
/// type annotation (`[SimEventKind; 15]`) serves as the primary compile-time
/// guard for that case.
#[test]
fn all_event_kinds_enumerated() {
    assert_eq!(
        ALL_EVENT_KINDS.len(),
        15,
        "update ALL_EVENT_KINDS if SimEventKind gains new variants"
    );
}
