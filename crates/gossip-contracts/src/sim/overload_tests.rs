//! Focused tests for scripted overload runs.
//!
//! The main simulation suites already cover broad randomized behavior.
//! These tests add targeted guarantees for the overload path:
//!
//! - each overload scenario executes without invariant violations,
//! - deterministic replay is stable for a fixed seed and scenario,
//! - D1 availability reporting matches full-scan ground truth.

use super::{OverloadKind, OverloadScenario};
use crate::sim::{CoordinationSim, FaultLevel};
use crate::test_util::miri_proptest_config;
use proptest::prelude::*;

/// Shared overload harness preset for overload-focused tests.
///
/// Uses fixed worker/shard counts so failures are comparable across cases.
fn overload_sim(seed: u64, level: FaultLevel, cooldown: u64) -> CoordinationSim {
    CoordinationSim::new(seed, level)
        .with_cooldown(cooldown)
        .with_workers_and_shards(4, 15)
}

/// Proptest config tuned for overload coverage without making CI prohibitive.
///
/// Under Miri we keep the inherited small-case budget; outside Miri we raise
/// to 50 cases to improve seed diversity for stress paths.
fn sim_proptest_config() -> proptest::test_runner::Config {
    let mut cfg = miri_proptest_config();
    if !cfg!(miri) {
        cfg.cases = 50;
    }
    cfg
}

/// Strategy over all scripted overload kinds.
fn arb_overload_kind() -> impl Strategy<Value = OverloadKind> {
    prop_oneof![
        Just(OverloadKind::BurstClaim),
        Just(OverloadKind::CapacityDrop),
        Just(OverloadKind::BurstShards),
    ]
}

#[test]
fn test_overload_burst_claim_sunny() {
    let report = overload_sim(42, FaultLevel::SunnyDay, 20).run_overload(
        100,
        OverloadScenario::new(OverloadKind::BurstClaim, 10),
        200,
    );
    assert!(
        report.violations.is_empty(),
        "unexpected violations: {:?}",
        report.violations,
    );
    assert!(report.l1_passed, "expected recovery liveness to pass");
}

#[test]
fn test_overload_capacity_drop_stormy() {
    let report = overload_sim(77, FaultLevel::Stormy, 20).run_overload(
        150,
        OverloadScenario::new(OverloadKind::CapacityDrop, 8),
        250,
    );
    assert!(
        report.violations.is_empty(),
        "unexpected violations: {:?}",
        report.violations,
    );
}

#[test]
#[ignore = "radioactive overload sweep is intentionally slow"]
fn test_overload_burst_shards_radioactive() {
    let report = overload_sim(9, FaultLevel::Radioactive, 30).run_overload(
        200,
        OverloadScenario::new(OverloadKind::BurstShards, 12),
        300,
    );
    assert!(
        report.violations.is_empty(),
        "unexpected violations: {:?}",
        report.violations,
    );
}

#[test]
fn test_overload_deterministic_replay() {
    let seed = 123;
    let scenario = OverloadScenario::new(OverloadKind::BurstClaim, 12);
    let report_a = overload_sim(seed, FaultLevel::Stormy, 25).run_overload(120, scenario, 220);
    let report_b = overload_sim(seed, FaultLevel::Stormy, 25).run_overload(120, scenario, 220);

    assert_eq!(report_a.event_counts, report_b.event_counts);
    assert_eq!(report_a.ops_executed, report_b.ops_executed);
    assert_eq!(report_a.end_time, report_b.end_time);
    assert_eq!(report_a.d1_observations, report_b.d1_observations);
}

#[test]
fn test_d1_accuracy_sunny() {
    let report = overload_sim(7, FaultLevel::SunnyDay, 0).run_overload(
        80,
        OverloadScenario::new(OverloadKind::BurstClaim, 10),
        120,
    );
    assert!(
        !report.d1_observations.is_empty(),
        "expected at least one D1 observation"
    );
    assert!(
        report
            .d1_observations
            .iter()
            .all(|obs| obs.reported == obs.ground_truth),
        "D1 mismatch in observations: {:?}",
        report.d1_observations,
    );
}

proptest! {
    #![proptest_config(sim_proptest_config())]

    #[test]
    fn proptest_overload_safety(
        seed in any::<u64>(),
        kind in arb_overload_kind(),
        rounds in 1u32..=6,
        cooldown in 0u64..=50,
    ) {
        let scenario = OverloadScenario::new(kind, rounds);
        let report = overload_sim(seed, FaultLevel::Stormy, cooldown)
            .run_overload(60, scenario, 120);
        prop_assert!(
            report.violations.is_empty(),
            "seed {seed}, kind {kind:?}, rounds {rounds}, cooldown {cooldown}: {:?}",
            report.violations,
        );
    }
}
