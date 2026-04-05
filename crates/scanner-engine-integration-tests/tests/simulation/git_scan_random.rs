//! Bounded random Git simulation harness.
//!
//! Environment knobs:
//! - `SIM_GIT_SCAN_DEEP=1` enables larger defaults.
//! - `SIM_GIT_SCAN_SEED_START` and `SIM_GIT_SCAN_SEED_COUNT` control seed ranges.
//! - `SIM_GIT_SCAN_FAULT_SEED_COUNT` controls the extra fault-injected
//!   reproducibility sweep.
//! - `SIM_GIT_SCENARIO_COMMITS`, `SIM_GIT_SCENARIO_REFS`, `SIM_GIT_SCENARIO_BLOBS_PER_TREE`
//!   override generator sizing.
//! - `SIM_GIT_RUN_WORKERS`, `SIM_GIT_RUN_MAX_STEPS`, `SIM_GIT_RUN_STABILITY_RUNS`,
//!   `SIM_GIT_RUN_TRACE_CAP` override runner config.
//! - `GIT_SIM_WRITE_FAIL=1` writes failing artifacts to `tests/failures/`.
//!
//! The sweeps are deterministic for a given `(scenario_seed, schedule_seed,
//! fault_plan, environment)` tuple. The plain sweep keeps the happy path green;
//! the fault-injected sweep checks that the same tuple reproduces the same
//! success or failure shape across repeated runs while `stability_runs >= 2`.

use std::fs;

use crate::scanner_rs::sim::rng::SimRng;
use crate::scanner_rs::sim_git_scan::fault::GitResourceFaults;
use crate::scanner_rs::sim_git_scan::{
    FailureKind, FailureReport, GitCorruption, GitFaultPlan, GitIoFault, GitReadFault,
    GitReproArtifact, GitResourceId, GitRunConfig, GitScenario, GitScenarioGenConfig, GitSimRunner,
    GitTraceDump, GitTraceEvent, RunOutcome, RunReport, generate_scenario,
};

const DEFAULT_SEED_COUNT: u64 = 25;
const DEFAULT_FAULT_SEED_COUNT: u64 = 8;

fn seed_value_from_env(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("{name}={v:?} is not a valid u64: {e}")),
        Err(_) => default,
    }
}

fn env_u32(name: &str, default: u32) -> u32 {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("{name}={v:?} is not a valid u32: {e}")),
        Err(_) => default,
    }
}

fn env_u32_opt(name: &str) -> Option<u32> {
    match std::env::var(name) {
        Ok(v) => Some(
            v.parse()
                .unwrap_or_else(|e| panic!("{name}={v:?} is not a valid u32: {e}")),
        ),
        Err(_) => None,
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    match std::env::var(name) {
        Ok(v) => v
            .parse()
            .unwrap_or_else(|e| panic!("{name}={v:?} is not a valid u64: {e}")),
        Err(_) => default,
    }
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => {
            let v = v.to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        }
        Err(_) => default,
    }
}

fn rand_range_inclusive(rng: &mut SimRng, min: u32, max: u32) -> u32 {
    if min >= max {
        return min;
    }
    match max.checked_add(1) {
        Some(hi) => rng.gen_range(min, hi),
        // max == u32::MAX: the exclusive upper bound overflows u32.
        // Draw uniformly from [0, width) in u64 arithmetic and shift.
        None => {
            let width = u64::from(max) - u64::from(min) + 1;
            (u64::from(min) + rng.next_u64() % width) as u32
        }
    }
}

fn scenario_config_from_env(deep: bool) -> GitScenarioGenConfig {
    let mut cfg = GitScenarioGenConfig {
        commit_count: if deep { 8 } else { 3 },
        ref_count: if deep { 3 } else { 1 },
        blobs_per_tree: if deep { 3 } else { 1 },
        ..GitScenarioGenConfig::default()
    };

    cfg.commit_count = env_u32("SIM_GIT_SCENARIO_COMMITS", cfg.commit_count);
    cfg.ref_count = env_u32("SIM_GIT_SCENARIO_REFS", cfg.ref_count);
    cfg.blobs_per_tree = env_u32("SIM_GIT_SCENARIO_BLOBS_PER_TREE", cfg.blobs_per_tree);
    cfg
}

fn random_run_config(rng: &mut SimRng, deep: bool) -> GitRunConfig {
    let workers_max_default = if deep { 6 } else { 3 };
    let workers_min = env_u32("SIM_GIT_RUN_WORKERS_MIN", 1).max(1);
    let workers_max = env_u32("SIM_GIT_RUN_WORKERS_MAX", workers_max_default).max(workers_min);
    let workers = env_u32_opt("SIM_GIT_RUN_WORKERS")
        .unwrap_or_else(|| rand_range_inclusive(rng, workers_min, workers_max));

    let stability_runs = env_u32("SIM_GIT_RUN_STABILITY_RUNS", if deep { 3 } else { 2 });
    let trace_capacity = env_u32("SIM_GIT_RUN_TRACE_CAP", if deep { 2048 } else { 512 });
    let max_steps = env_u64("SIM_GIT_RUN_MAX_STEPS", 0);

    GitRunConfig {
        workers,
        max_steps,
        stability_runs,
        trace_capacity,
    }
}

fn random_fault_seed_count(deep: bool) -> u64 {
    let default = if deep {
        DEFAULT_FAULT_SEED_COUNT.saturating_mul(2)
    } else {
        DEFAULT_FAULT_SEED_COUNT
    };
    seed_value_from_env("SIM_GIT_SCAN_FAULT_SEED_COUNT", default)
}

fn random_corruption(rng: &mut SimRng) -> GitCorruption {
    match rng.gen_range(0, 3) {
        0 => GitCorruption::TruncateTo {
            new_len: rng.gen_range(0, 16),
        },
        1 => GitCorruption::FlipBit {
            offset: rng.gen_range(0, 16),
            mask: 1u8 << (rng.gen_range(0, 8) as u8),
        },
        _ => GitCorruption::Overwrite {
            offset: rng.gen_range(0, 16),
            bytes: vec![
                rng.gen_range(0, 256) as u8,
                rng.gen_range(0, 256) as u8,
                rng.gen_range(0, 256) as u8,
            ],
        },
    }
}

fn random_read_fault(rng: &mut SimRng) -> GitReadFault {
    let latency_ticks = rng.gen_range(0, 4) as u64;
    // Arms 0-2 each inject a distinct I/O fault (ErrKind, PartialRead,
    // EIntrOnce). Arms 3-4 inject data corruption without an I/O fault,
    // giving corruption-only paths ~40% weight to exercise the
    // corruption-detection codepaths more heavily.
    match rng.gen_range(0, 5) {
        0 => GitReadFault {
            fault: Some(GitIoFault::ErrKind {
                kind: rng.gen_range(1, 4) as u8,
            }),
            latency_ticks,
            corruption: None,
        },
        1 => GitReadFault {
            fault: Some(GitIoFault::PartialRead {
                max_len: rng.gen_range(1, 32),
            }),
            latency_ticks,
            corruption: None,
        },
        2 => GitReadFault {
            fault: Some(GitIoFault::EIntrOnce),
            latency_ticks,
            corruption: None,
        },
        _ => GitReadFault {
            fault: None,
            latency_ticks,
            corruption: Some(random_corruption(rng)),
        },
    }
}

fn maybe_push_fault_resource(
    resources: &mut Vec<GitResourceFaults>,
    rng: &mut SimRng,
    resource: GitResourceId,
) {
    if !rng.gen_bool(1, 2) {
        return;
    }
    resources.push(GitResourceFaults {
        resource,
        reads: vec![random_read_fault(rng)],
    });
}

/// Builds a randomized fault plan from the given scenario's resource set.
///
/// Only `Persist` and `SeenPersist` faults are exercised because
/// `generate_scenario` produces `artifacts: None`. The
/// `CommitGraph`/`Midx`/`Pack` branches are present but dormant until
/// scenarios include artifact bundles. A fallback guarantees at least one
/// `Persist` fault.
fn random_fault_plan(rng: &mut SimRng, scenario: &GitScenario) -> GitFaultPlan {
    let mut resources = Vec::new();
    maybe_push_fault_resource(&mut resources, rng, GitResourceId::Persist);
    maybe_push_fault_resource(&mut resources, rng, GitResourceId::SeenPersist);

    if let Some(artifacts) = scenario.artifacts.as_ref() {
        if artifacts.commit_graph.is_some() {
            maybe_push_fault_resource(&mut resources, rng, GitResourceId::CommitGraph);
        }
        if artifacts.midx.is_some() {
            maybe_push_fault_resource(&mut resources, rng, GitResourceId::Midx);
        }
        if !artifacts.packs.is_empty() {
            let idx = rng.gen_range(0, artifacts.packs.len() as u32) as usize;
            maybe_push_fault_resource(
                &mut resources,
                rng,
                GitResourceId::Pack {
                    pack_id: artifacts.packs[idx].pack_id,
                },
            );
        }
    }

    if resources.is_empty() {
        resources.push(GitResourceFaults {
            resource: GitResourceId::Persist,
            reads: vec![random_read_fault(rng)],
        });
    }

    GitFaultPlan { resources }
}

fn assert_same_report(left: &RunReport, right: &RunReport, seed: u64) {
    // Per-field assertions for targeted diagnostics on mismatch.
    assert_eq!(left.steps, right.steps, "seed {seed}: step count diverged");
    assert_eq!(
        left.commit_count, right.commit_count,
        "seed {seed}: commit count diverged"
    );
    assert_eq!(
        left.candidate_count, right.candidate_count,
        "seed {seed}: candidate count diverged"
    );
    assert_eq!(
        left.skipped_count, right.skipped_count,
        "seed {seed}: skipped count diverged"
    );
    assert_eq!(left.outcome, right.outcome, "seed {seed}: outcome diverged");
    assert_eq!(
        left.scanned_hash, right.scanned_hash,
        "seed {seed}: scanned hash diverged"
    );
    assert_eq!(
        left.skipped_hash, right.skipped_hash,
        "seed {seed}: skipped hash diverged"
    );
    assert_eq!(
        left.trace_hash, right.trace_hash,
        "seed {seed}: trace hash diverged"
    );
    assert_eq!(
        left.trace_dump, right.trace_dump,
        "seed {seed}: trace dump diverged"
    );
    // Structural guard: catches any field added to RunReport not yet covered
    // by the per-field assertions above.
    assert_eq!(
        left, right,
        "seed {seed}: reports diverged (uncovered field)"
    );
}

fn assert_reproducible_failure(left: &FailureReport, right: &FailureReport, seed: u64) {
    // Per-field assertions for targeted diagnostics on mismatch.
    assert_eq!(
        left.kind, right.kind,
        "seed {seed}: failure kind diverged: {:?} vs {:?}",
        left.kind, right.kind
    );
    assert_eq!(
        left.message, right.message,
        "seed {seed}: failure message diverged"
    );
    assert_eq!(left.step, right.step, "seed {seed}: failure step diverged");
    // Structural guard: catches any field added to FailureReport not yet
    // covered by the per-field assertions above.
    assert_eq!(
        left, right,
        "seed {seed}: failure reports diverged (uncovered field)"
    );
    // Fault-injected sweeps must not panic, hang, or lose schedule stability.
    assert!(
        !matches!(
            left.kind,
            FailureKind::Panic | FailureKind::Hang | FailureKind::StabilityMismatch
        ),
        "seed {seed}: fault-injected sweep must not panic, hang, or lose schedule stability: {:?}",
        left.kind
    );
}

fn assert_same_outcome(left: &RunOutcome, right: &RunOutcome, seed: u64) {
    match (left, right) {
        (RunOutcome::Ok { report: left }, RunOutcome::Ok { report: right }) => {
            assert_same_report(left, right, seed);
            assert!(
                left.commit_count > 0 || left.candidate_count > 0,
                "seed {seed}: successful fault-injected run produced no scan work"
            );
            assert!(
                left.trace_dump
                    .iter()
                    .any(|e| matches!(e, GitTraceEvent::FaultInjected { .. })),
                "seed {seed}: fault plan had resources but no FaultInjected events appeared in the trace"
            );
        }
        (RunOutcome::Failed(left), RunOutcome::Failed(right)) => {
            assert_reproducible_failure(left, right, seed);
        }
        _ => {
            panic!("seed {seed}: repeated fault-injected runs must stay in the same outcome shape")
        }
    }
}

#[test]
fn bounded_random_git_sims() {
    let deep = env_bool("SIM_GIT_SCAN_DEEP", false);
    let seed_start = seed_value_from_env("SIM_GIT_SCAN_SEED_START", 0);
    let seed_count = seed_value_from_env("SIM_GIT_SCAN_SEED_COUNT", DEFAULT_SEED_COUNT);

    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let mut rng = SimRng::new(seed.wrapping_add(0xA5A5_5A5A));
        // The run config is randomized but derived only from the seed and env.
        let run_cfg = random_run_config(&mut rng, deep);
        let gen_cfg = scenario_config_from_env(deep);

        let scenario = generate_scenario(seed, &gen_cfg).expect("generate scenario");
        let fault_plan = GitFaultPlan::default();
        let schedule_seed = seed.wrapping_add(0xC0FF_EE00);
        let runner = GitSimRunner::new(run_cfg.clone(), schedule_seed);

        match runner.run(&scenario, &fault_plan) {
            RunOutcome::Ok { .. } => {}
            RunOutcome::Failed(fail) => {
                if std::env::var_os("GIT_SIM_WRITE_FAIL").is_some() {
                    write_failure_artifact(
                        seed,
                        schedule_seed,
                        &run_cfg,
                        &scenario,
                        &fault_plan,
                        &fail,
                    );
                }
                panic!("git sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}

#[test]
fn bounded_random_git_sims_with_fault_injection_are_reproducible() {
    let deep = env_bool("SIM_GIT_SCAN_DEEP", false);
    let seed_start = seed_value_from_env("SIM_GIT_SCAN_SEED_START", 0);
    let seed_count = random_fault_seed_count(deep);

    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let mut rng = SimRng::new(seed.wrapping_add(0x51A7_FA11));
        let mut run_cfg = random_run_config(&mut rng, deep);
        run_cfg.stability_runs = run_cfg.stability_runs.max(2);
        let gen_cfg = scenario_config_from_env(deep);

        let scenario = generate_scenario(seed, &gen_cfg).expect("generate scenario");
        let fault_plan = random_fault_plan(&mut rng, &scenario);
        let schedule_seed = seed.wrapping_add(0xF411_7A9E);
        let runner = GitSimRunner::new(run_cfg, schedule_seed);

        // Re-running the exact same tuple is the smallest proof that injected
        // resource faults do not introduce hidden nondeterminism in the harness.
        let first = runner.run(&scenario, &fault_plan);
        let second = runner.run(&scenario, &fault_plan);
        assert_same_outcome(&first, &second, seed);
    }
}

fn write_failure_artifact(
    scenario_seed: u64,
    schedule_seed: u64,
    run_config: &GitRunConfig,
    scenario: &crate::scanner_rs::sim_git_scan::GitScenario,
    fault_plan: &GitFaultPlan,
    failure: &crate::scanner_rs::sim_git_scan::FailureReport,
) {
    let artifact = GitReproArtifact {
        schema_version: 1,
        scanner_pkg_version: "dev".to_string(),
        git_commit: None,
        target: "local".to_string(),
        scenario_seed,
        schedule_seed,
        run_config: run_config.clone(),
        scenario: scenario.clone(),
        fault_plan: fault_plan.clone(),
        failure: failure.clone(),
        trace: GitTraceDump {
            // Keep artifacts small; a failing repro can be re-run to capture full traces.
            ring: Vec::new(),
            full: None,
        },
    };

    let out_dir = "tests/failures";
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("git sim: failed to create {out_dir}: {err}");
        return;
    }

    let path = format!("{out_dir}/git_scan_seed_{scenario_seed}.case.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(json) => {
            if let Err(err) = fs::write(&path, json) {
                eprintln!("git sim: failed to write {path}: {err}");
            }
        }
        Err(err) => {
            eprintln!("git sim: failed to serialize artifact: {err}");
        }
    }
}
