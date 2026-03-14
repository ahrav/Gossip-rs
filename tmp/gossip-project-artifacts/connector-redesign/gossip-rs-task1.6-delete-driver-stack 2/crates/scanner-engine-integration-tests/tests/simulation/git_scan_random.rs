//! Bounded random Git simulation harness.
//!
//! Environment knobs:
//! - `SIM_GIT_SCAN_DEEP=1` enables larger defaults.
//! - `SIM_GIT_SCAN_SEED_START` and `SIM_GIT_SCAN_SEED_COUNT` control seed ranges.
//! - `SIM_GIT_SCENARIO_COMMITS`, `SIM_GIT_SCENARIO_REFS`, `SIM_GIT_SCENARIO_BLOBS_PER_TREE`
//!   override generator sizing.
//! - `SIM_GIT_RUN_WORKERS`, `SIM_GIT_RUN_MAX_STEPS`, `SIM_GIT_RUN_STABILITY_RUNS`,
//!   `SIM_GIT_RUN_TRACE_CAP` override runner config.
//! - `GIT_SIM_WRITE_FAIL=1` writes failing artifacts to `tests/failures/`.
//!
//! The run is deterministic for a given seed set and environment configuration.

use std::fs;

use crate::scanner_rs::sim::rng::SimRng;
use crate::scanner_rs::sim_git_scan::{
    GitFaultPlan, GitReproArtifact, GitRunConfig, GitScenarioGenConfig, GitSimRunner, GitTraceDump,
    RunOutcome, generate_scenario,
};

const DEFAULT_SEED_COUNT: u64 = 25;

fn seed_value_from_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32(name: &str, default: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u32_opt(name: &str) -> Option<u32> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
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
    let hi = max.saturating_add(1);
    if min >= hi {
        return min;
    }
    rng.gen_range(min, hi)
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
