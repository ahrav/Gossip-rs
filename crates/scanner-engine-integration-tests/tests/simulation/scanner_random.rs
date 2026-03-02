#![cfg(any(test, feature = "sim-harness"))]
//! Bounded random scanner simulations to exercise scheduling, chunking, and faults.
//!
//! Environment knobs:
//! - `SIM_SCANNER_DEEP=1` enables a larger default scenario and higher fault rates.
//! - `SIM_SCENARIO_*` overrides scenario size (rules/files/secrets/noise).
//! - `SIM_RUN_*` overrides run config (workers/chunk/overlap/stability/etc).
//! - `SIM_RUN_MAX_FILE_SIZE` sets the max file size cap for scanning.

use std::collections::BTreeMap;
use std::fs;

use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::fault::{Corruption, FaultPlan, FileFaultPlan, IoFault, ReadFault};
use crate::scanner_rs::sim::{ReproArtifact, SimRng, TraceDump};
use crate::scanner_rs::sim_scanner::{
    RunConfig, RunOutcome, ScannerSimRunner, ScenarioGenConfig, SecretRepr,
    build_engine_from_suite, generate_scenario,
};

const DEFAULT_SEED_COUNT: u64 = 25;

fn seed_value_from_env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn env_u64(name: &str, default: u64) -> u64 {
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

fn scenario_config_from_env(deep: bool) -> ScenarioGenConfig {
    let mut cfg = ScenarioGenConfig {
        rule_count: if deep { 8 } else { 3 },
        file_count: if deep { 8 } else { 3 },
        secrets_per_file: if deep { 6 } else { 3 },
        token_len: if deep { 24 } else { 12 },
        min_noise_len: if deep { 8 } else { 4 },
        max_noise_len: if deep { 128 } else { 16 },
        representations: vec![
            SecretRepr::Raw,
            SecretRepr::Base64,
            SecretRepr::UrlPercent,
            SecretRepr::Utf16Le,
            SecretRepr::Utf16Be,
        ],
        ..ScenarioGenConfig::default()
    };

    cfg.rule_count = env_u32("SIM_SCENARIO_RULES", cfg.rule_count);
    cfg.file_count = env_u32("SIM_SCENARIO_FILES", cfg.file_count);
    cfg.secrets_per_file = env_u32("SIM_SCENARIO_SECRETS", cfg.secrets_per_file);
    cfg.token_len = env_u32("SIM_SCENARIO_TOKEN_LEN", cfg.token_len);
    cfg.min_noise_len = env_u32("SIM_SCENARIO_MIN_NOISE", cfg.min_noise_len);
    cfg.max_noise_len = env_u32("SIM_SCENARIO_MAX_NOISE", cfg.max_noise_len);
    cfg
}

#[test]
fn bounded_random_scanner_sims() {
    let deep = env_bool("SIM_SCANNER_DEEP", false);
    let seed_start = seed_value_from_env("SIM_SCANNER_SEED_START", 0);
    let seed_count = seed_value_from_env("SIM_SCANNER_SEED_COUNT", DEFAULT_SEED_COUNT);
    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let mut rng = SimRng::new(seed.wrapping_add(0xA5A5_5A5A));
        let run_cfg = random_run_config(&mut rng, deep);
        let gen_cfg = scenario_config_from_env(deep);

        let scenario = generate_scenario(seed, &gen_cfg).expect("generate scenario");
        let engine = build_engine_from_suite(&scenario.rule_suite, &run_cfg).expect("build engine");
        let mut run_cfg = run_cfg;
        let required = engine.required_overlap() as u32;
        if run_cfg.overlap < required {
            run_cfg.overlap = required;
        }
        if run_cfg.chunk_size < run_cfg.overlap {
            run_cfg.chunk_size = run_cfg.overlap;
        }

        let fault_plan = random_fault_plan(&mut rng, &scenario, run_cfg.chunk_size, deep);
        let schedule_seed = seed.wrapping_add(0xC0FF_EE00);
        let runner = ScannerSimRunner::new(run_cfg.clone(), schedule_seed);

        let (outcome, trace) = runner.run_with_trace(&scenario, &engine, &fault_plan);
        match outcome {
            RunOutcome::Ok { .. } => {}
            RunOutcome::Failed(fail) => {
                if std::env::var_os("DUMP_SIM_FAIL").is_some() {
                    eprintln!(
                        "sim failure (seed {seed}):\nrun_config={run_cfg:?}\nscenario={}\nfault_plan={fault_plan:?}",
                        serde_json::to_string_pretty(&scenario).unwrap()
                    );
                }
                if std::env::var_os("SCANNER_SIM_WRITE_FAIL").is_some() {
                    write_failure_artifact(
                        seed,
                        schedule_seed,
                        &run_cfg,
                        &scenario,
                        &fault_plan,
                        &fail,
                        &trace,
                    );
                }
                panic!("scanner sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}

fn random_run_config(rng: &mut SimRng, deep: bool) -> RunConfig {
    let workers_max_default = if deep { 8 } else { 4 };
    let workers_min = env_u32("SIM_RUN_WORKERS_MIN", 1).max(1);
    let workers_max = env_u32("SIM_RUN_WORKERS_MAX", workers_max_default).max(workers_min);
    let workers = env_u32_opt("SIM_RUN_WORKERS")
        .unwrap_or_else(|| rand_range_inclusive(rng, workers_min, workers_max));

    let chunk_max_default = if deep { 128 } else { 64 };
    let chunk_min = env_u32("SIM_RUN_CHUNK_MIN", 16).max(1);
    let chunk_max = env_u32("SIM_RUN_CHUNK_MAX", chunk_max_default).max(chunk_min);
    let chunk_size = env_u32_opt("SIM_RUN_CHUNK_SIZE")
        .unwrap_or_else(|| rand_range_inclusive(rng, chunk_min, chunk_max));

    let overlap = env_u32("SIM_RUN_OVERLAP", if deep { 128 } else { 64 });
    let max_in_flight_objects = env_u32("SIM_RUN_MAX_IN_FLIGHT", if deep { 32 } else { 16 });
    let buffer_pool_cap = env_u32("SIM_RUN_BUFFER_POOL_CAP", if deep { 16 } else { 8 });
    let max_file_size = env_u64("SIM_RUN_MAX_FILE_SIZE", u64::MAX);
    let max_steps = env_u64("SIM_RUN_MAX_STEPS", 0);
    let max_transform_depth = env_u32("SIM_RUN_MAX_TRANSFORM_DEPTH", if deep { 4 } else { 3 });
    let scan_utf16_variants = env_bool("SIM_RUN_SCAN_UTF16", true);
    let stability_runs = env_u32("SIM_RUN_STABILITY_RUNS", if deep { 4 } else { 2 });

    RunConfig {
        workers,
        chunk_size,
        overlap,
        max_in_flight_objects,
        buffer_pool_cap,
        max_file_size,
        max_steps,
        max_transform_depth,
        scan_utf16_variants,
        archive: ArchiveConfig::default(),
        stability_runs,
        archive_deadline_countdown: None,
    }
}

fn random_fault_plan(
    rng: &mut SimRng,
    scenario: &crate::scanner_rs::sim_scanner::Scenario,
    chunk_size: u32,
    deep: bool,
) -> FaultPlan {
    let mut per_file = BTreeMap::new();
    let max_len = chunk_size.max(4);

    for node in &scenario.fs.nodes {
        let crate::scanner_rs::sim::SimNodeSpec::File { path, .. } = node else {
            continue;
        };
        let mut plan = FileFaultPlan {
            open: None,
            reads: Vec::new(),
            cancel_after_reads: None,
        };

        if rng.gen_bool(1, if deep { 5 } else { 10 }) {
            plan.open = Some(IoFault::ErrKind { kind: 2 });
        }

        let read_faults = rng.gen_range(0, if deep { 5 } else { 3 });
        for _ in 0..read_faults {
            let fault = match rng.gen_range(0, 3) {
                0 => IoFault::PartialRead {
                    max_len: rng.gen_range(1, max_len),
                },
                1 => IoFault::EIntrOnce,
                _ => IoFault::ErrKind { kind: 5 },
            };
            let latency = if rng.gen_bool(1, 3) {
                rng.gen_range(1, 4) as u64
            } else {
                0
            };
            let corruption = if rng.gen_bool(1, if deep { 6 } else { 12 }) {
                Some(Corruption::FlipBit {
                    offset: 0,
                    mask: 0x01,
                })
            } else {
                None
            };
            plan.reads.push(ReadFault {
                fault: Some(fault),
                latency_ticks: latency,
                corruption,
            });
        }

        if rng.gen_bool(1, if deep { 10 } else { 20 }) {
            plan.cancel_after_reads = Some(rng.gen_range(1, 4));
        }

        if plan.open.is_some() || plan.cancel_after_reads.is_some() || !plan.reads.is_empty() {
            per_file.insert(path.bytes.clone(), plan);
        }
    }

    FaultPlan { per_file }
}

fn write_failure_artifact(
    scenario_seed: u64,
    schedule_seed: u64,
    run_config: &RunConfig,
    scenario: &crate::scanner_rs::sim_scanner::Scenario,
    fault_plan: &FaultPlan,
    failure: &crate::scanner_rs::sim_scanner::FailureReport,
    trace: &TraceDump,
) {
    let artifact = ReproArtifact {
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
        trace: trace.clone(),
    };

    let out_dir = "tests/failures";
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("scanner sim: failed to create {out_dir}: {err}");
        return;
    }

    let path = format!("{out_dir}/scanner_seed_{scenario_seed}.case.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(json) => {
            if let Err(err) = fs::write(&path, json) {
                eprintln!("scanner sim: failed to write {path}: {err}");
            }
        }
        Err(err) => {
            eprintln!("scanner sim: failed to serialize artifact: {err}");
        }
    }
}
