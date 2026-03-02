#![cfg(any(test, feature = "sim-harness"))]
//! Random-seeded mutation-plan scanner simulations.

use std::collections::BTreeMap;
use std::fs;

use crate::scanner_rs::Engine;
use crate::scanner_rs::archive::ArchiveConfig;
use crate::scanner_rs::sim::SimRng;
use crate::scanner_rs::sim::fault::FaultPlan;
use crate::scanner_rs::sim::mutation::{
    GeneratedCase, MutationPlan, MutationViolation, build_mutation_engine, build_mutation_scenario,
    check_mutation_expectations, random_mutation_plans_all_families,
};
use crate::scanner_rs::sim_scanner::{RunConfig, RunOutcome, ScannerSimRunner, Scenario};

const DEFAULT_SEED_COUNT: u64 = 25;

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

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes" | "on"),
        Err(_) => default,
    }
}

/// Two-pass build: probe for required overlap, adjust run config, then rebuild
/// the scenario with noise padding equal to the engine's required overlap.
///
/// Returns `(scenario, cases, noise_len, engine, run_cfg)` ready for scanning.
pub(super) fn build_mutation_sim(
    plans: &[MutationPlan],
    base_run_cfg: &RunConfig,
) -> (Scenario, Vec<GeneratedCase>, usize, Engine, RunConfig) {
    // First pass: discover required_overlap from a probe scenario.
    let (probe_scenario, _, _) = build_mutation_scenario(plans, 64);
    let probe_engine =
        build_mutation_engine(&probe_scenario.rule_suite, base_run_cfg).expect("build engine");
    let required = probe_engine.required_overlap() as u32;
    let mut run_cfg = base_run_cfg.clone();
    run_cfg.adjust_for_overlap(required);

    // Second pass: rebuild with noise_len = required_overlap so padding is
    // wide enough for the engine's search radius. The engine is reused since
    // rules are identical regardless of noise_len and synthetic_tuning does
    // not depend on overlap/chunk_size.
    let noise_len = required as usize;
    let (scenario, cases, actual_noise) = build_mutation_scenario(plans, noise_len);
    (scenario, cases, actual_noise, probe_engine, run_cfg)
}

#[test]
fn bounded_random_mutation_scanner_sims() {
    let deep = env_bool("SIM_MUTATION_DEEP", false);
    let seed_start = env_u64("SIM_MUTATION_SEED_START", 0);
    let seed_count = env_u64("SIM_MUTATION_SEED_COUNT", DEFAULT_SEED_COUNT);
    let plans_per_family = env_u32("SIM_MUTATION_PLANS_PER_FAMILY", if deep { 3 } else { 1 });

    let base_run_cfg = RunConfig {
        workers: 2,
        chunk_size: 48,
        overlap: 128,
        max_in_flight_objects: 16,
        buffer_pool_cap: 8,
        max_file_size: u64::MAX,
        max_steps: 0,
        max_transform_depth: 0,
        scan_utf16_variants: false,
        archive: ArchiveConfig::default(),
        stability_runs: 1,
        archive_deadline_countdown: None,
    };

    let empty_fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    for seed in seed_start..seed_start.saturating_add(seed_count) {
        let mut rng = SimRng::new(seed.wrapping_add(0xA1B2_CAFE));
        let plans = random_mutation_plans_all_families(&mut rng, plans_per_family);

        let (scenario, cases, noise_len, engine, run_cfg) =
            build_mutation_sim(&plans, &base_run_cfg);

        let schedule_seed = seed.wrapping_add(0xC0FF_EE00);
        let runner = ScannerSimRunner::new(run_cfg.clone(), schedule_seed);
        let (outcome, _trace) = runner.run_with_trace(&scenario, &engine, &empty_fault_plan);

        match outcome {
            RunOutcome::Ok { findings } => {
                let check = check_mutation_expectations(&cases, noise_len, &findings);
                if !check.passed() {
                    if std::env::var_os("SCANNER_SIM_WRITE_FAIL").is_some() {
                        write_mutation_failure(seed, &plans, &run_cfg, check.violations());
                    }
                    let msgs: Vec<&str> = check
                        .violations()
                        .iter()
                        .map(|v| v.message.as_str())
                        .collect();
                    panic!("mutation check failed (seed {seed}):\n{}", msgs.join("\n"));
                }
            }
            RunOutcome::Failed(fail) => {
                if std::env::var_os("SCANNER_SIM_WRITE_FAIL").is_some() {
                    write_mutation_failure(seed, &plans, &run_cfg, &[]);
                }
                panic!("scanner sim failed (seed {seed}): {fail:?}");
            }
        }
    }
}

fn write_mutation_failure(
    seed: u64,
    plans: &[MutationPlan],
    run_config: &RunConfig,
    violations: &[MutationViolation],
) {
    // Write directly to the corpus replay directory so that captured failure
    // artifacts are automatically picked up by `replay_mutation_corpus_cases`.
    let out_dir = "tests/corpus/scanner_mutation";
    if let Err(err) = fs::create_dir_all(out_dir) {
        eprintln!("mutation sim: failed to create {out_dir}: {err}");
        return;
    }

    #[derive(serde::Serialize)]
    struct MutationFailArtifact<'a> {
        seed: u64,
        run_config: &'a RunConfig,
        plans: &'a [MutationPlan],
        violation_messages: Vec<String>,
    }

    let artifact = MutationFailArtifact {
        seed,
        run_config,
        plans,
        violation_messages: violations.iter().map(|v| v.message.clone()).collect(),
    };

    let path = format!("{out_dir}/mutation_seed_{seed}.mutation.case.json");
    match serde_json::to_string_pretty(&artifact) {
        Ok(json) => {
            if let Err(err) = fs::write(&path, json) {
                eprintln!("mutation sim: failed to write {path}: {err}");
            }
        }
        Err(err) => {
            eprintln!("mutation sim: failed to serialize artifact: {err}");
        }
    }
}
