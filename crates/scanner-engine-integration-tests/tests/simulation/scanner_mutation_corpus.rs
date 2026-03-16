#![cfg(any(test, feature = "sim-harness"))]
//! Replay checked-in `.mutation.case.json` artifacts for regression prevention.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::scanner_rs::sim::fault::FaultPlan;
use crate::scanner_rs::sim::mutation::{MutationPlan, check_mutation_expectations};
use crate::scanner_rs::sim_scanner::{RunConfig, RunOutcome, ScannerSimRunner};

use super::scanner_mutation_random::build_mutation_sim;

#[derive(serde::Deserialize)]
struct MutationCorpusEntry {
    seed: u64,
    run_config: RunConfig,
    plans: Vec<MutationPlan>,
}

fn corpus_dir() -> PathBuf {
    PathBuf::from("tests")
        .join("corpus")
        .join("scanner_mutation")
}

fn list_cases(dir: &Path) -> Vec<PathBuf> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => panic!("mutation corpus dir {dir:?} exists but is unreadable: {e}"),
    };
    let mut cases: Vec<PathBuf> = entries
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| {
            path.file_name()
                .and_then(|s| s.to_str())
                .is_some_and(|name| name.ends_with(".mutation.case.json"))
        })
        .collect();
    cases.sort();
    cases
}

#[test]
fn replay_mutation_corpus_cases() {
    let dir = corpus_dir();
    let cases = list_cases(&dir);
    if cases.is_empty() {
        eprintln!("WARN: no .mutation.case.json files found in {dir:?}, corpus replay is a no-op");
        return;
    }

    let empty_fault_plan = FaultPlan {
        per_file: BTreeMap::new(),
    };

    for path in cases {
        let bytes = fs::read(&path).expect("read corpus case");
        let entry: MutationCorpusEntry = serde_json::from_slice(&bytes).expect("parse corpus case");
        assert!(!entry.plans.is_empty(), "corpus case {path:?} has no plans");

        let (scenario, gen_cases, noise_len, engine, run_config) =
            build_mutation_sim(&entry.plans, &entry.run_config);

        let schedule_seed = entry.seed.wrapping_add(0xC0FF_EE00);
        let runner = ScannerSimRunner::new(run_config, schedule_seed);
        let outcome = runner.run(&scenario, &engine, &empty_fault_plan);

        match outcome {
            RunOutcome::Ok { findings } => {
                let check = check_mutation_expectations(&gen_cases, noise_len, &findings);
                if !check.passed() {
                    let msgs: Vec<&str> = check
                        .violations()
                        .iter()
                        .map(|v| v.message.as_str())
                        .collect();
                    panic!(
                        "mutation corpus replay failed for {:?}:\n{}",
                        path,
                        msgs.join("\n"),
                    );
                }
            }
            RunOutcome::Failed(fail) => {
                panic!("mutation corpus replay failed for {:?}: {:?}", path, fail);
            }
        }
    }
}
