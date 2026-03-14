//! Artifact replay entry points for the scanner simulation.
//!
//! The full runner will rebuild the engine and filesystem from the artifact
//! and re-execute the simulation. For now this is a stub that returns a
//! structured "unimplemented" failure.

use crate::sim::artifact::ReproArtifact;
use crate::sim_scanner::generator::build_engine_from_suite;
use crate::sim_scanner::runner::{FailureKind, FailureReport, RunOutcome, ScannerSimRunner};

/// Replay a previously captured artifact.
pub fn replay_artifact(artifact: &ReproArtifact) -> RunOutcome {
    let engine = match build_engine_from_suite(&artifact.scenario.rule_suite, &artifact.run_config)
    {
        Ok(engine) => engine,
        Err(err) => {
            return RunOutcome::Failed(FailureReport {
                kind: FailureKind::InvariantViolation { code: 900 },
                message: format!("failed to rebuild engine: {err}"),
                step: 0,
            });
        }
    };

    let runner = ScannerSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
    runner.run(&artifact.scenario, &engine, &artifact.fault_plan)
}
