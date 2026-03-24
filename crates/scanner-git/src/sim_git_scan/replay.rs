//! Replay support for Git simulation artifacts.
//!
//! Provides helpers to load `.case.json` artifacts and replay them with the
//! embedded deterministic schedule seed. This is intended for the simulation
//! harness (`sim-harness` feature) so that a failing case can be reproduced
//! without consulting external state.

use super::artifact::GitReproArtifact;
use super::runner::{GitSimRunner, RunOutcome};

#[cfg(feature = "sim-harness")]
use std::fs;
#[cfg(feature = "sim-harness")]
use std::io;
#[cfg(feature = "sim-harness")]
use std::path::Path;

/// Errors returned while loading replay artifacts.
#[cfg(feature = "sim-harness")]
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("replay I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("replay JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Load a replay artifact from JSON bytes.
#[cfg(feature = "sim-harness")]
pub fn load_artifact(bytes: &[u8]) -> Result<GitReproArtifact, ReplayError> {
    Ok(serde_json::from_slice(bytes)?)
}

/// Load and replay a Git simulation artifact from JSON bytes.
#[cfg(feature = "sim-harness")]
pub fn replay_artifact_bytes(bytes: &[u8]) -> Result<RunOutcome, ReplayError> {
    let artifact = load_artifact(bytes)?;
    Ok(replay_artifact(&artifact))
}

/// Load and replay a Git simulation artifact from disk.
#[cfg(feature = "sim-harness")]
pub fn replay_artifact_path(path: &Path) -> Result<RunOutcome, ReplayError> {
    let bytes = fs::read(path)?;
    replay_artifact_bytes(&bytes)
}

/// Replay a Git simulation artifact with deterministic settings.
///
/// Uses the `run_config` and `schedule_seed` embedded in the artifact to ensure
/// the schedule and the run parameters match the original failing case.
#[must_use]
pub fn replay_artifact(artifact: &GitReproArtifact) -> RunOutcome {
    let runner = GitSimRunner::new(artifact.run_config.clone(), artifact.schedule_seed);
    runner.run(&artifact.scenario, &artifact.fault_plan)
}
