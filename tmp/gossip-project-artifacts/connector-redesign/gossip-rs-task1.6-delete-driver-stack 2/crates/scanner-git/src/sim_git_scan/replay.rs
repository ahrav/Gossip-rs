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
#[derive(Debug)]
pub enum ReplayError {
    Io(io::Error),
    Json(serde_json::Error),
}

#[cfg(feature = "sim-harness")]
impl std::fmt::Display for ReplayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(err) => write!(f, "replay I/O error: {err}"),
            Self::Json(err) => write!(f, "replay JSON error: {err}"),
        }
    }
}

#[cfg(feature = "sim-harness")]
impl std::error::Error for ReplayError {}

#[cfg(feature = "sim-harness")]
impl From<io::Error> for ReplayError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

#[cfg(feature = "sim-harness")]
impl From<serde_json::Error> for ReplayError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
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
