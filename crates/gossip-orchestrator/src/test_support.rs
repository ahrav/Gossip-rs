//! Shared test fixtures for the orchestrator crate.

use gossip_coordination::{CursorSemantics, RunConfig};

/// Default run configuration for orchestrator unit tests.
pub(crate) fn run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30_000, Some(5))
        .expect("run config should be valid")
}
