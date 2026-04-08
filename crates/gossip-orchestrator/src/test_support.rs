//! Shared test fixtures for the orchestrator crate.

use gossip_coordination::{CursorSemantics, RunConfig};

pub(crate) use gossip_stdx::git_test_support::{
    init_committed_repo, init_git_repo, run_git as run_git_in,
};

/// Default run configuration for orchestrator unit tests.
pub(crate) fn run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30_000, Some(5))
        .expect("run config should be valid")
}
