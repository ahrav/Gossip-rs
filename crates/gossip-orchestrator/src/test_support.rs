//! Shared test fixtures for the orchestrator crate.

use std::path::Path;
use std::process::Command;

use gossip_coordination::{CursorSemantics, RunConfig};

/// Default run configuration for orchestrator unit tests.
pub(crate) fn run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30_000, Some(5))
        .expect("run config should be valid")
}

pub(crate) fn run_git_in(dir: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git command");
    assert!(
        output.status.success(),
        "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
        dir.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

pub(crate) fn init_git_repo(dir: &Path, email: &str, name: &str) {
    run_git_in(dir, &["init", "-q"]);
    run_git_in(dir, &["config", "user.email", email]);
    run_git_in(dir, &["config", "user.name", name]);
}
