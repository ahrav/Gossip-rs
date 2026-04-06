//! Git merge operations.
//!
//! Merges completed agent branches into section integration branches and then
//! consolidates section branches into a single result branch. All git
//! operations use `std::process::Command` because libgit2 has limited merge
//! support (no recursive strategy, no worktree management).
//!
//! The merge workflow uses detached worktrees so the main repository working
//! tree is never disturbed:
//!
//! 1. [`create_merge_worktree`] — set up a temporary worktree detached from
//!    the base branch.
//! 2. [`merge_section`] — create a section integration branch and merge each
//!    agent branch into it, skipping branches that conflict.
//! 3. [`merge_consolidated`] — create a consolidated branch from `origin/main`
//!    and merge every section branch into it.
//! 4. [`push_branch`] — push the result to the remote.
//! 5. [`cleanup_worktree`] — remove the temporary worktree and its directory.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::{Context, bail};
use tracing::{debug, warn};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// Handle to a temporary git worktree used for merging.
pub struct WorktreeHandle {
    /// Path to the worktree directory.
    pub path: PathBuf,
    /// Name used to identify this worktree.
    pub name: String,
}

/// Result of merging agent branches within a section.
#[derive(Debug)]
pub struct SectionMergeResult {
    /// Branches that merged successfully.
    pub merged: Vec<String>,
    /// Branches that had merge conflicts and were skipped.
    pub conflicts: Vec<String>,
    /// Name of the section integration branch.
    pub integration_branch: String,
}

/// Result of merging all section branches into one consolidated branch.
#[derive(Debug)]
pub struct ConsolidatedResult {
    /// Section branches that merged successfully.
    pub merged_sections: Vec<String>,
    /// Section branches that had conflicts.
    pub conflicts: Vec<String>,
    /// Name of the consolidated branch.
    pub consolidated_branch: String,
}

// ---------------------------------------------------------------------------
// Git helper
// ---------------------------------------------------------------------------

/// Run a git command in the given working directory, logging stdout/stderr.
fn git(cwd: &Path, args: &[&str]) -> anyhow::Result<Output> {
    debug!(cwd = %cwd.display(), args = ?args, "git");
    let output = Command::new("git")
        .current_dir(cwd)
        .args(args)
        .output()
        .with_context(|| format!("spawn `git {}` in {}", args.join(" "), cwd.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !stdout.is_empty() {
        debug!(stdout = %stdout.trim_end());
    }
    if !stderr.is_empty() {
        debug!(stderr = %stderr.trim_end());
    }

    Ok(output)
}

/// Run a git command and return an error when the exit code is non-zero.
fn git_ok(cwd: &Path, args: &[&str]) -> anyhow::Result<Output> {
    let output = git(cwd, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "`git {}` failed (exit {:?}) in {}: {}",
            args.join(" "),
            output.status.code(),
            cwd.display(),
            stderr.trim_end(),
        );
    }
    Ok(output)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Create a temporary git worktree detached at `origin/{base_branch}`.
///
/// The worktree lives under the system temp directory and is named
/// `fleet-merge-{run_id}`. A local git identity is configured inside the
/// worktree so commits are attributed to the fleet orchestrator.
pub fn create_merge_worktree(
    repo_path: &Path,
    base_branch: &str,
    run_id: &str,
) -> anyhow::Result<WorktreeHandle> {
    let name = format!("fleet-merge-{run_id}");
    let wt_path = std::env::temp_dir().join(&name);

    // Remove leftover worktree directory from a previous crashed run.
    if wt_path.exists() {
        let _ = std::fs::remove_dir_all(&wt_path);
        // Also prune stale worktree bookkeeping inside the repo.
        let _ = git(repo_path, &["worktree", "prune"]);
    }

    git_ok(
        repo_path,
        &[
            "worktree",
            "add",
            &wt_path.to_string_lossy(),
            &format!("origin/{base_branch}"),
            "--detach",
        ],
    )
    .with_context(|| {
        format!(
            "create worktree at {} from origin/{base_branch}",
            wt_path.display(),
        )
    })?;

    // Configure committer identity inside the worktree.
    git_ok(&wt_path, &["config", "user.name", "fleet-orchestrator"])?;
    git_ok(&wt_path, &["config", "user.email", "fleet@gossip-rs.local"])?;

    Ok(WorktreeHandle {
        path: wt_path,
        name,
    })
}

/// Merge agent branches into a section integration branch.
///
/// Creates a branch named `{branch_prefix}/section-{section_id}/{run_id}`
/// inside the worktree, then attempts to merge each agent branch. Branches
/// that produce merge conflicts are aborted and recorded in
/// [`SectionMergeResult::conflicts`].
pub fn merge_section(
    worktree: &WorktreeHandle,
    section_id: &str,
    agent_branches: &[String],
    run_id: &str,
    branch_prefix: &str,
) -> anyhow::Result<SectionMergeResult> {
    let branch_name = format!("{branch_prefix}/section-{section_id}/{run_id}");

    git_ok(&worktree.path, &["checkout", "-b", &branch_name])
        .with_context(|| format!("create section branch {branch_name}"))?;

    let mut merged = Vec::new();
    let mut conflicts = Vec::new();

    for branch in agent_branches {
        // Ensure we have the latest remote ref for this branch.
        git_ok(&worktree.path, &["fetch", "origin", branch])
            .with_context(|| format!("fetch origin/{branch}"))?;

        let merge_msg = format!("Merge {branch} guide-sync fixes");
        let output = git(
            &worktree.path,
            &[
                "merge",
                &format!("origin/{branch}"),
                "--no-edit",
                "-m",
                &merge_msg,
            ],
        )?;

        if output.status.success() {
            debug!(branch = %branch, section = %section_id, "merged successfully");
            merged.push(branch.clone());
        } else {
            warn!(
                branch = %branch,
                section = %section_id,
                "merge conflict, aborting and skipping",
            );
            let _ = git(&worktree.path, &["merge", "--abort"]);
            conflicts.push(branch.clone());
        }
    }

    Ok(SectionMergeResult {
        merged,
        conflicts,
        integration_branch: branch_name,
    })
}

/// Merge section integration branches into a single consolidated branch.
///
/// Creates `{branch_prefix}/consolidated/{run_id}` starting from
/// `origin/main`, then merges each section branch sequentially. Section
/// branches that conflict are aborted and recorded in
/// [`ConsolidatedResult::conflicts`].
pub fn merge_consolidated(
    worktree: &WorktreeHandle,
    section_branches: &[String],
    run_id: &str,
    branch_prefix: &str,
) -> anyhow::Result<ConsolidatedResult> {
    let branch_name = format!("{branch_prefix}/consolidated/{run_id}");

    git_ok(
        &worktree.path,
        &["checkout", "-b", &branch_name, "origin/main"],
    )
    .with_context(|| format!("create consolidated branch {branch_name}"))?;

    let mut merged_sections = Vec::new();
    let mut conflicts = Vec::new();

    for section_branch in section_branches {
        let merge_msg = format!("Merge {section_branch} into consolidated");
        let output = git(
            &worktree.path,
            &["merge", section_branch, "--no-edit", "-m", &merge_msg],
        )?;

        if output.status.success() {
            debug!(section_branch = %section_branch, "merged into consolidated");
            merged_sections.push(section_branch.clone());
        } else {
            warn!(
                section_branch = %section_branch,
                "conflict merging into consolidated, aborting and skipping",
            );
            let _ = git(&worktree.path, &["merge", "--abort"]);
            conflicts.push(section_branch.clone());
        }
    }

    Ok(ConsolidatedResult {
        merged_sections,
        conflicts,
        consolidated_branch: branch_name,
    })
}

/// Push the current HEAD of the worktree to a named remote branch.
pub fn push_branch(worktree: &WorktreeHandle, branch: &str) -> anyhow::Result<()> {
    git_ok(
        &worktree.path,
        &["push", "origin", &format!("HEAD:refs/heads/{branch}")],
    )
    .with_context(|| format!("push HEAD to refs/heads/{branch}"))?;
    Ok(())
}

/// Remove a worktree and its temporary directory.
///
/// Runs `git worktree remove` from the **repository root** (not the worktree
/// itself) so that the worktree bookkeeping is cleaned up correctly.
pub fn cleanup_worktree(handle: WorktreeHandle, repo_path: &Path) -> anyhow::Result<()> {
    let path_str = handle.path.to_string_lossy().to_string();
    let result = git(repo_path, &["worktree", "remove", &path_str, "--force"]);

    if let Err(e) = result {
        warn!(error = %e, path = %path_str, "git worktree remove failed, cleaning up manually");
    }

    // Belt-and-suspenders: remove the directory if the git command did not.
    if handle.path.exists() {
        std::fs::remove_dir_all(&handle.path).with_context(|| {
            format!(
                "remove leftover worktree directory {}",
                handle.path.display(),
            )
        })?;
    }

    Ok(())
}

/// Create a temporary clone for merge operations in the same repository.
///
/// Used by the audit pipeline where the target repository is the same as
/// the source. Clones into a temp directory, checks out a merge branch from
/// `origin/{base_branch}`, and configures the fleet-orchestrator identity.
/// The returned `WorktreeHandle` can be used with the same merge functions.
pub fn create_clone_worktree(
    remote_url: &str,
    base_branch: &str,
    run_id: &str,
) -> anyhow::Result<WorktreeHandle> {
    let name = format!("fleet-clone-{run_id}");
    let clone_path = std::env::temp_dir().join(&name);

    // Remove leftover directory from a previous crashed run.
    if clone_path.exists() {
        let _ = std::fs::remove_dir_all(&clone_path);
    }

    // Shallow clone (single branch) to minimise disk and network usage.
    let output = Command::new("git")
        .args([
            "clone",
            "--quiet",
            "--no-checkout",
            "--single-branch",
            "--branch",
            base_branch,
            remote_url,
            &clone_path.to_string_lossy(),
        ])
        .output()
        .context("spawn git clone for merge worktree")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "git clone failed (exit {:?}): {}",
            output.status.code(),
            stderr.trim_end()
        );
    }

    // Create a merge branch starting from origin/{base_branch}.
    let merge_branch = format!("{run_id}-merge");
    git_ok(
        &clone_path,
        &[
            "checkout",
            "-b",
            &merge_branch,
            &format!("origin/{base_branch}"),
        ],
    )
    .context("checkout merge branch in clone")?;

    // Configure committer identity.
    git_ok(&clone_path, &["config", "user.name", "fleet-orchestrator"])?;
    git_ok(
        &clone_path,
        &["config", "user.email", "fleet@gossip-rs.local"],
    )?;

    Ok(WorktreeHandle {
        path: clone_path,
        name,
    })
}

/// Merge agent branches directly into the current branch (flat merge).
///
/// Unlike `merge_section` which creates a new integration branch, this
/// function merges each agent branch into whatever branch is currently
/// checked out. Suited for the audit pipeline where all agent branches
/// merge into a single consolidated branch without intermediate grouping.
pub fn merge_flat(
    worktree: &WorktreeHandle,
    agent_branches: &[String],
) -> anyhow::Result<SectionMergeResult> {
    let mut merged = Vec::new();
    let mut conflicts = Vec::new();

    for branch in agent_branches {
        // Check that the branch exists on the remote before attempting fetch.
        let ls_output = git(
            &worktree.path,
            &[
                "ls-remote",
                "--exit-code",
                "origin",
                &format!("refs/heads/{branch}"),
            ],
        )?;

        if !ls_output.status.success() {
            debug!(branch = %branch, "no branch pushed, skipping");
            continue;
        }

        git_ok(&worktree.path, &["fetch", "origin", branch])
            .with_context(|| format!("fetch origin/{branch}"))?;

        let merge_msg = format!("Merge {branch} audit fixes");
        let output = git(
            &worktree.path,
            &[
                "merge",
                &format!("origin/{branch}"),
                "--no-edit",
                "-m",
                &merge_msg,
            ],
        )?;

        if output.status.success() {
            debug!(branch = %branch, "merged successfully");
            merged.push(branch.clone());
        } else {
            warn!(branch = %branch, "merge conflict, aborting and skipping");
            let _ = git(&worktree.path, &["merge", "--abort"]);
            conflicts.push(branch.clone());
        }
    }

    // The integration_branch field is set to the current branch name.
    let head_output = git_ok(&worktree.path, &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let current_branch = String::from_utf8_lossy(&head_output.stdout)
        .trim()
        .to_owned();

    Ok(SectionMergeResult {
        merged,
        conflicts,
        integration_branch: current_branch,
    })
}

/// Post-merge verification checks.
#[derive(Debug)]
pub struct VerificationResult {
    /// Human-readable notes (one line per check).
    pub notes: String,
    /// `true` when every check passed.
    pub all_passed: bool,
}

/// Run post-merge verification (fmt, check, doc) inside a worktree.
///
/// Non-fatal: records pass/fail for each check and returns a summary.
pub fn run_post_merge_checks(worktree: &WorktreeHandle) -> VerificationResult {
    let mut notes = Vec::new();
    let mut all_passed = true;

    let checks: &[(&str, &[&str])] = &[
        ("cargo fmt", &["cargo", "fmt", "--all", "--", "--check"]),
        ("cargo check", &["cargo", "check", "--all-features"]),
        (
            "cargo doc",
            &["cargo", "doc", "--no-deps", "--all-features"],
        ),
    ];

    for (label, args) in checks {
        let mut cmd = Command::new(args[0]);
        cmd.current_dir(&worktree.path).args(&args[1..]);

        // Set RUSTDOCFLAGS for the doc check.
        if *label == "cargo doc" {
            cmd.env("RUSTDOCFLAGS", "-D warnings");
        }

        match cmd.output() {
            Ok(output) if output.status.success() => {
                notes.push(format!("- {label}: PASSED"));
            }
            Ok(_) => {
                notes.push(format!("- {label}: FAILED"));
                all_passed = false;
            }
            Err(e) => {
                notes.push(format!("- {label}: ERROR ({e})"));
                all_passed = false;
            }
        }
    }

    VerificationResult {
        notes: notes.join("\n"),
        all_passed,
    }
}

/// Clean up a clone-based worktree (just removes the directory).
pub fn cleanup_clone(handle: WorktreeHandle) -> anyhow::Result<()> {
    if handle.path.exists() {
        std::fs::remove_dir_all(&handle.path).with_context(|| {
            format!("remove clone worktree directory {}", handle.path.display(),)
        })?;
    }
    Ok(())
}

/// Check whether a branch exists on the remote.
///
/// Uses `git ls-remote --exit-code` which returns exit code 0 when the ref
/// exists and 2 when it does not.
pub fn branch_exists_on_remote(repo_path: &Path, branch: &str) -> anyhow::Result<bool> {
    let output = git(
        repo_path,
        &[
            "ls-remote",
            "--exit-code",
            "origin",
            &format!("refs/heads/{branch}"),
        ],
    )?;

    Ok(output.status.success())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    /// Create a fresh git repository in a temporary directory for test
    /// isolation. Returns the path to the repository.
    fn init_test_repo(name: &str) -> PathBuf {
        let dir = std::env::temp_dir()
            .join("fleet_merge_tests")
            .join(name)
            .join(format!("{}", std::process::id()));

        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clean old test dir");
        }
        fs::create_dir_all(&dir).expect("create test dir");

        git_ok(&dir, &["init"]).expect("git init");
        git_ok(&dir, &["config", "user.name", "test"]).expect("config name");
        git_ok(&dir, &["config", "user.email", "test@test"]).expect("config email");

        // Create an initial commit so HEAD exists.
        let readme = dir.join("README.md");
        fs::write(&readme, "# test\n").expect("write readme");
        git_ok(&dir, &["add", "README.md"]).expect("add readme");
        git_ok(&dir, &["commit", "-m", "initial commit"]).expect("initial commit");

        dir
    }

    #[test]
    fn git_helper_captures_output() {
        let repo = init_test_repo("git_helper_output");
        let output = git_ok(&repo, &["rev-parse", "HEAD"]).unwrap();
        let sha = String::from_utf8_lossy(&output.stdout);
        // A git SHA is 40 hex characters (plus trailing newline).
        assert!(sha.trim().len() >= 40, "expected SHA, got: {sha:?}",);
    }

    #[test]
    fn git_helper_returns_error_on_bad_command() {
        let repo = init_test_repo("git_helper_error");
        let result = git_ok(&repo, &["log", "--no-such-flag-at-all"]);
        assert!(result.is_err());
    }

    #[test]
    fn branch_exists_returns_false_for_nonexistent() {
        let repo = init_test_repo("branch_exists_false");

        // Point "origin" at the repo itself so ls-remote has something to
        // query without requiring a real remote.
        git_ok(&repo, &["remote", "add", "origin", &repo.to_string_lossy()]).expect("add origin");

        let exists = branch_exists_on_remote(&repo, "no-such-branch-ever").unwrap();
        assert!(
            !exists,
            "nonexistent branch should not be reported as existing"
        );
    }

    #[test]
    fn branch_exists_returns_true_for_existing() {
        let repo = init_test_repo("branch_exists_true");

        // The default branch (main or master) exists after init+commit.
        // Determine its name so the test is not sensitive to git defaults.
        let output = git_ok(&repo, &["branch", "--show-current"]).unwrap();
        let default_branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        git_ok(&repo, &["remote", "add", "origin", &repo.to_string_lossy()]).expect("add origin");

        let exists = branch_exists_on_remote(&repo, &default_branch).unwrap();
        assert!(exists, "default branch should exist on self-remote");
    }

    #[test]
    fn worktree_create_and_cleanup() {
        let repo = init_test_repo("worktree_lifecycle");

        // Determine the default branch name.
        let output = git_ok(&repo, &["branch", "--show-current"]).unwrap();
        let default_branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        // Set up a self-referencing "origin" remote so that
        // `origin/{default_branch}` resolves.
        git_ok(&repo, &["remote", "add", "origin", &repo.to_string_lossy()]).expect("add origin");
        git_ok(&repo, &["fetch", "origin"]).expect("fetch origin");

        let run_id = format!("test-wt-{}", std::process::id());
        let handle = create_merge_worktree(&repo, &default_branch, &run_id).unwrap();

        assert!(handle.path.exists(), "worktree directory should exist");
        assert!(
            handle.path.join(".git").exists(),
            "worktree should contain a .git entry",
        );

        // Verify the git identity was configured.
        let name_out = git_ok(&handle.path, &["config", "user.name"]).unwrap();
        let name = String::from_utf8_lossy(&name_out.stdout);
        assert_eq!(name.trim(), "fleet-orchestrator");

        cleanup_worktree(handle, &repo).unwrap();
    }

    /// End-to-end section merge using branches that do not conflict.
    #[test]
    fn merge_section_no_conflicts() {
        let repo = init_test_repo("merge_section_ok");

        let output = git_ok(&repo, &["branch", "--show-current"]).unwrap();
        let default_branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        // Self-remote so origin/* refs work.
        git_ok(&repo, &["remote", "add", "origin", &repo.to_string_lossy()]).expect("add origin");
        git_ok(&repo, &["fetch", "origin"]).expect("fetch origin");

        // Create two agent branches that modify different files.
        git_ok(&repo, &["checkout", "-b", "agent/a"]).unwrap();
        fs::write(repo.join("a.txt"), "from agent a\n").unwrap();
        git_ok(&repo, &["add", "a.txt"]).unwrap();
        git_ok(&repo, &["commit", "-m", "agent a"]).unwrap();

        git_ok(&repo, &["checkout", &default_branch]).unwrap();
        git_ok(&repo, &["checkout", "-b", "agent/b"]).unwrap();
        fs::write(repo.join("b.txt"), "from agent b\n").unwrap();
        git_ok(&repo, &["add", "b.txt"]).unwrap();
        git_ok(&repo, &["commit", "-m", "agent b"]).unwrap();

        // Return to default branch and re-fetch so origin/* includes new
        // branches.
        git_ok(&repo, &["checkout", &default_branch]).unwrap();
        git_ok(&repo, &["fetch", "origin"]).expect("re-fetch");

        // Create worktree and merge.
        let run_id = format!("sec-ok-{}", std::process::id());
        let handle = create_merge_worktree(&repo, &default_branch, &run_id).unwrap();

        let branches = vec!["agent/a".to_owned(), "agent/b".to_owned()];
        let result = merge_section(&handle, "s1", &branches, &run_id, "guide-sync").unwrap();

        assert_eq!(result.merged.len(), 2);
        assert!(result.conflicts.is_empty());
        assert!(result.integration_branch.contains("section-s1"));

        cleanup_worktree(handle, &repo).unwrap();
    }

    /// Section merge where one branch conflicts with a prior merge.
    #[test]
    fn merge_section_with_conflict() {
        let repo = init_test_repo("merge_section_conflict");

        let output = git_ok(&repo, &["branch", "--show-current"]).unwrap();
        let default_branch = String::from_utf8_lossy(&output.stdout).trim().to_owned();

        git_ok(&repo, &["remote", "add", "origin", &repo.to_string_lossy()]).expect("add origin");
        git_ok(&repo, &["fetch", "origin"]).expect("fetch origin");

        // Two branches that modify the same file differently.
        git_ok(&repo, &["checkout", "-b", "agent/x"]).unwrap();
        fs::write(repo.join("shared.txt"), "version x\n").unwrap();
        git_ok(&repo, &["add", "shared.txt"]).unwrap();
        git_ok(&repo, &["commit", "-m", "agent x"]).unwrap();

        git_ok(&repo, &["checkout", &default_branch]).unwrap();
        git_ok(&repo, &["checkout", "-b", "agent/y"]).unwrap();
        fs::write(repo.join("shared.txt"), "version y\n").unwrap();
        git_ok(&repo, &["add", "shared.txt"]).unwrap();
        git_ok(&repo, &["commit", "-m", "agent y"]).unwrap();

        git_ok(&repo, &["checkout", &default_branch]).unwrap();
        git_ok(&repo, &["fetch", "origin"]).expect("re-fetch");

        let run_id = format!("sec-conflict-{}", std::process::id());
        let handle = create_merge_worktree(&repo, &default_branch, &run_id).unwrap();

        let branches = vec!["agent/x".to_owned(), "agent/y".to_owned()];
        let result = merge_section(&handle, "s2", &branches, &run_id, "guide-sync").unwrap();

        // First branch merges, second conflicts.
        assert_eq!(result.merged, vec!["agent/x"]);
        assert_eq!(result.conflicts, vec!["agent/y"]);

        cleanup_worktree(handle, &repo).unwrap();
    }
}
