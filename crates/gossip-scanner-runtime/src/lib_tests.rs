//! Runtime tests for config parsing, path validation, and placeholder family
//! boundaries.

use std::fs;
use std::path::Path;
use std::process::Command;

use tempfile::tempdir;

use super::*;

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git command should run");
    assert!(
        output.status.success(),
        "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
        repo.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn create_test_repo(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    run_git(dir.path(), &["init", "-q"]);
    run_git(
        dir.path(),
        &["config", "user.email", "scanner-runtime-tests@example.com"],
    );
    run_git(
        dir.path(),
        &["config", "user.name", "Scanner Runtime Tests"],
    );

    for (path, contents) in files {
        let full = dir.path().join(path);
        if let Some(parent) = full.parent() {
            fs::create_dir_all(parent).expect("create parent directory");
        }
        fs::write(full, contents).expect("write fixture file");
    }

    if !files.is_empty() {
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);
    }

    dir
}

#[test]
fn parse_execution_mode_valid_values() {
    assert_eq!(
        "direct".parse::<ExecutionMode>().unwrap(),
        ExecutionMode::Direct
    );
    assert_eq!(
        "CONNECTOR".parse::<ExecutionMode>().unwrap(),
        ExecutionMode::Connector
    );
    assert_eq!(
        "  direct  ".parse::<ExecutionMode>().unwrap(),
        ExecutionMode::Direct
    );
}

#[test]
fn parse_execution_mode_invalid_value_mentions_input() {
    let err = "unknown".parse::<ExecutionMode>().unwrap_err();
    assert!(err.to_string().contains("unknown"));
}

#[test]
fn cancellation_token_transitions_to_cancelled() {
    let token = CancellationToken::new();
    assert!(!token.is_cancelled());
    token.cancel();
    assert!(token.is_cancelled());
}

#[test]
fn scan_budgets_reject_zero_items() {
    let error = ScanBudgets {
        max_items: 0,
        max_bytes: 1,
    }
    .validate()
    .expect_err("zero items should fail");
    assert!(matches!(error, ScanRuntimeError::ConnectorInput(_)));
}

#[test]
fn scan_budgets_reject_zero_bytes() {
    let error = ScanBudgets {
        max_items: 1,
        max_bytes: 0,
    }
    .validate()
    .expect_err("zero bytes should fail");
    assert!(matches!(error, ScanRuntimeError::ConnectorInput(_)));
}

#[test]
fn scan_fs_direct_rejects_nonexistent_path() {
    let error = scan_fs_direct(&FsScanConfig::new("/no/such/path"))
        .expect_err("nonexistent path should fail");
    assert!(matches!(
        error,
        ScanRuntimeError::InvalidPath {
            source: "filesystem",
            ..
        }
    ));
}

#[test]
fn scan_fs_direct_returns_placeholder_error_after_validation() {
    let dir = tempdir().expect("tempdir");
    let error = scan_fs_direct(&FsScanConfig::new(dir.path())).expect_err("placeholder");
    assert!(matches!(error, ScanRuntimeError::Driver(_)));
    assert!(error.to_string().contains("ordered-content"));
}

#[test]
fn scan_fs_connector_matches_direct_placeholder_shape() {
    let dir = tempdir().expect("tempdir");
    let direct = scan_fs(&FsScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Direct))
        .expect_err("direct placeholder");
    let connector =
        scan_fs(&FsScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Connector))
            .expect_err("connector placeholder");

    assert!(matches!(direct, ScanRuntimeError::Driver(_)));
    assert!(matches!(connector, ScanRuntimeError::Driver(_)));
}

#[test]
fn scan_git_direct_rejects_missing_repo() {
    let error = scan_git_direct(&GitScanConfig::new("/definitely/missing/repo"))
        .expect_err("missing path should fail");
    assert!(matches!(
        error,
        ScanRuntimeError::InvalidPath { source: "git", .. }
    ));
}

#[test]
fn scan_git_direct_rejects_non_repo_directory() {
    let dir = tempdir().expect("tempdir");
    let error = scan_git_direct(&GitScanConfig::new(dir.path())).expect_err("non-repo");
    assert!(matches!(
        error,
        ScanRuntimeError::GitCommandFailed { .. } | ScanRuntimeError::Io { .. }
    ));
}

#[test]
fn scan_git_rejects_subdirectory_of_repo() {
    let repo = create_test_repo(&[("sub/a.txt", b"password=alpha")]);
    let subdir = repo.path().join("sub");
    let error = scan_git_direct(&GitScanConfig::new(&subdir)).expect_err("subdirectory");
    assert!(matches!(
        error,
        ScanRuntimeError::InvalidPath { source: "git", .. }
    ));
}

#[test]
fn scan_git_direct_returns_placeholder_error_after_validation() {
    let repo = create_test_repo(&[("secret.txt", b"password=test-password-fixture")]);
    let error = scan_git_direct(&GitScanConfig::new(repo.path())).expect_err("placeholder");
    assert!(matches!(error, ScanRuntimeError::Driver(_)));
    assert!(error.to_string().contains("git-repo"));
}

#[test]
fn fs_config_clamps_zero_workers_to_one() {
    let config = FsScanConfig::new("/tmp").with_workers(0);
    assert_eq!(config.workers, 1, "zero workers must be clamped to 1");
}

#[test]
fn git_config_clamps_zero_workers_to_one() {
    let config = GitScanConfig::new("/tmp").with_workers(0);
    assert_eq!(config.workers, 1, "zero workers must be clamped to 1");
}
