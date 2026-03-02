use std::{fs, path::Path, process::Command};

use rstest::rstest;
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

#[rstest]
#[case::lowercase_direct("direct", ExecutionMode::Direct)]
#[case::uppercase_direct("DIRECT", ExecutionMode::Direct)]
#[case::lowercase_connector("connector", ExecutionMode::Connector)]
#[case::uppercase_connector("CONNECTOR", ExecutionMode::Connector)]
#[case::mixed_case("DiReCt", ExecutionMode::Direct)]
#[case::padded("  direct  ", ExecutionMode::Direct)]
fn parse_execution_mode_valid(#[case] input: &str, #[case] expected: ExecutionMode) {
    assert_eq!(input.parse::<ExecutionMode>().unwrap(), expected);
}

#[rstest]
#[case::unknown("unknown")]
#[case::empty("")]
#[case::numeric("42")]
fn parse_execution_mode_invalid(#[case] input: &str) {
    let err = input.parse::<ExecutionMode>().unwrap_err();
    let display = err.to_string();
    assert!(
        display.contains(input),
        "Display should include the raw input '{input}', got: {display}"
    );
}

#[test]
fn scan_fs_direct_scans_directory() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), "password=alpha").expect("write a");
    fs::write(dir.path().join("b.txt"), "token=bravo").expect("write b");

    let outcome = scan_fs_direct(&FsScanConfig::new(dir.path())).expect("fs direct scan");
    assert!(outcome.items_scanned >= 2);
    assert!(outcome.findings_emitted >= 2);
}

#[test]
fn scan_fs_connector_matches_direct_for_directory() {
    let dir = tempdir().expect("tempdir");
    for i in 0..6 {
        fs::write(
            dir.path().join(format!("secret_{i}.txt")),
            format!("password=alpha{i}"),
        )
        .expect("write fixture file");
    }

    let budgets = ScanBudgets {
        max_items: 1,
        max_bytes: 1_000_000,
    };

    let direct = scan_fs(
        &FsScanConfig::new(dir.path())
            .with_budgets(budgets)
            .with_execution_mode(ExecutionMode::Direct),
    )
    .expect("direct outcome");

    let connector = scan_fs(
        &FsScanConfig::new(dir.path())
            .with_budgets(budgets)
            .with_execution_mode(ExecutionMode::Connector),
    )
    .expect("connector outcome");

    assert_eq!(direct.items_scanned, connector.items_scanned);
    assert_eq!(direct.findings_emitted, connector.findings_emitted);
}

#[rstest]
#[case::zero_items(ScanBudgets {
    max_items: 0,
    max_bytes: 1_000_000,
})]
#[case::zero_bytes(ScanBudgets {
    max_items: 256,
    max_bytes: 0,
})]
fn scan_fs_rejects_zero_budgets(#[case] budgets: ScanBudgets) {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), "password=alpha").expect("write fixture");

    let error = scan_fs_direct(&FsScanConfig::new(dir.path()).with_budgets(budgets))
        .expect_err("zero budgets should fail");
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
fn scan_git_direct_scans_repo() {
    let repo = create_test_repo(&[("a.txt", b"password=alpha"), ("b.txt", b"token=bravo")]);

    let outcome = scan_git_direct(&GitScanConfig::new(repo.path())).expect("git direct scan");
    assert!(outcome.items_scanned >= 2);
    assert!(outcome.findings_emitted >= 2);
}

#[test]
fn scan_git_connector_matches_direct_for_repo() {
    let repo = create_test_repo(&[("a.txt", b"password=alpha"), ("b.txt", b"token=bravo")]);
    let budgets = ScanBudgets {
        max_items: 1,
        max_bytes: 1_000_000,
    };

    let direct = scan_git(
        &GitScanConfig::new(repo.path())
            .with_budgets(budgets)
            .with_execution_mode(ExecutionMode::Direct),
    )
    .expect("direct outcome");

    let connector = scan_git(
        &GitScanConfig::new(repo.path())
            .with_budgets(budgets)
            .with_execution_mode(ExecutionMode::Connector),
    )
    .expect("connector outcome");

    assert_eq!(direct.items_scanned, connector.items_scanned);
    assert_eq!(direct.findings_emitted, connector.findings_emitted);
}

#[test]
fn scan_git_direct_errors_for_non_repo() {
    let dir = tempdir().expect("tempdir");
    let error = scan_git_direct(&GitScanConfig::new(dir.path())).expect_err("non-repo");
    assert!(matches!(
        error,
        ScanRuntimeError::GitCommandFailed { .. } | ScanRuntimeError::Io { .. }
    ));
}

#[test]
fn scan_git_direct_errors_for_missing_repo() {
    let error = scan_git_direct(&GitScanConfig::new("/definitely/missing/repo"))
        .expect_err("missing path should fail");
    assert!(matches!(
        error,
        ScanRuntimeError::InvalidPath { source: "git", .. }
    ));
}

#[test]
fn scan_git_rejects_subdirectory_of_repo() {
    let repo = create_test_repo(&[("sub/a.txt", b"password=alpha")]);
    let subdir = repo.path().join("sub");
    assert!(subdir.is_dir(), "subdirectory must exist");

    // A subdirectory inside a git repo is not a repo root. Validation
    // should reject it early rather than letting it through to a confusing
    // runtime error from GitRepoPaths::resolve.
    let result = scan_git_direct(&GitScanConfig::new(&subdir));
    assert!(
        result.is_err(),
        "subdirectory of a repo should not be accepted as a git scan root; got {:?}",
        result,
    );
}
