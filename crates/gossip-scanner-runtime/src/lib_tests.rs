use std::io::Write;

use rstest::rstest;
use tempfile::tempdir;

use super::*;

// ── ExecutionMode parsing ──────────────────────────────────────

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
    assert_eq!(err.raw(), input);
}

// ── Filesystem scan integration ────────────────────────────────

#[test]
fn scan_fs_direct_scans_directory() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("a.txt");
    let mut file = fs::File::create(&file_path).expect("create file");
    writeln!(file, "hello world").expect("write file");

    let outcome = scan_fs_direct(&FsScanConfig::new(dir.path())).expect("fs direct scan");
    assert!(outcome.pages_scanned() >= 1);
    assert!(outcome.items_scanned() >= 1);
    assert!(outcome.findings_emitted() >= 1);
}

#[test]
fn scan_fs_direct_scans_single_file() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("secret.txt");
    fs::write(&file_path, "password=hunter2").expect("write");

    let outcome = scan_fs_direct(&FsScanConfig::new(&file_path)).expect("single file scan");
    assert_eq!(outcome.pages_scanned(), 1);
    assert_eq!(outcome.items_scanned(), 1);
}

#[test]
fn scan_fs_direct_rejects_nonexistent_path() {
    let err = scan_fs_direct(&FsScanConfig::new("/no/such/path")).expect_err("nonexistent path");
    assert!(matches!(
        err,
        ScanRuntimeError::InvalidPath {
            source: "filesystem",
            ..
        }
    ));
}

// ── Connector-mode gating ──────────────────────────────────────

#[test]
fn scan_fs_connector_is_explicitly_gated() {
    let dir = tempdir().expect("tempdir");
    let error =
        scan_fs(&FsScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Connector))
            .expect_err("connector mode should be gated");
    assert!(matches!(
        error,
        ScanRuntimeError::UnsupportedExecutionMode {
            source: "filesystem",
            mode: ExecutionMode::Connector,
        }
    ));
}

#[test]
fn scan_git_connector_is_explicitly_gated() {
    let dir = tempdir().expect("tempdir");
    let error =
        scan_git(&GitScanConfig::new(dir.path()).with_execution_mode(ExecutionMode::Connector))
            .expect_err("connector mode should be gated");
    assert!(matches!(
        error,
        ScanRuntimeError::UnsupportedExecutionMode {
            source: "git",
            mode: ExecutionMode::Connector,
        }
    ));
}

// ── Git scan error paths ───────────────────────────────────────

#[test]
fn scan_git_direct_errors_for_non_repo() {
    let dir = tempdir().expect("tempdir");
    let error = scan_git_direct(&GitScanConfig::new(dir.path())).expect_err("non-repo");
    assert!(matches!(
        error,
        ScanRuntimeError::GitCommandFailed { .. } | ScanRuntimeError::Io { .. }
    ));
}

// ── Git scan happy-path (F4) ────────────────────────────────────

#[test]
fn scan_git_direct_scans_tracked_files() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();

    // Init a git repo with a tracked file.
    std::process::Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(repo)
        .output()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(repo)
        .output()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(repo)
        .output()
        .expect("git config name");

    fs::write(repo.join("hello.txt"), "secret_key=abc123").expect("write");
    std::process::Command::new("git")
        .args(["add", "hello.txt"])
        .current_dir(repo)
        .output()
        .expect("git add");

    let outcome = scan_git_direct(&GitScanConfig::new(repo)).expect("git direct scan");
    assert!(outcome.items_scanned() >= 1, "should scan at least 1 item");
    assert!(
        outcome.findings_emitted() >= 1,
        "should emit at least 1 finding"
    );
}

// ── Multi-page pagination (F5) ──────────────────────────────────

#[test]
fn scan_fs_direct_paginates_large_directories() {
    let dir = tempdir().expect("tempdir");
    for i in 0..10 {
        fs::write(dir.path().join(format!("f{i:02}.txt")), "data").expect("write");
    }

    let config = FsScanConfig::new(dir.path()).with_budgets(ScanBudgets {
        max_items: 3,
        max_bytes: 1_000_000,
    });
    let outcome = scan_fs_direct(&config).expect("paginated scan");
    assert!(
        outcome.pages_scanned() >= 4,
        "10 items / 3 per page = at least 4 pages, got {}",
        outcome.pages_scanned()
    );
    assert_eq!(outcome.items_scanned(), 10);
}

// ── Too-many-tracked-files limit (F3) ───────────────────────────

#[test]
fn scan_git_direct_rejects_too_many_tracked_files() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();

    std::process::Command::new("git")
        .args(["init", "--initial-branch=main"])
        .current_dir(repo)
        .output()
        .expect("git init");
    std::process::Command::new("git")
        .args(["config", "user.email", "test@test.com"])
        .current_dir(repo)
        .output()
        .expect("git config email");
    std::process::Command::new("git")
        .args(["config", "user.name", "Test"])
        .current_dir(repo)
        .output()
        .expect("git config name");

    for i in 0..3 {
        fs::write(repo.join(format!("f{i}.txt")), "x").expect("write");
    }
    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");

    let config = GitScanConfig::new(repo).with_max_tracked_files(Some(2));
    let error = scan_git_direct(&config).expect_err("should exceed limit");
    assert!(
        matches!(
            error,
            ScanRuntimeError::TooManyTrackedFiles { count: 3, limit: 2 }
        ),
        "expected TooManyTrackedFiles, got: {error}"
    );
}

// ── Symlink rejection (F2) ──────────────────────────────────────

#[cfg(unix)]
#[test]
fn scan_fs_direct_rejects_symlink_target() {
    let dir = tempdir().expect("tempdir");
    let real_file = dir.path().join("real.txt");
    fs::write(&real_file, "data").expect("write");
    let link = dir.path().join("link.txt");
    std::os::unix::fs::symlink(&real_file, &link).expect("symlink");

    let err = scan_fs_direct(&FsScanConfig::new(&link)).expect_err("should reject symlink");
    assert!(
        matches!(err, ScanRuntimeError::InvalidPath { .. }),
        "expected InvalidPath for symlink, got: {err}"
    );
}

// ── ScanBudgets zero-value validation (F11) ─────────────────────

#[rstest]
#[case::zero_items(ScanBudgets { max_items: 0, max_bytes: 1_000_000 })]
#[case::zero_bytes(ScanBudgets { max_items: 256, max_bytes: 0 })]
fn scan_fs_direct_rejects_zero_budgets(#[case] budgets: ScanBudgets) {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), "data").expect("write");

    let config = FsScanConfig::new(dir.path()).with_budgets(budgets);
    let err = scan_fs_direct(&config).expect_err("zero budgets");
    assert!(
        matches!(err, ScanRuntimeError::ConnectorInput(_)),
        "expected ConnectorInput, got: {err}"
    );
}

// ── Empty directory (F13) ───────────────────────────────────────

#[test]
fn scan_fs_direct_handles_empty_directory() {
    let dir = tempdir().expect("tempdir");
    let outcome = scan_fs_direct(&FsScanConfig::new(dir.path())).expect("empty dir scan");
    assert_eq!(outcome.pages_scanned(), 0);
    assert_eq!(outcome.items_scanned(), 0);
    assert_eq!(outcome.findings_emitted(), 0);
    assert_eq!(outcome.diagnostics_emitted(), 0);
}
