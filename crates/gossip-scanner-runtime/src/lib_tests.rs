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

// ── Connector-mode filesystem path ─────────────────────────────

#[test]
fn scan_fs_connector_scans_directory() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), "password=alpha").expect("write a");
    fs::write(dir.path().join("b.txt"), "token=bravo").expect("write b");

    let outcome = scan_fs_connector(&FsScanConfig::new(dir.path())).expect("connector scan");
    assert!(outcome.pages_scanned() >= 1);
    assert!(outcome.items_scanned() >= 2);
    assert!(outcome.findings_emitted() >= 2);
}

#[test]
fn scan_fs_connector_scans_single_file() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("secret.txt");
    fs::write(&file_path, "password=hunter2").expect("write");

    let outcome = scan_fs_connector(&FsScanConfig::new(&file_path)).expect("single file scan");
    assert_eq!(outcome.pages_scanned(), 1);
    assert_eq!(outcome.items_scanned(), 1);
}

#[test]
fn scan_fs_direct_and_connector_match_for_directory() {
    // Structural note: direct mode uses ShardSpec::with_range([], []) (unbounded)
    // while connector mode uses connector_mode_shard_spec() (bounded [0x00, 0xff..ff)).
    // ScannerCore currently does not filter by key range, so counters match for
    // identical input files. If key-range filtering is ever added, this test
    // would need to compare actual findings, not just aggregate counters.
    let dir = tempdir().expect("tempdir");
    for i in 0..5 {
        fs::write(
            dir.path().join(format!("secret_{i}.txt")),
            format!("password=alpha{i}"),
        )
        .expect("write");
    }

    // max_items: 1 forces multi-page execution, exercising page-boundary
    // behavior in both modes (connector mode uses the scan loop with
    // checkpoint/complete transitions; direct mode uses
    // scan_from_connector_pages).
    let budgets = ScanBudgets {
        max_items: 1,
        max_bytes: 1_000_000,
    };
    let direct =
        scan_fs(&FsScanConfig::new(dir.path()).with_budgets(budgets)).expect("direct outcome");
    let connector = scan_fs(
        &FsScanConfig::new(dir.path())
            .with_budgets(budgets)
            .with_execution_mode(ExecutionMode::Connector),
    )
    .expect("connector outcome");

    assert_eq!(
        direct.pages_scanned(),
        connector.pages_scanned(),
        "page count mismatch"
    );
    assert_eq!(
        direct.items_scanned(),
        connector.items_scanned(),
        "item count mismatch"
    );
    assert_eq!(
        direct.findings_emitted(),
        connector.findings_emitted(),
        "finding count mismatch"
    );
    assert_eq!(
        direct.diagnostics_emitted(),
        connector.diagnostics_emitted(),
        "diagnostic count mismatch"
    );
}

// ── Connector-mode gating (git only) ─────────────────────────────

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

// ── Shard op-log scope after session creation ───────────────────

#[test]
fn shard_op_log_accepts_op_id_one_after_session_creation() {
    // register_shards stores its OpId in the RUN's op log, not the shard's.
    // The shard op log starts empty, so OpId::from_raw(1) must be available
    // for the first shard-level checkpoint.
    let shard = connector_mode_shard_spec();
    let mut coordinator = InMemoryCoordinator::new(CONNECTOR_MODE_LEASE_DURATION_TICKS);
    let mut session =
        create_runtime_worker_session(&mut coordinator, &shard).expect("session creation");

    // If register_shards had occupied shard op log slot 1, this would fail
    // with OpIdConflict.
    let cursor = CursorUpdate::new(&[0x01]);
    let result = session.checkpoint(LogicalTime::from_raw(4), &cursor, OpId::from_raw(1));
    assert!(
        result.is_ok(),
        "OpId::from_raw(1) should be available in shard op log: {result:?}"
    );
}

// ── Error source chain for ScanLoopLeaseLost ────────────────────

#[test]
fn lease_lost_with_renew_failed_exposes_error_source() {
    use std::error::Error;

    let error = ScanRuntimeError::ScanLoopLeaseLost {
        pages_completed: 5,
        cause: LeaseLossCause::RenewFailed(gossip_coordination::RenewError::LeaseExpired {
            deadline: LogicalTime::from_raw(100),
            now: LogicalTime::from_raw(200),
        }),
    };

    // source() should expose the inner RenewError for error-chain traversal.
    assert!(
        error.source().is_some(),
        "ScanLoopLeaseLost with RenewFailed cause should expose source()"
    );
}

#[test]
fn lease_lost_with_deadline_elapsed_has_no_source() {
    use std::error::Error;

    let error = ScanRuntimeError::ScanLoopLeaseLost {
        pages_completed: 0,
        cause: LeaseLossCause::DeadlineElapsed {
            now: LogicalTime::from_raw(200),
            deadline: LogicalTime::from_raw(100),
        },
    };

    // DeadlineElapsed has no inner error to expose.
    assert!(
        error.source().is_none(),
        "ScanLoopLeaseLost with DeadlineElapsed should have no source"
    );
}
