use std::{io::Write, path::Path, process::Command};

use gossip_contracts::connector::{ConnectorCapabilities, EnumerationPage};
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
    let display = err.to_string();
    assert!(
        display.contains(input),
        "Display should include the raw input '{input}', got: {display}"
    );
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

// ── Connector-mode git path ─────────────────────────────────────

#[test]
fn scan_git_connector_scans_repo() {
    let repo = create_test_repo(&[("a.txt", b"password=alpha"), ("b.txt", b"token=bravo")]);

    let outcome = scan_git_connector(&GitScanConfig::new(repo.path())).expect("connector scan");
    assert!(outcome.pages_scanned() >= 1);
    assert!(outcome.items_scanned() >= 2);
    assert!(outcome.findings_emitted() >= 2);
}

#[test]
fn scan_git_direct_and_connector_match_for_repo() {
    let repo = create_test_repo(&[("a.txt", b"password=alpha"), ("b.txt", b"token=bravo")]);

    let budgets = ScanBudgets {
        max_items: 1,
        max_bytes: 1_000_000,
    };
    let direct =
        scan_git(&GitScanConfig::new(repo.path()).with_budgets(budgets)).expect("direct outcome");
    let connector = scan_git(
        &GitScanConfig::new(repo.path())
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

// ── Cursor stall detection (F1) ─────────────────────────────────

/// Test connector that returns one non-empty page but never advances its cursor.
struct StallingConnector {
    called: bool,
}

impl StallingConnector {
    fn new() -> Self {
        Self { called: false }
    }
}

impl EnumerationConnector for StallingConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: false,
            token_resume: false,
            range_read: false,
            split_hints: false,
        }
    }

    fn enumerate_page(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        if self.called {
            // Safety net: if stall detection fails to fire, return empty to
            // prevent an actual infinite loop in the test runner.
            return Ok(EnumerationPage::new(vec![], Cursor::initial()));
        }
        self.called = true;

        let tag = ConnectorTag::from_ascii(b"test");
        let key = ItemKey::try_from_slice(b"stall-key").expect("key");
        let item_ref = ItemRef::try_from_slice(b"stall-ref").expect("ref");
        let stable_id = ItemIdentityKey::new(tag, b"stall-key").stable_id();
        let version = VersionId::Weak(ObjectVersionId::from_version_bytes(b"v1"));
        let item = ScanItem::new(key, item_ref, stable_id, version);

        // Return items but keep the cursor at initial — this is the stall.
        Ok(EnumerationPage::new(vec![item], Cursor::initial()))
    }
}

#[test]
fn scan_from_connector_pages_detects_cursor_stall() {
    let mut connector = StallingConnector::new();
    let scanner = ScannerCore::default();
    let shard = ShardSpec::with_range([], []);
    let budgets = Budgets::try_new(256, 1_000_000, None).expect("budgets");

    let err =
        scan_from_connector_pages(&mut connector, &scanner, &shard, budgets).expect_err("stall");
    assert!(
        matches!(err, ScanRuntimeError::CursorStalled { page_num: 1 }),
        "expected CursorStalled {{ page_num: 1 }}, got: {err}"
    );
}

// ── Git path traversal rejection (F2) ───────────────────────────
//
// Modern git rejects `..` paths at the index level, so we cannot inject a
// literal `../escape.txt` entry through `git update-index`. Instead we
// test the `Component::ParentDir` filtering predicate directly (the exact
// guard at lib.rs:567-572) and verify it correctly classifies traversal
// paths.

#[test]
fn parent_dir_component_filter_rejects_traversal_paths() {
    use std::path::{Component, Path};

    // The predicate used in scan_git_direct to reject `..` paths.
    let has_parent_dir = |p: &Path| p.components().any(|c| matches!(c, Component::ParentDir));

    // Paths that should be rejected.
    assert!(has_parent_dir(Path::new("../escape.txt")));
    assert!(has_parent_dir(Path::new("sub/../../escape.txt")));
    assert!(has_parent_dir(Path::new("a/b/../../../etc/passwd")));

    // Paths that should be allowed.
    assert!(!has_parent_dir(Path::new("normal.txt")));
    assert!(!has_parent_dir(Path::new("sub/normal.txt")));
    assert!(!has_parent_dir(Path::new("a/b/c/deep.txt")));
}

/// End-to-end: a normal git repo with no traversal paths scans cleanly.
/// This complements the predicate test above by proving the guard does not
/// interfere with legitimate paths in a real git repository.
#[test]
fn scan_git_direct_accepts_normal_paths_through_traversal_filter() {
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

    fs::create_dir_all(repo.join("sub")).expect("mkdir sub");
    fs::write(repo.join("sub/normal.txt"), "secret_key=abc123").expect("write");
    fs::write(repo.join("root.txt"), "token=xyz").expect("write root");
    std::process::Command::new("git")
        .args(["add", "."])
        .current_dir(repo)
        .output()
        .expect("git add");

    let outcome = scan_git_direct(&GitScanConfig::new(repo)).expect("git direct scan");
    assert_eq!(
        outcome.items_scanned(),
        2,
        "both normal files should pass the traversal filter"
    );
}

// ── Git symlink containment (F3) ────────────────────────────────

#[cfg(unix)]
#[test]
fn scan_git_direct_excludes_symlink_outside_repo_boundary() {
    let dir = tempdir().expect("tempdir");
    let repo = dir.path();

    // Init a git repo.
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

    // Create a tracked normal file inside the repo.
    fs::write(repo.join("inside.txt"), "secret_key=abc123").expect("write inside");
    std::process::Command::new("git")
        .args(["add", "inside.txt"])
        .current_dir(repo)
        .output()
        .expect("git add inside");

    // Create a file outside the repo and a symlink inside pointing to it.
    // We need a truly outside file, so create a sibling tempdir.
    let outside_dir = tempdir().expect("outside tempdir");
    let outside_path = outside_dir.path().join("sensitive.txt");
    fs::write(&outside_path, "password=supersecret").expect("write outside");

    let link_path = repo.join("link.txt");
    std::os::unix::fs::symlink(&outside_path, &link_path).expect("symlink");

    // Track the symlink in git.
    std::process::Command::new("git")
        .args(["add", "link.txt"])
        .current_dir(repo)
        .output()
        .expect("git add link");

    let outcome = scan_git_direct(&GitScanConfig::new(repo)).expect("git direct scan");

    // The symlink should be excluded by the `!metadata.is_file()` check
    // (symlink_metadata returns symlink type, not file type) and/or the
    // canonicalization containment check. Only inside.txt should be scanned.
    assert_eq!(
        outcome.items_scanned(),
        1,
        "symlink pointing outside repo should be excluded"
    );
}

// ── Heap-allocation path in build_scan_item (F9) ────────────────

#[test]
fn scan_fs_direct_exercises_heap_allocation_for_long_path() {
    let dir = tempdir().expect("tempdir");

    // build_scan_item uses a stack buffer for paths <= 128 bytes and falls
    // back to heap allocation for longer paths. Create a deeply nested path
    // that exceeds 128 bytes total to exercise the heap path.
    let deep_name = "a".repeat(140);
    let nested_dir = dir.path().join(&deep_name);
    fs::create_dir_all(&nested_dir).expect("mkdir deep");

    let file_path = nested_dir.join("secret.txt");
    fs::write(&file_path, "password=hunter2").expect("write");

    // Verify the path actually exceeds the INLINE_CAP threshold.
    let path_len = file_path.as_os_str().len();
    assert!(
        path_len > 128,
        "path must exceed 128 bytes for heap path, got {path_len}"
    );

    let outcome = scan_fs_direct(&FsScanConfig::new(&file_path)).expect("long-path scan");
    assert_eq!(outcome.items_scanned(), 1);
    assert!(
        outcome.findings_emitted() >= 1,
        "should emit at least 1 finding"
    );
}
