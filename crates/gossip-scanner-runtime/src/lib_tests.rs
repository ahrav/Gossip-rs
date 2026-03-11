//! Integration-leaning unit tests for runtime entry points and parity fixtures.
//!
//! These tests validate three contracts:
//! - `ExecutionMode` parsing and mode routing behavior.
//! - Baseline FS/Git scan behavior and budget validation.
//! - JSONL parity against pinned scanner-rs fixtures and distributed-vs-CLI
//!   finding-set parity on the same runtime corpus.

use std::{
    collections::BTreeSet,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::Command,
    sync::{Arc, Mutex},
};

use gossip_contracts::{
    connector::Cursor,
    coordination::ShardSpec,
    identity::{PolicyHash, TenantId, TenantSecretKey},
};
use gossip_scan_driver::{Assignment, AssignmentSource, ConnectorKind};
use rstest::rstest;
use scanner_scheduler::events::EventOutput;
use tempfile::tempdir;

use super::*;
use crate::coordination_sink::StoredCoreEvent;

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

/// Create a git fixture with optional tracked files and an initial commit when
/// at least one file is provided.
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
    // Secrets must be ≥16 chars with ≥3.5 bits/byte entropy to pass the
    // builtin `generic-api-key` rule's entropy + min_confidence gates.
    fs::write(dir.path().join("a.txt"), "password=xK9mP2qL7wN4vR8t").expect("write a");
    fs::write(dir.path().join("b.txt"), "token=aB3dE5fG7hJ9kL1m").expect("write b");

    let outcome = scan_fs_direct(&FsScanConfig::new(dir.path())).expect("fs direct scan");
    assert!(outcome.items_scanned >= 2);
    assert!(outcome.findings_emitted >= 2);
}

#[test]
fn scan_fs_connector_matches_direct_for_directory() {
    let dir = tempdir().expect("tempdir");
    // Each value must be ≥16 high-entropy chars to trigger builtin rules.
    let suffixes = ["Qr4Tz", "Wn8Xp", "Jv6Hg", "Ym3Bk", "Lf5Ds", "Ct7Nw"];
    for (i, sfx) in suffixes.iter().enumerate() {
        fs::write(
            dir.path().join(format!("secret_{i}.txt")),
            format!("password=xK9mP2qL7w{sfx}vR8t"),
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
    let repo = create_test_repo(&[
        ("a.txt", b"password=xK9mP2qL7wN4vR8t"),
        ("b.txt", b"token=aB3dE5fG7hJ9kL1m"),
    ]);

    let outcome = scan_git_direct(&GitScanConfig::new(repo.path())).expect("git direct scan");
    assert!(outcome.items_scanned >= 2);
    assert!(outcome.findings_emitted >= 2);
}

#[test]
fn scan_git_connector_matches_direct_for_repo() {
    let repo = create_test_repo(&[
        ("a.txt", b"password=xK9mP2qL7wN4vR8t"),
        ("b.txt", b"token=aB3dE5fG7hJ9kL1m"),
    ]);
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
fn git_config_normalizes_zero_workers_consistently() {
    // Construct a GitScanConfig with workers=0 via struct literal
    // (bypassing with_workers which clamps to max(1)).
    let config = GitScanConfig {
        repo: PathBuf::from("/tmp/fake-repo"),
        workers: 0,
        decode_depth: None,
        scan_binary: false,
        debug_level: GitDebugLevel::Off,
        enrich_identities: false,
        anchor_mode: AnchorMode::Manual,
        rules_file: None,
        transform_filter: TransformFilter::All,
        repo_id: 1,
        scan_mode: GitScanMode::OdbBlobFast,
        merge_mode: MergeDiffMode::AllParents,
        tree_delta_cache_mb: None,
        engine_chunk_mb: None,
        execution_mode: ExecutionMode::Direct,
        budgets: ScanBudgets::default(),
    };

    // Reproduce the runtime config construction from scan_git_with_runtime.
    let workers = config.workers.max(1);
    let runtime = config
        .budgets
        .to_execution_config_with_workers(workers)
        .expect("config should build");

    // Both fields should use the same normalized worker count.
    assert_eq!(
        runtime.workers, 1,
        "to_execution_config_with_workers should normalize 0 to 1"
    );
    assert_eq!(
        workers, 1,
        "pack_exec_workers should use the normalized worker count, not the raw config value"
    );
}

/// End-to-end check that `scan_git_direct` succeeds with `workers=0`.
///
/// Exercises the real normalization path in `scan_git_with_runtime` rather
/// than replicating the `.max(1)` logic inline. A zero-worker config must
/// be clamped to 1 internally — not panic or produce a degenerate scan.
#[test]
fn scan_git_direct_normalizes_zero_workers_end_to_end() {
    let repo = create_test_repo(&[("secret.txt", b"password=xK9mP2qL7wN4vR8t")]);
    let config = GitScanConfig {
        workers: 0,
        ..GitScanConfig::new(repo.path())
    };
    let outcome = scan_git_direct(&config).expect("workers=0 should normalize to 1 and scan");
    assert!(
        outcome.items_scanned >= 1,
        "scan with workers=0 (normalized to 1) should process at least one item"
    );
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

#[derive(Clone, Default)]
struct SharedWriter {
    bytes: Arc<Mutex<Vec<u8>>>,
}

impl SharedWriter {
    fn snapshot(&self) -> Vec<u8> {
        self.bytes.lock().expect("shared writer lock").clone()
    }
}

impl Write for SharedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.bytes
            .lock()
            .map_err(|_| io::Error::other("shared writer lock poisoned"))?
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn parity_path(relative: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("parity")
        .join(relative)
}

/// Run one filesystem assignment with the JSONL sink and return emitted bytes.
fn run_fs_jsonl(path: &Path, mode: ExecutionMode) -> Vec<u8> {
    let writer = SharedWriter::default();
    let sink = event_sink::JsonlEventSink::new(writer.clone());
    let commit = commit_sink::CliNoOpCommitSink;
    let cancel = CancellationToken::new();

    let outcome = scan_fs_with_runtime(
        &FsScanConfig::new(path)
            .with_execution_mode(mode)
            .with_budgets(ScanBudgets::default()),
        &sink,
        &commit,
        &cancel,
    )
    .expect("filesystem scan should succeed");
    assert!(outcome.report.items_scanned >= 1);

    sink.flush();
    let mut output = writer.snapshot();
    // `scan_fs_with_runtime` emits finding/progress events but no terminal
    // summary record; parity canonicalization requires throughput on summary.
    let summary = format!(
        "{{\"type\":\"summary\",\"source\":\"fs\",\"status\":\"complete\",\"elapsed_ms\":0,\"bytes_scanned\":{},\"findings_emitted\":{},\"errors\":0,\"throughput_mib_s\":0.00}}\n",
        outcome.report.bytes_scanned, outcome.report.findings_emitted
    );
    output.extend_from_slice(summary.as_bytes());
    output
}

/// Convert distributed event paths into parity-comparable relative paths.
fn normalize_distributed_path(path_bytes: &[u8], root: &Path) -> String {
    let raw = std::str::from_utf8(path_bytes).expect("path should be utf8 for fixture");
    let path = Path::new(raw);
    match path.strip_prefix(root) {
        Ok(stripped) => stripped.to_string_lossy().replace('\\', "/"),
        Err(_) => raw.replace('\\', "/"),
    }
}

#[test]
fn parity_golden_has_pinned_scanner_rs_commit() {
    let raw = fs::read_to_string(parity_path("golden/PINNED_COMMIT")).expect("pinned commit file");
    let pinned = raw.trim();
    assert_eq!(pinned.len(), 40, "pinned commit should be full SHA-1");
    assert!(
        pinned.chars().all(|ch| ch.is_ascii_hexdigit()),
        "pinned commit should be hexadecimal"
    );
}

#[test]
fn scan_fs_direct_matches_scanner_rs_golden_findings() {
    let corpus_root = parity_path("corpus/fs_golden");
    let golden_jsonl = fs::read(parity_path("golden/fs_golden.jsonl")).expect("golden jsonl");

    let actual_jsonl = run_fs_jsonl(&corpus_root, ExecutionMode::Direct);
    let actual =
        parity::canonicalize_jsonl_events_with_roots(&actual_jsonl, &[corpus_root.as_path()])
            .expect("canonicalize runtime output");
    let golden =
        parity::canonicalize_jsonl_events(&golden_jsonl).expect("canonicalize golden output");

    assert_eq!(actual.findings, golden.findings);
    assert!(actual.throughput_mib_s.is_finite());
}

#[test]
fn scan_fs_connector_matches_direct_canonical_findings() {
    let corpus_root = parity_path("corpus/fs_runtime");

    let direct_jsonl = run_fs_jsonl(&corpus_root, ExecutionMode::Direct);
    let connector_jsonl = run_fs_jsonl(&corpus_root, ExecutionMode::Connector);

    let direct =
        parity::canonicalize_jsonl_events_with_roots(&direct_jsonl, &[corpus_root.as_path()])
            .expect("canonicalize direct run");
    let connector =
        parity::canonicalize_jsonl_events_with_roots(&connector_jsonl, &[corpus_root.as_path()])
            .expect("canonicalize connector run");

    assert_eq!(direct.findings, connector.findings);
}

#[test]
fn scan_fs_distributed_matches_cli_findings_for_fixture() {
    let corpus_root = parity_path("corpus/fs_runtime");
    let cli_jsonl = run_fs_jsonl(&corpus_root, ExecutionMode::Direct);
    let cli_run =
        parity::canonicalize_jsonl_events_with_roots(&cli_jsonl, &[corpus_root.as_path()])
            .expect("canonicalize cli run");

    let lease = distributed::ShardLease {
        shard_id: std::sync::Arc::from("parity-shard"),
        assignment: Assignment {
            job_id: "parity-job".to_owned(),
            connector_kind: ConnectorKind::Filesystem,
            connector_instance_id: corpus_root.display().to_string(),
            policy_hash: PolicyHash::from_bytes([0x44; 32]),
            shard_spec: ShardSpec::with_range([], []),
            cursor: Cursor::initial(),
            source: AssignmentSource::Filesystem {
                root: corpus_root.clone(),
            },
        },
        tenant_id: TenantId::from_bytes([0xA1; 32]),
        tenant_secret_key: TenantSecretKey::from_bytes([0xB2; 32]),
    };
    let coordinator = distributed::InMemoryCoordinator::new(vec![lease]);
    let report = distributed::run_worker(
        &coordinator,
        distributed::DistributedRuntimeConfig::default(),
    )
    .expect("run distributed worker");
    assert_eq!(report.shards_scanned, 1);

    let cli_findings: BTreeSet<(String, String, u64, u64)> = cli_run
        .findings
        .iter()
        .map(|finding| {
            (
                finding.path.clone(),
                finding.rule.clone(),
                finding.start,
                finding.end,
            )
        })
        .collect();
    assert!(
        !cli_findings.is_empty(),
        "distributed parity fixture should emit at least one finding"
    );
    let distributed_findings: BTreeSet<(String, String, u64, u64)> = coordinator
        .core_events()
        .into_iter()
        .filter_map(|(_, event)| match event {
            StoredCoreEvent::Finding {
                object_path,
                start,
                end,
                rule_name,
                ..
            } => Some((
                normalize_distributed_path(&object_path, &corpus_root),
                rule_name,
                start,
                end,
            )),
            _ => None,
        })
        .collect();

    assert_eq!(cli_findings, distributed_findings);
}
