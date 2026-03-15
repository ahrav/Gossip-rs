//! Runtime tests for parsing, validation, and local scan execution.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::Mutex;

use serde_json::Value;
use tempfile::{NamedTempFile, tempdir};

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

fn write_runtime_rules() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("rules temp file");
    write!(
        file,
        "rules:\n  - name: \"runtime-fixture\"\n    regex: 'TOK_[A-Z0-9]{{8}}'\n    anchors: [\"TOK_\"]\n    radius: 32\n"
    )
    .expect("write rules");
    file
}

fn write_empty_rules() -> NamedTempFile {
    let mut file = NamedTempFile::new().expect("rules temp file");
    writeln!(file, "rules: []").expect("write empty rules");
    file
}

fn parse_jsonl(bytes: Vec<u8>) -> Vec<Value> {
    String::from_utf8(bytes)
        .expect("event sink output should be valid utf-8")
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).expect("event line should be valid json"))
        .collect()
}

#[derive(Default)]
struct SpyCommitSink {
    begun: Mutex<Vec<(Vec<u8>, commit_sink::ItemMeta)>>,
    batches: Mutex<Vec<(Vec<u8>, commit_sink::FindingsBatch)>>,
    finished: Mutex<Vec<Vec<u8>>>,
}

impl SpyCommitSink {
    fn begun(&self) -> Vec<(Vec<u8>, commit_sink::ItemMeta)> {
        self.begun.lock().expect("begun lock").clone()
    }

    fn batches(&self) -> Vec<(Vec<u8>, commit_sink::FindingsBatch)> {
        self.batches.lock().expect("batches lock").clone()
    }

    fn finished(&self) -> Vec<Vec<u8>> {
        self.finished.lock().expect("finished lock").clone()
    }
}

impl commit_sink::CommitSink for SpyCommitSink {
    fn begin_item(
        &self,
        item_key: &gossip_contracts::connector::ItemKey,
        meta: &commit_sink::ItemMeta,
    ) -> anyhow::Result<()> {
        self.begun
            .lock()
            .expect("begun lock")
            .push((item_key.as_bytes().to_vec(), meta.clone()));
        Ok(())
    }

    fn upsert_findings(
        &self,
        item_key: &gossip_contracts::connector::ItemKey,
        batch: &commit_sink::FindingsBatch,
    ) -> anyhow::Result<()> {
        self.batches
            .lock()
            .expect("batches lock")
            .push((item_key.as_bytes().to_vec(), batch.clone()));
        Ok(())
    }

    fn finish_item(&self, item_key: &gossip_contracts::connector::ItemKey) -> anyhow::Result<()> {
        self.finished
            .lock()
            .expect("finished lock")
            .push(item_key.as_bytes().to_vec());
        Ok(())
    }
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
fn scan_fs_direct_scans_directory_with_custom_rules() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();

    let report = scan_fs_direct(
        &FsScanConfig::new(dir.path()).with_rules_file(Some(rules.path().to_path_buf())),
    )
    .expect("filesystem scan should succeed");

    assert_eq!(report.items_scanned, 1);
    assert!(report.bytes_scanned > 0);
    assert!(report.chunks_scanned >= 1);
    assert!(report.findings_emitted >= 1);
    assert_eq!(report.errors, 0);
}

#[test]
fn scan_fs_connector_matches_direct_counters() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();
    let rules_path = rules.path().to_path_buf();
    let base = FsScanConfig::new(dir.path()).with_rules_file(Some(rules_path));

    let direct = scan_fs(&base.clone().with_execution_mode(ExecutionMode::Direct))
        .expect("direct filesystem scan");
    let connector = scan_fs(&base.with_execution_mode(ExecutionMode::Connector))
        .expect("connector filesystem scan");

    assert_eq!(connector.items_scanned, direct.items_scanned);
    assert_eq!(connector.bytes_scanned, direct.bytes_scanned);
    assert_eq!(connector.chunks_scanned, direct.chunks_scanned);
    assert_eq!(connector.findings_emitted, direct.findings_emitted);
    assert_eq!(connector.errors, direct.errors);
}

#[test]
fn scan_fs_with_runtime_emits_finding_and_summary_events() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();
    let out = scanner_scheduler::events::VecEventOutput::new();
    let cancel = CancellationToken::new();

    let outcome = scan_fs_with_runtime(
        &FsScanConfig::new(dir.path()).with_rules_file(Some(rules.path().to_path_buf())),
        &out,
        &commit_sink::CliNoOpCommitSink,
        &cancel,
    )
    .expect("filesystem scan should succeed");

    let events = parse_jsonl(out.take());
    assert!(outcome.report.findings_emitted >= 1);
    assert!(events.iter().any(|event| {
        event["type"] == "finding"
            && event["source"] == "fs"
            && event["rule"] == "runtime-fixture"
            && event["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("secret.txt"))
    }));
}

#[test]
fn scan_fs_with_runtime_forwards_persisted_findings() {
    let dir = tempdir().expect("tempdir");
    let nested = dir.path().join("nested");
    fs::create_dir_all(&nested).expect("create nested fixture dir");
    fs::write(nested.join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();
    let sink = SpyCommitSink::default();
    let cancel = CancellationToken::new();

    let outcome = scan_fs_with_runtime(
        &FsScanConfig::new(dir.path())
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_persist_findings(true),
        &NullEventOutput,
        &sink,
        &cancel,
    )
    .expect("filesystem scan should succeed");

    let begun = sink.begun();
    let batches = sink.batches();
    let finished = sink.finished();

    assert_eq!(outcome.report.items_scanned, 1);
    assert!(outcome.report.findings_emitted >= 1);
    assert_eq!(begun.len(), 1);
    assert_eq!(begun[0].0, b"nested/secret.txt".to_vec());
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].0, b"nested/secret.txt".to_vec());
    assert!(!batches[0].1.findings.is_empty());
    assert_eq!(finished, vec![b"nested/secret.txt".to_vec()]);
}

#[test]
fn scan_fs_with_runtime_uses_file_name_for_single_file_persistence_key() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("secret.txt");
    fs::write(&file_path, "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();
    let sink = SpyCommitSink::default();
    let cancel = CancellationToken::new();

    let outcome = scan_fs_with_runtime(
        &FsScanConfig::new(&file_path)
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_persist_findings(true),
        &NullEventOutput,
        &sink,
        &cancel,
    )
    .expect("single-file scan should succeed");

    let begun = sink.begun();
    let batches = sink.batches();
    let finished = sink.finished();

    assert_eq!(outcome.report.items_scanned, 1);
    assert!(outcome.report.findings_emitted >= 1);
    assert_eq!(begun.len(), 1);
    assert_eq!(begun[0].0, b"secret.txt".to_vec());
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].0, b"secret.txt".to_vec());
    assert!(!batches[0].1.findings.is_empty());
    assert_eq!(finished, vec![b"secret.txt".to_vec()]);
}

#[test]
fn scan_fs_direct_returns_rules_config_error_for_empty_rules_file() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_empty_rules();

    let error = scan_fs_direct(
        &FsScanConfig::new(dir.path()).with_rules_file(Some(rules.path().to_path_buf())),
    )
    .expect_err("empty rules file should fail");

    assert!(matches!(
        error,
        ScanRuntimeError::RulesConfig { path: Some(_), .. }
    ));
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
    let repo = create_test_repo(&[("sub/a.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let subdir = repo.path().join("sub");
    let error = scan_git_direct(&GitScanConfig::new(&subdir)).expect_err("subdirectory");
    assert!(matches!(
        error,
        ScanRuntimeError::InvalidPath { source: "git", .. }
    ));
}

#[test]
fn scan_git_direct_scans_repo_with_custom_rules() {
    let repo = create_test_repo(&[("secret.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let rules = write_runtime_rules();

    let report = scan_git_direct(
        &GitScanConfig::new(repo.path()).with_rules_file(Some(rules.path().to_path_buf())),
    )
    .expect("git scan should succeed");

    assert!(report.items_scanned > 0);
    assert!(report.bytes_scanned > 0);
    assert!(report.chunks_scanned >= 1);
    assert!(report.findings_emitted >= 1);
}

#[test]
fn scan_git_connector_matches_direct_counters() {
    let repo = create_test_repo(&[("secret.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let rules = write_runtime_rules();
    let rules_path = rules.path().to_path_buf();
    let base = GitScanConfig::new(repo.path()).with_rules_file(Some(rules_path));

    let direct = scan_git(&base.clone().with_execution_mode(ExecutionMode::Direct))
        .expect("direct git scan");
    let connector =
        scan_git(&base.with_execution_mode(ExecutionMode::Connector)).expect("connector git scan");

    assert_eq!(connector.items_scanned, direct.items_scanned);
    assert_eq!(connector.bytes_scanned, direct.bytes_scanned);
    assert_eq!(connector.chunks_scanned, direct.chunks_scanned);
    assert_eq!(connector.findings_emitted, direct.findings_emitted);
    assert_eq!(connector.errors, direct.errors);
}

#[test]
fn scan_git_with_runtime_emits_finding_events_and_debug_output() {
    let repo = create_test_repo(&[("secret.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let rules = write_runtime_rules();
    let out = scanner_git::VecEventSink::new();
    let cancel = CancellationToken::new();

    let outcome = scan_git_with_runtime(
        &GitScanConfig::new(repo.path())
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_debug_level(GitDebugLevel::Stats),
        &out,
        &cancel,
    )
    .expect("git scan should succeed");

    let debug_output = outcome.debug_output.expect("stats debug output");
    let events = parse_jsonl(out.take());

    assert!(debug_output.contains("git_debug.level=stats"));
    assert!(debug_output.contains("git.objects_scanned="));
    assert!(events.iter().any(|event| {
        event["type"] == "finding"
            && event["source"] == "git"
            && event["rule"] == "runtime-fixture"
            && event["path"]
                .as_str()
                .is_some_and(|path| path.ends_with("secret.txt"))
    }));
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

#[test]
fn scan_fs_with_runtime_returns_empty_report_when_pre_cancelled() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), "prefix TOK_ABCDEFGH suffix").expect("write fixture");
    let rules = write_runtime_rules();
    let out = scanner_scheduler::events::VecEventOutput::new();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = scan_fs_with_runtime(
        &FsScanConfig::new(dir.path()).with_rules_file(Some(rules.path().to_path_buf())),
        &out,
        &commit_sink::CliNoOpCommitSink,
        &cancel,
    )
    .expect("pre-cancelled scan should return Ok");

    assert_eq!(outcome.report, ScanReport::default());
    assert!(
        out.take().is_empty(),
        "no events should be emitted when pre-cancelled"
    );
}

#[test]
fn forward_commits_surfaces_first_commit_error() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::sync_channel;

    struct FailingCommitSink {
        call_count: AtomicUsize,
        fail_after: usize,
    }

    impl commit_sink::CommitSink for FailingCommitSink {
        fn begin_item(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
            _meta: &commit_sink::ItemMeta,
        ) -> anyhow::Result<()> {
            let n = self.call_count.fetch_add(1, Ordering::SeqCst);
            if n >= self.fail_after {
                anyhow::bail!("injected begin_item failure");
            }
            Ok(())
        }

        fn upsert_findings(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
            _batch: &commit_sink::FindingsBatch,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn finish_item(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let sink = FailingCommitSink {
        call_count: AtomicUsize::new(0),
        fail_after: 0,
    };
    let (tx, rx) = sync_channel(16);

    tx.send(CommitMessage::Batch(OwnedCommitBatch {
        object_path: b"file_a.txt".to_vec(),
        stable_item_id: gossip_contracts::identity::StableItemId::from_bytes([0x01; 32]),
        findings: Vec::new(),
    }))
    .unwrap();
    tx.send(CommitMessage::Batch(OwnedCommitBatch {
        object_path: b"file_b.txt".to_vec(),
        stable_item_id: gossip_contracts::identity::StableItemId::from_bytes([0x02; 32]),
        findings: Vec::new(),
    }))
    .unwrap();
    drop(tx);

    let result = forward_commits(&sink, rx);
    assert!(
        result.is_err(),
        "forward_commits should surface the first error"
    );
    assert!(
        result.unwrap_err().to_string().contains("injected"),
        "error message should come from the failing sink"
    );
}

#[test]
fn forward_commits_drains_channel_after_error() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc::sync_channel;

    struct CountingFailSink {
        begin_calls: AtomicUsize,
    }

    impl commit_sink::CommitSink for CountingFailSink {
        fn begin_item(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
            _meta: &commit_sink::ItemMeta,
        ) -> anyhow::Result<()> {
            let n = self.begin_calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                anyhow::bail!("first batch fails");
            }
            Ok(())
        }

        fn upsert_findings(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
            _batch: &commit_sink::FindingsBatch,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn finish_item(
            &self,
            _item_key: &gossip_contracts::connector::ItemKey,
        ) -> anyhow::Result<()> {
            Ok(())
        }
    }

    let sink = CountingFailSink {
        begin_calls: AtomicUsize::new(0),
    };
    let (tx, rx) = sync_channel(16);

    for i in 0u8..3 {
        tx.send(CommitMessage::Batch(OwnedCommitBatch {
            object_path: format!("file_{i}.txt").into_bytes(),
            stable_item_id: gossip_contracts::identity::StableItemId::from_bytes([i; 32]),
            findings: Vec::new(),
        }))
        .unwrap();
    }
    drop(tx);

    let result = forward_commits(&sink, rx);
    assert!(result.is_err());
    // All 3 messages were drained even though the first failed.
    assert_eq!(
        sink.begin_calls.load(Ordering::SeqCst),
        3,
        "all batches must be drained from the channel"
    );
}

#[test]
fn forward_commits_handles_run_loss_and_end_run_messages() {
    use std::sync::mpsc::sync_channel;

    let sink = SpyCommitSink::default();
    let (tx, rx) = sync_channel(16);

    tx.send(CommitMessage::RunLoss(
        scanner_scheduler::store::FsRunLoss {
            dropped_findings: 5,
            persistence_emit_failures: 1,
        },
    ))
    .unwrap();
    tx.send(CommitMessage::EndRun(true)).unwrap();
    drop(tx);

    let result = forward_commits(&sink, rx);
    assert!(result.is_ok(), "RunLoss and EndRun should not cause errors");
    // No begin/upsert/finish calls for non-Batch messages.
    assert!(sink.begun().is_empty());
    assert!(sink.batches().is_empty());
    assert!(sink.finished().is_empty());
}

#[test]
fn channel_store_producer_sends_run_loss_and_end_run() {
    use scanner_scheduler::store::StoreProducer;
    use std::sync::mpsc::sync_channel;

    let (tx, rx) = sync_channel(16);
    let dir = tempdir().expect("tempdir");
    let producer = ChannelStoreProducer::new(tx, dir.path().to_path_buf());

    producer
        .record_fs_run_loss(scanner_scheduler::store::FsRunLoss {
            dropped_findings: 3,
            persistence_emit_failures: 0,
        })
        .expect("record_fs_run_loss should succeed");

    producer.end_run(false).expect("end_run should succeed");

    drop(producer);

    let mut messages = Vec::new();
    while let Ok(msg) = rx.recv() {
        messages.push(msg);
    }
    assert_eq!(messages.len(), 2);
    assert!(matches!(messages[0], CommitMessage::RunLoss(_)));
    assert!(matches!(messages[1], CommitMessage::EndRun(false)));
}

#[test]
fn normalize_rejects_path_not_under_root() {
    let result = normalize_scheduler_path(Path::new("/a/b"), b"/c/d/file.txt");
    let err = result.expect_err("path not under root should fail");
    assert!(
        err.to_string().contains("not under scan root"),
        "error should mention 'not under scan root', got: {err}"
    );
}

#[test]
fn normalize_strips_root_prefix_to_relative_key() {
    let result = normalize_scheduler_path(Path::new("/a/b"), b"/a/b/sub/file.txt")
        .expect("valid path should normalize");
    assert_eq!(result, b"sub/file.txt");
}

#[test]
fn normalize_uses_file_name_for_single_file() {
    let result = normalize_scheduler_path(Path::new("/a/b/file.txt"), b"/a/b/file.txt")
        .expect("single-file path should normalize");
    assert_eq!(result, b"file.txt");
}

#[test]
fn scan_git_with_runtime_returns_empty_report_when_pre_cancelled() {
    let repo = create_test_repo(&[("secret.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let rules = write_runtime_rules();
    let out = scanner_git::VecEventSink::new();
    let cancel = CancellationToken::new();
    cancel.cancel();

    let outcome = scan_git_with_runtime(
        &GitScanConfig::new(repo.path()).with_rules_file(Some(rules.path().to_path_buf())),
        &out,
        &cancel,
    )
    .expect("pre-cancelled scan should return Ok");

    assert_eq!(outcome.report, ScanReport::default());
    assert!(
        out.take().is_empty(),
        "no events should be emitted when pre-cancelled"
    );
}
