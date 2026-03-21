//! Runtime tests for parsing, validation, and local scan execution.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use gossip_contracts::{
    coordination::ShardSpec,
    identity::{
        LogicalTime, OpId, PolicyHash, RunId, ShardId, TenantId, TenantSecretKey, WorkerId,
    },
};
use gossip_coordination::{
    CursorSemantics, InMemoryCoordinator as CoordinationInMemoryCoordinator, InitialShardInput,
    RunConfig, RunManagement,
};
use gossip_frontier::{ShardSpecScratch, range_shard_ref};
use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
use serde_json::Value;
use tempfile::{NamedTempFile, tempdir};

use super::*;
use crate::{
    coordination_sink::{CommitProgressRecord, CoordinationEventRecorder, StoredGitEvent},
    distributed::{DistributedPersistence, DistributedRuntimeConfig, WorkerIdentity, run_worker},
};

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

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ComparableFinding {
    path: String,
    rule: String,
    start: u64,
    end: u64,
}

fn comparable_findings_from_jsonl(bytes: Vec<u8>, root: &Path) -> Vec<ComparableFinding> {
    let roots: &[&Path] = &[root];
    let mut findings: Vec<_> = parse_jsonl(bytes)
        .into_iter()
        .filter(crate::parity::is_finding_event)
        .map(|event| ComparableFinding {
            path: crate::parity::normalize_path(
                event["path"].as_str().expect("finding path").to_owned(),
                roots,
            ),
            rule: event
                .get("rule")
                .and_then(Value::as_str)
                .or_else(|| event.get("rule_name").and_then(Value::as_str))
                .expect("finding rule")
                .to_owned(),
            start: event["start"].as_u64().expect("finding start"),
            end: event["end"].as_u64().expect("finding end"),
        })
        .collect();
    findings.sort();
    findings
}

#[derive(Debug, Default)]
struct DistributedCoreRecorder {
    core_events: Mutex<Vec<OwnedCoreEvent>>,
}

impl DistributedCoreRecorder {
    fn core_jsonl(&self) -> Vec<u8> {
        let events = self.core_events.lock().expect("core events lock").clone();
        let out = scanner_scheduler::events::VecEventOutput::new();
        for event in &events {
            event.emit_into(&out);
        }
        out.take()
    }
}

impl CoordinationEventRecorder for DistributedCoreRecorder {
    fn record_core_event(&self, _shard_id: &str, event: OwnedCoreEvent) -> anyhow::Result<()> {
        self.core_events
            .lock()
            .expect("core events lock")
            .push(event);
        Ok(())
    }

    fn record_git_event(&self, _shard_id: &str, _event: StoredGitEvent) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_commit_progress(
        &self,
        _shard_id: &str,
        _event: CommitProgressRecord,
    ) -> anyhow::Result<()> {
        Ok(())
    }
}

fn distributed_tenant() -> TenantId {
    TenantId::from_bytes([0x11; 32])
}

fn distributed_run() -> RunId {
    RunId::from_raw(7)
}

fn distributed_worker() -> WorkerId {
    WorkerId::from_raw(13)
}

fn distributed_policy_hash() -> PolicyHash {
    PolicyHash::from_bytes([0x22; 32])
}

fn distributed_tenant_secret_key() -> TenantSecretKey {
    TenantSecretKey::from_bytes([0x33; 32])
}

fn distributed_run_config(lease_duration_ms: u64) -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, None).expect("run config")
}

fn distributed_now() -> LogicalTime {
    LogicalTime::from_raw(1)
}

fn setup_distributed_coordinator(
    path: &Path,
    lease_duration_ms: u64,
) -> CoordinationInMemoryCoordinator {
    let mut coordinator = CoordinationInMemoryCoordinator::new(lease_duration_ms);
    let now = distributed_now();
    coordinator
        .create_run(
            now,
            distributed_tenant(),
            distributed_run(),
            distributed_run_config(lease_duration_ms),
        )
        .expect("create run");

    let connector_extra = path
        .to_str()
        .expect("test path must be valid UTF-8")
        .as_bytes();
    let mut scratch = ShardSpecScratch::new();
    let spec_ref =
        range_shard_ref(b"\x00", b"\xFF", connector_extra, &mut scratch).expect("range shard spec");
    let spec = ShardSpec::try_from_ref(spec_ref).expect("owned shard spec");
    let shard_id = ShardId::from_raw(1);
    let shards = [InitialShardInput::new(
        shard_id,
        spec.as_ref(),
        gossip_coordination::CursorUpdate::initial(),
    )];
    let _ = coordinator
        .register_shards(
            now,
            distributed_tenant(),
            distributed_run(),
            &shards,
            OpId::from_raw(1),
        )
        .expect("register shards");

    coordinator
}

fn distributed_worker_identity(
    path: &Path,
    recorder: Arc<dyn CoordinationEventRecorder>,
) -> WorkerIdentity {
    WorkerIdentity::new(
        distributed_tenant(),
        distributed_run(),
        distributed_worker(),
        distributed_policy_hash(),
        distributed_tenant_secret_key(),
        FsScanConfig::new(path.to_path_buf()),
        recorder,
    )
}

fn fs_runtime_corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/parity/corpus/fs_runtime")
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
fn scan_fs_local_and_distributed_paths_match_on_finding_set() {
    let fixture_root = fs_runtime_corpus_dir();
    let local_out = scanner_scheduler::events::VecEventOutput::new();
    let cancel = CancellationToken::new();

    let local_outcome = scan_fs_with_runtime(
        &FsScanConfig::new(&fixture_root),
        &local_out,
        &commit_sink::CliNoOpCommitSink,
        &cancel,
    )
    .expect("local filesystem scan should succeed");
    assert!(
        local_outcome.report.findings_emitted >= 1,
        "parity fixture should emit at least one local finding",
    );

    let recorder = Arc::new(DistributedCoreRecorder::default());
    let mut coordinator = setup_distributed_coordinator(&fixture_root, 30_000);
    let report = run_worker(
        &mut coordinator,
        distributed_worker_identity(&fixture_root, recorder.clone()),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("distributed filesystem scan should succeed");
    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);

    let local = comparable_findings_from_jsonl(local_out.take(), &fixture_root);
    let distributed = comparable_findings_from_jsonl(recorder.core_jsonl(), &fixture_root);

    assert!(
        !local.is_empty(),
        "parsed local JSONL must contain at least one finding",
    );
    assert!(
        !distributed.is_empty(),
        "parity fixture should emit at least one distributed finding",
    );
    assert_eq!(distributed, local);
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

// ---------------------------------------------------------------------------
// OwnedCoreEvent round-trip fidelity (F11)
// ---------------------------------------------------------------------------

#[test]
fn owned_core_event_finding_round_trips() {
    let original = CoreEvent::Finding(FindingEvent {
        source: SourceKind::Fs,
        object_path: b"/tmp/secret.txt",
        start: 10,
        end: 42,
        rule_id: 7,
        rule_name: "test-rule",
        commit_id: Some(3),
        change_kind: Some("modify"),
        confidence_score: 85,
    });

    let owned = OwnedCoreEvent::from_core(original);
    let out = scanner_scheduler::events::VecEventOutput::new();
    owned.emit_into(&out);

    let events = parse_jsonl(out.take());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["type"], "finding");
    assert_eq!(event["source"], "fs");
    assert_eq!(event["rule"], "test-rule");
    assert_eq!(event["start"], 10);
    assert_eq!(event["end"], 42);
    assert_eq!(event["confidence_score"], 85);
    assert_eq!(event["commit_id"], 3);
    assert_eq!(event["change_kind"], "modify");
}

#[test]
fn owned_core_event_summary_round_trips() {
    let original = CoreEvent::Summary(SummaryEvent {
        source: SourceKind::Git,
        status: "completed",
        elapsed_ms: 1234,
        bytes_scanned: 5678,
        findings_emitted: 3,
        errors: 0,
        throughput_mib_s: 42.5,
    });

    let owned = OwnedCoreEvent::from_core(original);
    let out = scanner_scheduler::events::VecEventOutput::new();
    owned.emit_into(&out);

    let events = parse_jsonl(out.take());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["type"], "summary");
    assert_eq!(event["status"], "completed");
    assert_eq!(event["elapsed_ms"], 1234);
    assert_eq!(event["bytes_scanned"], 5678);
    assert_eq!(event["findings_emitted"], 3);
}

#[test]
fn owned_core_event_diagnostic_round_trips() {
    let original = CoreEvent::Diagnostic(DiagnosticEvent {
        level: "warn",
        message: "something went wrong",
    });

    let owned = OwnedCoreEvent::from_core(original);
    let out = scanner_scheduler::events::VecEventOutput::new();
    owned.emit_into(&out);

    let events = parse_jsonl(out.take());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["type"], "diagnostic");
    assert_eq!(event["level"], "warn");
    assert_eq!(event["message"], "something went wrong");
}

// ---------------------------------------------------------------------------
// OwnedGitEvent round-trip fidelity (F11)
// ---------------------------------------------------------------------------

#[test]
fn owned_git_event_commit_meta_round_trips() {
    let oid = OidBytes::sha1([0xab; 20]);
    let identity = CommitIdentityIds {
        author_name: 1,
        author_email: 2,
        committer_name: 3,
        committer_email: 4,
    };

    let original = GitEvent::CommitMeta(CommitMetaEvent {
        commit_id: 42,
        commit_oid: oid,
        timestamp: 1_700_000_000,
        identity: Some(identity),
    });

    let owned = OwnedGitEvent::from_git(original);
    let out = scanner_git::VecEventSink::new();
    owned.emit_into(&out);

    let events = parse_jsonl(out.take());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["type"], "commit_meta");
    assert_eq!(event["commit_id"], 42);
    assert_eq!(event["timestamp"], 1_700_000_000u64);
}

#[test]
fn scan_git_with_perf_debug_includes_pack_exec_keys() {
    let repo = create_test_repo(&[("secret.txt", b"prefix TOK_ABCDEFGH suffix")]);
    let rules = write_runtime_rules();
    let out = scanner_git::VecEventSink::new();
    let cancel = CancellationToken::new();

    let outcome = scan_git_with_runtime(
        &GitScanConfig::new(repo.path())
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_debug_level(GitDebugLevel::Perf),
        &out,
        &cancel,
    )
    .expect("git scan should succeed");

    let debug_output = outcome.debug_output.expect("perf debug output");
    assert!(
        debug_output.contains("git_debug.level=perf"),
        "debug output should contain perf level marker"
    );
    // Perf level includes stage timing, which is always present.
    assert!(
        debug_output.contains("stage.pack_exec.nanos"),
        "perf debug should include stage timing"
    );
}

#[test]
fn scan_git_with_perf_debug_handles_empty_pack_exec_reports() {
    // A repo with an empty commit has no pack_exec_reports, exercising the
    // empty-vector path in format_git_debug_output's Perf branch.
    let repo = create_test_repo(&[]);
    // Create an empty commit so the repo has at least one ref.
    run_git(
        repo.path(),
        &["commit", "-q", "--allow-empty", "-m", "empty"],
    );
    let rules = write_runtime_rules();
    let out = scanner_git::VecEventSink::new();
    let cancel = CancellationToken::new();

    let outcome = scan_git_with_runtime(
        &GitScanConfig::new(repo.path())
            .with_rules_file(Some(rules.path().to_path_buf()))
            .with_debug_level(GitDebugLevel::Perf),
        &out,
        &cancel,
    )
    .expect("git scan should succeed");

    let debug_output = outcome.debug_output.expect("perf debug output");
    assert!(debug_output.contains("git_debug.level=perf"));
    // No pack_exec entries expected since there are no blob objects.
    assert!(
        !debug_output.contains("pack_exec.0.cache_lookup_nanos"),
        "empty repo should have no pack_exec entries"
    );
}

#[test]
fn owned_git_event_identity_dictionary_round_trips() {
    let original = GitEvent::IdentityDictionary(IdentityDictionaryEvent {
        id: 99,
        value: b"alice@example.com",
    });

    let owned = OwnedGitEvent::from_git(original);
    let out = scanner_git::VecEventSink::new();
    owned.emit_into(&out);

    let events = parse_jsonl(out.take());
    assert_eq!(events.len(), 1);
    let event = &events[0];
    assert_eq!(event["type"], "identity_dictionary");
    assert_eq!(event["id"], 99);
}
