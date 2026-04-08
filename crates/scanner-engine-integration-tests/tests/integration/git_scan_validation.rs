//! Integration tests covering Git scan validation matrix scenarios.
//!
//! These tests exercise combinations of packed vs loose objects, watermark
//! presence, and missing objects. They rely on the `git` CLI to create repos,
//! generate commit-graph/MIDX artifacts, and mutate the object store.

use std::cell::{Cell, RefCell};
use std::collections::HashSet;
use std::fs;
use std::num::NonZeroU32;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use crate::git_test_support::{git_available, git_output, init_git_repo, oid_from_hex, run_git};
use regex::bytes::Regex;
use tempfile::TempDir;

use scanner_engine::{
    AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId, demo_tuning,
};
use scanner_engine::{TransformMode, ValidatorKind};
use scanner_git::events::{NullEventSink, VecEventSink};
use scanner_git::{
    ArtifactAcquireError, CommitLoadError, FinalizeOutcome, GitScanConfig, GitScanError,
    GitScanMode, GitScanReport, GitScanResult, InMemoryPersistenceStore, MappingCandidateKind,
    NeverSeenStore, OidBytes, PersistError, PersistenceStore, RefWatermark, RefWatermarkStore,
    RepoOpenError, SeenBitmapDelta, SeenBitmapPersister, SeenBlobStore, SpillError, StartSetConfig,
    StartSetResolver, WriteOp, run_git_scan,
};

use scanner_git::{NS_BLOB_CTX, NS_FINDING, NS_SEEN_BLOB};

pub(crate) fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

/// Initialize a new repo with a deterministic user identity.
pub(crate) fn create_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path(), "test@example.com", "Test User");
    tmp
}

/// Write a file and commit it to the repo.
pub(crate) fn commit_file(repo: &Path, name: &str, contents: &str, msg: &str) {
    let path = repo.join(name);
    fs::write(&path, contents).unwrap();
    run_git(repo, &["add", name]);
    run_git(repo, &["commit", "-m", msg]);
}

/// Ensure all objects are packed and indexed.
pub(crate) fn ensure_artifacts(repo: &Path) {
    run_git(repo, &["gc"]);
}

/// Repack after new commits so in-memory artifact builders can find them.
fn repack_all(repo: &Path) {
    run_git(repo, &["repack", "-ad"]);
}

/// Build a tiny engine that detects TOK_ secrets (and Base64 variants).
pub(crate) fn test_engine() -> Engine {
    let rule = RuleSpec {
        name: "tok",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: Some(1),
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

/// Start set resolver pinned to the current `main` tip.
pub(crate) struct TestResolver {
    pub(crate) tip: OidBytes,
}

impl StartSetResolver for TestResolver {
    fn resolve(
        &self,
        _paths: &scanner_git::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(vec![(b"refs/heads/main".to_vec(), self.tip)])
    }
}

/// Watermark store that returns a fixed optional watermark for all refs.
pub(crate) struct TestWatermarkStore {
    pub(crate) watermark: Option<scanner_git::RefWatermark>,
}

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, RepoOpenError> {
        Ok(ref_names.iter().map(|_| self.watermark).collect())
    }
}

#[derive(Default)]
struct RetryStore {
    seen: RefCell<HashSet<OidBytes>>,
    fail_commit_once: Cell<bool>,
}

impl SeenBlobStore for RetryStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        let seen = self.seen.borrow();
        Ok(oids.iter().map(|oid| seen.contains(oid)).collect())
    }
}

impl SeenBitmapPersister for RetryStore {
    fn persist_seen_delta(&self, _oids: &[OidBytes]) -> Result<(), SpillError> {
        // No-op: spill checkpoints must not update the live seen set.
        // Only commit_finalize folds OIDs into the set atomically.
        Ok(())
    }
}

impl PersistenceStore for RetryStore {
    fn commit_finalize(&self, output: &scanner_git::FinalizeOutput) -> Result<(), PersistError> {
        if self.fail_commit_once.replace(false) {
            return Err(PersistError::backend("injected finalize failure"));
        }
        // Model production behavior: decode all finalize seen ops first, then
        // publish them atomically into the live seen set.
        let mut staged_oids = Vec::new();
        for op in &output.data_ops {
            if op.key.starts_with(&NS_SEEN_BLOB) {
                let delta = SeenBitmapDelta::deserialize(&op.value)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                staged_oids.extend(delta.oids().iter().copied());
            }
        }
        self.seen.borrow_mut().extend(staged_oids);
        Ok(())
    }
}

/// Run a Git scan for the repo with an optional watermark.
///
/// The config pins `repo_id`, `policy_hash`, and `start_set` to keep the
/// test inputs deterministic. Persistence is routed to an in-memory store.
fn run_scan(repo: &Path, watermark: Option<RefWatermark>) -> GitScanResult {
    run_scan_with_config(repo, watermark, base_config()).unwrap()
}

pub(crate) fn base_config() -> GitScanConfig {
    GitScanConfig {
        repo_id: 42,
        policy_hash: [0x11; 32],
        start_set: StartSetConfig::DefaultBranchOnly,
        ..Default::default()
    }
}

fn run_scan_with_config(
    repo: &Path,
    watermark: Option<RefWatermark>,
    config: GitScanConfig,
) -> Result<GitScanResult, GitScanError> {
    let engine = test_engine();
    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark };
    #[cfg(feature = "rocksdb")]
    let persist_store =
        InMemoryPersistenceStore::with_seen_scope(config.repo_id, config.policy_hash);
    #[cfg(not(feature = "rocksdb"))]
    let persist_store = InMemoryPersistenceStore::default();
    let abort = AtomicBool::new(false);

    run_git_scan(
        repo,
        std::sync::Arc::new(engine),
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
}

fn assert_write_ops_equal(left: &[WriteOp], right: &[WriteOp]) {
    assert_eq!(left.len(), right.len(), "write op length mismatch");
    for (idx, (lhs, rhs)) in left.iter().zip(right.iter()).enumerate() {
        assert_eq!(lhs.key, rhs.key, "write op key mismatch at index {idx}");
        assert_eq!(
            lhs.value, rhs.value,
            "write op value mismatch at index {idx}"
        );
    }
}

fn assert_scan_outputs_equal(left: &GitScanReport, right: &GitScanReport) {
    assert_eq!(left.skipped_candidates, right.skipped_candidates);
    assert_eq!(left.finalize.outcome, right.finalize.outcome);
    assert_eq!(
        left.finalize.stats.unique_blobs,
        right.finalize.stats.unique_blobs
    );
    assert_eq!(
        left.finalize.stats.total_findings,
        right.finalize.stats.total_findings
    );
    assert_eq!(
        left.finalize.stats.findings_deduped,
        right.finalize.stats.findings_deduped
    );
    assert_write_ops_equal(&left.finalize.data_ops, &right.finalize.data_ops);
    assert_write_ops_equal(&left.finalize.watermark_ops, &right.finalize.watermark_ops);
}

fn select_ops_with_ns(ops: &[WriteOp], ns: &[u8; 3]) -> Vec<WriteOp> {
    ops.iter()
        .filter(|op| op.key.starts_with(ns))
        .cloned()
        .collect()
}

fn assert_odb_parallel_contract(left: &GitScanReport, right: &GitScanReport) {
    assert_eq!(left.skipped_candidates, right.skipped_candidates);
    assert_eq!(left.finalize.outcome, right.finalize.outcome);
    assert_eq!(
        left.finalize.stats.unique_blobs,
        right.finalize.stats.unique_blobs
    );
    assert_eq!(
        left.finalize.stats.total_findings,
        right.finalize.stats.total_findings
    );
    assert_eq!(
        left.finalize.stats.findings_deduped,
        right.finalize.stats.findings_deduped
    );

    let left_blob_ctx = select_ops_with_ns(&left.finalize.data_ops, &NS_BLOB_CTX);
    let right_blob_ctx = select_ops_with_ns(&right.finalize.data_ops, &NS_BLOB_CTX);
    assert_eq!(
        left_blob_ctx.len(),
        right_blob_ctx.len(),
        "blob_ctx cardinality mismatch"
    );
    for (idx, (lhs, rhs)) in left_blob_ctx.iter().zip(right_blob_ctx.iter()).enumerate() {
        assert_eq!(lhs.key, rhs.key, "blob_ctx key mismatch at index {idx}");
    }

    let left_findings = select_ops_with_ns(&left.finalize.data_ops, &NS_FINDING);
    let right_findings = select_ops_with_ns(&right.finalize.data_ops, &NS_FINDING);
    assert_write_ops_equal(&left_findings, &right_findings);

    let left_seen = select_ops_with_ns(&left.finalize.data_ops, &NS_SEEN_BLOB);
    let right_seen = select_ops_with_ns(&right.finalize.data_ops, &NS_SEEN_BLOB);
    assert_write_ops_equal(&left_seen, &right_seen);

    assert_write_ops_equal(&left.finalize.watermark_ops, &right.finalize.watermark_ops);
}

#[test]
fn loose_only_candidate_scans_complete() {
    if !git_available() {
        eprintln!("git not available; skipping git scan validation test");
        return;
    }

    let tmp = create_repo();
    commit_file(tmp.path(), "base.txt", "base\n", "base");
    ensure_artifacts(tmp.path());
    // Commit after artifacts so the new blob remains loose.
    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");
    repack_all(tmp.path());

    let watermark = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD~1"]));
    // Root commit in a 2-commit chain has generation 1.
    let result = run_scan(
        tmp.path(),
        Some(RefWatermark {
            oid: watermark,
            generation: NonZeroU32::new(1).unwrap(),
        }),
    );

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    if perf_stats_enabled() {
        assert!(report.finalize.stats.total_findings >= 1);
    } else {
        assert_eq!(report.finalize.stats.total_findings, 0);
    }
}

#[test]
fn odb_blob_parallel_intro_handles_empty_midx_without_panic() {
    if !git_available() {
        eprintln!("git not available; skipping empty-midx parallel intro test");
        return;
    }

    let tmp = create_repo();
    // Keep all objects loose (no gc/repack), with >1 commits so parallel intro
    // is selected when blob_intro_workers > 1.
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH\n", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP\n", "c2");

    let pack_dir = tmp.path().join(".git").join("objects").join("pack");
    let has_pack = fs::read_dir(&pack_dir)
        .expect("pack directory should exist")
        .filter_map(Result::ok)
        .any(|entry| entry.file_name().to_string_lossy().ends_with(".pack"));
    assert!(
        !has_pack,
        "fixture requires no pack files so MIDX object_count is zero"
    );

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.blob_intro_workers = 4;

    let GitScanResult(report) = run_scan_with_config(tmp.path(), None, config)
        .expect("parallel ODB blob intro should not panic with empty MIDX");
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(
        report.pack_exec_reports.is_empty(),
        "empty MIDX should produce no packed candidates"
    );
    assert!(report.skipped_candidates.is_empty());
}

#[test]
fn odb_blob_parallel_intro_handles_low_delta_cache_budget() {
    if !git_available() {
        eprintln!("git not available; skipping low delta-cache budget test");
        return;
    }

    let tmp = create_repo();
    // Keep all objects loose (no gc/repack), with >1 commits so parallel intro
    // is selected when blob_intro_workers > 1.
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH\n", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP\n", "c2");

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.blob_intro_workers = 4;
    config.tree_diff.max_tree_delta_cache_bytes = 8 * 1024 * 1024;

    let GitScanResult(report) = run_scan_with_config(tmp.path(), None, config)
        .expect("parallel ODB blob intro should not fail with 8MiB total delta cache");
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
}

#[test]
fn odb_blob_respects_packed_candidate_cap() {
    if !git_available() {
        eprintln!("git not available; skipping packed candidate cap test");
        return;
    }

    let tmp = create_repo();
    commit_file(tmp.path(), "a.txt", "TOK_ABCDEFGH", "c1");
    commit_file(tmp.path(), "b.txt", "TOK_IJKLMNOP", "c2");
    ensure_artifacts(tmp.path());

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.mapping.max_packed_candidates = 1;

    let err = run_scan_with_config(tmp.path(), None, config)
        .expect_err("expected packed candidate cap error");
    match err {
        GitScanError::Spill(SpillError::MappingCandidateLimitExceeded {
            kind,
            max,
            observed,
        }) => {
            assert_eq!(kind, MappingCandidateKind::Packed);
            assert_eq!(max, 1);
            assert!(observed >= 2);
        }
        other => panic!("expected mapping cap error, got {other:?}"),
    }
}

#[test]
fn packed_and_loose_candidates_scan_complete() {
    if !git_available() {
        eprintln!("git not available; skipping git scan validation test");
        return;
    }

    let tmp = create_repo();
    commit_file(tmp.path(), "base.txt", "TOK_BASE1234\n", "base");
    ensure_artifacts(tmp.path());
    // Base blob is packed; secret blob remains loose.
    commit_file(tmp.path(), "secret.txt", "TOK_ABCDEFGH\n", "secret");
    repack_all(tmp.path());

    let result = run_scan(tmp.path(), None);

    let GitScanResult(report) = result;
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
    if perf_stats_enabled() {
        assert!(report.finalize.stats.total_findings >= 2);
    } else {
        assert_eq!(report.finalize.stats.total_findings, 0);
    }
}

#[test]
fn diff_history_pack_exec_workers_preserve_deterministic_output() {
    if !git_available() {
        eprintln!("git not available; skipping diff-history worker test");
        return;
    }

    let tmp = create_repo();
    let payloads = [
        "TOK_ABCDEFGH\n",
        "TOK_IJKLMNOP\n",
        "TOK_QRSTUVWX\n",
        "TOK_YZABCDEF\n",
        "TOK_GHIJKLMN\n",
        "TOK_OPQRSTUV\n",
        "TOK_WXYZ1234\n",
        "TOK_5678ABCD\n",
    ];
    for (idx, payload) in payloads.iter().enumerate() {
        let name = format!("secret-{idx}.txt");
        let msg = format!("c{idx}");
        commit_file(tmp.path(), &name, payload, &msg);
    }
    ensure_artifacts(tmp.path());

    let mut serial_cfg = base_config();
    serial_cfg.scan_mode = GitScanMode::DiffHistory;
    serial_cfg.pack_exec_workers = 1;

    let mut parallel_cfg = serial_cfg.clone();
    parallel_cfg.pack_exec_workers = 4;

    let GitScanResult(serial_report) = run_scan_with_config(tmp.path(), None, serial_cfg).unwrap();
    let GitScanResult(parallel_report) =
        run_scan_with_config(tmp.path(), None, parallel_cfg).unwrap();

    assert_eq!(serial_report.finalize.outcome, FinalizeOutcome::Complete);
    assert_eq!(parallel_report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(
        !serial_report.pack_exec_reports.is_empty(),
        "expected packed candidates in diff-history test fixture"
    );

    assert_scan_outputs_equal(&serial_report, &parallel_report);
}

#[test]
fn odb_blob_parallel_intro_keeps_persistence_contract_without_blob_ctx_determinism() {
    if !git_available() {
        eprintln!("git not available; skipping odb-blob parallel intro contract test");
        return;
    }

    let tmp = create_repo();
    commit_file(tmp.path(), "base.txt", "base\n", "base");

    // Emit the same blob across many commit/path contexts to exercise
    // race-winner attribution in parallel ODB introduction.
    for idx in 0..16 {
        let file = format!("shared-{idx}.txt");
        let msg = format!("shared-{idx}");
        commit_file(tmp.path(), &file, "TOK_SHARED00\n", &msg);
    }
    ensure_artifacts(tmp.path());

    let mut serial_cfg = base_config();
    serial_cfg.scan_mode = GitScanMode::OdbBlobFast;
    serial_cfg.blob_intro_workers = 1;

    let mut parallel_cfg = serial_cfg.clone();
    parallel_cfg.blob_intro_workers = 4;

    let GitScanResult(serial_report) = run_scan_with_config(tmp.path(), None, serial_cfg).unwrap();
    let GitScanResult(parallel_report) =
        run_scan_with_config(tmp.path(), None, parallel_cfg).unwrap();

    assert_eq!(serial_report.finalize.outcome, FinalizeOutcome::Complete);
    assert_eq!(parallel_report.finalize.outcome, FinalizeOutcome::Complete);

    let serial_blob_ctx = select_ops_with_ns(&serial_report.finalize.data_ops, &NS_BLOB_CTX);
    let parallel_blob_ctx = select_ops_with_ns(&parallel_report.finalize.data_ops, &NS_BLOB_CTX);
    assert!(
        !serial_blob_ctx.is_empty(),
        "expected blob_ctx ops in serial output"
    );
    assert!(
        !parallel_blob_ctx.is_empty(),
        "expected blob_ctx ops in parallel output"
    );

    assert_odb_parallel_contract(&serial_report, &parallel_report);
}

// The `LooseMissing` code path is covered by `missing_loose_object_is_skipped`
// in `runner_exec_tests.rs`. In-memory artifact builds require all commits to
// be in packs, so a loose-only blob whose commit is already packed cannot be
// constructed via standard Git operations in an integration fixture.

#[test]
fn shallow_clone_boundary_treats_missing_parent_as_external_root() {
    if !git_available() {
        eprintln!("git not available; skipping shallow clone regression test");
        return;
    }

    let source = create_repo();
    commit_file(source.path(), "base.txt", "base\n", "c1");
    commit_file(source.path(), "base.txt", "TOK_ABCDEFGH\n", "c2");

    let shallow_tmp = TempDir::new().unwrap();
    let shallow_repo = shallow_tmp.path().join("repo");
    // Use file:// so Git honors --depth for local clones.
    let source_url = format!("file://{}", source.path().display());
    let clone_status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(source_url)
        .arg(&shallow_repo)
        .status()
        .expect("failed to run git clone");
    assert!(clone_status.success(), "git clone --depth 1 must succeed");

    assert_eq!(
        git_output(&shallow_repo, &["rev-parse", "--is-shallow-repository"]).trim(),
        "true",
        "fixture must be a shallow clone"
    );

    // `git show --pretty=%P` respects shallow grafts and hides boundary parents.
    // Parse raw commit headers to capture the parent OID that is truly missing.
    let head_raw = git_output(&shallow_repo, &["cat-file", "-p", "HEAD"]);
    let missing_parent_hex = head_raw
        .lines()
        .find_map(|line| line.strip_prefix("parent "))
        .expect("fixture expects HEAD raw commit to include a parent");
    let parent_present = Command::new("git")
        .arg("cat-file")
        .arg("-e")
        .arg(missing_parent_hex)
        .current_dir(&shallow_repo)
        .status()
        .expect("failed to run git cat-file -e")
        .success();
    assert!(
        !parent_present,
        "fixture requires missing parent {missing_parent_hex}"
    );

    let GitScanResult(report) = run_scan_with_config(&shallow_repo, None, base_config())
        .expect("shallow-boundary missing parent should not fail artifact acquisition");
    assert_eq!(report.finalize.outcome, FinalizeOutcome::Complete);
    assert!(report.skipped_candidates.is_empty());
}

#[test]
fn shallow_clone_fails_fast_when_shallow_root_limit_is_exceeded() {
    if !git_available() {
        eprintln!("git not available; skipping shallow limit regression test");
        return;
    }

    let source = create_repo();
    commit_file(source.path(), "base.txt", "base\n", "c1");
    commit_file(source.path(), "base.txt", "TOK_ABCDEFGH\n", "c2");

    let shallow_tmp = TempDir::new().unwrap();
    let shallow_repo = shallow_tmp.path().join("repo");
    let source_url = format!("file://{}", source.path().display());
    let clone_status = Command::new("git")
        .arg("clone")
        .arg("--depth")
        .arg("1")
        .arg(source_url)
        .arg(&shallow_repo)
        .status()
        .expect("failed to run git clone");
    assert!(clone_status.success(), "git clone --depth 1 must succeed");

    let mut config = base_config();
    config.artifact_build.commit_load.max_shallow_roots = 0;

    let err = run_scan_with_config(&shallow_repo, None, config).unwrap_err();
    match err {
        GitScanError::ArtifactAcquire(ArtifactAcquireError::CommitLoad(
            CommitLoadError::TooManyShallowRoots { limit, .. },
        )) => {
            assert_eq!(limit, 0);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

// ============================================================================
// commit_meta event output tests
// ============================================================================

/// Run a scan using a `VecEventSink` and return the JSONL output as lines.
fn run_scan_with_events(
    repo: &Path,
    watermark: Option<RefWatermark>,
    config: GitScanConfig,
) -> (GitScanResult, Vec<String>) {
    let engine = test_engine();
    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark };
    #[cfg(feature = "rocksdb")]
    let persist_store =
        InMemoryPersistenceStore::with_seen_scope(config.repo_id, config.policy_hash);
    #[cfg(not(feature = "rocksdb"))]
    let persist_store = InMemoryPersistenceStore::default();
    let sink = std::sync::Arc::new(VecEventSink::new());
    let abort = AtomicBool::new(false);

    let result = run_git_scan(
        repo,
        std::sync::Arc::new(engine),
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
        &abort,
        sink.clone(),
    )
    .expect("scan should succeed");

    let bytes = sink.take();
    let output = String::from_utf8(bytes).expect("valid UTF-8");
    let lines: Vec<String> = output
        .lines()
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect();
    (result, lines)
}

#[test]
fn failed_finalize_retry_still_scans_blob() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();
    commit_file(
        repo,
        "secret.txt",
        "prefix TOK_ABCDEFGH suffix",
        "add secret",
    );
    ensure_artifacts(repo);

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark: None };
    let store = RetryStore {
        seen: RefCell::new(HashSet::new()),
        fail_commit_once: Cell::new(true),
    };
    let config = base_config();
    let abort = AtomicBool::new(false);

    let first = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &store,
        &watermark_store,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    );
    assert!(
        matches!(first, Err(GitScanError::Persist(_))),
        "expected finalize persistence failure, got {first:?}"
    );

    let second = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &store,
        &watermark_store,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect("retry should succeed");

    assert_eq!(second.0.finalize.outcome, FinalizeOutcome::Complete);
    if perf_stats_enabled() {
        assert_eq!(
            second.0.finalize.stats.unique_blobs, 1,
            "retry should re-scan the single blob"
        );
    }
    if perf_stats_enabled() {
        assert_eq!(second.0.finalize.stats.total_findings, 1);
    } else {
        assert_eq!(second.0.finalize.stats.total_findings, 0);
    }

    // Third run: the successful finalize persisted seen state, so the blob
    // should now be skipped by `batch_check_seen`.
    let third = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &store,
        &watermark_store,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect("third run should succeed");

    assert_eq!(third.0.finalize.outcome, FinalizeOutcome::Complete);
    if perf_stats_enabled() {
        assert_eq!(
            third.0.finalize.stats.unique_blobs, 0,
            "blob should be skipped after successful finalize persisted seen state"
        );
    }
}

#[test]
fn aborted_scan_skips_finalize_persistence() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();
    commit_file(
        repo,
        "secret.txt",
        "prefix TOK_ABCDEFGH suffix",
        "add secret",
    );
    ensure_artifacts(repo);

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark: None };
    let persist_store = InMemoryPersistenceStore::default();
    let config = base_config();
    let abort = AtomicBool::new(true);

    let err = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect_err("pre-cancelled scan should abort");

    assert!(matches!(
        err,
        GitScanError::TreeDiff(scanner_git::TreeDiffError::Aborted)
    ));
    assert!(persist_store.data_ops.borrow().is_empty());
    assert!(persist_store.watermark_ops.borrow().is_empty());
}

/// Verify that every finding's `commit_id` has a matching `commit_meta` event
/// and that `commit_meta` is emitted exactly once per commit_id.
///
/// Event ordering is intentionally not asserted: pack/loose workers emit in
/// parallel, so commit metadata and findings may interleave non-deterministically.
#[test]
fn commit_meta_output_matches_findings() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();

    // Commit a file with a detectable secret.
    commit_file(
        repo,
        "secret.txt",
        "prefix TOK_ABCDEFGH suffix",
        "add secret",
    );
    // Second commit modifying the same file (different content but same secret).
    commit_file(
        repo,
        "secret.txt",
        "changed prefix TOK_ABCDEFGH changed suffix",
        "modify secret",
    );
    // A clean file with no secrets.
    commit_file(repo, "clean.txt", "nothing here", "add clean file");
    ensure_artifacts(repo);

    for &mode in &[GitScanMode::OdbBlobFast, GitScanMode::DiffHistory] {
        let config = GitScanConfig {
            repo_id: 42,
            policy_hash: [0x11; 32],
            start_set: StartSetConfig::DefaultBranchOnly,
            scan_mode: mode,
            ..Default::default()
        };

        let (_result, lines) = run_scan_with_events(repo, None, config);

        // Collect commit_meta and finding events.
        let mut meta_ids: std::collections::HashMap<u64, usize> = std::collections::HashMap::new();
        let mut finding_ids: std::collections::HashSet<u64> = std::collections::HashSet::new();
        for line in &lines {
            if line.contains("\"type\":\"commit_meta\"") {
                if let Some(cid) = extract_commit_id(line) {
                    *meta_ids.entry(cid).or_insert(0) += 1;
                }
            } else if line.contains("\"type\":\"finding\"")
                && let Some(cid) = extract_commit_id(line)
            {
                finding_ids.insert(cid);
            }
        }

        // 1. Every commit_id in a finding has exactly one commit_meta.
        for &fid in &finding_ids {
            assert_eq!(
                meta_ids.get(&fid).copied().unwrap_or(0),
                1,
                "mode={mode:?}: commit_id {fid} should have exactly 1 commit_meta"
            );
        }

        // 2. No commit_meta exists without a matching finding.
        for &mid in meta_ids.keys() {
            assert!(
                finding_ids.contains(&mid),
                "mode={mode:?}: commit_meta for id={mid} has no matching finding"
            );
        }
    }
}

fn extract_commit_id(line: &str) -> Option<u64> {
    let marker = "\"commit_id\":";
    let start = line.find(marker)? + marker.len();
    let rest = &line[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse::<u64>().ok()
}

/// A delayed abort signal propagates through the parallel blob introduction
/// path and prevents finalize persistence.
///
/// Starts with `abort = false` and flips it from a background thread after a
/// short delay, exercising the cooperative cancellation check inside
/// `introduce_parallel`'s worker loop.
///
/// Timing-dependent: on fast machines the scan may complete before the abort
/// fires. Both outcomes are accepted — the key property is that when abort
/// *is* observed, no finalize data is persisted.
#[test]
fn parallel_blob_intro_aborts_on_delayed_flag() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();

    // Create enough commits to keep the parallel blob introduction busy
    // long enough for the delayed abort to fire.
    for i in 0..16 {
        let name = format!("secret-{i}.txt");
        let content = format!("prefix TOK_{i:08X} suffix\n");
        let msg = format!("c{i}");
        commit_file(repo, &name, &content, &msg);
    }
    ensure_artifacts(repo);

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark: None };
    let persist_store = InMemoryPersistenceStore::default();

    let mut config = base_config();
    config.scan_mode = GitScanMode::OdbBlobFast;
    config.blob_intro_workers = 4;

    let abort = std::sync::Arc::new(AtomicBool::new(false));
    let abort_setter = std::sync::Arc::clone(&abort);
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(5));
        abort_setter.store(true, std::sync::atomic::Ordering::Release);
    });

    let result = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &NeverSeenStore,
        &watermark_store,
        Some(&persist_store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    );

    match result {
        Err(ref err) => {
            assert!(
                matches!(
                    err,
                    GitScanError::TreeDiff(scanner_git::TreeDiffError::Aborted)
                ),
                "expected Aborted, got {err:?}"
            );
            assert!(
                persist_store.data_ops.borrow().is_empty(),
                "aborted scan must not persist data ops"
            );
            assert!(
                persist_store.watermark_ops.borrow().is_empty(),
                "aborted scan must not persist watermark ops"
            );
        }
        Ok(_) => {
            // The scan completed before the background thread set the flag.
            // This is acceptable on fast machines; the abort path is still
            // covered by `aborted_scan_skips_finalize_persistence`.
            eprintln!(
                "scan completed before abort fired — timing-dependent, \
                 still validates no crash under concurrent flag flip"
            );
        }
    }
}

/// Flipping the abort flag mid-scan causes a clean abort and prevents
/// finalize persistence.
///
/// Starts with `abort = false` and flips it from a scoped thread after a
/// short delay, exercising the cooperative `check_abort` calls at stage
/// boundaries inside the scan pipeline.
///
/// Timing-dependent: on fast machines the scan may complete before the abort
/// fires. Both outcomes are accepted.
#[test]
fn mid_scan_abort_stops_execution_and_skips_finalize() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();

    // Create enough commits to keep the scan busy long enough for the
    // delayed abort to fire on most machines.
    for i in 0..25 {
        commit_file(
            repo,
            &format!("file_{i:03}.txt"),
            &format!("line1\nprefix TOK_SECRET_{i:03} suffix\nline3\n"),
            &format!("commit {i}"),
        );
    }
    ensure_artifacts(repo);

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark: None };
    let persist_store = InMemoryPersistenceStore::default();
    let config = base_config();
    let abort = AtomicBool::new(false);

    // `std::thread::scope` guarantees the setter thread joins before `abort`
    // is dropped, so the `&AtomicBool` reference remains valid for the
    // entire scan duration.
    let result = std::thread::scope(|s| {
        let abort_ref: &AtomicBool = &abort;
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            abort_ref.store(true, std::sync::atomic::Ordering::Release);
        });

        run_git_scan(
            repo,
            std::sync::Arc::new(test_engine()),
            &resolver,
            &NeverSeenStore,
            &watermark_store,
            Some(&persist_store),
            &config,
            abort_ref,
            std::sync::Arc::new(NullEventSink),
        )
    });

    match result {
        Err(ref e) => {
            assert!(
                matches!(
                    e,
                    GitScanError::TreeDiff(scanner_git::TreeDiffError::Aborted)
                ),
                "expected Aborted, got {e:?}"
            );
            assert!(persist_store.data_ops.borrow().is_empty());
            assert!(persist_store.watermark_ops.borrow().is_empty());
        }
        Ok(_) => {
            // Scan completed before the abort fired — acceptable on fast machines.
        }
    }
}

/// The abort flag is checked at stage boundaries in DiffHistory scan mode.
///
/// Exercises the `check_abort` call after `bridge.finish()` in
/// `runner_diff_history.rs`. Timing-dependent: both abort and completion
/// are accepted.
#[test]
fn stage_boundary_abort_in_diff_history_mode() {
    if !git_available() {
        eprintln!("git not available, skipping");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();

    // Create enough commits for meaningful work in diff-history mode.
    for i in 0..15 {
        commit_file(
            repo,
            &format!("src_{i:02}.txt"),
            &format!("content TOK_DIFFHIST_{i:02} here\n"),
            &format!("diff-history commit {i}"),
        );
    }
    ensure_artifacts(repo);

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let watermark_store = TestWatermarkStore { watermark: None };
    let persist_store = InMemoryPersistenceStore::default();
    let mut config = base_config();
    config.scan_mode = GitScanMode::DiffHistory;
    let abort = AtomicBool::new(false);

    let result = std::thread::scope(|s| {
        let abort_ref: &AtomicBool = &abort;
        s.spawn(|| {
            std::thread::sleep(std::time::Duration::from_millis(5));
            abort_ref.store(true, std::sync::atomic::Ordering::Release);
        });

        run_git_scan(
            repo,
            std::sync::Arc::new(test_engine()),
            &resolver,
            &NeverSeenStore,
            &watermark_store,
            Some(&persist_store),
            &config,
            abort_ref,
            std::sync::Arc::new(NullEventSink),
        )
    });

    match result {
        Err(ref e) => {
            assert!(
                matches!(
                    e,
                    GitScanError::TreeDiff(scanner_git::TreeDiffError::Aborted)
                ),
                "expected Aborted, got {e:?}"
            );
            assert!(persist_store.data_ops.borrow().is_empty());
            assert!(persist_store.watermark_ops.borrow().is_empty());
        }
        Ok(_) => {
            // Scan completed before abort fired — acceptable on fast machines.
        }
    }
}
