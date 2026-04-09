//! Simulation-harness regression for shallow-root ingestion limits.
//!
//! This test runs under the `simulation` target (`--features sim-harness`) so
//! shallow-ingestion guardrails are exercised alongside other simulation suites.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use crate::git_test_support::{git_available, git_stdout, init_git_repo, oid_from_hex, run_git};
use regex::bytes::Regex;
use tempfile::TempDir;

use crate::scanner_rs::git_scan::{
    ArtifactAcquireError, CommitLoadError, GitScanConfig, GitScanError, InMemoryPersistenceStore,
    NeverSeenStore, OidBytes, RefWatermarkStore, RepoOpenError, StartSetConfig, StartSetResolver,
    run_git_scan,
};
use crate::scanner_rs::unified::events::NullEventSink;
use crate::scanner_rs::{AnchorPolicy, Engine, RuleSpec, ValidatorKind, demo_tuning};

fn create_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    init_git_repo(tmp.path(), "test@example.com", "Test User");
    tmp
}

fn commit_file(repo: &Path, name: &str, contents: &str, msg: &str) {
    fs::write(repo.join(name), contents).unwrap();
    run_git(repo, &["add", name]);
    run_git(repo, &["commit", "-m", msg]);
}

fn test_engine() -> Engine {
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

    Engine::new_with_anchor_policy(vec![rule], vec![], demo_tuning(), AnchorPolicy::ManualOnly)
}

struct TestResolver {
    tip: OidBytes,
}

impl StartSetResolver for TestResolver {
    fn resolve(
        &self,
        _paths: &crate::scanner_rs::git_scan::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(vec![(b"refs/heads/main".to_vec(), self.tip)])
    }
}

struct TestWatermarkStore;

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, RepoOpenError> {
        Ok(ref_names.iter().map(|_| None).collect())
    }
}

#[test]
fn shallow_root_limit_failure_is_covered_by_sim_harness() {
    if !git_available() {
        eprintln!("git not available; skipping sim shallow-limit regression");
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

    let tip = oid_from_hex(&git_stdout(&shallow_repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let persist = InMemoryPersistenceStore::default();
    let mut config = GitScanConfig {
        repo_id: 7,
        policy_hash: [0x77; 32],
        start_set: StartSetConfig::DefaultBranchOnly,
        ..Default::default()
    };
    config.artifact_build.commit_load.max_shallow_roots = 0;
    let abort = AtomicBool::new(false);

    let err = run_git_scan(
        &shallow_repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &NeverSeenStore,
        &TestWatermarkStore,
        Some(&persist),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .unwrap_err();

    match err {
        GitScanError::ArtifactAcquire(ArtifactAcquireError::CommitLoad(
            CommitLoadError::TooManyShallowRoots { limit, .. },
        )) => {
            assert_eq!(limit, 0);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}
