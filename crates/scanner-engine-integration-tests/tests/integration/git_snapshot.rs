//! Integration test for snapshot planning against a real `git` repo.
//!
//! Snapshot planning selects the tip commit for each ref as a "snapshot root"
//! that requires a full tree diff (no parent to diff against). This test
//! verifies that `snapshot_plan` emits exactly one entry per ref with the
//! correct position and the `snapshot_root` flag set.
//!
//! Requires `git` on `PATH`; skips gracefully if unavailable.

use std::path::Path;
use std::process::Command;

use scanner_git::OidBytes;
use scanner_git::{
    ArtifactBuildLimits, CommitGraph, CommitWalkLimits, MidxView, RefWatermarkStore, RepoOpenError,
    RepoOpenLimits, StartSetConfig, StartSetResolver, acquire_commit_graph, acquire_midx,
    repo_open, snapshot_plan,
};
use tempfile::TempDir;

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn run_git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git command failed: {args:?}");
}

fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(out.status.success(), "git command failed: {args:?}");
    String::from_utf8(out.stdout).expect("git output not utf8")
}

fn decode_hex(hex: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(hex.len() / 2);
    let bytes = hex.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap();
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap();
        out.push(((hi << 4) | lo) as u8);
        i += 2;
    }
    out
}

fn oid_from_hex(hex: &str) -> OidBytes {
    let bytes = decode_hex(hex.trim());
    OidBytes::from_slice(&bytes)
}

fn init_repo_with_commits(count: usize) -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    for i in 0..count {
        let msg = format!("c{i}");
        run_git(tmp.path(), &["commit", "--allow-empty", "-m", &msg]);
    }

    // Pack objects so acquire_midx can find .idx files.
    run_git(tmp.path(), &["repack", "-ad"]);

    tmp
}

struct TestResolver {
    refs: Vec<(Vec<u8>, OidBytes)>,
}

impl StartSetResolver for TestResolver {
    fn resolve(
        &self,
        _paths: &scanner_git::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(self.refs.clone())
    }
}

struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

#[test]
fn snapshot_plan_emits_ref_tips() {
    if !git_available() {
        eprintln!("git not available; skipping snapshot integration test");
        return;
    }

    let tmp = init_repo_with_commits(3);

    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let prev = git_output(tmp.path(), &["rev-parse", "HEAD~1"]);

    let head_oid = oid_from_hex(&head);
    let prev_oid = oid_from_hex(&prev);

    let resolver = TestResolver {
        refs: vec![
            (b"refs/heads/main".to_vec(), head_oid),
            (b"refs/heads/feature".to_vec(), prev_oid),
        ],
    };

    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        99,
        [0u8; 32],
        start_set_id,
        &resolver,
        &EmptyWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let limits = ArtifactBuildLimits::default();
    let midx_result = acquire_midx(&mut state, &limits).unwrap();
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), state.object_format).unwrap();
    let cg = acquire_commit_graph(&state, &midx_view, &midx_result.pack_paths, &limits).unwrap();

    let plan = snapshot_plan(&state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();

    assert_eq!(plan.len(), 2);

    let pos_main = cg.lookup(&head_oid).unwrap().unwrap();
    let pos_feature = cg.lookup(&prev_oid).unwrap().unwrap();

    assert_eq!(plan[0].pos, pos_feature);
    assert!(plan[0].snapshot_root);
    assert_eq!(plan[1].pos, pos_main);
    assert!(plan[1].snapshot_root);
}
