//! Integration tests for commit-graph range walking against a real `git` repo.
//!
//! Each test creates a temporary repository with `git` CLI commands, builds
//! in-memory artifacts (MIDX + commit graph), and verifies that `CommitPlanIter`
//! produces the expected commit ranges.
//!
//! # Scenarios
//! - **Linear with watermark**: walks only commits between watermark and tip.
//! - **Missing watermark**: falls back to scanning full history.
//! - **Non-ancestor watermark**: detects divergent histories and scans full history.
//!
//! Requires `git` on `PATH`; tests skip gracefully if unavailable.

use std::fs;
use std::path::Path;
use std::process::Command;

use scanner_git::OidBytes;
use scanner_git::{
    ArtifactAcquireError, ArtifactBuildLimits, CommitGraph, CommitGraphMem, CommitPlanIter,
    CommitWalkLimits, MidxView, RefWatermarkStore, RepoOpenError, RepoOpenLimits, StartSetConfig,
    StartSetResolver, acquire_commit_graph, acquire_midx, repo_open,
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
    while i + 1 < bytes.len() {
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

fn rev_list(repo: &Path, rev: &str) -> Vec<OidBytes> {
    let out = git_output(repo, &["rev-list", rev]);
    out.lines().map(oid_from_hex).collect()
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

fn init_repo_with_branches() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("base.txt"), "base\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "base"]);

    run_git(tmp.path(), &["checkout", "-b", "other"]);
    fs::write(tmp.path().join("other.txt"), "other\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "other"]);

    run_git(tmp.path(), &["checkout", "main"]);
    fs::write(tmp.path().join("main.txt"), "main\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "main"]);

    // Pack objects so acquire_midx can find .idx files.
    run_git(tmp.path(), &["repack", "-ad"]);

    tmp
}

fn remove_disk_artifacts(repo: &Path) {
    let objects_dir = repo.join(".git").join("objects");
    let midx_path = objects_dir.join("pack").join("multi-pack-index");
    let commit_graph_path = objects_dir.join("info").join("commit-graph");
    let chain_path = objects_dir
        .join("info")
        .join("commit-graphs")
        .join("commit-graph-chain");

    let _ = fs::remove_file(&midx_path);
    let _ = fs::remove_file(&commit_graph_path);
    let _ = fs::remove_file(&chain_path);

    assert!(!midx_path.exists(), "midx should be absent in fixture");
    assert!(
        !commit_graph_path.exists(),
        "commit-graph should be absent in fixture"
    );
    assert!(
        !chain_path.exists(),
        "commit-graph chain should be absent in fixture"
    );
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

struct TestWatermarkStore {
    watermarks: Vec<(Vec<u8>, Option<OidBytes>)>,
}

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        let mut out = Vec::with_capacity(ref_names.len());
        for name in ref_names {
            let mut found = None;
            for (n, wm) in &self.watermarks {
                if n.as_slice() == *name {
                    found = *wm;
                    break;
                }
            }
            out.push(found);
        }
        Ok(out)
    }
}

/// Build an in-memory commit graph from a mutable `RepoJobState`.
fn build_commit_graph(state: &mut RepoJobState) -> CommitGraphMem {
    let limits = ArtifactBuildLimits::default();
    let midx_result = acquire_midx(state, &limits).unwrap();
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), state.object_format).unwrap();
    acquire_commit_graph(state, &midx_view, &midx_result.pack_paths, &limits).unwrap()
}

use scanner_git::RepoJobState;

/// With a watermark two commits behind HEAD, only the commits between the watermark (exclusive) and tip should be walked.
#[test]
fn commit_walk_linear_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(4);

    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let head_parent = git_output(tmp.path(), &["rev-parse", "HEAD~1"]);
    let watermark = git_output(tmp.path(), &["rev-parse", "HEAD~2"]);

    let tip_oid = oid_from_hex(&head);
    let parent_oid = oid_from_hex(&head_parent);
    let watermark_oid = oid_from_hex(&watermark);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore {
        watermarks: vec![(b"refs/heads/main".to_vec(), Some(watermark_oid))],
    };

    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        42,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let cg = build_commit_graph(&mut state);

    let iter = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();
    let mut out = Vec::new();
    for item in iter {
        out.push(item.unwrap().pos.0);
    }

    let tip_pos = cg.lookup(&tip_oid).unwrap().unwrap().0;
    let parent_pos = cg.lookup(&parent_oid).unwrap().unwrap().0;

    assert_eq!(out, vec![tip_pos, parent_pos]);
}

/// When no watermark exists for a ref, the walker must scan the entire history reachable from the tip.
#[test]
fn commit_walk_missing_watermark_scans_full_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(3);
    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let tip_oid = oid_from_hex(&head);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore { watermarks: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let cg = build_commit_graph(&mut state);
    let mut actual: Vec<u32> = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE)
        .unwrap()
        .map(|item| item.unwrap().pos.0)
        .collect();
    actual.sort_unstable();

    let expected_oids = rev_list(tmp.path(), "HEAD");
    let mut expected: Vec<u32> = expected_oids
        .iter()
        .map(|oid| cg.lookup(oid).unwrap().unwrap().0)
        .collect();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

/// When the watermark points to a commit on a different branch (not an ancestor of the tip), the walker falls back to full history.
#[test]
fn commit_walk_watermark_not_ancestor_scans_full_history() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_branches();
    let head = git_output(tmp.path(), &["rev-parse", "HEAD"]);
    let other = git_output(tmp.path(), &["rev-parse", "other"]);
    let tip_oid = oid_from_hex(&head);
    let other_oid = oid_from_hex(&other);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
    };
    let watermark_store = TestWatermarkStore {
        watermarks: vec![(b"refs/heads/main".to_vec(), Some(other_oid))],
    };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        8,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let cg = build_commit_graph(&mut state);
    let mut actual: Vec<u32> = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE)
        .unwrap()
        .map(|item| item.unwrap().pos.0)
        .collect();
    actual.sort_unstable();

    let expected_oids = rev_list(tmp.path(), "main");
    let mut expected: Vec<u32> = expected_oids
        .iter()
        .map(|oid| cg.lookup(oid).unwrap().unwrap().0)
        .collect();
    expected.sort_unstable();

    assert_eq!(actual, expected);
}

/// With missing on-disk artifacts, a resolvable non-empty start set should be
/// handled safely: either build a non-empty graph or return an explicit
/// `EmptyStartSetWithRefs` error.
#[test]
fn commit_walk_missing_artifacts_with_resolved_start_set_is_safe() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(4);
    remove_disk_artifacts(tmp.path());

    let tip_oid = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD"]));
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();
    let run_once = || -> Result<Vec<u32>, ArtifactAcquireError> {
        let resolver = TestResolver {
            refs: vec![(b"refs/heads/main".to_vec(), tip_oid)],
        };
        let watermark_store = TestWatermarkStore { watermarks: vec![] };

        let mut state = repo_open(
            tmp.path(),
            9,
            [0u8; 32],
            start_set_id,
            &resolver,
            &watermark_store,
            RepoOpenLimits::DEFAULT,
        )
        .unwrap();

        assert!(
            !state.start_set.is_empty(),
            "resolver should provide a non-empty start set"
        );

        let limits = ArtifactBuildLimits::default();
        let midx_result = acquire_midx(&mut state, &limits).unwrap();
        let midx_view = MidxView::parse(midx_result.bytes.as_slice(), state.object_format).unwrap();
        let cg = acquire_commit_graph(&state, &midx_view, &midx_result.pack_paths, &limits)?;

        assert!(
            cg.num_commits() > 0,
            "non-empty start set should yield non-empty commit graph"
        );

        let mut actual: Vec<u32> = CommitPlanIter::new(&state, &cg, CommitWalkLimits::RESTRICTIVE)
            .unwrap()
            .map(|item| item.unwrap().pos.0)
            .collect();
        actual.sort_unstable();

        let expected_oids = rev_list(tmp.path(), "HEAD");
        let mut expected: Vec<u32> = expected_oids
            .iter()
            .map(|oid| cg.lookup(oid).unwrap().unwrap().0)
            .collect();
        expected.sort_unstable();

        assert_eq!(actual, expected);
        Ok(actual)
    };

    let first = run_once();
    let second = run_once();
    match (first, second) {
        (Ok(left), Ok(right)) => assert_eq!(left, right, "commit plan must be deterministic"),
        (Err(left), Err(right)) => {
            assert!(
                matches!(left, ArtifactAcquireError::EmptyStartSetWithRefs),
                "unexpected first error: {left:?}"
            );
            assert!(
                matches!(right, ArtifactAcquireError::EmptyStartSetWithRefs),
                "unexpected second error: {right:?}"
            );
        }
        (left, right) => panic!("nondeterministic outcome: left={left:?}, right={right:?}"),
    }
}

#[test]
fn commit_graph_builds_with_loose_tip_chain_not_in_midx() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(1);
    run_git(tmp.path(), &["commit", "--allow-empty", "-m", "loose-1"]);
    run_git(tmp.path(), &["commit", "--allow-empty", "-m", "loose-2"]);

    let head = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD"]));
    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), head)],
    };
    let watermark_store = TestWatermarkStore { watermarks: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        9,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let limits = ArtifactBuildLimits::default();
    let midx_result = acquire_midx(&mut state, &limits).unwrap();
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), state.object_format).unwrap();
    assert!(
        midx_view.find_oid(&head).unwrap().is_none(),
        "fixture expects loose HEAD commit missing from MIDX"
    );

    let cg = acquire_commit_graph(&state, &midx_view, &midx_result.pack_paths, &limits).unwrap();
    let expected = rev_list(tmp.path(), "HEAD");

    assert_eq!(cg.num_commits(), expected.len() as u32);
    for oid in &expected {
        assert!(
            cg.lookup(oid).unwrap().is_some(),
            "expected commit {oid} to be present in in-memory graph"
        );
    }
}

#[test]
fn commit_graph_builds_with_packed_parent_and_loose_head() {
    if !git_available() {
        eprintln!("git not available; skipping commit walk integration test");
        return;
    }

    let tmp = init_repo_with_commits(2);
    let packed_parent = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD"]));
    run_git(tmp.path(), &["commit", "--allow-empty", "-m", "loose-head"]);
    let loose_head = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD"]));

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), loose_head)],
    };
    let watermark_store = TestWatermarkStore { watermarks: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        10,
        [0u8; 32],
        start_set_id,
        &resolver,
        &watermark_store,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    let limits = ArtifactBuildLimits::default();
    let midx_result = acquire_midx(&mut state, &limits).unwrap();
    let midx_view = MidxView::parse(midx_result.bytes.as_slice(), state.object_format).unwrap();
    assert!(
        midx_view.find_oid(&loose_head).unwrap().is_none(),
        "fixture expects loose HEAD commit missing from MIDX"
    );
    assert!(
        midx_view.find_oid(&packed_parent).unwrap().is_some(),
        "fixture expects parent commit present in MIDX"
    );

    let cg = acquire_commit_graph(&state, &midx_view, &midx_result.pack_paths, &limits).unwrap();

    assert!(cg.lookup(&loose_head).unwrap().is_some());
    assert!(cg.lookup(&packed_parent).unwrap().is_some());
}
