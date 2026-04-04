//! Integration tests for tree diff and object store against a real Git repo.
//!
//! These tests build small repos, write commit-graph/MIDX artifacts, and then
//! compare tree-diff behavior against `git diff-tree` output or explicit
//! expectations. They also exercise spill partitioning and corrupt-tree
//! error reporting.
//!
//! # Test Harness
//! These tests require a `git` CLI with multi-pack-index support; otherwise
//! they skip. Repos are fully packed and have commit-graph/MIDX artifacts
//! because the object store requires those ready artifacts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use std::sync::atomic::AtomicBool;

use scanner_git::{
    ArtifactBuildLimits, BlobIntroducer, CandidateBuffer, CandidateSink, ChangeKind,
    CollectedUniqueBlob, CollectingUniqueBlobSink, CommitGraph, CommitGraphIndex, CommitWalkLimits,
    MergeDiffMode, MidxView, NeverSeenStore, ObjectStore, OidIndex, ParentScratch,
    RefWatermarkStore, RepoOpenError, RepoOpenLimits, SpillLimits, Spiller, StartSetConfig,
    StartSetResolver, TreeBytes, TreeDiffError, TreeDiffLimits, TreeDiffWalker, TreeSource,
    acquire_commit_graph, acquire_midx, introduced_by_plan, repo_open,
};
use scanner_git::{OidBytes, PlannedCommit, RepoJobState};
use tempfile::TempDir;

static NEVER_ABORT: AtomicBool = AtomicBool::new(false);

/// Returns true when the `git` CLI is available on the host.
fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

/// Returns true when this git build supports the MIDX command.
fn git_supports_midx() -> bool {
    // Some Git builds omit the multi-pack-index command; probing `--help`
    // keeps the check fast and portable.
    Command::new("git")
        .args(["multi-pack-index", "--help"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

/// Runs a git command inside `repo` and asserts success.
fn run_git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(repo)
        .status()
        .expect("failed to run git");
    assert!(status.success(), "git command failed: {args:?}");
}

/// Runs a git command and returns UTF-8 stdout, asserting success.
fn git_output(repo: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .args(args)
        .current_dir(repo)
        .output()
        .expect("failed to run git");
    assert!(out.status.success(), "git command failed: {args:?}");
    String::from_utf8(out.stdout).expect("git output not utf8")
}

/// Decode a hex string into bytes (expects even length and valid hex digits).
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

/// Parse a Git object ID from hex output.
fn oid_from_hex(hex: &str) -> OidBytes {
    let bytes = decode_hex(hex.trim());
    OidBytes::from_slice(&bytes)
}

/// Start set resolver that returns fixed refs.
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

/// Watermark store that returns no watermarks for all refs.
struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

/// Create a repo with a simple two-commit history.
///
/// The second commit modifies, adds, and deletes paths to exercise tree diff.
fn prepare_repo_with_commits() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("a.txt"), "one\n").unwrap();
    fs::create_dir_all(tmp.path().join("dir")).unwrap();
    fs::write(tmp.path().join("dir/b.txt"), "two\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c1"]);

    fs::write(tmp.path().join("a.txt"), "one\nchanged\n").unwrap();
    fs::write(tmp.path().join("dir/c.txt"), "three\n").unwrap();
    fs::remove_file(tmp.path().join("dir/b.txt")).unwrap();
    run_git(tmp.path(), &["add", "-A"]);
    run_git(tmp.path(), &["commit", "-m", "c2"]);

    // Prepare artifacts expected by the object store.
    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

/// Create a repo with many files to force large tree payloads.
fn prepare_repo_with_many_files(count: usize) -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    for idx in 0..count {
        let path = tmp.path().join(format!("file_{idx:04}.txt"));
        fs::write(path, format!("line {idx}\n")).unwrap();
    }

    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "initial"]);

    // Modify one file to create a second commit.
    fs::write(tmp.path().join("file_0000.txt"), "updated\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "update"]);

    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

/// Create a repo with a two-parent merge commit for merge diff tests.
fn prepare_repo_with_merge() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("a.txt"), "base\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "base"]);

    run_git(tmp.path(), &["checkout", "-b", "feature"]);
    fs::write(tmp.path().join("feature.txt"), "feature\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "feature"]);

    run_git(tmp.path(), &["checkout", "main"]);
    fs::write(tmp.path().join("a.txt"), "base\nmain\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "main change"]);

    run_git(
        tmp.path(),
        &["merge", "--no-ff", "feature", "-m", "merge feature"],
    );

    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

/// Create a repo where a blob appears under an excluded path first, then a non-excluded path.
fn prepare_repo_with_excluded_blob_paths() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    let content = b"secret payload\n";
    fs::write(tmp.path().join("image.png"), content).unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c1"]);

    fs::create_dir_all(tmp.path().join("src")).unwrap();
    fs::write(tmp.path().join("src/secret.txt"), content).unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c2"]);

    run_git(tmp.path(), &["repack", "-ad"]);
    run_git(tmp.path(), &["multi-pack-index", "write"]);

    tmp
}

/// Create a repo where two commits introduce the same blob content under
/// different paths (`loose.txt` and `loose_dup.txt`). All objects are packed
/// so the in-memory artifact builders can find every commit.
fn prepare_repo_with_duplicate_blobs() -> TempDir {
    let tmp = TempDir::new().unwrap();
    run_git(tmp.path(), &["init", "-b", "main"]);
    run_git(tmp.path(), &["config", "user.email", "test@example.com"]);
    run_git(tmp.path(), &["config", "user.name", "Test User"]);

    fs::write(tmp.path().join("packed.txt"), "packed\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c1"]);

    fs::write(tmp.path().join("loose.txt"), "loose\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c2"]);

    fs::write(tmp.path().join("loose_dup.txt"), "loose\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "c3"]);

    // Pack everything so in-memory artifact builders can load all commits.
    run_git(tmp.path(), &["repack", "-ad"]);

    tmp
}

/// Open repo state and build in-memory artifacts (MIDX + commit graph).
///
/// Returns the mutable state with MIDX populated.
fn open_repo_state(repo: &Path) -> RepoJobState {
    let head = git_output(repo, &["rev-parse", "HEAD"]);
    let head_oid = oid_from_hex(&head);

    let resolver = TestResolver {
        refs: vec![(b"refs/heads/main".to_vec(), head_oid)],
    };
    // Keep the start set consistent with the resolver: only the default branch.
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        repo,
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &EmptyWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    // Build MIDX in-memory (populates state.mmaps.midx).
    let limits = ArtifactBuildLimits::default();
    acquire_midx(&mut state, &limits).unwrap();

    state
}

/// Build an in-memory commit graph from a `RepoJobState` that already has MIDX populated.
fn build_commit_graph_from_state(state: &RepoJobState) -> scanner_git::CommitGraphMem {
    let midx_bytes = state.mmaps.midx.as_ref().unwrap().as_ref();
    let midx = MidxView::parse(midx_bytes, state.object_format).unwrap();

    let pack_dirs = scanner_git::collect_pack_dirs(&state.paths);
    let pack_paths = scanner_git::resolve_pack_paths_from_midx(&midx, &pack_dirs).unwrap();

    let limits = ArtifactBuildLimits::default();
    acquire_commit_graph(state, &midx, &pack_paths, &limits).unwrap()
}

/// Collect tree diff change kinds into a map keyed by UTF-8 path.
///
/// The repo fixtures use ASCII paths, so the UTF-8 conversion is lossless.
fn diff_paths(
    store: &mut ObjectStore,
    limits: &TreeDiffLimits,
    new_tree: &OidBytes,
    old_tree: &OidBytes,
    parent_idx: u8,
) -> BTreeMap<String, ChangeKind> {
    let mut walker = TreeDiffWalker::new(limits, store.oid_len());
    let mut candidates = CandidateBuffer::new(limits, store.oid_len());

    walker
        .diff_trees(
            store,
            &mut candidates,
            Some(new_tree),
            Some(old_tree),
            0,
            parent_idx,
            &NEVER_ABORT,
        )
        .unwrap();

    let mut out = BTreeMap::new();
    for cand in candidates.iter_resolved() {
        let path = String::from_utf8_lossy(cand.path).into_owned();
        out.insert(path, cand.change_kind);
    }
    out
}

#[test]
fn tree_diff_matches_git_diff_tree() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping tree diff test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();
    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());

    let new_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD"],
    ));
    let old_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD~1"],
    ));

    walker
        .diff_trees(
            &mut store,
            &mut candidates,
            Some(&new_tree),
            Some(&old_tree),
            0,
            0,
            &NEVER_ABORT,
        )
        .unwrap();

    let diff = git_output(
        tmp.path(),
        &[
            "diff-tree",
            "-r",
            "--name-status",
            "--no-commit-id",
            "--no-renames",
            "HEAD~1",
            "HEAD",
        ],
    );

    // Baseline expected changes from git itself.
    let mut expected: BTreeMap<String, ChangeKind> = BTreeMap::new();
    for line in diff.lines() {
        let mut parts = line.splitn(2, '\t');
        let status = parts.next().unwrap_or("");
        let path = parts.next().unwrap_or("");
        let kind = match status {
            "A" => ChangeKind::Add,
            "M" => ChangeKind::Modify,
            _ => continue,
        };
        expected.insert(path.to_string(), kind);
    }

    let mut actual: BTreeMap<String, ChangeKind> = BTreeMap::new();
    for cand in candidates.iter_resolved() {
        let path = String::from_utf8_lossy(cand.path).into_owned();
        actual.insert(path, cand.change_kind);
    }

    assert_eq!(actual, expected);
}

#[test]
fn blob_introducer_matches_diff_history_unique_oids() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping blob introducer test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();
    let cg = build_commit_graph_from_state(&state);
    let commit_limits = CommitWalkLimits::RESTRICTIVE;
    let plan = introduced_by_plan(&state, &cg, commit_limits).unwrap();

    let mut diff_set = BTreeSet::new();
    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    for PlannedCommit { pos, .. } in &plan {
        let commit_id = pos.0;
        let new_tree = cg.root_tree_oid(*pos);

        parent_scratch.clear();
        cg.collect_parents(
            *pos,
            commit_limits.max_parents_per_commit,
            &mut parent_scratch,
        )
        .unwrap();
        let parents = parent_scratch.as_slice();

        if parents.is_empty() {
            walker
                .diff_trees(
                    &mut store,
                    &mut candidates,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                    &NEVER_ABORT,
                )
                .unwrap();
        } else {
            for (idx, parent_pos) in parents.iter().enumerate() {
                let old_tree = cg.root_tree_oid(*parent_pos);
                walker
                    .diff_trees(
                        &mut store,
                        &mut candidates,
                        Some(&new_tree),
                        Some(&old_tree),
                        commit_id,
                        idx as u8,
                        &NEVER_ABORT,
                    )
                    .unwrap();
            }
        }

        for cand in candidates.iter_resolved() {
            diff_set.insert(cand.oid);
        }
        candidates.clear();
    }

    let midx_bytes = state.mmaps.midx.as_ref().unwrap().as_ref();
    let midx = MidxView::parse(midx_bytes, state.object_format).unwrap();
    let oid_index = OidIndex::from_midx(&midx);

    let cg_index = CommitGraphIndex::build(&cg).unwrap();
    let mut introducer = BlobIntroducer::new(
        &limits,
        state.object_format.oid_len(),
        midx.object_count(),
        limits.max_candidates,
        false,
    );
    let mut intro_candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());
    introducer
        .introduce(
            &mut store,
            &cg_index,
            &plan,
            &oid_index,
            &NEVER_ABORT,
            &mut intro_candidates,
        )
        .unwrap();

    let mut intro_set = BTreeSet::new();
    for cand in intro_candidates.iter_resolved() {
        intro_set.insert(cand.oid);
    }

    assert_eq!(diff_set, intro_set);
}

#[test]
fn blob_introducer_prefers_first_non_excluded_path() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping path policy test");
        return;
    }

    let tmp = prepare_repo_with_excluded_blob_paths();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();
    let cg = build_commit_graph_from_state(&state);
    let commit_limits = CommitWalkLimits::RESTRICTIVE;
    let plan = introduced_by_plan(&state, &cg, commit_limits).unwrap();

    let midx_bytes = state.mmaps.midx.as_ref().unwrap().as_ref();
    let midx = MidxView::parse(midx_bytes, state.object_format).unwrap();
    let oid_index = OidIndex::from_midx(&midx);
    let cg_index = CommitGraphIndex::build(&cg).unwrap();

    let mut introducer = BlobIntroducer::new(
        &limits,
        state.object_format.oid_len(),
        midx.object_count(),
        limits.max_candidates,
        false,
    );
    let mut intro_candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());
    introducer
        .introduce(
            &mut store,
            &cg_index,
            &plan,
            &oid_index,
            &NEVER_ABORT,
            &mut intro_candidates,
        )
        .unwrap();

    let mut paths: Vec<String> = intro_candidates
        .iter_resolved()
        .map(|cand| String::from_utf8_lossy(cand.path).into_owned())
        .collect();
    paths.sort();

    assert!(paths.contains(&"src/secret.txt".to_string()));
    assert!(!paths.contains(&"image.png".to_string()));
    assert_eq!(paths.len(), 1);
}

#[test]
fn blob_introducer_dedupes_duplicate_oids() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping duplicate oid test");
        return;
    }

    let tmp = prepare_repo_with_duplicate_blobs();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();
    let cg = build_commit_graph_from_state(&state);
    let commit_limits = CommitWalkLimits::RESTRICTIVE;
    let plan = introduced_by_plan(&state, &cg, commit_limits).unwrap();

    let midx_bytes = state.mmaps.midx.as_ref().unwrap().as_ref();
    let midx = MidxView::parse(midx_bytes, state.object_format).unwrap();
    let oid_index = OidIndex::from_midx(&midx);
    let cg_index = CommitGraphIndex::build(&cg).unwrap();

    let mut introducer = BlobIntroducer::new(
        &limits,
        state.object_format.oid_len(),
        midx.object_count(),
        limits.max_candidates,
        false,
    );
    let mut intro_candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());
    introducer
        .introduce(
            &mut store,
            &cg_index,
            &plan,
            &oid_index,
            &NEVER_ABORT,
            &mut intro_candidates,
        )
        .unwrap();

    let loose_oid = oid_from_hex(&git_output(tmp.path(), &["hash-object", "loose.txt"]));
    let mut paths = Vec::new();
    for cand in intro_candidates.iter_resolved() {
        if cand.oid == loose_oid {
            paths.push(String::from_utf8_lossy(cand.path).into_owned());
        }
    }

    assert_eq!(paths.len(), 1);
    assert_eq!(paths[0], "loose.txt");
}

#[test]
fn tree_diff_spill_path_uses_spill_arena() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping spill path test");
        return;
    }

    let tmp = prepare_repo_with_many_files(128);
    let state = open_repo_state(tmp.path());

    // Force spill behavior by keeping the cache tiny.
    let mut limits = TreeDiffLimits::RESTRICTIVE;
    limits.max_tree_cache_bytes = 64;
    limits.max_tree_spill_bytes = 1024 * 1024;
    limits.max_tree_bytes_in_flight = 8 * 1024 * 1024;
    limits.max_path_arena_bytes = 1024 * 1024;

    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();

    let new_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD"],
    ));
    let old_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD~1"],
    ));

    let bytes = store.load_tree(&new_tree).unwrap();
    assert!(matches!(bytes, TreeBytes::Spilled(_)));

    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());

    walker
        .diff_trees(
            &mut store,
            &mut candidates,
            Some(&new_tree),
            Some(&old_tree),
            0,
            0,
            &NEVER_ABORT,
        )
        .unwrap();

    assert!(!candidates.is_empty());
}

#[test]
fn tree_diff_streaming_matches_buffered() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping streaming test");
        return;
    }

    let tmp = prepare_repo_with_many_files(128);
    let state = open_repo_state(tmp.path());

    let new_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD"],
    ));
    let old_tree = oid_from_hex(&git_output(
        tmp.path(),
        &["show", "-s", "--format=%T", "HEAD~1"],
    ));

    // Streaming limits: tiny cache/spill budgets to maximize re-reads.
    let mut limits_stream = TreeDiffLimits::RESTRICTIVE;
    limits_stream.max_tree_cache_bytes = 64;
    limits_stream.max_tree_spill_bytes = 1;
    limits_stream.max_tree_bytes_in_flight = 8 * 1024 * 1024;
    limits_stream.max_path_arena_bytes = 1024 * 1024;

    // Buffered limits: large cache/spill budgets to maximize reuse.
    let mut limits_buffered = limits_stream;
    limits_buffered.max_tree_cache_bytes = 8 * 1024 * 1024;
    limits_buffered.max_tree_spill_bytes = 8 * 1024 * 1024;

    let spill_stream = tempfile::tempdir().unwrap();
    let spill_buffered = tempfile::tempdir().unwrap();

    let mut store_stream = ObjectStore::open(&state, &limits_stream, spill_stream.path()).unwrap();
    let mut store_buffered =
        ObjectStore::open(&state, &limits_buffered, spill_buffered.path()).unwrap();

    let out_stream = diff_paths(&mut store_stream, &limits_stream, &new_tree, &old_tree, 0);
    let out_buffered = diff_paths(
        &mut store_buffered,
        &limits_buffered,
        &new_tree,
        &old_tree,
        0,
    );

    assert_eq!(out_stream, out_buffered);
}

#[test]
fn corrupt_tree_is_reported() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping corrupt tree test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();
    let mut walker = TreeDiffWalker::new(&limits, state.object_format.oid_len());
    let mut candidates = CandidateBuffer::new(&limits, state.object_format.oid_len());

    let corrupt_oid = OidBytes::sha1([0x11; 20]);
    write_corrupt_tree(state.paths.objects_dir(), &corrupt_oid);

    let result = walker.diff_trees(
        &mut store,
        &mut candidates,
        Some(&corrupt_oid),
        None,
        0,
        0,
        &NEVER_ABORT,
    );

    assert!(matches!(result, Err(TreeDiffError::CorruptTree { .. })));
}

#[test]
fn merge_diff_modes_emit_expected_candidates() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping merge diff test");
        return;
    }

    let tmp = prepare_repo_with_merge();
    let state = open_repo_state(tmp.path());

    let merge_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^{tree}"]));
    let parent1_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^1^{tree}"]));
    let parent2_tree = oid_from_hex(&git_output(tmp.path(), &["rev-parse", "HEAD^2^{tree}"]));

    let limits = TreeDiffLimits::RESTRICTIVE;
    let spill = tempfile::tempdir().unwrap();
    let mut store = ObjectStore::open(&state, &limits, spill.path()).unwrap();

    let first_parent = diff_paths(&mut store, &limits, &merge_tree, &parent1_tree, 0);
    let second_parent = diff_paths(&mut store, &limits, &merge_tree, &parent2_tree, 1);

    assert!(first_parent.contains_key("feature.txt"));
    assert!(!first_parent.contains_key("a.txt"));
    assert!(second_parent.contains_key("a.txt"));
    assert!(!second_parent.contains_key("feature.txt"));

    let all_parents =
        collect_merge_candidates(MergeDiffMode::AllParents, &first_parent, &second_parent);
    let first_only = collect_merge_candidates(
        MergeDiffMode::FirstParentOnly,
        &first_parent,
        &second_parent,
    );

    assert!(all_parents.contains_key("feature.txt"));
    assert!(all_parents.contains_key("a.txt"));
    assert_eq!(first_only.len(), 1);
    assert!(first_only.contains_key("feature.txt"));
}

/// Merge diff mode helper: compose expected per-parent change maps.
fn collect_merge_candidates(
    mode: MergeDiffMode,
    first_parent: &BTreeMap<String, ChangeKind>,
    second_parent: &BTreeMap<String, ChangeKind>,
) -> BTreeMap<String, ChangeKind> {
    match mode {
        MergeDiffMode::AllParents => {
            let mut out = first_parent.clone();
            out.extend(second_parent.iter().map(|(k, v)| (k.clone(), *v)));
            out
        }
        MergeDiffMode::FirstParentOnly => first_parent.clone(),
    }
}

/// Collect unique blobs via spill with the supplied limits.
///
/// This uses streaming candidate emission into `Spiller` to exercise the
/// spill partitioning logic under tight limits.
fn collect_unique_blobs(state: &RepoJobState, limits: SpillLimits) -> Vec<CollectedUniqueBlob> {
    let cg = build_commit_graph_from_state(state);
    let plan = introduced_by_plan(state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();

    let tree_limits = TreeDiffLimits::RESTRICTIVE;
    let tmp = TempDir::new().unwrap();
    let mut store = ObjectStore::open(state, &tree_limits, tmp.path()).unwrap();
    let mut walker = TreeDiffWalker::new(&tree_limits, state.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();

    let mut spiller = Spiller::new(limits, state.object_format.oid_len(), tmp.path()).unwrap();

    struct SpillSink<'a> {
        spiller: &'a mut Spiller,
    }

    impl CandidateSink for SpillSink<'_> {
        fn emit(
            &mut self,
            oid: OidBytes,
            path: &[u8],
            commit_id: u32,
            parent_idx: u8,
            change_kind: ChangeKind,
            ctx_flags: u16,
            cand_flags: u16,
        ) -> Result<(), TreeDiffError> {
            // Translate candidate emission into spiller pushes.
            self.spiller
                .push(
                    oid,
                    path,
                    commit_id,
                    parent_idx,
                    change_kind,
                    ctx_flags,
                    cand_flags,
                )
                .map_err(|err| TreeDiffError::CandidateSinkError {
                    detail: err.to_string(),
                })
        }
    }

    {
        let mut sink = SpillSink {
            spiller: &mut spiller,
        };
        for PlannedCommit { pos, snapshot_root } in &plan {
            let commit_id = pos.0;
            let new_tree = cg.root_tree_oid(*pos);

            if *snapshot_root {
                walker
                    .diff_trees(
                        &mut store,
                        &mut sink,
                        Some(&new_tree),
                        None,
                        commit_id,
                        0,
                        &NEVER_ABORT,
                    )
                    .unwrap();
                continue;
            }

            parent_scratch.clear();
            cg.collect_parents(
                *pos,
                CommitWalkLimits::RESTRICTIVE.max_parents_per_commit,
                &mut parent_scratch,
            )
            .unwrap();
            let parents = parent_scratch.as_slice();

            if parents.is_empty() {
                walker
                    .diff_trees(
                        &mut store,
                        &mut sink,
                        Some(&new_tree),
                        None,
                        commit_id,
                        0,
                        &NEVER_ABORT,
                    )
                    .unwrap();
                continue;
            }

            let merge_mode = MergeDiffMode::AllParents;
            match merge_mode {
                MergeDiffMode::AllParents => {
                    for (idx, parent_pos) in parents.iter().enumerate() {
                        let old_tree = cg.root_tree_oid(*parent_pos);
                        walker
                            .diff_trees(
                                &mut store,
                                &mut sink,
                                Some(&new_tree),
                                Some(&old_tree),
                                commit_id,
                                idx as u8,
                                &NEVER_ABORT,
                            )
                            .unwrap();
                    }
                }
                MergeDiffMode::FirstParentOnly => {
                    let old_tree = cg.root_tree_oid(parents[0]);
                    walker
                        .diff_trees(
                            &mut store,
                            &mut sink,
                            Some(&new_tree),
                            Some(&old_tree),
                            commit_id,
                            0,
                            &NEVER_ABORT,
                        )
                        .unwrap();
                }
            }
        }
    }

    let store = NeverSeenStore;
    let mut sink = CollectingUniqueBlobSink::default();
    spiller
        .finalize(&store, &scanner_git::NullSeenBitmapPersister, &mut sink)
        .unwrap();
    sink.blobs
}

/// Collect unique blobs using a buffered candidate path before spilling.
///
/// This mirrors `collect_unique_blobs` but uses `CandidateBuffer` to ensure
/// buffered and streaming paths are equivalent.
fn collect_unique_blobs_buffered(
    state: &RepoJobState,
    limits: SpillLimits,
) -> Vec<CollectedUniqueBlob> {
    let cg = build_commit_graph_from_state(state);
    let plan = introduced_by_plan(state, &cg, CommitWalkLimits::RESTRICTIVE).unwrap();

    let tree_limits = TreeDiffLimits::RESTRICTIVE;
    let tmp = TempDir::new().unwrap();
    let mut store = ObjectStore::open(state, &tree_limits, tmp.path()).unwrap();
    let mut walker = TreeDiffWalker::new(&tree_limits, state.object_format.oid_len());
    let mut parent_scratch = ParentScratch::new();
    let mut buffer = CandidateBuffer::new(&tree_limits, state.object_format.oid_len());
    let mut spiller = Spiller::new(limits, state.object_format.oid_len(), tmp.path()).unwrap();

    for PlannedCommit { pos, snapshot_root } in &plan {
        let commit_id = pos.0;
        let new_tree = cg.root_tree_oid(*pos);

        if *snapshot_root {
            walker
                .diff_trees(
                    &mut store,
                    &mut buffer,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                    &NEVER_ABORT,
                )
                .unwrap();
            continue;
        }

        parent_scratch.clear();
        cg.collect_parents(
            *pos,
            CommitWalkLimits::RESTRICTIVE.max_parents_per_commit,
            &mut parent_scratch,
        )
        .unwrap();
        let parents = parent_scratch.as_slice();

        if parents.is_empty() {
            walker
                .diff_trees(
                    &mut store,
                    &mut buffer,
                    Some(&new_tree),
                    None,
                    commit_id,
                    0,
                    &NEVER_ABORT,
                )
                .unwrap();
            continue;
        }

        for (idx, parent_pos) in parents.iter().enumerate() {
            let old_tree = cg.root_tree_oid(*parent_pos);
            walker
                .diff_trees(
                    &mut store,
                    &mut buffer,
                    Some(&new_tree),
                    Some(&old_tree),
                    commit_id,
                    idx as u8,
                    &NEVER_ABORT,
                )
                .unwrap();
        }
    }

    for cand in buffer.iter_resolved() {
        spiller
            .push(
                cand.oid,
                cand.path,
                cand.commit_id,
                cand.parent_idx,
                cand.change_kind,
                cand.ctx_flags,
                cand.cand_flags,
            )
            .unwrap();
    }

    let store = NeverSeenStore;
    let mut sink = CollectingUniqueBlobSink::default();
    spiller
        .finalize(&store, &scanner_git::NullSeenBitmapPersister, &mut sink)
        .unwrap();
    sink.blobs
}

fn sort_unique_blobs(blobs: &mut [CollectedUniqueBlob]) {
    blobs.sort_by(|a, b| {
        (
            a.oid,
            a.ctx.commit_id,
            a.ctx.parent_idx,
            a.ctx.change_kind.as_u8(),
            a.ctx.ctx_flags,
            a.ctx.cand_flags,
            &a.path,
        )
            .cmp(&(
                b.oid,
                b.ctx.commit_id,
                b.ctx.parent_idx,
                b.ctx.change_kind.as_u8(),
                b.ctx.ctx_flags,
                b.ctx.cand_flags,
                &b.path,
            ))
    });
}

#[test]
fn spill_limits_streaming_is_partition_invariant() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping spill limits test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let mut limits_small = SpillLimits::RESTRICTIVE;
    limits_small.max_chunk_candidates = 2;
    limits_small.max_chunk_path_bytes = 64;
    limits_small.seen_batch_max_oids = 2;
    limits_small.seen_batch_max_path_bytes = 64;
    limits_small.max_path_len = 64;

    let mut limits_large = limits_small;
    limits_large.max_chunk_candidates = 1024;
    limits_large.max_chunk_path_bytes = 4096;

    let mut out_small = collect_unique_blobs(&state, limits_small);
    let mut out_large = collect_unique_blobs(&state, limits_large);

    sort_unique_blobs(&mut out_small);
    sort_unique_blobs(&mut out_large);

    assert_eq!(out_small, out_large);
}

#[test]
fn buffered_vs_streaming_candidates_match() {
    if !git_available() || !git_supports_midx() {
        eprintln!("git or multi-pack-index not available; skipping buffered vs streaming test");
        return;
    }

    let tmp = prepare_repo_with_commits();
    let state = open_repo_state(tmp.path());

    let limits = SpillLimits::RESTRICTIVE;
    let mut out_stream = collect_unique_blobs(&state, limits);
    let mut out_buffered = collect_unique_blobs_buffered(&state, limits);

    sort_unique_blobs(&mut out_stream);
    sort_unique_blobs(&mut out_buffered);

    assert_eq!(out_stream, out_buffered);
}

/// Write a corrupt tree object into the object database.
fn write_corrupt_tree(objects_dir: &Path, oid: &OidBytes) {
    // Missing the trailing OID bytes, so the tree entry is truncated.
    let payload = b"100644 file\0";
    let mut data = format!("tree {}\0", payload.len()).into_bytes();
    data.extend_from_slice(payload);

    let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(&data).unwrap();
    let compressed = encoder.finish().unwrap();

    let hex = oid.to_string();
    let (dir, file) = hex.split_at(2);

    let obj_dir = objects_dir.join(dir);
    fs::create_dir_all(&obj_dir).unwrap();
    fs::write(obj_dir.join(file), compressed).unwrap();
}
