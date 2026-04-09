//! Integration tests for repo_open's filesystem discovery and artifact handling.
//!
//! Tests use either synthetic `.git` layouts (for path/ref resolution) or real
//! repos created via `git init` (for pack-based fingerprinting).
use std::fs;
use std::path::{Path, PathBuf};

use crate::git_test_support::{git_available, init_git_repo, run_git};
use scanner_git::OidBytes;
use scanner_git::{
    ArtifactBuildLimits, RefWatermarkStore, RepoOpenError, RepoOpenLimits, StartSetConfig,
    StartSetResolver, acquire_midx, repo_open,
};
use tempfile::TempDir;

/// Writes a minimal commit-graph marker file (not a valid commit-graph).
fn write_commit_graph(objects_dir: &Path) {
    let info_dir = objects_dir.join("info");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("commit-graph"), b"CGPH").unwrap();
}

/// Writes a minimal multi-pack-index marker file (not a valid MIDX).
fn write_midx(pack_dir: &Path) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();
}

/// Creates a minimal worktree .git layout with HEAD, objects, and refs dirs.
fn create_main_repo(root: &Path) -> PathBuf {
    let git_dir = root.join(".git");
    fs::create_dir_all(git_dir.join("objects").join("pack")).unwrap();
    fs::create_dir_all(git_dir.join("refs")).unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    git_dir
}

/// Creates a linked worktree with a .git file pointing at worktrees/<name>.
fn create_linked_worktree(worktree_root: &Path, main_git_dir: &Path, name: &str) -> PathBuf {
    fs::create_dir_all(worktree_root).unwrap();

    let wt_git_dir = main_git_dir.join("worktrees").join(name);
    fs::create_dir_all(&wt_git_dir).unwrap();
    fs::write(wt_git_dir.join("commondir"), "../..\n").unwrap();

    let gitdir_line = format!("gitdir: {}\n", wt_git_dir.to_string_lossy());
    fs::write(worktree_root.join(".git"), gitdir_line).unwrap();

    wt_git_dir
}

/// Writes an info/alternates file with one path per line.
fn write_alternates(objects_dir: &Path, alternates: &[PathBuf]) {
    let alternates_path = objects_dir.join("info").join("alternates");
    fs::create_dir_all(alternates_path.parent().unwrap()).unwrap();

    let mut content = Vec::new();
    for path in alternates {
        content.extend_from_slice(path.to_string_lossy().as_bytes());
        content.push(b'\n');
    }
    fs::write(alternates_path, content).unwrap();
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

struct TestWatermarkStore;

impl RefWatermarkStore for TestWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, RepoOpenError> {
        Ok(ref_names
            .iter()
            .map(|name| {
                if *name == b"refs/heads/a" {
                    Some(scanner_git::RefWatermark {
                        oid: OidBytes::sha1([0x0a; 20]),
                        // OID will not resolve in a real commit graph;
                        // generation satisfies the non-zero invariant.
                        generation: std::num::NonZeroU32::new(1).unwrap(),
                    })
                } else {
                    None
                }
            })
            .collect())
    }
}

#[test]
fn repo_open_linked_worktree_and_alternates() {
    let tmp = TempDir::new().unwrap();

    let main_repo = tmp.path().join("main");
    let main_git_dir = create_main_repo(&main_repo);

    let worktree_root = tmp.path().join("worktree");
    create_linked_worktree(&worktree_root, &main_git_dir, "wt1");

    let objects_dir = main_git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let alt_objects = tmp.path().join("alt-objects");
    fs::create_dir_all(&alt_objects).unwrap();
    write_alternates(&objects_dir, std::slice::from_ref(&alt_objects));

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        &worktree_root,
        7,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert!(state.paths.is_linked_worktree());
    assert_eq!(state.paths.alternate_object_dirs().len(), 1);
    assert!(state.paths.alternate_object_dirs()[0].ends_with("alt-objects"));
}

#[test]
fn repo_open_sorts_refs_and_loads_watermarks() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_main_repo(tmp.path());

    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let resolver = TestResolver {
        refs: vec![
            (b"refs/heads/z".to_vec(), OidBytes::sha1([0x03; 20])),
            (b"refs/heads/a".to_vec(), OidBytes::sha1([0x01; 20])),
            (b"refs/heads/m".to_vec(), OidBytes::sha1([0x02; 20])),
        ],
    };

    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        9,
        [1u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    assert_eq!(state.start_set.len(), 3);

    let names: Vec<&[u8]> = state
        .start_set
        .iter()
        .map(|r| state.ref_names.get(r.name))
        .collect();
    assert_eq!(names[0], b"refs/heads/a");
    assert_eq!(names[1], b"refs/heads/m");
    assert_eq!(names[2], b"refs/heads/z");

    assert!(state.start_set[0].watermark.is_some());
    assert!(state.start_set[1].watermark.is_none());
    assert!(state.start_set[2].watermark.is_none());
}

#[test]
fn repo_open_detects_lock_files() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_main_repo(tmp.path());

    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let lock_path = objects_dir.join("info").join("commit-graph.lock");
    fs::write(lock_path, b"").unwrap();

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let state = repo_open(
        tmp.path(),
        1,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    // Lock files signal ongoing maintenance; the repo reports no usable
    // MIDX or artifact fingerprint when they are present.
    assert!(state.mmaps.midx.is_none());
    assert!(state.artifact_fingerprint.is_none());
}

#[test]
fn repo_open_detects_artifact_changes() {
    // Skip if git is not available.
    if !git_available() {
        eprintln!("git not available; skipping artifact change detection test");
        return;
    }

    let tmp = TempDir::new().unwrap();

    // Create a real repo with a commit so there are pack files.
    init_git_repo(tmp.path(), "test@example.com", "Test User");
    fs::write(tmp.path().join("file.txt"), "data\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "initial"]);
    run_git(tmp.path(), &["repack", "-ad"]);

    let resolver = TestResolver { refs: vec![] };
    let start_set_id = StartSetConfig::DefaultBranchOnly.id();

    let mut state = repo_open(
        tmp.path(),
        1,
        [0u8; 32],
        start_set_id,
        &resolver,
        &TestWatermarkStore,
        RepoOpenLimits::DEFAULT,
    )
    .unwrap();

    // Before acquire_midx, fingerprint is None → unchanged returns false.
    assert!(!state.artifacts_unchanged().unwrap());

    // Build MIDX in memory, which sets the PackSet fingerprint.
    let _midx = acquire_midx(&mut state, &ArtifactBuildLimits::default()).unwrap();
    assert!(state.artifact_fingerprint.is_some());
    assert!(state.artifacts_unchanged().unwrap());

    // Add a new commit and repack so the pack files change on disk.
    fs::write(tmp.path().join("file2.txt"), "more\n").unwrap();
    run_git(tmp.path(), &["add", "."]);
    run_git(tmp.path(), &["commit", "-m", "second"]);
    run_git(tmp.path(), &["repack", "-ad"]);

    // The fingerprint should now differ from the new pack set.
    assert!(!state.artifacts_unchanged().unwrap());
}
