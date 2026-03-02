//! Integration coverage for preflight maintenance signals.
//!
//! These tests exercise the distinction between readiness (required artifacts)
//! and maintenance recommendations (pack count) using on-disk fixtures.

use std::fs;
use std::path::{Path, PathBuf};

use scanner_git::{ArtifactStatus, PreflightLimits, preflight};
use tempfile::TempDir;

/// Creates a minimal worktree-style repository layout rooted at `root`.
fn create_worktree_repo(root: &Path) -> PathBuf {
    let git_dir = root.join(".git");
    fs::create_dir_all(git_dir.join("objects").join("pack")).unwrap();
    fs::create_dir_all(git_dir.join("refs")).unwrap();
    fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
    git_dir
}

/// Writes a minimal commit-graph header to satisfy presence checks.
fn write_commit_graph(objects_dir: &Path) {
    let info_dir = objects_dir.join("info");
    fs::create_dir_all(&info_dir).unwrap();
    fs::write(info_dir.join("commit-graph"), b"CGPH").unwrap();
}

/// Writes a minimal MIDX header to satisfy presence checks.
fn write_midx(pack_dir: &Path) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join("multi-pack-index"), b"MIDX").unwrap();
}

/// Writes an empty pack file placeholder with the given name.
fn write_pack(pack_dir: &Path, name: &str) {
    fs::create_dir_all(pack_dir).unwrap();
    fs::write(pack_dir.join(name), b"").unwrap();
}

#[test]
fn preflight_missing_artifacts() {
    let tmp = TempDir::new().unwrap();
    create_worktree_repo(tmp.path());

    let report = preflight(tmp.path(), PreflightLimits::DEFAULT).unwrap();

    match report.status {
        ArtifactStatus::NeedsMaintenance {
            missing_commit_graph,
            missing_midx,
            lock_present,
            ..
        } => {
            assert!(missing_commit_graph, "commit-graph should be missing");
            assert!(missing_midx, "midx should be missing");
            assert!(!lock_present, "lock should be absent");
        }
        ArtifactStatus::Ready => panic!("expected NeedsMaintenance"),
    }
}

#[test]
fn preflight_pack_count_threshold() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_worktree_repo(tmp.path());
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");

    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);
    write_pack(&pack_dir, "pack-1.pack");
    write_pack(&pack_dir, "pack-2.pack");

    let limits = PreflightLimits {
        max_pack_count: 1,
        ..PreflightLimits::DEFAULT
    };
    let report = preflight(tmp.path(), limits).unwrap();

    // Pack count is a maintenance recommendation, not a readiness gate.
    assert!(matches!(report.status, ArtifactStatus::Ready));
    assert!(
        report.maintenance.pack_count > report.maintenance.max_pack_count as u32,
        "pack count should exceed limit"
    );
    assert!(
        report.maintenance.pack_count_exceeded,
        "maintenance should be recommended"
    );
}

#[test]
fn preflight_alternates_in_pack_count() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_worktree_repo(tmp.path());
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");

    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);
    write_pack(&pack_dir, "pack-main.pack");

    let alt_objects = tmp.path().join("alt-objects");
    let alt_pack_dir = alt_objects.join("pack");
    fs::create_dir_all(&alt_pack_dir).unwrap();
    write_pack(&alt_pack_dir, "pack-alt.pack");

    // Alternate object directories are listed one-per-line in info/alternates.
    let alternates_path = objects_dir.join("info").join("alternates");
    fs::create_dir_all(alternates_path.parent().unwrap()).unwrap();
    let mut alternates_line = alt_objects.to_string_lossy().to_string();
    alternates_line.push('\n');
    fs::write(alternates_path, alternates_line.as_bytes()).unwrap();

    let limits = PreflightLimits {
        max_pack_count: 1,
        ..PreflightLimits::DEFAULT
    };
    let report = preflight(tmp.path(), limits).unwrap();

    assert_eq!(report.repo.alternate_object_dirs.len(), 1);

    // Alternates contribute to maintenance recommendations without blocking readiness.
    assert!(matches!(report.status, ArtifactStatus::Ready));
    assert!(
        report.maintenance.pack_count > 1,
        "alternate pack should count toward total"
    );
    assert!(report.maintenance.pack_count_exceeded);
}

#[test]
fn preflight_detects_lock_files() {
    let tmp = TempDir::new().unwrap();
    let git_dir = create_worktree_repo(tmp.path());
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");

    write_commit_graph(&objects_dir);
    write_midx(&pack_dir);

    let lock_path = objects_dir.join("info").join("commit-graph.lock");
    fs::write(lock_path, b"").unwrap();

    let report = preflight(tmp.path(), PreflightLimits::DEFAULT).unwrap();

    // Lock files force NeedsMaintenance even if artifacts are present.
    match report.status {
        ArtifactStatus::NeedsMaintenance { lock_present, .. } => {
            assert!(lock_present, "lock should be detected");
        }
        ArtifactStatus::Ready => panic!("expected NeedsMaintenance"),
    }
}
