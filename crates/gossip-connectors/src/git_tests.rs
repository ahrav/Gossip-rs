//! Integration-style tests for [`GitConnector`] that exercise real git repositories.
//!
//! These tests build temporary repositories on disk instead of mocking git state so
//! split-point selection, item lookup, and capability reporting are validated
//! against the same tree layout and command behavior used in production. The
//! fixtures commit tracked files unless the caller explicitly provides an empty
//! repository, which keeps the tests focused on connector semantics rather than
//! setup details.

use std::path::Path;
use std::process::Command;

use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key};

/// Runs a git command in a fixture repository and asserts that setup succeeded.
///
/// These tests rely on real git metadata, so fixture construction fails fast if
/// any command exits unsuccessfully.
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

/// Creates a temporary git repository populated with the provided tracked files.
///
/// The helper configures a local author identity so commit creation is stable in
/// CI environments. When `files` is empty, it intentionally leaves the
/// repository without a commit so tests can opt into an empty fixture.
fn create_test_repo(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    run_git(dir.path(), &["init", "-q"]);
    run_git(
        dir.path(),
        &["config", "user.email", "connector-tests@example.com"],
    );
    run_git(dir.path(), &["config", "user.name", "Connector Tests"]);

    for (rel_path, content) in files {
        let path = dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent directories");
        }
        std::fs::write(path, content).expect("write fixture file");
    }

    if !files.is_empty() {
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);
    }

    dir
}

/// Asserts the split point over the full key range (`\x00`..`\xff`).
///
/// The helper expects the fixture to produce a split candidate for a multi-item
/// range. Tests that need different bounds or need to assert `None` should call
/// `choose_split_point_range` directly.
fn assert_split_point(files: &[(&str, &[u8])], expected: &[u8]) {
    let dir = create_test_repo(files);
    let mut connector = GitConnector::new(dir.path());

    let split = connector
        .choose_split_point_range(
            &make_key(b"\x00"),
            &make_key(b"\xff"),
            &Cursor::initial(),
            None,
        )
        .unwrap();
    let split = split.expect("expected split candidate for multi-item range");
    assert_eq!(split.as_bytes(), expected);
}

/// Verifies that byte-weighted midpoint selection falls back to the rank midpoint
/// when the weighted candidate would leave the right shard empty.
#[test]
fn choose_split_point_selects_byte_weighted_midpoint() {
    assert_split_point(
        &[
            ("a.txt", b"1"),
            ("b.txt", b"22"),
            ("c.txt", b"333"),
            ("d.txt", b"4444"),
        ],
        b"c.txt",
    );
    // The byte-weighted candidate is d.txt (position 6, closest to midpoint 5),
    // but the last-key guard prevents an empty right shard. Rank-fallback
    // selects the rank midpoint: c.txt (rank 2 of 4).
}

/// Verifies that split points never select the very first file even if the
/// byte weight heavily favors the beginning of the repository, preventing
/// an empty left shard.
#[test]
fn choose_split_point_avoids_first_file_when_weight_is_front_loaded() {
    assert_split_point(
        &[("a.txt", &[0u8; 64]), ("b.txt", b"1"), ("c.txt", b"2")],
        b"b.txt",
    );
}

/// Invalid item references should fail immediately and remain non-retryable for
/// both open and range-read operations.
#[test]
fn invalid_item_ref_returns_error() {
    let dir = create_test_repo(&[("a.txt", b"a")]);
    let mut connector = GitConnector::new(dir.path());
    let missing_ref = ItemRef::try_from_slice(b"missing.txt").unwrap();

    let open_result = connector.open(&missing_ref, default_budgets());
    assert!(open_result.is_err());
    let open_err = open_result.err().unwrap();
    assert!(!open_err.is_retryable());

    let mut buf = [0u8; 8];
    let read_err = connector
        .read_range(&missing_ref, 0, &mut buf, default_budgets())
        .unwrap_err();
    assert!(!read_err.is_retryable());
}

/// Capability reporting should only change for token resume support when token
/// emission is toggled.
#[rstest]
#[case::with_token(true)]
#[case::without_token(false)]
fn capabilities_match_token_setting(#[case] emit_tokens: bool) {
    let connector = GitConnector::new("/tmp/repo").with_tokens(emit_tokens);
    let caps = connector.caps();
    assert!(caps.seek_by_key);
    assert!(caps.range_read);
    assert!(caps.split_hints);
    assert_eq!(caps.token_resume, emit_tokens);
}
