use std::{
    io::Read as _,
    path::{Path, PathBuf},
    process::Command,
    time::{Duration, Instant},
};

use gossip_contracts::connector::conformance::{ConformanceConfig, check_connector_conforms};
use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key, small_page_budgets};

/// Run a git command and assert success for test setup.
fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("git command should run");
    assert!(
        output.status.success(),
        "git command failed: git -C {} {}\\nstdout:{}\\nstderr:{}",
        repo.display(),
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Create a temporary git repository with tracked files.
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

/// Collect all items by paging until exhaustion.
fn collect_all(connector: &mut GitConnector, start: &ItemKey, end: &ItemKey) -> Vec<ScanItem> {
    let mut all = Vec::new();
    let mut cursor = Cursor::initial();
    loop {
        let page = connector
            .enumerate_page_range(start, end, &cursor, default_budgets())
            .unwrap();
        if page.items().is_empty() {
            break;
        }
        cursor = page.next_cursor().clone();
        all.extend(page.into_parts().0);
    }
    all
}

fn run_conformance(
    files: &[(&str, &[u8])],
    make_conn: impl Fn(PathBuf) -> GitConnector,
    config: ConformanceConfig,
) {
    let dir = create_test_repo(files);
    let root = dir.path().to_path_buf();
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    check_connector_conforms(
        || make_conn(root.clone()),
        |c| c.caps(),
        |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
        &start,
        &end,
        config,
    )
    .expect("conformance should pass");
}

// ---------------------------------------------------------------
// Conformance harness integration
// ---------------------------------------------------------------

#[test]
fn conformance_harness_with_tokens() {
    run_conformance(
        &[
            ("alpha.txt", b"a"),
            ("bravo.txt", b"b"),
            ("charlie.txt", b"c"),
            ("nested/delta.txt", b"d"),
        ],
        |root| GitConnector::new(root).with_tokens(true),
        ConformanceConfig::default(),
    );
}

#[test]
fn conformance_harness_no_tokens() {
    run_conformance(
        &[
            ("alpha.txt", b"a"),
            ("bravo.txt", b"b"),
            ("charlie.txt", b"c"),
        ],
        |root| GitConnector::new(root).with_tokens(false),
        ConformanceConfig::default(),
    );
}

#[test]
fn conformance_harness_small_pages() {
    run_conformance(
        &[
            ("a1.txt", b"1"),
            ("b2.txt", b"2"),
            ("c3.txt", b"3"),
            ("d4.txt", b"4"),
            ("e5.txt", b"5"),
        ],
        GitConnector::new,
        ConformanceConfig {
            page_budgets: small_page_budgets(2),
            ..ConformanceConfig::default()
        },
    );
}

// ---------------------------------------------------------------
// Enumeration tests
// ---------------------------------------------------------------

#[test]
fn empty_repo_returns_empty_page() {
    let dir = create_test_repo(&[]);
    let mut connector = GitConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = connector
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(page.items().is_empty());
}

#[test]
fn single_file_enumeration_and_resume() {
    let dir = create_test_repo(&[("key.txt", b"payload")]);
    let mut connector = GitConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = connector
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"key.txt");

    let page2 = connector
        .enumerate_page_range(&start, &end, page.next_cursor(), default_budgets())
        .unwrap();
    assert!(page2.items().is_empty());
}

#[test]
fn untracked_files_are_not_enumerated() {
    let dir = create_test_repo(&[("tracked.txt", b"tracked")]);
    std::fs::write(dir.path().join("untracked.txt"), b"untracked").expect("write untracked");

    let mut connector = GitConnector::new(dir.path());
    let items = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));
    let keys: Vec<&[u8]> = items
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"tracked.txt".as_slice()]);
}

#[test]
fn expired_budget_returns_retryable_error() {
    let dir = create_test_repo(&[("a.txt", b"a")]);
    let mut connector = GitConnector::new(dir.path());

    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let result = connector.enumerate_page_range(
        &make_key(b"\x00"),
        &make_key(b"\xff"),
        &Cursor::initial(),
        expired,
    );
    let err = result.expect_err("expired budget should error");
    assert!(err.is_retryable());
}

#[test]
fn choose_split_point_selects_byte_weighted_midpoint() {
    let dir = create_test_repo(&[
        ("a.txt", b"1"),
        ("b.txt", b"22"),
        ("c.txt", b"333"),
        ("d.txt", b"4444"),
    ]);
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
    // The byte-weighted candidate is d.txt (position 6, closest to midpoint 5),
    // but the last-key guard prevents an empty right shard. Rank-fallback
    // selects the rank midpoint: c.txt (rank 2 of 4).
    assert_eq!(split.as_bytes(), b"c.txt");
}

#[test]
fn choose_split_point_avoids_first_file_when_weight_is_front_loaded() {
    let dir = create_test_repo(&[("a.txt", &[0u8; 64]), ("b.txt", b"1"), ("c.txt", b"2")]);
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
    assert_eq!(split.as_bytes(), b"b.txt");
}

// ---------------------------------------------------------------
// max_tracked_files tests
// ---------------------------------------------------------------

#[test]
fn max_tracked_files_rejects_over_limit() {
    let dir = create_test_repo(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = GitConnector::new(dir.path()).with_max_tracked_files(2);

    let result = connector.enumerate_page_range(
        &make_key(b"\x00"),
        &make_key(b"\xff"),
        &Cursor::initial(),
        default_budgets(),
    );
    let err = result.expect_err("should reject repos exceeding file limit");
    assert!(!err.is_retryable(), "limit violation should be permanent");
    assert!(
        err.message().contains("exceeding limit of 2"),
        "error should mention the limit: {}",
        err.message()
    );
}

#[test]
fn max_tracked_files_none_allows_unlimited() {
    let dir = create_test_repo(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = GitConnector::new(dir.path());

    let items = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));
    assert_eq!(items.len(), 3);
}

// ---------------------------------------------------------------
// Read tests
// ---------------------------------------------------------------

#[test]
fn open_returns_tracked_file_content() {
    let dir = create_test_repo(&[("docs/readme.txt", b"hello from git connector")]);
    let mut connector = GitConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = connector
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut reader = connector.open(&item_ref, default_budgets()).unwrap();
    let mut content = Vec::new();
    reader.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"hello from git connector");
}

#[test]
fn read_range_respects_max_bytes_budget() {
    let dir = create_test_repo(&[("secret.txt", b"0123456789")]);
    let mut connector = GitConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = connector
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 16];
    let budgets = Budgets::try_new(100, 4, None).unwrap();
    let read = connector
        .read_range(&item_ref, 2, &mut buf, budgets)
        .unwrap();
    assert_eq!(read, 4);
    assert_eq!(&buf[..read], b"2345");
}

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

// ---------------------------------------------------------------
// Symlink and TOCTOU tests
// ---------------------------------------------------------------

/// Tracked symlinks must be excluded from indexing to prevent
/// directory-traversal reads in untrusted repositories.
#[cfg(unix)]
#[test]
fn tracked_symlinks_are_excluded_from_index() {
    let dir = create_test_repo(&[("target.txt", b"real content")]);

    // Create a symlink tracked by git.
    let link_path = dir.path().join("link.txt");
    std::os::unix::fs::symlink("target.txt", &link_path).expect("create symlink");
    run_git(dir.path(), &["add", "link.txt"]);
    run_git(dir.path(), &["commit", "-q", "-m", "add symlink"]);

    let mut connector = GitConnector::new(dir.path());
    let items = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));
    let keys: Vec<&[u8]> = items.iter().map(|i| i.item_key().as_bytes()).collect();

    // Only the real file should appear — the symlink must be skipped.
    assert_eq!(keys, vec![b"target.txt".as_slice()]);
}

/// Files deleted between `git ls-files` and indexing should be
/// silently skipped rather than causing a hard error.
#[test]
fn deleted_file_during_indexing_is_skipped() {
    let dir = create_test_repo(&[("keep.txt", b"keep"), ("vanish.txt", b"gone")]);

    // Remove the file from disk but leave it in git's index.
    std::fs::remove_file(dir.path().join("vanish.txt")).expect("delete file");

    let mut connector = GitConnector::new(dir.path());
    let items = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));
    let keys: Vec<&[u8]> = items.iter().map(|i| i.item_key().as_bytes()).collect();

    assert_eq!(keys, vec![b"keep.txt".as_slice()]);
}

/// A symlink pointing outside the repository must be excluded from
/// enumeration even when git tracks it, to prevent data exfiltration.
#[cfg(unix)]
#[test]
fn symlink_outside_repo_is_skipped() {
    let outside = tempfile::tempdir().expect("create outside dir");
    let secret = outside.path().join("secret.txt");
    std::fs::write(&secret, b"sensitive data").expect("write secret");

    let dir = create_test_repo(&[("legit.txt", b"ok")]);

    // Create a symlink that escapes the repo root.
    let link_path = dir.path().join("escape.txt");
    std::os::unix::fs::symlink(&secret, &link_path).expect("create symlink");
    run_git(dir.path(), &["add", "escape.txt"]);
    run_git(dir.path(), &["commit", "-q", "-m", "add escape symlink"]);

    let mut connector = GitConnector::new(dir.path());
    let items = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));
    let keys: Vec<&[u8]> = items.iter().map(|i| i.item_key().as_bytes()).collect();

    // Only the legitimate file should be enumerated.
    assert_eq!(keys, vec![b"legit.txt".as_slice()]);
}

/// An item_ref that resolves outside the repository boundary at read
/// time must return a permanent error, even if the index contains it.
#[test]
fn read_path_escaping_repo_returns_error() {
    let dir = create_test_repo(&[("a.txt", b"a")]);
    let mut connector = GitConnector::new(dir.path());

    // Force indexing so the connector is ready.
    let _ = collect_all(&mut connector, &make_key(b"\x00"), &make_key(b"\xff"));

    // Fabricate a ref that does not exist in the index — the binary search
    // in open_path_for_ref should reject it with a permanent error.
    let bad_ref = ItemRef::try_from_slice(b"../../../etc/passwd").unwrap();
    let result = connector.open(&bad_ref, default_budgets());
    let err = result.err().expect("escape attempt should return error");
    assert!(!err.is_retryable(), "escape attempt should be permanent");
}
