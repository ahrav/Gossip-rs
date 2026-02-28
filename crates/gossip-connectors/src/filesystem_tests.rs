use std::io::Read as _;
use std::os::unix::ffi::OsStringExt;
use std::time::{Duration, Instant};

use gossip_contracts::connector::conformance::{check_connector_conforms, ConformanceConfig};
use rstest::rstest;

use super::*;

// ---------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------

fn make_key(s: &[u8]) -> ItemKey {
    ItemKey::try_from_slice(s).expect("test key")
}

fn default_budgets() -> Budgets {
    Budgets::try_new(100, u64::MAX, None).unwrap()
}

fn small_page_budgets(max_items: usize) -> Budgets {
    Budgets::try_new(max_items, u64::MAX, None).unwrap()
}

/// Create a temporary directory populated with the given files.
///
/// Each entry is `(relative_path, content)`. Parent directories are
/// created automatically.
fn create_test_dir(files: &[(&str, &[u8])]) -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("create tempdir");
    for (rel, content) in files {
        let path = dir.path().join(rel);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent dirs");
        }
        fs::write(&path, content).expect("write test file");
    }
    dir
}

/// Collect all items from a connector by paging until empty.
fn collect_all(
    connector: &mut FilesystemConnector,
    start: &ItemKey,
    end: &ItemKey,
) -> Vec<ScanItem> {
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

/// Shared conformance-test driver that eliminates boilerplate across the five
/// conformance scenarios.
fn run_conformance(
    files: &[(&str, &[u8])],
    make_conn: impl Fn(PathBuf) -> FilesystemConnector,
    config: ConformanceConfig,
) {
    let dir = create_test_dir(files);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let root = dir.path().to_path_buf();

    check_connector_conforms(
        || make_conn(root.clone()),
        |c| c.caps(),
        |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
        &start,
        &end,
        config,
    )
    .expect("conformance harness should pass");
}

// ---------------------------------------------------------------
// Conformance harness integration
// ---------------------------------------------------------------

#[test]
fn conformance_harness_with_tokens() {
    run_conformance(
        &[
            ("alpha.txt", b"data-a"),
            ("bravo.txt", b"data-b"),
            ("charlie.txt", b"data-c"),
            ("delta.txt", b"data-d"),
            ("echo.txt", b"data-e"),
        ],
        |root| FilesystemConnector::new(&root).with_tokens(true),
        ConformanceConfig::default(),
    );
}

#[test]
fn conformance_harness_no_tokens() {
    run_conformance(
        &[
            ("alpha.txt", b"data-a"),
            ("bravo.txt", b"data-b"),
            ("charlie.txt", b"data-c"),
        ],
        |root| FilesystemConnector::new(&root).with_tokens(false),
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
        |root| FilesystemConnector::new(&root),
        ConformanceConfig {
            page_budgets: small_page_budgets(2),
            ..ConformanceConfig::default()
        },
    );
}

#[test]
fn conformance_harness_nested_dirs() {
    run_conformance(
        &[
            ("a/one.txt", b"data-1"),
            ("a/two.txt", b"data-2"),
            ("b/sub/three.txt", b"data-3"),
            ("c.txt", b"data-4"),
        ],
        |root| FilesystemConnector::new(&root),
        ConformanceConfig::default(),
    );
}

#[test]
fn conformance_harness_single_file() {
    run_conformance(
        &[("only.txt", b"sole item")],
        |root| FilesystemConnector::new(&root),
        ConformanceConfig::default(),
    );
}

// ---------------------------------------------------------------
// Unit tests — Enumeration
// ---------------------------------------------------------------

#[test]
fn empty_directory_returns_empty_page() {
    let dir = create_test_dir(&[]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(page.items().is_empty());
}

#[test]
fn single_file_enumeration_and_resume() {
    let dir = create_test_dir(&[("key.txt", b"payload")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"key.txt");

    // Resume from cursor returns empty (exhausted).
    let page2 = c
        .enumerate_page_range(&start, &end, page.next_cursor(), default_budgets())
        .unwrap();
    assert!(page2.items().is_empty());
}

#[test]
fn expired_budget_returns_empty_page() {
    let dir = create_test_dir(&[("key.txt", b"payload")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), expired)
        .unwrap();
    assert!(page.items().is_empty());
}

// ---------------------------------------------------------------
// Unit tests — Shard bounds
// ---------------------------------------------------------------

#[test]
fn shard_bounds_between_items() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());

    // Range [b.txt, d.txt) should yield b.txt, c.txt.
    let start = make_key(b"b.txt");
    let end = make_key(b"d.txt");
    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
    assert_eq!(keys, vec![b"b.txt".as_slice(), b"c.txt".as_slice()]);
}

#[test]
fn shard_bounds_exact_on_items() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let mut c = FilesystemConnector::new(dir.path());

    // Range [a.txt, c.txt) should yield a.txt, b.txt.
    let start = make_key(b"a.txt");
    let end = make_key(b"c.txt");
    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
    assert_eq!(keys, vec![b"a.txt".as_slice(), b"b.txt".as_slice()]);
}

#[test]
fn shard_bounds_no_items_in_range() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("z.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    let start = make_key(b"m");
    let end = make_key(b"n");
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(page.items().is_empty());
}

// ---------------------------------------------------------------
// Unit tests — Token parity
// ---------------------------------------------------------------

#[test]
fn token_enabled_vs_disabled_parity() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let mut with_tokens = FilesystemConnector::new(dir.path()).with_tokens(true);
    let mut without_tokens = FilesystemConnector::new(dir.path()).with_tokens(false);

    let items_a = collect_all(&mut with_tokens, &start, &end);
    let items_b = collect_all(&mut without_tokens, &start, &end);

    assert_eq!(items_a.len(), items_b.len());
    for (a, b) in items_a.iter().zip(items_b.iter()) {
        assert_eq!(a.item_key(), b.item_key());
        assert_eq!(a.stable_item_id(), b.stable_item_id());
        assert_eq!(a.version(), b.version());
    }
}

// ---------------------------------------------------------------
// Unit tests — Split points
// ---------------------------------------------------------------

#[test]
fn split_point_fewer_than_two_returns_none() {
    let dir = create_test_dir(&[("only.txt", b"1")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    assert!(split.is_none());
}

#[test]
fn split_point_empty_set_returns_none() {
    let dir = create_test_dir(&[]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    assert!(split.is_none());
}

#[test]
fn split_point_cursor_past_midpoint_returns_none() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Advance cursor past b.txt — only c.txt remains, fewer than 2.
    let cursor = Cursor::with_last_key(make_key(b"b.txt"));
    let split = c.choose_split_point_range(&start, &end, &cursor).unwrap();
    assert!(split.is_none());
}

#[test]
fn split_point_valid_returns_key_between_bounds() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("should produce a split point");
    assert!(split > make_key(b"\x00"));
    assert!(split < make_key(b"\xff"));
}

// ---------------------------------------------------------------
// Unit tests — Capabilities
// ---------------------------------------------------------------

#[test]
fn caps_reflect_token_setting() {
    let dir = create_test_dir(&[]);

    let c_default = FilesystemConnector::new(dir.path());
    assert!(!c_default.caps().token_resume);
    assert!(c_default.caps().seek_by_key);
    assert!(c_default.caps().range_read);
    assert!(c_default.caps().split_hints);

    let c_with = FilesystemConnector::new(dir.path()).with_tokens(true);
    assert!(c_with.caps().token_resume);
    assert!(c_with.caps().seek_by_key);
    assert!(c_with.caps().range_read);
    assert!(c_with.caps().split_hints);
}

// ---------------------------------------------------------------
// Unit tests — ReadConnector::open
// ---------------------------------------------------------------

#[test]
fn open_reads_full_content() {
    let dir = create_test_dir(&[("hello.txt", b"hello world")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut reader = c.open(&item_ref, default_budgets()).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world");
}

#[test]
fn open_budget_exceeded_returns_error() {
    let dir = create_test_dir(&[("large.txt", b"large payload here")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let small_budget = Budgets::try_new(100, 5, None).unwrap();
    let result = c.open(&item_ref, small_budget);
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// Unit tests — ReadConnector::read_range
// ---------------------------------------------------------------

#[test]
fn read_range_full_read() {
    let dir = create_test_dir(&[("file.txt", b"hello world")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 64];
    let n = c
        .read_range(&item_ref, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"hello world");
}

#[test]
fn read_range_partial_read() {
    let dir = create_test_dir(&[("file.txt", b"hello world")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 64];
    let n = c
        .read_range(&item_ref, 6, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"world");
}

#[test]
fn read_range_offset_beyond_length_returns_zero() {
    let dir = create_test_dir(&[("file.txt", b"short")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 32];
    let n = c
        .read_range(&item_ref, 1000, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn read_range_zero_length_dst_returns_zero() {
    let dir = create_test_dir(&[("file.txt", b"payload")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [];
    let n = c
        .read_range(&item_ref, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(n, 0);
}

#[test]
fn read_range_overflow_offset_returns_error() {
    let dir = create_test_dir(&[("file.txt", b"payload")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 16];
    let result = c.read_range(&item_ref, u64::MAX, &mut buf, default_budgets());
    assert!(result.is_err());
}

#[test]
fn read_range_budget_clamps_read() {
    let dir = create_test_dir(&[("file.txt", b"0123456789")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    // Budget allows only 3 bytes, buffer is larger.
    let clamped_budget = Budgets::try_new(100, 3, None).unwrap();
    let mut buf = [0u8; 10];
    let n = c
        .read_range(&item_ref, 0, &mut buf, clamped_budget)
        .unwrap();
    assert!(n <= 3);
}

// ---------------------------------------------------------------
// Unit tests — Path security (consolidated via rstest)
// ---------------------------------------------------------------

#[rstest]
#[case::absolute_path(b"/etc/passwd")]
#[case::parent_traversal(b"../etc/passwd")]
#[case::embedded_traversal(b"sub/../../etc/passwd")]
fn resolve_rejects_malicious_paths(#[case] path: &[u8]) {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let bad_ref = ItemRef::try_from_slice(path).unwrap();
    let result = c.open(&bad_ref, default_budgets());
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// Unit tests — FS-specific behavior
// ---------------------------------------------------------------

#[test]
fn nested_dirs_sorted_by_full_path_key() {
    let dir = create_test_dir(&[
        ("b/a.txt", b"1"),
        ("a/z.txt", b"2"),
        ("a/a.txt", b"3"),
        ("c.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
    assert_eq!(
        keys,
        vec![
            b"a/a.txt".as_slice(),
            b"a/z.txt".as_slice(),
            b"b/a.txt".as_slice(),
            b"c.txt".as_slice(),
        ]
    );
}

#[test]
fn empty_subdirectory_is_skipped() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    // Create an empty subdir manually.
    fs::create_dir(dir.path().join("empty_sub")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"file.txt");
}

#[test]
fn mutations_after_first_enumerate_invisible() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // First enumerate triggers indexing.
    let all1 = collect_all(&mut c, &start, &end);
    assert_eq!(all1.len(), 2);

    // Mutate directory after indexing.
    fs::write(dir.path().join("c.txt"), b"3").unwrap();

    // Second enumerate on same connector still sees only original files.
    let all2 = collect_all(&mut c, &start, &end);
    assert_eq!(all2.len(), 2);
}

#[test]
fn determinism_same_directory_same_output() {
    let dir = create_test_dir(&[("c.txt", b"3"), ("a.txt", b"1"), ("b.txt", b"2")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let mut c1 = FilesystemConnector::new(dir.path());
    let mut c2 = FilesystemConnector::new(dir.path());

    let items1 = collect_all(&mut c1, &start, &end);
    let items2 = collect_all(&mut c2, &start, &end);

    assert_eq!(items1.len(), items2.len());
    for (a, b) in items1.iter().zip(items2.iter()) {
        assert_eq!(a.item_key(), b.item_key());
        assert_eq!(a.item_ref(), b.item_ref());
        assert_eq!(a.stable_item_id(), b.stable_item_id());
        assert_eq!(a.version(), b.version());
    }
}

#[test]
fn enumerated_item_refs_round_trip_to_files() {
    let files = &[
        ("alpha.txt", b"content-a" as &[u8]),
        ("sub/beta.txt", b"content-b"),
    ];
    let dir = create_test_dir(files);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), files.len());

    // Sort expected files by key to match enumeration order.
    let mut expected: Vec<(&str, &[u8])> = files.iter().map(|(p, d)| (*p, *d)).collect();
    expected.sort_by_key(|(p, _)| *p);

    for (item, (_, expected_content)) in all.iter().zip(expected.iter()) {
        let mut reader = c.open(item.item_ref(), default_budgets()).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, *expected_content);
    }
}

// ---------------------------------------------------------------
// Symlink handling tests
// ---------------------------------------------------------------

#[test]
fn symlink_to_file_is_skipped() {
    let dir = create_test_dir(&[("real.txt", b"real content")]);
    std::os::unix::fs::symlink(dir.path().join("real.txt"), dir.path().join("link.txt")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    // Only real.txt is indexed; link.txt is skipped.
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"real.txt");

    // The symlink should be recorded as a warning.
    assert!(
        c.walk_warnings().iter().any(|w| w.message == "symlink"),
        "expected a symlink warning"
    );
}

#[test]
fn symlink_cycle_does_not_hang() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    // Create a symlink cycle: loop -> .
    std::os::unix::fs::symlink(".", dir.path().join("loop")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"file.txt");

    assert!(
        c.walk_warnings().iter().any(|w| w.message == "symlink"),
        "expected a symlink warning for the cycle link"
    );
}

#[test]
fn symlink_escape_root_is_skipped() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    std::os::unix::fs::symlink("/etc/passwd", dir.path().join("escape")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"file.txt");

    assert!(
        c.walk_warnings().iter().any(|w| w.message == "symlink"),
        "expected a symlink warning for the escape link"
    );
}

#[test]
fn symlink_to_directory_is_skipped() {
    let dir = create_test_dir(&[("sub/file.txt", b"data"), ("other.txt", b"ok")]);
    std::os::unix::fs::symlink(dir.path().join("sub"), dir.path().join("link_dir")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();

    // link_dir/file.txt should NOT appear -- the symlink to directory is skipped.
    assert!(!keys.iter().any(|k| k.starts_with(b"link_dir")));
    // But the real sub/file.txt and other.txt should be there.
    assert!(keys.contains(&b"sub/file.txt".as_slice()));
    assert!(keys.contains(&b"other.txt".as_slice()));
}

#[test]
fn dangling_symlink_is_skipped() {
    let dir = create_test_dir(&[]);
    std::os::unix::fs::symlink("/nonexistent/target", dir.path().join("dangling")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Indexing succeeds; the dangling symlink is skipped with a warning.
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(page.items().is_empty());
    assert!(
        c.walk_warnings().iter().any(|w| w.message == "symlink"),
        "expected a symlink warning for the dangling link"
    );
}

// ---------------------------------------------------------------
// Error classification & memoization tests
// ---------------------------------------------------------------

#[test]
fn root_not_found_is_permanent() {
    let mut c = FilesystemConnector::new("/nonexistent/path/that/does/not/exist");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets());
    let err = result.unwrap_err();
    assert!(!err.is_retryable(), "NotFound should be a permanent error");
}

#[test]
fn index_failure_is_memoized() {
    let mut c = FilesystemConnector::new("/nonexistent/path/that/does/not/exist");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // First call fails.
    let err1 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap_err();
    // Second call returns the memoized error without re-walking.
    let err2 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap_err();
    assert_eq!(err1.message(), err2.message());
    assert_eq!(err1.is_retryable(), err2.is_retryable());
}

#[test]
fn open_rejects_directory_path() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    fs::create_dir(dir.path().join("subdir")).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let dir_ref = ItemRef::try_from_slice(b"subdir").unwrap();
    let err = c
        .open(&dir_ref, default_budgets())
        .expect_err("should reject directory");
    assert!(!err.is_retryable(), "directory open should be permanent");
}

// ---------------------------------------------------------------
// Unreadable entry tests
// ---------------------------------------------------------------

#[test]
fn unreadable_subdir_is_skipped_with_warning() {
    use std::os::unix::fs::PermissionsExt;
    let dir = create_test_dir(&[("good.txt", b"ok"), ("sub/file.txt", b"hidden")]);
    fs::set_permissions(dir.path().join("sub"), fs::Permissions::from_mode(0o000)).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"good.txt");
    assert!(
        !c.walk_warnings().is_empty(),
        "expected a warning for the unreadable subdirectory"
    );

    // Restore permissions for tempdir cleanup.
    fs::set_permissions(dir.path().join("sub"), fs::Permissions::from_mode(0o755)).unwrap();
}

// ---------------------------------------------------------------
// Byte-weighted split tests
// ---------------------------------------------------------------

#[test]
fn byte_weighted_split_balances_by_size() {
    let dir = create_test_dir(&[
        ("a.txt", &[0u8; 500] as &[u8]),
        ("b.txt", &[0u8; 500]),
        ("c.txt", b"x"),
        ("d.txt", b"x"),
        ("e.txt", b"x"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap()
        .expect("should have a split point");

    // Count-balanced would split at c.txt (index 2, 5/2=2).
    // Byte-weighted: cumulative at a.txt (500) < half (501),
    // cumulative at b.txt (1000) >= half -> split_idx = 1.
    assert_eq!(
        split.as_bytes(),
        b"b.txt",
        "byte-weighted split should balance by file size, not count"
    );
}

#[test]
fn byte_weighted_split_falls_back_for_zero_size() {
    let dir = create_test_dir(&[
        ("a.txt", b""),
        ("b.txt", b""),
        ("c.txt", b""),
        ("d.txt", b""),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap()
        .expect("should have a split point");

    // Count-balanced: 4/2 = 2 -> files[2].key = "c.txt".
    assert_eq!(
        split.as_bytes(),
        b"c.txt",
        "zero-size fallback should use count-balanced median"
    );
}

// ---------------------------------------------------------------
// Deep directory test
// ---------------------------------------------------------------

#[test]
fn deep_directory_does_not_stack_overflow() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let mut path = dir.path().to_path_buf();
    for i in 0..200 {
        path = path.join(format!("d{i:03}"));
    }
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("leaf.txt"), b"deep").unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    let key = all[0].item_key();
    assert!(
        key.as_bytes().len() > 100,
        "key should be a long nested path"
    );
}

// ---------------------------------------------------------------
// FD cache test
// ---------------------------------------------------------------

#[test]
fn consecutive_read_ranges_on_same_file_succeed() {
    let dir = create_test_dir(&[("file.txt", b"abcdefghij")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    let mut buf = [0u8; 3];
    let n1 = c
        .read_range(&item_ref, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n1], b"abc");

    let n2 = c
        .read_range(&item_ref, 3, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n2], b"def");

    let n3 = c
        .read_range(&item_ref, 6, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n3], b"ghi");
}

// ---------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------

mod prop {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;
    use proptest::string::string_regex;

    /// Strategy: generate a set of (path, content) pairs with unique paths.
    ///
    /// Paths use `[a-z0-9_]{1,8}` segments with 0-2 levels of nesting.
    fn file_set_strategy(max_files: usize) -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
        let segment = "[a-z0-9_]{1,8}";
        let path = string_regex(&format!(
            "{segment}(\\.txt|/{segment}\\.txt|/{segment}/{segment}\\.txt)"
        ))
        .unwrap();

        pvec((path, pvec(any::<u8>(), 0..32usize)), 0..max_files).prop_map(
            |entries: Vec<(String, Vec<u8>)>| {
                let mut seen = std::collections::HashSet::new();
                entries
                    .into_iter()
                    .filter(|(p, _)| seen.insert(p.clone()))
                    .collect()
            },
        )
    }

    /// Create a connector from a generated file set, returning the tempdir
    /// (to keep it alive) and the connector.
    fn make_connector(files: &[(String, Vec<u8>)]) -> (tempfile::TempDir, FilesystemConnector) {
        let dir = tempfile::tempdir().expect("create tempdir");
        for (rel, content) in files {
            let path = dir.path().join(rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent dirs");
            }
            fs::write(&path, content).expect("write test file");
        }
        let conn = FilesystemConnector::new(dir.path());
        (dir, conn)
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn full_enum_yields_sorted_keys(files in file_set_strategy(20)) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let (_dir, mut c) = make_connector(&files);

            let all = collect_all(&mut c, &start, &end);
            let keys: Vec<Vec<u8>> = all
                .iter()
                .map(|i| i.item_key().as_bytes().to_vec())
                .collect();

            // Keys must be strictly ascending.
            for w in keys.windows(2) {
                prop_assert!(w[0] < w[1], "keys not strictly ascending: {:?} >= {:?}", w[0], w[1]);
            }
        }

        #[test]
        fn token_vs_no_token_same_items(files in file_set_strategy(15)) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");

            let (_dir1, mut with) = make_connector(&files);
            with = with.with_tokens(true);
            let (_dir2, mut without) = make_connector(&files);

            let a = collect_all(&mut with, &start, &end);
            let b = collect_all(&mut without, &start, &end);

            prop_assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(b.iter()) {
                prop_assert_eq!(x.item_key(), y.item_key());
            }
        }

        #[test]
        fn split_point_strictly_between_cursor_and_end(
            files in file_set_strategy(20),
        ) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let (_dir, mut c) = make_connector(&files);

            if let Ok(Some(split)) = c.choose_split_point_range(
                &start, &end, &Cursor::initial(),
            ) {
                prop_assert!(split > start);
                prop_assert!(split < end);
            }
        }

        #[test]
        fn determinism_property(files in file_set_strategy(15)) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");

            let (_dir1, mut c1) = make_connector(&files);
            let (_dir2, mut c2) = make_connector(&files);

            let a = collect_all(&mut c1, &start, &end);
            let b = collect_all(&mut c2, &start, &end);

            prop_assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(b.iter()) {
                prop_assert_eq!(x.item_key(), y.item_key());
                prop_assert_eq!(x.item_ref(), y.item_ref());
                prop_assert_eq!(x.stable_item_id(), y.stable_item_id());
            }
        }

        #[test]
        fn enumerated_refs_round_trip_to_readable_files(
            files in file_set_strategy(10),
        ) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let (_dir, mut c) = make_connector(&files);

            let all = collect_all(&mut c, &start, &end);
            for item in &all {
                let result = c.open(item.item_ref(), default_budgets());
                prop_assert!(result.is_ok(), "open failed for key {:?}", item.item_key().as_bytes());
                let mut reader = result.unwrap();
                let mut buf = Vec::new();
                reader.read_to_end(&mut buf).unwrap();
                // Content must not be empty only if original was non-empty,
                // but we verify the read itself succeeds without error.
            }
        }
    }
}

// ---------------------------------------------------------------
// Lower-priority tests
// ---------------------------------------------------------------

#[test]
fn non_utf8_filename_is_indexed() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let raw_name = std::ffi::OsString::from_vec(vec![0xC0, 0xC1, 0xFE]);
    let file_path = dir.path().join(&raw_name);

    // macOS APFS rejects non-UTF-8 filenames; skip gracefully.
    if fs::write(&file_path, b"non-utf8 content").is_err() {
        return;
    }

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), &[0xC0, 0xC1, 0xFE]);

    // Readable via ItemRef.
    let mut reader = c.open(all[0].item_ref(), default_budgets()).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"non-utf8 content");
}

#[test]
fn version_id_changes_when_file_modified() {
    let dir = create_test_dir(&[("file.txt", b"original")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let mut c1 = FilesystemConnector::new(dir.path());
    let items1 = collect_all(&mut c1, &start, &end);
    let v1 = items1[0].version();

    // Modify the file to change its metadata (size changes).
    fs::write(
        dir.path().join("file.txt"),
        b"modified content that is longer",
    )
    .unwrap();

    let mut c2 = FilesystemConnector::new(dir.path());
    let items2 = collect_all(&mut c2, &start, &end);
    let v2 = items2[0].version();

    assert_ne!(v1, v2);
}
