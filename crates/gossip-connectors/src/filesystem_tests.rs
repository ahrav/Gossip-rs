use std::io::Read as _;
use std::os::unix::ffi::OsStringExt;
use std::time::{Duration, Instant};

use gossip_contracts::connector::conformance::{ConformanceConfig, check_connector_conforms};
use gossip_contracts::connector::{MAX_ITEM_KEY_SIZE, TokenBytes};
use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key, small_page_budgets};

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

/// Collect all items from a connector via the trait entrypoint.
fn collect_all_via_shard(
    connector: &mut FilesystemConnector,
    shard: &ShardSpec,
    budgets: Budgets,
) -> Vec<ScanItem> {
    let mut all = Vec::new();
    let mut cursor = Cursor::initial();
    loop {
        let page = connector.enumerate_page(shard, &cursor, budgets).unwrap();
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
fn enumerate_page_uses_pooled_toxic_wrappers() {
    let dir = create_test_dir(&[("alpha.txt", b"a"), ("bravo.txt", b"b")]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    // Filesystem pages should emit pooled wrappers for key/ref fields.
    assert!(
        !page.items().is_empty(),
        "fixture should produce a non-empty page"
    );
    for item in page.items() {
        assert!(
            item.item_key().is_pooled(),
            "item_key should be slab-backed"
        );
        assert!(
            item.item_ref().is_pooled(),
            "item_ref should be slab-backed"
        );
        assert_eq!(
            item.item_key().as_bytes(),
            item.item_ref().as_bytes(),
            "filesystem key/ref bytes should be identical"
        );
        assert_eq!(
            item.item_key().as_bytes().as_ptr(),
            item.item_ref().as_bytes().as_ptr(),
            "filesystem key/ref should share backing storage"
        );
    }

    let next = page.next_cursor();
    // Cursor key/token remain pooled so resume can reuse page-local slab bytes.
    assert!(
        next.last_key().is_some_and(|last_key| last_key.is_pooled()),
        "next cursor key should share pooled storage"
    );
    assert!(
        next.token().is_some_and(|token| token.is_pooled()),
        "token should be slab-backed when emitted"
    );
}

#[test]
fn expired_budget_returns_retryable_error() {
    let dir = create_test_dir(&[("key.txt", b"payload")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), expired);
    assert!(result.is_err(), "expired budget should return an error");
}

// ---------------------------------------------------------------
// Inverted range rejection
// ---------------------------------------------------------------

#[test]
fn inverted_range_returns_error() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    // start > end is invalid.
    let start = make_key(b"\xff");
    let end = make_key(b"\x00");
    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets());
    assert!(result.is_err(), "inverted range should return an error");
}

#[test]
fn inverted_range_split_returns_error() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    let start = make_key(b"\xff");
    let end = make_key(b"\x00");
    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
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
#[case::traversal_after_valid(b"valid/../../../etc/passwd")]
#[case::null_byte_injection(b"file.txt\x00../../etc/passwd")]
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
    // Index a real file, then replace it with a directory to exercise the
    // `metadata.is_file()` guard in `open_beneath_root`.
    let dir = create_test_dir(&[("target.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Replace the indexed file with a directory.
    fs::remove_file(dir.path().join("target.txt")).unwrap();
    fs::create_dir(dir.path().join("target.txt")).unwrap();

    let err = c
        .open(&item_ref, default_budgets())
        .err()
        .expect("should reject directory");
    assert!(!err.is_retryable(), "directory open should be permanent");
    assert!(
        err.message().contains("not a regular file"),
        "expected 'not a regular file' error, got: {}",
        err.message(),
    );
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
    // Use short directory names to stay within OS path-length limits on macOS
    // (NAME_MAX=255, PATH_MAX=1024). 100 levels of 2-char names is ~300 bytes.
    for i in 0..100 {
        path = path.join(format!("{i:02}"));
    }
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("f.txt"), b"deep").unwrap();

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
// ShardSpec trait-method coverage
// ---------------------------------------------------------------

#[test]
fn enumerate_page_via_shard_spec() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let mut c = FilesystemConnector::new(dir.path());

    let shard = ShardSpec::try_with_range(b"a.txt", b"c.txt").unwrap();
    let page = c
        .enumerate_page(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    let keys: Vec<&[u8]> = page
        .items()
        .iter()
        .map(|i| i.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"a.txt".as_slice(), b"b.txt".as_slice()]);
}

#[test]
fn choose_split_point_via_shard_spec() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());

    let shard = ShardSpec::try_with_range(b"\x00", b"\xff").unwrap();
    let split = c
        .choose_split_point(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(split.is_some(), "should produce a split point");
}

#[test]
fn enumerate_page_via_shard_spec_unbounded_bounds() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let shard = ShardSpec::try_with_range(b"", b"").unwrap();

    let all = collect_all_via_shard(&mut c, &shard, small_page_budgets(2));
    let keys: Vec<&[u8]> = all.iter().map(|item| item.item_key().as_bytes()).collect();
    assert_eq!(
        keys,
        vec![
            b"a.txt".as_slice(),
            b"b.txt".as_slice(),
            b"c.txt".as_slice(),
            b"d.txt".as_slice(),
        ]
    );
}

#[test]
fn enumerate_page_via_shard_spec_one_sided_unbounded_resumes() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
        ("e.txt", b"5"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let shard = ShardSpec::try_with_range(b"c.txt", b"").unwrap();
    let budgets = small_page_budgets(2);

    let page1 = c
        .enumerate_page(&shard, &Cursor::initial(), budgets)
        .expect("first page");
    assert_eq!(page1.items().len(), 2);
    assert_eq!(page1.items()[0].item_key().as_bytes(), b"c.txt");
    assert_eq!(page1.items()[1].item_key().as_bytes(), b"d.txt");

    let page2 = c
        .enumerate_page(&shard, page1.next_cursor(), budgets)
        .expect("second page");
    assert_eq!(page2.items().len(), 1);
    assert_eq!(page2.items()[0].item_key().as_bytes(), b"e.txt");

    let page3 = c
        .enumerate_page(&shard, page2.next_cursor(), budgets)
        .expect("terminal page");
    assert!(
        page3.items().is_empty(),
        "resume should terminate without dupes"
    );
}

#[test]
fn choose_split_point_via_shard_spec_unbounded_and_one_sided() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
        ("e.txt", b"5"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());

    let unbounded = ShardSpec::try_with_range(b"", b"").unwrap();
    let split_unbounded = c
        .choose_split_point(&unbounded, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(
        split_unbounded.is_some(),
        "unbounded split should produce a hint"
    );

    let one_sided = ShardSpec::try_with_range(b"c.txt", b"").unwrap();
    let split_one_sided = c
        .choose_split_point(&one_sided, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(
        split_one_sided
            .expect("one-sided range should split")
            .as_bytes(),
        b"d.txt",
    );
}

#[test]
fn enumerate_page_trait_and_range_paths_match_across_pages() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
        ("e.txt", b"5"),
    ]);
    let mut via_trait = FilesystemConnector::new(dir.path()).with_tokens(true);
    let mut via_range = FilesystemConnector::new(dir.path()).with_tokens(true);
    let shard = ShardSpec::try_with_range(b"b.txt", b"z.txt").unwrap();
    let start = make_key(b"b.txt");
    let end = make_key(b"z.txt");
    let budgets = small_page_budgets(2);

    let mut cursor_trait = Cursor::initial();
    let mut cursor_range = Cursor::initial();
    loop {
        let trait_page = via_trait
            .enumerate_page(&shard, &cursor_trait, budgets)
            .expect("trait enumerate_page");
        let range_page = via_range
            .enumerate_page_range(&start, &end, &cursor_range, budgets)
            .expect("range enumerate_page");

        assert_eq!(trait_page.items().len(), range_page.items().len());
        for (left, right) in trait_page.items().iter().zip(range_page.items()) {
            assert_eq!(left.item_key(), right.item_key());
            assert_eq!(left.item_ref(), right.item_ref());
            assert_eq!(left.stable_item_id(), right.stable_item_id());
            assert_eq!(left.version(), right.version());
        }
        assert_eq!(
            trait_page.next_cursor().last_key(),
            range_page.next_cursor().last_key()
        );
        assert_eq!(
            trait_page.next_cursor().token().map(TokenBytes::as_bytes),
            range_page.next_cursor().token().map(TokenBytes::as_bytes)
        );

        if trait_page.items().is_empty() {
            break;
        }
        cursor_trait = trait_page.next_cursor().clone();
        cursor_range = range_page.next_cursor().clone();
    }
}

#[test]
fn trait_methods_reject_oversized_non_empty_bounds() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    let oversized_start = ShardSpec::from_raw_parts(
        vec![b'x'; MAX_ITEM_KEY_SIZE + 1].into_boxed_slice(),
        Box::<[u8]>::default(),
        Box::<[u8]>::default(),
    );
    let err = c
        .enumerate_page(&oversized_start, &Cursor::initial(), default_budgets())
        .expect_err("oversized non-empty start bound should fail");
    assert!(
        !err.is_retryable(),
        "oversized non-empty start bound should be permanent"
    );
    assert!(
        err.message().contains("invalid shard start bound"),
        "error should identify malformed start bound"
    );

    let oversized_end = ShardSpec::from_raw_parts(
        Box::<[u8]>::default(),
        vec![b'y'; MAX_ITEM_KEY_SIZE + 1].into_boxed_slice(),
        Box::<[u8]>::default(),
    );
    let err = c
        .choose_split_point(&oversized_end, &Cursor::initial(), default_budgets())
        .expect_err("oversized non-empty end bound should fail");
    assert!(
        !err.is_retryable(),
        "oversized non-empty end bound should be permanent"
    );
    assert!(
        err.message().contains("invalid shard end bound"),
        "error should identify malformed end bound"
    );
}

#[test]
fn trait_methods_accept_exact_max_size_bound() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    let exact_start = ShardSpec::from_raw_parts(
        vec![b'x'; MAX_ITEM_KEY_SIZE].into_boxed_slice(),
        Box::<[u8]>::default(),
        Box::<[u8]>::default(),
    );
    // Exact-max-size bound must be accepted (boundary is `>`, not `>=`).
    c.enumerate_page(&exact_start, &Cursor::initial(), default_budgets())
        .expect("exact MAX_ITEM_KEY_SIZE start bound should be accepted");

    let exact_end = ShardSpec::from_raw_parts(
        Box::<[u8]>::default(),
        vec![b'y'; MAX_ITEM_KEY_SIZE].into_boxed_slice(),
        Box::<[u8]>::default(),
    );
    c.choose_split_point(&exact_end, &Cursor::initial(), default_budgets())
        .expect("exact MAX_ITEM_KEY_SIZE end bound should be accepted");
}

// ---------------------------------------------------------------
// FD cache eviction
// ---------------------------------------------------------------

#[test]
fn fd_cache_eviction_on_different_file() {
    let dir = create_test_dir(&[("a.txt", b"alpha"), ("b.txt", b"bravo")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 2);
    let ref_a = page.items()[0].item_ref().clone();
    let ref_b = page.items()[1].item_ref().clone();

    // Read from file A (cache miss — opens file).
    let mut buf = [0u8; 32];
    let n = c
        .read_range(&ref_a, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"alpha");

    // Read from file B (cache miss — evicts A, opens B).
    let n = c
        .read_range(&ref_b, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"bravo");

    // Read from file A again (cache miss — evicts B, reopens A).
    let n = c
        .read_range(&ref_a, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"alpha");
}

// ---------------------------------------------------------------
// Cached FD clears O_NONBLOCK
// ---------------------------------------------------------------

#[test]
fn cached_fd_has_clear_nonblock_after_read_range() {
    let dir = create_test_dir(&[("file.txt", b"hello")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    // Trigger get_or_open_cached via read_range.
    let mut buf = [0u8; 5];
    let n = c
        .read_range(&item_ref, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(&buf[..n], b"hello");

    // Inspect the cached fd — O_NONBLOCK must NOT be set.
    let cached = c
        .cached_file
        .as_ref()
        .expect("cached_file should be populated after read_range");
    let fd = cached.1.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    assert!(flags >= 0, "fcntl(F_GETFL) failed");
    assert_eq!(
        flags & libc::O_NONBLOCK,
        0,
        "cached fd should NOT have O_NONBLOCK set (flags={flags:#x})"
    );
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
        #![proptest_config(ProptestConfig {
            cases: std::env::var("PROPTEST_CASES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(64),
            ..ProptestConfig::default()
        })]

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
fn open_rejects_symlink_replacing_indexed_file() {
    // Create a file outside the connector root that the symlink will target.
    let outside = tempfile::tempdir().expect("create outside dir");
    fs::write(outside.path().join("secret.txt"), b"sensitive data").unwrap();

    // Create a directory with a regular file and index it.
    let dir = create_test_dir(&[("target.txt", b"original content")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Trigger indexing — target.txt is indexed as a regular file.
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item_key().as_bytes(), b"target.txt");
    let item_ref = items[0].item_ref().clone();

    // TOCTOU: replace the real file with a symlink pointing outside root.
    fs::remove_file(dir.path().join("target.txt")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        dir.path().join("target.txt"),
    )
    .unwrap();

    // The open should reject the symlink to prevent root-escape.
    let result = c.open(&item_ref, default_budgets());
    assert!(
        result.is_err(),
        "open should refuse to follow a symlink that replaced an indexed regular file"
    );
}

#[test]
fn read_range_rejects_symlink_replacing_indexed_file() {
    // Create a file outside the connector root.
    let outside = tempfile::tempdir().expect("create outside dir");
    fs::write(outside.path().join("secret.txt"), b"sensitive data").unwrap();

    let dir = create_test_dir(&[("target.txt", b"original content")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Replace with symlink after indexing.
    fs::remove_file(dir.path().join("target.txt")).unwrap();
    std::os::unix::fs::symlink(
        outside.path().join("secret.txt"),
        dir.path().join("target.txt"),
    )
    .unwrap();

    // read_range should also reject the symlink.
    let mut buf = [0u8; 64];
    let result = c.read_range(&item_ref, 0, &mut buf, default_budgets());
    assert!(
        result.is_err(),
        "read_range should refuse to follow a symlink that replaced an indexed regular file"
    );
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

// ---------------------------------------------------------------
// Walk depth limit tests
// ---------------------------------------------------------------

#[test]
fn walk_respects_max_depth_limit() {
    let dir = tempfile::tempdir().expect("create tempdir");

    // Create a tree: root/a.txt, root/d1/b.txt, root/d1/d2/c.txt, root/d1/d2/d3/d.txt
    fs::write(dir.path().join("a.txt"), b"root-level").unwrap();
    let d1 = dir.path().join("d1");
    fs::create_dir(&d1).unwrap();
    fs::write(d1.join("b.txt"), b"depth-1").unwrap();
    let d2 = d1.join("d2");
    fs::create_dir(&d2).unwrap();
    fs::write(d2.join("c.txt"), b"depth-2").unwrap();
    let d3 = d2.join("d3");
    fs::create_dir(&d3).unwrap();
    fs::write(d3.join("d.txt"), b"depth-3").unwrap();

    // max_depth=2 allows root (0), d1 (1), d2 (2), but NOT d3 (3).
    let mut c = FilesystemConnector::new(dir.path()).with_max_depth(2);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();

    assert!(keys.contains(&b"a.txt".as_slice()), "root-level file");
    assert!(keys.contains(&b"d1/b.txt".as_slice()), "depth-1 file");
    assert!(keys.contains(&b"d1/d2/c.txt".as_slice()), "depth-2 file");
    assert!(
        !keys.contains(&b"d1/d2/d3/d.txt".as_slice()),
        "depth-3 file should be skipped"
    );

    assert!(
        c.walk_warnings()
            .iter()
            .any(|w| w.message == "exceeded maximum walk depth"),
        "expected a depth-limit warning"
    );
}

#[test]
fn walk_depth_zero_indexes_only_root_files() {
    let dir = create_test_dir(&[("top.txt", b"ok"), ("sub/nested.txt", b"hidden")]);
    let mut c = FilesystemConnector::new(dir.path()).with_max_depth(0);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"top.txt");
}

// ---------------------------------------------------------------
// Edge case tests
// ---------------------------------------------------------------

#[test]
fn unreadable_file_is_skipped_with_warning() {
    use std::os::unix::fs::PermissionsExt;
    let dir = create_test_dir(&[("good.txt", b"ok"), ("secret.txt", b"hidden")]);
    // Make the file unreadable. Note: symlink_metadata (used for indexing)
    // only needs directory read+execute, not file read permission. The walk
    // should still index the file because metadata is accessible even when
    // content is not. This test verifies the file IS indexed (metadata is
    // readable) but that open() fails when content is unreadable.
    fs::set_permissions(
        dir.path().join("secret.txt"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    // Both files are indexed (metadata is readable with dir perms).
    assert_eq!(all.len(), 2);

    // But opening the unreadable file for reading should fail.
    let secret_item = all
        .iter()
        .find(|i| i.item_key().as_bytes() == b"secret.txt")
        .unwrap();
    let result = c.open(secret_item.item_ref(), default_budgets());
    assert!(result.is_err(), "should fail to open unreadable file");

    // Restore permissions for tempdir cleanup.
    fs::set_permissions(
        dir.path().join("secret.txt"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

#[test]
fn version_id_changes_on_mtime_only() {
    let dir = create_test_dir(&[("file.txt", b"same content")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let mut c1 = FilesystemConnector::new(dir.path());
    let items1 = collect_all(&mut c1, &start, &end);
    let v1 = items1[0].version();

    // Sleep briefly to ensure mtime changes, then touch file without
    // changing content.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let content = fs::read(dir.path().join("file.txt")).unwrap();
    fs::write(dir.path().join("file.txt"), &content).unwrap();

    let mut c2 = FilesystemConnector::new(dir.path());
    let items2 = collect_all(&mut c2, &start, &end);
    let v2 = items2[0].version();

    // mtime changed even though content is identical, so version should differ.
    assert_ne!(v1, v2, "version should change when mtime changes");
}

#[test]
fn fifo_is_skipped() {
    use std::process::Command;

    let dir = create_test_dir(&[("file.txt", b"data")]);
    let fifo_path = dir.path().join("pipe");

    // Create a named pipe. If mkfifo is not available, skip the test.
    let status = Command::new("mkfifo").arg(&fifo_path).status();
    if status.is_err() || !status.unwrap().success() {
        return; // mkfifo not available; skip gracefully.
    }

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    // Only file.txt should be indexed; the FIFO is skipped.
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"file.txt");

    assert!(
        c.walk_warnings()
            .iter()
            .any(|w| w.message.contains("special file")),
        "expected a special-file warning for the FIFO"
    );
}

#[test]
fn open_rejects_fifo_replacing_indexed_file() {
    use std::process::Command;

    let dir = create_test_dir(&[("target.txt", b"real data")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Index while it's a regular file.
    let mut c = FilesystemConnector::new(dir.path());
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Replace the regular file with a FIFO.
    let target = dir.path().join("target.txt");
    fs::remove_file(&target).unwrap();
    let status = Command::new("mkfifo").arg(&target).status();
    if status.is_err() || !status.unwrap().success() {
        return; // mkfifo not available; skip gracefully.
    }

    // open() on the now-FIFO path should fail with a permanent error.
    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("open should reject FIFO replacing a regular file"),
    };
    assert!(!err.is_retryable(), "FIFO rejection should be permanent");
}

#[test]
fn very_long_filename_is_indexed() {
    let dir = tempfile::tempdir().expect("create tempdir");
    // 255 chars is the maximum filename length on most filesystems.
    let long_name = "a".repeat(255);
    let file_path = dir.path().join(&long_name);

    if fs::write(&file_path, b"long name content").is_err() {
        return; // Filesystem doesn't support 255-char names; skip.
    }

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), long_name.as_bytes());

    // Verify it round-trips through open.
    let mut reader = c.open(all[0].item_ref(), default_budgets()).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"long name content");
}

// ---------------------------------------------------------------
// Membership enforcement tests
// ---------------------------------------------------------------

#[test]
fn read_rejects_non_indexed_item_ref() {
    let dir = create_test_dir(&[("a.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Trigger indexing.
    let _ = collect_all(&mut c, &start, &end);

    // Create a new file after indexing.
    fs::write(dir.path().join("b.txt"), b"post-index").unwrap();

    // Attempt to read the non-indexed file.
    let bad_ref = ItemRef::try_from_slice(b"b.txt").unwrap();
    let result = c.open(&bad_ref, default_budgets());
    let err = result.err().expect("should reject item_ref not in index");
    assert!(
        !err.is_retryable(),
        "membership rejection should be permanent"
    );
}

#[test]
fn read_range_rejects_non_indexed_item_ref() {
    let dir = create_test_dir(&[("a.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let _ = collect_all(&mut c, &start, &end);

    let bad_ref = ItemRef::try_from_slice(b"nonexistent.txt").unwrap();
    let mut buf = [0u8; 32];
    let result = c.read_range(&bad_ref, 0, &mut buf, default_budgets());
    assert!(result.is_err(), "should reject item_ref not in index");
}

#[rstest]
#[case::current_dir_prefix(b"./a.txt")]
#[case::double_slash(b"a//b.txt")]
#[case::trailing_slash(b"a.txt/")]
#[case::just_dot(b".")]
fn non_canonical_item_ref_rejected(#[case] ref_bytes: &[u8]) {
    let dir = create_test_dir(&[("a.txt", b"data"), ("a/b.txt", b"nested")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Trigger indexing.
    let _ = collect_all(&mut c, &start, &end);

    // These non-canonical spellings don't match any indexed key.
    let bad_ref = ItemRef::try_from_slice(ref_bytes).unwrap();
    let result = c.open(&bad_ref, default_budgets());
    assert!(
        result.is_err(),
        "non-canonical ref {:?} should be rejected",
        ref_bytes
    );
}

#[test]
fn open_without_prior_enumerate_triggers_lazy_indexing() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());

    // A valid ItemRef that exists on disk should succeed even without
    // prior enumeration — lazy indexing satisfies the ReadConnector
    // affinity contract for compatible instances.
    let item_ref = ItemRef::try_from_slice(b"file.txt").unwrap();
    let mut reader = match c.open(&item_ref, default_budgets()) {
        Ok(r) => r,
        Err(e) => panic!("open should trigger lazy indexing, got: {e:?}"),
    };
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"data");
}

#[test]
fn open_without_enumerate_rejects_absent_item_ref() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());

    // An ItemRef for a file that does not exist should still fail
    // after lazy indexing because membership enforcement rejects it.
    let item_ref = ItemRef::try_from_slice(b"no_such_file.txt").unwrap();
    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("absent item_ref should be rejected"),
    };
    assert!(
        err.message().contains("not found in index"),
        "error should indicate item_ref not found, got: {}",
        err.message()
    );
}

// ---------------------------------------------------------------
// Warning cap tests
// ---------------------------------------------------------------

#[test]
fn warning_cap_limits_storage() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    // Create many symlinks to exceed the warning cap.
    for i in 0..20 {
        std::os::unix::fs::symlink("target", dir.path().join(format!("link_{i:03}"))).unwrap();
    }

    let mut c = FilesystemConnector::new(dir.path()).with_max_warnings(5);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let _ = collect_all(&mut c, &start, &end);
    assert!(
        c.walk_warnings().len() <= 5,
        "warnings should be capped at max_warnings"
    );
    assert!(
        c.overflow_warning_count() > 0,
        "overflow count should be nonzero when warnings exceed cap"
    );
    assert_eq!(
        c.walk_warnings().len() + c.overflow_warning_count(),
        20,
        "total warnings + overflow should equal number of symlinks"
    );
}

#[test]
fn zero_max_warnings_drops_all() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    std::os::unix::fs::symlink("target", dir.path().join("link")).unwrap();

    let mut c = FilesystemConnector::new(dir.path()).with_max_warnings(0);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let _ = collect_all(&mut c, &start, &end);
    assert!(c.walk_warnings().is_empty(), "no warnings should be stored");
    assert_eq!(
        c.overflow_warning_count(),
        1,
        "overflow should count the dropped warning"
    );
}

// ---------------------------------------------------------------
// Error classification tests
// ---------------------------------------------------------------

#[test]
fn eloop_classified_as_permanent() {
    let err = io::Error::from_raw_os_error(libc::ELOOP);
    assert!(
        crate::common::is_permanent_io_error(&err),
        "ELOOP should be permanent"
    );
}

#[test]
fn enotdir_classified_as_permanent() {
    let err = io::Error::from_raw_os_error(libc::ENOTDIR);
    assert!(
        crate::common::is_permanent_io_error(&err),
        "ENOTDIR should be permanent"
    );
}

#[test]
fn eisdir_classified_as_permanent() {
    let err = io::Error::from_raw_os_error(libc::EISDIR);
    assert!(
        crate::common::is_permanent_io_error(&err),
        "EISDIR should be permanent"
    );
}

#[test]
fn transient_error_remains_retryable() {
    // EAGAIN / EWOULDBLOCK is transient.
    let err = io::Error::from_raw_os_error(libc::EAGAIN);
    assert!(
        !crate::common::is_permanent_io_error(&err),
        "EAGAIN should be retryable"
    );
}

// ---------------------------------------------------------------
// Deadline-aware indexing tests
// ---------------------------------------------------------------

#[test]
fn deadline_expires_during_walk_returns_retryable() {
    // Create a directory tree with multiple subdirectories.
    let dir = create_test_dir(&[("a/f1.txt", b"1"), ("b/f2.txt", b"2"), ("c/f3.txt", b"3")]);

    // Use an already-expired deadline.
    let expired_deadline = Instant::now() - Duration::from_secs(1);
    let budgets = Budgets::try_new(100, u64::MAX, Some(expired_deadline)).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), budgets);
    assert!(result.is_err(), "expired deadline should abort indexing");
    assert!(
        result.unwrap_err().is_retryable(),
        "deadline expiry should be retryable"
    );
}

#[test]
fn deadline_expiry_allows_retry_with_fresh_deadline() {
    let dir = create_test_dir(&[("file.txt", b"data")]);

    // First call with expired deadline fails.
    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), expired);
    assert!(result.is_err());

    // Second call with no deadline succeeds.
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 1);
}

// ---------------------------------------------------------------
// Root canonicalization tests
// ---------------------------------------------------------------

/// RAII guard that restores the process working directory on drop,
/// even if the test panics.
struct CwdGuard(PathBuf);

impl CwdGuard {
    fn set(path: &Path) -> Self {
        let original = std::env::current_dir().expect("get cwd");
        std::env::set_current_dir(path).expect("set cwd");
        Self(original)
    }
}

impl Drop for CwdGuard {
    fn drop(&mut self) {
        let _ = std::env::set_current_dir(&self.0);
    }
}

#[test]
fn relative_root_is_canonicalized() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Use a relative path through the tempdir's parent.
    let abs_path = dir.path().to_path_buf();
    let parent = abs_path.parent().unwrap();
    let dir_name = abs_path.file_name().unwrap();
    let relative = PathBuf::from(".").join(dir_name);

    // CwdGuard restores the original cwd even on panic.
    let _guard = CwdGuard::set(parent);

    let mut c = FilesystemConnector::new(&relative);
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 1);

    // After indexing, reads still work even if we change cwd.
    drop(_guard);
    let item_ref = page.items()[0].item_ref().clone();
    let mut reader = c.open(&item_ref, default_budgets()).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"data");
}

// ---------------------------------------------------------------
// openat traversal tests
// ---------------------------------------------------------------

#[test]
fn openat_rejects_intermediate_symlink_replacement() {
    // Create a directory tree: dir/sub/file.txt
    let dir = create_test_dir(&[("sub/file.txt", b"original")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Index the tree.
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].item_key().as_bytes(), b"sub/file.txt");
    let item_ref = items[0].item_ref().clone();

    // Replace the intermediate directory with a symlink.
    let escape_dir = tempfile::tempdir().expect("create escape dir");
    fs::write(escape_dir.path().join("file.txt"), b"escaped content").unwrap();

    fs::remove_dir_all(dir.path().join("sub")).unwrap();
    std::os::unix::fs::symlink(escape_dir.path(), dir.path().join("sub")).unwrap();

    // openat with O_NOFOLLOW on the intermediate "sub" should fail.
    let result = c.open(&item_ref, default_budgets());
    assert!(
        result.is_err(),
        "openat should reject intermediate symlink (sub -> escape)"
    );
}

// ---------------------------------------------------------------
// File-modification-after-index tests
// ---------------------------------------------------------------

#[test]
fn file_deleted_after_indexing_returns_permanent_error() {
    let dir = create_test_dir(&[("ephemeral.txt", b"will be deleted")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Delete the file after indexing.
    fs::remove_file(dir.path().join("ephemeral.txt")).unwrap();

    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("open should succeed for deleted file"),
    };
    assert!(
        !err.is_retryable(),
        "deleted file should be a permanent error"
    );
}

#[test]
fn file_truncated_after_indexing_reads_shorter() {
    let dir = create_test_dir(&[("shrink.txt", b"original content here")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Truncate the file after indexing.
    fs::write(dir.path().join("shrink.txt"), b"").unwrap();

    let mut buf = [0u8; 128];
    let n = c
        .read_range(&item_ref, 0, &mut buf, default_budgets())
        .unwrap();
    assert_eq!(n, 0, "truncated file should return 0 bytes");
}

#[test]
fn permissions_removed_after_indexing_returns_permanent_error() {
    use std::os::unix::fs::PermissionsExt;

    let dir = create_test_dir(&[("locked.txt", b"sensitive")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    // Remove read permissions after indexing.
    fs::set_permissions(
        dir.path().join("locked.txt"),
        fs::Permissions::from_mode(0o000),
    )
    .unwrap();

    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("open should fail when permissions are removed"),
    };
    assert!(
        !err.is_retryable(),
        "permission denied should be a permanent error"
    );

    // Restore permissions for tempdir cleanup.
    fs::set_permissions(
        dir.path().join("locked.txt"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
}

// ---------------------------------------------------------------
// Prefix-sum split consistency test
// ---------------------------------------------------------------

#[test]
fn prefix_sum_split_matches_linear_scan() {
    // Verify that the prefix-sum-based split produces the same result as the
    // linear-scan in common::choose_split_index for various file configurations.
    let configs: &[&[(&str, &[u8])]] = &[
        &[
            ("a.txt", &[0u8; 100] as &[u8]),
            ("b.txt", &[0u8; 100]),
            ("c.txt", &[0u8; 100]),
            ("d.txt", &[0u8; 100]),
        ],
        &[
            ("a.txt", &[0u8; 900] as &[u8]),
            ("b.txt", &[0u8; 50]),
            ("c.txt", &[0u8; 50]),
        ],
        &[
            ("a.txt", &[0u8; 10] as &[u8]),
            ("b.txt", &[0u8; 10]),
            ("c.txt", &[0u8; 900]),
        ],
    ];

    for (i, config) in configs.iter().enumerate() {
        let dir = create_test_dir(config);
        let mut c = FilesystemConnector::new(dir.path());
        let start = make_key(b"\x00");
        let end = make_key(b"\xff");

        // Trigger indexing.
        let _ = collect_all(&mut c, &start, &end);

        // Prefix-sum split.
        let ps_split = c
            .choose_split_point_range(&start, &end, &Cursor::initial())
            .unwrap();

        // Linear-scan split via common::choose_split_index.
        let linear_idx = common::choose_split_index(&c.files, 0, c.files.len());
        let linear_split = linear_idx.map(|idx| c.files[idx].key.clone());

        assert_eq!(
            ps_split, linear_split,
            "config {i}: prefix-sum split should match linear scan"
        );
    }
}

// ---------------------------------------------------------------
// Split deadline enforcement test
// ---------------------------------------------------------------

#[test]
fn choose_split_point_respects_deadline() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let mut c = FilesystemConnector::new(dir.path());

    let shard = ShardSpec::try_with_range(b"\x00", b"\xff").unwrap();
    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();

    let result = c.choose_split_point(&shard, &Cursor::initial(), expired);
    assert!(result.is_err(), "expired deadline should cause an error");
    assert!(
        result.unwrap_err().is_retryable(),
        "deadline error should be retryable"
    );
}

// ---------------------------------------------------------------
// Cross-instance read compatibility
// ---------------------------------------------------------------

#[test]
fn compatible_instance_reads_item_ref_from_another_instance() {
    let dir = create_test_dir(&[("hello.txt", b"hello world")]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Instance A: enumerate and grab an ItemRef.
    let mut a = FilesystemConnector::new(dir.path());
    let page = a
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    let item_ref = page.items()[0].item_ref().clone();

    // Instance B: fresh connector over the same root, never enumerated.
    // The ReadConnector contract allows compatible instances to read
    // ItemRefs from each other.
    let mut b = FilesystemConnector::new(dir.path());
    let mut reader = match b.open(&item_ref, default_budgets()) {
        Ok(r) => r,
        Err(e) => {
            panic!("a compatible instance should read ItemRefs from another instance, got: {e:?}")
        }
    };
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world");
}

// ---------------------------------------------------------------
// Unix socket skip test
// ---------------------------------------------------------------

#[test]
fn unix_socket_is_skipped() {
    use std::os::unix::net::UnixListener;

    let dir = create_test_dir(&[("file.txt", b"data")]);
    // Bind a Unix domain socket inside the test directory.
    let _listener = UnixListener::bind(dir.path().join("test.sock")).expect("bind unix socket");

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    // Only the regular file should be indexed; the socket is skipped.
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"file.txt");

    assert!(
        c.walk_warnings()
            .iter()
            .any(|w| w.message.contains("special file")),
        "expected a special-file warning for the unix socket"
    );
}

// ---------------------------------------------------------------
// Hard link behavior test
// ---------------------------------------------------------------

#[test]
fn hard_links_indexed_as_separate_items() {
    let dir = create_test_dir(&[("original.txt", b"shared content")]);
    fs::hard_link(dir.path().join("original.txt"), dir.path().join("link.txt"))
        .expect("create hard link");

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(
        all.len(),
        2,
        "both the original and the hard link should be indexed"
    );

    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
    assert!(keys.contains(&b"link.txt".as_slice()));
    assert!(keys.contains(&b"original.txt".as_slice()));

    // Hard links share the same inode, so version IDs should match
    // (same inode/mtime/size/dev).
    assert_eq!(
        all[0].version(),
        all[1].version(),
        "hard links with identical metadata should have the same version ID"
    );

    // Both should be independently readable via open().
    for item in &all {
        let mut reader = c.open(item.item_ref(), default_budgets()).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"shared content");
    }
}

// ---------------------------------------------------------------
// Post-indexing enumerate deadline test
// ---------------------------------------------------------------

#[test]
fn expired_deadline_after_successful_indexing_returns_retryable() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Index successfully first.
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1, "indexing should succeed");

    // Now call enumerate with an already-expired deadline. This hits the
    // deadline check in `enumerate_page_bounds` after `ensure_indexed`
    // returns immediately from the memoized index.
    let expired_budgets =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), expired_budgets);

    assert!(
        result.is_err(),
        "expired deadline after indexing should error"
    );
    assert!(
        result.unwrap_err().is_retryable(),
        "deadline expiry should be a retryable error"
    );
}
