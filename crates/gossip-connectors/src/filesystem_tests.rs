//! Filesystem connector behavior and regression tests.
//!
//! The highest-risk logic is the per-directory sorted walker: it must produce
//! global byte-sorted keys without whole-tree buffering, while still honoring
//! depth limits and deadline checks. The ordering, stress, and deadline tests
//! below document those invariants and guard walker regressions.

use std::io::Read as _;
use std::os::unix::ffi::OsStringExt;
use std::time::{Duration, Instant};

use gossip_contracts::connector::conformance::{ConformanceConfig, check_connector_conforms};
use gossip_contracts::connector::{MAX_ITEM_KEY_SIZE, MAX_TOKEN_SIZE, TokenBytes};
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
fn cold_resume_with_new_instance_skips_to_cursor_last_key() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let budgets = small_page_budgets(2);

    let mut first = FilesystemConnector::new(dir.path());
    let page1 = first
        .enumerate_page_range(&start, &end, &Cursor::initial(), budgets)
        .expect("first page should enumerate");
    assert_eq!(page1.items().len(), 2);
    assert_eq!(page1.items()[0].item_key().as_bytes(), b"a.txt");
    assert_eq!(page1.items()[1].item_key().as_bytes(), b"b.txt");

    // New connector instance resumes from only the persisted cursor key.
    let mut resumed = FilesystemConnector::new(dir.path());
    let page2 = resumed
        .enumerate_page_range(&start, &end, page1.next_cursor(), budgets)
        .expect("cold-resume page should enumerate");
    assert_eq!(page2.items().len(), 2);
    assert_eq!(page2.items()[0].item_key().as_bytes(), b"c.txt");
    assert_eq!(page2.items()[1].item_key().as_bytes(), b"d.txt");
}

#[test]
fn enumerate_page_uses_pooled_toxic_wrappers() {
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("bravo.txt", b"b"),
        ("charlie.txt", b"c"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Use a small page size so the walk is NOT exhausted after the first page,
    // ensuring the walk state stack is non-empty and a token can be encoded.
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(2))
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
        next.token().is_some(),
        "token should be emitted when token resume is enabled"
    );
    assert!(
        next.token()
            .is_some_and(|token| token.as_bytes().len() <= MAX_TOKEN_SIZE),
        "token must respect MAX_TOKEN_SIZE"
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

// Table-driven coverage for the subtree overlap predicate used by directory
// pruning. Cases intentionally include conservative edges (root prefix and
// trailing 0xFF) where we keep traversal to avoid false-positive skips.
#[rstest]
#[case::unbounded_shard(b"docs", None, None, false)]
#[case::subtree_below_range(b"aaa", Some(b"mmm".as_slice()), Some(b"zzz".as_slice()), true)]
#[case::subtree_above_range(b"zzz", Some(b"aaa".as_slice()), Some(b"mmm".as_slice()), true)]
#[case::overlaps_shard_start(
    b"mmm",
    Some(b"mmm/abc".as_slice()),
    Some(b"zzz".as_slice()),
    false
)]
#[case::overlaps_shard_end(
    b"src",
    Some(b"aaa".as_slice()),
    Some(b"src/z".as_slice()),
    false
)]
#[case::fully_inside_shard(
    b"src/lib",
    Some(b"src/a".as_slice()),
    Some(b"src/z".as_slice()),
    false
)]
#[case::empty_prefix_root(
    b"",
    Some(b"abc".as_slice()),
    Some(b"xyz".as_slice()),
    false
)]
#[case::unbounded_start(b"zzz", None, Some(b"mmm".as_slice()), true)]
#[case::unbounded_end(b"aaa", Some(b"mmm".as_slice()), None, true)]
#[case::trailing_ff_is_prunable(
    b"\xff",
    Some(b"abc".as_slice()),
    Some(b"xyz".as_slice()),
    true
)]
#[case::trailing_ff_overlaps_unbounded_end(
    b"\xff",
    Some(b"abc".as_slice()),
    None,
    false
)]
#[case::nested_prefix_outside(
    b"docs/internal",
    Some(b"src/a".as_slice()),
    Some(b"src/z".as_slice()),
    true
)]
#[case::single_char_prefix(b"z", Some(b"a".as_slice()), Some(b"m".as_slice()), true)]
fn should_skip_subtree_respects_range_overlap(
    #[case] dir_prefix: &[u8],
    #[case] shard_start: Option<&[u8]>,
    #[case] shard_end: Option<&[u8]>,
    #[case] expected: bool,
) {
    assert_eq!(
        should_skip_subtree(dir_prefix, shard_start, shard_end),
        expected
    );
}

#[test]
fn with_key_range_prunes_walk_to_expected_subset() {
    let dir = create_test_dir(&[
        ("docs/readme.md", b"docs"),
        ("src/a.rs", b"a"),
        ("src/mid.rs", b"mid"),
        ("src/more/lib.rs", b"more"),
        ("src/zeta.rs", b"z"),
        ("tests/test.rs", b"test"),
    ]);
    let mut bounded =
        FilesystemConnector::new(dir.path()).with_key_range(Some(b"src/m"), Some(b"src/z"));
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut bounded, &start, &end);
    let keys: Vec<&[u8]> = items
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(
        keys,
        // End bound is exclusive: src/zeta.rs is outside [src/m, src/z).
        vec![b"src/mid.rs".as_slice(), b"src/more/lib.rs".as_slice()]
    );
}

#[test]
fn bounded_walk_matches_unbounded_filtered_range() {
    let dir = create_test_dir(&[
        ("aaa/one.txt", b"1"),
        ("src/a.txt", b"2"),
        ("src/m/a.txt", b"3"),
        ("src/m/b.txt", b"4"),
        ("src/t/z.txt", b"5"),
        ("zzz/last.txt", b"6"),
    ]);
    let full_start = make_key(b"\x00");
    let full_end = make_key(b"\xff");

    let mut unbounded = FilesystemConnector::new(dir.path());
    let baseline = collect_all(&mut unbounded, &full_start, &full_end);

    let mut bounded =
        FilesystemConnector::new(dir.path()).with_key_range(Some(b"src/m"), Some(b"src/t"));
    let bounded_items = collect_all(&mut bounded, &full_start, &full_end);

    // Baseline oracle: enumerate everything, then apply the same half-open
    // filter the bounded walk should enforce.
    let expected: Vec<Vec<u8>> = baseline
        .iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .filter(|key| key.as_slice() >= b"src/m".as_slice() && key.as_slice() < b"src/t".as_slice())
        .collect();
    let actual: Vec<Vec<u8>> = bounded_items
        .iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();
    assert_eq!(actual, expected);
}

#[test]
fn with_key_range_intersects_per_request_bounds() {
    let dir = create_test_dir(&[
        ("src/a.txt", b"a"),
        ("src/m.txt", b"m"),
        ("src/t.txt", b"t"),
        ("src/z.txt", b"z"),
    ]);
    let mut bounded =
        FilesystemConnector::new(dir.path()).with_key_range(Some(b"src/m"), Some(b"src/z"));

    // Request bounds are wider; effective range is the intersection.
    let request_start = make_key(b"src/a");
    let request_end = make_key(b"src/zz");
    let items = collect_all(&mut bounded, &request_start, &request_end);
    let keys: Vec<&[u8]> = items
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();

    assert_eq!(keys, vec![b"src/m.txt".as_slice(), b"src/t.txt".as_slice()]);
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

#[test]
fn walk_token_round_trips_from_live_walk_state() {
    let dir = create_test_dir(&[
        ("a/one.txt", b"1"),
        ("a/two.txt", b"2"),
        ("b/three.txt", b"3"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(1))
        .expect("first page");
    let emitted = page
        .next_cursor()
        .token()
        .expect("token must be present with token resume enabled");
    let decoded = WalkToken::decode_bytes(emitted.as_bytes()).expect("decode emitted token");

    let state = c
        .walk_state
        .as_ref()
        .expect("walk state must persist after first page");
    let rebuilt = WalkToken::encode_from_state(state).expect("encode token from walk state");
    let rebuilt_decoded =
        WalkToken::decode_bytes(rebuilt.as_bytes()).expect("decode rebuilt token");

    assert_eq!(decoded, rebuilt_decoded);
}

#[test]
fn walk_token_decode_rejects_invalid_payloads() {
    // Wrong version byte.
    assert!(WalkToken::decode_bytes(&[WALK_TOKEN_VERSION + 1, 0, 0]).is_none());

    // Truncated frame payload.
    assert!(WalkToken::decode_bytes(&[WALK_TOKEN_VERSION, 1, 0, 0]).is_none());

    // Non-root frame with zero-length component is invalid.
    let mut malformed = Vec::new();
    malformed.push(WALK_TOKEN_VERSION);
    malformed.extend_from_slice(&2u16.to_le_bytes());
    malformed.extend_from_slice(&0u16.to_le_bytes());
    malformed.extend_from_slice(&0u32.to_le_bytes());
    malformed.extend_from_slice(&0u16.to_le_bytes());
    malformed.extend_from_slice(&0u32.to_le_bytes());
    assert!(WalkToken::decode_bytes(&malformed).is_none());

    // `.` component in non-root frame is rejected (path traversal).
    let mut dot = Vec::new();
    dot.push(WALK_TOKEN_VERSION);
    dot.extend_from_slice(&2u16.to_le_bytes());
    // root frame: empty component
    dot.extend_from_slice(&0u16.to_le_bytes());
    dot.extend_from_slice(&0u32.to_le_bytes());
    // child frame: "."
    dot.extend_from_slice(&1u16.to_le_bytes());
    dot.push(b'.');
    dot.extend_from_slice(&0u32.to_le_bytes());
    assert!(
        WalkToken::decode_bytes(&dot).is_none(),
        "dot component must be rejected"
    );

    // `..` component in non-root frame is rejected (path traversal).
    let mut dotdot = Vec::new();
    dotdot.push(WALK_TOKEN_VERSION);
    dotdot.extend_from_slice(&2u16.to_le_bytes());
    // root frame: empty component
    dotdot.extend_from_slice(&0u16.to_le_bytes());
    dotdot.extend_from_slice(&0u32.to_le_bytes());
    // child frame: ".."
    dotdot.extend_from_slice(&2u16.to_le_bytes());
    dotdot.extend_from_slice(b"..");
    dotdot.extend_from_slice(&0u32.to_le_bytes());
    assert!(
        WalkToken::decode_bytes(&dotdot).is_none(),
        "dotdot component must be rejected"
    );
}

#[test]
fn walk_token_encoding_truncates_to_token_budget() {
    let mut stack = Vec::new();
    stack.push(WalkFrame {
        component: None,
        depth: 0,
        entries_since_check: 0,
        next_child_index: 7,
        entries: std::collections::VecDeque::new(),
    });
    for depth in 1..=512 {
        stack.push(WalkFrame {
            component: Some(std::ffi::OsString::from_vec(vec![b'a'; 255])),
            depth,
            entries_since_check: 0,
            next_child_index: 7,
            entries: std::collections::VecDeque::new(),
        });
    }
    let state = WalkState {
        stack,
        current_path: std::path::PathBuf::from("/tmp"),
        pending: None,
        last_emitted_key: None,
        emitted_count: 0,
        exhausted: false,
        visited_dirs: std::collections::HashSet::new(),
    };

    let token = WalkToken::encode_from_state(&state).expect("token should be emitted");
    assert!(
        token.as_bytes().len() <= MAX_TOKEN_SIZE,
        "token exceeded MAX_TOKEN_SIZE"
    );

    let decoded = WalkToken::decode_bytes(token.as_bytes()).expect("decoded truncated token");
    assert!(
        decoded.frames.len() < state.stack.len(),
        "deep stack should be truncated to fit budget"
    );
    assert_eq!(
        decoded
            .frames
            .last()
            .expect("truncated token keeps at least one frame")
            .next_child_index,
        6,
        "truncated token rewinds one child at retained leaf frame"
    );
}

// ---------------------------------------------------------------
// Unit tests — from_token failure paths
// ---------------------------------------------------------------

#[test]
fn from_token_rejects_empty_frames() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let token = WalkToken { frames: Vec::new() };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(result.is_none(), "empty frames must yield None");
}

#[test]
fn from_token_rejects_non_empty_root_component() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let token = WalkToken {
        frames: vec![WalkTokenFrame {
            component: b"bad".to_vec(),
            next_child_index: 0,
        }],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(result.is_none(), "non-empty root component must yield None");
}

#[test]
fn from_token_rejects_depth_exceeding_max() {
    let dir = create_test_dir(&[("sub/a.txt", b"1")]);
    let token = WalkToken {
        frames: vec![
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
            WalkTokenFrame {
                component: b"sub".to_vec(),
                next_child_index: 0,
            },
        ],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    // max_depth=0 means zero children allowed.
    let result =
        WalkState::from_token(dir.path(), token, 0, None, 10, &mut warnings, &mut overflow)
            .expect("should not error");
    assert!(
        result.is_none(),
        "child count exceeding max_depth must yield None"
    );
}

#[test]
fn from_token_rejects_empty_child_component() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let token = WalkToken {
        frames: vec![
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
        ],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(result.is_none(), "empty child component must yield None");
}

#[test]
fn from_token_rejects_child_with_slash() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let token = WalkToken {
        frames: vec![
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
            WalkTokenFrame {
                component: b"a/b".to_vec(),
                next_child_index: 0,
            },
        ],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(
        result.is_none(),
        "child component with slash must yield None"
    );
}

#[test]
fn from_token_rejects_child_with_null_byte() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let token = WalkToken {
        frames: vec![
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
            WalkTokenFrame {
                component: vec![b'a', 0],
                next_child_index: 0,
            },
        ],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(
        result.is_none(),
        "child component with null byte must yield None"
    );
}

#[test]
fn from_token_handles_missing_directory() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    // Point at a child directory that does not exist on disk.
    let token = WalkToken {
        frames: vec![
            WalkTokenFrame {
                component: Vec::new(),
                next_child_index: 0,
            },
            WalkTokenFrame {
                component: b"nonexistent".to_vec(),
                next_child_index: 0,
            },
        ],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(result.is_none(), "missing child directory must yield None");
}

#[test]
fn from_token_rejects_out_of_range_child_index() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    // Root has 2 entries; an index of u32::MAX is way past the end.
    let token = WalkToken {
        frames: vec![WalkTokenFrame {
            component: Vec::new(),
            next_child_index: u32::MAX,
        }],
    };
    let mut warnings = Vec::new();
    let mut overflow = 0usize;
    let result = WalkState::from_token(
        dir.path(),
        token,
        64,
        None,
        10,
        &mut warnings,
        &mut overflow,
    )
    .expect("should not error");
    assert!(result.is_none(), "out-of-range child index must yield None");
}

// ---------------------------------------------------------------
// Unit tests — Token resume after filesystem mutation
// ---------------------------------------------------------------

#[test]
fn token_resume_after_filesystem_mutation() {
    let dir = create_test_dir(&[
        ("aaa.txt", b"1"),
        ("bbb.txt", b"2"),
        ("ccc.txt", b"3"),
        ("ddd.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Page 1: enumerate first 2 items.
    let page1 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(2))
        .expect("page 1");
    assert_eq!(page1.items().len(), 2);
    let last_key_p1 = page1.items().last().unwrap().item_key().as_bytes().to_vec();
    let cursor_after_p1 = page1.next_cursor().clone();

    // Mutate the filesystem between pages: remove one file, add another.
    fs::remove_file(dir.path().join("ccc.txt")).expect("remove ccc.txt");
    fs::write(dir.path().join("bcc.txt"), b"new").expect("write bcc.txt");

    // Resume from the cursor saved after page 1.
    let mut c2 = FilesystemConnector::new(dir.path()).with_tokens(true);
    let mut remaining_keys = Vec::new();
    let mut cursor = cursor_after_p1;
    loop {
        let page = c2
            .enumerate_page_range(&start, &end, &cursor, small_page_budgets(10))
            .expect("resume page");
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            remaining_keys.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    // Invariants: no duplicates, all keys sorted, all keys > last key from page 1.
    for (i, key) in remaining_keys.iter().enumerate() {
        assert!(
            key.as_slice() > last_key_p1.as_slice(),
            "resumed key {:?} should be > last page-1 key {:?}",
            String::from_utf8_lossy(key),
            String::from_utf8_lossy(&last_key_p1),
        );
        if i > 0 {
            assert!(
                key.as_slice() > remaining_keys[i - 1].as_slice(),
                "keys must be strictly sorted"
            );
        }
    }
    // No duplicates (sorted + distinct check above implies this).
}

// ---------------------------------------------------------------
// Unit tests — Token + shard bounds interaction
// ---------------------------------------------------------------

#[test]
fn token_resume_with_shard_bounds() {
    let dir = create_test_dir(&[
        ("aaa/f1.txt", b"1"),
        ("aaa/f2.txt", b"2"),
        ("mmm/f1.txt", b"3"),
        ("mmm/f2.txt", b"4"),
        ("zzz/f1.txt", b"5"),
        ("zzz/f2.txt", b"6"),
    ]);
    let mut c = FilesystemConnector::new(dir.path())
        .with_tokens(true)
        .with_shard_bounds(b"mmm", b"zzz");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Enumerate one item at a time to force multi-page token resume.
    let mut all_keys = Vec::new();
    let mut cursor = Cursor::initial();
    loop {
        let page = c
            .enumerate_page_range(&start, &end, &cursor, small_page_budgets(1))
            .expect("page");
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            all_keys.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    // All keys must be in [mmm, zzz) and sorted.
    for (i, key) in all_keys.iter().enumerate() {
        assert!(
            key.as_slice() >= b"mmm".as_slice(),
            "key {:?} should be >= mmm",
            String::from_utf8_lossy(key),
        );
        assert!(
            key.as_slice() < b"zzz".as_slice(),
            "key {:?} should be < zzz",
            String::from_utf8_lossy(key),
        );
        if i > 0 {
            assert!(
                key.as_slice() > all_keys[i - 1].as_slice(),
                "keys must be strictly sorted"
            );
        }
    }
    // Expect exactly the mmm/ subtree items.
    assert!(
        !all_keys.is_empty(),
        "should enumerate at least one key in [mmm, zzz)"
    );
    for key in &all_keys {
        assert!(
            key.starts_with(b"mmm/"),
            "all keys should be under mmm/; got {:?}",
            String::from_utf8_lossy(key),
        );
    }
}

// ---------------------------------------------------------------
// Unit tests — Token size boundaries with long components
// ---------------------------------------------------------------

#[test]
fn token_encodes_frames_with_varying_component_lengths() {
    // Build a WalkState with components of length 1, 127, 254, and 255 bytes.
    let component_lengths = [1usize, 127, 254, 255];
    let mut stack = Vec::new();
    stack.push(WalkFrame {
        component: None,
        depth: 0,
        entries_since_check: 0,
        next_child_index: 0,
        entries: std::collections::VecDeque::new(),
    });
    for (i, &len) in component_lengths.iter().enumerate() {
        stack.push(WalkFrame {
            component: Some(std::ffi::OsString::from_vec(vec![b'x'; len])),
            depth: i + 1,
            entries_since_check: 0,
            next_child_index: i as u32 + 1,
            entries: std::collections::VecDeque::new(),
        });
    }
    let state = WalkState {
        stack,
        current_path: std::path::PathBuf::from("/tmp"),
        pending: None,
        last_emitted_key: None,
        emitted_count: 0,
        exhausted: false,
        visited_dirs: std::collections::HashSet::new(),
    };

    let token = WalkToken::encode_from_state(&state).expect("should encode");
    let decoded = WalkToken::decode_bytes(token.as_bytes()).expect("should decode");

    // All 5 frames (root + 4 components) should survive the round-trip.
    assert_eq!(decoded.frames.len(), 5);
    for (i, &len) in component_lengths.iter().enumerate() {
        assert_eq!(
            decoded.frames[i + 1].component.len(),
            len,
            "component {i} length mismatch"
        );
    }
}

#[test]
fn token_truncation_drops_oversized_component() {
    // A single frame with a component at u16::MAX + 1 bytes cannot be encoded
    // because component_len exceeds u16. The encoder should break before it and
    // produce a root-only token with the saturating_sub(1) rewind applied.
    let huge_len = u16::MAX as usize + 1;
    let stack = vec![
        WalkFrame {
            component: None,
            depth: 0,
            entries_since_check: 0,
            next_child_index: 5,
            entries: std::collections::VecDeque::new(),
        },
        WalkFrame {
            component: Some(std::ffi::OsString::from_vec(vec![b'z'; huge_len])),
            depth: 1,
            entries_since_check: 0,
            next_child_index: 0,
            entries: std::collections::VecDeque::new(),
        },
    ];
    let state = WalkState {
        stack,
        current_path: std::path::PathBuf::from("/tmp"),
        pending: None,
        last_emitted_key: None,
        emitted_count: 0,
        exhausted: false,
        visited_dirs: std::collections::HashSet::new(),
    };

    let token = WalkToken::encode_from_state(&state).expect("root-only token should be emitted");
    let decoded = WalkToken::decode_bytes(token.as_bytes()).expect("should decode");

    // Only the root frame survives; it becomes the truncated leaf.
    assert_eq!(decoded.frames.len(), 1, "only root frame should survive");
    assert_eq!(
        decoded.frames[0].next_child_index, 4,
        "truncated leaf root should have saturating_sub(1) applied: 5 -> 4"
    );
}

// ---------------------------------------------------------------
// Unit tests — Split points
// ---------------------------------------------------------------

#[test]
fn split_point_returns_streaming_hint_for_nontrivial_range() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Enumerate to populate the integrated estimator.
    let _ = collect_all(&mut c, &start, &end);

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("streaming split hint should be available");
    assert!(
        split.as_bytes() > b"a.txt".as_slice() && split.as_bytes() <= b"d.txt".as_slice(),
        "split should keep at least one item on the left and remain in-range"
    );
}

#[test]
fn split_point_with_key_range_stays_within_configured_bounds() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("m.txt", b"2"),
        ("r.txt", b"3"),
        ("z.txt", b"4"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"m"), Some(b"z"));
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Enumerate to populate the integrated estimator.
    let _ = collect_all(&mut c, &start, &end);

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("split should exist within intersected bounds");
    assert!(
        split.as_bytes() >= b"m".as_slice() && split.as_bytes() < b"z".as_slice(),
        "split should honor connector-level key-range intersection"
    );
}

#[test]
fn split_point_advances_past_cursor_last_key() {
    // Use skewed sizes so the byte-weighted median falls well past the cursor.
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", &[b'x'; 1000]),
        ("e.txt", &[b'x'; 1000]),
        ("f.txt", &[b'x'; 1000]),
        ("g.txt", &[b'x'; 1000]),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Enumerate all pages to populate the integrated estimator.
    let _ = collect_all(&mut c, &start, &end);

    let cursor = Cursor::with_last_key(make_key(b"b.txt"));
    let split = c.choose_split_point_range(&start, &end, &cursor).unwrap();
    let split = split.expect("split should still be available after cursor");
    assert!(
        split.as_bytes() > b"b.txt".as_slice(),
        "split must advance past cursor last_key"
    );
}

#[test]
fn split_point_inverted_bounds_returns_permanent_error() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"a"), Some(b"z"));
    let start = make_key(b"\xff");
    let end = make_key(b"\x00");

    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted bounds should produce an error");
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

    // Interleaved fixture: traversal-by-discovery would be unstable here.
    // The walker must match a global lexicographic sort of encoded path keys.
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
fn directory_file_prefix_order_matches_git_tree_sort_rules() {
    let dir = create_test_dir(&[
        ("src/inside.txt", b"1"),
        ("src-utils.txt", b"2"),
        ("a/inside.txt", b"3"),
        ("aa.txt", b"4"),
        ("z/inside.txt", b"5"),
        ("z.txt", b"6"),
    ]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Regression guard for trailing-separator ordering:
    // `src-utils.txt` must sort before `src/...` because directories compare as `name/`.
    let all = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = all.iter().map(|item| item.item_key().as_bytes()).collect();
    assert_eq!(
        keys,
        vec![
            b"a/inside.txt".as_slice(),
            b"aa.txt".as_slice(),
            b"src-utils.txt".as_slice(),
            b"src/inside.txt".as_slice(),
            b"z.txt".as_slice(),
            b"z/inside.txt".as_slice(),
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
fn mutations_visible_after_restarting_from_initial_cursor() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // First enumerate drains the current walk.
    let all1 = collect_all(&mut c, &start, &end);
    assert_eq!(all1.len(), 2);

    // Mutate directory after indexing.
    fs::write(dir.path().join("c.txt"), b"3").unwrap();

    // Restarting from the initial cursor rebuilds walk state and sees
    // filesystem changes.
    let all2 = collect_all(&mut c, &start, &end);
    assert_eq!(all2.len(), 3);
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
// Error classification & retry semantics tests
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
fn index_failure_is_repeatable_without_memoization() {
    let mut c = FilesystemConnector::new("/nonexistent/path/that/does/not/exist");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // First call fails.
    let err1 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap_err();
    // Second call re-attempts setup and should surface the same permanent class.
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
// Depth limit and cycle detection tests
// ---------------------------------------------------------------

#[test]
fn depth_limit_catches_deep_trees() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let mut path = dir.path().to_path_buf();
    // Create 10-deep tree: 00/01/02/.../09/leaf.txt
    for i in 0..10 {
        path = path.join(format!("{i:02}"));
    }
    fs::create_dir_all(&path).unwrap();
    fs::write(path.join("leaf.txt"), b"deep").unwrap();

    // Also create a shallow file that IS reachable.
    fs::write(dir.path().join("shallow.txt"), b"top").unwrap();

    let mut c = FilesystemConnector::new(dir.path()).with_max_depth(5);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    // Only the shallow file should be returned; the deep leaf is past depth 5.
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].item_key().as_bytes(), b"shallow.txt");

    // A depth-exceeded warning should be present.
    assert!(
        c.walk_warnings()
            .iter()
            .any(|w| w.message.contains("exceeded maximum walk depth")),
        "expected a depth-exceeded warning, got: {:?}",
        c.walk_warnings(),
    );
}

#[test]
fn file_deleted_between_readdir_and_stat_generates_warning() {
    let dir = create_test_dir(&[("a.txt", b"aaa"), ("doomed.txt", b"bye"), ("z.txt", b"zzz")]);

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // First page: get a.txt with a page budget of 1.
    let page1 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(1))
        .unwrap();
    assert_eq!(page1.items().len(), 1);
    assert_eq!(page1.items()[0].item_key().as_bytes(), b"a.txt");

    // Delete doomed.txt between pages — simulates the race.
    fs::remove_file(dir.path().join("doomed.txt")).unwrap();

    // Second page: doomed.txt is already buffered in the walker's directory
    // entries but stat will fail. The walker should skip it with a warning
    // and return z.txt.
    let page2 = c
        .enumerate_page_range(&start, &end, page1.next_cursor(), small_page_budgets(2))
        .unwrap();
    let keys: Vec<&[u8]> = page2
        .items()
        .iter()
        .map(|i| i.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"z.txt".as_slice()]);

    // A metadata-related warning should have been recorded.
    assert!(
        c.walk_warnings()
            .iter()
            .any(|w| w.message.contains("metadata failed")),
        "expected a 'metadata failed' warning, got: {:?}",
        c.walk_warnings(),
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

    // Enumerate to populate the integrated estimator.
    let shard = ShardSpec::try_with_range(b"\x00", b"\xff").unwrap();
    let _ = collect_all_via_shard(&mut c, &shard, default_budgets());

    let split = c
        .choose_split_point(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    let split = split.expect("split should be available via shard API");
    assert!(
        split.as_bytes() > b"a.txt".as_slice() && split.as_bytes() <= b"d.txt".as_slice(),
        "split should be a valid in-range candidate"
    );
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
    let fd = cached.file.as_raw_fd();
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

    use gossip_stdx::test_support::proptest_cases;

    /// Strategy: generate a set of (path, content) pairs with unique paths.
    ///
    /// Paths use `[a-z0-9_-]{1,8}` segments with 0-2 levels of nesting.
    fn file_set_strategy(max_files: usize) -> impl Strategy<Value = Vec<(String, Vec<u8>)>> {
        let segment = "[a-z0-9_-]{1,8}";
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

    fn key_bound_strategy() -> impl Strategy<Value = Vec<u8>> {
        pvec(any::<u8>(), 1..6usize)
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
        #![proptest_config(ProptestConfig::with_cases(proptest_cases(64)))]

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
        fn full_enum_matches_global_sort(files in file_set_strategy(20)) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let (_dir, mut c) = make_connector(&files);

            let actual: Vec<Vec<u8>> = collect_all(&mut c, &start, &end)
                .iter()
                .map(|item| item.item_key().as_bytes().to_vec())
                .collect();

            // Global sort is the reference oracle for walker correctness.
            // If per-directory sorting composes incorrectly, this diverges.
            let mut expected: Vec<Vec<u8>> = files
                .iter()
                .map(|(path, _)| path.as_bytes().to_vec())
                .collect();
            expected.sort_unstable();
            expected.dedup();

            prop_assert_eq!(actual, expected);
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
        fn cold_resume_with_tokens_matches_key_only_resume(
            files in file_set_strategy(20),
            page_size in 1usize..5usize,
        ) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let budgets = small_page_budgets(page_size);

            let (token_dir, _token_seed_conn) = make_connector(&files);
            let token_root = token_dir.path().to_path_buf();
            let mut token_cursor = Cursor::initial();
            let mut token_keys: Vec<Vec<u8>> = Vec::new();
            loop {
                let mut conn = FilesystemConnector::new(&token_root).with_tokens(true);
                let page = conn
                    .enumerate_page_range(&start, &end, &token_cursor, budgets)
                    .expect("token cold resume page");
                if page.items().is_empty() {
                    break;
                }
                token_keys.extend(
                    page.items()
                        .iter()
                        .map(|item| item.item_key().as_bytes().to_vec()),
                );
                token_cursor = page.next_cursor().clone();
            }

            let (key_dir, _key_seed_conn) = make_connector(&files);
            let key_root = key_dir.path().to_path_buf();
            let mut key_cursor = Cursor::initial();
            let mut key_only_keys: Vec<Vec<u8>> = Vec::new();
            loop {
                let mut conn = FilesystemConnector::new(&key_root).with_tokens(false);
                let page = conn
                    .enumerate_page_range(&start, &end, &key_cursor, budgets)
                    .expect("key-only cold resume page");
                if page.items().is_empty() {
                    break;
                }
                key_only_keys.extend(
                    page.items()
                        .iter()
                        .map(|item| item.item_key().as_bytes().to_vec()),
                );
                key_cursor = page.next_cursor().clone();
            }

            prop_assert_eq!(token_keys, key_only_keys);
        }

        #[test]
        fn split_point_is_valid_for_property_inputs(files in file_set_strategy(20)) {
            let start = make_key(b"\x00");
            let end = make_key(b"\xff");
            let (_dir, mut c) = make_connector(&files);

            // Enumerate to populate the integrated estimator.
            let all = collect_all(&mut c, &start, &end);
            let split = c
                .choose_split_point_range(&start, &end, &Cursor::initial())
                .expect("split lookup should not error");
            if all.len() < 2 {
                prop_assert!(split.is_none());
            } else {
                let split = split.expect("split should exist with at least two items");
                let keys: Vec<&[u8]> = all.iter().map(|item| item.item_key().as_bytes()).collect();
                let first = keys.first().expect("non-empty keys");
                let last = keys.last().expect("non-empty keys");
                prop_assert!(
                    split.as_bytes() > *first && split.as_bytes() <= *last,
                    "split must leave at least one key on the left and stay in bounds",
                );
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
        fn bounded_walk_matches_unbounded_filtered_property(
            files in file_set_strategy(20),
            raw_start in key_bound_strategy(),
            raw_end in key_bound_strategy(),
        ) {
            // with_key_range accepts arbitrary byte bounds; normalize to a
            // non-inverted half-open interval for the expected-value oracle.
            let (bound_start, bound_end) = if raw_start <= raw_end {
                (raw_start, raw_end)
            } else {
                (raw_end, raw_start)
            };

            let full_start = make_key(b"\x00");
            let full_end = make_key(b"\xff");

            let (_dir_unbounded, mut unbounded) = make_connector(&files);
            let baseline = collect_all(&mut unbounded, &full_start, &full_end);

            let (_dir_bounded, mut bounded) = make_connector(&files);
            bounded = bounded.with_key_range(
                Some(bound_start.as_slice()),
                Some(bound_end.as_slice()),
            );
            let actual = collect_all(&mut bounded, &full_start, &full_end);

            // Oracle: unbounded enumeration filtered by the same half-open
            // interval must match bounded traversal exactly.
            let expected_keys: Vec<Vec<u8>> = baseline
                .iter()
                .map(|item| item.item_key().as_bytes().to_vec())
                .filter(|key| {
                    key.as_slice() >= bound_start.as_slice()
                        && key.as_slice() < bound_end.as_slice()
                })
                .collect();
            let actual_keys: Vec<Vec<u8>> = actual
                .iter()
                .map(|item| item.item_key().as_bytes().to_vec())
                .collect();
            prop_assert_eq!(actual_keys, expected_keys);
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

#[test]
fn walk_stress_wide_directory_tree() {
    // Flat, high-breadth tree: regression guard for walkers that accumulate a
    // whole frontier/sibling queue. The per-directory frame design should keep
    // state bounded to active stack frames plus one buffered directory.
    let dir = tempfile::tempdir().expect("create tempdir");
    let sibling_dirs = 8_192usize;
    for i in 0..sibling_dirs {
        let subdir = dir.path().join(format!("d{i:05}"));
        fs::create_dir(&subdir).unwrap();
        fs::write(subdir.join("f.txt"), b"x").unwrap();
    }

    let mut c = FilesystemConnector::new(dir.path()).with_max_depth(1);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let all = collect_all(&mut c, &start, &end);
    assert_eq!(all.len(), sibling_dirs, "all leaf files should be indexed");
    assert!(
        all.iter()
            .any(|item| item.item_key().as_bytes() == b"d00000/f.txt"),
        "expected first sibling leaf file"
    );
    assert!(
        all.iter()
            .any(|item| item.item_key().as_bytes() == b"d08191/f.txt"),
        "expected last sibling leaf file"
    );
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
// Read membership semantics tests
// ---------------------------------------------------------------

#[test]
fn read_accepts_existing_item_ref_even_if_not_preenumerated() {
    let dir = create_test_dir(&[("a.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Drain initial walk state.
    let _ = collect_all(&mut c, &start, &end);

    // Create a new file after the initial enumeration.
    fs::write(dir.path().join("b.txt"), b"post-index").unwrap();

    // openat-based read membership should accept any confined path that exists.
    let bad_ref = ItemRef::try_from_slice(b"b.txt").unwrap();
    let mut reader = c
        .open(&bad_ref, default_budgets())
        .expect("existing file should be readable even if not pre-enumerated");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"post-index");
}

#[test]
fn read_range_rejects_absent_item_ref() {
    let dir = create_test_dir(&[("a.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let _ = collect_all(&mut c, &start, &end);

    let bad_ref = ItemRef::try_from_slice(b"nonexistent.txt").unwrap();
    let mut buf = [0u8; 32];
    let result = c.read_range(&bad_ref, 0, &mut buf, default_budgets());
    assert!(result.is_err(), "non-existent item_ref should fail");
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
    // prior enumeration — lazy root setup satisfies the ReadConnector
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

    // An ItemRef for a file that does not exist should fail with the
    // underlying openat ENOENT classification.
    let item_ref = ItemRef::try_from_slice(b"no_such_file.txt").unwrap();
    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("absent item_ref should be rejected"),
    };
    assert!(
        err.message().contains("No such file or directory"),
        "error should indicate ENOENT from openat, got: {}",
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

    // First call with an expired deadline fails retryably.
    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), expired);
    assert!(result.is_err());

    // Retryable deadline failures must not latch a permanent connector failure.
    // A subsequent call with a fresh budget should initialize and succeed.
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

    // Now call enumerate with an already-expired deadline. The page-level
    // deadline gate in `enumerate_page_bounds` should still classify this as
    // retryable even after prior successful traversal.
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

// ---------------------------------------------------------------
// Telemetry safety tests (Phase VI)
// ---------------------------------------------------------------

#[test]
fn error_messages_do_not_leak_filenames() {
    // Create a file with a "canary" secret in the filename.
    let canary = "CANARY_SECRET_abc123";
    let dir = create_test_dir(&[(&format!("{canary}.txt"), b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Index successfully, then delete the file to provoke a read error.
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(items.len(), 1);
    let item_ref = items[0].item_ref().clone();

    fs::remove_file(dir.path().join(format!("{canary}.txt"))).unwrap();

    let err = match c.open(&item_ref, default_budgets()) {
        Err(e) => e,
        Ok(_) => panic!("deleted file should fail"),
    };
    assert!(
        !err.message().contains(canary),
        "error message must not contain the raw filename canary; got: {}",
        err.message(),
    );
}

#[test]
fn walk_warnings_do_not_leak_paths() {
    let canary = "SECRET_TOKEN_xyz789";
    let dir = create_test_dir(&[("file.txt", b"data")]);
    std::os::unix::fs::symlink("target", dir.path().join(canary)).unwrap();

    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let _ = collect_all(&mut c, &start, &end);

    // WalkWarning should store a ToxicDigest, not a raw PathBuf.
    for w in c.walk_warnings() {
        let debug_str = format!("{w:?}");
        assert!(
            !debug_str.contains(canary),
            "walk warning Debug output must not contain the raw path canary; got: {debug_str}",
        );
    }
}

#[test]
fn enumerate_error_for_nonexistent_root_does_not_leak_path() {
    let canary = "CANARY_ROOT_PATH_secret42";
    let nonexistent = format!("/tmp/{canary}/does/not/exist");
    let mut c = FilesystemConnector::new(&nonexistent);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let err = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .expect_err("nonexistent root should fail");
    assert!(
        !err.message().contains(canary),
        "enumerate error must not contain the raw root path canary; got: {}",
        err.message(),
    );
}

// ---------------------------------------------------------------
// Intra-directory deadline granularity test
// ---------------------------------------------------------------

#[test]
fn intra_directory_deadline_check_triggers_within_large_directory() {
    // Single-directory fixture with enough entries to exercise the 512-entry
    // deadline cadence while polling one frame (no fd-cap spill path needed).
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_count = 2048usize;
    for i in 0..file_count {
        fs::write(dir.path().join(format!("f{i:05}.txt")), b"x").unwrap();
    }

    // Keep the deadline live at walk start, but short enough to expire while
    // draining one large frame. This confirms we do not defer budget checks
    // until "directory complete" when per-directory buffering is large.
    let tight_deadline = Budgets::try_new(
        file_count + 1,
        u64::MAX,
        Some(Instant::now() + Duration::from_nanos(1)),
    )
    .unwrap();
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), tight_deadline);
    // The walk should fail with a retryable deadline error regardless of which
    // checkpoint (per-directory vs 512-entry cadence) trips first.
    assert!(
        result.is_err(),
        "tight deadline should abort during a large directory walk"
    );
    assert!(
        result.unwrap_err().is_retryable(),
        "deadline error should be retryable"
    );
}

// ---------------------------------------------------------------
// Root identity verification test
// ---------------------------------------------------------------

#[test]
fn root_fd_identity_check_passes_for_stable_directory() {
    // Verify that fd_dev_ino + verify_root_identity succeed for a
    // normal temporary directory (no races, no swaps).
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Indexing triggers canonicalize + open_dir_fd + verify_root_identity.
    // If verify_root_identity fails, enumerate would return an error.
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .expect("indexing should succeed on a stable directory");
    assert_eq!(page.items().len(), 1);
}

#[test]
fn root_fd_identity_check_rejects_dev_ino_mismatch() {
    // Open an fd to directory A, then verify against the path of a
    // *different* directory B.  The dev/ino values will differ, so
    // verify_root_identity must return an error.
    let dir_a = tempfile::tempdir().expect("create dir_a");
    let dir_b = tempfile::tempdir().expect("create dir_b");

    let fd_a = open_dir_fd(dir_a.path()).expect("open dir_a fd");

    // Capture dir_b's identity and verify against dir_a's fd.
    let b_meta = fs::metadata(dir_b.path()).expect("stat dir_b");
    let b_id = (b_meta.dev(), b_meta.ino());
    let err = verify_root_identity(&fd_a, b_id)
        .expect_err("verify_root_identity should reject a mismatched path");

    assert_eq!(err.kind(), std::io::ErrorKind::Other);
    assert!(
        err.to_string().contains("dev/ino mismatch"),
        "error should mention dev/ino mismatch; got: {err}",
    );
}

// ---------------------------------------------------------------
// Bug verification: exhausted walk with no files should not
// prevent a second range from producing results
// ---------------------------------------------------------------

#[test]
fn exhausted_empty_range_does_not_block_subsequent_populated_range() {
    // Files exist only in the [a, d) range.
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2"), ("c.txt", b"3")]);
    let mut c = FilesystemConnector::new(dir.path());

    // First call: range [z, ~) — no files match, walk exhausts.
    let empty_start = make_key(b"z");
    let empty_end = make_key(b"\xff");
    let page = c
        .enumerate_page_range(
            &empty_start,
            &empty_end,
            &Cursor::initial(),
            default_budgets(),
        )
        .expect("empty range should not error");
    assert!(page.items().is_empty(), "no files match [z, 0xff) range");

    // Second call: range [\x00, \xff) — files exist, should be returned.
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let items = collect_all(&mut c, &start, &end);
    assert_eq!(
        items.len(),
        3,
        "second range should find all 3 files; got {}",
        items.len()
    );
    assert_eq!(items[0].item_key().as_bytes(), b"a.txt");
    assert_eq!(items[1].item_key().as_bytes(), b"b.txt");
    assert_eq!(items[2].item_key().as_bytes(), b"c.txt");
}

// ---------------------------------------------------------------
// Bug verification: current_path must be clean after deadline
// error during directory descent
// ---------------------------------------------------------------

#[test]
fn deadline_during_directory_descent_does_not_corrupt_subsequent_walk() {
    // Create a deep directory structure: root/deep/nested/file.txt
    // plus a root-level file that sorts after the directory.
    let dir = create_test_dir(&[("deep/nested/file.txt", b"inner"), ("z_root.txt", b"root")]);
    let mut c = FilesystemConnector::new(dir.path());
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Use a very tight deadline that may expire during directory descent.
    // Even if the deadline doesn't trigger during next_file's directory
    // processing, the retry must still produce correct results.
    let tight_deadline = Budgets::try_new(
        100,
        u64::MAX,
        Some(Instant::now() + Duration::from_nanos(1)),
    )
    .unwrap();

    // First attempt: may succeed or fail with retryable error.
    let _result = c.enumerate_page_range(&start, &end, &Cursor::initial(), tight_deadline);
    // We don't care whether this succeeds or fails — only that a retry works.

    // Retry with a generous deadline: must produce correct, uncorrupted keys.
    let items = collect_all(&mut c, &start, &end);
    let keys: Vec<&[u8]> = items.iter().map(|i| i.item_key().as_bytes()).collect();
    assert_eq!(
        keys,
        vec![b"deep/nested/file.txt".as_slice(), b"z_root.txt"],
        "retry after deadline error must produce correct paths, not corrupted ones"
    );
}

// ---------------------------------------------------------------
// Walk-token corruption and debug cross-check behavior
// ---------------------------------------------------------------

#[test]
fn corrupted_token_version_falls_back_to_key_only_resume() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let budgets = small_page_budgets(2);

    let mut first = FilesystemConnector::new(dir.path()).with_tokens(true);
    let page1 = first
        .enumerate_page_range(&start, &end, &Cursor::initial(), budgets)
        .expect("first page");
    let last_key = page1
        .next_cursor()
        .last_key()
        .expect("first page must carry last_key")
        .clone();
    let mut corrupted = page1
        .next_cursor()
        .token()
        .expect("token must be emitted")
        .as_bytes()
        .to_vec();
    corrupted[0] ^= 0x7f; // force version mismatch for decode failure.
    let corrupted_cursor = Cursor::with_token(
        last_key.clone(),
        TokenBytes::try_from_vec(corrupted).expect("corrupted token bytes still valid wrapper"),
    );

    let mut resumed_with_corrupt = FilesystemConnector::new(dir.path()).with_tokens(true);
    let corrupt_page = resumed_with_corrupt
        .enumerate_page_range(&start, &end, &corrupted_cursor, budgets)
        .expect("corrupt token should fall back to key-only resume");

    let key_only_cursor = Cursor::with_last_key(last_key);
    let mut key_only = FilesystemConnector::new(dir.path()).with_tokens(false);
    let key_page = key_only
        .enumerate_page_range(&start, &end, &key_only_cursor, budgets)
        .expect("key-only resume page");

    let corrupt_keys: Vec<&[u8]> = corrupt_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    let key_keys: Vec<&[u8]> = key_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(corrupt_keys, key_keys);
}

/// A forged token with a shifted `next_child_index` is detected by the
/// A shifted token positions the walker past some entries. Without a
/// cross-check probe, the token is trusted and resume proceeds from the
/// shifted position. Key-based seek ensures we never emit keys <= last_key,
/// but entries between last_key and the shifted position may be skipped.
#[test]
fn shifted_token_resumes_from_token_position() {
    let dir = create_test_dir(&[
        ("a.txt", b"1"),
        ("b.txt", b"2"),
        ("c.txt", b"3"),
        ("d.txt", b"4"),
    ]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");
    let budgets = small_page_budgets(2);

    let mut first = FilesystemConnector::new(dir.path()).with_tokens(true);
    let page1 = first
        .enumerate_page_range(&start, &end, &Cursor::initial(), budgets)
        .expect("first page");
    let last_key = page1
        .next_cursor()
        .last_key()
        .expect("first page must carry last_key")
        .clone();

    // Valid v1 token with one root frame, but intentionally shifted root index
    // past the remaining children so the token-based walker skips c.txt.
    let mut forged = Vec::new();
    forged.push(WALK_TOKEN_VERSION);
    forged.extend_from_slice(&1u16.to_le_bytes());
    forged.extend_from_slice(&0u16.to_le_bytes());
    forged.extend_from_slice(&3u32.to_le_bytes());
    let forged_cursor = Cursor::with_token(
        last_key,
        TokenBytes::try_from_vec(forged).expect("forged token wrapper"),
    );

    let mut resumed = FilesystemConnector::new(dir.path()).with_tokens(true);
    let page2 = resumed
        .enumerate_page_range(&start, &end, &forged_cursor, budgets)
        .expect("resumed page after forged token");

    // Token is trusted: resume from the shifted position yields only d.txt.
    let keys: Vec<&[u8]> = page2
        .items()
        .iter()
        .map(|i| i.item_key().as_bytes())
        .collect();
    assert_eq!(
        keys,
        vec![b"d.txt".as_slice()],
        "shifted token resumes from token position; got {keys:?}"
    );
}

// ---------------------------------------------------------------
// Unit tests — prefix_successor
// ---------------------------------------------------------------

#[rstest]
#[case::empty_returns_none(b"", None)]
#[case::single_byte(b"a", Some(b"b".as_slice()))]
#[case::single_byte_max(b"\xff", None)]
#[case::trailing_ff(b"abc\xff", None)]
#[case::internal_ff_followed_by_normal(b"a\xff\x00", Some(b"a\xff\x01".as_slice()))]
#[case::multi_byte_normal(b"src/lib", Some(b"src/lic".as_slice()))]
#[case::slash_increments(b"src/", Some(b"src0".as_slice()))]
fn prefix_successor_produces_expected_output(
    #[case] input: &[u8],
    #[case] expected: Option<&[u8]>,
) {
    let result = prefix_successor(input);
    assert_eq!(
        result.as_ref().map(|v| v.as_slice()),
        expected,
        "prefix_successor({input:?})"
    );
}

// ---------------------------------------------------------------
// Unit tests — empty / inverted key ranges
// ---------------------------------------------------------------

#[test]
fn with_shard_bounds_filters_to_half_open_range() {
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("middle.txt", b"m"),
        ("zulu.txt", b"z"),
    ]);
    let mut c = FilesystemConnector::new(dir.path()).with_shard_bounds(b"middle", b"z");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let keys: Vec<Vec<u8>> = collect_all(&mut c, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();
    assert_eq!(keys, vec![b"middle.txt".to_vec()]);
}

#[test]
fn with_shard_bounds_empty_bounds_keep_full_keyspace() {
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("middle.txt", b"m"),
        ("zulu.txt", b"z"),
    ]);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let mut baseline = FilesystemConnector::new(dir.path());
    let all_keys: Vec<Vec<u8>> = collect_all(&mut baseline, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();

    let mut shard_unbounded = FilesystemConnector::new(dir.path()).with_shard_bounds(b"", b"");
    let unbounded_keys: Vec<Vec<u8>> = collect_all(&mut shard_unbounded, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();

    assert_eq!(unbounded_keys, all_keys);
}

#[test]
fn shard_bounds_intersect_with_connector_bounds_via_enumerate_page() {
    // Connector-level bounds [g, t) and shard bounds [d, n) should intersect
    // to the tighter [g, n), so only keys in that interval are returned.
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("golf.txt", b"g"),
        ("kilo.txt", b"k"),
        ("november.txt", b"n"),
        ("sierra.txt", b"s"),
        ("zulu.txt", b"z"),
    ]);

    let mut c = FilesystemConnector::new(dir.path()).with_shard_bounds(b"g", b"t");
    let shard = ShardSpec::try_with_range(b"d", b"n").unwrap();

    let items = collect_all_via_shard(&mut c, &shard, default_budgets());
    let keys: Vec<&[u8]> = items.iter().map(|i| i.item_key().as_bytes()).collect();

    assert_eq!(
        keys,
        vec![b"golf.txt".as_slice(), b"kilo.txt".as_slice()],
        "intersection of connector [g,t) and shard [d,n) should yield [g,n)"
    );
}

#[test]
fn with_shard_bounds_start_only_filters_lower_bound() {
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("middle.txt", b"m"),
        ("zulu.txt", b"z"),
    ]);
    // start="middle", end="" (unbounded) → keys >= "middle".
    let mut c = FilesystemConnector::new(dir.path()).with_shard_bounds(b"middle", b"");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let keys: Vec<Vec<u8>> = collect_all(&mut c, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![b"middle.txt".to_vec(), b"zulu.txt".to_vec()],
        "start-only bound should filter out keys below 'middle'"
    );
}

#[test]
fn with_shard_bounds_end_only_filters_upper_bound() {
    let dir = create_test_dir(&[
        ("alpha.txt", b"a"),
        ("middle.txt", b"m"),
        ("zulu.txt", b"z"),
    ]);
    // start="" (unbounded), end="middle" → keys < "middle".
    let mut c = FilesystemConnector::new(dir.path()).with_shard_bounds(b"", b"middle");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let keys: Vec<Vec<u8>> = collect_all(&mut c, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![b"alpha.txt".to_vec()],
        "end-only bound should filter out keys at or above 'middle'"
    );
}

#[test]
fn with_shard_bounds_end_boundary_is_exclusive() {
    let dir = create_test_dir(&[
        ("a.txt", b"a"),
        ("middle", b"m"),
        ("middle.txt", b"m2"),
        ("y.txt", b"y"),
        ("z", b"z1"),
        ("z.txt", b"z2"),
    ]);
    // Shard range [middle, z) — file "z" sits exactly at the end bound and must be excluded.
    let mut c = FilesystemConnector::new(dir.path()).with_shard_bounds(b"middle", b"z");
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let keys: Vec<Vec<u8>> = collect_all(&mut c, &start, &end)
        .into_iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect();
    assert_eq!(
        keys,
        vec![
            b"middle".to_vec(),
            b"middle.txt".to_vec(),
            b"y.txt".to_vec(),
        ],
        "end bound must be exclusive — file exactly at end should be excluded"
    );
}

#[test]
fn with_key_range_equal_bounds_returns_empty() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("m.txt", b"m"), ("z.txt", b"z")]);
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"m"), Some(b"m"));
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert!(items.is_empty(), "equal start/end should yield zero items");
}

#[test]
fn with_key_range_inverted_bounds_returns_empty() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("m.txt", b"m"), ("z.txt", b"z")]);
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"z"), Some(b"a"));
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let items = collect_all(&mut c, &start, &end);
    assert!(
        items.is_empty(),
        "inverted bounds (start > end) should yield zero items"
    );
}

#[test]
fn with_key_range_disjoint_intersection_returns_empty() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("m.txt", b"m"), ("z.txt", b"z")]);
    // Config range [a, b) and request range [y, z) are disjoint.
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"a"), Some(b"b"));
    let request_start = make_key(b"y");
    let request_end = make_key(b"z");

    let items = collect_all(&mut c, &request_start, &request_end);
    assert!(
        items.is_empty(),
        "disjoint config and request ranges should yield zero items"
    );
}

// ---------------------------------------------------------------
// Unit tests — cursor resume across pruned subtrees
// ---------------------------------------------------------------

#[test]
fn with_key_range_cursor_resume_across_pruned_subtrees() {
    let dir = create_test_dir(&[
        ("aaa/file1.txt", b"1"),
        ("aaa/file2.txt", b"2"),
        ("mmm/file3.txt", b"3"),
        ("mmm/file4.txt", b"4"),
        ("zzz/file5.txt", b"5"),
        ("zzz/file6.txt", b"6"),
    ]);
    // Only [mmm, zzz) is in range — aaa/ and zzz/ should be pruned.
    let mut c = FilesystemConnector::new(dir.path()).with_key_range(Some(b"mmm"), Some(b"zzz"));
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Page with max_items=1 to force cursor resume between items.
    let budgets_1 = small_page_budgets(1);
    let mut all_keys: Vec<Vec<u8>> = Vec::new();
    let mut cursor = Cursor::initial();

    for _ in 0..10 {
        let page = c
            .enumerate_page_range(&start, &end, &cursor, budgets_1)
            .expect("enumerate page");
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            all_keys.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    assert_eq!(
        all_keys,
        vec![b"mmm/file3.txt".to_vec(), b"mmm/file4.txt".to_vec(),],
        "only files in [mmm, zzz) should be returned across cursor resumes"
    );

    // Keys must be in sorted order.
    for window in all_keys.windows(2) {
        assert!(
            window[0] < window[1],
            "keys must be globally sorted: {:?} < {:?}",
            window[0],
            window[1]
        );
    }
}

#[test]
fn walk_token_decode_rejects_dot_and_dotdot_components() {
    // A forged token with ".." as a non-root component should be rejected
    // during decode to prevent path traversal outside the configured root.
    for component in &[b".." as &[u8], b"." as &[u8]] {
        let mut payload = Vec::new();
        payload.push(WALK_TOKEN_VERSION);
        // Two frames: root + one child.
        payload.extend_from_slice(&2u16.to_le_bytes());
        // Root frame: empty component, next_child_index = 0.
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        // Child frame: ".." or "." component, next_child_index = 0.
        payload.extend_from_slice(&(component.len() as u16).to_le_bytes());
        payload.extend_from_slice(component);
        payload.extend_from_slice(&0u32.to_le_bytes());

        assert!(
            WalkToken::decode_bytes(&payload).is_none(),
            "decode_bytes should reject component {:?}",
            std::str::from_utf8(component).unwrap()
        );
    }
}

/// A stale/corrupted token with a shifted `next_child_index` at root can
/// cause token-based resume to skip directory subtrees that contain keys
/// A forged token with an advanced `next_child_index` causes the walker to
/// skip directories. Without a cross-check probe, the token is trusted and
/// some keys may be skipped. Key-based seek ensures we never regress behind
/// `last_key`, but entries between `last_key` and the shifted position are
/// lost.
#[test]
fn stale_token_resumes_from_token_position() {
    // Directory layout (sorted):
    //   a/file.txt   -> key "a/file.txt"
    //   b/file.txt   -> key "b/file.txt"
    //   c/file.txt   -> key "c/file.txt"
    //
    // Page 1 (size=1) emits "a/file.txt".
    // We forge a token that positions at child index 2 (directory "c"),
    // skipping "b/" entirely.
    let dir = create_test_dir(&[
        ("a/file.txt", b"a"),
        ("b/file.txt", b"b"),
        ("c/file.txt", b"c"),
    ]);

    let mut c = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    let page1 = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(1))
        .expect("first page");
    let first_key = page1.items()[0].item_key().clone();
    assert_eq!(first_key.as_bytes(), b"a/file.txt");

    let real_token = page1.next_cursor().token().expect("cursor must have token");
    let mut decoded = WalkToken::decode_bytes(real_token.as_bytes()).expect("decode real token");
    decoded.frames[0].next_child_index += 1;

    let mut forged_bytes = Vec::new();
    forged_bytes.push(WALK_TOKEN_VERSION);
    forged_bytes.extend_from_slice(&(decoded.frames.len() as u16).to_le_bytes());
    for frame in &decoded.frames {
        forged_bytes.extend_from_slice(&(frame.component.len() as u16).to_le_bytes());
        forged_bytes.extend_from_slice(&frame.component);
        forged_bytes.extend_from_slice(&frame.next_child_index.to_le_bytes());
    }
    let forged_token = TokenBytes::try_from_vec(forged_bytes).expect("forge token");
    let forged_cursor = Cursor::with_token(first_key, forged_token);

    let mut c2 = FilesystemConnector::new(dir.path()).with_tokens(true);
    let mut remaining = Vec::new();
    let mut cursor = forged_cursor;
    loop {
        let page = c2
            .enumerate_page_range(&start, &end, &cursor, small_page_budgets(10))
            .expect("page");
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            remaining.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    // Token is trusted: "b/file.txt" is skipped, only "c/file.txt" remains.
    let expected: Vec<&[u8]> = vec![b"c/file.txt"];
    let actual: Vec<&[u8]> = remaining.iter().map(|v: &Vec<u8>| v.as_slice()).collect();
    assert_eq!(
        actual, expected,
        "stale token resumes from token position; got {actual:?}, expected {expected:?}"
    );
}

/// A crafted token where a non-leaf frame has `next_child_index` equal to the
/// directory entry count drains the parent's deque to empty. Siblings that
/// appear after the child subtree in DFS order would be lost.
/// `fast_forward_frame_entries` should reject this for non-leaf frames.
#[test]
fn exhausted_non_leaf_frame_in_token_does_not_skip_siblings() {
    // Layout:
    //   root/
    //     a_file.txt        -> key "a_file.txt"
    //     subdir/
    //       inner.txt       -> key "subdir/inner.txt"
    //     z_file.txt        -> key "z_file.txt"
    //
    // DFS order: a_file.txt, subdir/inner.txt, z_file.txt
    //
    // A crafted token that descends into subdir/ but drains root entries so
    // next_child_index at root == total root entries would lose z_file.txt.
    let dir = create_test_dir(&[
        ("a_file.txt", b"a"),
        ("subdir/inner.txt", b"i"),
        ("z_file.txt", b"z"),
    ]);

    let mut c1 = FilesystemConnector::new(dir.path()).with_tokens(true);
    let start = make_key(b"\x00");
    let end = make_key(b"\xff");

    // Get page 1 (1 item) to emit a_file.txt.
    let page1 = c1
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(1))
        .expect("first page");
    assert_eq!(page1.items()[0].item_key().as_bytes(), b"a_file.txt");
    let last_key = page1
        .next_cursor()
        .last_key()
        .expect("must have last key")
        .clone();

    // Count root directory entries for our forge.
    let root_entry_count = std::fs::read_dir(dir.path()).expect("read root").count() as u32;

    // Forge a token with 2 frames:
    //   - Root frame: next_child_index = root_entry_count (drain all root entries)
    //   - Child frame: component = "subdir", next_child_index = 0
    let mut forged = Vec::new();
    forged.push(WALK_TOKEN_VERSION);
    forged.extend_from_slice(&2u16.to_le_bytes());
    // Root frame.
    forged.extend_from_slice(&0u16.to_le_bytes()); // empty component
    forged.extend_from_slice(&root_entry_count.to_le_bytes());
    // Child frame: "subdir".
    let comp = b"subdir";
    forged.extend_from_slice(&(comp.len() as u16).to_le_bytes());
    forged.extend_from_slice(comp);
    forged.extend_from_slice(&0u32.to_le_bytes());

    let forged_token = TokenBytes::try_from_vec(forged).expect("forge token");
    let forged_cursor = Cursor::with_token(last_key, forged_token);

    // Collect remaining items.
    let mut c2 = FilesystemConnector::new(dir.path()).with_tokens(true);
    let mut remaining = Vec::new();
    let mut cursor = forged_cursor;
    loop {
        let page = c2
            .enumerate_page_range(&start, &end, &cursor, small_page_budgets(10))
            .expect("page");
        if page.items().is_empty() {
            break;
        }
        for item in page.items() {
            remaining.push(item.item_key().as_bytes().to_vec());
        }
        cursor = page.next_cursor().clone();
    }

    // Must see both "subdir/inner.txt" and "z_file.txt".
    let actual: Vec<&[u8]> = remaining.iter().map(|v: &Vec<u8>| v.as_slice()).collect();
    assert!(
        actual.contains(&b"z_file.txt".as_slice()),
        "exhausted non-leaf frame must not lose sibling z_file.txt; got {actual:?}"
    );
    assert!(
        actual.contains(&b"subdir/inner.txt".as_slice()),
        "subdir/inner.txt should still be reachable; got {actual:?}"
    );
}
