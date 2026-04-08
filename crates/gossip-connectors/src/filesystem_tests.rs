//! Purpose: Provides regression coverage for the filesystem connector's ordered-content contract.
//!
//! Invariants:
//! - Enumeration must remain lexicographically ordered.
//! - Resume must honor `last_key` even when persisted tokens are stale.
//! - Stable IDs must be rooted in the canonical connector instance.
//! - Path handling must not allow callers to escape the configured root.
//!
//! Algorithm Overview:
//! Tests exercise the `FilesystemConnector` directly and via the `OrderedContentSource`
//! conformance harness. Fixtures mix directory roots and single-file roots to validate
//! path and identity checks under both operating modes.
//!
//! Design Trade-offs:
//! Test helpers require explicit budget parameters instead of using defaults to ensure
//! pagination, byte limits, and deadline handling remain visible at the call site.

use std::{
    io::{self, Read as _},
    os::unix::ffi::OsStrExt,
    path::Path,
    time::{Duration, Instant},
};

use gossip_contracts::{
    connector::{
        Budgets, Cursor, FILESYSTEM_CONNECTOR_TAG, ItemRef, PageBuf, PageState, ScanItem,
        TokenBytes, VersionId, conformance::run_ordered_content_conformance,
        ordered::OrderedContentSource,
    },
    identity::{ConnectorInstanceIdHash, ItemIdentityKey, ObjectVersionId},
};
use proptest::prelude::*;
use rstest::rstest;

use super::*;
use crate::common::test_util::make_key;

/// Intent: Provide a temporary directory with a known file layout.
///
/// Invariants:
/// - Parent directories for nested files are implicitly created.
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

/// Intent: Provide a full-range shard for tests not exercising bounds.
fn unbounded_shard() -> ShardSpec {
    ShardSpec::unbounded()
}

/// Intent: Execute `fill_page` with explicit limits, unwrapping the page.
///
/// Invariants:
/// - Requires all budget parameters to be specified explicitly so limits remain visible at the test call site.
fn fill_page_with_limits(
    connector: &mut FilesystemConnector,
    shard: &ShardSpec,
    cursor: &Cursor,
    max_items: usize,
    max_bytes: u64,
) -> PageBuf<ScanItem> {
    connector
        .fill_page(
            shard,
            cursor,
            Budgets::try_new(max_items, max_bytes, None).expect("valid budgets"),
        )
        .expect("fill_page should succeed")
        .expect("page should be present")
}

/// Intent: Recompute the stable ID a filesystem item should advertise.
///
/// Invariants:
/// - The instance hash is derived from the canonicalized root path, guaranteeing equivalent roots resolve to the same identity.
fn expected_stable_item_id(
    root: &Path,
    rel_path: &[u8],
) -> gossip_contracts::identity::StableItemId {
    let canonical_root = fs::canonicalize(root).expect("canonical root");
    let connector_instance =
        ConnectorInstanceIdHash::from_instance_id_bytes(canonical_root.as_os_str().as_bytes());
    ItemIdentityKey::new(FILESYSTEM_CONNECTOR_TAG, connector_instance, rel_path).stable_id()
}

/// Intent: Extract ordered item keys from a conformance run for direct assertions.
fn drain_keys(run: &gossip_contracts::connector::conformance::OrderedContentDrain) -> Vec<Vec<u8>> {
    run.items()
        .iter()
        .map(|item| item.item_key().as_bytes().to_vec())
        .collect()
}

// ---------------------------------------------------------------
// Ordered-content conformance harness
// ---------------------------------------------------------------

/// Confirms the ordered-content conformance harness accepts an empty filesystem root and produces no pages.
#[test]
fn ordered_content_conformance_accepts_empty_filesystem_root() {
    let dir = create_test_dir(&[]);

    let run = run_ordered_content_conformance(
        || FilesystemConnector::new(dir.path()),
        &unbounded_shard(),
        2,
        u64::MAX,
        &[],
    )
    .expect("empty filesystem root should satisfy ordered-content conformance");

    assert!(run.is_empty());
    assert!(run.page_lengths().is_empty());
}

/// Ensures a bounded filesystem fixture anchored by a root canary yields the expected keys and page lengths.
#[test]
fn ordered_content_conformance_accepts_bounded_fixture_and_root_canary() {
    let base = tempfile::tempdir().expect("create base tempdir");
    let root = base.path().join("FS_ROOT_CANARY");
    fs::create_dir(&root).expect("create root dir");
    fs::write(root.join("a.txt"), b"a").expect("write a");
    fs::write(root.join("b.txt"), b"b").expect("write b");
    fs::create_dir(root.join("c")).expect("create nested dir");
    fs::write(root.join("c").join("nested.txt"), b"c").expect("write c");
    fs::write(root.join("d.txt"), b"d").expect("write d");

    let shard = ShardSpec::try_with_range(b"b", b"d").expect("valid shard");
    let run = run_ordered_content_conformance(
        || FilesystemConnector::new(&root),
        &shard,
        2,
        u64::MAX,
        &[b"FS_ROOT_CANARY".as_slice()],
    )
    .expect("bounded filesystem fixture should satisfy ordered-content conformance");

    assert_eq!(
        drain_keys(&run),
        vec![b"b.txt".to_vec(), b"c/nested.txt".to_vec()]
    );
    assert_eq!(run.page_lengths(), &[2]);
}

/// Validates the conformance harness honors the intersection between the connector key range and the shard.
#[test]
fn ordered_content_conformance_accepts_connector_range_intersection() {
    let dir = create_test_dir(&[
        ("a.txt", b"a"),
        ("b.txt", b"b"),
        ("c.txt", b"c"),
        ("d.txt", b"d"),
        ("e.txt", b"e"),
    ]);
    let shard = ShardSpec::try_with_range(b"a", b"e").expect("valid shard");

    let run = run_ordered_content_conformance(
        || FilesystemConnector::new(dir.path()).with_key_range(Some(b"b"), Some(b"d")),
        &shard,
        2,
        u64::MAX,
        &[],
    )
    .expect("effective range intersection should satisfy conformance");

    assert_eq!(drain_keys(&run), vec![b"b.txt".to_vec(), b"c.txt".to_vec()]);
    assert_eq!(run.page_lengths(), &[2]);
}

proptest! {
    #![proptest_config(gossip_contracts::test_util::miri_proptest_config())]

    /// Property test: random files should be enumerated in sorted order while respecting the configured page size.
    #[test]
    fn ordered_content_conformance_matches_sorted_random_files(
        ids in proptest::collection::btree_set(0u16..60000, 1..16)
    ) {
        let dir = tempfile::tempdir().expect("create tempdir");
        let mut expected = Vec::new();

        for (index, id) in ids.iter().copied().enumerate() {
            let rel = if index % 2 == 0 {
                format!("{id:04x}.txt")
            } else {
                format!("nested/{id:04x}.txt")
            };
            let path = dir.path().join(&rel);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("create parent dirs");
            }
            fs::write(&path, format!("payload-{id:04x}").as_bytes()).expect("write fixture file");
            expected.push(rel.into_bytes());
        }
        expected.sort();

        let root_bytes = dir.path().as_os_str().as_bytes();
        let run = run_ordered_content_conformance(
            || FilesystemConnector::new(dir.path()),
            &unbounded_shard(),
            3,
            u64::MAX,
            &[root_bytes],
        )
        .expect("random filesystem fixture should satisfy ordered-content conformance");

        prop_assert_eq!(drain_keys(&run), expected);
        prop_assert_eq!(run.page_lengths().iter().sum::<usize>(), ids.len());
        prop_assert!(run.page_lengths().iter().all(|len| *len > 0 && *len <= 3));
    }
}

// ---------------------------------------------------------------
// Trait surface / capabilities
// ---------------------------------------------------------------

/// Compile-time assertion that `FilesystemConnector` implements `OrderedContentSource`.
#[test]
fn filesystem_connector_implements_ordered_content_source() {
    fn assert_ordered_source<T: OrderedContentSource>() {}
    assert_ordered_source::<FilesystemConnector>();
}

/// Verifies the connector capabilities match the ordered-content contract expectations.
#[test]
fn caps_reflect_ordered_content_contract() {
    let dir = create_test_dir(&[]);
    let connector = FilesystemConnector::new(dir.path());

    assert!(connector.caps().seek_by_key);
    assert!(connector.caps().range_read);
    assert!(!connector.caps().token_resume);
    assert!(!connector.caps().split_hints);

    let ordered_caps = OrderedContentSource::capabilities(&connector);
    assert!(ordered_caps.range_read);
    assert!(!ordered_caps.token_resume);
    assert!(!ordered_caps.split_hints);
}

// ---------------------------------------------------------------
// Page fill / ordering / identity
// ---------------------------------------------------------------

/// Exercises pagination to confirm `fill_page` returns lexicographically sorted items and a resume cursor that includes the last key.
#[test]
fn fill_page_returns_sorted_items_and_resume_cursor() {
    let dir = create_test_dir(&[
        ("src.rs", b"mod src;"),
        ("src/lib.rs", b"pub fn lib() {}"),
        ("src/main.rs", b"fn main() {}"),
        ("z.rs", b"pub const Z: u8 = 1;"),
    ]);
    let mut connector = FilesystemConnector::new(dir.path());
    let shard = unbounded_shard();

    let first_page = fill_page_with_limits(&mut connector, &shard, &Cursor::initial(), 2, u64::MAX);
    let first_keys: Vec<&[u8]> = first_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(
        first_keys,
        vec![b"src.rs".as_slice(), b"src/lib.rs".as_slice()]
    );

    let resume_cursor = match first_page.state() {
        PageState::HasMore { cursor } => cursor.clone(),
        PageState::Complete => panic!("first page should be resumable"),
    };
    assert_eq!(
        resume_cursor
            .last_key()
            .expect("resume cursor should include last_key")
            .as_bytes(),
        b"src/lib.rs"
    );

    let second_page = fill_page_with_limits(&mut connector, &shard, &resume_cursor, 8, u64::MAX);
    let second_keys: Vec<&[u8]> = second_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(
        second_keys,
        vec![b"src/main.rs".as_slice(), b"z.rs".as_slice()]
    );
    assert!(matches!(second_page.state(), PageState::Complete));

    let exhausted = connector
        .fill_page(
            &shard,
            &Cursor::with_last_key(make_key(b"z.rs")),
            crate::common::test_util::default_budgets(),
        )
        .expect("post-complete fill_page should succeed");
    assert!(exhausted.is_none(), "exhausted suffix should return None");
}

/// Across token states, resuming the same connector must rely only on `last_key` and ignore connector tokens.
#[rstest]
#[case::without_token(Cursor::with_last_key(make_key(b"b.txt")))]
#[case::arbitrary_token(Cursor::with_token(
    make_key(b"b.txt"),
    TokenBytes::try_from_slice(b"ignored-token").expect("valid token"),
))]
#[case::stale_token(Cursor::with_token(
    make_key(b"b.txt"),
    TokenBytes::try_from_slice(b"stale-next-index=999").expect("valid token"),
))]
#[case::garbage_token(Cursor::with_token(
    make_key(b"b.txt"),
    TokenBytes::try_from_slice(b"\x00\xffstill-ignored").expect("valid token"),
))]
fn fill_page_resumes_from_last_key_for_same_connector(#[case] resume_cursor: Cursor) {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let shard = unbounded_shard();

    let first_page = fill_page_with_limits(&mut connector, &shard, &Cursor::initial(), 2, u64::MAX);
    assert!(matches!(first_page.state(), PageState::HasMore { .. }));
    assert_eq!(
        first_page.items()[1].item_key().as_bytes(),
        b"b.txt",
        "test setup assumes the first page ends at b.txt"
    );

    fs::write(dir.path().join("aa.txt"), b"aa").expect("insert key before last_key");
    fs::write(dir.path().join("d.txt"), b"d").expect("insert key after last_key");

    let resumed_page = fill_page_with_limits(&mut connector, &shard, &resume_cursor, 8, u64::MAX);
    let resumed_keys: Vec<&[u8]> = resumed_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(
        resumed_keys,
        vec![b"c.txt".as_slice(), b"d.txt".as_slice()],
        "resume must honor only last_key and ignore connector tokens"
    );
    assert!(matches!(resumed_page.state(), PageState::Complete));
}

/// A fresh connector instance should resume from the persisted `last_key` even when provided tokens are stale.
#[test]
fn fresh_connector_resume_restarts_from_last_key_on_live_view() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let shard = unbounded_shard();

    let persisted_cursor = {
        let mut first_connector = FilesystemConnector::new(dir.path());
        let first_page = fill_page_with_limits(
            &mut first_connector,
            &shard,
            &Cursor::initial(),
            2,
            u64::MAX,
        );
        let last_key = first_page
            .items()
            .last()
            .expect("page should be non-empty")
            .item_key()
            .clone();
        Cursor::with_token(
            last_key,
            TokenBytes::try_from_slice(b"persisted-but-ignored").expect("valid token"),
        )
    };

    fs::write(dir.path().join("aa.txt"), b"aa").expect("insert key before persisted cursor");
    fs::write(dir.path().join("d.txt"), b"d").expect("insert key after persisted cursor");

    let mut resumed_connector = FilesystemConnector::new(dir.path());
    let resumed_page = fill_page_with_limits(
        &mut resumed_connector,
        &shard,
        &persisted_cursor,
        8,
        u64::MAX,
    );
    let resumed_keys: Vec<&[u8]> = resumed_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(
        resumed_keys,
        vec![b"c.txt".as_slice(), b"d.txt".as_slice()],
        "fresh connectors must resume from last_key even when persisted tokens are stale"
    );
    assert!(matches!(resumed_page.state(), PageState::Complete));
}

/// Ensures shard boundaries constrain enumeration to the given range.
#[test]
fn fill_page_respects_shard_bounds() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let shard = ShardSpec::try_with_range(b"b", b"c").expect("valid shard");

    let page = fill_page_with_limits(&mut connector, &shard, &Cursor::initial(), 8, u64::MAX);
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"b.txt");
    assert!(matches!(page.state(), PageState::Complete));
}

/// Confirms an item exactly matching the shard start bound is included.
#[test]
fn fill_page_includes_item_matching_exact_shard_start() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let shard = ShardSpec::try_with_range(b"b.txt", b"c.txt").expect("valid shard");

    let page = fill_page_with_limits(&mut connector, &shard, &Cursor::initial(), 8, u64::MAX);
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"b.txt");
    assert!(matches!(page.state(), PageState::Complete));
}

/// Connector-level key ranges should filter enumeration regardless of the shard.
#[test]
fn fill_page_respects_connector_key_range() {
    let dir = create_test_dir(&[
        ("a.txt", b"a"),
        ("b.txt", b"b"),
        ("c.txt", b"c"),
        ("d.txt", b"d"),
    ]);
    let mut connector = FilesystemConnector::new(dir.path()).with_key_range(Some(b"b"), Some(b"d"));

    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    );
    let keys: Vec<&[u8]> = page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"b.txt".as_slice(), b"c.txt".as_slice()]);
    assert!(matches!(page.state(), PageState::Complete));
}

/// Validates that enumeration advertises weak version IDs and stable IDs derived from the canonical root.
#[test]
fn fill_page_uses_weak_versions_and_expected_stable_ids() {
    let dir = create_test_dir(&[("nested/file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    );
    let item = &page.items()[0];

    match item.version() {
        VersionId::Weak(version_id) => assert_ne!(version_id, ObjectVersionId::ZERO),
        VersionId::Strong(_) => panic!("filesystem connector must advertise weak versions"),
    }
    assert_eq!(
        item.stable_item_id(),
        expected_stable_item_id(dir.path(), b"nested/file.txt"),
    );
}

/// Identical relative paths under different roots should produce distinct stable IDs.
#[test]
fn stable_ids_are_root_scoped() {
    let dir_a = create_test_dir(&[("same.txt", b"value")]);
    let dir_b = create_test_dir(&[("same.txt", b"value")]);

    let mut connector_a = FilesystemConnector::new(dir_a.path());
    let mut connector_b = FilesystemConnector::new(dir_b.path());
    let item_a = fill_page_with_limits(
        &mut connector_a,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    )
    .items()[0]
        .clone();
    let item_b = fill_page_with_limits(
        &mut connector_b,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    )
    .items()[0]
        .clone();

    assert_ne!(item_a.stable_item_id(), item_b.stable_item_id());
}

/// Verifies that item references remain relative and do not leak connector root paths.
#[test]
fn item_ref_is_relative_and_does_not_leak_root_identifier() {
    let base = tempfile::tempdir().expect("create base tempdir");
    let root = base.path().join("TEST_SECRET_ROOT_CANARY");
    fs::create_dir(&root).expect("create explicit root");
    fs::write(root.join("visible.txt"), b"data").expect("write visible file");

    let mut connector = FilesystemConnector::new(&root);
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    );
    let item_ref = page.items()[0].item_ref().as_bytes();

    assert_eq!(item_ref, b"visible.txt");
    assert!(
        !item_ref
            .windows(b"TEST_SECRET_ROOT_CANARY".len())
            .any(|window| window == b"TEST_SECRET_ROOT_CANARY"),
        "item_ref must remain relative to the connector root"
    );
}

/// Byte budgets must prevent pagination from exceeding the configured max bytes.
#[test]
fn fill_page_stops_before_exceeding_max_bytes() {
    let dir = create_test_dir(&[("a.txt", b"aaa"), ("b.txt", b"bbbb")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, 3);
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"a.txt");
    assert!(matches!(page.state(), PageState::HasMore { .. }));
}

/// Even if the first item exceeds the byte budget, the connector must emit it so progress can be made.
#[test]
fn fill_page_emits_large_first_item_to_make_progress() {
    let dir = create_test_dir(&[("large.txt", b"12345678")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, 1);
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"large.txt");
    assert_eq!(page.items()[0].size_hint(), Some(8));
    assert!(matches!(page.state(), PageState::Complete));
}

/// When `max_items` equals the remaining file count, `fill_page` should return `Complete` even though it peeks ahead without propagating the peek failure.
#[test]
fn max_items_exactly_matching_file_count_yields_complete_page() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        3,
        u64::MAX,
    );
    assert_eq!(page.len(), 3);
    assert!(
        matches!(page.state(), PageState::Complete),
        "page should be Complete when max_items equals total file count"
    );
}

/// Hitting `max_items` before exhausting the directory keeps pagination open (`HasMore`).
#[test]
fn max_items_less_than_file_count_yields_has_more() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        2,
        u64::MAX,
    );
    assert_eq!(page.len(), 2);
    assert!(
        matches!(page.state(), PageState::HasMore { .. }),
        "page should be HasMore when more files remain"
    );
}

/// `fill_page` should reject an already-expired deadline with a retryable error.
#[test]
fn fill_page_rejects_expired_deadline() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);

    let err = connector
        .fill_page(
            &unbounded_shard(),
            &Cursor::initial(),
            Budgets::try_new(8, 64, Some(expired)).expect("valid budgets"),
        )
        .expect_err("expired deadline should reject fill_page");
    assert!(err.is_retryable(), "deadline expiry should be retryable");
}

// ---------------------------------------------------------------
// Read behavior
// ---------------------------------------------------------------

/// Opening without prior enumeration should trigger lazy root setup and successfully read the file.
#[test]
fn open_without_prior_enumerate_triggers_lazy_root_setup() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");

    let mut reader = connector
        .open(&item_ref, crate::common::test_util::default_budgets())
        .expect("open should succeed");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read full file");
    assert_eq!(buf, b"data");
}

/// Opening a non-existent `ItemRef` without prior enumeration should yield an ENOENT error.
#[test]
fn open_without_enumerate_rejects_absent_item_ref() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"no_such_file.txt").expect("valid item_ref");

    let err = match connector.open(&item_ref, crate::common::test_util::default_budgets()) {
        Ok(_) => panic!("absent item_ref should be rejected"),
        Err(err) => err,
    };
    assert!(
        err.message().contains("No such file or directory"),
        "error should indicate ENOENT from openat, got: {}",
        err.message()
    );
}

/// `open` must obey the read byte budget when streaming content.
#[test]
fn open_enforces_byte_budget() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let mut reader = connector
        .open(
            &item_ref,
            Budgets::try_new(8, 3, None).expect("valid budgets"),
        )
        .expect("open should succeed");

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read budgeted bytes");
    assert_eq!(buf, b"abc");
}

/// `read_range` should clamp reads so that the returned byte count never exceeds the configured budget.
#[test]
fn read_range_clamps_to_budget() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let mut buf = [0u8; 8];

    let read = connector
        .read_range(
            &item_ref,
            1,
            &mut buf,
            Budgets::try_new(8, 2, None).expect("valid budgets"),
        )
        .expect("read_range should succeed");
    assert_eq!(read, 2);
    assert_eq!(&buf[..read], b"bc");
}

/// `open` must reject deadlines that have already expired and classify the error as retryable.
#[test]
fn open_rejects_expired_deadline() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);

    let err = match connector.open(
        &item_ref,
        Budgets::try_new(8, 64, Some(expired)).expect("valid budgets"),
    ) {
        Ok(_) => panic!("expired deadline should reject open"),
        Err(err) => err,
    };
    assert!(err.is_retryable(), "deadline expiry should be retryable");
}

/// `read_range` also rejects expired deadlines while signalling retryable failures.
#[test]
fn read_range_rejects_expired_deadline() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);
    let mut buf = [0u8; 4];

    let err = connector
        .read_range(
            &item_ref,
            0,
            &mut buf,
            Budgets::try_new(8, 64, Some(expired)).expect("valid budgets"),
        )
        .expect_err("expired deadline should reject read_range");
    assert!(err.is_retryable(), "deadline expiry should be retryable");
}

/// A single-file root enumerates with its basename key and allows reading the file contents.
#[test]
fn single_file_root_uses_basename_key_and_opens_content() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_path = dir.path().join("only.txt");
    fs::write(&file_path, b"payload").expect("write single file");

    let mut connector = FilesystemConnector::new(&file_path);
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    );
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"only.txt");
    assert_eq!(page.items()[0].item_ref().as_bytes(), b"only.txt");
    assert!(matches!(page.state(), PageState::Complete));

    let mut reader = connector
        .open(
            &ItemRef::try_from_slice(b"only.txt").expect("valid item_ref"),
            crate::common::test_util::default_budgets(),
        )
        .expect("single-file open should succeed");
    let mut buf = Vec::new();
    reader
        .read_to_end(&mut buf)
        .expect("read single-file content");
    assert_eq!(buf, b"payload");
}

/// A single-file root honors a start bound that exactly matches the basename.
#[test]
fn single_file_root_includes_basename_matching_exact_start_bound() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_path = dir.path().join("only.txt");
    fs::write(&file_path, b"payload").expect("write single file");

    let mut connector =
        FilesystemConnector::new(&file_path).with_key_range(Some(b"only.txt"), None);
    let page = fill_page_with_limits(
        &mut connector,
        &unbounded_shard(),
        &Cursor::initial(),
        8,
        u64::MAX,
    );

    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"only.txt");
    assert!(matches!(page.state(), PageState::Complete));
}

// ---------------------------------------------------------------
// Split point and path security
// ---------------------------------------------------------------

/// Requesting a split point for an inverted range should return an error.
#[test]
fn inverted_range_split_returns_error() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let start = make_key(b"\xff");
    let end = make_key(b"\x00");
    let result = connector.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
}

/// An inverted connector key range should make split-point selection fail with a permanent error.
#[test]
fn split_point_inverted_bounds_returns_permanent_error() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let mut connector = FilesystemConnector::new(dir.path()).with_key_range(Some(b"a"), Some(b"z"));
    let start = make_key(b"\xff");
    let end = make_key(b"\x00");

    let result = connector.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted bounds should produce an error");
}

/// Verifies that various malicious `ItemRef` inputs are rejected before they can escape the root.
#[rstest]
#[case::absolute_path(b"/etc/passwd")]
#[case::parent_traversal(b"../etc/passwd")]
#[case::embedded_traversal(b"sub/../../etc/passwd")]
#[case::traversal_after_valid(b"valid/../../../etc/passwd")]
#[case::null_byte_injection(b"file.txt\x00../../etc/passwd")]
fn resolve_rejects_malicious_paths(#[case] path: &[u8]) {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let bad_ref = ItemRef::try_from_slice(path).unwrap();
    let result = connector.open(&bad_ref, crate::common::test_util::default_budgets());
    assert!(result.is_err());
}

/// Ensures canonical persistent errno values are classified as permanent errors by `is_permanent_io_error`.
#[rstest]
#[case::eloop(libc::ELOOP, "ELOOP")]
#[case::enotdir(libc::ENOTDIR, "ENOTDIR")]
#[case::eisdir(libc::EISDIR, "EISDIR")]
fn permanent_error_codes_are_classified_as_permanent(#[case] errno: i32, #[case] label: &str) {
    let err = io::Error::from_raw_os_error(errno);
    assert!(
        crate::common::is_permanent_io_error(&err),
        "{label} should be permanent"
    );
}

/// A transient errno like `EAGAIN` should remain retryable.
#[test]
fn transient_error_remains_retryable() {
    let err = io::Error::from_raw_os_error(libc::EAGAIN);
    assert!(
        !crate::common::is_permanent_io_error(&err),
        "EAGAIN should be retryable"
    );
}

// ---------------------------------------------------------------
// Root identity verification
// ---------------------------------------------------------------

/// Detects if a single-file root is replaced after initialization by rejecting the reopened item.
#[test]
fn single_file_open_detects_replacement_after_init() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_path = dir.path().join("data.txt");
    fs::write(&file_path, b"original").expect("write original");

    let mut connector = FilesystemConnector::new(&file_path);
    let item_ref = ItemRef::try_from_slice(b"data.txt").expect("valid ref");
    let mut reader = connector
        .open(&item_ref, crate::common::test_util::default_budgets())
        .expect("initial open should succeed");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read original content");
    assert_eq!(buf, b"original");
    drop(reader);

    // Create the replacement while the original still exists so the
    // filesystem must allocate a distinct inode (two live files cannot share
    // one).  A plain remove+create can recycle the inode on ext4.
    let staging = dir.path().join("data.txt.new");
    fs::write(&staging, b"impostor").expect("write replacement");
    fs::remove_file(&file_path).expect("remove original");
    fs::rename(&staging, &file_path).expect("swap replacement into place");
    // A distinct inode at the same path must be rejected.
    let result = connector.open(&item_ref, crate::common::test_util::default_budgets());
    assert!(
        result.is_err(),
        "opening a replaced file should fail inode verification"
    );
}

/// Verifies that `verify_root_identity` rejects mismatched dev/ino identifiers for a given FD.
#[test]
fn root_fd_identity_check_rejects_dev_ino_mismatch() {
    let dir_a = tempfile::tempdir().expect("create dir_a");
    let dir_b = tempfile::tempdir().expect("create dir_b");

    let fd_a = open_dir_fd(dir_a.path()).expect("open dir_a fd");

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
