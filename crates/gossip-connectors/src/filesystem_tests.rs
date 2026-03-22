//! Filesystem connector behavior and regression tests.

use std::{
    io::{self, Read as _},
    path::Path,
    time::{Duration, Instant},
};

use gossip_contracts::{
    connector::{
        Budgets, FILESYSTEM_CONNECTOR_TAG, ItemRef, PageBuf, PageState, ScanItem, VersionId,
        ordered::OrderedContentSource,
    },
    identity::{ConnectorInstanceIdHash, ItemIdentityKey, ObjectVersionId},
};
use rstest::rstest;

use super::*;
use crate::common::test_util::make_key;

/// Create a temporary directory populated with the given files.
///
/// Each entry is `(relative_path, content)`. Parent directories are created
/// automatically.
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

fn unbounded_shard() -> ShardSpec {
    ShardSpec::unbounded()
}

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

fn expected_stable_item_id(
    root: &Path,
    rel_path: &[u8],
) -> gossip_contracts::identity::StableItemId {
    let canonical_root = fs::canonicalize(root).expect("canonical root");
    let connector_instance =
        ConnectorInstanceIdHash::from_instance_id_bytes(canonical_root.as_os_str().as_bytes());
    ItemIdentityKey::new(FILESYSTEM_CONNECTOR_TAG, connector_instance, rel_path).stable_id()
}

// ---------------------------------------------------------------
// Trait surface / capabilities
// ---------------------------------------------------------------

#[test]
fn filesystem_connector_implements_ordered_content_source() {
    fn assert_ordered_source<T: OrderedContentSource>() {}
    assert_ordered_source::<FilesystemConnector>();
}

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

#[test]
fn fill_page_stops_before_exceeding_max_bytes() {
    let dir = create_test_dir(&[("a.txt", b"aaa"), ("b.txt", b"bbbb")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, 3);
    assert_eq!(page.len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"a.txt");
    assert!(matches!(page.state(), PageState::HasMore { .. }));
}

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

#[test]
fn inverted_range_split_returns_error() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let start = make_key(b"\xff");
    let end = make_key(b"\x00");
    let result = connector.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
}

#[test]
fn split_point_inverted_bounds_returns_permanent_error() {
    let dir = create_test_dir(&[("a.txt", b"1")]);
    let mut connector = FilesystemConnector::new(dir.path()).with_key_range(Some(b"a"), Some(b"z"));
    let start = make_key(b"\xff");
    let end = make_key(b"\x00");

    let result = connector.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted bounds should produce an error");
}

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
