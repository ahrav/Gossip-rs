//! Filesystem connector behavior and regression tests.

use std::{
    io::Read as _,
    path::Path,
    time::{Duration, Instant},
};

use rstest::rstest;

use gossip_contracts::connector::TokenBytes;

use super::*;
use crate::common::test_util::make_key;

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

fn first_item_for(root: &Path) -> ScanItem {
    let mut connector = FilesystemConnector::new(root);
    fill_page_with_limits(
        &mut connector,
        &ShardSpec::unbounded(),
        &Cursor::initial(),
        16,
        u64::MAX,
    )
    .items()[0]
        .clone()
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
    let c = FilesystemConnector::new(dir.path());

    assert!(c.caps().seek_by_key);
    assert!(c.caps().range_read);
    assert!(!c.caps().token_resume);
    assert!(!c.caps().split_hints);

    let ordered_caps = c.capabilities();
    assert!(ordered_caps.range_read);
    assert!(!ordered_caps.token_resume);
    assert!(!ordered_caps.split_hints);
}

// ---------------------------------------------------------------
// Page fill / ordering / shard membership
// ---------------------------------------------------------------

#[test]
fn fill_page_returns_sorted_items_and_resume_cursor() {
    let dir = create_test_dir(&[
        ("c.txt", b"ccc"),
        ("a.txt", b"aaa"),
        ("b/nested.txt", b"bbb"),
    ]);
    let mut connector = FilesystemConnector::new(dir.path());
    let shard = unbounded_shard();

    let first_page = fill_page_with_limits(&mut connector, &shard, &Cursor::initial(), 2, u64::MAX);
    let first_keys: Vec<&[u8]> = first_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(first_keys, vec![b"a.txt".as_slice(), b"b/nested.txt".as_slice()]);

    let resume_cursor = match first_page.state() {
        PageState::HasMore { cursor } => cursor.clone(),
        PageState::Complete => panic!("first page should be resumable"),
    };
    assert_eq!(
        resume_cursor
            .last_key()
            .expect("resume cursor should include last_key")
            .as_bytes(),
        b"b/nested.txt"
    );

    let second_page = fill_page_with_limits(&mut connector, &shard, &resume_cursor, 2, u64::MAX);
    let second_keys: Vec<&[u8]> = second_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();
    assert_eq!(second_keys, vec![b"c.txt".as_slice()]);
    assert!(matches!(second_page.state(), PageState::Complete));

    let exhausted = connector
        .fill_page(
            &shard,
            &Cursor::with_last_key(make_key(b"c.txt")),
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
fn fill_page_intersects_connector_key_range_and_ignores_input_token() {
    let dir = create_test_dir(&[
        ("a.txt", b"a"),
        ("b.txt", b"b"),
        ("c.txt", b"c"),
        ("d.txt", b"d"),
    ]);
    let mut connector = FilesystemConnector::new(dir.path()).with_key_range(Some(b"b"), Some(b"d"));
    let cursor = Cursor::with_token(
        make_key(b"a.txt"),
        TokenBytes::try_from_slice(b"stale-token").expect("valid token"),
    );

    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &cursor, 8, u64::MAX);
    let keys: Vec<&[u8]> = page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();

    assert_eq!(keys, vec![b"b.txt".as_slice(), b"c.txt".as_slice()]);
    assert!(matches!(page.state(), PageState::Complete));
}

#[test]
fn fill_page_returns_none_when_connector_range_and_shard_do_not_overlap() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("b.txt", b"b")]);
    let mut connector = FilesystemConnector::new(dir.path()).with_key_range(Some(b"x"), Some(b"z"));
    let shard = ShardSpec::try_with_range(b"a", b"c").expect("valid shard");

    let page = connector
        .fill_page(
            &shard,
            &Cursor::initial(),
            crate::common::test_util::default_budgets(),
        )
        .expect("fill_page should succeed for an empty effective range");
    assert!(page.is_none(), "empty effective range should produce no page");
}

#[test]
fn fill_page_uses_weak_versions() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, u64::MAX);

    match page.items()[0].version() {
        VersionId::Weak(version_id) => assert_ne!(version_id, ObjectVersionId::ZERO),
        VersionId::Strong(_) => panic!("filesystem connector must advertise weak versions"),
    }
}

#[test]
fn item_ref_is_relative_and_does_not_leak_root_identifier() {
    let base = tempfile::tempdir().expect("create base tempdir");
    let root = base.path().join("TEST_SECRET_ROOT_CANARY");
    fs::create_dir(&root).expect("create explicit root");
    fs::write(root.join("visible.txt"), b"data").expect("write visible file");

    let mut connector = FilesystemConnector::new(&root);
    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, u64::MAX);
    let item_ref = page.items()[0].item_ref().as_bytes();

    assert_eq!(item_ref, b"visible.txt");
    assert!(
        !item_ref
            .windows(b"TEST_SECRET_ROOT_CANARY".len())
            .any(|window| window == b"TEST_SECRET_ROOT_CANARY"),
        "item_ref must remain relative to the connector root"
    );
}

// ---------------------------------------------------------------
// Stable-id scoping
// ---------------------------------------------------------------

#[test]
fn stable_ids_are_root_scoped_by_default() {
    let dir_a = create_test_dir(&[("same.txt", b"value")]);
    let dir_b = create_test_dir(&[("same.txt", b"value")]);

    let item_a = first_item_for(dir_a.path());
    let item_b = first_item_for(dir_b.path());

    assert_ne!(
        item_a.stable_item_id(),
        item_b.stable_item_id(),
        "default filesystem stable ids must be scoped by canonical root path"
    );
}

#[test]
fn explicit_connector_instance_override_aligns_stable_ids_across_roots() {
    let dir_a = create_test_dir(&[("same.txt", b"value")]);
    let dir_b = create_test_dir(&[("same.txt", b"value")]);
    let override_hash = ConnectorInstanceIdHash::from_instance_id_bytes(b"shared-filesystem-instance");

    let mut connector_a = FilesystemConnector::new(dir_a.path()).with_connector_instance_hash(override_hash);
    let mut connector_b = FilesystemConnector::new(dir_b.path()).with_connector_instance_hash(override_hash);

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

    assert_eq!(
        item_a.stable_item_id(),
        item_b.stable_item_id(),
        "explicit connector-instance override should intentionally align identity across roots"
    );
}

// ---------------------------------------------------------------
// Budgeted reads / fixed view
// ---------------------------------------------------------------

#[test]
fn open_without_prior_enumerate_triggers_lazy_indexing() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");

    let mut reader = connector
        .open(&item_ref, crate::common::test_util::default_budgets())
        .expect("open should trigger lazy indexing");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read full file");
    assert_eq!(buf, b"data");
}

#[test]
fn open_without_enumerate_rejects_absent_item_ref() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"no_such_file.txt").expect("valid item_ref");

    let err = connector
        .open(&item_ref, crate::common::test_util::default_budgets())
        .expect_err("absent item_ref should be rejected");
    assert!(
        err.message().contains("item_ref not found in snapshot"),
        "error should come from frozen-snapshot membership check, got: {}",
        err.message()
    );
}

#[test]
fn open_enforces_byte_budget() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let mut reader = connector
        .open(&item_ref, Budgets::try_new(8, 3, None).expect("valid budgets"))
        .expect("open should succeed");

    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).expect("read budgeted bytes");
    assert_eq!(buf, b"abc");
}

#[test]
fn open_rejects_expired_deadline() {
    let dir = create_test_dir(&[("file.txt", b"abcdef")]);
    let mut connector = FilesystemConnector::new(dir.path());
    let item_ref = ItemRef::try_from_slice(b"file.txt").expect("valid item_ref");
    let expired = Instant::now()
        .checked_sub(Duration::from_millis(1))
        .unwrap_or_else(Instant::now);

    let err = connector
        .open(
            &item_ref,
            Budgets::try_new(8, 64, Some(expired)).expect("valid budgets"),
        )
        .expect_err("expired deadline should reject open");
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
fn snapshot_view_rejects_files_added_after_indexing() {
    let dir = create_test_dir(&[("before.txt", b"before")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let _page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, u64::MAX);
    fs::write(dir.path().join("after.txt"), b"after").expect("write late file");

    let late_ref = ItemRef::try_from_slice(b"after.txt").expect("valid item_ref");
    let err = connector
        .open(&late_ref, crate::common::test_util::default_budgets())
        .expect_err("late-added file should not enter the frozen snapshot view");
    assert!(
        err.message().contains("item_ref not found in snapshot"),
        "open should stay pinned to the indexed view, got: {}",
        err.message()
    );
}


#[test]
fn resumed_paging_on_same_connector_stays_pinned_to_frozen_snapshot() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("c.txt", b"c")]);
    let mut connector = FilesystemConnector::new(dir.path());

    let first_page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 1, u64::MAX);
    let resume_cursor = match first_page.state() {
        PageState::HasMore { cursor } => cursor.clone(),
        PageState::Complete => panic!("first page should be resumable"),
    };
    fs::write(dir.path().join("b.txt"), b"b").expect("write late file");

    let second_page = fill_page_with_limits(&mut connector, &unbounded_shard(), &resume_cursor, 8, u64::MAX);
    let second_keys: Vec<&[u8]> = second_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();

    assert_eq!(second_keys, vec![b"c.txt".as_slice()]);
    assert!(matches!(second_page.state(), PageState::Complete));
}

#[test]
fn fresh_connector_resumes_from_persisted_last_key_on_current_view() {
    let dir = create_test_dir(&[("a.txt", b"a"), ("c.txt", b"c")]);
    let mut initial = FilesystemConnector::new(dir.path());

    let first_page = fill_page_with_limits(&mut initial, &unbounded_shard(), &Cursor::initial(), 1, u64::MAX);
    let persisted_cursor = match first_page.state() {
        PageState::HasMore { cursor } => Cursor::with_token(
            cursor
                .last_key()
                .expect("resume cursor should include last_key")
                .clone(),
            TokenBytes::try_from_slice(b"stale-token").expect("valid token"),
        ),
        PageState::Complete => panic!("first page should be resumable"),
    };

    fs::write(dir.path().join("b.txt"), b"b").expect("write late file");
    fs::write(dir.path().join("d.txt"), b"d").expect("write later file");

    let mut resumed = FilesystemConnector::new(dir.path());
    let resumed_page = fill_page_with_limits(&mut resumed, &unbounded_shard(), &persisted_cursor, 8, u64::MAX);
    let resumed_keys: Vec<&[u8]> = resumed_page
        .items()
        .iter()
        .map(|item| item.item_key().as_bytes())
        .collect();

    assert_eq!(
        resumed_keys,
        vec![b"b.txt".as_slice(), b"c.txt".as_slice(), b"d.txt".as_slice()]
    );
    assert!(matches!(resumed_page.state(), PageState::Complete));
}

#[test]
fn single_file_root_uses_basename_key_and_opens_content() {
    let dir = tempfile::tempdir().expect("create tempdir");
    let file_path = dir.path().join("only.txt");
    fs::write(&file_path, b"payload").expect("write single file");

    let mut connector = FilesystemConnector::new(&file_path);
    let page = fill_page_with_limits(&mut connector, &unbounded_shard(), &Cursor::initial(), 8, u64::MAX);
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
    reader.read_to_end(&mut buf).expect("read single-file content");
    assert_eq!(buf, b"payload");
}

// ---------------------------------------------------------------
// Inverted range rejection
// ---------------------------------------------------------------

#[test]
fn inverted_range_split_returns_error() {
    let dir = create_test_dir(&[("a.txt", b"1"), ("b.txt", b"2")]);
    let mut c = FilesystemConnector::new(dir.path());

    let start = make_key(b"\xff");
    let end = make_key(b"\x00");
    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
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
// Path security / IO classification
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
    let result = c.open(&bad_ref, crate::common::test_util::default_budgets());
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
    // EAGAIN / EWOULDBLOCK is transient.
    let err = io::Error::from_raw_os_error(libc::EAGAIN);
    assert!(
        !crate::common::is_permanent_io_error(&err),
        "EAGAIN should be retryable"
    );
}

// ---------------------------------------------------------------
// Root identity verification test
// ---------------------------------------------------------------

#[test]
fn root_fd_identity_check_rejects_dev_ino_mismatch() {
    // Open an fd to directory A, then verify against the path of a
    // *different* directory B. The dev/ino values will differ, so
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
