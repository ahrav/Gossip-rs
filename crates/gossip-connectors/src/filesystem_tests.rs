//! Filesystem connector behavior and regression tests.

use rstest::rstest;

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

// ---------------------------------------------------------------
// Unit tests — Split points (inverted bounds only)
// ---------------------------------------------------------------

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
fn caps_reflect_defaults() {
    let dir = create_test_dir(&[]);

    let c = FilesystemConnector::new(dir.path());
    assert!(!c.caps().token_resume);
    assert!(c.caps().seek_by_key);
    assert!(c.caps().range_read);
    assert!(
        !c.caps().split_hints,
        "split_hints must be false when no observation feed populates the estimator"
    );
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
    let result = c.open(&bad_ref, crate::common::test_util::default_budgets());
    assert!(result.is_err());
}

// ---------------------------------------------------------------
// Error classification tests
// ---------------------------------------------------------------

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
// Read membership semantics tests
// ---------------------------------------------------------------

#[test]
fn open_without_prior_enumerate_triggers_lazy_indexing() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());

    // A valid ItemRef that exists on disk should succeed even without
    // prior enumeration — lazy root setup satisfies the read
    // affinity contract for compatible instances.
    let item_ref = ItemRef::try_from_slice(b"file.txt").unwrap();
    let mut reader = match c.open(&item_ref, crate::common::test_util::default_budgets()) {
        Ok(r) => r,
        Err(e) => panic!("open should trigger lazy indexing, got: {e:?}"),
    };
    let mut buf = Vec::new();
    std::io::Read::read_to_end(&mut reader, &mut buf).unwrap();
    assert_eq!(buf, b"data");
}

#[test]
fn open_without_enumerate_rejects_absent_item_ref() {
    let dir = create_test_dir(&[("file.txt", b"data")]);
    let mut c = FilesystemConnector::new(dir.path());

    // An ItemRef for a file that does not exist should fail with the
    // underlying openat ENOENT classification.
    let item_ref = ItemRef::try_from_slice(b"no_such_file.txt").unwrap();
    let err = match c.open(&item_ref, crate::common::test_util::default_budgets()) {
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
// Root identity verification test
// ---------------------------------------------------------------

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
