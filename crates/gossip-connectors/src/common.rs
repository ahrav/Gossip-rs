//! Shared connector utilities: shard-bound validation, binary search,
//! and split-candidate validation.

use std::{
    io,
    path::{Path, PathBuf},
    time::Instant,
};

#[cfg(unix)]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use gossip_contracts::connector::{
    ConnectorInputError, Cursor, EnumerateError, ItemKey, MAX_ITEM_KEY_SIZE, ReadError, ToxicDigest,
};

/// Parse an 8-byte big-endian `u64` from a byte slice.
///
/// Returns `None` for non-8-byte payloads, letting callers decide whether to
/// treat malformed values as permanent errors ([`ItemRef`] decoding) or as
/// advisory-state misses ([`Cursor`] tokens).
///
/// [`ItemRef`]: gossip_contracts::connector::ItemRef
/// [`Cursor`]: gossip_contracts::connector::Cursor
pub(crate) fn parse_u64_be(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// Validate a shard key-range bound where `[]` (empty) means unbounded.
///
/// Empty bounds are treated as unbounded to match [`ShardSpec`] semantics.
/// Non-empty bounds are validated allocation-free against [`ItemKey`] size
/// limits and then returned as borrowed slices, so callers can run binary
/// search without materializing temporary `ItemKey` wrappers.
///
/// This helper intentionally validates only boundary shape (`empty` vs
/// `<= MAX_ITEM_KEY_SIZE`): connector bound resolution is byte-lexicographic,
/// so no additional per-bound decoding is required.
/// Malformed payloads produce a permanent error including `which` for
/// diagnostics.
///
/// [`ShardSpec`]: gossip_contracts::coordination::ShardSpec
pub(crate) fn borrowed_shard_bound<'a>(
    bound: &'a [u8],
    which: &'static str,
) -> Result<Option<&'a [u8]>, EnumerateError> {
    if bound.is_empty() {
        return Ok(None);
    }
    if bound.len() > MAX_ITEM_KEY_SIZE {
        let err = ConnectorInputError::TooLarge {
            field: "ItemKey",
            size: bound.len(),
            max: MAX_ITEM_KEY_SIZE,
        };
        return Err(EnumerateError::permanent(format!(
            "invalid shard {which} bound: {err}"
        )));
    }
    Ok(Some(bound))
}

/// Trait abstraction for entries that expose a key byte slice.
///
/// Enables generic binary search (`lower_bound`, `upper_bound`) over both
/// `FileEntry` (filesystem connector) and `PreparedItem` (in-memory connector).
pub(crate) trait KeyedEntry {
    fn key_bytes(&self) -> &[u8];
}

/// Return the first index whose key is `>= key`.
pub(crate) fn lower_bound<T: KeyedEntry>(items: &[T], key: &[u8]) -> usize {
    items.partition_point(|item| item.key_bytes() < key)
}

/// Return the first index whose key is `> key`.
///
/// Used for resume progression so the last emitted key is never re-emitted.
pub(crate) fn upper_bound<T: KeyedEntry>(items: &[T], key: &[u8]) -> usize {
    items.partition_point(|item| item.key_bytes() <= key)
}

/// Half-open index range `[range_start, range_end)` within a sorted item slice.
///
/// Produced by [`resolve_bounds`]. Callers combine these indices with
/// connector-specific cursor resume logic to determine the effective start
/// position.
pub(crate) struct ResolvedBounds {
    /// Inclusive lower bound index (first item whose key is `>= shard start`,
    /// or `0` when the shard start is unbounded).
    pub range_start: usize,
    /// Exclusive upper bound index (first item whose key is `>= shard end`,
    /// or `items.len()` when the shard end is unbounded).
    pub range_end: usize,
}

/// Validate shard bounds and map them to indices via binary search.
///
/// This is the pure bound-resolution kernel shared by both page enumeration and
/// split-point selection. It validates `start <= end` and converts byte bounds
/// to half-open indices via [`lower_bound`].
///
/// # Errors
///
/// Returns `EnumerateError::permanent` when `start > end`.
pub(crate) fn resolve_bounds<T: KeyedEntry>(
    items: &[T],
    start: Option<&[u8]>,
    end: Option<&[u8]>,
) -> Result<ResolvedBounds, EnumerateError> {
    if let (Some(s), Some(e)) = (start, end)
        && s > e
    {
        return Err(EnumerateError::permanent("shard start key exceeds end key"));
    }

    let range_start = start.map_or(0, |bound| lower_bound(items, bound));
    let range_end = end.map_or(items.len(), |bound| lower_bound(items, bound));

    Ok(ResolvedBounds {
        range_start,
        range_end,
    })
}

/// Key-authoritative cursor resume: first index past the last emitted key.
///
/// Returns the O(log N) `upper_bound` position for `cursor.last_key()`,
/// clamped to `range_start` when no key is present. Callers use this as the
/// floor for resume; connector-specific token logic may advance further but
/// never behind this position.
pub(crate) fn key_resume_start<T: KeyedEntry>(
    items: &[T],
    cursor: &Cursor,
    range_start: usize,
) -> usize {
    cursor.last_key().map_or(range_start, |last_key| {
        upper_bound(items, last_key.as_bytes()).max(range_start)
    })
}

/// Check whether a split candidate advances past the cursor and stays below
/// the upper shard bound.
///
/// Both connectors apply identical post-selection guards after choosing a
/// byte-weighted split index. This helper centralizes the check so the guards
/// stay in sync.
pub(crate) fn is_valid_split_candidate(
    candidate: &[u8],
    cursor: &Cursor,
    end: Option<&[u8]>,
) -> bool {
    let past_cursor = cursor
        .last_key()
        .is_none_or(|last| candidate > last.as_bytes());
    let below_end = end.is_none_or(|upper| candidate < upper);
    past_cursor && below_end
}

/// Estimate a byte-weighted split key from a sorted entry range.
///
/// Shared post-selection flow for batch connectors (git, in-memory) that
/// already hold all entries in memory. Builds a [`StreamingSplitEstimator`]
/// with sample cap equal to `entry_count` (no compaction), estimates the
/// split key, validates it against the cursor and end bound, and converts
/// to an [`ItemKey`].
///
/// Returns `Ok(None)` when the estimator produces no candidate or the
/// candidate fails validation (does not advance past the cursor, or lands
/// at or beyond the upper shard bound).
pub(crate) fn estimate_split_from_sorted<'a>(
    entries: impl Iterator<Item = (&'a [u8], u64)>,
    entry_count: usize,
    cursor: &Cursor,
    end: Option<&[u8]>,
) -> Result<Option<ItemKey>, EnumerateError> {
    use crate::split_estimator::StreamingSplitEstimator;

    let split_estimator = StreamingSplitEstimator::from_sorted_entries(entry_count, entries);
    let Some(split_key) = split_estimator.estimate_split_key() else {
        return Ok(None);
    };
    if !is_valid_split_candidate(split_key, cursor, end) {
        return Ok(None);
    }
    // Split key bytes originate from validated ItemKey values, so they are
    // guaranteed non-empty and within MAX_ITEM_KEY_SIZE.
    let split = ItemKey::try_from_slice(split_key)
        .expect("split key bytes from validated ItemKey must round-trip");
    Ok(Some(split))
}

/// Returns `true` when a deadline is present and has already passed.
#[inline]
pub(crate) fn deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|value| Instant::now() >= value)
}

// ---------------------------------------------------------------------------
// I/O error classification
// ---------------------------------------------------------------------------

/// Returns `true` for I/O errors that are deterministically permanent.
///
/// Structural filesystem errors — missing files, permission denials, type
/// mismatches, read-only mounts, and symlink loops — will not resolve on
/// retry. Everything else (interrupted, would-block, connection-reset, etc.)
/// is assumed transient and therefore retryable.
pub fn is_permanent_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidFilename
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
            | io::ErrorKind::ReadOnlyFilesystem
    ) || is_symlink_loop(err)
}

/// Detect `ELOOP` (too many levels of symbolic links) on Unix.
#[cfg(unix)]
pub fn is_symlink_loop(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

/// Non-Unix stub: symlink loops cannot be detected via `raw_os_error`.
#[cfg(not(unix))]
pub fn is_symlink_loop(_err: &io::Error) -> bool {
    false
}

/// Map an I/O error to an [`EnumerateError`], classifying permanence.
///
/// The path is redacted through [`ToxicDigest`] so that raw filesystem
/// paths never appear in error messages that could reach logs or traces.
pub(crate) fn classify_io_enumerate_error(
    op: &str,
    path: &Path,
    err: &io::Error,
) -> EnumerateError {
    let digest = path_digest(path);
    if is_permanent_io_error(err) {
        EnumerateError::permanent(format!("{op} failed for ({digest}): {err}"))
    } else {
        EnumerateError::retryable(format!("{op} failed for ({digest}): {err}"))
    }
}

/// Map an I/O error to a [`ReadError`], classifying permanence.
///
/// When `path` is `Some`, a [`ToxicDigest`] of the path is included in
/// the message for log-safe diagnostics; when `None`, only the operation
/// and error are reported.
pub(crate) fn classify_io_read_error(op: &str, path: Option<&Path>, err: &io::Error) -> ReadError {
    let msg = match path {
        Some(p) => format!("{op} failed for ({digest}): {err}", digest = path_digest(p)),
        None => format!("{op} failed: {err}"),
    };
    if is_permanent_io_error(err) {
        ReadError::permanent(msg)
    } else {
        ReadError::retryable(msg)
    }
}

/// Compute a [`ToxicDigest`] of raw path bytes for log-safe diagnostics.
///
/// On Unix, this digests the raw `OsStr` bytes (which may be non-UTF-8).
/// On non-Unix platforms, this uses the lossy UTF-8 representation.
pub(crate) fn path_digest(path: &Path) -> ToxicDigest {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        ToxicDigest::of_bytes(path.as_os_str().as_bytes())
    }
    #[cfg(not(unix))]
    {
        ToxicDigest::of_bytes(path.to_string_lossy().as_bytes())
    }
}

/// Bridge an [`EnumerateError`] into a [`ReadError`], preserving retryability.
pub(crate) fn enumerate_error_to_read(error: EnumerateError) -> ReadError {
    if error.is_retryable() {
        ReadError::retryable(error.into_message())
    } else {
        ReadError::permanent(error.into_message())
    }
}

// ---------------------------------------------------------------------------
// Platform-aware path ↔ byte conversions
// ---------------------------------------------------------------------------

/// Convert raw path bytes to a [`PathBuf`] losslessly on Unix.
#[cfg(unix)]
pub fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

/// Convert raw path bytes to a [`PathBuf`] on non-Unix platforms.
///
/// Invalid UTF-8 sequences are replaced with U+FFFD. This is lossy but
/// avoids panicking; in practice, non-UTF-8 paths are rare on platforms
/// where this fallback applies (e.g., Windows).
#[cfg(not(unix))]
pub fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
pub(crate) mod test_util {
    use gossip_contracts::connector::{Budgets, ItemKey};

    pub fn make_key(s: &[u8]) -> ItemKey {
        ItemKey::try_from_slice(s).expect("test key")
    }

    pub fn default_budgets() -> Budgets {
        Budgets::try_new(100, u64::MAX, None).unwrap()
    }
}

/// Tests for generic binary search helpers (`lower_bound`, `upper_bound`).
///
/// Uses rstest parameterized cases since all non-empty-slice cases share the
/// identical structure: build sorted items, search for key, assert index.
/// Empty-slice cases remain standalone because their setup differs.
#[cfg(test)]
mod binary_search_tests {
    use super::*;
    use rstest::rstest;

    struct TestKey(Vec<u8>);

    impl KeyedEntry for TestKey {
        fn key_bytes(&self) -> &[u8] {
            &self.0
        }
    }

    fn sample_items() -> Vec<TestKey> {
        // Sorted: "b", "d", "f"
        vec![
            TestKey(b"b".to_vec()),
            TestKey(b"d".to_vec()),
            TestKey(b"f".to_vec()),
        ]
    }

    // -- lower_bound: first index where key >= target --

    #[test]
    fn lower_bound_empty_slice() {
        let items: Vec<TestKey> = vec![];
        assert_eq!(lower_bound(&items, b"x"), 0);
    }

    #[rstest]
    #[case::before_all(b"a", 0)]
    #[case::equal_to_first(b"b", 0)]
    #[case::between_b_and_d(b"c", 1)]
    #[case::equal_to_middle(b"d", 1)]
    #[case::between_d_and_f(b"e", 2)]
    #[case::after_all(b"z", 3)]
    fn lower_bound_cases(#[case] key: &[u8], #[case] expected: usize) {
        let items = sample_items();
        assert_eq!(lower_bound(&items, key), expected);
    }

    // -- upper_bound: first index where key > target --

    #[test]
    fn upper_bound_empty_slice() {
        let items: Vec<TestKey> = vec![];
        assert_eq!(upper_bound(&items, b"x"), 0);
    }

    #[rstest]
    #[case::before_all(b"a", 0)]
    #[case::equal_to_first(b"b", 1)]
    #[case::between_b_and_d(b"c", 1)]
    #[case::equal_to_middle(b"d", 2)]
    #[case::equal_to_last(b"f", 3)]
    #[case::after_all(b"z", 3)]
    fn upper_bound_cases(#[case] key: &[u8], #[case] expected: usize) {
        let items = sample_items();
        assert_eq!(upper_bound(&items, key), expected);
    }
}

#[cfg(test)]
mod borrowed_shard_bound_tests {
    use super::*;
    use gossip_contracts::connector::MAX_ITEM_KEY_SIZE;

    #[test]
    fn empty_bound_returns_none() {
        let result = borrowed_shard_bound(b"", "start").unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn valid_bound_returns_some() {
        let result = borrowed_shard_bound(b"abc", "start").unwrap();
        assert_eq!(result, Some(b"abc".as_slice()));
    }

    #[test]
    fn exact_max_size_returns_some() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE];
        let result = borrowed_shard_bound(&key, "end").unwrap();
        assert_eq!(result, Some(key.as_slice()));
    }

    #[test]
    fn oversized_bound_returns_permanent_error() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE + 1];
        let err = borrowed_shard_bound(&key, "start").expect_err("should reject oversized bound");
        assert!(!err.is_retryable(), "oversized bound should be permanent");
    }

    #[test]
    fn error_message_contains_which_param() {
        let key = vec![b'x'; MAX_ITEM_KEY_SIZE + 1];
        let err = borrowed_shard_bound(&key, "start").unwrap_err();
        assert!(
            err.message().contains("start"),
            "error should mention 'start': {}",
            err.message()
        );

        let err = borrowed_shard_bound(&key, "end").unwrap_err();
        assert!(
            err.message().contains("end"),
            "error should mention 'end': {}",
            err.message()
        );
    }
}

/// [`is_permanent_io_error`] treats structural filesystem failures
/// (`PermissionDenied`, `NotFound`, `InvalidInput`, `ReadOnlyFilesystem`,
/// etc.) as permanent — they will not resolve on retry. All other
/// `ErrorKind` variants are transient.
#[cfg(test)]
mod is_permanent_io_error_tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case::not_found(io::ErrorKind::NotFound)]
    #[case::permission_denied(io::ErrorKind::PermissionDenied)]
    #[case::invalid_input(io::ErrorKind::InvalidInput)]
    #[case::invalid_filename(io::ErrorKind::InvalidFilename)]
    #[case::not_a_directory(io::ErrorKind::NotADirectory)]
    #[case::is_a_directory(io::ErrorKind::IsADirectory)]
    #[case::read_only_filesystem(io::ErrorKind::ReadOnlyFilesystem)]
    fn permanent_error_kinds(#[case] kind: io::ErrorKind) {
        let err = io::Error::new(kind, "test");
        assert!(
            is_permanent_io_error(&err),
            "{kind:?} should be classified as permanent"
        );
    }

    #[rstest]
    #[case::would_block(io::ErrorKind::WouldBlock)]
    #[case::timed_out(io::ErrorKind::TimedOut)]
    #[case::interrupted(io::ErrorKind::Interrupted)]
    #[case::connection_reset(io::ErrorKind::ConnectionReset)]
    fn transient_error_kinds(#[case] kind: io::ErrorKind) {
        let err = io::Error::new(kind, "test");
        assert!(
            !is_permanent_io_error(&err),
            "{kind:?} should be classified as transient"
        );
    }
}
