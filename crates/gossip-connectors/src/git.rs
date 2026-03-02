//! Deterministic connector for Git-tracked files.
//!
//! This connector indexes tracked files via `git ls-files -z`, then serves
//! key-range pages over that static snapshot. Item keys and item refs are both
//! the raw repository-relative path bytes.
//!
//! # Indexing model
//!
//! - Indexing is lazy (`ensure_indexed`): the first
//!   enumerate or read call shells out to `git ls-files -z` and builds a
//!   sorted in-memory snapshot.
//! - Once indexed, the snapshot is immutable for the connector's lifetime.
//!   The connector does **not** track live repository changes — any new
//!   commits, staging-area edits, or working-tree mutations after the first
//!   enumeration call are invisible.
//! - Enumeration order is deterministic for a fixed repository state because
//!   entries are globally sorted by raw key bytes after indexing.
//!
//! # Version model
//!
//! Git does not expose a strong per-file content hash through `ls-files`, so
//! this connector produces **weak** versions: a BLAKE3 digest over
//! `(path, file_size, mtime_nanos)`. Two snapshots of the same file will
//! yield identical versions only when both size and mtime agree. This is
//! sufficient for change-detection but does not guarantee content identity.
//!
//! # Error classification
//!
//! I/O errors are classified as *permanent* (not-found, permission-denied,
//! invalid-input, symlink loops) or *retryable* (everything else — typically
//! transient filesystem errors). Permanent errors during initial indexing
//! latch `IndexState::Failed` so subsequent calls fail fast without
//! re-shelling to `git`.
//!
//! # Platform behavior
//!
//! On Unix, git paths are converted to `OsString` losslessly via
//! [`OsStringExt::from_vec`]. On non-Unix platforms, paths are decoded
//! through [`String::from_utf8_lossy`], which replaces invalid UTF-8 with
//! U+FFFD — a lossy but safe fallback.

use std::{
    fs,
    io::{self, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
    process::Command,
    time::{Instant, UNIX_EPOCH},
};

#[cfg(unix)]
use std::{ffi::OsString, os::unix::ffi::OsStringExt};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ObjectVersionId, StableItemId},
};

use crate::common::{self, borrowed_shard_bound, derive_stable_item_id};

/// Connector tag used to domain-separate stable item identity derivation.
const GIT_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"gitlocal");

/// A single indexed file from `git ls-files`.
///
/// Each entry caches the pre-computed identity and weak version so that
/// enumeration pages can be assembled without re-hashing on every page
/// request. Entries are sorted by `key` (byte-lexicographic) after indexing
/// and remain immutable thereafter.
#[derive(Debug)]
struct GitEntry {
    /// Repository-relative path used as both the item key and the item ref.
    key: ItemKey,
    /// Domain-separated BLAKE3 identity derived from `(ConnectorTag, key)`.
    stable_item_id: StableItemId,
    /// Weak version fingerprint over `(path, size, mtime)`.
    version: VersionId,
    /// File size in bytes at index time, used as a size hint for budgeting.
    size_hint: u64,
}

impl common::KeyedEntry for GitEntry {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

impl common::SizedEntry for GitEntry {
    fn entry_size(&self) -> u64 {
        self.size_hint
    }
}

/// Tri-state machine for the lazy indexing lifecycle.
///
/// Transitions:
/// - `NotIndexed → Indexed` on successful `git ls-files` + snapshot build.
/// - `NotIndexed → Failed` on permanent I/O or git errors.
///
/// Both `Indexed` and `Failed` are **terminal**: once reached, the connector
/// never re-attempts indexing. `Failed` latches an error message so that
/// subsequent calls fail fast with a stable diagnostic.
enum IndexState {
    /// No indexing attempt has been made yet.
    NotIndexed,
    /// Snapshot built successfully; entries are populated and sorted.
    Indexed,
    /// A permanent error occurred during indexing; retries are suppressed.
    Failed(String),
}

/// Connector that enumerates and reads Git-tracked repository files.
///
/// The connector lazily indexes tracked files on first use, then serves
/// paginated enumeration and byte-range reads from that frozen snapshot.
/// It implements both [`EnumerationConnector`] and [`ReadConnector`].
///
/// # Invariants
///
/// - After `index_state` reaches `IndexState::Indexed`, `entries` is
///   non-empty (unless the repository has no tracked files), sorted by
///   `key` in byte-lexicographic order, and never mutated again.
/// - `repo` is validated once during indexing; a missing or non-directory
///   path latches a permanent failure.
/// - When `emit_tokens` is true, cursors carry an 8-byte big-endian
///   absolute index that enables O(1) resume. Token validity is always
///   cross-checked against the last emitted key.
pub struct GitConnector {
    /// Absolute path to the repository root (working directory).
    repo: PathBuf,
    /// Whether pagination cursors include positional tokens for O(1)
    /// resume. Defaults to `true`; set to `false` for key-only cursors.
    emit_tokens: bool,
    /// Lazy indexing state machine. See [`IndexState`].
    index_state: IndexState,
    /// Sorted snapshot of tracked files, populated by [`ensure_indexed`].
    entries: Vec<GitEntry>,
}

impl GitConnector {
    /// Create a connector rooted at `repo`.
    pub fn new(repo: impl Into<PathBuf>) -> Self {
        Self {
            repo: repo.into(),
            emit_tokens: true,
            index_state: IndexState::NotIndexed,
            entries: Vec::new(),
        }
    }

    /// Enable or disable pagination token emission/consumption.
    #[must_use]
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    /// Enumerate one page over the explicit half-open key range `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(
            Some(start.as_bytes()),
            Some(end.as_bytes()),
            cursor,
            budgets,
        )
    }

    /// Return a split-point hint over the explicit half-open key range
    /// `[start, end)`.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start.as_bytes()), Some(end.as_bytes()), cursor)
    }

    /// Lazily build the sorted file snapshot on first call.
    ///
    /// Runs `git ls-files -z` in the repository, stats each tracked path,
    /// and populates `self.entries` in sorted key order. Subsequent calls
    /// are no-ops (indexed) or fast-fail (permanently failed).
    ///
    /// The `deadline` is checked both before shelling out and between
    /// per-file stat calls, so large repositories can be interrupted
    /// without blocking the caller. A deadline expiry returns a
    /// *retryable* error (the index state stays `NotIndexed`), while a
    /// git/I/O failure that is classified as permanent latches
    /// [`IndexState::Failed`].
    fn ensure_indexed(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        match &self.index_state {
            IndexState::Indexed => return Ok(()),
            IndexState::Failed(message) => {
                return Err(EnumerateError::permanent(message.clone()));
            }
            IndexState::NotIndexed => {}
        }

        if deadline_expired(deadline) {
            return Err(EnumerateError::retryable("indexing deadline expired"));
        }

        if !self.repo.exists() {
            let msg = format!("repository path does not exist: {}", self.repo.display());
            self.index_state = IndexState::Failed(msg.clone());
            return Err(EnumerateError::permanent(msg));
        }
        if !self.repo.is_dir() {
            let msg = format!(
                "repository path must be a directory: {}",
                self.repo.display()
            );
            self.index_state = IndexState::Failed(msg.clone());
            return Err(EnumerateError::permanent(msg));
        }

        let tracked = match list_git_tracked_paths(&self.repo) {
            Ok(paths) => paths,
            Err(error) => {
                if !error.is_retryable() {
                    self.index_state = IndexState::Failed(error.message().to_owned());
                }
                return Err(error);
            }
        };

        let mut entries = Vec::with_capacity(tracked.len());
        for key_bytes in tracked {
            if deadline_expired(deadline) {
                return Err(EnumerateError::retryable("indexing deadline expired"));
            }
            if key_bytes.is_empty() {
                continue;
            }

            let abs_path = self.repo.join(path_buf_from_bytes(&key_bytes));
            // git ls-files can report submodule entries, symlinks to
            // directories, or paths that were deleted in the working tree.
            // Silently skip anything that isn't a regular file.
            if !abs_path.is_file() {
                continue;
            }
            let metadata = fs::metadata(&abs_path)
                .map_err(|error| classify_io_enumerate_error("metadata", &abs_path, &error))?;
            let entry = build_git_entry(&key_bytes, metadata.len(), metadata.modified().ok())?;
            entries.push(entry);
        }

        entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));

        self.entries = entries;
        self.index_state = IndexState::Indexed;
        Ok(())
    }

    /// Core pagination over an optional half-open byte range `[start, end)`.
    ///
    /// 1. Ensures the index is built (lazy, respects `budgets.deadline()`).
    /// 2. Resolves shard bounds to index positions via binary search.
    /// 3. Determines the resume position from the cursor — first by
    ///    key-authoritative O(log N) upper-bound, then accelerated to
    ///    O(1) when a valid positional token is present and its key
    ///    cross-check passes (see inline comments below).
    /// 4. Slices at most `budgets.max_items()` entries, assembles pooled
    ///    `ScanItem`s, and builds the continuation cursor.
    ///
    /// `None` bounds mean unbounded on that side.
    fn enumerate_page_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.ensure_indexed(budgets.deadline())?;
        let bounds = common::resolve_page_bounds(&self.entries, start, end, budgets)?;
        let key_resume = common::key_resume_start(&self.entries, cursor, bounds.range_start);
        let mut start_idx = key_resume;

        // Token fast-path: when the cursor carries a positional token and the
        // entry at `token_idx - 1` still matches the last emitted key, we can
        // skip the O(log N) binary search and resume at O(1). If the token is
        // missing, malformed, out of range, or disagrees with the key, we
        // silently fall back to `key_resume` (the binary-search result above).
        //
        // The `.max(token_idx)` ensures the token can only advance the resume
        // position forward — never behind the key-derived floor.
        if let Some(last_key) = cursor.last_key() {
            let token_idx = self
                .emit_tokens
                .then(|| common::cursor_token_index(cursor))
                .flatten();
            if let Some(token_idx) = token_idx
                && token_idx > 0
                && token_idx <= self.entries.len()
                && self.entries[token_idx - 1].key == *last_key
            {
                start_idx = start_idx.max(token_idx);

                // In debug builds, verify the O(1) token path and O(log N)
                // key path agree — a mismatch indicates an index corruption
                // or a cursor that was constructed against a different snapshot.
                #[cfg(debug_assertions)]
                debug_assert_eq!(
                    token_idx, key_resume,
                    "token index {token_idx} disagrees with key-derived resume position {key_resume}"
                );
            }
        }

        if start_idx >= bounds.range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(bounds.range_end - start_idx);
        let page_entries = &self.entries[start_idx..(start_idx + take)];

        let staged = common::assemble_pooled_page_shared_key_ref(
            page_entries.iter().map(|entry| entry.key.as_bytes()),
            self.emit_tokens,
            start_idx,
        )?;

        let common::StagedPage { wrappers, token } = staged;
        let mut out = Vec::with_capacity(wrappers.len());
        for ((item_key, item_ref), entry) in wrappers.into_iter().zip(page_entries) {
            out.push(
                ScanItem::new(item_key, item_ref, entry.stable_item_id, entry.version)
                    .with_size_hint(entry.size_hint),
            );
        }

        let last_key = match out.last() {
            Some(item) => item.item_key().clone(),
            None => return Ok(EnumerationPage::new(Vec::new(), cursor.clone())),
        };
        let next_cursor = common::build_next_cursor_from_staged(
            last_key,
            start_idx,
            out.len(),
            self.emit_tokens,
            token,
        )?;

        Ok(EnumerationPage::new(out, next_cursor))
    }

    /// Choose a byte-weighted split point in the optional range `[start, end)`.
    ///
    /// Delegates to [`common::choose_split_index`] which picks the entry
    /// closest to the cumulative-size midpoint. The candidate is rejected
    /// if it does not advance past the current cursor or would land at or
    /// beyond the upper shard bound.
    ///
    /// Indexing uses no deadline here because split selection is a
    /// metadata-only decision (no file I/O after the snapshot is built).
    fn choose_split_point_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.ensure_indexed(None)?;

        let bounds = common::resolve_bounds(&self.entries, start, end)?;
        let start_idx = common::key_resume_start(&self.entries, cursor, bounds.range_start);
        let split_idx = match common::choose_split_index(&self.entries, start_idx, bounds.range_end)
        {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let candidate = &self.entries[split_idx].key;
        if !common::is_valid_split_candidate(candidate.as_bytes(), cursor, end) {
            return Ok(None);
        }

        Ok(Some(candidate.clone()))
    }

    /// Resolve an `ItemRef` to an absolute filesystem path.
    ///
    /// Ensures the index is built, then performs an O(log N) binary search
    /// to verify the ref exists in the snapshot. This prevents reads of
    /// files that were not present at index time (e.g., untracked or
    /// newly created files).
    fn open_path_for_ref(&mut self, item_ref: &ItemRef) -> Result<PathBuf, ReadError> {
        self.ensure_indexed(None).map_err(enumerate_error_to_read)?;

        let ref_bytes = item_ref.as_bytes();
        self.entries
            .binary_search_by(|entry| entry.key.as_bytes().cmp(ref_bytes))
            .map_err(|_| ReadError::permanent("item_ref not found in index"))?;

        Ok(self.repo.join(path_buf_from_bytes(ref_bytes)))
    }
}

impl EnumerationConnector for GitConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start, end, cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor)
    }
}

impl ReadConnector for GitConnector {
    fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let path = self.open_path_for_ref(item_ref)?;
        let file =
            fs::File::open(&path).map_err(|error| classify_io_read_error("open", &path, &error))?;
        Ok(Box::new(file))
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        if offset.checked_add(dst.len() as u64).is_none() {
            return Err(ReadError::permanent("offset + dst length overflow"));
        }

        let max_bytes = usize::try_from(budgets.max_bytes()).unwrap_or(usize::MAX);
        let allowed = dst.len().min(max_bytes);
        if allowed == 0 {
            return Ok(0);
        }

        let path = self.open_path_for_ref(item_ref)?;
        let mut file =
            fs::File::open(&path).map_err(|error| classify_io_read_error("open", &path, &error))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|error| classify_io_read_error("seek", &path, &error))?;
        file.read(&mut dst[..allowed])
            .map_err(|error| classify_io_read_error("read", &path, &error))
    }
}

/// Construct a [`GitEntry`] from raw path bytes and filesystem metadata.
///
/// Validates `key_bytes` as both an [`ItemKey`] and an [`ItemRef`] (they
/// share the same byte representation for this connector). The dual
/// validation catches oversized or malformed paths at index time rather
/// than during later enumeration or read calls.
fn build_git_entry(
    key_bytes: &[u8],
    size_hint: u64,
    modified: Option<std::time::SystemTime>,
) -> Result<GitEntry, EnumerateError> {
    let key = ItemKey::try_from_slice(key_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid git item key: {error}")))?;
    // Validate that the same bytes are also a valid ItemRef. This connector
    // uses identical bytes for key and ref, but the types have independent
    // size limits, so both must pass.
    let _ = ItemRef::try_from_slice(key_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid git item_ref: {error}")))?;
    let stable_item_id = derive_stable_item_id(GIT_CONNECTOR_TAG, &key);
    let version = build_weak_version(key_bytes, size_hint, modified);

    Ok(GitEntry {
        key,
        stable_item_id,
        version,
        size_hint,
    })
}

/// Derive a weak version fingerprint from `(path, size, mtime)`.
///
/// "Weak" means the version is based on filesystem metadata rather than
/// file content — two files with identical size and mtime but different
/// contents will collide. This is acceptable because the coordination
/// layer treats weak versions as change-detection hints, not as content
/// identity proofs.
///
/// When `modified` is `None` (e.g., on filesystems that lack mtime
/// support), the mtime component defaults to zero. This still produces a
/// unique version per `(path, size)` pair but loses change sensitivity.
fn build_weak_version(
    key_bytes: &[u8],
    size_hint: u64,
    modified: Option<std::time::SystemTime>,
) -> VersionId {
    let mut version_material = Vec::with_capacity(key_bytes.len() + 32);
    version_material.extend_from_slice(key_bytes);
    version_material.extend_from_slice(&size_hint.to_le_bytes());
    let modified_nanos = modified
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    version_material.extend_from_slice(&modified_nanos.to_le_bytes());

    VersionId::Weak(ObjectVersionId::from_version_bytes(&version_material))
}

/// Shell out to `git ls-files -z` and return NUL-split raw path entries.
///
/// Uses `-z` for NUL-delimited output so paths containing newlines or
/// other special characters are handled correctly. The returned byte
/// vectors are raw repository-relative paths — no encoding conversion is
/// applied here (that happens in [`path_buf_from_bytes`]).
///
/// A non-zero exit from `git` is classified as a permanent error because
/// it typically indicates that the directory is not a git repository.
fn list_git_tracked_paths(repo: &Path) -> Result<Vec<Vec<u8>>, EnumerateError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .arg("ls-files")
        .arg("-z")
        .output()
        .map_err(|error| classify_io_enumerate_error("git ls-files", repo, &error))?;

    if !output.status.success() {
        return Err(EnumerateError::permanent(format!(
            "git ls-files failed in '{}' (status={:?}): {}",
            repo.display(),
            output.status.code(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }

    let mut paths = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        paths.push(entry.to_vec());
    }
    Ok(paths)
}

/// Bridge an [`EnumerateError`] into a [`ReadError`], preserving retryability.
///
/// Used by [`ReadConnector`] methods that must call [`ensure_indexed`]
/// (which speaks `EnumerateError`) before performing read I/O.
fn enumerate_error_to_read(error: EnumerateError) -> ReadError {
    if error.is_retryable() {
        ReadError::retryable(error.into_message())
    } else {
        ReadError::permanent(error.into_message())
    }
}

/// Returns `true` when a deadline is present and has already passed.
fn deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|value| Instant::now() >= value)
}

/// Map an I/O error to an [`EnumerateError`], classifying permanence.
fn classify_io_enumerate_error(op: &str, path: &Path, err: &io::Error) -> EnumerateError {
    if is_permanent_io_error(err) {
        EnumerateError::permanent(format!("{op} failed for {}: {err}", path.display()))
    } else {
        EnumerateError::retryable(format!("{op} failed for {}: {err}", path.display()))
    }
}

/// Map an I/O error to a [`ReadError`], classifying permanence.
fn classify_io_read_error(op: &str, path: &Path, err: &io::Error) -> ReadError {
    if is_permanent_io_error(err) {
        ReadError::permanent(format!("{op} failed for {}: {err}", path.display()))
    } else {
        ReadError::retryable(format!("{op} failed for {}: {err}", path.display()))
    }
}

/// Decide whether an I/O error is permanent (won't resolve on retry).
///
/// The policy treats structural filesystem errors — missing files,
/// permission denials, type mismatches, and symlink loops — as permanent.
/// Everything else (interrupted, would-block, connection-reset, etc.) is
/// assumed transient and therefore retryable.
fn is_permanent_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidFilename
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
    ) || is_symlink_loop(err)
}

/// Detect `ELOOP` (too many levels of symbolic links) on Unix.
#[cfg(unix)]
fn is_symlink_loop(err: &io::Error) -> bool {
    err.raw_os_error() == Some(libc::ELOOP)
}

/// Non-Unix stub: symlink loops cannot be detected via `raw_os_error`.
#[cfg(not(unix))]
fn is_symlink_loop(_err: &io::Error) -> bool {
    false
}

/// Convert raw git path bytes to a [`PathBuf`] losslessly on Unix.
#[cfg(unix)]
fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(OsString::from_vec(bytes.to_vec()))
}

/// Convert raw git path bytes to a [`PathBuf`] on non-Unix platforms.
///
/// Invalid UTF-8 sequences are replaced with U+FFFD. This is lossy but
/// avoids panicking; in practice, non-UTF-8 paths are rare on platforms
/// where this fallback applies (e.g., Windows).
#[cfg(not(unix))]
fn path_buf_from_bytes(bytes: &[u8]) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(bytes).into_owned())
}

#[cfg(test)]
#[path = "git_tests.rs"]
mod tests;
