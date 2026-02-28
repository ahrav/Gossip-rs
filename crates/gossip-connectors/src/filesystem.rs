//! Deterministic filesystem-backed connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], an implementation of
//! [`gossip_contracts::connector::EnumerationConnector`] and
//! [`gossip_contracts::connector::ReadConnector`] that indexes regular files
//! under a root directory and serves shard-friendly key-range scans.
//!
//! # Algorithm
//!
//! 1. **Lazy indexing** -- The first enumerate/split call walks the root using
//!    an explicit stack (no recursion), collecting regular files only. Symlinks
//!    are skipped.
//! 2. **Canonical path encoding** -- Each relative path is encoded to raw bytes
//!    with `/` separators and reused for both [`ItemKey`] and [`ItemRef`].
//! 3. **Deterministic serving** -- Entries are globally sorted by key, then
//!    pagination and split hints resolve bounds via binary search.
//!
//! # Determinism and trade-offs
//!
//! - Enumeration order is stable for a fixed directory snapshot because the
//!   collected entries are globally sorted by key bytes.
//! - Indexing is one-shot per connector instance (`ensure_indexed`); this favors
//!   deterministic page progression over live directory updates.
//! - [`StableItemId`] uses the standard connector-tag + key derivation, while
//!   [`VersionId`] is weak metadata-derived (`mtime`, `mtime_nsec`, `len`,
//!   `inode`) to avoid content hashing during index build.
//!
//! # Resume semantics
//!
//! Cursor progression is anchored on key ordering, not opaque tokens. The
//! authoritative resume position is always [`Cursor::last_key`], resolved to
//! the first index strictly greater than that key (`upper_bound`), clamped to
//! the shard range start. Tokens, when enabled via [`FilesystemConnector::with_tokens`],
//! carry the next absolute index as a big-endian `u64` and serve only as a
//! consistency cross-check: in debug builds a `debug_assert_eq!` fires when
//! the token index disagrees with the key-derived position (indicating a
//! connector or cursor-construction bug), while in release builds the mismatch
//! is silently ignored. Pagination advances monotonically by key regardless of
//! token state.
//!
//! Unlike the in-memory connector, which uses tokens as an O(1) fast path
//! with runtime key-validation fallback, the filesystem connector treats
//! tokens as purely advisory. In debug builds, a `debug_assert_eq!` fires
//! when the token disagrees with key-derived resume to catch cursor-
//! construction bugs during testing. In release builds, key-based resume
//! is the sole authority and tokens are silently ignored. This divergence
//! reflects the different trust models: in-memory items are immutable after
//! construction (tokens are always consistent), while filesystem state can
//! change between connector instances.
//!
//! # Symlink handling
//!
//! Symlinks are **skipped** during the directory walk. [`std::fs::DirEntry::file_type`]
//! (backed by `d_type` on Unix) classifies each entry without following links.
//! Symlinks to files and symlinks to directories are both skipped and recorded
//! in [`FilesystemConnector::walk_warnings`]. This prevents symlink-cycle
//! hangs, root-escape via symlink targets, and snapshot inconsistency from
//! mutable symlink targets.
//!
//! Read-path operations (`open`, `read_range`) additionally open files with
//! `O_NOFOLLOW` so that a regular file replaced with a symlink between indexing
//! and reading produces an `ELOOP` error instead of following the link. This
//! closes the TOCTOU window for symlink-based root-escape.
//!
//! # Split-point heuristic
//!
//! [`choose_split_point`](EnumerationConnector::choose_split_point) selects a
//! byte-weighted median: the split key is chosen where cumulative file size
//! crosses the halfway mark, so that shards are balanced by total byte volume
//! rather than item count. Falls back to count-balanced when all files are
//! zero-size.
//!
//! # TOCTOU limitations
//!
//! The file index is built once per connector instance. Reads (`open`,
//! `read_range`) later reopen files by path. If a file is replaced, renamed,
//! or truncated between indexing and reading, the [`VersionId`] from
//! enumeration may describe a different object than what the read returns.
//! Callers requiring snapshot consistency should use version checks at a
//! higher layer (e.g., the orchestration runtime).
//!
//! # Platform and path handling
//!
//! This implementation is Unix-only because deterministic handling of non-UTF8
//! file names depends on raw `OsStr` byte access (`OsStrExt`). Item refs are
//! interpreted as relative paths; absolute and traversal components are rejected
//! before joining with the connector root.
//!
//! # Scope and limitations
//!
//! - Designed for single-threaded sequential page calls; the struct holds
//!   mutable state (`index_state`, `files`) with no interior synchronization.
//! - The file index is built once per connector instance. Directory mutations
//!   after the first enumerate call are invisible; construct a new connector
//!   to observe changes.
//! - Non-fatal walk issues (unreadable entries, symlinks, encoding failures)
//!   are recorded in [`WalkWarning`]s rather than aborting the entire index.
//!   Only root-directory failures are hard errors.
//! - [`ItemRef`] values are the raw relative-path bytes of each file and are
//!   stable for a given directory snapshot, unlike the positional indices used
//!   by the in-memory connector.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use std::ffi::OsStr;

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, TokenBytes,
        VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ObjectVersionId, StableItemId},
};

use std::os::unix::{
    ffi::OsStrExt,
    fs::{FileExt, MetadataExt, OpenOptionsExt},
};

use crate::common::{
    self, derive_stable_item_id, lower_bound, parse_u64_be, shard_bound, upper_bound,
};

/// Connector tag used to domain-separate [`StableItemId`] derivation.
///
/// All filesystem-sourced items share this tag so that identity hashes are
/// disjoint from items produced by other connector types (in-memory, git, SaaS).
const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

/// A non-fatal issue encountered during the directory walk.
///
/// Warnings are collected in [`FilesystemConnector::walk_warnings`] and do
/// not abort indexing. They report entries that were skipped due to I/O
/// errors, symlinks, encoding failures, or other non-fatal conditions.
#[derive(Debug)]
pub struct WalkWarning {
    /// Path of the entry that triggered the warning.
    pub path: PathBuf,
    /// Human-readable description of why the entry was skipped.
    pub message: String,
}

impl WalkWarning {
    fn io(path: &Path, op: &str, err: &io::Error) -> Self {
        Self {
            path: path.to_path_buf(),
            message: format!("{op} failed: {err}"),
        }
    }

    fn skipped(path: &Path, reason: &str) -> Self {
        Self {
            path: path.to_path_buf(),
            message: reason.to_owned(),
        }
    }
}

/// Tri-state indexing lifecycle.
///
/// - `NotIndexed`: walk has not been attempted yet.
/// - `Indexed`: walk succeeded; `files` is populated and sorted.
/// - `Failed`: walk failed with a permanent error; the message is memoized
///   so that repeated calls return immediately without redundant re-walks.
///   Only permanent failures are memoized — retryable failures leave the
///   state as `NotIndexed` to permit re-attempts.
enum IndexState {
    NotIndexed,
    Indexed,
    Failed(String),
}

/// One entry in the sorted file index.
///
/// Constructed during [`FilesystemConnector::ensure_indexed`] and immutable
/// afterward. Fields are pre-computed at index time so that enumeration pages
/// can be assembled by slice iteration without re-visiting the filesystem.
///
/// The canonical key bytes double as the `ItemRef` payload (both are the
/// encoded relative path), so no separate `rel_bytes` field is needed.
/// `ItemRef` values are derived from `key.as_bytes()` at page-emission time.
#[derive(Debug)]
struct FileEntry {
    /// Canonical key derived from normalized relative path bytes.
    /// Also serves as the `ItemRef` source -- `key.as_bytes()` yields the
    /// relative-path payload needed for read operations.
    key: ItemKey,
    /// Deterministic per-item identity derived from connector tag + key.
    stable_item_id: StableItemId,
    /// Metadata-derived object version (weak freshness signal).
    version: VersionId,
    /// File size observed during index build.
    size: u64,
}

impl common::KeyedEntry for FileEntry {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

impl common::SizedEntry for FileEntry {
    fn entry_size(&self) -> u64 {
        self.size
    }
}

/// Deterministic filesystem connector rooted at a local directory.
///
/// The first enumerate or split call builds an in-memory sorted file index.
/// Subsequent enumeration and split-hint calls use binary search over that
/// stable index.
///
/// # Resume semantics
///
/// Cursor progression is keyed by `Cursor::last_key`; tokens are optional
/// advisory state (`emit_tokens` defaults to `false`). When tokens are enabled,
/// debug builds assert that a well-formed token index matches the key-derived
/// resume position.
///
/// # Symlink handling
///
/// Symlinks are skipped during indexing and recorded in
/// [`walk_warnings`](Self::walk_warnings). This prevents symlink-cycle hangs
/// and root-escape attacks.
///
/// # TOCTOU and consistency
///
/// The file index is built once per connector instance. Reads (`open`,
/// `read_range`) later reopen files by path (or use a single-entry FD cache
/// keyed on [`ItemRef`] bytes). If a file is replaced, renamed, or truncated
/// between indexing and reading, the [`VersionId`] from enumeration may
/// describe a different object than what the read returns. The FD cache
/// widens this window slightly for consecutive reads on the same item, since
/// the cached descriptor may outlive a concurrent replace. Callers requiring
/// snapshot consistency should use version checks at a higher layer. See the
/// module-level [TOCTOU limitations](self#toctou-limitations) section for
/// details.
pub struct FilesystemConnector {
    /// Absolute or relative directory root; all indexed paths are relative to this.
    root: PathBuf,
    /// When `true`, each returned [`EnumerationPage`] cursor carries an opaque
    /// big-endian `u64` token encoding the next absolute index. Defaults to
    /// `false` because key-based resume is always authoritative.
    emit_tokens: bool,
    /// Maximum directory nesting depth during the walk. Directories deeper
    /// than this limit are skipped with a [`WalkWarning`]. The root directory
    /// is at depth 0. Defaults to 512.
    max_walk_depth: usize,
    /// Indexing lifecycle state. Transitions once from `NotIndexed` to either
    /// `Indexed` or `Failed`; subsequent calls use the memoized result.
    index_state: IndexState,
    /// Sorted file index built by [`ensure_indexed`](Self::ensure_indexed).
    /// Empty until the first enumerate or split call triggers a walk.
    files: Vec<FileEntry>,
    /// Non-fatal issues encountered during the directory walk. Populated
    /// alongside `files` during [`ensure_indexed`](Self::ensure_indexed).
    walk_warnings: Vec<WalkWarning>,
    /// Single-entry file-descriptor cache for sequential
    /// [`ReadConnector::read_range`] calls. Avoids re-opening the same file
    /// for consecutive chunked reads on the same item. Keyed on the raw
    /// [`ItemRef`] bytes to avoid `resolve_item_ref` + `PathBuf` allocation
    /// on cache hits.
    cached_file: Option<(Box<[u8]>, fs::File)>,
}

impl FilesystemConnector {
    /// Default maximum directory nesting depth for the walk. Directories
    /// deeper than this are skipped with a warning.
    const DEFAULT_MAX_WALK_DEPTH: usize = 512;

    /// Create a connector rooted at `root`.
    ///
    /// Indexing is lazy and performed on the first enumerate/split call.
    ///
    /// Token emission is disabled by default; enable it via [`with_tokens`].
    ///
    /// [`with_tokens`]: Self::with_tokens
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            emit_tokens: false,
            max_walk_depth: Self::DEFAULT_MAX_WALK_DEPTH,
            index_state: IndexState::NotIndexed,
            files: Vec::new(),
            walk_warnings: Vec::new(),
            cached_file: None,
        }
    }

    /// Enable or disable opaque pagination token emission.
    ///
    /// Tokens carry the next index as big-endian `u64`. They are never the
    /// authoritative resume source; `Cursor::last_key` remains primary.
    #[must_use]
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    /// Set the maximum directory nesting depth for the walk.
    ///
    /// The root directory is at depth 0. Subdirectories exceeding this limit
    /// are skipped with a [`WalkWarning`]. Defaults to 512.
    #[must_use]
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_walk_depth = max_depth;
        self
    }

    /// Non-fatal issues collected during the directory walk.
    ///
    /// Returns an empty slice until the first enumerate or split call
    /// triggers indexing. Warnings include skipped symlinks, unreadable
    /// entries, and encoding failures.
    pub fn walk_warnings(&self) -> &[WalkWarning] {
        &self.walk_warnings
    }

    /// Build the file index once on first use.
    ///
    /// On success, transitions to `Indexed` and populates `files`.
    /// On permanent failure, transitions to `Failed` and memoizes the error
    /// so repeated calls return immediately without redundant re-walks.
    /// Retryable failures leave the state as `NotIndexed` to permit re-attempts.
    fn ensure_indexed(&mut self) -> Result<(), EnumerateError> {
        match &self.index_state {
            IndexState::Indexed => return Ok(()),
            IndexState::Failed(message) => {
                return Err(EnumerateError::permanent(message.clone()));
            }
            IndexState::NotIndexed => {}
        }

        let mut files = Vec::new();
        let mut warnings = Vec::new();
        match walk_dir_collect_files(&self.root, self.max_walk_depth, &mut files, &mut warnings) {
            Ok(()) => {
                files.sort_unstable_by(|left, right| left.key.cmp(&right.key));
                debug_assert!(
                    files.windows(2).all(|w| w[0].key != w[1].key),
                    "filesystem walk produced duplicate keys after encoding"
                );
                self.files = files;
                self.walk_warnings = warnings;
                self.index_state = IndexState::Indexed;
                Ok(())
            }
            Err(err) => {
                let permanent = !err.is_retryable();
                let message = err.into_message();
                self.walk_warnings = warnings;
                if permanent {
                    self.index_state = IndexState::Failed(message.clone());
                }
                // Retryable errors leave index_state as NotIndexed so
                // the next call re-attempts the walk.
                Err(if permanent {
                    EnumerateError::permanent(message)
                } else {
                    EnumerateError::retryable(message)
                })
            }
        }
    }

    /// Enumerate one page over explicit half-open bounds `[start, end)`.
    ///
    /// This helper bypasses [`ShardSpec`] decoding so tests can exercise paging
    /// logic with explicit bounds.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(Some(start), Some(end), cursor, budgets)
    }

    /// Return a split-point hint over explicit half-open bounds `[start, end)`.
    ///
    /// Like [`enumerate_page_range`], this bypasses [`ShardSpec`] decoding.
    ///
    /// [`enumerate_page_range`]: Self::enumerate_page_range
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start), Some(end), cursor)
    }

    /// Core paging implementation shared by shard-based and explicit-range APIs.
    ///
    /// # Behavior
    ///
    /// - Bounds are treated as half-open `[start, end)` ranges.
    /// - Cursor advancement uses the first index strictly greater than
    ///   `cursor.last_key()`, preventing duplicate emission on resume.
    /// - If the deadline budget is already expired, returns a retryable error
    ///   (avoids ambiguity with an empty EOF page).
    ///
    /// # Errors
    ///
    /// Propagates retryable indexing I/O failures from [`ensure_indexed`] and
    /// returns permanent errors for structural invariant violations (for
    /// example, invalid wrapper conversions or index conversion overflow).
    fn enumerate_page_bounds(
        &mut self,
        start: Option<&ItemKey>,
        end: Option<&ItemKey>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.ensure_indexed()?;

        if budgets.is_expired_at(Instant::now()) {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }

        if let (Some(s), Some(e)) = (start, end)
            && s > e
        {
            return Err(EnumerateError::permanent("shard start key exceeds end key"));
        }

        let range_start = start.map_or(0, |bound| lower_bound(&self.files, bound.as_bytes()));
        let range_end = end.map_or(self.files.len(), |bound| {
            lower_bound(&self.files, bound.as_bytes())
        });

        let mut start_idx = range_start;
        if let Some(last_key) = cursor.last_key() {
            let expected = upper_bound(&self.files, last_key.as_bytes());
            start_idx = start_idx.max(expected);

            // Tokens are advisory. In debug builds, check that any provided
            // token agrees with key-based resume state to catch inconsistent
            // cursor construction during tests.
            #[cfg(debug_assertions)]
            if self.emit_tokens
                && let Some(token) = cursor.token()
                && let Some(token_idx_u64) = parse_u64_be(token.as_bytes())
                && let Ok(token_idx) = usize::try_from(token_idx_u64)
            {
                debug_assert_eq!(
                    token_idx, expected,
                    "token index {token_idx} disagrees with key-derived resume position {expected}"
                );
            }
        }

        if start_idx >= range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(range_end - start_idx);
        let mut out = Vec::with_capacity(take);
        for file in &self.files[start_idx..(start_idx + take)] {
            let item_ref = ItemRef::try_from_slice(file.key.as_bytes())
                .map_err(|err| EnumerateError::permanent(format!("invalid item_ref: {err}")))?;
            out.push(
                ScanItem::new(
                    file.key.clone(),
                    item_ref,
                    file.stable_item_id,
                    file.version,
                )
                .with_size_hint(file.size),
            );
        }

        let last_key = out
            .last()
            .expect("non-empty page must have a last key")
            .item_key()
            .clone();
        let next_cursor = if self.emit_tokens {
            let next_idx = start_idx
                .checked_add(out.len())
                .and_then(|sum| u64::try_from(sum).ok())
                .ok_or_else(|| EnumerateError::permanent("next index exceeds capacity"))?;
            let token = TokenBytes::try_from_slice(&next_idx.to_be_bytes())
                .map_err(|err| EnumerateError::permanent(format!("invalid token: {err}")))?;
            Cursor::with_token(last_key, token)
        } else {
            Cursor::with_last_key(last_key)
        };

        Ok(EnumerationPage::new(out, next_cursor))
    }

    /// Choose a byte-weighted split-point hint from the unconsumed portion of
    /// the range.
    ///
    /// The split key is placed where cumulative file size crosses the halfway
    /// mark, producing shards balanced by total byte volume rather than item
    /// count. Falls back to count-balanced when all files are zero-size.
    ///
    /// Returns `None` when fewer than two items remain, when the candidate
    /// would not advance beyond `cursor.last_key()`, or when the candidate
    /// falls at/above the upper bound.
    fn choose_split_point_bounds(
        &mut self,
        start: Option<&ItemKey>,
        end: Option<&ItemKey>,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.ensure_indexed()?;

        if let (Some(s), Some(e)) = (start, end)
            && s > e
        {
            return Err(EnumerateError::permanent("shard start key exceeds end key"));
        }

        let range_start = start.map_or(0, |bound| lower_bound(&self.files, bound.as_bytes()));
        let range_end = end.map_or(self.files.len(), |bound| {
            lower_bound(&self.files, bound.as_bytes())
        });
        let resume_start = cursor.last_key().map_or(range_start, |last| {
            upper_bound(&self.files, last.as_bytes())
        });

        let start_idx = range_start.max(resume_start);
        let split_idx = match common::choose_split_index(&self.files, start_idx, range_end) {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let candidate = &self.files[split_idx].key;

        // Splits must move forward relative to cursor position.
        if cursor.last_key().is_some_and(|last| candidate <= last) {
            return Ok(None);
        }
        // Rejecting candidates at/above `end` avoids empty right-hand shards.
        if end.is_some_and(|upper| candidate >= upper) {
            return Ok(None);
        }

        Ok(Some(candidate.clone()))
    }

    /// Resolve an item reference into an absolute path under `self.root`.
    ///
    /// The reference bytes are interpreted as a Unix path payload. Absolute
    /// paths and lexical traversal (`..`, root, or platform prefix components)
    /// are rejected before joining with the connector root.
    ///
    /// Uses zero-copy `OsStr::from_bytes` on Unix to avoid allocating an
    /// intermediate `OsString`.
    fn resolve_item_ref(&self, item_ref: &ItemRef) -> Result<PathBuf, ReadError> {
        if item_ref.as_bytes().contains(&0) {
            return Err(ReadError::permanent("item_ref contains null bytes"));
        }

        let rel = OsStr::from_bytes(item_ref.as_bytes());
        let rel_path = Path::new(rel);
        if rel_path.is_absolute() {
            return Err(ReadError::permanent("item_ref must be a relative path"));
        }
        if rel_path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        }) {
            return Err(ReadError::permanent(
                "item_ref contains forbidden path traversal components",
            ));
        }
        Ok(self.root.join(rel_path))
    }

    /// Open a file with `O_NOFOLLOW` to prevent symlink traversal.
    ///
    /// If the path is a symlink (e.g., a file replaced after indexing),
    /// the open fails with `ELOOP`, which is classified as a permanent error.
    /// This prevents TOCTOU root-escape where an indexed regular file is
    /// replaced with a symlink pointing outside the connector root.
    fn open_nofollow(path: &Path) -> Result<fs::File, ReadError> {
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|err| classify_io_read_error("open", &err))
    }

    /// Open a file or return the cached handle if the item ref matches.
    ///
    /// Single-entry cache optimized for sequential `read_range` calls on the
    /// same item. Keyed on the raw [`ItemRef`] bytes so cache hits avoid
    /// `resolve_item_ref` and `PathBuf` allocation entirely. On cache miss,
    /// the previous handle (if any) is dropped, the item ref is resolved to
    /// a path, and a new file is opened with `O_NOFOLLOW`.
    fn get_or_open_cached(&mut self, item_ref: &ItemRef) -> Result<&fs::File, ReadError> {
        let ref_bytes = item_ref.as_bytes();
        let need_open = self
            .cached_file
            .as_ref()
            .is_none_or(|(key, _)| &**key != ref_bytes);
        if need_open {
            let path = self.resolve_item_ref(item_ref)?;
            let file = Self::open_nofollow(&path)?;
            self.cached_file = Some((ref_bytes.into(), file));
        }
        Ok(&self.cached_file.as_ref().unwrap().1)
    }
}

impl EnumerationConnector for FilesystemConnector {
    /// Report static capabilities.
    ///
    /// The filesystem connector always supports key-seek, range-read, and
    /// split hints. Token resume tracks the `emit_tokens` configuration flag.
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    /// Decode shard key-range bounds from [`ShardSpec`] and delegate to
    /// the internal paging implementation.
    ///
    /// Empty shard bounds are interpreted as unbounded (full key space).
    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = shard_bound(shard.key_range_start(), "start")?;
        let end = shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start.as_ref(), end.as_ref(), cursor, budgets)
    }

    /// Decode shard key-range bounds from [`ShardSpec`] and delegate to
    /// the internal split-point selection.
    ///
    /// Budgets are accepted for trait conformance but not consumed: split-point
    /// selection is a metadata-only operation with no I/O or time-bounded work.
    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = shard_bound(shard.key_range_start(), "start")?;
        let end = shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start.as_ref(), end.as_ref(), cursor)
    }
}

impl ReadConnector for FilesystemConnector {
    /// Open a file for streaming whole-object reads.
    ///
    /// Opens with `O_NOFOLLOW` to prevent symlink traversal, then verifies via
    /// `fstat` on the descriptor that the target is a regular file and within
    /// the `max_bytes` budget before returning a reader handle.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let path = self.resolve_item_ref(item_ref)?;
        let file = Self::open_nofollow(&path)?;
        let metadata = file
            .metadata()
            .map_err(|err| classify_io_read_error("fstat", &err))?;
        if !metadata.is_file() {
            return Err(ReadError::permanent("path is not a regular file"));
        }
        if metadata.len() > budgets.max_bytes() {
            return Err(ReadError::permanent("item exceeds max_bytes budget"));
        }
        Ok(Box::new(file))
    }

    /// Read a byte range starting at `offset` into `dst`.
    ///
    /// The read length is clamped to `min(dst.len(), max_bytes)`. `offset` past
    /// EOF naturally yields `Ok(0)` from the underlying `read_at` / `pread`.
    ///
    /// On Unix, uses [`FileExt::read_at`] (positional `pread`) to avoid seeking.
    /// A single-entry FD cache keyed on [`ItemRef`] bytes avoids re-opening
    /// (and re-resolving the path for) consecutive chunked reads on the same
    /// item. Note that the cached FD may outlive a concurrent file replace,
    /// reading stale content; see the struct-level TOCTOU section.
    ///
    /// Returns a permanent error if `offset + dst.len()` would overflow `u64`.
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

        let file = self.get_or_open_cached(item_ref)?;
        file.read_at(&mut dst[..allowed], offset)
            .map_err(|err| classify_io_read_error("read_at", &err))
    }
}

/// Classify an I/O error for read operations.
///
/// `NotFound` and `PermissionDenied` are permanent (retrying will not help
/// without external changes). All other I/O errors are treated as potentially
/// transient.
fn classify_io_read_error(op: &str, err: &io::Error) -> ReadError {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            ReadError::permanent(format!("{op} failed: {err}"))
        }
        _ => ReadError::retryable(format!("{op} failed: {err}")),
    }
}

/// Classify an I/O error for enumeration operations.
///
/// Same classification as [`classify_io_read_error`] but returns
/// [`EnumerateError`] and includes the path in the message.
fn classify_io_enumerate_error(op: &str, path: &Path, err: &io::Error) -> EnumerateError {
    match err.kind() {
        io::ErrorKind::NotFound | io::ErrorKind::PermissionDenied => {
            EnumerateError::permanent(format!("{op} failed for {}: {err}", path.display()))
        }
        _ => EnumerateError::retryable(format!("{op} failed for {}: {err}", path.display())),
    }
}

/// Iteratively collect regular files under `root`, appending [`FileEntry`]s
/// to `out`.
///
/// Uses an explicit directory stack instead of recursion to avoid
/// stack-overflow on deeply nested trees. Each directory's entries are
/// classified via [`DirEntry::file_type`] (which uses `d_type` on Unix and
/// does not follow symlinks):
///
/// - **Symlinks** are skipped and recorded in `warnings`.
/// - **Directories** are pushed onto the stack for later processing, up to
///   `max_depth` levels deep (root = depth 0). Directories exceeding the
///   limit are skipped with a warning.
/// - **Regular files** are indexed via `symlink_metadata` (no follow).
/// - **Special files** (devices, FIFOs, sockets) are skipped and warned.
///
/// Root-directory failures are hard errors; all other failures are recorded
/// as warnings and the walk continues.
///
/// # Errors
///
/// Returns a permanent or retryable error only when the root directory
/// itself is inaccessible.
fn walk_dir_collect_files(
    root: &Path,
    max_depth: usize,
    out: &mut Vec<FileEntry>,
    warnings: &mut Vec<WalkWarning>,
) -> Result<(), EnumerateError> {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        let is_root = dir == root;
        let reader = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(err) => {
                if is_root {
                    return Err(classify_io_enumerate_error("read_dir", &dir, &err));
                }
                warnings.push(WalkWarning::io(&dir, "read_dir", &err));
                continue;
            }
        };

        for entry_result in reader {
            let entry = match entry_result {
                Ok(e) => e,
                Err(err) => {
                    warnings.push(WalkWarning::io(&dir, "read_dir entry", &err));
                    continue;
                }
            };

            let path = entry.path();

            // DirEntry::file_type() uses d_type on Unix -- no extra syscall, no
            // symlink following. On filesystems that report DT_UNKNOWN, std
            // falls back to lstat internally.
            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(err) => {
                    warnings.push(WalkWarning::io(&path, "file_type", &err));
                    continue;
                }
            };

            if file_type.is_symlink() {
                warnings.push(WalkWarning::skipped(&path, "symlink"));
                continue;
            }

            if file_type.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                } else {
                    warnings.push(WalkWarning::skipped(&path, "exceeded maximum walk depth"));
                }
                continue;
            }

            if !file_type.is_file() {
                warnings.push(WalkWarning::skipped(&path, "special file (not regular)"));
                continue;
            }

            // Regular file: get metadata for size/mtime/ino.
            // symlink_metadata avoids following if a TOCTOU race replaced
            // the file with a symlink between file_type() and now.
            let metadata = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(err) => {
                    warnings.push(WalkWarning::io(&path, "metadata", &err));
                    continue;
                }
            };

            // TOCTOU guard: if the entry was replaced between file_type()
            // and symlink_metadata(), the type may have changed.
            if !metadata.is_file() {
                continue;
            }

            let rel = match path.strip_prefix(root) {
                Ok(r) => r,
                Err(_) => {
                    warnings.push(WalkWarning::skipped(&path, "path escaped connector root"));
                    continue;
                }
            };

            let rel_bytes = match encode_rel_path(rel) {
                Ok(b) => b,
                Err(err) => {
                    warnings.push(WalkWarning::skipped(
                        &path,
                        &format!("path encoding failed: {}", err.message()),
                    ));
                    continue;
                }
            };

            let key = match ItemKey::try_from_vec(rel_bytes) {
                Ok(k) => k,
                Err(err) => {
                    warnings.push(WalkWarning::skipped(
                        &path,
                        &format!("invalid file key: {err}"),
                    ));
                    continue;
                }
            };

            let stable_item_id = derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, &key);
            let version = VersionId::Weak(derive_fs_version_id(&metadata));

            out.push(FileEntry {
                key,
                stable_item_id,
                version,
                size: metadata.len(),
            });
        }
    }

    Ok(())
}

/// Encode a root-relative path into canonical connector key bytes.
///
/// Only [`Component::Normal`](std::path::Component::Normal) segments are
/// accepted; any traversal (`..`), root, or prefix component is a permanent
/// error. Segments are joined with a literal `/` byte so that:
///
/// - Key ordering matches lexicographic path ordering on Unix.
/// - The encoding is reversible: splitting on `/` recovers the original
///   path components (assuming no component contains a literal `/`, which
///   Unix forbids in filenames).
///
/// Returns a permanent error if the path is empty after encoding.
fn encode_rel_path(rel: &Path) -> Result<Vec<u8>, EnumerateError> {
    let mut out = Vec::new();
    for component in rel.components() {
        let normal = match component {
            std::path::Component::Normal(segment) => segment,
            _ => {
                return Err(EnumerateError::permanent(format!(
                    "path contains non-normal component: {}",
                    rel.display()
                )));
            }
        };
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(normal.as_bytes());
    }
    if out.is_empty() {
        return Err(EnumerateError::permanent(
            "relative file path encoded to an empty key",
        ));
    }
    Ok(out)
}

/// Build a weak [`ObjectVersionId`] from already-fetched file metadata.
///
/// Packs four 8-byte big-endian fields into a fixed 32-byte buffer:
/// `[mtime | mtime_nsec | len | ino]`. This avoids content hashing during
/// index build while still producing a distinct version when any of the
/// commonly-mutated metadata fields change.
///
/// The resulting ID is wrapped in [`VersionId::Weak`] by the caller to
/// signal that it is a metadata-derived freshness hint, not a
/// content-addressed digest.
fn derive_fs_version_id(metadata: &fs::Metadata) -> ObjectVersionId {
    // Fixed layout: each field occupies exactly 8 bytes at a known offset.
    let mut encoded = [0u8; 32];
    encoded[0..8].copy_from_slice(&metadata.mtime().to_be_bytes());
    encoded[8..16].copy_from_slice(&metadata.mtime_nsec().to_be_bytes());
    encoded[16..24].copy_from_slice(&metadata.len().to_be_bytes());
    encoded[24..32].copy_from_slice(&metadata.ino().to_be_bytes());
    ObjectVersionId::from_version_bytes(&encoded)
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
