//! Deterministic filesystem-backed connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], an implementation of
//! [`gossip_contracts::connector::EnumerationConnector`] and
//! [`gossip_contracts::connector::ReadConnector`] that indexes regular files
//! under a root directory and serves shard-friendly key-range scans.
//!
//! # Algorithm
//!
//! 1. **Lazy indexing** -- The first enumerate/split call recursively walks the
//!    root, collecting regular files only.
//! 2. **Canonical path encoding** -- Each relative path is encoded to raw bytes
//!    with `/` separators and reused for both [`ItemKey`] and [`ItemRef`].
//! 3. **Deterministic serving** -- Entries are globally sorted by key, then
//!    pagination and split hints resolve bounds via binary search.
//!
//! # Determinism and trade-offs
//!
//! - Enumeration order is stable for a fixed directory snapshot because each
//!   directory's entries are sorted by raw filename bytes before recursion, then
//!   a global key sort is applied.
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
//!   mutable state (`indexed`, `files`) with no interior synchronization.
//! - The file index is built once per connector instance. Directory mutations
//!   after the first enumerate call are invisible; construct a new connector
//!   to observe changes.
//! - Symlinks are transparently resolved via `fs::metadata` (which follows
//!   links): symlinks to regular files are indexed normally, symlinks to
//!   directories are recursed into, and dangling symlinks produce retryable
//!   errors. Device nodes, FIFOs, and sockets are silently skipped.
//! - [`ItemRef`] values are the raw relative-path bytes of each file and are
//!   stable for a given directory snapshot, unlike the positional indices used
//!   by the in-memory connector.

use std::{
    fs, io,
    path::{Path, PathBuf},
    time::Instant,
};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, TokenBytes,
        VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ItemIdentityKey, ObjectVersionId, StableItemId},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::{OsStrExt, OsStringExt},
    fs::MetadataExt,
};

/// Connector tag used to domain-separate [`StableItemId`] derivation.
///
/// All filesystem-sourced items share this tag so that identity hashes are
/// disjoint from items produced by other connector types (in-memory, git, SaaS).
const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

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
pub struct FilesystemConnector {
    /// Absolute or relative directory root; all indexed paths are relative to this.
    root: PathBuf,
    /// When `true`, each returned [`EnumerationPage`] cursor carries an opaque
    /// big-endian `u64` token encoding the next absolute index. Defaults to
    /// `false` because key-based resume is always authoritative.
    emit_tokens: bool,
    /// Set once after the first successful [`ensure_indexed`](Self::ensure_indexed)
    /// call. Guards against redundant re-walks.
    indexed: bool,
    /// Sorted file index built by [`ensure_indexed`](Self::ensure_indexed).
    /// Empty until the first enumerate or split call triggers a walk.
    files: Vec<FileEntry>,
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
    /// Also serves as the `ItemRef` source — `key.as_bytes()` yields the
    /// relative-path payload needed for read operations.
    key: ItemKey,
    /// Deterministic per-item identity derived from connector tag + key.
    stable_item_id: StableItemId,
    /// Metadata-derived object version (weak freshness signal).
    version: VersionId,
    /// File size observed during index build.
    size: u64,
}

impl FilesystemConnector {
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
            indexed: false,
            files: Vec::new(),
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

    /// Build the file index once on first use.
    ///
    /// The index is intentionally immutable afterward. If the directory changes
    /// on disk, callers must construct a new connector to observe those changes.
    fn ensure_indexed(&mut self) -> Result<(), EnumerateError> {
        if self.indexed {
            return Ok(());
        }

        #[cfg(not(unix))]
        {
            return Err(EnumerateError::permanent(
                "FilesystemConnector indexing is unsupported on non-unix targets",
            ));
        }

        #[cfg(unix)]
        {
            let mut files = Vec::new();
            walk_dir_collect_files(&self.root, &self.root, &mut files)?;
            files.sort_by(|left, right| left.key.cmp(&right.key));
            self.files = files;
            self.indexed = true;
            Ok(())
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
    /// - If the deadline budget is already expired, returns an empty page with
    ///   the original cursor.
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
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let range_start = start.map_or(0, |bound| lower_bound_file(&self.files, bound.as_bytes()));
        let range_end = end.map_or(self.files.len(), |bound| {
            lower_bound_file(&self.files, bound.as_bytes())
        });

        let mut start_idx = range_start;
        if let Some(last_key) = cursor.last_key() {
            let expected = upper_bound_file(&self.files, last_key.as_bytes());
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

    /// Choose a median split hint from the unconsumed portion of the range.
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

        let range_start = start.map_or(0, |bound| lower_bound_file(&self.files, bound.as_bytes()));
        let range_end = end.map_or(self.files.len(), |bound| {
            lower_bound_file(&self.files, bound.as_bytes())
        });
        let resume_start = cursor.last_key().map_or(range_start, |last| {
            upper_bound_file(&self.files, last.as_bytes())
        });

        let start_idx = range_start.max(resume_start);
        if range_end.saturating_sub(start_idx) < 2 {
            return Ok(None);
        }

        let split_idx = start_idx + (range_end - start_idx) / 2;
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

    /// Decode a shard bound where `[]` means unbounded.
    fn shard_bound(bound: &[u8], which: &'static str) -> Result<Option<ItemKey>, EnumerateError> {
        if bound.is_empty() {
            return Ok(None);
        }
        ItemKey::try_from_slice(bound)
            .map(Some)
            .map_err(|err| EnumerateError::permanent(format!("invalid shard {which} bound: {err}")))
    }

    /// Resolve an item reference into an absolute path under `self.root`.
    ///
    /// The reference bytes are interpreted as a Unix path payload. Absolute
    /// paths and lexical traversal (`..`, root, or platform prefix components)
    /// are rejected before joining with the connector root.
    fn resolve_item_ref(&self, item_ref: &ItemRef) -> Result<PathBuf, ReadError> {
        #[cfg(not(unix))]
        {
            let _ = item_ref;
            return Err(ReadError::unsupported(
                "filesystem item_ref decoding is unsupported on non-unix targets",
            ));
        }

        #[cfg(unix)]
        {
            let rel = std::ffi::OsString::from_vec(item_ref.as_bytes().to_vec());
            let rel_path = PathBuf::from(rel);
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
        let start = Self::shard_bound(shard.key_range_start(), "start")?;
        let end = Self::shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start.as_ref(), end.as_ref(), cursor, budgets)
    }

    /// Decode shard key-range bounds from [`ShardSpec`] and delegate to
    /// the internal split-point selection.
    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = Self::shard_bound(shard.key_range_start(), "start")?;
        let end = Self::shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start.as_ref(), end.as_ref(), cursor)
    }
}

impl ReadConnector for FilesystemConnector {
    /// Open a file for streaming whole-object reads.
    ///
    /// Unlike `read_range`, this path can preflight total object size via
    /// metadata and reject files larger than `max_bytes` before returning a
    /// reader handle.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let path = self.resolve_item_ref(item_ref)?;
        let file = fs::File::open(&path)
            .map_err(|err| ReadError::retryable(format!("open failed: {err}")))?;
        let metadata = file
            .metadata()
            .map_err(|err| ReadError::retryable(format!("metadata failed: {err}")))?;
        if metadata.len() > budgets.max_bytes() {
            return Err(ReadError::permanent("item exceeds max_bytes budget"));
        }
        Ok(Box::new(file))
    }

    /// Read a byte range starting at `offset` into `dst`.
    ///
    /// The read length is clamped to `min(dst.len(), max_bytes)`. `offset` past
    /// EOF naturally yields `Ok(0)` from the underlying file read.
    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        use std::io::{Read as _, Seek as _, SeekFrom};

        if offset.checked_add(dst.len() as u64).is_none() {
            return Err(ReadError::permanent("offset + dst length overflow"));
        }

        let max_bytes = usize::try_from(budgets.max_bytes()).unwrap_or(usize::MAX);
        let allowed = dst.len().min(max_bytes);
        if allowed == 0 {
            return Ok(0);
        }

        let path = self.resolve_item_ref(item_ref)?;
        let mut file = fs::File::open(path)
            .map_err(|err| ReadError::retryable(format!("open failed: {err}")))?;
        file.seek(SeekFrom::Start(offset))
            .map_err(|err| ReadError::retryable(format!("seek failed: {err}")))?;
        file.read(&mut dst[..allowed])
            .map_err(|err| ReadError::retryable(format!("read failed: {err}")))
    }
}

/// Return the first index whose key is `>= key`.
fn lower_bound_file(files: &[FileEntry], key: &[u8]) -> usize {
    files.partition_point(|file| file.key.as_bytes() < key)
}

/// Return the first index whose key is `> key`.
///
/// Used for resume progression so the last emitted key is never re-emitted.
fn upper_bound_file(files: &[FileEntry], key: &[u8]) -> usize {
    files.partition_point(|file| file.key.as_bytes() <= key)
}

/// Parse an 8-byte big-endian index/token payload.
///
/// Returning `None` for non-8-byte payloads lets callers decide whether to
/// treat malformed bytes as hard errors or advisory-state misses.
fn parse_u64_be(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// Derive connector-scoped stable identity from canonical key bytes.
fn derive_stable_item_id(key: &ItemKey) -> StableItemId {
    ItemIdentityKey::new(FILESYSTEM_CONNECTOR_TAG, key.as_bytes()).stable_id()
}

/// Recursively collect regular files under `dir`, appending [`FileEntry`]s to
/// `out` in deterministic order.
///
/// Determinism is enforced by sorting each directory's entries by raw filename
/// bytes before descending, then sorting the final `Vec<FileEntry>` by key in
/// [`FilesystemConnector::ensure_indexed`]. The two-level sort (local then
/// global) keeps the walk order predictable even though the final key sort is
/// what matters for enumeration.
///
/// Symlinks are transparently resolved via `fs::metadata` (which follows
/// links): symlinks to regular files are indexed, symlinks to directories
/// are recursed into, and dangling symlinks produce retryable errors. Device
/// nodes, FIFOs, and sockets are silently skipped; only entries whose
/// resolved metadata reports `is_file()` produce index entries.
///
/// # Errors
///
/// Returns a retryable error for I/O failures (directory read, metadata fetch)
/// and a permanent error if a collected path escapes the connector root or
/// encodes to an invalid [`ItemKey`].
#[cfg(unix)]
fn walk_dir_collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<FileEntry>,
) -> Result<(), EnumerateError> {
    let mut entries = Vec::new();
    let reader = fs::read_dir(dir).map_err(|err| {
        EnumerateError::retryable(format!("read_dir failed for {}: {err}", dir.display()))
    })?;
    for entry in reader {
        let entry = entry.map_err(|err| {
            EnumerateError::retryable(format!(
                "read_dir entry failed for {}: {err}",
                dir.display()
            ))
        })?;
        entries.push(entry);
    }

    entries.sort_by(|left, right| {
        left.file_name()
            .as_bytes()
            .cmp(right.file_name().as_bytes())
    });

    for entry in entries {
        let path = entry.path();
        let metadata = fs::metadata(&path).map_err(|err| {
            EnumerateError::retryable(format!("metadata failed for {}: {err}", path.display()))
        })?;
        if metadata.is_dir() {
            walk_dir_collect_files(root, &path, out)?;
            continue;
        }
        // Skip non-regular files (symlinks, devices, FIFOs, sockets).
        // Symlinks are already resolved by `fs::metadata` (follows links),
        // so this branch catches only true special files.
        if !metadata.is_file() {
            continue;
        }

        let rel = path.strip_prefix(root).map_err(|_| {
            EnumerateError::permanent(format!("path escaped connector root: {}", path.display()))
        })?;
        let rel_bytes = encode_rel_path(rel)?;
        let key = ItemKey::try_from_slice(&rel_bytes)
            .map_err(|err| EnumerateError::permanent(format!("invalid file key: {err}")))?;
        let stable_item_id = derive_stable_item_id(&key);
        let version = VersionId::Weak(derive_fs_version_id(&metadata));

        out.push(FileEntry {
            key,
            stable_item_id,
            version,
            size: metadata.len(),
        });
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
#[cfg(unix)]
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
#[cfg(unix)]
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
#[cfg(unix)]
#[path = "filesystem_tests.rs"]
mod tests;
