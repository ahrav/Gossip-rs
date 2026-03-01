//! Deterministic filesystem-backed connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], an implementation of
//! [`gossip_contracts::connector::EnumerationConnector`] and
//! [`gossip_contracts::connector::ReadConnector`] that indexes regular files
//! under a root directory and serves shard-friendly key-range scans.
//!
//! # Algorithm
//!
//! 1. **Lazy indexing** -- The first enumerate, split, or read call walks the
//!    root using an explicit stack (no recursion), collecting regular files
//!    only. Symlinks are skipped. This allows a fresh connector instance to
//!    read [`ItemRef`]s obtained from a compatible instance over the same root
//!    without requiring explicit enumeration first.
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
//!   `inode`, `dev`) to avoid content hashing during index build.
//!
//! # Pooled toxic-byte page assembly
//!
//! Enumeration uses a shared-slot page assembly path: filesystem [`ItemRef`]
//! bytes are identical to [`ItemKey`] bytes, so each item's bytes are staged
//! once and both wrappers are materialized from that same slot.
//!
//! This cuts key/ref staging copies versus the generic two-slot path while
//! keeping wrapper cloning allocation-free in the HOT emit loop. The
//! optimization depends on the key==ref byte invariant from path encoding.
//!
//! Staging and wrapper reconstruction failures are reported as permanent
//! `EnumerateError`s because page sizes are derived from already-validated
//! contract values; failure indicates internal accounting/resource exhaustion,
//! not external cursor drift.
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
//! # Trust model
//!
//! This advisory-only treatment differs from the in-memory connector's
//! O(1) token fast path with key-validation fallback, reflecting different
//! trust models: in-memory items are immutable after construction (tokens
//! are always consistent), while filesystem state can change between
//! connector instances.
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
//! Read-path operations (`open`, `read_range`) use component-by-component
//! `openat` traversal from a root directory file descriptor, applying
//! `O_NOFOLLOW` at every path component. This prevents symlink following on
//! intermediate directories, not just the leaf. Files are opened with
//! `O_NONBLOCK` to prevent blocking on FIFOs or devices, validated via
//! `fstat` as regular files, and then `O_NONBLOCK` is cleared (`fcntl
//! F_SETFL`) before any read occurs. `ELOOP` from symlink
//! replacement and `ENOTDIR` from intermediate directory replacement are both
//! classified as permanent errors.
//!
//! # Split-point heuristic
//!
//! [`choose_split_point`](EnumerationConnector::choose_split_point) selects a
//! byte-weighted median: the split key is chosen where cumulative file size
//! crosses the halfway mark, so that shards are balanced by total byte volume
//! rather than item count. Falls back to count-balanced when all files are
//! zero-size. A prefix-sum array built at index time allows O(log n) split
//! selection via binary search instead of linear scan.
//!
//! # Budget enforcement
//!
//! - **Deadline**: The walk checks the deadline once per directory during
//!   indexing. If the deadline expires mid-walk, a retryable error is returned
//!   and the incomplete index is discarded. Post-indexing operations
//!   (enumeration, split) also check the deadline before proceeding.
//! - **`max_items`**: Honored as a hard cap on page size during enumeration.
//!   `Budgets` stores `max_items` as `NonZeroUsize` so zero-item pages from
//!   budget capping are unrepresentable.
//! - **`max_bytes`**: Enforced in `read_range()` (clamp read length). `open()`
//!   leaves byte-budget enforcement to higher layers, matching the advisory
//!   budget contract on [`ReadConnector`].
//!
//! # TOCTOU limitations
//!
//! The file index is built once per connector instance. Reads (`open`,
//! `read_range`) later reopen files via `openat` from the root directory fd.
//! If a file is replaced, renamed, or truncated between indexing and reading,
//! the [`VersionId`] from enumeration may describe a different object than
//! what the read returns. The FD cache widens this window slightly for
//! consecutive reads on the same item, since the cached descriptor may
//! outlive a concurrent replace. Callers requiring snapshot consistency
//! should use version checks at a higher layer (e.g., the orchestration
//! runtime).
//!
//! # Platform and path handling
//!
//! This implementation is Unix-only because deterministic handling of non-UTF8
//! file names depends on raw `OsStr` byte access (`OsStrExt`), and read-path
//! confinement uses `openat(2)` with per-component `O_NOFOLLOW`. Item refs
//! must exactly match an indexed key; reads reject any `ItemRef` not present
//! in the index.
//!
//! # Scope and limitations
//!
//! - Designed for single-threaded sequential page calls; the struct holds
//!   mutable state (`index_state`, `files`) with no interior synchronization.
//! - The file index is built once per connector instance. Directory mutations
//!   after the first indexing-triggering call (`enumerate_page`,
//!   `choose_split_point`, `open`, or `read_range`) are invisible; construct a
//!   new connector to observe changes.
//! - Non-fatal walk issues (unreadable entries, symlinks, encoding failures)
//!   are recorded in [`WalkWarning`]s (up to a configurable cap) rather than
//!   aborting the entire index. Only root-directory failures are hard errors.
//!   Use [`overflow_warning_count`](FilesystemConnector::overflow_warning_count)
//!   to detect whether warnings were dropped.
//! - [`ItemRef`] values are the raw relative-path bytes of each file and are
//!   stable for a given directory snapshot, unlike the positional indices used
//!   by the in-memory connector.

use std::{
    ffi::CString,
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{FileExt, MetadataExt},
        io::{AsRawFd, FromRawFd, OwnedFd},
    },
    path::{Path, PathBuf},
    time::Instant,
};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ObjectVersionId, StableItemId},
};

use crate::common::{self, borrowed_shard_bound, derive_stable_item_id};

/// Connector tag used to domain-separate [`StableItemId`] derivation.
///
/// All filesystem-sourced items share this tag so that identity hashes are
/// disjoint from items produced by other connector types (in-memory, git, SaaS).
const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

// ---------------------------------------------------------------------------
// WalkWarning
// ---------------------------------------------------------------------------

/// A non-fatal issue encountered during the directory walk.
///
/// Warnings are collected in [`FilesystemConnector::walk_warnings`] and do
/// not abort indexing. They report entries that were skipped due to I/O
/// errors, symlinks, encoding failures, or other non-fatal conditions.
/// Warning storage is capped; see
/// [`FilesystemConnector::overflow_warning_count`].
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

// ---------------------------------------------------------------------------
// IndexState
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// FileEntry
// ---------------------------------------------------------------------------

/// One entry in the sorted file index.
#[derive(Debug)]
struct FileEntry {
    key: ItemKey,
    stable_item_id: StableItemId,
    version: VersionId,
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

// ---------------------------------------------------------------------------
// FilesystemConnector
// ---------------------------------------------------------------------------

/// Deterministic filesystem connector rooted at a local directory.
///
/// See [module-level documentation](self) for full design details.
pub struct FilesystemConnector {
    root: PathBuf,
    emit_tokens: bool,
    max_walk_depth: usize,
    max_warnings: usize,
    index_state: IndexState,
    files: Vec<FileEntry>,
    /// Cumulative file sizes for O(log n) byte-weighted split selection.
    /// `prefix_sums[i]` = sum of `files[0..=i].size`.
    prefix_sums: Vec<u64>,
    walk_warnings: Vec<WalkWarning>,
    overflow_warning_count: usize,
    /// Directory fd for the canonical root, opened during indexing.
    root_fd: Option<OwnedFd>,
    /// Single-entry FD cache for sequential `read_range` calls.
    /// Keyed on the index position within [`Self::files`] to avoid
    /// heap-allocating a copy of the item-ref bytes on every cache miss.
    cached_file: Option<(usize, fs::File)>,
}

impl FilesystemConnector {
    /// Maximum directory traversal depth to prevent infinite loops on cyclic bind mounts.
    const DEFAULT_MAX_WALK_DEPTH: usize = 512;
    /// Maximum warnings to collect before suppressing further diagnostics.
    const DEFAULT_MAX_WARNINGS: usize = 1024;

    /// Create a connector rooted at `root`.
    ///
    /// Indexing is lazy; the root is canonicalized at first use.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            emit_tokens: false,
            max_walk_depth: Self::DEFAULT_MAX_WALK_DEPTH,
            max_warnings: Self::DEFAULT_MAX_WARNINGS,
            index_state: IndexState::NotIndexed,
            files: Vec::new(),
            prefix_sums: Vec::new(),
            walk_warnings: Vec::new(),
            overflow_warning_count: 0,
            root_fd: None,
            cached_file: None,
        }
    }

    #[must_use]
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    #[must_use]
    pub fn with_max_depth(mut self, max_depth: usize) -> Self {
        self.max_walk_depth = max_depth;
        self
    }

    /// Set the maximum number of [`WalkWarning`]s to retain.
    #[must_use]
    pub fn with_max_warnings(mut self, max_warnings: usize) -> Self {
        self.max_warnings = max_warnings;
        self
    }

    pub fn walk_warnings(&self) -> &[WalkWarning] {
        &self.walk_warnings
    }

    /// Number of walk warnings dropped because the buffer was full.
    pub fn overflow_warning_count(&self) -> usize {
        self.overflow_warning_count
    }

    // ---------------------------------------------------------------
    // Indexing
    // ---------------------------------------------------------------

    fn ensure_indexed(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        match &self.index_state {
            IndexState::Indexed => return Ok(()),
            IndexState::Failed(message) => {
                return Err(EnumerateError::permanent(message.clone()));
            }
            IndexState::NotIndexed => {}
        }

        // Canonicalize root to prevent cwd drift and resolve root symlinks.
        match fs::canonicalize(&self.root) {
            Ok(canonical) => self.root = canonical,
            Err(err) => {
                let e = classify_io_enumerate_error("canonicalize", &self.root, &err);
                if !e.is_retryable() {
                    self.index_state = IndexState::Failed(e.message().to_owned());
                }
                return Err(e);
            }
        }

        // Open root as a directory fd for openat-based reads.
        let root_fd = open_dir_fd(&self.root).map_err(|err| {
            let e = classify_io_enumerate_error("open_root_dir", &self.root, &err);
            if !e.is_retryable() {
                self.index_state = IndexState::Failed(e.message().to_owned());
            }
            e
        })?;

        let mut files = Vec::new();
        let mut warnings = Vec::new();
        let mut overflow_count = 0usize;
        match walk_dir_collect_files(
            &self.root,
            self.max_walk_depth,
            deadline,
            self.max_warnings,
            &mut overflow_count,
            &mut files,
            &mut warnings,
        ) {
            Ok(()) => {
                files.sort_unstable_by(|left, right| left.key.cmp(&right.key));
                debug_assert!(
                    files.windows(2).all(|w| w[0].key != w[1].key),
                    "filesystem walk produced duplicate keys after encoding"
                );

                // Build prefix sums for O(log n) byte-weighted split selection.
                let mut prefix_sums = Vec::with_capacity(files.len());
                let mut cumulative = 0u64;
                for f in &files {
                    cumulative = cumulative.saturating_add(f.size);
                    prefix_sums.push(cumulative);
                }

                self.files = files;
                self.prefix_sums = prefix_sums;
                self.walk_warnings = warnings;
                self.overflow_warning_count = overflow_count;
                self.root_fd = Some(root_fd);
                self.index_state = IndexState::Indexed;
                Ok(())
            }
            Err(err) => {
                self.walk_warnings = warnings;
                self.overflow_warning_count = overflow_count;
                if !err.is_retryable() {
                    self.index_state = IndexState::Failed(err.message().to_owned());
                }
                Err(err)
            }
        }
    }

    // ---------------------------------------------------------------
    // Enumeration
    // ---------------------------------------------------------------

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

    /// Core page enumeration used by both shard-based and explicit-range APIs.
    ///
    /// The method resolves bounds via binary search, applies key-authoritative
    /// resume semantics, then stages key/ref/token bytes in a page-local slab
    /// for pooled toxic-byte wrappers.
    ///
    /// Unlike the in-memory connector, filesystem tokens are advisory only:
    /// key-derived resume remains authoritative and token mismatch is debug-only
    /// telemetry for cursor-construction bugs.
    ///
    /// # Failure modes
    ///
    /// - Deadline expiry is retryable.
    /// - Invalid shard ranges (`start > end`) are permanent.
    /// - Slab sizing/staging failures are permanent because staged lengths come
    ///   from validated in-memory index fields.
    fn enumerate_page_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.ensure_indexed(budgets.deadline())?;
        let bounds = common::resolve_page_bounds(&self.files, start, end, budgets)?;
        let key_resume = common::key_resume_start(&self.files, cursor, bounds.range_start);
        let start_idx = key_resume;

        // Advisory-token check: keep release behavior key-authoritative while
        // surfacing token drift during development.
        #[cfg(debug_assertions)]
        if self.emit_tokens
            && cursor.last_key().is_some()
            && let Some(token_idx) = common::cursor_token_index(cursor)
        {
            debug_assert_eq!(
                token_idx, key_resume,
                "token index {token_idx} disagrees with key-derived resume position {key_resume}"
            );
        }

        if start_idx >= bounds.range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(bounds.range_end - start_idx);
        let page_files = &self.files[start_idx..(start_idx + take)];

        // Filesystem item refs mirror key bytes exactly.
        let staged = common::assemble_pooled_page_shared_key_ref(
            page_files.iter().map(|file| file.key.as_bytes()),
            self.emit_tokens,
            start_idx,
        )?;
        let common::StagedPage { wrappers, token } = staged;
        let mut out = Vec::with_capacity(wrappers.len());
        for ((item_key, item_ref), file) in wrappers.into_iter().zip(page_files) {
            out.push(
                ScanItem::new(item_key, item_ref, file.stable_item_id, file.version)
                    .with_size_hint(file.size),
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

    // ---------------------------------------------------------------
    // Split-point selection
    // ---------------------------------------------------------------

    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start.as_bytes()), Some(end.as_bytes()), cursor, None)
    }

    /// Shared bound resolution + filesystem-specific split selection.
    ///
    /// The window `[start_idx, range_end)` comes from [`common::resolve_bounds`]
    /// and [`common::key_resume_start`], then split selection uses the
    /// precomputed prefix sums (`byte_weighted_split_idx`) for O(log n)
    /// byte-balanced hints. Post-selection guards use
    /// [`common::is_valid_split_candidate`].
    ///
    /// Returning `None` means no safe/meaningful split exists after applying
    /// cursor-progress and upper-bound guards.
    fn choose_split_point_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        deadline: Option<Instant>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.ensure_indexed(deadline)?;

        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        let bounds = common::resolve_bounds(&self.files, start, end)?;
        let start_idx = common::key_resume_start(&self.files, cursor, bounds.range_start);
        let split_idx = match self.byte_weighted_split_idx(start_idx, bounds.range_end) {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let candidate = &self.files[split_idx].key;
        if !common::is_valid_split_candidate(candidate.as_bytes(), cursor, end) {
            return Ok(None);
        }

        Ok(Some(candidate.clone()))
    }

    /// O(log n) byte-weighted median split using prefix sums.
    ///
    /// The linear-scan equivalent lives in [`common::choose_split_index`]; both
    /// produce identical results but this version uses the precomputed
    /// [`prefix_sums`](Self::prefix_sums) for O(log n) selection.
    fn byte_weighted_split_idx(&self, start_idx: usize, range_end: usize) -> Option<usize> {
        let count = range_end.saturating_sub(start_idx);
        if count < 2 {
            return None;
        }

        let base = if start_idx > 0 {
            self.prefix_sums[start_idx - 1]
        } else {
            0
        };
        let total = self.prefix_sums[range_end - 1].saturating_sub(base);

        let split_idx = if total == 0 {
            start_idx + count / 2
        } else {
            let target = base.saturating_add(total / 2);
            let relative = self.prefix_sums[start_idx..range_end].partition_point(|&s| s < target);
            let idx = start_idx + relative;
            if idx == start_idx {
                start_idx + count / 2
            } else {
                idx
            }
        };

        Some(split_idx.max(start_idx + 1).min(range_end - 1))
    }

    // ---------------------------------------------------------------
    // Read-path: openat traversal + membership enforcement
    // ---------------------------------------------------------------

    fn verify_membership(&mut self, item_ref: &ItemRef) -> Result<usize, ReadError> {
        self.ensure_indexed(None).map_err(|e| {
            if e.is_retryable() {
                ReadError::retryable(e.into_message())
            } else {
                ReadError::permanent(e.into_message())
            }
        })?;
        let ref_bytes = item_ref.as_bytes();
        self.files
            .binary_search_by(|f| f.key.as_bytes().cmp(ref_bytes))
            .map_err(|_| ReadError::permanent("item_ref not found in index"))
    }

    /// Open a file beneath `root_fd` using component-by-component `openat`
    /// with `O_NOFOLLOW` at every step.
    ///
    /// The returned file descriptor has `O_NONBLOCK` set (to avoid blocking on
    /// FIFOs or device nodes in a TOCTOU race). Callers must [`clear_nonblock`]
    /// before performing any reads.
    fn open_beneath_root(&self, ref_bytes: &[u8]) -> Result<(fs::File, fs::Metadata), ReadError> {
        let root_fd = self
            .root_fd
            .as_ref()
            .ok_or_else(|| ReadError::permanent("connector not indexed; call enumerate first"))?;

        if ref_bytes.is_empty() {
            return Err(ReadError::permanent("empty item_ref"));
        }

        // Pre-count components (separators + 1) to detect the last component
        // without collecting into a Vec.
        let n = ref_bytes.iter().filter(|&&b| b == b'/').count() + 1;

        let mut dir_fd: Option<OwnedFd> = None;

        // Stack buffer for null-terminated component (NAME_MAX=255 + NUL).
        let mut c_buf = [0u8; 256];

        for (i, component) in ref_bytes.split(|&b| b == b'/').enumerate() {
            // Defense-in-depth: `encode_rel_path` only produces Normal segments,
            // and `verify_membership` rejects refs absent from the index, so this
            // guard is unreachable through any public API path.
            if component.is_empty() || component == b"." || component == b".." {
                return Err(ReadError::permanent("invalid path component in item_ref"));
            }

            let parent_raw = match &dir_fd {
                Some(fd) => fd.as_raw_fd(),
                None => root_fd.as_raw_fd(),
            };

            // Reject embedded NUL bytes before building the C string.
            if component.contains(&0) {
                return Err(ReadError::permanent("null byte in path component"));
            }

            // Build a null-terminated component on the stack (NAME_MAX=255 + NUL).
            if component.len() >= c_buf.len() {
                return Err(ReadError::permanent("path component exceeds NAME_MAX"));
            }
            c_buf[..component.len()].copy_from_slice(component);
            c_buf[component.len()] = 0;
            let c_ptr = c_buf.as_ptr().cast::<libc::c_char>();

            let is_last = i == n - 1;
            let flags = if is_last {
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
            };

            // SAFETY: `libc::openat` is a POSIX syscall. `parent_raw` is a valid
            // fd. `c_ptr` points to a null-terminated stack buffer. Returned fd
            // is wrapped in `OwnedFd` for close-on-drop.
            let raw = unsafe { libc::openat(parent_raw, c_ptr, flags) };
            if raw < 0 {
                let comp = String::from_utf8_lossy(component);
                return Err(classify_io_read_error(
                    &format!("openat component {}/{n} '{comp}'", i + 1),
                    &io::Error::last_os_error(),
                ));
            }

            // SAFETY: `raw >= 0` from the check above. `OwnedFd` takes
            // ownership; assigning to `dir_fd` drops the previous intermediate.
            dir_fd = Some(unsafe { OwnedFd::from_raw_fd(raw) });
        }

        let file = fs::File::from(dir_fd.expect("path has at least one component"));
        let metadata = file
            .metadata()
            .map_err(|e| classify_io_read_error("fstat", &e))?;
        if !metadata.is_file() {
            return Err(ReadError::permanent("path is not a regular file"));
        }

        Ok((file, metadata))
    }

    fn get_or_open_cached(&mut self, item_ref: &ItemRef) -> Result<&fs::File, ReadError> {
        let ref_bytes = item_ref.as_bytes();
        let need_open = self
            .cached_file
            .as_ref()
            .is_none_or(|(idx, _)| self.files[*idx].key.as_bytes() != ref_bytes);
        if need_open {
            let idx = self.verify_membership(item_ref)?;
            let (file, _metadata) = self.open_beneath_root(ref_bytes)?;
            clear_nonblock(&file)?;
            self.cached_file = Some((idx, file));
        }
        Ok(&self.cached_file.as_ref().unwrap().1)
    }
}

// ---------------------------------------------------------------------------
// EnumerationConnector impl
// ---------------------------------------------------------------------------

impl EnumerationConnector for FilesystemConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    /// Shard bounds are validated allocation-free via the internal
    /// `borrowed_shard_bound` helper
    /// before index lookup (`[]` means unbounded; oversize is permanent).
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

    /// The first call may trigger a full filesystem walk; subsequent calls
    /// operate purely over the in-memory index.
    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor, budgets.deadline())
    }
}

// ---------------------------------------------------------------------------
// ReadConnector impl
// ---------------------------------------------------------------------------

impl ReadConnector for FilesystemConnector {
    /// Budget enforcement is left to the runtime layer (which wraps the
    /// returned reader in a bounded adapter), consistent with the advisory
    /// budget contract in [`ReadConnector`].
    fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        self.verify_membership(item_ref)?;
        let (file, _metadata) = self.open_beneath_root(item_ref.as_bytes())?;
        clear_nonblock(&file)?;
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

        let file = self.get_or_open_cached(item_ref)?;
        file.read_at(&mut dst[..allowed], offset)
            .map_err(|err| classify_io_read_error("read_at", &err))
    }
}

// ---------------------------------------------------------------------------
// Error classification
// ---------------------------------------------------------------------------

/// Returns `true` for I/O errors that are deterministically permanent.
///
/// # Permanent errors
///
/// - `NotFound`: file/directory doesn't exist
/// - `PermissionDenied`: insufficient access rights
/// - `InvalidInput`: malformed arguments
/// - `InvalidFilename`: invalid path bytes
/// - `NotADirectory` / `IsADirectory`: wrong path kind for the operation
/// - `ELOOP`: symlink loop detected (POSIX-specific)
///
/// Other errors (for example `EAGAIN`, `EINTR`) are treated as transient and
/// warrant retry.
fn is_permanent_io_error(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::NotFound
            | io::ErrorKind::PermissionDenied
            | io::ErrorKind::InvalidInput
            | io::ErrorKind::InvalidFilename
            | io::ErrorKind::NotADirectory
            | io::ErrorKind::IsADirectory
    ) || err.raw_os_error() == Some(libc::ELOOP)
}

/// Convert an I/O error to a `ReadError` with appropriate retryability.
///
/// Permanent errors (file not found, permission denied) become non-retryable.
/// Transient errors (network hiccups, resource contention) become retryable.
fn classify_io_read_error(op: &str, err: &io::Error) -> ReadError {
    if is_permanent_io_error(err) {
        ReadError::permanent(format!("{op} failed: {err}"))
    } else {
        ReadError::retryable(format!("{op} failed: {err}"))
    }
}

/// Convert an I/O error to an `EnumerateError` with appropriate retryability.
///
/// Similar to `classify_io_read_error` but includes the failing path in the
/// error message for better diagnostics during directory traversal.
fn classify_io_enumerate_error(op: &str, path: &Path, err: &io::Error) -> EnumerateError {
    if is_permanent_io_error(err) {
        EnumerateError::permanent(format!("{op} failed for {}: {err}", path.display()))
    } else {
        EnumerateError::retryable(format!("{op} failed for {}: {err}", path.display()))
    }
}

// ---------------------------------------------------------------------------
// Directory walk
// ---------------------------------------------------------------------------

/// Walk directory tree depth-first and collect regular files.
///
/// # Algorithm
///
/// Uses an explicit stack to avoid recursion and traverses each directory's
/// entries in filesystem-provided order. A final global sort by encoded key
/// enforces deterministic output ordering. Symlinks are skipped (logged as
/// warnings) to avoid cycles and ensure deterministic membership.
///
/// # Trade-offs
///
/// - **No recursion**: Explicit stack prevents stack overflow on deep trees
/// - **Post-walk sort**: Keep traversal simple, then sort collected files by
///   encoded key to guarantee deterministic final order
/// - **Skip symlinks**: Avoids cycles and non-deterministic resolution
/// - **Regular files only**: Devices, FIFOs, sockets are skipped
/// - **Depth limit**: Prevents infinite traversal of cyclic bind mounts
/// - **Warning limit**: Caps diagnostic noise from problematic directories
///
/// # Errors
///
/// Returns hard errors for invalid root path and root-level traversal failures
/// (for example `read_dir(root)` failure). Encoding failures for individual
/// entries are downgraded to warnings and do not fail the walk.
fn walk_dir_collect_files(
    root: &Path,
    max_depth: usize,
    deadline: Option<Instant>,
    max_warnings: usize,
    overflow_count: &mut usize,
    out: &mut Vec<FileEntry>,
    warnings: &mut Vec<WalkWarning>,
) -> Result<(), EnumerateError> {
    fn push_warning(
        warnings: &mut Vec<WalkWarning>,
        max_warnings: usize,
        overflow_count: &mut usize,
        w: WalkWarning,
    ) {
        if warnings.len() < max_warnings {
            warnings.push(w);
        } else {
            *overflow_count += 1;
        }
    }

    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];

    while let Some((dir, depth)) = stack.pop() {
        // Periodic deadline check: once per directory.
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            return Err(EnumerateError::retryable("indexing deadline expired"));
        }

        let is_root = dir == root;
        let reader = match fs::read_dir(&dir) {
            Ok(r) => r,
            Err(err) => {
                if is_root {
                    return Err(classify_io_enumerate_error("read_dir", &dir, &err));
                }
                push_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::io(&dir, "read_dir", &err),
                );
                continue;
            }
        };

        for entry_result in reader {
            let entry = match entry_result {
                Ok(e) => e,
                Err(err) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::io(&dir, "read_dir entry", &err),
                    );
                    continue;
                }
            };

            let path = entry.path();

            let file_type = match entry.file_type() {
                Ok(ft) => ft,
                Err(err) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::io(&path, "file_type", &err),
                    );
                    continue;
                }
            };

            if file_type.is_symlink() {
                push_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::skipped(&path, "symlink"),
                );
                continue;
            }

            if file_type.is_dir() {
                if depth < max_depth {
                    stack.push((path, depth + 1));
                } else {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::skipped(&path, "exceeded maximum walk depth"),
                    );
                }
                continue;
            }

            if !file_type.is_file() {
                push_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::skipped(&path, "special file (not regular)"),
                );
                continue;
            }

            let metadata = match fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(err) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::io(&path, "metadata", &err),
                    );
                    continue;
                }
            };

            if !metadata.is_file() {
                push_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::skipped(&path, "file type changed between readdir and stat"),
                );
                continue;
            }

            let rel = match path.strip_prefix(root) {
                Ok(r) => r,
                Err(_) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::skipped(&path, "path escaped connector root"),
                    );
                    continue;
                }
            };

            let rel_bytes = match encode_rel_path(rel) {
                Ok(b) => b,
                Err(err) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::skipped(
                            &path,
                            &format!("path encoding failed: {}", err.message()),
                        ),
                    );
                    continue;
                }
            };

            let key = match ItemKey::try_from_vec(rel_bytes) {
                Ok(k) => k,
                Err(err) => {
                    push_warning(
                        warnings,
                        max_warnings,
                        overflow_count,
                        WalkWarning::skipped(&path, &format!("invalid file key: {err}")),
                    );
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

// ---------------------------------------------------------------------------
// Path encoding
// ---------------------------------------------------------------------------

/// Encode a relative path as a `/`-separated byte key.
///
/// Key ordering matches lexicographic path ordering on Unix because segments
/// are joined with `/` (0x2F). The encoding is reversible by splitting on `/`
/// since Unix filenames cannot contain `/`. Only [`Component::Normal`] segments
/// are accepted; `.`, `..`, and root prefixes are rejected.
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

// ---------------------------------------------------------------------------
// Version ID
// ---------------------------------------------------------------------------

/// Build a weak [`ObjectVersionId`] from file metadata.
///
/// Layout: `[mtime(8) | mtime_nsec(8) | len(8) | ino(8) | dev(8)]` = 40 bytes.
/// Including `dev()` ensures version IDs are distinct across filesystem
/// boundaries where `ino()` alone can collide.
///
/// # Why not content hashing?
///
/// Content hashing would require reading every file during indexing, turning
/// O(n) directory traversal into O(total_bytes) I/O. Metadata-based versioning
/// provides "good enough" change detection for filesystem sources while keeping
/// indexing fast. The trade-off: identical content with different mtimes gets
/// different version IDs, and filesystem metadata manipulation can forge versions.
fn derive_fs_version_id(metadata: &fs::Metadata) -> ObjectVersionId {
    let mut encoded = [0u8; 40];
    encoded[0..8].copy_from_slice(&metadata.mtime().to_be_bytes());
    encoded[8..16].copy_from_slice(&metadata.mtime_nsec().to_be_bytes());
    encoded[16..24].copy_from_slice(&metadata.len().to_be_bytes());
    encoded[24..32].copy_from_slice(&metadata.ino().to_be_bytes());
    encoded[32..40].copy_from_slice(&metadata.dev().to_be_bytes());
    ObjectVersionId::from_version_bytes(&encoded)
}

// ---------------------------------------------------------------------------
// Low-level fd helpers
// ---------------------------------------------------------------------------

/// Open a directory file descriptor for use with `openat`.
///
/// Uses `O_RDONLY | O_DIRECTORY | O_CLOEXEC` flags to ensure we get a
/// directory handle that won't leak to child processes. The `O_DIRECTORY`
/// flag causes `open` to fail if the path isn't a directory. Symlink traversal
/// hardening for child path components is enforced later via `openat` with
/// `O_NOFOLLOW`.
fn open_dir_fd(path: &Path) -> Result<OwnedFd, io::Error> {
    let c_path = path_to_cstring(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))?;
    // SAFETY: POSIX open(2) with a valid null-terminated path.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: fd >= 0 from the check above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Clear `O_NONBLOCK` from an already-opened file descriptor.
///
/// The read path opens leaf files with `O_NONBLOCK` to avoid blocking on
/// FIFOs or device nodes that slip past the `fstat` regular-file check in
/// a TOCTOU race. After validation, this function clears the flag so that
/// subsequent `read`/`read_at` calls use normal blocking semantics.
///
/// # Safety invariant
///
/// We validate the file is regular (via `fstat`) before clearing O_NONBLOCK.
/// This prevents hanging on FIFOs/devices that might have been swapped in
/// via TOCTOU race. The window is narrow but non-zero: between our `openat`
/// and `fstat`, the filesystem could change. This validation ensures we
/// never block indefinitely on special files.
fn clear_nonblock(file: &fs::File) -> Result<(), ReadError> {
    let fd = file.as_raw_fd();
    // SAFETY: fcntl F_GETFL/F_SETFL on a valid fd.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(classify_io_read_error(
            "fcntl(F_GETFL)",
            &io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_SETFL on a valid fd with flags obtained from F_GETFL above.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if result < 0 {
        return Err(classify_io_read_error(
            "fcntl(F_SETFL)",
            &io::Error::last_os_error(),
        ));
    }
    Ok(())
}

/// Convert a Path to a null-terminated C string for syscall use.
///
/// Unix paths can contain any bytes except NUL, but C APIs require
/// NUL-termination. This function validates no embedded NULs exist
/// and appends the terminator.
fn path_to_cstring(path: &Path) -> Result<CString, std::ffi::NulError> {
    CString::new(path.as_os_str().as_bytes())
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
