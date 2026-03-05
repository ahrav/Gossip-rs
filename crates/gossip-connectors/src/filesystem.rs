//! Deterministic filesystem-backed connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], an implementation of
//! [`gossip_contracts::connector::EnumerationConnector`] and
//! [`gossip_contracts::connector::ReadConnector`] that serves pages directly
//! from a resumable sorted DFS walk.
//!
//! # Streaming serving model
//!
//! The connector no longer materializes a full `Vec<FileEntry>` index.
//! Instead, `enumerate_page` advances an in-memory `WalkState` that keeps:
//!
//! - a DFS stack of sorted per-directory entry buffers,
//! - a mutable path buffer for the active frame,
//! - cursor-alignment metadata (`last_emitted_key`, `pending`, `exhausted`).
//!
//! This keeps memory proportional to:
//! - `O(Σ entries_per_active_dir)` for buffered DFS frames, plus
//! - `O(visited_dirs)` for cycle-detection identities collected during descent.
//!
//! This is still substantially smaller than full-tree materialization for deep,
//! balanced trees, but can approach full-tree scale for very wide or highly
//! connected hierarchies.
//!
//! Optional key-range pruning (`with_key_range`) further reduces walk I/O by
//! skipping directory subtrees whose lexicographic prefix ranges cannot overlap
//! the requested half-open key range. Pruning is conservative: when prefix
//! bounds are ambiguous, the subtree is kept and leaf-level filtering enforces
//! correctness.
//!
//! # Ordering and resume
//!
//! Per-directory sorting plus depth-first traversal yields globally sorted
//! keys. Cursor progression is key-authoritative:
//!
//! - Sequential pages continue from the existing walk state.
//! - Cursor mismatch (including cold resume in a fresh connector) first attempts
//!   token-based walk-stack restore, then falls back to rebuilding from root and
//!   skipping until the first key strictly greater than `cursor.last_key()`.
//!
//! # Consistency model
//!
//! Enumeration is streaming, not snapshot-isolated. Directory entries are
//! buffered per frame when that directory is opened, and file metadata is read
//! later when entries are emitted. Concurrent filesystem mutation can therefore
//! make specific items appear/disappear between pages; when races are detected,
//! the walk records a [`WalkWarning`] and continues.
//!
//! # Read-path confinement
//!
//! Reads are constrained with component-by-component `openat` traversal from a
//! canonical root directory fd, using `O_NOFOLLOW` at each step. This prevents
//! symlink escapes and intermediate directory substitution attacks.
//!
//! Files are opened with `O_NONBLOCK`, validated as regular files via metadata,
//! then `O_NONBLOCK` is cleared before reads.
//!
//! # Split hints
//!
//! Split-point hints are intentionally disabled in this streaming phase:
//! `caps().split_hints == false`, and `choose_split_point*` returns `Ok(None)`
//! after validating deadline/range inputs.
//!
//! # Warnings and failures
//!
//! Non-fatal walk issues (symlinks, unreadable entries, encoding failures) are
//! recorded in [`WalkWarning`] up to `max_warnings`; overflow is counted in
//! [`overflow_warning_count`](FilesystemConnector::overflow_warning_count).
//! Deadline expiry remains retryable; malformed bounds remain permanent.

use std::{
    collections::{HashSet, VecDeque},
    ffi::{CString, OsString},
    fs, io,
    os::unix::{
        ffi::{OsStrExt, OsStringExt},
        fs::{FileExt, MetadataExt},
        io::{AsRawFd, FromRawFd, OwnedFd},
    },
    path::{Path, PathBuf},
    time::Instant,
};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, MAX_TOKEN_SIZE, ReadConnector, ReadError, ScanItem,
        TokenBytes, ToxicDigest, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ObjectVersionId, StableItemId},
};

use gossip_stdx::InlineVec;

use crate::common::{
    self, borrowed_shard_bound, classify_io_enumerate_error, classify_io_read_error,
    derive_stable_item_id, enumerate_error_to_read,
};

/// Connector tag used to domain-separate [`StableItemId`] derivation.
///
/// All filesystem-sourced items share this tag so that identity hashes are
/// disjoint from items produced by other connector types (in-memory, git, SaaS).
pub const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

// ---------------------------------------------------------------------------
// WalkWarning
// ---------------------------------------------------------------------------

/// A non-fatal issue encountered during the directory walk.
///
/// Warnings are collected in [`FilesystemConnector::walk_warnings`] and do
/// not abort page production. They report entries that were skipped due to I/O
/// errors, symlinks, encoding failures, or other non-fatal conditions.
/// Warning storage is capped; see
/// [`FilesystemConnector::overflow_warning_count`].
///
/// The path is stored as a [`ToxicDigest`] rather than a raw [`PathBuf`]
/// so that filesystem paths never leak into log-visible diagnostics.
#[derive(Debug)]
pub struct WalkWarning {
    /// Redacted digest of the path that triggered the warning.
    pub path_digest: ToxicDigest,
    /// Human-readable description of why the entry was skipped.
    pub message: String,
}

impl WalkWarning {
    fn io(path: &Path, op: &str, err: &io::Error) -> Self {
        Self {
            path_digest: ToxicDigest::of_bytes(path.as_os_str().as_bytes()),
            message: format!("{op} failed: {err}"),
        }
    }

    fn skipped(path: &Path, reason: &str) -> Self {
        Self {
            path_digest: ToxicDigest::of_bytes(path.as_os_str().as_bytes()),
            message: reason.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// FileEntry
// ---------------------------------------------------------------------------

/// One file record emitted by the streaming walk.
///
/// This is an internal staging type between [`WalkState::next_file`] and page
/// assembly. It does not represent a persisted or full in-memory index.
#[derive(Debug)]
struct FileEntry {
    key: ItemKey,
    stable_item_id: StableItemId,
    version: VersionId,
    size: u64,
}

/// Single-entry read cache keyed by `item_ref` bytes.
///
/// `read_range` workloads often perform adjacent reads on the same file; this
/// avoids repeated `openat` traversal in the common sequential case while
/// keeping memory and fd retention bounded.
struct CachedFile {
    item_ref: Box<[u8]>,
    file: fs::File,
}

/// One buffered directory entry in a sorted frame queue.
struct BufferedDirEntry {
    name: OsString,
    file_type: fs::FileType,
}

/// DFS stack frame for one directory.
///
/// `entries` is pre-sorted with [`cmp_dir_entry`], so popping from the front
/// preserves per-directory order. The frame's `component` mirrors one segment
/// in [`WalkState::current_path`] while the frame is active.
struct WalkFrame {
    /// Directory component relative to parent (`None` for root frame).
    component: Option<OsString>,
    depth: usize,
    /// Yielded-entry count since the last deadline check.
    entries_since_check: usize,
    /// Index of the next child to poll in this frame's sorted entry list.
    next_child_index: u32,
    /// Sorted remaining entries for this directory.
    entries: VecDeque<BufferedDirEntry>,
}

#[derive(Clone, Copy)]
struct WalkQuery<'a> {
    root: &'a Path,
    max_depth: usize,
    start: Option<&'a [u8]>,
    end: Option<&'a [u8]>,
    deadline: Option<Instant>,
    max_warnings: usize,
}

/// Cursor token encoding version for serialized DFS walk checkpoints.
const WALK_TOKEN_VERSION: u8 = 0x01;

/// Compact serialized DFS walk position used for cursor resume.
///
/// Tokens are advisory only. Decode/restore failure falls back to key-only
/// resume from root.
///
/// Wire format (little-endian except version):
/// `[version: u8][frame_count: u16][frames..]`, where each frame is
/// `[component_len: u16][component_bytes][next_child_index: u32]`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WalkToken {
    frames: Vec<WalkTokenFrame>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct WalkTokenFrame {
    /// Directory component relative to parent (empty for root frame).
    component: Vec<u8>,
    /// Index of the next child to poll in this directory's sorted list.
    next_child_index: u32,
}

/// Resumable sorted DFS state used as the serving layer for pagination.
///
/// # Invariants
///
/// - `stack` + `current_path` represent the active DFS frontier.
/// - `pending` stores exactly one already-discovered file that must be emitted
///   before continuing traversal (used for upper-bound stop and cursor seek).
/// - `last_emitted_key` tracks connector-visible resume position, not merely
///   "last discovered" path.
/// - `exhausted` is sticky once a full walk pass returns `None`.
/// - `visited_dirs` tracks `(dev, ino)` pairs of already-descended directories
///   to break cycles from bind mounts or directory hardlinks.
struct WalkState {
    stack: Vec<WalkFrame>,
    current_path: PathBuf,
    pending: Option<FileEntry>,
    last_emitted_key: Option<ItemKey>,
    /// Approximate number of items emitted across the lifetime of this walk.
    ///
    /// After token-based resume, this only counts items from the token position
    /// forward (not the global count from root). This field is currently
    /// unused for decision logic — it exists for observability and may be
    /// removed if no consumer materializes.
    emitted_count: usize,
    exhausted: bool,
    /// `(dev, ino)` pairs of directories already descended into.
    /// Prevents infinite traversal on bind-mount or hardlink cycles.
    visited_dirs: HashSet<(u64, u64)>,
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
    walk_key_range_start: Option<Box<[u8]>>,
    walk_key_range_end: Option<Box<[u8]>>,
    walk_state: Option<WalkState>,
    walk_warnings: Vec<WalkWarning>,
    overflow_warning_count: usize,
    /// Directory fd for the canonical root, opened lazily.
    root_fd: Option<OwnedFd>,
    /// Single-entry FD cache for sequential `read_range` calls.
    cached_file: Option<CachedFile>,
}

impl FilesystemConnector {
    /// Maximum directory traversal depth to prevent infinite loops on cyclic bind mounts.
    const DEFAULT_MAX_WALK_DEPTH: usize = 512;
    /// Maximum warnings to collect before suppressing further diagnostics.
    const DEFAULT_MAX_WARNINGS: usize = 1024;

    /// Create a connector rooted at `root`.
    ///
    /// Walk initialization is lazy; the root is canonicalized at first use.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            emit_tokens: false,
            max_walk_depth: Self::DEFAULT_MAX_WALK_DEPTH,
            max_warnings: Self::DEFAULT_MAX_WARNINGS,
            walk_key_range_start: None,
            walk_key_range_end: None,
            walk_state: None,
            walk_warnings: Vec::new(),
            overflow_warning_count: 0,
            root_fd: None,
            cached_file: None,
        }
    }

    #[must_use]
    /// Enable or disable opaque resume tokens in returned cursors.
    ///
    /// Key-based resume remains available regardless of this setting.
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    #[must_use]
    /// Restrict traversal to keys inside the half-open range `[start, end)`.
    ///
    /// The range is applied during walk traversal (subtree pruning and
    /// per-entry filtering) and intersected with per-request shard bounds.
    /// `None` means unbounded on that side.
    ///
    /// If the configured bounds collapse to an empty interval (`start >= end`),
    /// enumeration becomes a no-op (empty pages, unchanged cursor) instead of
    /// returning an error.
    pub fn with_key_range(mut self, start: Option<&[u8]>, end: Option<&[u8]>) -> Self {
        self.walk_key_range_start = start.map(|bound| bound.to_vec().into_boxed_slice());
        self.walk_key_range_end = end.map(|bound| bound.to_vec().into_boxed_slice());
        self
    }

    #[must_use]
    /// Restrict traversal using shard-style byte bounds `[start, end)`.
    ///
    /// Empty slices are treated as unbounded on that side, matching
    /// [`ShardSpec`] semantics.
    pub fn with_shard_bounds(self, start: &[u8], end: &[u8]) -> Self {
        let start = (!start.is_empty()).then_some(start);
        let end = (!end.is_empty()).then_some(end);
        self.with_key_range(start, end)
    }

    #[must_use]
    /// Set a hard ceiling on DFS depth.
    ///
    /// Exceeding this limit does not fail enumeration; affected subtrees are
    /// skipped with [`WalkWarning`] entries.
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

    /// Return collected non-fatal walk diagnostics for this connector instance.
    ///
    /// Warnings accumulate across pages and cursor re-alignments until the
    /// connector is dropped.
    pub fn walk_warnings(&self) -> &[WalkWarning] {
        &self.walk_warnings
    }

    /// Number of walk warnings dropped because the buffer was full.
    pub fn overflow_warning_count(&self) -> usize {
        self.overflow_warning_count
    }

    // ---------------------------------------------------------------
    // Walk initialization + cursor alignment
    // ---------------------------------------------------------------

    /// Canonicalize and open the root directory once, then cache its fd.
    ///
    /// This method retries on every call when the root is unavailable rather
    /// than latching permanent failures. The streaming walk model intentionally
    /// omits failure memoization because root-directory conditions can change
    /// between calls (e.g., a mount appearing, permissions being adjusted),
    /// and the per-attempt cost is low (3-4 syscalls).
    ///
    /// Root identity is verified by capturing the canonical path's `(dev, ino)`
    /// *before* opening, then comparing it to the opened fd's `fstat` result.
    /// This narrows the TOCTOU window: the race is stat→open (same direction)
    /// rather than open→stat where the fd could refer to a different directory
    /// than the one we stat'd.
    fn ensure_root_fd(&mut self) -> Result<(), EnumerateError> {
        if self.root_fd.is_some() {
            return Ok(());
        }

        // Canonicalize root to prevent cwd drift and resolve root symlinks.
        self.root = fs::canonicalize(&self.root)
            .map_err(|err| classify_io_enumerate_error("canonicalize", &self.root, &err))?;

        // Capture path identity BEFORE open so the authoritative check is
        // fstat on the fd (which cannot be swapped out from under us).
        let path_meta = fs::metadata(&self.root)
            .map_err(|err| classify_io_enumerate_error("stat_root", &self.root, &err))?;
        let expected_id = (path_meta.dev(), path_meta.ino());

        // Open root as a directory fd for openat-based reads.
        let root_fd = open_dir_fd(&self.root)
            .map_err(|err| classify_io_enumerate_error("open_root_dir", &self.root, &err))?;

        // Verify the opened fd matches the pre-captured identity.
        verify_root_identity(&root_fd, expected_id)
            .map_err(|err| classify_io_enumerate_error("verify_root_identity", &self.root, &err))?;

        self.root_fd = Some(root_fd);
        Ok(())
    }

    /// Lazily create [`WalkState`] for the first enumeration request.
    fn start_walk_if_needed(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        self.ensure_root_fd()?;
        if self.walk_state.is_some() {
            return Ok(());
        }

        let state = WalkState::new(
            &self.root,
            deadline,
            self.max_warnings,
            &mut self.walk_warnings,
            &mut self.overflow_warning_count,
        )?;
        self.walk_state = Some(state);
        Ok(())
    }

    /// Rebuild traversal state from root and drop any cached read handle.
    ///
    /// We clear `cached_file` because seek-style cursor jumps can move reads to
    /// unrelated paths, and keeping stale per-file cache entries provides no
    /// locality benefit after a full rewind.
    fn reset_walk_state(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        let state = WalkState::new(
            &self.root,
            deadline,
            self.max_warnings,
            &mut self.walk_warnings,
            &mut self.overflow_warning_count,
        )?;
        self.cached_file = None;
        self.walk_state = Some(state);
        Ok(())
    }

    /// Compare resume authority (`last_key`) between in-memory state and cursor.
    ///
    /// An exhausted walk that never emitted any key (`last_emitted_key == None`)
    /// must NOT match an initial cursor (`last_key == None`), because the caller
    /// may be starting a different range and needs a fresh walk. Without this
    /// guard, reusing a connector across ranges silently drops results.
    fn cursor_matches_state(state: &WalkState, cursor: &Cursor) -> bool {
        match (state.last_emitted_key.as_ref(), cursor.last_key()) {
            (None, None) => !state.exhausted,
            (Some(state_key), Some(cursor_key)) => state_key.as_bytes() == cursor_key.as_bytes(),
            _ => false,
        }
    }

    /// Advance the active walk to the first file strictly greater than `last_key`.
    ///
    /// The selected file is staged into `WalkState::pending` so page assembly
    /// can emit it without re-traversal.
    fn seek_after_last_key(
        &mut self,
        last_key: &ItemKey,
        walk_query: WalkQuery<'_>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let mut skipped = 0usize;
        {
            let state = self
                .walk_state
                .as_mut()
                .expect("walk state must exist while seeking to cursor");
            state.pending = None;
        }

        loop {
            let next = {
                let state = self
                    .walk_state
                    .as_mut()
                    .expect("walk state must exist while seeking to cursor");
                state.next_file(
                    walk_query,
                    &mut self.walk_warnings,
                    &mut self.overflow_warning_count,
                )?
            };
            let Some(file) = next else {
                break;
            };
            if file.key.as_bytes() > last_key.as_bytes() {
                let state = self
                    .walk_state
                    .as_mut()
                    .expect("walk state must exist while seeking to cursor");
                state.pending = Some(file);
                break;
            }
            skipped += 1;
        }

        let state = self
            .walk_state
            .as_mut()
            .expect("walk state must exist while finalizing cursor seek");
        state.last_emitted_key = Some(last_key.clone());
        state.emitted_count = skipped;
        Ok(state.pending.as_ref().map(|file| file.key.clone()))
    }

    /// Walk from root to find the first key strictly greater than `last_key`.
    ///
    /// Used as the ground-truth reference for token resume cross-checks.
    /// Runs unconditionally after token resume to detect divergence from stale
    /// or corrupted tokens; on mismatch the key-only result is adopted and the
    /// token result is discarded.
    fn key_only_resume_probe(
        &mut self,
        last_key: &ItemKey,
        walk_query: WalkQuery<'_>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let mut probe_warnings = Vec::new();
        let mut probe_overflow = 0usize;
        let mut probe = WalkState::new(
            &self.root,
            walk_query.deadline,
            self.max_warnings,
            &mut probe_warnings,
            &mut probe_overflow,
        )?;

        loop {
            let next = probe.next_file(walk_query, &mut probe_warnings, &mut probe_overflow)?;
            let Some(file) = next else {
                return Ok(None);
            };
            if file.key.as_bytes() > last_key.as_bytes() {
                return Ok(Some(file.key));
            }
        }
    }

    /// Ensure traversal state is aligned with the caller-provided cursor.
    ///
    /// On mismatch we first try rebuilding from the advisory walk token. Any
    /// decode/restore failure falls back to key-only seek from root.
    fn align_walk_to_cursor(
        &mut self,
        cursor: &Cursor,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        deadline: Option<Instant>,
    ) -> Result<(), EnumerateError> {
        self.start_walk_if_needed(deadline)?;

        if Self::cursor_matches_state(
            self.walk_state
                .as_ref()
                .expect("walk state must exist after start_walk_if_needed"),
            cursor,
        ) {
            return Ok(());
        }

        self.cached_file = None;
        let root = self.root.clone();
        let walk_query = WalkQuery {
            root: &root,
            max_depth: self.max_walk_depth,
            start,
            end,
            deadline,
            max_warnings: self.max_warnings,
        };

        let Some(last_key) = cursor.last_key() else {
            self.reset_walk_state(deadline)?;
            return Ok(());
        };

        let mut resumed_from_token = false;
        if self.emit_tokens
            && let Some(walk_token) = WalkToken::decode_cursor_token(cursor)
            && let Some(restored) = WalkState::from_token(
                &root,
                &walk_token,
                self.max_walk_depth,
                deadline,
                self.max_warnings,
                &mut self.walk_warnings,
                &mut self.overflow_warning_count,
            )?
        {
            self.walk_state = Some(restored);
            let token_next = self.seek_after_last_key(last_key, walk_query)?;

            // Cross-check: verify token-based resume agrees with key-only resume.
            // A stale or corrupted token may position the walker past directories
            // that still contain unvisited keys > last_key. When divergence is
            // detected, discard the token result and adopt the key-only position.
            //
            // The probe uses an unbounded deadline so a tight page budget cannot
            // turn a successful token restore into a spurious retryable error.
            let probe_query = WalkQuery {
                deadline: None,
                ..walk_query
            };
            let key_next = self.key_only_resume_probe(last_key, probe_query)?;
            let token_matches = token_next.as_ref().map(|k| k.as_bytes())
                == key_next.as_ref().map(|k| k.as_bytes());

            if token_matches {
                resumed_from_token = true;
            }
            // On mismatch, fall through to key-only resume below.
        }

        if !resumed_from_token {
            self.reset_walk_state(deadline)?;
            let _ = self.seek_after_last_key(last_key, walk_query)?;
        }

        Ok(())
    }

    /// Build the next cursor from `last_key` plus optional walk-state token.
    ///
    /// Token construction failures (for example size-budget truncation to zero)
    /// degrade to key-only cursors by design.
    fn build_next_walk_cursor(&self, last_key: ItemKey) -> Cursor {
        if !self.emit_tokens {
            return Cursor::with_last_key(last_key);
        }
        match self
            .walk_state
            .as_ref()
            .and_then(WalkToken::encode_from_state)
        {
            Some(token) => Cursor::with_token(last_key, token),
            None => Cursor::with_last_key(last_key),
        }
    }

    // ---------------------------------------------------------------
    // Enumeration
    // ---------------------------------------------------------------

    /// Enumerate one page over the explicit half-open key range `[start, end)`.
    ///
    /// This entry point bypasses [`ShardSpec`] decoding, letting tests exercise
    /// the core pagination logic (including persistent walk state) with
    /// known-good bounds and without constructing a full shard object.
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

    /// Core page enumeration used by both shard-based and explicit-range APIs.
    ///
    /// This method advances a resumable DFS walk state directly, skipping
    /// out-of-range entries and emitting up to `budgets.max_items()` items.
    /// Connector-level walk bounds from [`Self::with_key_range`] are intersected
    /// with per-request bounds before traversal.
    ///
    /// Cursor handling is key-authoritative: when the in-memory walk cursor does
    /// not match `cursor.last_key`, the connector first attempts token-based
    /// stack restore, then falls back to root rebuild and key-only seek.
    ///
    /// If no in-range items are available for this call, the returned page is
    /// empty and the cursor is left unchanged.
    fn enumerate_page_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        if budgets.is_expired_at(Instant::now()) {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        if let (Some(s), Some(e)) = (start, end)
            && s > e
        {
            return Err(EnumerateError::permanent("shard start key exceeds end key"));
        }

        // Clone connector bounds so the returned slices don't borrow `self`,
        // letting us take `&mut self` for walk operations below.
        let config_start = self.walk_key_range_start.clone();
        let config_end = self.walk_key_range_end.clone();

        let Some((effective_start, effective_end)) =
            intersect_key_bounds(start, end, config_start.as_deref(), config_end.as_deref())
        else {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        };

        self.align_walk_to_cursor(cursor, effective_start, effective_end, budgets.deadline())?;

        let mut page_files = Vec::with_capacity(budgets.max_items());
        let walk_query = WalkQuery {
            root: &self.root,
            max_depth: self.max_walk_depth,
            start: effective_start,
            end: effective_end,
            deadline: budgets.deadline(),
            max_warnings: self.max_warnings,
        };
        while page_files.len() < budgets.max_items() {
            if budgets.is_expired_at(Instant::now()) {
                return Err(EnumerateError::retryable("budget deadline expired"));
            }

            let next = {
                let state = self
                    .walk_state
                    .as_mut()
                    .expect("walk state must exist while enumerating");
                state.next_file(
                    walk_query,
                    &mut self.walk_warnings,
                    &mut self.overflow_warning_count,
                )?
            };
            let Some(file) = next else {
                break;
            };

            if effective_start.is_some_and(|lower| file.key.as_bytes() < lower) {
                continue;
            }
            if effective_end.is_some_and(|upper| file.key.as_bytes() >= upper) {
                // Keys are globally sorted; once we cross the exclusive upper
                // bound, stash this file for potential reuse by a later request.
                let state = self
                    .walk_state
                    .as_mut()
                    .expect("walk state must exist while enumerating");
                state.pending = Some(file);
                break;
            }

            debug_assert!(
                page_files
                    .last()
                    .is_none_or(|prev: &FileEntry| file.key > prev.key),
                "filesystem walk must produce strictly ascending keys"
            );

            page_files.push(file);
        }

        {
            let count = page_files.len();
            let state = self
                .walk_state
                .as_mut()
                .expect("walk state must exist after page production");
            if let Some(last) = page_files.last() {
                state.last_emitted_key = Some(last.key.clone());
            }
            state.emitted_count = state
                .emitted_count
                .checked_add(count)
                .ok_or_else(|| EnumerateError::permanent("emitted count overflow"))?;
        }

        if page_files.is_empty() {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let staged = common::assemble_pooled_page_shared_key_ref(
            page_files.iter().map(|file| file.key.as_bytes()),
            false,
            0,
        )?;
        let common::StagedPage { wrappers, token: _ } = staged;
        let mut out = Vec::with_capacity(wrappers.len());
        for ((item_key, item_ref), file) in wrappers.into_iter().zip(page_files.into_iter()) {
            out.push(
                ScanItem::new(item_key, item_ref, file.stable_item_id, file.version)
                    .with_size_hint(file.size),
            );
        }

        let last_key = out
            .last()
            .expect("page_files non-empty implies staged output non-empty")
            .item_key()
            .clone();
        let next_cursor = self.build_next_walk_cursor(last_key);

        Ok(EnumerationPage::new(out, next_cursor))
    }

    // ---------------------------------------------------------------
    // Split-point selection
    // ---------------------------------------------------------------

    /// Return a split-point hint over the explicit half-open key range
    /// `[start, end)`.
    ///
    /// This entry point mirrors shard-based split behavior without requiring a
    /// [`ShardSpec`], keeping split-point unit tests focused and self-contained.
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
        self.choose_split_point_bounds(Some(start.as_bytes()), Some(end.as_bytes()), cursor, None)
    }

    /// Split hints are intentionally disabled until streaming quantiles land.
    ///
    /// This still validates deadline and range bounds so callers get consistent
    /// retryable/permanent classification even while hints are unavailable.
    fn choose_split_point_bounds(
        &mut self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        _cursor: &Cursor,
        deadline: Option<Instant>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        if let Some(dl) = deadline
            && Instant::now() >= dl
        {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        if let (Some(s), Some(e)) = (start, end)
            && s > e
        {
            return Err(EnumerateError::permanent("shard start key exceeds end key"));
        }
        Ok(None)
    }

    // ---------------------------------------------------------------
    // Read-path: openat traversal
    // ---------------------------------------------------------------

    /// Open a file beneath `root_fd` using component-by-component `openat`
    /// with `O_NOFOLLOW` at every step.
    ///
    /// The returned file descriptor has `O_NONBLOCK` set (to avoid blocking on
    /// FIFOs or device nodes in a TOCTOU race). Callers must [`clear_nonblock`]
    /// before performing any reads. Returned metadata is from the opened fd
    /// itself (not from path re-resolution) and is used to enforce regular-file
    /// reads only.
    fn open_beneath_root(&self, ref_bytes: &[u8]) -> Result<(fs::File, fs::Metadata), ReadError> {
        let root_fd = self
            .root_fd
            .as_ref()
            .ok_or_else(|| ReadError::permanent("root directory handle is unavailable"))?;

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
            // Defense-in-depth: `encode_rel_path` only produces normal segments,
            // and openat confinement prevents root escape even for hostile refs.
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
                return Err(classify_io_read_error(
                    &format!("openat component {}/{n}", i + 1),
                    None,
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
            .map_err(|e| classify_io_read_error("fstat", None, &e))?;
        if !metadata.is_file() {
            return Err(ReadError::permanent("path is not a regular file"));
        }

        Ok((file, metadata))
    }

    /// Return a cached file handle when the `item_ref` matches, else reopen.
    ///
    /// Cache size is intentionally one entry to match dominant sequential range
    /// reads without retaining unbounded descriptors.
    fn get_or_open_cached(&mut self, item_ref: &ItemRef) -> Result<&fs::File, ReadError> {
        let ref_bytes = item_ref.as_bytes();
        let need_open = self
            .cached_file
            .as_ref()
            .is_none_or(|cached| cached.item_ref.as_ref() != ref_bytes);
        if need_open {
            self.ensure_root_fd().map_err(enumerate_error_to_read)?;
            let (file, _metadata) = self.open_beneath_root(ref_bytes)?;
            clear_nonblock(&file)?;
            self.cached_file = Some(CachedFile {
                item_ref: ref_bytes.into(),
                file,
            });
        }
        Ok(&self.cached_file.as_ref().expect("cache must exist").file)
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
            split_hints: false,
        }
    }

    /// Shard bounds are validated allocation-free via the internal
    /// `borrowed_shard_bound` helper (`[]` means unbounded; oversize is permanent).
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

    /// Split hints are disabled while streaming quantile support is pending.
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
        self.ensure_root_fd().map_err(enumerate_error_to_read)?;
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
        // Keep arithmetic explicit so offset checks fail permanently instead of
        // wrapping through usize conversions on large inputs.
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
            .map_err(|err| classify_io_read_error("read_at", None, &err))
    }
}

// ---------------------------------------------------------------------------
// Directory walk
// ---------------------------------------------------------------------------

/// Entries between intra-directory deadline checks during the walk.
///
/// Balances deadline responsiveness against `Instant::now()` syscall overhead.
const DEADLINE_CHECK_INTERVAL: usize = 512;

/// Hard cap on entries buffered from a single directory.
///
/// Pathological directories (e.g. `/proc`-like mounts or intentional DoS via
/// millions of files in one folder) could otherwise exhaust memory during the
/// sort step. 500K entries × ~40 bytes ≈ 20 MB, which is large but bounded.
const MAX_ENTRIES_PER_DIR: usize = 500_000;

#[inline]
/// Append a warning until capacity is reached, then increment overflow count.
fn push_walk_warning(
    warnings: &mut Vec<WalkWarning>,
    max_warnings: usize,
    overflow_count: &mut usize,
    warning: WalkWarning,
) {
    if warnings.len() < max_warnings {
        warnings.push(warning);
    } else {
        *overflow_count += 1;
    }
}

#[inline]
/// Return a retryable error once `deadline` has passed.
fn check_walk_deadline(deadline: Option<Instant>) -> Result<(), EnumerateError> {
    if let Some(dl) = deadline
        && Instant::now() >= dl
    {
        return Err(EnumerateError::retryable("budget deadline expired"));
    }
    Ok(())
}

#[inline]
/// Increment per-frame progress and poll deadline at a fixed cadence.
fn bump_entry_counter(
    frame: &mut WalkFrame,
    deadline: Option<Instant>,
) -> Result<(), EnumerateError> {
    frame.entries_since_check += 1;
    if frame.entries_since_check >= DEADLINE_CHECK_INTERVAL {
        frame.entries_since_check = 0;
        check_walk_deadline(deadline)?;
    }
    Ok(())
}

/// Compare two byte slices lexicographically, treating directory names as
/// if they had a virtual trailing `/` byte for ordering.
///
/// This mirrors Git tree ordering (`name` vs `name/`) and is the key
/// comparator that makes local per-directory sorting equivalent to sorting
/// fully encoded relative paths globally.
#[inline]
fn cmp_with_trailing_sep(
    left: &[u8],
    left_is_dir: bool,
    right: &[u8],
    right_is_dir: bool,
) -> std::cmp::Ordering {
    let l = left.iter().copied().chain(left_is_dir.then_some(b'/'));
    let r = right.iter().copied().chain(right_is_dir.then_some(b'/'));
    l.cmp(r)
}

#[inline]
fn cmp_dir_entry(left: &BufferedDirEntry, right: &BufferedDirEntry) -> std::cmp::Ordering {
    cmp_with_trailing_sep(
        left.name.as_bytes(),
        left.file_type.is_dir(),
        right.name.as_bytes(),
        right.file_type.is_dir(),
    )
}

/// Intersect request `[start, end)` with connector-level key-range bounds.
///
/// Returns the tighter of each pair, or `None` when the intersection
/// collapses to an empty interval (`effective_start >= effective_end`).
#[allow(clippy::type_complexity)]
fn intersect_key_bounds<'a>(
    request_start: Option<&'a [u8]>,
    request_end: Option<&'a [u8]>,
    config_start: Option<&'a [u8]>,
    config_end: Option<&'a [u8]>,
) -> Option<(Option<&'a [u8]>, Option<&'a [u8]>)> {
    let effective_start = match config_start {
        Some(cs) => Some(match request_start {
            Some(rs) if rs >= cs => rs,
            _ => cs,
        }),
        None => request_start,
    };
    let effective_end = match config_end {
        Some(ce) => Some(match request_end {
            Some(re) if re <= ce => re,
            _ => ce,
        }),
        None => request_end,
    };
    match (effective_start, effective_end) {
        (Some(s), Some(e)) if s >= e => None,
        bounds => Some(bounds),
    }
}

#[inline]
fn decode_u16_le(bytes: &[u8], offset: &mut usize) -> Option<u16> {
    let end = offset.checked_add(std::mem::size_of::<u16>())?;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(u16::from_le_bytes(chunk.try_into().ok()?))
}

#[inline]
fn decode_u32_le(bytes: &[u8], offset: &mut usize) -> Option<u32> {
    let end = offset.checked_add(std::mem::size_of::<u32>())?;
    let chunk = bytes.get(*offset..end)?;
    *offset = end;
    Some(u32::from_le_bytes(chunk.try_into().ok()?))
}

impl WalkToken {
    #[inline]
    fn decode_cursor_token(cursor: &Cursor) -> Option<Self> {
        cursor
            .token()
            .and_then(|token| Self::decode_bytes(token.as_bytes()))
    }

    fn decode_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.first().copied()? != WALK_TOKEN_VERSION {
            return None;
        }

        let mut offset = 1usize;
        let frame_count = decode_u16_le(bytes, &mut offset)? as usize;
        let mut frames = Vec::with_capacity(frame_count);
        for frame_idx in 0..frame_count {
            let component_len = decode_u16_le(bytes, &mut offset)? as usize;
            let component_end = offset.checked_add(component_len)?;
            let component = bytes.get(offset..component_end)?.to_vec();
            offset = component_end;
            let next_child_index = decode_u32_le(bytes, &mut offset)?;

            // Root frame uses an empty component; all non-root frames must have
            // non-empty component bytes and represent a single path segment.
            // Reject `.` and `..` to prevent path traversal outside the root.
            if frame_idx == 0 {
                if !component.is_empty() {
                    return None;
                }
            } else if component.is_empty()
                || component.contains(&b'/')
                || component.contains(&0)
                || component == b"."
                || component == b".."
            {
                return None;
            }

            frames.push(WalkTokenFrame {
                component,
                next_child_index,
            });
        }

        if offset != bytes.len() {
            return None;
        }

        Some(Self { frames })
    }

    fn encode_from_state(state: &WalkState) -> Option<TokenBytes> {
        if state.stack.is_empty() {
            return None;
        }

        let mut frames: Vec<WalkTokenFrame> = state
            .stack
            .iter()
            .map(|frame| WalkTokenFrame {
                component: frame
                    .component
                    .as_ref()
                    .map_or_else(Vec::new, |component| component.as_bytes().to_vec()),
                next_child_index: frame.next_child_index,
            })
            .collect();

        let total_frames = frames.len().min(u16::MAX as usize);
        frames.truncate(total_frames);

        let mut encoded_size = 1usize + std::mem::size_of::<u16>();
        let mut keep = 0usize;
        for frame in &frames {
            if frame.component.len() > u16::MAX as usize {
                break;
            }
            let frame_size = std::mem::size_of::<u16>()
                .checked_add(frame.component.len())?
                .checked_add(std::mem::size_of::<u32>())?;
            let next_size = encoded_size.checked_add(frame_size)?;
            if next_size > MAX_TOKEN_SIZE {
                break;
            }
            encoded_size = next_size;
            keep += 1;
        }

        if keep == 0 {
            return None;
        }

        let truncated = keep < total_frames;
        frames.truncate(keep);

        // Invariant: in the DFS walk, the last entry consumed by the retained
        // leaf frame is always the directory entry whose child frames are being
        // dropped. Rewinding `next_child_index` by one forces that directory to
        // be re-entered on resume so its descendants are not silently skipped.
        //
        // This relies on DFS never advancing a parent frame past the entry that
        // caused descent while deeper frames are active on the stack.
        if truncated && let Some(last) = frames.last_mut() {
            last.next_child_index = last.next_child_index.saturating_sub(1);
        }

        let frame_count = u16::try_from(frames.len()).ok()?;
        let mut out = Vec::with_capacity(encoded_size);
        out.push(WALK_TOKEN_VERSION);
        out.extend_from_slice(&frame_count.to_le_bytes());
        for frame in frames {
            let component_len = u16::try_from(frame.component.len()).ok()?;
            out.extend_from_slice(&component_len.to_le_bytes());
            out.extend_from_slice(&frame.component);
            out.extend_from_slice(&frame.next_child_index.to_le_bytes());
        }
        TokenBytes::try_from_vec(out).ok()
    }
}

/// Compute the lexicographic successor of `prefix` by incrementing the last byte.
///
/// Returns `None` when the input is empty or the last byte is `0xFF` (no finite
/// successor without carry propagation). The result is stored in an `InlineVec`
/// to avoid heap allocation for typical path-length prefixes (< 256 bytes).
pub(crate) fn prefix_successor(prefix: &[u8]) -> Option<InlineVec<u8, 256>> {
    let last = *prefix.last()?;
    if last == u8::MAX {
        return None;
    }
    let mut out = InlineVec::<u8, 256>::new();
    out.extend_from_slice(&prefix[..prefix.len() - 1]);
    out.push(last + 1);
    Some(out)
}

/// Return `true` when a directory subtree cannot overlap `[shard_start, shard_end)`.
///
/// `dir_prefix` is the encoded key prefix without a trailing `/` (for example
/// `b"src/lib"`). Keys under the subtree are bounded by:
/// - inclusive lower bound: `dir_prefix + b'/'`
/// - exclusive upper bound: the byte-level successor of that lower bound
///
/// The implementation is conservative: `true` means safe-to-skip; `false` may
/// still be out of range but is kept to avoid false-positive pruning. Empty
/// prefixes (root) and prefixes whose last byte is `0xFF` (no finite successor)
/// are never pruned on the below-range side.
pub(crate) fn should_skip_subtree(
    dir_prefix: &[u8],
    shard_start: Option<&[u8]>,
    shard_end: Option<&[u8]>,
) -> bool {
    if dir_prefix.is_empty() {
        return false;
    }

    // Subtree entirely below range: prefix_successor(dir_prefix + b'/') <= shard_start.
    // The subtree key `dir_prefix + b'/'` has successor `dir_prefix[..n-1] + (last+1)`
    // because b'/' (0x2F) increments to 0x30.
    let mut subtree_key = InlineVec::<u8, 256>::new();
    subtree_key.extend_from_slice(dir_prefix);
    subtree_key.push(b'/');
    if let Some(successor) = prefix_successor(subtree_key.as_slice())
        && shard_start.is_some_and(|start| successor.as_slice() <= start)
    {
        return true;
    }

    // Subtree entirely above range: shard_end <= dir_prefix + b'/'.
    shard_end.is_some_and(|end| end <= subtree_key.as_slice())
}

/// Eagerly read and sort one directory frame before DFS descent.
///
/// This intentionally spends memory per active frame (`Vec` + `VecDeque`) so
/// enumeration can yield globally ordered keys without building a full-tree
/// index.
fn read_dir_sorted_entries(
    reader: fs::ReadDir,
    dir_path: &Path,
    deadline: Option<Instant>,
    max_warnings: usize,
    overflow_count: &mut usize,
    warnings: &mut Vec<WalkWarning>,
) -> Result<VecDeque<BufferedDirEntry>, EnumerateError> {
    let mut buffered = Vec::with_capacity(256);
    let mut entries_since_check = 0usize;
    for entry_result in reader {
        entries_since_check += 1;
        if entries_since_check >= DEADLINE_CHECK_INTERVAL {
            entries_since_check = 0;
            check_walk_deadline(deadline)?;
        }

        let entry = match entry_result {
            Ok(entry) => entry,
            Err(err) => {
                push_walk_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::io(dir_path, "read_dir entry", &err),
                );
                continue;
            }
        };

        let name = entry.file_name();
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(err) => {
                let mut entry_path = dir_path.to_path_buf();
                entry_path.push(&name);
                push_walk_warning(
                    warnings,
                    max_warnings,
                    overflow_count,
                    WalkWarning::io(&entry_path, "file_type", &err),
                );
                continue;
            }
        };
        buffered.push(BufferedDirEntry { name, file_type });
        if buffered.len() >= MAX_ENTRIES_PER_DIR {
            return Err(EnumerateError::retryable(
                "directory exceeds maximum entry count",
            ));
        }
    }
    buffered.sort_unstable_by(cmp_dir_entry);
    Ok(VecDeque::from(buffered))
}

#[inline]
fn fast_forward_frame_entries(
    entries: &mut VecDeque<BufferedDirEntry>,
    next_child_index: u32,
) -> Option<()> {
    let to_skip = usize::try_from(next_child_index).ok()?;
    if to_skip > entries.len() {
        return None;
    }
    entries.drain(..to_skip);
    Some(())
}

impl WalkState {
    /// Build a fresh traversal state rooted at `root`.
    ///
    /// Root entries are buffered and sorted up front; deeper directories are
    /// loaded lazily on descent.
    fn new(
        root: &Path,
        deadline: Option<Instant>,
        max_warnings: usize,
        warnings: &mut Vec<WalkWarning>,
        overflow_count: &mut usize,
    ) -> Result<Self, EnumerateError> {
        check_walk_deadline(deadline)?;
        let root_reader = fs::read_dir(root)
            .map_err(|err| classify_io_enumerate_error("read_dir", root, &err))?;
        let root_entries = read_dir_sorted_entries(
            root_reader,
            root,
            deadline,
            max_warnings,
            overflow_count,
            warnings,
        )?;

        // Seed visited set with the root directory identity so cycles back
        // to root are detected immediately.
        let mut visited_dirs = HashSet::new();
        if let Ok(root_meta) = fs::metadata(root) {
            visited_dirs.insert((root_meta.dev(), root_meta.ino()));
        }

        Ok(Self {
            stack: vec![WalkFrame {
                component: None,
                depth: 0,
                entries_since_check: 0,
                next_child_index: 0,
                entries: root_entries,
            }],
            current_path: {
                // Pre-allocate for root + one page of typical path components
                // to avoid repeated small reallocations during DFS descent.
                let mut buf = OsString::with_capacity(root.as_os_str().len() + 4096);
                buf.push(root);
                PathBuf::from(buf)
            },
            pending: None,
            last_emitted_key: None,
            emitted_count: 0,
            exhausted: false,
            visited_dirs,
        })
    }

    /// Rebuild traversal state from a serialized walk token.
    ///
    /// Returns `Ok(None)` when token data is syntactically valid but cannot be
    /// restored against the current filesystem view (missing path, out-of-range
    /// child index, or cycle identity mismatch). Callers should fall back to
    /// key-only resume in that case.
    fn from_token(
        root: &Path,
        token: &WalkToken,
        max_depth: usize,
        deadline: Option<Instant>,
        max_warnings: usize,
        warnings: &mut Vec<WalkWarning>,
        overflow_count: &mut usize,
    ) -> Result<Option<Self>, EnumerateError> {
        let Some((root_frame, child_frames)) = token.frames.split_first() else {
            return Ok(None);
        };
        if !root_frame.component.is_empty() {
            return Ok(None);
        }
        if child_frames.len() > max_depth {
            return Ok(None);
        }

        check_walk_deadline(deadline)?;
        let root_reader = match fs::read_dir(root) {
            Ok(reader) => reader,
            Err(_) => return Ok(None),
        };
        let mut root_entries = read_dir_sorted_entries(
            root_reader,
            root,
            deadline,
            max_warnings,
            overflow_count,
            warnings,
        )?;
        if fast_forward_frame_entries(&mut root_entries, root_frame.next_child_index).is_none() {
            return Ok(None);
        }
        // A non-leaf root (has child frames) must retain at least one entry
        // after fast-forward; an empty deque would silently lose sibling files
        // that appear after the child subtree in DFS order.
        if !child_frames.is_empty() && root_entries.is_empty() {
            return Ok(None);
        }

        let mut visited_dirs = HashSet::new();
        if let Ok(root_meta) = fs::metadata(root) {
            visited_dirs.insert((root_meta.dev(), root_meta.ino()));
        }

        let mut stack = Vec::with_capacity(token.frames.len());
        stack.push(WalkFrame {
            component: None,
            depth: 0,
            entries_since_check: 0,
            next_child_index: root_frame.next_child_index,
            entries: root_entries,
        });

        let mut current_path = {
            let mut buf = OsString::with_capacity(root.as_os_str().len() + 4096);
            buf.push(root);
            PathBuf::from(buf)
        };

        for (depth, frame) in child_frames.iter().enumerate() {
            if frame.component.is_empty()
                || frame.component.contains(&b'/')
                || frame.component.contains(&0)
                || frame.component == b"."
                || frame.component == b".."
            {
                return Ok(None);
            }
            let component = OsString::from_vec(frame.component.clone());
            current_path.push(&component);

            if let Ok(dir_meta) = fs::metadata(&current_path) {
                let dir_id = (dir_meta.dev(), dir_meta.ino());
                if !visited_dirs.insert(dir_id) {
                    return Ok(None);
                }
            }

            check_walk_deadline(deadline)?;
            let reader = match fs::read_dir(&current_path) {
                Ok(reader) => reader,
                Err(_) => return Ok(None),
            };
            let mut entries = read_dir_sorted_entries(
                reader,
                &current_path,
                deadline,
                max_warnings,
                overflow_count,
                warnings,
            )?;
            if fast_forward_frame_entries(&mut entries, frame.next_child_index).is_none() {
                return Ok(None);
            }
            // Non-leaf child frames (those that still have deeper children on
            // the stack) must retain at least one entry after fast-forward;
            // otherwise sibling files after the child subtree are lost.
            let is_last_child = depth == child_frames.len() - 1;
            if !is_last_child && entries.is_empty() {
                return Ok(None);
            }

            stack.push(WalkFrame {
                component: Some(component),
                depth: depth + 1,
                entries_since_check: 0,
                next_child_index: frame.next_child_index,
                entries,
            });
        }

        Ok(Some(Self {
            stack,
            current_path,
            pending: None,
            last_emitted_key: None,
            emitted_count: 0,
            exhausted: false,
            visited_dirs,
        }))
    }

    #[inline]
    /// Pop the next entry from a frame while maintaining deadline cadence.
    fn poll_frame(
        frame: &mut WalkFrame,
        deadline: Option<Instant>,
    ) -> Result<Option<BufferedDirEntry>, EnumerateError> {
        let Some(entry) = frame.entries.pop_front() else {
            return Ok(None);
        };
        frame.next_child_index = frame
            .next_child_index
            .checked_add(1)
            .ok_or_else(|| EnumerateError::permanent("walk frame index overflow"))?;
        bump_entry_counter(frame, deadline)?;
        Ok(Some(entry))
    }

    /// Produce the next regular file in sorted DFS order.
    ///
    /// The walker is resilient to filesystem churn: unreadable entries,
    /// symlinks, special files, and encoding failures become warnings and are
    /// skipped. Hard failures are limited to deadline expiry and retryable
    /// directory-buffer limits (for example `MAX_ENTRIES_PER_DIR` overflow)
    /// plus root/bootstrap I/O classified by [`classify_io_enumerate_error`].
    fn next_file(
        &mut self,
        query: WalkQuery<'_>,
        warnings: &mut Vec<WalkWarning>,
        overflow_count: &mut usize,
    ) -> Result<Option<FileEntry>, EnumerateError> {
        if let Some(file) = self.pending.take() {
            return Ok(Some(file));
        }
        if self.exhausted {
            return Ok(None);
        }

        while !self.stack.is_empty() {
            let maybe_entry = {
                let frame = self.stack.last_mut().expect("non-empty walk stack");
                Self::poll_frame(frame, query.deadline)?
            };

            let entry = match maybe_entry {
                Some(entry) => entry,
                None => {
                    let popped = self.stack.pop().expect("non-empty walk stack");
                    if popped.component.is_some() {
                        let _ = self.current_path.pop();
                    }
                    continue;
                }
            };

            let depth = self
                .stack
                .last()
                .expect("active frame must exist when entry is produced")
                .depth;

            self.current_path.push(&entry.name);

            if entry.file_type.is_symlink() {
                push_walk_warning(
                    warnings,
                    query.max_warnings,
                    overflow_count,
                    WalkWarning::skipped(&self.current_path, "symlink"),
                );
                let _ = self.current_path.pop();
                continue;
            }

            if entry.file_type.is_dir() {
                // Key-range subtree pruning: only worth the prefix computation
                // when at least one bound is present.
                if query.start.is_some() || query.end.is_some() {
                    let rel_dir = match self.current_path.strip_prefix(query.root) {
                        Ok(rel) => rel,
                        Err(_) => {
                            push_walk_warning(
                                warnings,
                                query.max_warnings,
                                overflow_count,
                                WalkWarning::skipped(
                                    &self.current_path,
                                    "path escaped connector root",
                                ),
                            );
                            let _ = self.current_path.pop();
                            continue;
                        }
                    };
                    let dir_prefix = match encode_rel_path(rel_dir) {
                        Ok(prefix) => prefix,
                        Err(err) => {
                            push_walk_warning(
                                warnings,
                                query.max_warnings,
                                overflow_count,
                                WalkWarning::skipped(
                                    &self.current_path,
                                    &format!("path encoding failed: {}", err.message()),
                                ),
                            );
                            let _ = self.current_path.pop();
                            continue;
                        }
                    };
                    if should_skip_subtree(&dir_prefix, query.start, query.end) {
                        let _ = self.current_path.pop();
                        continue;
                    }
                }

                // Cycle detection: skip directories already visited (bind
                // mounts, directory hardlinks). Placed after pruning so that
                // a pruned directory does not poison the visited set — a
                // later in-range path to the same inode can still descend.
                if let Ok(dir_meta) = fs::metadata(&self.current_path) {
                    let dir_id = (dir_meta.dev(), dir_meta.ino());
                    if !self.visited_dirs.insert(dir_id) {
                        push_walk_warning(
                            warnings,
                            query.max_warnings,
                            overflow_count,
                            WalkWarning::skipped(
                                &self.current_path,
                                "directory cycle detected (duplicate dev/ino)",
                            ),
                        );
                        let _ = self.current_path.pop();
                        continue;
                    }
                }

                if depth < query.max_depth {
                    if let Err(e) = check_walk_deadline(query.deadline) {
                        let _ = self.current_path.pop();
                        return Err(e);
                    }
                    match fs::read_dir(&self.current_path) {
                        Ok(reader) => {
                            let child_entries = match read_dir_sorted_entries(
                                reader,
                                &self.current_path,
                                query.deadline,
                                query.max_warnings,
                                overflow_count,
                                warnings,
                            ) {
                                Ok(entries) => entries,
                                Err(e) => {
                                    let _ = self.current_path.pop();
                                    return Err(e);
                                }
                            };
                            self.stack.push(WalkFrame {
                                component: Some(entry.name),
                                depth: depth + 1,
                                entries_since_check: 0,
                                next_child_index: 0,
                                entries: child_entries,
                            });
                            continue;
                        }
                        Err(err) => {
                            push_walk_warning(
                                warnings,
                                query.max_warnings,
                                overflow_count,
                                WalkWarning::io(&self.current_path, "read_dir", &err),
                            );
                        }
                    }
                } else {
                    push_walk_warning(
                        warnings,
                        query.max_warnings,
                        overflow_count,
                        WalkWarning::skipped(&self.current_path, "exceeded maximum walk depth"),
                    );
                }

                let _ = self.current_path.pop();
                continue;
            }

            if !entry.file_type.is_file() {
                push_walk_warning(
                    warnings,
                    query.max_warnings,
                    overflow_count,
                    WalkWarning::skipped(&self.current_path, "special file (not regular)"),
                );
                let _ = self.current_path.pop();
                continue;
            }

            let metadata = match fs::symlink_metadata(&self.current_path) {
                Ok(m) => m,
                Err(err) => {
                    push_walk_warning(
                        warnings,
                        query.max_warnings,
                        overflow_count,
                        WalkWarning::io(&self.current_path, "metadata", &err),
                    );
                    let _ = self.current_path.pop();
                    continue;
                }
            };

            if !metadata.is_file() {
                push_walk_warning(
                    warnings,
                    query.max_warnings,
                    overflow_count,
                    WalkWarning::skipped(
                        &self.current_path,
                        "file type changed between readdir and stat",
                    ),
                );
                let _ = self.current_path.pop();
                continue;
            }

            let rel = match self.current_path.strip_prefix(query.root) {
                Ok(r) => r,
                Err(_) => {
                    push_walk_warning(
                        warnings,
                        query.max_warnings,
                        overflow_count,
                        WalkWarning::skipped(&self.current_path, "path escaped connector root"),
                    );
                    let _ = self.current_path.pop();
                    continue;
                }
            };

            let rel_bytes = match encode_rel_path(rel) {
                Ok(bytes) => bytes,
                Err(err) => {
                    push_walk_warning(
                        warnings,
                        query.max_warnings,
                        overflow_count,
                        WalkWarning::skipped(
                            &self.current_path,
                            &format!("path encoding failed: {}", err.message()),
                        ),
                    );
                    let _ = self.current_path.pop();
                    continue;
                }
            };

            if query
                .start
                .is_some_and(|lower| rel_bytes.as_slice() < lower)
            {
                let _ = self.current_path.pop();
                continue;
            }

            // Keys are globally sorted; once we exceed the upper bound every
            // subsequent key will too for the current query. Do not set
            // `self.exhausted` — the walk state may be reused with different
            // bounds, and the caller already handles `None` correctly.
            if query.end.is_some_and(|upper| rel_bytes.as_slice() >= upper) {
                let _ = self.current_path.pop();
                return Ok(None);
            }

            let key = match ItemKey::try_from_vec(rel_bytes) {
                Ok(key) => key,
                Err(err) => {
                    push_walk_warning(
                        warnings,
                        query.max_warnings,
                        overflow_count,
                        WalkWarning::skipped(
                            &self.current_path,
                            &format!("invalid file key: {err}"),
                        ),
                    );
                    let _ = self.current_path.pop();
                    continue;
                }
            };

            let stable_item_id = derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, &key);
            let version = VersionId::Weak(derive_fs_version_id(&metadata));
            let size = metadata.len();

            let _ = self.current_path.pop();
            return Ok(Some(FileEntry {
                key,
                stable_item_id,
                version,
                size,
            }));
        }

        self.exhausted = true;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Path encoding
// ---------------------------------------------------------------------------

/// Encode a relative path as a `/`-separated byte key.
///
/// Key ordering matches lexicographic path ordering on Unix because segments
/// are joined with `/` (0x2F). The encoding is reversible by splitting on `/`
/// since Unix filenames cannot contain `/`. Only
/// [`std::path::Component::Normal`] segments are accepted; `.`, `..`, and root
/// prefixes are rejected.
fn encode_rel_path(rel: &Path) -> Result<Vec<u8>, EnumerateError> {
    let mut out = Vec::new();
    for component in rel.components() {
        let normal = match component {
            std::path::Component::Normal(segment) => segment,
            _ => {
                return Err(EnumerateError::permanent(format!(
                    "path contains non-normal component ({})",
                    ToxicDigest::of_bytes(rel.as_os_str().as_bytes())
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
/// Content hashing would require reading every file during enumeration, turning
/// O(n) directory traversal into O(total_bytes) I/O. Metadata-based versioning
/// provides "good enough" change detection for filesystem sources while keeping
/// traversal fast. The trade-off: identical content with different mtimes gets
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
            None,
            &io::Error::last_os_error(),
        ));
    }
    // SAFETY: F_SETFL on a valid fd with flags obtained from F_GETFL above.
    let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) };
    if result < 0 {
        return Err(classify_io_read_error(
            "fcntl(F_SETFL)",
            None,
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

/// Extract `(dev, ino)` from an open file descriptor via `fstat`.
///
/// Used to verify that a directory fd matches the expected path identity,
/// closing the TOCTOU window between `open_dir_fd` and the walk.
fn fd_dev_ino(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `fstat` on a valid fd, writing into an uninitialized stat buffer.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fstat` succeeded, so the buffer is initialized.
    let stat = unsafe { stat.assume_init() };
    // Use `as u64` to be portable across platforms where st_dev/st_ino
    // may be narrower types, while allowing clippy to elide no-op casts.
    #[allow(clippy::unnecessary_cast)]
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Verify that the opened root fd matches a pre-captured `(dev, ino)` identity.
///
/// The caller captures the expected identity via `fs::metadata` *before*
/// opening the fd, then passes it here. This keeps the authoritative check
/// on the fd side (fstat cannot be raced) and narrows the TOCTOU window to
/// stat→open rather than open→stat.
///
/// # Error classification
///
/// The returned `io::Error` uses `ErrorKind::Other`, which
/// `is_permanent_io_error` does **not** recognize as permanent. This is
/// intentional: a directory swap is a transient environmental condition
/// (race with an external rename/mount), not a permanent attribute of the
/// path itself. Retryable classification allows callers to re-canonicalize and
/// re-open on the next attempt — at which point the fd and path will agree (or
/// the path will have vanished, producing a different permanent error).
fn verify_root_identity(root_fd: &OwnedFd, expected_id: (u64, u64)) -> Result<(), io::Error> {
    let (fd_dev, fd_ino) = fd_dev_ino(root_fd)?;
    if fd_dev != expected_id.0 || fd_ino != expected_id.1 {
        return Err(io::Error::other(
            "root directory changed between open and walk (dev/ino mismatch); retry with a fresh connector",
        ));
    }
    Ok(())
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
