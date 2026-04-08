//! Deterministic filesystem-backed ordered-content connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], which implements the
//! ordered-content source contract for local filesystem roots.
//!
//! # Purpose
//! Provides a deterministic, ordered-content source over a local Unix filesystem,
//! offering secure, lazy enumeration and bounded-memory read traversal.
//!
//! # Invariants
//! - **Bounded Memory**: The connector never loads the entire directory tree into memory.
//! - **Confinement**: Read operations are strictly confined to the canonical root directory using `openat` and `O_NOFOLLOW`.
//! - **Identity Preservation**: Single-file identities `(dev, ino)` must match their recorded state at initialization to prevent TOCTOU replacement attacks.
//! - **Ordering**: Item ordering matches the lexicographic order of relative path bytes.
//!
//! # Algorithm
//! - **Enumeration**: Lazily walks the canonical root using a depth-first traversal with a bounded stack.
//!   Directory siblings are sorted with a virtual trailing `/` to ensure depth-first traversal matches the lexicographical order of full paths.
//! - **Resumption**: Skips keys at or below `cursor.last_key()`. Re-traverses from the root on each `fill_page`.
//! - **Read Path Validation**: Uses component-by-component `openat` from a pinned parent descriptor to prevent symlink and substitution attacks.
//!
//! # Design Trade-offs
//! - **Memory vs. Resumption Cost**: Lazily expanding directories keeps memory bounded to `O(depth * max_dir_entries)` but requires re-traversing ancestor nodes on resumption.
//! - **Confinement Overhead**: Component-by-component `openat` traversal adds system call overhead on cache misses and first reads, but adjacent `read_range` calls can reuse the cached descriptor while preserving confinement guarantees.
//! - **Weak Versioning**: Versions derive from metadata (`mtime`, `size`, `ino`, `dev`) and paths. This enables fast change detection but does not guarantee immutable content identity.
//!
//! # Budget behavior
//!
//! - `fill_page` rejects expired deadlines, caps page cardinality at
//!   `max_items`, and treats `size_hint` bytes as the page byte budget.
//!   The first in-scope item is still emitted even when its `size_hint`
//!   exceeds `max_bytes`, which guarantees forward progress for large files.
//! - `open()` rejects expired deadlines and returns a reader that enforces
//!   `max_bytes` on subsequent reads.
//! - `read_range()` rejects expired deadlines and clamps returned bytes to
//!   `min(dst.len(), max_bytes)`.
//!
//! # Split hints
//!
//! The split-point API consults the connector's integrated
//! `StreamingSplitEstimator`, but capability reporting still keeps
//! `split_hints = false` because enumeration does not feed observations into
//! that estimator yet. A fresh connector therefore returns `None` until an
//! external caller records enough samples.
//!
//! Connector-level key-range bounds participate in both page fill and
//! split-point selection: candidates outside the effective `[start, end)`
//! interval are ignored.

use std::{
    cmp::Ordering,
    ffi::{CString, OsString},
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
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, FILESYSTEM_CONNECTOR_TAG, ItemKey,
        ItemRef, PageBuf, PageState, ReadError, ScanItem, VersionId,
        ordered::{OrderedContentCapabilities, OrderedContentSource},
    },
    coordination::ShardSpec,
    identity::{ConnectorInstanceIdHash, ItemIdentityKey, ObjectVersionId},
};

use crate::common::{
    self, borrowed_shard_bound, classify_io_enumerate_error, classify_io_read_error,
    deadline_expired, enumerate_error_to_read,
};
use crate::split_estimator::StreamingSplitEstimator;

// ---------------------------------------------------------------------------
// CachedFile
// ---------------------------------------------------------------------------

/// Single-entry read cache keyed by `item_ref` bytes.
///
/// # Purpose
/// Optimizes sequential `read_range` workloads by caching the file descriptor
/// of the most recently accessed file.
///
/// # Guarantees
/// - Caches exactly one file descriptor at a time, keeping descriptor retention bounded.
/// - Avoids repeated component-by-component `openat` resolution in the common sequential case.
struct CachedFile {
    item_ref: Box<[u8]>,
    file: fs::File,
}

/// Reader adapter that enforces `max_bytes` and checks the deadline before
/// every delegated read call.
///
/// # Purpose
/// Enforces scanning budgets at the read stream layer, intercepting `io::Read`
/// operations to restrict elapsed time and total byte limits.
///
/// # Guarantees
/// - Total bytes read will never exceed `max_bytes`.
/// - Exhaustion of the byte budget returns standard EOF (`Ok(0)`). Callers
///   must distinguish budget exhaustion from true end-of-file by comparing total bytes read against the item's `size_hint`.
///
/// # Errors
/// - Yields `io::ErrorKind::TimedOut` if the budget deadline expires before or during a read.
struct BudgetedReader<R> {
    inner: R,
    remaining: u64,
    deadline: Option<Instant>,
}

impl<R> BudgetedReader<R> {
    fn new(inner: R, budgets: Budgets) -> Self {
        Self {
            inner,
            remaining: budgets.max_bytes(),
            deadline: budgets.deadline(),
        }
    }
}

impl<R: io::Read> io::Read for BudgetedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if deadline_expired(self.deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "budget deadline expired",
            ));
        }
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }

        let cap = usize::try_from(self.remaining).unwrap_or(usize::MAX);
        let allowed = buf.len().min(cap);
        let read = self.inner.read(&mut buf[..allowed])?;
        self.remaining = self.remaining.saturating_sub(read as u64);
        Ok(read)
    }
}

// ---------------------------------------------------------------------------
// Enumeration walk state
// ---------------------------------------------------------------------------

/// Minimal per-entry state retained while sorting a single directory.
///
/// # Purpose
/// Buffers the name and file type of directory elements required for
/// lexicographical sorting and traversal.
///
/// # Guarantees
/// - Uses minimal memory by keeping only the `OsString` name and `fs::FileType`.
struct BufferedDirEntry {
    name: OsString,
    file_type: fs::FileType,
}

/// One stack frame in the bounded depth-first walk.
///
/// # Purpose
/// Represents the traversal state for a single opened directory, preserving
/// context for lazy enumeration.
///
/// # Guarantees
/// - Owns only the currently-open directory's sorted entries and the
///   relative-path prefix needed to derive child keys.
struct WalkFrame {
    abs_path: PathBuf,
    rel_path: Vec<u8>,
    entries: Vec<BufferedDirEntry>,
    next_index: usize,
}

/// File candidate yielded by the live directory walk.
///
/// # Purpose
/// Packages a fully resolved relative path and its associated filesystem
/// metadata for emission as a `ScanItem`.
struct WalkFile {
    rel_path: Vec<u8>,
    metadata: fs::Metadata,
}

/// Bounded-memory filesystem walker over the canonical directory root.
///
/// # Purpose
/// Executes a lazy, depth-first traversal of the filesystem, respecting
/// configured bounds and limits.
///
/// # Guarantees
/// - Keeps only the active ancestor stack in memory.
/// - Each directory is read, sorted, and dropped once traversal leaves that subtree.
struct DirectoryWalker<'a> {
    stack: Vec<WalkFrame>,
    start: Option<&'a [u8]>,
    resume_after: Option<&'a [u8]>,
    end: Option<&'a [u8]>,
    deadline: Option<Instant>,
}

impl<'a> DirectoryWalker<'a> {
    /// Create a walker that will enumerate files within the requested span.
    ///
    /// # Purpose
    /// Lazily instantiates the bounded depth-first traversal state for a canonical
    /// directory while honoring shard, cursor, and connector-level key bounds.
    ///
    /// # Guarantees
    /// - The root frame reads and sorts a single directory at a time.
    /// - `start`, `resume_after`, and `end` are applied before descending into any subtree.
    fn new(
        root: &Path,
        start: Option<&'a [u8]>,
        resume_after: Option<&'a [u8]>,
        end: Option<&'a [u8]>,
        deadline: Option<Instant>,
    ) -> Result<Self, EnumerateError> {
        Ok(Self {
            stack: vec![WalkFrame {
                abs_path: root.to_path_buf(),
                rel_path: Vec::new(),
                entries: read_sorted_dir_entries(root, deadline)?,
                next_index: 0,
            }],
            start,
            resume_after,
            end,
            deadline,
        })
    }

    /// Advance to the next reachable file, skipping directories and out-of-range entries.
    ///
    /// # Purpose
    /// Applies the deadline and range filters while unwinding the traversal stack so callers
    /// can resume from any cursor without losing ordering guarantees.
    ///
    /// # Guarantees
    /// - Always drills into newly encountered directories before emitting their files.
    /// - Respectfully skips files outside of `start`, `resume_after`, or `end`.
    /// - Returns `Ok(None)` once the traversal stack is empty.
    fn next_file(&mut self) -> Result<Option<WalkFile>, EnumerateError> {
        loop {
            if deadline_expired(self.deadline) {
                return Err(EnumerateError::retryable("budget deadline expired"));
            }

            let Some(frame) = self.stack.last_mut() else {
                return Ok(None);
            };
            if frame.next_index >= frame.entries.len() {
                self.stack.pop();
                continue;
            }

            let entry = &frame.entries[frame.next_index];
            frame.next_index += 1;

            let name_bytes = entry.name.as_os_str().as_bytes();
            if name_bytes.is_empty() {
                continue;
            }

            let rel_path = join_relative_path(&frame.rel_path, name_bytes);
            if entry.file_type.is_dir() {
                if should_skip_subtree(&rel_path, self.start, self.resume_after, self.end) {
                    continue;
                }

                let abs_path = frame.abs_path.join(&entry.name);
                self.stack.push(WalkFrame {
                    abs_path: abs_path.clone(),
                    rel_path,
                    entries: read_sorted_dir_entries(&abs_path, self.deadline)?,
                    next_index: 0,
                });
                continue;
            }

            if !entry.file_type.is_file() {
                continue;
            }

            // Shard/config starts are inclusive, while resume cursors must
            // advance strictly past the last emitted key.
            if self.start.is_some_and(|start| rel_path.as_slice() < start) {
                continue;
            }
            if self
                .resume_after
                .is_some_and(|resume_after| rel_path.as_slice() <= resume_after)
            {
                continue;
            }
            if self.end.is_some_and(|end| rel_path.as_slice() >= end) {
                return Ok(None);
            }

            let abs_path = frame.abs_path.join(&entry.name);
            let metadata = fs::symlink_metadata(&abs_path).map_err(|error| {
                classify_io_enumerate_error("symlink_metadata", &abs_path, &error)
            })?;
            if !metadata.is_file() {
                continue;
            }

            return Ok(Some(WalkFile { rel_path, metadata }));
        }
    }
}

// ---------------------------------------------------------------------------
// FilesystemConnector
// ---------------------------------------------------------------------------

/// Mode of operation for the configured filesystem root.
///
/// # Purpose
/// Distinguishes between directory traversal and single-file roots, holding
/// the necessary pre-verified state for secure confined reads.
enum RootMode {
    Directory,
    SingleFile {
        file_name: Box<[u8]>,
        /// (dev, ino) recorded at init to detect file replacement.
        expected_id: (u64, u64),
    },
}

/// Deterministic ordered-content connector backed by a canonical local
/// directory or a single regular file.
///
/// # Purpose
/// Implements the standard connector protocol for filesystem sources, providing
/// repeatable enumeration and split-estimation capabilities.
///
/// # Guarantees
/// - Lazily canonicalizes `root`, derives a connector-instance scope from that canonical path,
///   and caches the root mode needed for secure fd-relative reads.
/// - Directory roots enumerate every regular file beneath the tree.
/// - Single-file roots expose exactly one item whose key matches the file name recorded at initialization.
/// - Connector-level key-range bounds act as sticky configuration: every enumeration or split-point request
///   intersects its shard bounds with the range configured via [`FilesystemConnector::with_key_range`].
pub struct FilesystemConnector {
    root: PathBuf,
    walk_key_range_start: Option<Box<[u8]>>,
    walk_key_range_end: Option<Box<[u8]>>,
    root_mode: Option<RootMode>,
    connector_instance: Option<ConnectorInstanceIdHash>,
    /// Directory fd for canonical directory roots, opened lazily.
    root_fd: Option<OwnedFd>,
    /// Single-entry FD cache for sequential `read_range` calls.
    cached_file: Option<CachedFile>,
    /// Streaming split-point estimator fed by external observation and reset
    /// whenever connector state is rebuilt.
    split_estimator: StreamingSplitEstimator,
}

impl FilesystemConnector {
    /// Default retained sample cap used for streaming split estimation.
    const SPLIT_ESTIMATOR_SAMPLE_CAP: usize = StreamingSplitEstimator::DEFAULT_SAMPLE_CAP;

    /// Create a connector rooted at `root`.
    ///
    /// # Purpose
    /// Initializes a filesystem connector. Root canonicalization and root-mode discovery are deferred
    /// until the first operation that needs filesystem access.
    ///
    /// # Preconditions
    /// - `root` must not be an empty path.
    ///
    /// # Guarantees
    /// - Delays disk I/O until absolutely necessary.
    ///
    /// # Panics
    /// Panics if `root` is an empty path, because the connector cannot derive
    /// a stable identity or valid `openat` base from it.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        assert!(
            !root.as_os_str().is_empty(),
            "FilesystemConnector root path must not be empty"
        );
        Self {
            root,
            walk_key_range_start: None,
            walk_key_range_end: None,
            root_mode: None,
            connector_instance: None,
            root_fd: None,
            cached_file: None,
            split_estimator: StreamingSplitEstimator::new(Self::SPLIT_ESTIMATOR_SAMPLE_CAP),
        }
    }

    /// Restrict enumeration and split-point selection to keys inside the
    /// half-open range `[start, end)`.
    ///
    /// # Purpose
    /// Limits the connector's operating scope to a specific sub-range of keys.
    ///
    /// # Guarantees
    /// - The configured bounds are sticky and will be intersected with per-request shard bounds.
    /// - `None` acts as an unbounded limit on the respective side.
    #[must_use]
    pub fn with_key_range(mut self, start: Option<&[u8]>, end: Option<&[u8]>) -> Self {
        self.walk_key_range_start = start.map(|bound| bound.to_vec().into_boxed_slice());
        self.walk_key_range_end = end.map(|bound| bound.to_vec().into_boxed_slice());
        self
    }

    /// Canonicalize the root and cache the root mode plus identity scope.
    ///
    /// # Purpose
    /// Defers root resolution until necessary, rewrites `root` to its canonical path,
    /// and records the descriptor-based state required for secure enumeration and reads.
    ///
    /// # Guarantees
    /// - The connector instance hash is derived from the canonical path.
    /// - `root_fd` points to a verified directory (or parent directory for single files).
    /// - `root_mode` is set to either a directory traversal mode or a single-file mode with the expected `(dev, ino)`.
    fn ensure_root_ready(&mut self) -> Result<(), EnumerateError> {
        if self.root_mode.is_some() {
            return Ok(());
        }

        self.root = fs::canonicalize(&self.root)
            .map_err(|error| classify_io_enumerate_error("canonicalize", &self.root, &error))?;
        self.connector_instance = Some(ConnectorInstanceIdHash::from_instance_id_bytes(
            self.root.as_os_str().as_bytes(),
        ));

        let path_meta = fs::metadata(&self.root)
            .map_err(|error| classify_io_enumerate_error("stat_root", &self.root, &error))?;
        if path_meta.is_dir() {
            let expected_id = (path_meta.dev(), path_meta.ino());
            let root_fd = open_dir_fd(&self.root).map_err(|error| {
                classify_io_enumerate_error("open_root_dir", &self.root, &error)
            })?;
            verify_root_identity(&root_fd, expected_id).map_err(|error| {
                classify_io_enumerate_error("verify_root_identity", &self.root, &error)
            })?;
            self.root_fd = Some(root_fd);
            self.root_mode = Some(RootMode::Directory);
            return Ok(());
        }

        if path_meta.is_file() {
            let file_name = self
                .root
                .file_name()
                .ok_or_else(|| EnumerateError::permanent("single-file root has no file name"))?;
            let file_name_bytes = file_name.as_bytes();
            if file_name_bytes.is_empty() {
                return Err(EnumerateError::permanent(
                    "single-file root encoded to an empty item key",
                ));
            }

            let expected_id = (path_meta.dev(), path_meta.ino());

            // Pin the parent directory fd so single-file opens use `openat`,
            // matching directory-root protection against parent-path swaps.
            let parent = self.root.parent().ok_or_else(|| {
                EnumerateError::permanent("single-file root has no parent directory")
            })?;
            let parent_meta = fs::metadata(parent)
                .map_err(|e| classify_io_enumerate_error("stat_parent", parent, &e))?;
            let parent_expected = (parent_meta.dev(), parent_meta.ino());
            let parent_fd = open_dir_fd(parent)
                .map_err(|e| classify_io_enumerate_error("open_parent_dir", parent, &e))?;
            verify_root_identity(&parent_fd, parent_expected)
                .map_err(|e| classify_io_enumerate_error("verify_parent_identity", parent, &e))?;
            self.root_fd = Some(parent_fd);

            self.root_mode = Some(RootMode::SingleFile {
                file_name: file_name_bytes.into(),
                expected_id,
            });
            return Ok(());
        }

        Err(EnumerateError::permanent(
            "filesystem root must be a regular file or directory",
        ))
    }

    fn ordered_content_caps(&self) -> OrderedContentCapabilities {
        OrderedContentCapabilities {
            range_read: true,
            split_hints: false,
            token_resume: false,
        }
    }

    fn connector_instance(&self) -> ConnectorInstanceIdHash {
        self.connector_instance
            .expect("root connector instance is initialized by ensure_root_ready")
    }

    /// Enumerate directory entries into a bounded page while obeying the cursor and budgets.
    ///
    /// # Purpose
    /// Traverses the canonical tree lazily, collecting `ScanItem`s until the page budget is met or traversal completes.
    ///
    /// # Guarantees
    /// - Honors `Cursor` resumption semantics (`resume_after`) and rejects files outside `effective_start`/`effective_end`.
    /// - Always emits the first in-range file even when its size exceeds `max_bytes`.
    /// - Leaves `start` and `end` limits intact so callers can construct appropriate `PageState`.
    fn fill_page_directory(
        &self,
        effective_start: Option<&[u8]>,
        effective_end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        let resume_after = cursor.last_key().map(|last_key| last_key.as_bytes());
        if let (Some(resume_after), Some(end)) = (resume_after, effective_end)
            && resume_after >= end
        {
            return Ok(None);
        }

        let mut walk = DirectoryWalker::new(
            &self.root,
            effective_start,
            resume_after,
            effective_end,
            budgets.deadline(),
        )?;
        let mut items = Vec::new();
        let mut total_bytes = 0_u64;
        let connector_instance = self.connector_instance();
        let mut complete = true;

        loop {
            let Some(next_file) = walk.next_file()? else {
                break;
            };
            let item =
                build_scan_item(&next_file.rel_path, &next_file.metadata, connector_instance)?;
            let item_size = item.size_hint().unwrap_or(0);
            // Always admit the first in-scope item so a single large file does
            // not stall cursor progress forever.
            if !items.is_empty() && total_bytes.saturating_add(item_size) > budgets.max_bytes() {
                complete = false;
                break;
            }

            total_bytes = total_bytes.saturating_add(item_size);
            items.push(item);
            if items.len() == budgets.max_items() {
                // Peek to decide Complete vs HasMore. On error (deadline
                // race, transient IO), conservatively report HasMore rather
                // than discarding the already-collected page via `?`.
                complete = walk.next_file().ok().is_some_and(|next| next.is_none());
                break;
            }
        }

        if items.is_empty() {
            return Ok(None);
        }

        let last_key = items
            .last()
            .expect("non-empty page has a final item")
            .item_key()
            .clone();
        let state = if complete {
            PageState::Complete
        } else {
            PageState::HasMore {
                cursor: Cursor::with_last_key(last_key),
            }
        };

        PageBuf::try_new_validated(
            items,
            state,
            effective_start.unwrap_or(b""),
            effective_end.unwrap_or(b""),
        )
        .map(Some)
        .map_err(|error| EnumerateError::permanent(format!("invalid filesystem page: {error}")))
    }

    /// Emit a single-item page for a connector rooted at one file, validating bounds and identity.
    ///
    /// # Purpose
    /// Applies shard/cursor bounds to the lone file, rechecks its `(dev, ino)` identity,
    /// and returns a validated `PageBuf` when the requested key is still within range.
    ///
    /// # Guarantees
    /// - The page respects the requested `[effective_start, effective_end)` interval.
    /// - Any change to the single file's identity is treated as a permanent error.
    fn fill_page_single_file(
        &self,
        file_name: &[u8],
        expected_id: (u64, u64),
        effective_start: Option<&[u8]>,
        effective_end: Option<&[u8]>,
        cursor: &Cursor,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        if effective_start.is_some_and(|start| file_name < start) {
            return Ok(None);
        }
        if cursor
            .last_key()
            .is_some_and(|last_key| file_name <= last_key.as_bytes())
        {
            return Ok(None);
        }
        if effective_end.is_some_and(|end| file_name >= end) {
            return Ok(None);
        }

        let metadata = {
            let parent_fd = self
                .root_fd
                .as_ref()
                .expect("single-file root has a pinned parent fd after ensure_root_ready");
            let c_name = CString::new(file_name)
                .map_err(|_| EnumerateError::permanent("null byte in single-file name"))?;
            // Open relative to the pinned parent fd with O_NOFOLLOW, matching
            // the security model used by `open_file_for_ref`. Using fd-relative
            // operations here avoids the TOCTOU gap inherent in path-based
            // `symlink_metadata`.
            // Safety: `parent_fd` is a valid file descriptor. `c_name` is a valid,
            // null-terminated C string.
            let fd = unsafe {
                libc::openat(
                    parent_fd.as_raw_fd(),
                    c_name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(classify_io_enumerate_error(
                    "openat_single_file",
                    &self.root,
                    &io::Error::last_os_error(),
                ));
            }
            // Safety: `fd >= 0` from the check above.
            let file = unsafe { fs::File::from_raw_fd(fd) };
            file.metadata().map_err(|error| {
                classify_io_enumerate_error("fstat_single_file", &self.root, &error)
            })?
        };
        if !metadata.is_file() {
            return Err(EnumerateError::permanent(
                "single-file root is no longer a regular file",
            ));
        }
        let actual_id = (metadata.dev(), metadata.ino());
        if actual_id != expected_id {
            return Err(EnumerateError::permanent(
                "single-file identity changed (dev/ino mismatch); rebuild the connector",
            ));
        }

        let item = build_scan_item(file_name, &metadata, self.connector_instance())?;
        PageBuf::try_new_validated(
            vec![item],
            PageState::Complete,
            effective_start.unwrap_or(b""),
            effective_end.unwrap_or(b""),
        )
        .map(Some)
        .map_err(|error| EnumerateError::permanent(format!("invalid filesystem page: {error}")))
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

    /// Choose a split-point hint from the integrated streaming estimator.
    ///
    /// Returns `Ok(None)` when insufficient data has been observed or when the
    /// estimate does not pass cursor/bound guards.
    ///
    /// # Purpose
    /// Delegates to `StreamingSplitEstimator` while intersecting shard bounds, ensuring split hints remain consistent across retries.
    ///
    /// # Guarantees
    /// - Returns `Ok(None)` when the bounds are empty, the deadline expires, or the estimator lacks data.
    /// - Validates that the selected split key advances the cursor and stays below the upper bound.
    fn choose_split_point_bounds(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        deadline: Option<Instant>,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        if deadline_expired(deadline) {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        if let (Some(start), Some(end)) = (start, end)
            && start > end
        {
            return Err(EnumerateError::permanent("shard start key exceeds end key"));
        }

        let Some((_effective_start, effective_end)) = intersect_key_bounds(
            start,
            end,
            self.walk_key_range_start.as_deref(),
            self.walk_key_range_end.as_deref(),
        ) else {
            return Ok(None);
        };

        let Some(split_key) = self.split_estimator.estimate_split_key() else {
            return Ok(None);
        };
        if !common::is_valid_split_candidate(split_key, cursor, effective_end) {
            return Ok(None);
        }
        let split = ItemKey::try_from_slice(split_key)
            .map_err(|error| EnumerateError::permanent(format!("invalid split key: {error}")))?;
        Ok(Some(split))
    }

    // ---------------------------------------------------------------
    // Read-path helpers
    // ---------------------------------------------------------------

    /// Open a file beneath `root_fd` using component-by-component `openat`
    /// with `O_NOFOLLOW` at every step.
    ///
    /// The returned file descriptor has `O_NONBLOCK` set. Callers must
    /// [`clear_nonblock`] before reading from it.
    fn open_beneath_root(&self, ref_bytes: &[u8]) -> Result<(fs::File, fs::Metadata), ReadError> {
        let root_fd = self
            .root_fd
            .as_ref()
            .ok_or_else(|| ReadError::permanent("root directory handle is unavailable"))?;

        if ref_bytes.is_empty() {
            return Err(ReadError::permanent("empty item_ref"));
        }

        let component_count = ref_bytes.iter().filter(|&&byte| byte == b'/').count() + 1;
        let mut dir_fd: Option<OwnedFd> = None;
        let mut component_buf = [0u8; 256];

        for (index, component) in ref_bytes.split(|&byte| byte == b'/').enumerate() {
            if component.is_empty() || component == b"." || component == b".." {
                return Err(ReadError::permanent("invalid path component in item_ref"));
            }

            let parent_fd = match &dir_fd {
                Some(fd) => fd.as_raw_fd(),
                None => root_fd.as_raw_fd(),
            };
            if component.contains(&0) {
                return Err(ReadError::permanent("null byte in path component"));
            }
            if component.len() >= component_buf.len() {
                return Err(ReadError::permanent("path component exceeds NAME_MAX"));
            }

            component_buf[..component.len()].copy_from_slice(component);
            component_buf[component.len()] = 0;
            let component_ptr = component_buf.as_ptr().cast::<libc::c_char>();
            let is_last = index == component_count - 1;
            let flags = if is_last {
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC
            } else {
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC
            };

            // Safety: `parent_fd` is a valid directory descriptor, the path is
            // a null-terminated stack buffer, and successful `openat` returns a
            // fresh fd that is wrapped in `OwnedFd`.
            let raw_fd = unsafe { libc::openat(parent_fd, component_ptr, flags) };
            if raw_fd < 0 {
                return Err(classify_io_read_error(
                    &format!("openat component {}/{}", index + 1, component_count),
                    None,
                    &io::Error::last_os_error(),
                ));
            }
            // Safety: `raw_fd >= 0` from the check above.
            dir_fd = Some(unsafe { OwnedFd::from_raw_fd(raw_fd) });
        }

        let file = fs::File::from(dir_fd.expect("path has at least one component"));
        let metadata = file
            .metadata()
            .map_err(|error| classify_io_read_error("fstat", None, &error))?;
        if !metadata.is_file() {
            return Err(ReadError::permanent("path is not a regular file"));
        }

        Ok((file, metadata))
    }

    fn open_file_for_ref(&self, item_ref: &ItemRef) -> Result<(fs::File, fs::Metadata), ReadError> {
        match self
            .root_mode
            .as_ref()
            .expect("root mode is initialized by ensure_root_ready")
        {
            RootMode::Directory => self.open_beneath_root(item_ref.as_bytes()),
            RootMode::SingleFile {
                file_name,
                expected_id,
            } => {
                if item_ref.as_bytes() != file_name.as_ref() {
                    return Err(ReadError::permanent(
                        "item_ref does not match the single-file root",
                    ));
                }
                // Open via the pinned parent dir fd, matching directory-root
                // protection against parent-path manipulation.
                let (file, metadata) = self.open_beneath_root(file_name)?;
                let actual_id = (metadata.dev(), metadata.ino());
                if actual_id != *expected_id {
                    return Err(ReadError::permanent(
                        "single-file identity changed (dev/ino mismatch); rebuild the connector",
                    ));
                }
                Ok((file, metadata))
            }
        }
    }

    /// Return a cached file handle when the `item_ref` matches, else reopen.
    ///
    /// Cache size is intentionally one entry to match dominant sequential
    /// range-read workloads without retaining unbounded descriptors.
    fn get_or_open_cached(&mut self, item_ref: &ItemRef) -> Result<&fs::File, ReadError> {
        let ref_bytes = item_ref.as_bytes();
        let needs_open = self
            .cached_file
            .as_ref()
            .is_none_or(|cached| cached.item_ref.as_ref() != ref_bytes);
        if needs_open {
            self.ensure_root_ready().map_err(enumerate_error_to_read)?;
            let (file, _metadata) = self.open_file_for_ref(item_ref)?;
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
// Ordered-content and read operations (inherent methods)
// ---------------------------------------------------------------------------

impl FilesystemConnector {
    /// Advertise connector capabilities used by orchestration planning.
    ///
    /// The connector supports seek-by-key pagination and byte-range reads, but
    /// not token-based resume or emitted split hints.
    pub fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: false,
            range_read: true,
            split_hints: false,
        }
    }

    /// Fill one bounded page of ordered filesystem items.
    ///
    /// # Purpose
    /// Enumerates filesystem items incrementally, yielding a bounded subset that respects all configured
    /// limits and shard constraints.
    ///
    /// # Guarantees
    /// - Always respects the intersection of shard bounds and connector-level key bounds.
    /// - Memory usage is bounded by directory depth and entry count.
    /// - Ensures forward progress: the first in-scope item is always emitted even if it exceeds the `max_bytes` budget.
    /// - Re-evaluates metadata if cursor resumes, picking up mutations since the last poll.
    ///
    /// # Errors
    /// - Returns a retryable error when the budget deadline expires before or during traversal.
    /// - Returns a permanent error if the root path cannot be resolved or changes type unexpectedly.
    pub fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        if deadline_expired(budgets.deadline()) {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        self.ensure_root_ready()?;

        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        let Some((effective_start, effective_end)) = intersect_key_bounds(
            start,
            end,
            self.walk_key_range_start.as_deref(),
            self.walk_key_range_end.as_deref(),
        ) else {
            return Ok(None);
        };

        match self
            .root_mode
            .as_ref()
            .expect("root mode is initialized by ensure_root_ready")
        {
            RootMode::Directory => {
                self.fill_page_directory(effective_start, effective_end, cursor, budgets)
            }
            RootMode::SingleFile {
                file_name,
                expected_id,
            } => self.fill_page_single_file(
                file_name.as_ref(),
                *expected_id,
                effective_start,
                effective_end,
                cursor,
            ),
        }
    }

    /// Return a best-effort split-point hint for dynamic shard subdivision.
    ///
    /// # Purpose
    /// Estimates a splitting key that divides the remaining un-scanned work approximately in half,
    /// enabling dynamic workload parallelization.
    ///
    /// # Guarantees
    /// - Computes the hint using an integrated `StreamingSplitEstimator` combined with active bounds.
    /// - Gracefully falls back to `Ok(None)` if there is insufficient historical data.
    /// - Guarantees the emitted split point strictly advances the cursor and respects the upper bound.
    ///
    /// # Errors
    /// - Returns a retryable error if the deadline expires.
    /// - Returns a permanent error if the shard bounds are malformed or logically inverted.
    pub fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor, budgets.deadline())
    }

    /// Open the full content for an item, enforcing the read byte budget on
    /// the returned reader.
    ///
    /// # Purpose
    /// Securely resolves and opens a file stream restricted by the provided budget limits.
    ///
    /// # Guarantees
    /// - Resolution happens via component-by-component `O_NOFOLLOW` validation relative to a pinned root `fd`.
    /// - Single-file targets must identically match the original configuration and recorded `(dev, ino)` state.
    /// - Caps output at `budgets.max_bytes()`, treating exhaustion as a stream EOF.
    ///
    /// # Preconditions
    /// - `item_ref` must resolve within the initialized root directory scope.
    ///
    /// # Errors
    /// - Yields a retryable error when the budget deadline is expired.
    /// - Permanent errors on malformed `item_ref`, symlink detours, unreadable files, or single-file identity changes.
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        if deadline_expired(budgets.deadline()) {
            return Err(ReadError::retryable("budget deadline expired"));
        }

        self.ensure_root_ready().map_err(enumerate_error_to_read)?;
        let (file, _metadata) = self.open_file_for_ref(item_ref)?;
        clear_nonblock(&file)?;
        Ok(Box::new(BudgetedReader::new(file, budgets)))
    }

    /// Range-read a file, clamping the returned bytes to `budgets.max_bytes()`.
    ///
    /// # Purpose
    /// Fetches a specific byte interval from an item, leveraging file-descriptor caching
    /// to speed up adjacent reads on the same file.
    ///
    /// # Guarantees
    /// - Caps byte output to `min(dst.len(), budgets.max_bytes())`.
    /// - Maintains bounds guarantees: zero-length or zero-budget reads return `Ok(0)` without disk access.
    /// - Descriptor caching is limited to a single retained entry to bound OS resources.
    ///
    /// # Preconditions
    /// - `offset + dst.len()` must not overflow `u64`.
    ///
    /// # Errors
    /// - Retryable error on expired deadline.
    /// - Permanent errors for offset overflow, confinement violations, or identity drift.
    pub fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        if deadline_expired(budgets.deadline()) {
            return Err(ReadError::retryable("budget deadline expired"));
        }
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
            .map_err(|error| classify_io_read_error("read_at", None, &error))
    }
}

impl OrderedContentSource for FilesystemConnector {
    fn capabilities(&self) -> OrderedContentCapabilities {
        self.ordered_content_caps()
    }

    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        Self::fill_page(self, shard, cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Self::choose_split_point(self, shard, cursor, budgets)
    }

    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        Self::open(self, item_ref, budgets)
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        Self::read_range(self, item_ref, offset, dst, budgets)
    }
}

// ---------------------------------------------------------------------------
// Filesystem identity and ordering helpers
// ---------------------------------------------------------------------------

/// Build the externally visible item identity for one filesystem entry.
///
/// Relative path bytes are reused as both the stable ordering key and the
/// reopenable item reference so pagination and read operations talk about the
/// same namespace.
fn build_scan_item(
    rel_path: &[u8],
    metadata: &fs::Metadata,
    connector_instance: ConnectorInstanceIdHash,
) -> Result<ScanItem, EnumerateError> {
    let item_key = ItemKey::try_from_slice(rel_path).map_err(|error| {
        EnumerateError::permanent(format!("invalid filesystem item key: {error}"))
    })?;
    let item_ref = ItemRef::try_from_slice(rel_path).map_err(|error| {
        EnumerateError::permanent(format!("invalid filesystem item_ref: {error}"))
    })?;
    let stable_item_id = ItemIdentityKey::new(
        FILESYSTEM_CONNECTOR_TAG,
        connector_instance,
        item_key.as_bytes(),
    )
    .stable_id();
    let version = VersionId::Weak(derive_filesystem_version(rel_path, metadata));

    Ok(ScanItem::new(item_key, item_ref, stable_item_id, version).with_size_hint(metadata.len()))
}

/// Derive the connector's weak version fingerprint for a filesystem entry.
///
/// The fingerprint combines the relative path with metadata fields that tend
/// to change across replacement or mutation. It is suitable for change
/// detection but intentionally does not claim immutable content identity.
fn derive_filesystem_version(rel_path: &[u8], metadata: &fs::Metadata) -> ObjectVersionId {
    let mut version_bytes = Vec::with_capacity(rel_path.len() + 48);
    version_bytes.extend_from_slice(rel_path);
    version_bytes.push(0);
    version_bytes.extend_from_slice(&metadata.dev().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.len().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.mtime().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.mtime_nsec().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.mode().to_le_bytes());
    ObjectVersionId::from_version_bytes(&version_bytes)
}

/// Hard cap on buffered entries per single directory to prevent unbounded
/// memory growth from pathological fan-out.  Page-level budgets are enforced
/// later; this cap guards the intermediate sort buffer.
const MAX_DIR_ENTRIES: usize = 500_000;

fn read_sorted_dir_entries(
    dir: &Path,
    deadline: Option<Instant>,
) -> Result<Vec<BufferedDirEntry>, EnumerateError> {
    if deadline_expired(deadline) {
        return Err(EnumerateError::retryable("budget deadline expired"));
    }

    let mut entries = Vec::new();
    let dir_iter =
        fs::read_dir(dir).map_err(|error| classify_io_enumerate_error("read_dir", dir, &error))?;
    for entry in dir_iter {
        if deadline_expired(deadline) {
            return Err(EnumerateError::retryable("budget deadline expired"));
        }
        if entries.len() >= MAX_DIR_ENTRIES {
            return Err(EnumerateError::permanent(format!(
                "directory {:?} exceeds {MAX_DIR_ENTRIES} entry cap",
                dir,
            )));
        }

        let entry =
            entry.map_err(|error| classify_io_enumerate_error("read_dir_entry", dir, &error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| classify_io_enumerate_error("file_type", dir, &error))?;
        entries.push(BufferedDirEntry {
            name: entry.file_name(),
            file_type,
        });
    }

    entries.sort_unstable_by(cmp_buffered_dir_entries);
    Ok(entries)
}

/// Order siblings so depth-first traversal matches lexicographic relative-path
/// ordering across the entire tree.
fn cmp_buffered_dir_entries(left: &BufferedDirEntry, right: &BufferedDirEntry) -> Ordering {
    cmp_component_with_dir_suffix(
        left.name.as_os_str().as_bytes(),
        left.file_type.is_dir(),
        right.name.as_os_str().as_bytes(),
        right.file_type.is_dir(),
    )
}

/// Compare one path component at a time, treating directories as if they had a
/// synthetic trailing `/`.
///
/// That makes depth-first traversal emit the same order as lexicographically
/// sorting full relative-path strings.
fn cmp_component_with_dir_suffix(
    left: &[u8],
    left_is_dir: bool,
    right: &[u8],
    right_is_dir: bool,
) -> Ordering {
    let mut index = 0;
    loop {
        let left_byte = synthetic_component_byte(left, left_is_dir, index);
        let right_byte = synthetic_component_byte(right, right_is_dir, index);
        match (left_byte, right_byte) {
            (Some(left_byte), Some(right_byte)) => match left_byte.cmp(&right_byte) {
                Ordering::Equal => index += 1,
                ordering => return ordering,
            },
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (None, None) => return Ordering::Equal,
        }
    }
}

/// Return the byte used for comparison at `index`, treating directories as if
/// they had a synthetic trailing `/`.
fn synthetic_component_byte(bytes: &[u8], is_dir: bool, index: usize) -> Option<u8> {
    if index < bytes.len() {
        Some(bytes[index])
    } else if is_dir && index == bytes.len() {
        Some(b'/')
    } else {
        None
    }
}

/// Join two validated path components with `/` only when the prefix is
/// non-empty.
fn join_relative_path(prefix: &[u8], component: &[u8]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(prefix.len() + component.len() + usize::from(!prefix.is_empty()));
    if !prefix.is_empty() {
        out.extend_from_slice(prefix);
        out.push(b'/');
    }
    out.extend_from_slice(component);
    out
}

/// Return `true` when a directory subtree cannot contain any key inside the
/// active `[floor, end)` interval.
///
/// The synthetic `subtree_start/` prefix lets the walker reject whole
/// directories before opening them when every descendant sorts below the
/// inclusive shard/config start, at-or-below the exclusive resume cursor, or
/// at-or-above `end`.
fn should_skip_subtree(
    dir_prefix: &[u8],
    start: Option<&[u8]>,
    resume_after: Option<&[u8]>,
    end: Option<&[u8]>,
) -> bool {
    if dir_prefix.is_empty() {
        return false;
    }

    let subtree_start = join_relative_path(dir_prefix, b"");
    let successor = prefix_successor(&subtree_start);
    if let Some(start) = start
        && successor
            .as_ref()
            .is_some_and(|successor| successor.as_slice() <= start)
    {
        return true;
    }
    if let Some(resume_after) = resume_after
        && successor
            .as_ref()
            .is_some_and(|successor| successor.as_slice() <= resume_after)
    {
        return true;
    }
    if let Some(end) = end
        && end <= subtree_start.as_slice()
    {
        return true;
    }
    false
}

/// Smallest strict lexicographic successor for an arbitrary byte prefix.
///
/// Used to decide whether an entire `prefix/` subtree must sort before the
/// current resume floor.
fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    let mut successor = prefix.to_vec();
    for index in (0..successor.len()).rev() {
        if successor[index] != u8::MAX {
            successor[index] += 1;
            successor.truncate(index + 1);
            return Some(successor);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Key-range intersection
// ---------------------------------------------------------------------------

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
        Some(config_start) => Some(match request_start {
            Some(request_start) if request_start >= config_start => request_start,
            _ => config_start,
        }),
        None => request_start,
    };
    let effective_end = match config_end {
        Some(config_end) => Some(match request_end {
            Some(request_end) if request_end <= config_end => request_end,
            _ => config_end,
        }),
        None => request_end,
    };
    match (effective_start, effective_end) {
        (Some(start), Some(end)) if start >= end => None,
        bounds => Some(bounds),
    }
}

// ---------------------------------------------------------------------------
// Low-level fd helpers
// ---------------------------------------------------------------------------

/// Open a directory file descriptor for use with `openat`.
///
/// Includes `O_NOFOLLOW` for consistency with the module-wide policy of
/// rejecting symlinks at every open, even though callers currently supply
/// canonicalized paths.
fn open_dir_fd(path: &Path) -> Result<OwnedFd, io::Error> {
    let c_path = path_to_cstring(path)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "null byte in path"))?;
    // Safety: POSIX open(2) with a valid null-terminated path.
    let fd = unsafe {
        libc::open(
            c_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: `fd >= 0` from the check above.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Clear `O_NONBLOCK` from an already-opened file descriptor.
fn clear_nonblock(file: &fs::File) -> Result<(), ReadError> {
    let fd = file.as_raw_fd();
    // Safety: `fcntl(F_GETFL)` on a valid file descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(classify_io_read_error(
            "fcntl(F_GETFL)",
            None,
            &io::Error::last_os_error(),
        ));
    }
    // Safety: `fcntl(F_SETFL)` on a valid file descriptor with flags obtained
    // from `F_GETFL`.
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

/// Convert a filesystem path into a C-compatible string for libc calls.
fn path_to_cstring(path: &Path) -> Result<CString, std::ffi::NulError> {
    CString::new(path.as_os_str().as_bytes())
}

/// Read the `(dev, ino)` identity pair for an already-open file descriptor.
fn fd_dev_ino(fd: &OwnedFd) -> io::Result<(u64, u64)> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // Safety: `fstat` writes a fully initialized `stat` struct on success.
    if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // Safety: `fstat` succeeded, so the buffer is initialized.
    let stat = unsafe { stat.assume_init() };
    #[allow(clippy::unnecessary_cast)]
    Ok((stat.st_dev as u64, stat.st_ino as u64))
}

/// Reject connector reuse when the opened root no longer matches the device
/// and inode observed during initialization.
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
