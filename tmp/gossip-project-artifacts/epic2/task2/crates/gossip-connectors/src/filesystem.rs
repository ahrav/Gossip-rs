//! Deterministic filesystem-backed ordered-content connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], which implements the
//! [`gossip_contracts::connector::ordered::OrderedContentSource`] contract for
//! local filesystem roots.
//!
//! # Enumeration model
//!
//! - The connector lazily builds an immutable in-memory snapshot of regular
//!   files beneath the canonical root on the first enumerate/read call.
//! - Snapshot entries are globally sorted by relative path bytes, yielding a
//!   deterministic lexicographic `ItemKey` order for a fixed root view.
//! - When the root is a single file, the snapshot contains exactly one entry
//!   whose key/ref is the file's basename, matching the runtime's direct-scan
//!   path normalization.
//!
//! # Identity and version model
//!
//! - `item_key` and `item_ref` are identical raw relative-path bytes.
//! - `StableItemId` is domain-separated with the canonical filesystem
//!   connector tag plus either:
//!   - an explicit connector-instance override, or
//!   - a hash of the canonical root path.
//! - Versions are **weak**: a digest of `(relative_path, dev, ino, size,
//!   mtime, mtime_nsec)`. This gives deterministic change detection but does
//!   not claim immutable content pinning. Reads may observe newer bytes if a
//!   file changes after enumeration.
//!
//! # Read-path confinement
//!
//! Directory roots are read with component-by-component `openat` traversal from
//! a canonical root directory fd, using `O_NOFOLLOW` at each step. This blocks
//! symlink escapes and intermediate directory substitution attacks. Single-file
//! roots bypass traversal and open the canonical file directly after validating
//! that the requested `item_ref` matches the frozen basename.
//!
//! Files are opened with `O_NONBLOCK`, validated as regular files via metadata,
//! then `O_NONBLOCK` is cleared before reads.
//!
//! # Budget behavior
//!
//! - `fill_page` respects `max_items`, uses `size_hint` for `max_bytes`, and
//!   returns a retryable error if the deadline expires before emitting any
//!   items.
//! - `open()` returns a reader that enforces `max_bytes` and checks the
//!   deadline before each read.
//! - `read_range()` clamps the read size to `max_bytes` and fails retryably if
//!   the deadline is already expired.
//!
//! # Split hints
//!
//! Split hints are derived from the connector's integrated
//! [`StreamingSplitEstimator`]. A fresh connector starts with an empty
//! estimator and returns `None` until sufficient observations accumulate.
//! Connector-level key-range bounds participate in split-point selection:
//! split candidates outside the effective `[start, end)` range are rejected.

use std::{
    ffi::CString,
    fs, io,
    io::Read,
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
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, ItemKey, ItemRef, PageBuf,
        PageState, ReadError, ScanItem, VersionId, derive_filesystem_stable_item_id,
        ordered::{OrderedContentCapabilities, OrderedContentSource},
    },
    coordination::ShardSpec,
    identity::{ConnectorInstanceIdHash, ObjectVersionId, StableItemId},
};

use crate::common::{
    self, borrowed_shard_bound, classify_io_enumerate_error, classify_io_read_error,
    enumerate_error_to_read,
};
use crate::split_estimator::StreamingSplitEstimator;

// ---------------------------------------------------------------------------
// Snapshot and read helper structs
// ---------------------------------------------------------------------------

/// One indexed filesystem entry in the frozen connector snapshot.
#[derive(Debug)]
struct FileEntry {
    key: ItemKey,
    item_ref: ItemRef,
    stable_item_id: StableItemId,
    version: VersionId,
    size_hint: u64,
}

impl common::KeyedEntry for FileEntry {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
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

/// Frozen interpretation of the canonical scan root.
enum RootMode {
    /// Directory root served through `openat` traversal from `root_fd`.
    Directory,
    /// Single-file root. The file is addressed by its frozen basename only.
    SingleFile { file_name: Box<[u8]> },
}

/// Tri-state machine for the lazy indexing lifecycle.
enum IndexState {
    /// No index attempt has been made yet.
    NotIndexed,
    /// Snapshot built successfully; `entries` is populated and sorted.
    Indexed,
    /// A permanent indexing failure occurred; retries are suppressed.
    Failed(String),
}

/// Reader adapter that enforces `max_bytes` and a monotonic deadline.
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

impl<R: Read> Read for BudgetedReader<R> {
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
        let n = self.inner.read(&mut buf[..allowed])?;
        self.remaining = self.remaining.saturating_sub(n as u64);
        Ok(n)
    }
}

// ---------------------------------------------------------------------------
// FilesystemConnector
// ---------------------------------------------------------------------------

/// Deterministic filesystem connector rooted at a local directory or file.
///
/// See [module-level documentation](self) for full design details.
pub struct FilesystemConnector {
    root: PathBuf,
    walk_key_range_start: Option<Box<[u8]>>,
    walk_key_range_end: Option<Box<[u8]>>,
    /// Optional explicit connector-instance scope for stable-id derivation.
    connector_instance: Option<ConnectorInstanceIdHash>,
    /// Canonicalized root interpretation, established lazily.
    root_mode: Option<RootMode>,
    /// Directory fd for canonical directory roots, opened lazily.
    root_fd: Option<OwnedFd>,
    /// Single-entry FD cache for sequential `read_range` calls.
    cached_file: Option<CachedFile>,
    /// Frozen snapshot of regular files under the root.
    entries: Vec<FileEntry>,
    /// Snapshot lifecycle state.
    index_state: IndexState,
    /// Streaming split-point estimator fed by external observation and reset
    /// whenever connector state is rebuilt.
    split_estimator: StreamingSplitEstimator,
}

impl FilesystemConnector {
    /// Default retained sample cap used for streaming split estimation.
    const SPLIT_ESTIMATOR_SAMPLE_CAP: usize = StreamingSplitEstimator::DEFAULT_SAMPLE_CAP;

    /// Create a connector rooted at `root`.
    ///
    /// Root canonicalization is lazy; it happens on first use.
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
            connector_instance: None,
            root_mode: None,
            root_fd: None,
            cached_file: None,
            entries: Vec::new(),
            index_state: IndexState::NotIndexed,
            split_estimator: StreamingSplitEstimator::new(Self::SPLIT_ESTIMATOR_SAMPLE_CAP),
        }
    }

    #[must_use]
    /// Restrict split-point selection to keys inside the half-open range
    /// `[start, end)`.
    ///
    /// The range is intersected with per-request shard bounds. `None` means
    /// unbounded on that side.
    pub fn with_key_range(mut self, start: Option<&[u8]>, end: Option<&[u8]>) -> Self {
        self.walk_key_range_start = start.map(|bound| bound.to_vec().into_boxed_slice());
        self.walk_key_range_end = end.map(|bound| bound.to_vec().into_boxed_slice());
        self
    }

    /// Override the connector-instance scope used for stable-id derivation.
    #[must_use]
    pub fn with_connector_instance_hash(
        mut self,
        connector_instance: ConnectorInstanceIdHash,
    ) -> Self {
        self.connector_instance = Some(connector_instance);
        self
    }

    /// Hash and store an explicit connector-instance identifier.
    #[must_use]
    pub fn with_connector_instance_id(mut self, connector_instance_id: impl AsRef<[u8]>) -> Self {
        self.connector_instance = Some(ConnectorInstanceIdHash::from_instance_id_bytes(
            connector_instance_id.as_ref(),
        ));
        self
    }

    /// Resolve and cache the canonical root interpretation.
    ///
    /// Directory roots keep an open directory fd for later `openat`-confined
    /// reads. Single-file roots freeze just the basename because there is no
    /// parent traversal to perform.
    fn ensure_root_ready(&mut self) -> Result<(), EnumerateError> {
        if self.root_mode.is_some() {
            return Ok(());
        }

        // Canonicalize root to prevent cwd drift and resolve root symlinks.
        self.root = fs::canonicalize(&self.root)
            .map_err(|err| classify_io_enumerate_error("canonicalize", &self.root, &err))?;

        // Capture path identity BEFORE open so the authoritative check is
        // fstat on the fd (which cannot be swapped out from under us).
        let path_meta = fs::metadata(&self.root)
            .map_err(|err| classify_io_enumerate_error("stat_root", &self.root, &err))?;

        if path_meta.is_dir() {
            let expected_id = (path_meta.dev(), path_meta.ino());
            let root_fd = open_dir_fd(&self.root)
                .map_err(|err| classify_io_enumerate_error("open_root_dir", &self.root, &err))?;
            verify_root_identity(&root_fd, expected_id).map_err(|err| {
                classify_io_enumerate_error("verify_root_identity", &self.root, &err)
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
            let encoded = file_name.as_encoded_bytes();
            if encoded.is_empty() {
                return Err(EnumerateError::permanent(
                    "single-file root encoded to an empty item key",
                ));
            }
            self.root_fd = None;
            self.root_mode = Some(RootMode::SingleFile {
                file_name: encoded.into(),
            });
            return Ok(());
        }

        Err(EnumerateError::permanent(
            "filesystem root must be a regular file or directory",
        ))
    }

    /// Return the effective connector-instance scope after root canonicalization.
    fn resolved_connector_instance(&self) -> ConnectorInstanceIdHash {
        self.connector_instance.unwrap_or_else(|| {
            ConnectorInstanceIdHash::from_instance_id_bytes(self.root.as_os_str().as_encoded_bytes())
        })
    }

    /// Ensure the snapshot index is built.
    fn ensure_indexed(&mut self, deadline: Option<Instant>) -> Result<(), EnumerateError> {
        match &self.index_state {
            IndexState::Indexed => return Ok(()),
            IndexState::Failed(message) => return Err(EnumerateError::permanent(message.clone())),
            IndexState::NotIndexed => {}
        }

        self.ensure_root_ready()?;
        let connector_instance = self.resolved_connector_instance();

        let entries = match self.root_mode.as_ref().expect("root mode initialized") {
            RootMode::Directory => self.build_directory_snapshot(deadline, connector_instance),
            RootMode::SingleFile { file_name } => {
                self.build_single_file_snapshot(file_name.as_ref(), connector_instance)
            }
        };

        match entries {
            Ok(entries) => {
                self.entries = entries;
                self.index_state = IndexState::Indexed;
                Ok(())
            }
            Err(error) => {
                if !error.is_retryable() {
                    self.index_state = IndexState::Failed(error.message().to_owned());
                }
                Err(error)
            }
        }
    }

    /// Build the frozen snapshot for a directory root.
    fn build_directory_snapshot(
        &self,
        deadline: Option<Instant>,
        connector_instance: ConnectorInstanceIdHash,
    ) -> Result<Vec<FileEntry>, EnumerateError> {
        let mut entries = Vec::new();
        let mut stack: Vec<(PathBuf, Vec<u8>)> = vec![(self.root.clone(), Vec::new())];

        while let Some((abs_dir, rel_prefix)) = stack.pop() {
            if deadline_expired(deadline) {
                return Err(EnumerateError::retryable("indexing deadline expired"));
            }

            let dir = fs::read_dir(&abs_dir)
                .map_err(|error| classify_io_enumerate_error("read_dir", &abs_dir, &error))?;

            for child in dir {
                if deadline_expired(deadline) {
                    return Err(EnumerateError::retryable("indexing deadline expired"));
                }

                let child = child.map_err(|error| {
                    classify_io_enumerate_error("read_dir_entry", &abs_dir, &error)
                })?;
                let name = child.file_name();
                let name_bytes = name.as_encoded_bytes();
                if name_bytes.is_empty() {
                    continue;
                }

                let mut rel_bytes = rel_prefix.clone();
                if !rel_bytes.is_empty() {
                    rel_bytes.push(b'/');
                }
                rel_bytes.extend_from_slice(name_bytes);

                let abs_path = child.path();
                let metadata = fs::symlink_metadata(&abs_path)
                    .map_err(|error| classify_io_enumerate_error("symlink_metadata", &abs_path, &error))?;

                if metadata.is_dir() {
                    stack.push((abs_path, rel_bytes));
                } else if metadata.is_file() {
                    entries.push(build_file_entry(
                        &rel_bytes,
                        &metadata,
                        connector_instance,
                    )?);
                }
            }
        }

        entries.sort_unstable_by(|left, right| left.key.cmp(&right.key));
        if let Some(pos) = entries.windows(2).position(|w| w[0].key == w[1].key) {
            return Err(EnumerateError::permanent(format!(
                "filesystem snapshot contains duplicate key {} at sorted position {pos}",
                entries[pos].key
            )));
        }
        Ok(entries)
    }

    /// Build the frozen snapshot for a single-file root.
    fn build_single_file_snapshot(
        &self,
        file_name: &[u8],
        connector_instance: ConnectorInstanceIdHash,
    ) -> Result<Vec<FileEntry>, EnumerateError> {
        let metadata = fs::metadata(&self.root)
            .map_err(|error| classify_io_enumerate_error("metadata", &self.root, &error))?;
        if !metadata.is_file() {
            return Err(EnumerateError::permanent(
                "single-file root is no longer a regular file",
            ));
        }
        Ok(vec![build_file_entry(
            file_name,
            &metadata,
            connector_instance,
        )?])
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
        if let (Some(s), Some(e)) = (start, end)
            && s > e
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
            .map_err(|err| EnumerateError::permanent(format!("invalid split key: {err}")))?;
        Ok(Some(split))
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
            // Defense-in-depth: only normal segments are accepted,
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

    /// Verify the requested `item_ref` is part of the frozen snapshot.
    fn ensure_item_ref_known(
        &mut self,
        item_ref: &ItemRef,
        deadline: Option<Instant>,
    ) -> Result<(), ReadError> {
        self.ensure_indexed(deadline).map_err(enumerate_error_to_read)?;
        self.entries
            .binary_search_by(|entry| entry.key.as_bytes().cmp(item_ref.as_bytes()))
            .map(|_| ())
            .map_err(|_| ReadError::permanent("item_ref not found in snapshot"))
    }

    /// Open the file represented by one validated `item_ref`.
    fn open_file_for_ref(&mut self, item_ref: &ItemRef) -> Result<(fs::File, fs::Metadata), ReadError> {
        self.ensure_root_ready().map_err(enumerate_error_to_read)?;
        match self.root_mode.as_ref().expect("root mode initialized") {
            RootMode::Directory => self.open_beneath_root(item_ref.as_bytes()),
            RootMode::SingleFile { file_name } => {
                if item_ref.as_bytes() != file_name.as_ref() {
                    return Err(ReadError::permanent("item_ref not found under single-file root"));
                }
                let file = fs::File::open(&self.root)
                    .map_err(|error| classify_io_read_error("open", Some(&self.root), &error))?;
                let metadata = file
                    .metadata()
                    .map_err(|error| classify_io_read_error("fstat", Some(&self.root), &error))?;
                if !metadata.is_file() {
                    return Err(ReadError::permanent(
                        "single-file root is no longer a regular file",
                    ));
                }
                Ok((file, metadata))
            }
        }
    }

    /// Return a cached file handle when the `item_ref` matches, else reopen.
    ///
    /// Cache size is intentionally one entry to match dominant sequential range
    /// reads without retaining unbounded descriptors.
    fn get_or_open_cached(
        &mut self,
        item_ref: &ItemRef,
        deadline: Option<Instant>,
    ) -> Result<&fs::File, ReadError> {
        let ref_bytes = item_ref.as_bytes();
        let need_open = self
            .cached_file
            .as_ref()
            .is_none_or(|cached| cached.item_ref.as_ref() != ref_bytes);
        if need_open {
            self.ensure_item_ref_known(item_ref, deadline)?;
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
    pub fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: false,
            range_read: true,
            split_hints: false,
        }
    }

    /// Split-point hint for dynamic shard subdivision.
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

    /// Fill one validated ordered page of filesystem items.
    pub fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        self.ensure_indexed(budgets.deadline())?;

        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        let bounds = common::resolve_bounds(&self.entries, start, end)?;
        let mut next_index = common::key_resume_start(&self.entries, cursor, bounds.range_start);
        if next_index >= bounds.range_end {
            return Ok(None);
        }

        let mut items = Vec::new();
        let mut total_bytes = 0u64;

        while next_index < bounds.range_end {
            if items.len() >= budgets.max_items() {
                break;
            }
            if deadline_expired(budgets.deadline()) {
                if items.is_empty() {
                    return Err(EnumerateError::retryable("budget deadline expired"));
                }
                break;
            }

            let entry = &self.entries[next_index];
            let would_exceed_bytes = !items.is_empty()
                && total_bytes.saturating_add(entry.size_hint) > budgets.max_bytes();
            if would_exceed_bytes {
                break;
            }

            total_bytes = total_bytes.saturating_add(entry.size_hint);
            items.push(
                ScanItem::new(
                    entry.key.clone(),
                    entry.item_ref.clone(),
                    entry.stable_item_id,
                    entry.version,
                )
                .with_size_hint(entry.size_hint),
            );
            next_index += 1;
        }

        if items.is_empty() {
            return Ok(None);
        }

        let state = if next_index < bounds.range_end {
            let last_key = items
                .last()
                .expect("non-empty page has a last item")
                .item_key()
                .clone();
            PageState::HasMore {
                cursor: Cursor::with_last_key(last_key),
            }
        } else {
            PageState::Complete
        };

        let page = PageBuf::try_new_validated(
            items,
            state,
            shard.key_range_start(),
            shard.key_range_end(),
        )
        .map_err(|error| {
            EnumerateError::permanent(format!("filesystem fill_page produced invalid page: {error}"))
        })?;

        Ok(Some(page))
    }

    /// Open one indexed filesystem item with budget enforcement.
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        if deadline_expired(budgets.deadline()) {
            return Err(ReadError::retryable("budget deadline expired"));
        }

        self.ensure_item_ref_known(item_ref, budgets.deadline())?;
        let (file, _metadata) = self.open_file_for_ref(item_ref)?;
        clear_nonblock(&file)?;
        Ok(Box::new(BudgetedReader::new(file, budgets)))
    }

    /// Range-read fast path with deadline and byte-budget enforcement.
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

        let file = self.get_or_open_cached(item_ref, budgets.deadline())?;
        file.read_at(&mut dst[..allowed], offset)
            .map_err(|err| classify_io_read_error("read_at", None, &err))
    }
}

impl OrderedContentSource for FilesystemConnector {
    fn capabilities(&self) -> OrderedContentCapabilities {
        OrderedContentCapabilities {
            range_read: true,
            split_hints: false,
            token_resume: false,
        }
    }

    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        FilesystemConnector::fill_page(self, shard, cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        FilesystemConnector::choose_split_point(self, shard, cursor, budgets)
    }

    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        FilesystemConnector::open(self, item_ref, budgets)
    }

    fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        FilesystemConnector::read_range(self, item_ref, offset, dst, budgets)
    }
}

// ---------------------------------------------------------------------------
// File-entry construction helpers
// ---------------------------------------------------------------------------

/// Build one indexed filesystem entry from relative path bytes and metadata.
fn build_file_entry(
    rel_bytes: &[u8],
    metadata: &fs::Metadata,
    connector_instance: ConnectorInstanceIdHash,
) -> Result<FileEntry, EnumerateError> {
    let key = ItemKey::try_from_slice(rel_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid filesystem item key: {error}")))?;
    let item_ref = ItemRef::try_from_slice(rel_bytes)
        .map_err(|error| EnumerateError::permanent(format!("invalid filesystem item_ref: {error}")))?;
    let stable_item_id = derive_filesystem_stable_item_id(connector_instance, &key);
    let version = VersionId::Weak(filesystem_weak_version_id(rel_bytes, metadata));

    Ok(FileEntry {
        key,
        item_ref,
        stable_item_id,
        version,
        size_hint: metadata.len(),
    })
}

/// Derive a weak version claim for one filesystem path snapshot.
fn filesystem_weak_version_id(rel_bytes: &[u8], metadata: &fs::Metadata) -> ObjectVersionId {
    let mut version_bytes = Vec::with_capacity(rel_bytes.len() + 8 * 5 + 18);
    version_bytes.extend_from_slice(b"filesystem-weak-v1\0");
    version_bytes.extend_from_slice(rel_bytes);
    version_bytes.extend_from_slice(&metadata.dev().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.ino().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.len().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.mtime().to_le_bytes());
    version_bytes.extend_from_slice(&metadata.mtime_nsec().to_le_bytes());
    ObjectVersionId::from_version_bytes(&version_bytes)
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

/// Returns `true` when a deadline is present and has already passed.
fn deadline_expired(deadline: Option<Instant>) -> bool {
    deadline.is_some_and(|value| Instant::now() >= value)
}

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
