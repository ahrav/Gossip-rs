//! Deterministic filesystem-backed connector (Unix-only).
//!
//! This module provides [`FilesystemConnector`], which implements split-point
//! hints and read operations against a local directory tree.
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
//! Split hints are derived from the connector's integrated
//! `StreamingSplitEstimator`. A fresh connector starts with an empty estimator
//! and returns `None` until sufficient observations accumulate.
//!
//! Connector-level key-range bounds participate in split-point selection:
//! split candidates outside the effective `[start, end)` range are rejected.

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
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, ItemKey, ItemRef, ReadError,
    },
    coordination::ShardSpec,
};

use crate::common::{
    self, borrowed_shard_bound, classify_io_enumerate_error, classify_io_read_error,
    enumerate_error_to_read,
};
use crate::split_estimator::StreamingSplitEstimator;

// ---------------------------------------------------------------------------
// CachedFile
// ---------------------------------------------------------------------------

/// Single-entry read cache keyed by `item_ref` bytes.
///
/// `read_range` workloads often perform adjacent reads on the same file; this
/// avoids repeated `openat` traversal in the common sequential case while
/// keeping memory and fd retention bounded.
struct CachedFile {
    item_ref: Box<[u8]>,
    file: fs::File,
}

// ---------------------------------------------------------------------------
// FilesystemConnector
// ---------------------------------------------------------------------------

/// Deterministic filesystem connector rooted at a local directory.
///
/// See [module-level documentation](self) for full design details.
pub struct FilesystemConnector {
    root: PathBuf,
    walk_key_range_start: Option<Box<[u8]>>,
    walk_key_range_end: Option<Box<[u8]>>,
    /// Directory fd for the canonical root, opened lazily.
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
            root_fd: None,
            cached_file: None,
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

    /// Canonicalize and open the root directory once, then cache its fd.
    ///
    /// This method retries on every call when the root is unavailable rather
    /// than latching permanent failures. Root-directory conditions can change
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

        let config_start = self.walk_key_range_start.clone();
        let config_end = self.walk_key_range_end.clone();
        let Some((_effective_start, effective_end)) =
            intersect_key_bounds(start, end, config_start.as_deref(), config_end.as_deref())
        else {
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
// Read and split-point operations (inherent methods)
// ---------------------------------------------------------------------------

impl FilesystemConnector {
    /// Advertise connector capabilities used by orchestration planning.
    pub fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: false,
            range_read: true,
            split_hints: true,
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

    /// Budget enforcement is left to the runtime layer (which wraps the
    /// returned reader in a bounded adapter), consistent with the advisory
    /// budget contract.
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        self.ensure_root_fd().map_err(enumerate_error_to_read)?;
        let (file, _metadata) = self.open_beneath_root(item_ref.as_bytes())?;
        clear_nonblock(&file)?;
        Ok(Box::new(file))
    }

    pub fn read_range(
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

#[cfg(test)]
#[path = "filesystem_tests.rs"]
mod tests;
