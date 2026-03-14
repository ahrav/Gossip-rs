//! Spill arena for tree payloads.
//!
//! Provides an append-only, preallocated, memory-mapped file used to store
//! tree bytes on disk while keeping RAM usage bounded. The arena is designed
//! for sequential writes and read-only slices by offset/length.
//!
//! # Dual-mapping strategy
//!
//! The backing file is mapped twice:
//! - **`writer` (`MmapMut`)** — used by the owning thread to append bytes
//!   via `copy_from_slice`. The cursor advances monotonically.
//! - **`reader` (`Arc<Mmap>`)** — a read-only mapping shared (via `Arc`)
//!   with all `SpillSlice` handles. Reads see writes because both mappings
//!   refer to the same file and the kernel ensures page-cache coherence.
//!
//! This split avoids handing out mutable references while readers exist
//! and lets `SpillSlice` outlive the arena without lifetime coupling.
//!
//! # File lifecycle
//!
//! The spill file is created with a fixed size (`capacity`) and is *not*
//! deleted by this type. The caller (usually the spill directory cleanup)
//! is responsible for removing the file or directory after the scan.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use memmap2::{Mmap, MmapMut};

#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;

/// Reference to a spilled payload within the arena.
///
/// Holds an `Arc` to the read-only mapping so the underlying bytes remain
/// valid even after the arena is moved or dropped.
#[derive(Clone, Debug)]
pub struct SpillSlice {
    reader: Arc<Mmap>,
    offset: u64,
    len: u64,
}

impl SpillSlice {
    /// Returns the spilled bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        let start = self.offset as usize;
        let end = start + self.len as usize;
        &self.reader[start..end]
    }

    /// Returns the offset within the spill arena.
    #[must_use]
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Returns the length in bytes.
    #[must_use]
    pub const fn len(&self) -> u64 {
        self.len
    }

    /// Returns true if the slice is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Errors returned by the spill arena.
#[derive(Debug)]
pub enum SpillArenaError {
    /// IO error while creating or mapping the spill file.
    Io(io::Error),
    /// Arena is out of space.
    OutOfSpace { requested: u64, remaining: u64 },
}

impl fmt::Display for SpillArenaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(err) => write!(f, "spill arena IO error: {err}"),
            Self::OutOfSpace {
                requested,
                remaining,
            } => write!(
                f,
                "spill arena out of space: requested {requested}, remaining {remaining}"
            ),
        }
    }
}

impl std::error::Error for SpillArenaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            _ => None,
        }
    }
}

impl From<io::Error> for SpillArenaError {
    fn from(err: io::Error) -> Self {
        Self::Io(err)
    }
}

/// Append-only spill arena backed by a memory-mapped file.
///
/// The arena pre-allocates the full file on creation and writes
/// sequentially via the mutable mapping. Reads go through `Arc<Mmap>`
/// handles embedded in `SpillSlice`, so returned slices remain valid
/// even after the arena itself is dropped.
///
/// # Thread safety
///
/// `SpillArena` is designed for single-writer use — only one thread
/// should append at a time. The type is technically `Sync` (all fields
/// are `Sync`), but concurrent appends would race on the cursor.
/// The returned `SpillSlice` handles are `Send + Sync` because they
/// hold an `Arc` to the immutable read mapping.
#[derive(Debug)]
pub struct SpillArena {
    path: PathBuf,
    capacity: u64,
    cursor: u64,
    writer: MmapMut,
    reader: Arc<Mmap>,
}

impl SpillArena {
    /// Creates a new spill arena with a fixed size in bytes.
    ///
    /// The backing file is created (or truncated) under `dir` and is not
    /// deleted by this type; callers should clean up the directory if needed.
    pub fn new(dir: &Path, capacity: u64) -> Result<Self, SpillArenaError> {
        let path = make_spill_path(dir);
        let file = open_spill_file(&path, capacity)?;

        // SAFETY: The file length is set once at creation (`set_len`) and
        // never resized. Only this arena writes to the file (through
        // `writer`), and the write cursor advances monotonically without
        // re-visiting earlier regions. No external process modifies the
        // file during the scan lifetime.
        let writer = unsafe { MmapMut::map_mut(&file)? };
        // SAFETY: Same fixed-length file. The read mapping is immutable
        // and only observes bytes previously written through `writer`.
        // Kernel page-cache coherence ensures visibility of prior writes.
        let reader = Arc::new(unsafe { Mmap::map(&file)? });

        advise_sequential(&file, &reader);

        Ok(Self {
            path,
            capacity,
            cursor: 0,
            writer,
            reader,
        })
    }

    /// Returns the configured capacity in bytes.
    #[must_use]
    pub const fn capacity(&self) -> u64 {
        self.capacity
    }

    /// Returns the remaining capacity in bytes.
    #[must_use]
    pub const fn remaining(&self) -> u64 {
        self.capacity - self.cursor
    }

    /// Appends bytes to the spill arena and returns a slice handle.
    ///
    /// Appends are sequential; the arena does not fsync or provide durability
    /// guarantees beyond the lifetime of the mmapped file.
    pub fn append(&mut self, bytes: &[u8]) -> Result<SpillSlice, SpillArenaError> {
        let len = bytes.len() as u64;
        if len > self.remaining() {
            return Err(SpillArenaError::OutOfSpace {
                requested: len,
                remaining: self.remaining(),
            });
        }

        let start = self.cursor as usize;
        let end = start + bytes.len();
        self.writer[start..end].copy_from_slice(bytes);
        self.cursor = self.cursor.saturating_add(len);

        Ok(SpillSlice {
            reader: Arc::clone(&self.reader),
            offset: (start as u64),
            len,
        })
    }

    /// Returns a slice handle for a previously spilled region.
    #[must_use]
    pub fn slice(&self, offset: u64, len: u64) -> SpillSlice {
        debug_assert!(offset.saturating_add(len) <= self.capacity);
        SpillSlice {
            reader: Arc::clone(&self.reader),
            offset,
            len,
        }
    }

    /// Returns the spill file path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Monotonic counter to prevent path collisions when multiple
/// `ObjectStore` instances are constructed concurrently (parallel blob
/// intro). The PID + timestamp alone can collide within the same
/// nanosecond on fast thread spawns.
static SPILL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Construct a unique spill file path within `dir`.
///
/// Includes PID, timestamp, and a monotonic counter to avoid collisions.
fn make_spill_path(dir: &Path) -> PathBuf {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let counter = SPILL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = dir.to_path_buf();
    path.push(format!(
        "tree_spill_{}_{}_{}",
        std::process::id(),
        now.as_nanos(),
        counter
    ));
    path
}

/// Creates (or truncates) the spill file and sets its length to `capacity`.
fn open_spill_file(path: &Path, capacity: u64) -> Result<File, SpillArenaError> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;

    file.set_len(capacity)?;
    Ok(file)
}

/// Hints the OS that the spill file will be accessed sequentially.
///
/// On Linux, calls `posix_fadvise(SEQUENTIAL)` on the file descriptor and
/// `madvise(SEQUENTIAL)` on the read mapping. On other Unix platforms,
/// only the madvise hint is issued. Failures are silently ignored because
/// these are advisory-only and do not affect correctness.
#[cfg(unix)]
fn advise_sequential(file: &File, reader: &Mmap) {
    // SAFETY: `file` is a valid open fd and `reader` is a live mmap.
    // Both libc calls are advisory hints; invalid arguments are harmless.
    unsafe {
        #[cfg(target_os = "linux")]
        let _ = libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
        #[cfg(not(target_os = "linux"))]
        let _ = file;
        let _ = libc::madvise(
            reader.as_ptr() as *mut libc::c_void,
            reader.len(),
            libc::MADV_SEQUENTIAL,
        );
    }
}

#[cfg(not(unix))]
fn advise_sequential(_file: &File, _reader: &Mmap) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spill_arena_append_and_read() {
        let dir = tempfile::tempdir().unwrap();
        let mut arena = SpillArena::new(dir.path(), 1024).unwrap();

        let slice = arena.append(b"hello").unwrap();
        assert_eq!(slice.as_slice(), b"hello");
        assert_eq!(slice.len(), 5);

        let slice2 = arena.append(b"world").unwrap();
        assert_eq!(slice2.as_slice(), b"world");
        assert_eq!(arena.remaining(), 1024 - 10);
    }

    #[test]
    fn spill_arena_out_of_space() {
        let dir = tempfile::tempdir().unwrap();
        let mut arena = SpillArena::new(dir.path(), 4).unwrap();
        let err = arena.append(b"hello").unwrap_err();
        match err {
            SpillArenaError::OutOfSpace {
                requested,
                remaining,
            } => {
                assert_eq!(requested, 5);
                assert_eq!(remaining, 4);
            }
            _ => panic!("expected out of space"),
        }
    }
}
