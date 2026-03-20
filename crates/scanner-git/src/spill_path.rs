//! Shared spill-file naming helpers for spill-backed scanner-git storage.
//!
//! Blob spill files and tree spill files use the same uniqueness strategy:
//! a per-process monotonic counter plus the process id and current timestamp.
//! Centralizing that scheme keeps sibling spill helpers aligned without
//! forcing one leaf module to depend on the other's implementation details.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use memmap2::{Mmap, MmapMut};

/// Spill-file families supported by the scanner-git spill helpers.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpillPathKind {
    /// Spill files that hold oversized blob payloads.
    Blob,
    /// Spill files that back the append-only tree arena.
    Tree,
}

impl SpillPathKind {
    const fn prefix(self) -> &'static str {
        match self {
            Self::Blob => "blob_spill",
            Self::Tree => "tree_spill",
        }
    }
}

/// Monotonic counter shared by every spill-backed helper in this crate.
///
/// The process id and timestamp already separate most file creations; this
/// counter prevents same-process collisions when two spill helpers create
/// files within the same timestamp tick.
static GLOBAL_SPILL_COUNTER: AtomicU64 = AtomicU64::new(0);

const MAX_SPILL_FILE_RESERVATION_ATTEMPTS: usize = 16;

/// Reserve a unique spill file within `dir` and size it to `capacity`.
///
/// `kind` selects the filename stem while the process id, timestamp, and
/// global monotonic counter keep spill paths unique across helper families.
/// The helper uses `create_new(true)` so the reservation is atomic; if a
/// candidate collides, it retries with fresh entropy before giving up.
pub(crate) fn reserve_unique_spill_file(
    dir: &Path,
    kind: SpillPathKind,
    capacity: u64,
) -> io::Result<(PathBuf, File)> {
    for _ in 0..MAX_SPILL_FILE_RESERVATION_ATTEMPTS {
        let path = next_spill_path_candidate(dir, kind);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => {
                if let Err(err) = file.set_len(capacity) {
                    drop(file);
                    let _ = std::fs::remove_file(&path);
                    return Err(err);
                }
                return Ok((path, file));
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "failed to reserve unique spill file after repeated collisions",
    ))
}

/// Creates paired writable and shared read-only mappings for a spill file.
///
/// # Safety contract for callers
///
/// To avoid undefined behaviour both of the following invariants MUST hold
/// for the lifetime of the returned mappings:
///
/// 1. **Monotonic writes only** — the owning writer must advance its cursor
///    strictly forward and must never overwrite a byte range that has already
///    been exposed via a cloned `Arc<Mmap>` handle.  Violating this creates
///    aliased `&mut [u8]` / `&[u8]` references to the same memory, which is
///    UB in Rust regardless of synchronisation.
/// 2. **No external modification** — no other process (or thread) must write
///    to the underlying file while either mapping is live.  The `memmap2`
///    safety contract requires this for read-only maps.
///
/// Spill helpers in this crate satisfy both invariants: the file is sized
/// once in [`reserve_unique_spill_file`] and never resized, and the write
/// cursor is monotonically advancing.
pub(crate) fn map_spill_file(file: &File) -> io::Result<(MmapMut, Arc<Mmap>)> {
    // SAFETY: Callers size the file to its final length before mapping and
    // write through the mutable mapping with a monotonically advancing
    // cursor, so no byte range is mutated while a reader observes it.
    let writer = unsafe { MmapMut::map_mut(file)? };
    // SAFETY: Read-only mapping of the same fixed-length file.  No external
    // process modifies the file during the mapping's lifetime.
    let reader = Arc::new(unsafe { Mmap::map(file)? });
    Ok((writer, reader))
}

fn next_spill_path_candidate(dir: &Path, kind: SpillPathKind) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = GLOBAL_SPILL_COUNTER.fetch_add(1, Ordering::Relaxed);
    dir.join(format!(
        "{}_{}_{}_{}",
        kind.prefix(),
        std::process::id(),
        now.as_nanos(),
        counter
    ))
}

#[cfg(test)]
mod tests {
    use super::{map_spill_file, reserve_unique_spill_file, SpillPathKind};

    #[test]
    fn spill_path_kind_controls_filename_prefix() {
        let dir = tempfile::tempdir().expect("create spill path test dir");
        let (blob, blob_file) =
            reserve_unique_spill_file(dir.path(), SpillPathKind::Blob, 8).expect("reserve blob");
        let (tree, tree_file) =
            reserve_unique_spill_file(dir.path(), SpillPathKind::Tree, 16).expect("reserve tree");

        assert_eq!(blob.parent(), Some(dir.path()));
        assert_eq!(tree.parent(), Some(dir.path()));
        assert!(blob
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("blob_spill_")));
        assert!(tree
            .file_name()
            .and_then(std::ffi::OsStr::to_str)
            .is_some_and(|name| name.starts_with("tree_spill_")));
        assert_eq!(blob_file.metadata().expect("blob metadata").len(), 8);
        assert_eq!(tree_file.metadata().expect("tree metadata").len(), 16);
    }

    #[test]
    fn map_spill_file_writes_visible_through_reader() {
        let dir = tempfile::tempdir().expect("create test dir");
        let (_path, file) =
            reserve_unique_spill_file(dir.path(), SpillPathKind::Blob, 64).expect("reserve");

        let (mut writer, reader) = map_spill_file(&file).expect("map");

        writer[..5].copy_from_slice(b"hello");
        assert_eq!(&reader[..5], b"hello");
    }

    #[test]
    fn map_spill_file_zero_length_returns_empty_mappings() {
        let dir = tempfile::tempdir().expect("create test dir");
        let (_path, file) =
            reserve_unique_spill_file(dir.path(), SpillPathKind::Tree, 0).expect("reserve");

        let (writer, reader) = map_spill_file(&file).expect("map");

        assert!(writer.is_empty());
        assert!(reader.is_empty());
    }
}
