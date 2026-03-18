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
use std::time::{SystemTime, UNIX_EPOCH};

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

fn next_spill_path_candidate(dir: &Path, kind: SpillPathKind) -> PathBuf {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let counter = GLOBAL_SPILL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let mut path = dir.to_path_buf();
    path.push(format!(
        "{}_{}_{}_{}",
        kind.prefix(),
        std::process::id(),
        now.as_nanos(),
        counter
    ));
    path
}

#[cfg(test)]
mod tests {
    use super::{reserve_unique_spill_file, SpillPathKind};

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
}
