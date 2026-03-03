//! Filesystem traversal helpers shared across eval-harness modules.
//!
//! This module owns recursive corpus walking behavior so hashing and
//! snapshot-loading code can share one implementation.

use std::io;
use std::path::{Path, PathBuf};

/// Recursively collect regular file paths under `dir` into `out`.
///
/// Symlinks and special files (sockets, FIFOs, device nodes) are intentionally
/// skipped. Symlinks are excluded because they can point outside the corpus
/// tree or create cycles, and their resolution depends on the host filesystem
/// layout.
///
/// Traversal is fail-fast: any `read_dir` / `file_type` error aborts
/// immediately and is returned to the caller.
pub(crate) fn collect_files_recursive(dir: &Path, out: &mut Vec<PathBuf>) -> io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let ft = entry.file_type()?;
        if ft.is_dir() {
            collect_files_recursive(&entry.path(), out)?;
        } else if ft.is_file() {
            out.push(entry.path());
        }
    }
    Ok(())
}
