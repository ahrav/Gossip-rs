//! Temporary spill file for oversized blob payloads.
//!
//! This helper creates a fixed-size, mmapped file under the provided
//! directory, writes payload bytes into it, and exposes a read-only slice.
//! The file is deleted on drop (best effort).
//!
//! # Concurrency
//! No internal synchronization is provided. Callers must finish writes
//! before reading from `as_slice`, and must ensure the spill file outlives
//! any consumers of the returned slice.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::spill_path::{reserve_unique_spill_file, SpillPathKind};
use memmap2::{Mmap, MmapMut};

/// Spill-backed blob bytes.
///
/// The backing file length is fixed at construction. Writes are sequential
/// and must cover the full length before the data is considered valid.
#[derive(Debug)]
pub struct BlobSpill {
    path: PathBuf,
    len: usize,
    writer: MmapMut,
    reader: Arc<Mmap>,
}

impl BlobSpill {
    /// Create a new spill file sized to `len` bytes.
    pub fn new(dir: &Path, len: usize) -> io::Result<Self> {
        let (path, file) = reserve_unique_spill_file(dir, SpillPathKind::Blob, len as u64)?;
        // SAFETY: The file length is fixed and we only write through the mutable mapping.
        let writer = unsafe { MmapMut::map_mut(&file)? };
        // SAFETY: Read-only view of the same immutable-length file.
        let reader = Arc::new(unsafe { Mmap::map(&file)? });

        Ok(Self {
            path,
            len,
            writer,
            reader,
        })
    }

    /// Returns a writer that fills the spill file sequentially.
    ///
    /// The writer starts at offset 0 and must be finished after writing
    /// exactly `len()` bytes.
    pub fn writer(&mut self) -> BlobSpillWriter<'_> {
        BlobSpillWriter {
            spill: self,
            cursor: 0,
        }
    }

    /// Returns the spilled bytes as a slice.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.reader[..self.len]
    }

    /// Returns the spilled length.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the spill has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Drop for BlobSpill {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Sequential writer for a spill file.
///
/// This writer is append-only; it does not support seeking or overwriting.
#[derive(Debug)]
pub struct BlobSpillWriter<'a> {
    spill: &'a mut BlobSpill,
    cursor: usize,
}

impl<'a> BlobSpillWriter<'a> {
    /// Append bytes to the spill file.
    ///
    /// Returns an error if the write would exceed the configured length.
    pub fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let end = self
            .cursor
            .checked_add(bytes.len())
            .ok_or_else(|| io::Error::other("spill cursor overflow"))?;
        if end > self.spill.len {
            return Err(io::Error::other("spill write exceeds length"));
        }
        self.spill.writer[self.cursor..end].copy_from_slice(bytes);
        self.cursor = end;
        Ok(())
    }

    /// Finalize the writer, ensuring the expected length was written.
    pub fn finish(self) -> io::Result<()> {
        if self.cursor != self.spill.len {
            return Err(io::Error::other("spill write incomplete"));
        }
        Ok(())
    }
}
