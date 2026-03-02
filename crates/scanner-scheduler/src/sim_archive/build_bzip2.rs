//! Deterministic bzip2 builder for simulation archives.
//!
//! The builder emits a canonical bzip2 payload stream for the provided entry
//! payload bytes. Unlike gzip/zip, bzip2 does not carry filename/timestamp
//! header fields that would need explicit normalization for determinism.

use std::io::Write;

use bzip2::write::BzEncoder;

use crate::sim_scanner::scenario::ArchiveEntrySpec;

/// Build deterministic bzip2 bytes for a single payload.
///
/// Only `entry.payload` is encoded; name/kind/compression metadata on
/// `ArchiveEntrySpec` is intentionally ignored for this single-stream format.
pub fn build_bzip2_bytes(entry: &ArchiveEntrySpec) -> Result<Vec<u8>, String> {
    let mut enc = BzEncoder::new(Vec::new(), bzip2::Compression::default());
    enc.write_all(&entry.payload)
        .map_err(|e| format!("bzip2 write failed: {e}"))?;
    enc.finish()
        .map_err(|e| format!("bzip2 finish failed: {e}"))
}
