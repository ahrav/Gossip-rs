//! Deterministic gzip builder for simulation archives.
//!
//! The builder fixes the mtime to 0 and emits a filename only when the entry
//! name is valid UTF-8. Payload bytes are written verbatim (no encryption or
//! OS-dependent metadata), making output stable across runs.

use std::io::Write;

use flate2::{Compression, GzBuilder};

use crate::sim_scanner::scenario::ArchiveEntrySpec;

/// Build deterministic gzip bytes for a single payload.
///
/// The gzip filename is included only when `entry.name_bytes` is valid UTF-8.
pub fn build_gzip_bytes(entry: &ArchiveEntrySpec) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut builder = GzBuilder::new().mtime(0);

    if let Ok(name) = std::str::from_utf8(&entry.name_bytes) {
        if !name.is_empty() {
            builder = builder.filename(name);
        }
    }

    let mut enc = builder.write(&mut out, Compression::default());
    enc.write_all(&entry.payload)
        .map_err(|e| format!("gzip write failed: {e}"))?;
    enc.finish()
        .map_err(|e| format!("gzip finish failed: {e}"))?;
    Ok(out)
}
