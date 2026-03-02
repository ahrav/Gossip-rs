//! Deterministic zip builder for simulation archives.
//!
//! Output is Zip32-only with fixed timestamps and explicit sizes (no data
//! descriptors). Encrypted entries set the flag bit but do not encrypt payload
//! bytes; this is sufficient for exercising scanner behavior.

use std::io::Write;

use flate2::write::DeflateEncoder;
use flate2::Compression;

use crate::sim_scanner::scenario::{ArchiveEntrySpec, EntryCompressionSpec, EntryKindSpec};

use super::{zip_entry_name, EntryLocator};

/// Build deterministic zip bytes and entry locators.
///
/// The local header offsets recorded in the locators are stable and align with
/// the central directory entries.
pub fn build_zip_bytes(
    entries: &[ArchiveEntrySpec],
) -> Result<(Vec<u8>, Vec<EntryLocator>), String> {
    fn u16le(v: u16) -> [u8; 2] {
        v.to_le_bytes()
    }
    fn u32le(v: u32) -> [u8; 4] {
        v.to_le_bytes()
    }

    let mut out = Vec::new();
    let mut cd = Vec::new();
    let mut locators = Vec::with_capacity(entries.len());

    for entry in entries {
        let name_bytes = zip_entry_name(entry);
        let is_dir = entry.kind == EntryKindSpec::Directory;
        let method = match entry.compression {
            EntryCompressionSpec::Store => 0u16,
            EntryCompressionSpec::Deflate => 8u16,
        };
        let flags: u16 = if entry.encrypted { 0x0001 } else { 0x0000 };

        let payload = if is_dir {
            &[][..]
        } else {
            entry.payload.as_slice()
        };
        let data = if method == 8 {
            let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(payload)
                .map_err(|e| format!("zip deflate failed: {e}"))?;
            encoder
                .finish()
                .map_err(|e| format!("zip deflate finish failed: {e}"))?
        } else {
            payload.to_vec()
        };

        let local_off = out.len() as u32;
        locators.push(EntryLocator::Zip {
            local_header_offset: local_off as u64,
        });

        out.extend_from_slice(&u32le(0x04034b50));
        out.extend_from_slice(&u16le(20));
        out.extend_from_slice(&u16le(flags));
        out.extend_from_slice(&u16le(method));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&u32le(0));
        out.extend_from_slice(&u32le(data.len() as u32));
        out.extend_from_slice(&u32le(payload.len() as u32));
        out.extend_from_slice(&u16le(name_bytes.len() as u16));
        out.extend_from_slice(&u16le(0));
        out.extend_from_slice(&name_bytes);
        out.extend_from_slice(&data);

        cd.extend_from_slice(&u32le(0x02014b50));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(20));
        cd.extend_from_slice(&u16le(flags));
        cd.extend_from_slice(&u16le(method));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(data.len() as u32));
        cd.extend_from_slice(&u32le(payload.len() as u32));
        cd.extend_from_slice(&u16le(name_bytes.len() as u16));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u16le(0));
        cd.extend_from_slice(&u32le(0));
        cd.extend_from_slice(&u32le(local_off));
        cd.extend_from_slice(&name_bytes);
    }

    let cd_start = out.len() as u32;
    out.extend_from_slice(&cd);
    let cd_size = cd.len() as u32;

    out.extend_from_slice(&u32le(0x06054b50));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(0));
    out.extend_from_slice(&u16le(entries.len() as u16));
    out.extend_from_slice(&u16le(entries.len() as u16));
    out.extend_from_slice(&u32le(cd_size));
    out.extend_from_slice(&u32le(cd_start));
    out.extend_from_slice(&u16le(0));

    Ok((out, locators))
}
