//! Deterministic archive materializers for the simulation harness.
//!
//! These builders produce stable bytes for bzip2, gzip, tar, tar.gz, tar.bz2,
//! and zip archives without relying on OS state. They are intended for test
//! harness usage only.
//!
//! Invariants:
//! - Output bytes are deterministic for the same `ArchiveFileSpec`.
//! - Tar uses minimal ustar headers and GNU longname records for names > 100 bytes.
//! - Zip uses fixed timestamps and explicit sizes (no data descriptors).
//! - Gzip header names are only emitted for valid UTF-8; invalid bytes fall back
//!   to the default `<gunzip>` entry name during path computation.
//! - Single-stream kinds (`Gzip`, `Bzip2`) materialize exactly one logical
//!   entry path regardless of extra entries in `ArchiveFileSpec.entries`.
//! - Entry paths are computed via `EntryPathCanonicalizer` + `VirtualPathBuilder`
//!   using `ArchiveConfig` limits so expected paths match production behavior.

use crate::archive::formats::tar::TAR_BLOCK_LEN;
use crate::archive::util::write_u64_hex_lower;
use crate::archive::{
    ArchiveConfig, EntryPathCanonicalizer, VirtualPathBuilder, DEFAULT_MAX_COMPONENTS,
};
use crate::sim_scanner::scenario::{
    ArchiveCorruptionSpec, ArchiveEntrySpec, ArchiveFileSpec, ArchiveKindSpec, EntryKindSpec,
};

mod build_bzip2;
mod build_gzip;
mod build_tar;
mod build_zip;

pub use build_bzip2::build_bzip2_bytes;
pub use build_gzip::build_gzip_bytes;
pub use build_tar::build_tar_bytes;
pub use build_zip::build_zip_bytes;

const LOCATOR_LEN: usize = 18;

/// Locator metadata for archive entries.
///
/// For multi-entry containers (tar/zip), locators align 1:1 with
/// `ArchiveFileSpec.entries`. For single-stream kinds (gzip/bzip2), there is
/// exactly one locator.
#[derive(Clone, Debug)]
pub enum EntryLocator {
    /// Single gzip stream (no locator suffix).
    Gzip,
    /// Single bzip2 stream (no locator suffix).
    Bzip2,
    /// Tar header block index for `@t<hex>` locators.
    Tar { header_block_index: u64 },
    /// Zip local header offset for `@z<hex>` locators.
    Zip { local_header_offset: u64 },
}

/// Materialized archive bytes plus entry locator metadata.
///
/// `entry_locators` is ordered to match emitted logical entries.
#[derive(Clone, Debug)]
pub struct ArchiveMaterialization {
    /// Final archive bytes (possibly corrupted if `corruption` was applied).
    pub bytes: Vec<u8>,
    /// Locator metadata for each entry.
    pub entry_locators: Vec<EntryLocator>,
}

/// Build deterministic archive bytes for the simulation harness.
///
/// Returns a materialization that includes entry locator metadata used by
/// `entry_paths`. Gzip and bzip2 archives use only the first entry (extra
/// entries are silently ignored).
pub fn materialize_archive(spec: &ArchiveFileSpec) -> Result<ArchiveMaterialization, String> {
    let mut out = match spec.kind {
        ArchiveKindSpec::Gzip => {
            let entry = spec.entries.first().ok_or("gzip archive needs 1 entry")?;
            let bytes = build_gzip_bytes(entry)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: vec![EntryLocator::Gzip],
            }
        }
        ArchiveKindSpec::Bzip2 => {
            let entry = spec.entries.first().ok_or("bzip2 archive needs 1 entry")?;
            let bytes = build_bzip2_bytes(entry)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: vec![EntryLocator::Bzip2],
            }
        }
        ArchiveKindSpec::Tar => {
            let (bytes, locators) = build_tar_bytes(&spec.entries)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: locators,
            }
        }
        ArchiveKindSpec::TarGz => {
            let (tar_bytes, locators) = build_tar_bytes(&spec.entries)?;
            let entry = ArchiveEntrySpec {
                name_bytes: Vec::new(),
                payload: tar_bytes,
                compression: crate::sim_scanner::scenario::EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            };
            let bytes = build_gzip_bytes(&entry)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: locators,
            }
        }
        ArchiveKindSpec::TarBz2 => {
            let (tar_bytes, locators) = build_tar_bytes(&spec.entries)?;
            let entry = ArchiveEntrySpec {
                name_bytes: Vec::new(),
                payload: tar_bytes,
                compression: crate::sim_scanner::scenario::EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            };
            let bytes = build_bzip2_bytes(&entry)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: locators,
            }
        }
        ArchiveKindSpec::Zip => {
            let (bytes, locators) = build_zip_bytes(&spec.entries)?;
            ArchiveMaterialization {
                bytes,
                entry_locators: locators,
            }
        }
    };

    if let Some(corrupt) = &spec.corruption {
        apply_corruption(&mut out.bytes, corrupt)?;
    }

    Ok(out)
}

/// Compute archive entry virtual paths for a materialized archive.
///
/// The returned paths align with production virtual-path construction and are
/// ordered by emitted logical entry. For single-stream kinds (gzip/bzip2),
/// callers should provide exactly one entry in `spec.entries` so the
/// cardinality matches `materialized.entry_locators`.
pub fn entry_paths(
    spec: &ArchiveFileSpec,
    materialized: &ArchiveMaterialization,
    archive: &ArchiveConfig,
) -> Result<Vec<Vec<u8>>, String> {
    // Cardinality must match what was actually materialized; this prevents
    // silently inventing paths for entries that do not exist in the bytes.
    if spec.entries.len() != materialized.entry_locators.len() {
        return Err("entry locator length mismatch".to_string());
    }

    let max_len = archive.max_virtual_path_len_per_entry;
    let mut canon = EntryPathCanonicalizer::with_capacity(DEFAULT_MAX_COMPONENTS, max_len);
    let mut vpath = VirtualPathBuilder::with_capacity(max_len);
    let root_display = spec.root_path.bytes.as_slice();

    let mut out = Vec::with_capacity(spec.entries.len());

    for (idx, entry) in spec.entries.iter().enumerate() {
        let display = match spec.kind {
            ArchiveKindSpec::Gzip => {
                let name_bytes = gzip_name_bytes(entry)?;
                let entry_bytes = if let Some(name) = name_bytes {
                    canon
                        .canonicalize(name, DEFAULT_MAX_COMPONENTS, max_len)
                        .bytes
                } else {
                    b"<gunzip>"
                };
                vpath.build(root_display, entry_bytes, max_len).bytes
            }
            ArchiveKindSpec::Bzip2 => vpath.build(root_display, b"<bunzip2>", max_len).bytes,
            ArchiveKindSpec::Tar | ArchiveKindSpec::TarGz | ArchiveKindSpec::TarBz2 => {
                let locator = match materialized.entry_locators[idx] {
                    EntryLocator::Tar { header_block_index } => {
                        build_locator(b't', header_block_index)
                    }
                    _ => return Err("unexpected tar locator".to_string()),
                };
                let name_bytes = tar_entry_name(entry);
                let entry_bytes = canon
                    .canonicalize(&name_bytes, DEFAULT_MAX_COMPONENTS, max_len)
                    .bytes;
                vpath
                    .build_with_suffix(root_display, entry_bytes, &locator, max_len)
                    .bytes
            }
            ArchiveKindSpec::Zip => {
                let locator = match materialized.entry_locators[idx] {
                    EntryLocator::Zip {
                        local_header_offset,
                    } => build_locator(b'z', local_header_offset),
                    _ => return Err("unexpected zip locator".to_string()),
                };
                let name_bytes = zip_entry_name(entry);
                let entry_bytes = canon
                    .canonicalize(&name_bytes, DEFAULT_MAX_COMPONENTS, max_len)
                    .bytes;
                vpath
                    .build_with_suffix(root_display, entry_bytes, &locator, max_len)
                    .bytes
            }
        };
        out.push(display.to_vec());
    }

    Ok(out)
}

/// Materialize archive bytes and entry paths in one step.
pub fn materialize_archive_with_paths(
    spec: &ArchiveFileSpec,
    archive: &ArchiveConfig,
) -> Result<(Vec<u8>, Vec<Vec<u8>>), String> {
    let materialized = materialize_archive(spec)?;
    let paths = entry_paths(spec, &materialized, archive)?;
    Ok((materialized.bytes, paths))
}

fn apply_corruption(bytes: &mut Vec<u8>, corruption: &ArchiveCorruptionSpec) -> Result<(), String> {
    match *corruption {
        ArchiveCorruptionSpec::TruncateTo { len } => {
            let keep = len.min(bytes.len() as u64) as usize;
            bytes.truncate(keep);
        }
    }
    Ok(())
}

fn gzip_name_bytes(entry: &ArchiveEntrySpec) -> Result<Option<&[u8]>, String> {
    if entry.name_bytes.is_empty() {
        return Ok(None);
    }
    let Ok(name) = std::str::from_utf8(&entry.name_bytes) else {
        return Ok(None);
    };
    if name.is_empty() {
        Ok(None)
    } else {
        Ok(Some(entry.name_bytes.as_slice()))
    }
}

fn tar_entry_name(entry: &ArchiveEntrySpec) -> Vec<u8> {
    let mut name = entry.name_bytes.clone();
    if entry.kind == EntryKindSpec::Directory && !name.ends_with(b"/") {
        name.push(b'/');
    }
    name
}

fn zip_entry_name(entry: &ArchiveEntrySpec) -> Vec<u8> {
    let mut name = entry.name_bytes.clone();
    if entry.kind == EntryKindSpec::Directory && !name.ends_with(b"/") {
        name.push(b'/');
    }
    name
}

fn build_locator(kind: u8, value: u64) -> [u8; LOCATOR_LEN] {
    let mut out = [0u8; LOCATOR_LEN];
    out[0] = b'@';
    out[1] = kind;
    write_u64_hex_lower(value, &mut out[2..]);
    out
}

#[inline(always)]
fn tar_pad(size: usize) -> usize {
    let rem = size % TAR_BLOCK_LEN;
    if rem == 0 {
        0
    } else {
        TAR_BLOCK_LEN - rem
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim_scanner::scenario::EntryCompressionSpec;

    #[test]
    fn zip_name_suffixes_directory() {
        let entry = ArchiveEntrySpec {
            name_bytes: b"dir".to_vec(),
            payload: Vec::new(),
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::Directory,
        };
        assert!(zip_entry_name(&entry).ends_with(b"/"));
    }

    #[test]
    fn locator_format_is_stable() {
        let locator = build_locator(b't', 0x1234);
        assert_eq!(&locator[..2], b"@t");
    }

    #[test]
    fn entry_paths_resolve() {
        let spec = ArchiveFileSpec {
            root_path: crate::sim::fs::SimPath::new(b"root.tar".to_vec()),
            kind: ArchiveKindSpec::Tar,
            entries: vec![ArchiveEntrySpec {
                name_bytes: b"entry.txt".to_vec(),
                payload: vec![0, 1, 2],
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            }],
            corruption: None,
        };
        let materialized = materialize_archive(&spec).expect("materialize");
        let cfg = ArchiveConfig::default();
        let paths = entry_paths(&spec, &materialized, &cfg).expect("paths");
        assert_eq!(paths.len(), 1);
    }

    #[test]
    fn gzip_name_invalid_utf8_is_ignored() {
        let entry = ArchiveEntrySpec {
            name_bytes: vec![0xff, 0xff],
            payload: vec![1, 2, 3],
            compression: EntryCompressionSpec::Store,
            encrypted: false,
            kind: EntryKindSpec::RegularFile,
        };
        assert!(gzip_name_bytes(&entry).unwrap().is_none());
    }

    #[test]
    fn bzip2_entry_path_uses_bunzip2_name() {
        let spec = ArchiveFileSpec {
            root_path: crate::sim::fs::SimPath::new(b"root.bz2".to_vec()),
            kind: ArchiveKindSpec::Bzip2,
            entries: vec![ArchiveEntrySpec {
                name_bytes: b"ignored.txt".to_vec(),
                payload: vec![1, 2, 3],
                compression: EntryCompressionSpec::Store,
                encrypted: false,
                kind: EntryKindSpec::RegularFile,
            }],
            corruption: None,
        };
        let materialized = materialize_archive(&spec).expect("materialize");
        let cfg = ArchiveConfig::default();
        let paths = entry_paths(&spec, &materialized, &cfg).expect("paths");
        assert_eq!(paths, vec![b"root.bz2::<bunzip2>".to_vec()]);
    }
}
