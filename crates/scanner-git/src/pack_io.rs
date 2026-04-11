//! Pack I/O utilities for external base resolution.
//!
//! This module manages pack file access and bounded object decoding for
//! cross-pack REF delta bases. It is intentionally narrow in scope:
//! callers provide OIDs, and `PackIo` resolves them via the MIDX to pack
//! offsets, loads pack bytes (mmap-backed by default), and decodes the object with strict
//! limits on header size, delta payload size, and output size.
//!
//! # Scope
//! - MIDX-backed pack lookup with loose-object fallback.
//! - Bounded delta decoding with configurable depth limits.
//! - Pack files are memory-mapped on demand and cached for reuse.
//!
//! # Invariants
//! - `pack_paths` is indexed by pack_id in PNAM order.
//! - Pack files are immutable for the lifetime of a repo job.
//! - Object sizes never exceed `limits.decode.max_object_bytes`.
//! - Delta payload sizes never exceed `limits.decode.max_delta_bytes`.
//! - Delta chains are bounded by `limits.max_delta_depth`.
//! - Loose object headers never exceed `LOOSE_HEADER_MAX_BYTES`.
//! - Missing bases are treated as missing objects (`None`).

use std::fs;
use std::fs::File;
use std::io;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::sync::Arc;

use memmap2::Mmap;

use super::midx::MidxView;
use super::midx_error::MidxError;
use super::object_id::OidBytes;
use super::pack_decode::{
    entry_header_at, inflate_entry_payload, PackDecodeError, PackDecodeLimits,
};
use super::pack_delta::{apply_delta, DeltaError};
use super::pack_exec::{ExternalBase, ExternalBaseProvider, PackExecError};
use super::pack_inflate::{inflate_limited, EntryKind, ObjectKind, PackFile, PackParseError};
use super::repo_open::RepoJobState;
use super::repo_paths;

/// Safety allowance for loose object headers (`"blob <size>\\0"`).
const LOOSE_HEADER_MAX_BYTES: usize = 64;

/// Limits for pack I/O decoding.
#[derive(Clone, Copy, Debug)]
pub struct PackIoLimits {
    /// Limits for header parsing and inflation.
    pub decode: PackDecodeLimits,
    /// Maximum delta chain depth across packs.
    ///
    /// Depth counts delta edges. A value of 0 rejects any delta entry.
    pub max_delta_depth: u8,
}

impl PackIoLimits {
    /// Constructs limits from decode settings and a cross-pack delta depth cap.
    #[must_use]
    pub const fn new(decode: PackDecodeLimits, max_delta_depth: u8) -> Self {
        Self {
            decode,
            max_delta_depth,
        }
    }
}

/// Errors from pack I/O.
#[derive(Debug, thiserror::Error)]
pub enum PackIoError {
    /// MIDX bytes are missing.
    #[error("midx bytes missing")]
    MissingMidx,
    /// MIDX parsing or lookup failed.
    #[error("{0}")]
    Midx(#[from] MidxError),
    /// Pack file I/O failed.
    #[error("pack I/O error: {0}")]
    Io(#[from] io::Error),
    /// Pack header parsing failed.
    #[error("{0}")]
    PackParse(#[from] PackParseError),
    /// Entry decode failed.
    #[error("{0}")]
    Decode(#[from] PackDecodeError),
    /// Delta application failed.
    #[error("{0}")]
    Delta(#[from] DeltaError),
    /// Pack ID does not exist in the pack list.
    #[error("pack id {pack_id} out of range (pack count {pack_count})")]
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Pack list length does not match the MIDX pack count.
    #[error("pack count mismatch: midx expects {expected}, provided {actual}")]
    PackCountMismatch { expected: usize, actual: usize },
    /// Delta chain exceeded the configured depth.
    #[error("delta depth exceeded (max {max_depth})")]
    DeltaDepthExceeded { max_depth: u8 },
    /// OID length does not match the configured MIDX format.
    #[error("OID length mismatch: got {got}, expected {expected}")]
    OidLengthMismatch { got: u8, expected: u8 },
    /// Loose object load failed.
    #[error("loose object error: {detail}")]
    LooseObject { detail: String },
}

/// Pack I/O helper for external base resolution.
#[derive(Debug)]
pub struct PackIo<'a> {
    oid_len: u8,
    midx: MidxView<'a>,
    pack_paths: Vec<PathBuf>,
    pack_cache: Vec<Option<Arc<Mmap>>>,
    loose_dirs: Vec<PathBuf>,
    limits: PackIoLimits,
}

impl<'a> PackIo<'a> {
    /// Opens pack I/O for a repository job.
    ///
    /// # Errors
    /// Returns `PackIoError` if artifacts are missing, the MIDX is invalid,
    /// or pack files cannot be resolved.
    pub fn open(repo: &'a RepoJobState, limits: PackIoLimits) -> Result<Self, PackIoError> {
        let midx_bytes = repo.mmaps.midx.as_ref().ok_or(PackIoError::MissingMidx)?;
        let midx = MidxView::parse(midx_bytes.as_slice(), repo.object_format)?;

        let pack_dirs = repo_paths::collect_pack_dirs(&repo.paths);
        let pack_names = repo_paths::list_pack_files(&pack_dirs)?;
        midx.verify_completeness(pack_names.iter().map(|n| n.as_slice()))?;

        let pack_paths = repo_paths::resolve_pack_paths(&midx, &pack_dirs)?;
        let loose_dirs = repo_paths::collect_loose_dirs(&repo.paths);
        Self::from_parts(midx, pack_paths, loose_dirs, limits)
    }

    /// Constructs pack I/O from pre-parsed parts.
    ///
    /// This is intended for tests or callers that already resolved pack paths.
    /// `pack_paths` must be in PNAM order (matching the MIDX pack list).
    ///
    /// # Errors
    /// Returns `PackCountMismatch` if `pack_paths` doesn't match the MIDX
    /// pack count.
    pub fn from_parts(
        midx: MidxView<'a>,
        pack_paths: Vec<PathBuf>,
        loose_dirs: Vec<PathBuf>,
        limits: PackIoLimits,
    ) -> Result<Self, PackIoError> {
        let expected = midx.pack_count() as usize;
        if pack_paths.len() != expected {
            return Err(PackIoError::PackCountMismatch {
                expected,
                actual: pack_paths.len(),
            });
        }

        Ok(Self {
            oid_len: midx.oid_len(),
            midx,
            pack_paths,
            pack_cache: vec![None; expected],
            loose_dirs,
            limits,
        })
    }

    /// Loads an object by OID, returning `None` if the OID is missing.
    ///
    /// Missing delta bases also return `None`; they are treated the same
    /// as missing OIDs to keep the API a simple optional lookup.
    ///
    /// Pack lookup is attempted first; on miss, loose object directories
    /// are searched.
    /// Delta depth is enforced across pack hops using `limits.max_delta_depth`.
    ///
    /// # Errors
    /// Returns `PackIoError` for malformed pack data or delta failures.
    pub fn load_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        self.load_object_with_depth(oid, self.limits.max_delta_depth)
    }

    /// Loads a loose object by OID, returning `None` if the object is missing.
    ///
    /// This bypasses pack lookup and is intended for loose candidate scanning.
    /// Loose objects are inflated with a strict size cap and validated against
    /// the `<kind> <size>\\0<payload>` header format.
    pub fn load_loose_object(
        &mut self,
        oid: &OidBytes,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        if oid.len() != self.oid_len {
            return Err(PackIoError::OidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len,
            });
        }

        let hex = repo_paths::oid_to_hex(oid);
        let (dir, file) = hex.split_at(2);
        let dir_name = String::from_utf8_lossy(dir);
        let file_name = String::from_utf8_lossy(file);

        for base in &self.loose_dirs {
            let path = base.join(dir_name.as_ref()).join(file_name.as_ref());
            let data = match fs::read(&path) {
                Ok(data) => data,
                Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(PackIoError::LooseObject {
                        detail: format!("loose object read failed: {err}"),
                    })
                }
            };

            let max_out = self
                .limits
                .decode
                .max_object_bytes
                .saturating_add(LOOSE_HEADER_MAX_BYTES);
            let mut out = Vec::with_capacity(max_out);
            inflate_limited(&data, &mut out, max_out).map_err(|err| PackIoError::LooseObject {
                detail: format!("loose object inflate failed: {err}"),
            })?;

            let (kind, payload) = parse_loose_object(&out, self.limits.decode.max_object_bytes)?;
            return Ok(Some((kind, payload)));
        }

        Ok(None)
    }

    /// Loads an object by OID with an explicit remaining delta depth.
    ///
    /// This is used internally to enforce `max_delta_depth` across pack hops.
    fn load_object_with_depth(
        &mut self,
        oid: &OidBytes,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        if oid.len() != self.oid_len {
            return Err(PackIoError::OidLengthMismatch {
                got: oid.len(),
                expected: self.oid_len,
            });
        }

        let idx = match self.midx.find_oid(oid)? {
            Some(idx) => idx,
            None => return self.load_loose_object(oid),
        };
        let (pack_id, offset) = self.midx.offset_at(idx)?;
        self.load_object_by_offset(pack_id, offset, depth)
    }

    fn load_object_by_offset(
        &mut self,
        pack_id: u16,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let pack = self.pack_data(pack_id)?;
        let pack_file = PackFile::parse(pack.as_ref(), self.oid_len as usize)?;
        self.read_pack_object(&pack_file, offset, depth)
    }

    /// Reads an object from a pack, resolving in-pack deltas recursively.
    ///
    /// Returns `Ok(None)` if a required base object cannot be loaded.
    fn read_pack_object(
        &mut self,
        pack: &PackFile<'_>,
        offset: u64,
        depth: u8,
    ) -> Result<Option<(ObjectKind, Vec<u8>)>, PackIoError> {
        let header = entry_header_at(pack, offset, &self.limits.decode)?;

        match header.kind {
            EntryKind::NonDelta { kind } => {
                let mut out = Vec::with_capacity(header.size as usize);
                inflate_entry_payload(pack, &header, &mut out, &self.limits.decode)?;
                Ok(Some((kind, out)))
            }
            EntryKind::OfsDelta { base_offset } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.read_pack_object(pack, base_offset, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
            EntryKind::RefDelta { base_oid } => {
                if depth == 0 {
                    return Err(PackIoError::DeltaDepthExceeded {
                        max_depth: self.limits.max_delta_depth,
                    });
                }
                let Some((base_kind, base_bytes)) =
                    self.load_object_with_depth(&base_oid, depth - 1)?
                else {
                    return Ok(None);
                };
                let out = apply_delta_entry(pack, &header, &base_bytes, &self.limits.decode)?;
                Ok(Some((base_kind, out)))
            }
        }
    }

    /// Returns the memory-mapped pack bytes for `pack_id`, mapping lazily.
    ///
    /// Mmaps are cached for the lifetime of the `PackIo` instance.
    fn pack_data(&mut self, pack_id: u16) -> Result<Arc<Mmap>, PackIoError> {
        let idx = pack_id as usize;
        let pack_count = self.pack_paths.len();
        let path = self
            .pack_paths
            .get(idx)
            .ok_or(PackIoError::PackIdOutOfRange {
                pack_id,
                pack_count,
            })?;

        if self.pack_cache.get(idx).is_none() {
            // Defensive check in case the cache length diverges from pack_paths.
            return Err(PackIoError::PackIdOutOfRange {
                pack_id,
                pack_count,
            });
        }

        if self.pack_cache[idx].is_none() {
            let file = File::open(path)?;
            // SAFETY: pack files are immutable for the duration of a repo job.
            let mmap = unsafe { Mmap::map(&file)? };
            advise_sequential(&file, &mmap);
            self.pack_cache[idx] = Some(Arc::new(mmap));
        }

        Ok(self.pack_cache[idx]
            .as_ref()
            .expect("pack bytes present")
            .clone())
    }
}

#[cfg(unix)]
fn advise_sequential(file: &File, reader: &Mmap) {
    // SAFETY: The file descriptor is valid for the duration of `fadvise`,
    // and the mmap pointer/length are valid for `madvise`. Both calls are
    // advisory; errors are silently ignored.
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

impl ExternalBaseProvider for PackIo<'_> {
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        match self.load_object(oid) {
            Ok(Some((kind, bytes))) => Ok(Some(ExternalBase { kind, bytes })),
            Ok(None) => Ok(None),
            Err(err) => Err(PackExecError::ExternalBase(err.to_string())),
        }
    }
}

/// Inflate and apply a delta entry, enforcing decode and output limits.
///
/// The delta payload is bounded by `limits.max_delta_bytes`; the final object
/// is capped at `limits.max_object_bytes`.
fn apply_delta_entry(
    pack: &PackFile<'_>,
    header: &super::pack_inflate::EntryHeader,
    base_bytes: &[u8],
    limits: &PackDecodeLimits,
) -> Result<Vec<u8>, PackIoError> {
    let mut delta = Vec::with_capacity(limits.max_delta_bytes);
    inflate_entry_payload(pack, header, &mut delta, limits)?;

    let mut out = Vec::new();
    apply_delta(base_bytes, &delta, &mut out, limits.max_object_bytes)?;

    Ok(out)
}

fn parse_loose_object(
    bytes: &[u8],
    max_payload: usize,
) -> Result<(ObjectKind, Vec<u8>), PackIoError> {
    // Parse `<kind> <size>\\0<payload>` and validate against the size cap.
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| PackIoError::LooseObject {
            detail: "missing object header terminator".to_string(),
        })?;

    let header = &bytes[..nul];
    let mut parts = header.split(|&b| b == b' ');
    let kind_bytes = parts.next().ok_or_else(|| PackIoError::LooseObject {
        detail: "missing object kind".to_string(),
    })?;
    let size_bytes = parts.next().ok_or_else(|| PackIoError::LooseObject {
        detail: "missing object size".to_string(),
    })?;
    if parts.next().is_some() {
        return Err(PackIoError::LooseObject {
            detail: "invalid object header".to_string(),
        });
    }

    let size = parse_decimal(size_bytes).ok_or_else(|| PackIoError::LooseObject {
        detail: "invalid object size".to_string(),
    })? as usize;
    if size > max_payload {
        return Err(PackIoError::LooseObject {
            detail: format!("object size {size} exceeds cap {max_payload}"),
        });
    }

    let payload = &bytes[nul + 1..];
    if payload.len() != size {
        return Err(PackIoError::LooseObject {
            detail: "object size mismatch".to_string(),
        });
    }

    let kind = match kind_bytes {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => {
            return Err(PackIoError::LooseObject {
                detail: "unknown loose object type".to_string(),
            })
        }
    };

    Ok((kind, payload.to_vec()))
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut value: u64 = 0;
    for &b in bytes {
        if !b.is_ascii_digit() {
            return None;
        }
        value = value.checked_mul(10)?.checked_add((b - b'0') as u64)?;
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use tempfile::tempdir;

    use super::super::delta_test_helpers::{
        encode_entry_header, encode_ofs_distance, encode_varint, zlib_compress,
    };
    use super::super::multi_pack_test_helpers::{stable_oid, test_limits, MultiPackFixture};
    use super::super::object_id::{ObjectFormat, OidBytes};

    use super::super::midx_test_builder::MidxBuilder;

    fn oid_to_hex(oid: &OidBytes) -> String {
        let mut out = String::with_capacity(oid.len() as usize * 2);
        for &b in oid.as_slice() {
            out.push_str(&format!("{:02x}", b));
        }
        out
    }

    /// Build the on-disk path for a loose object and ensure the fan-out directory exists.
    fn loose_object_path(objects_dir: &Path, oid: &OidBytes) -> PathBuf {
        let hex = oid_to_hex(oid);
        let (dir, file) = hex.split_at(2);
        let dir_path = objects_dir.join(dir);
        fs::create_dir_all(&dir_path).unwrap();
        dir_path.join(file)
    }

    fn write_loose_object(objects_dir: &Path, oid: OidBytes, kind: &str, payload: &[u8]) {
        let mut header = Vec::new();
        header.extend_from_slice(kind.as_bytes());
        header.push(b' ');
        header.extend_from_slice(payload.len().to_string().as_bytes());
        header.push(0);
        header.extend_from_slice(payload);

        let compressed = zlib_compress(&header);
        fs::write(loose_object_path(objects_dir, &oid), &compressed).unwrap();
    }

    fn write_loose_bytes(objects_dir: &Path, oid: OidBytes, payload: &[u8]) {
        fs::write(loose_object_path(objects_dir, &oid), payload).unwrap();
    }

    fn build_pack_blob(data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&encode_entry_header(3, data.len()));
        out.extend_from_slice(&zlib_compress(data));
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    fn build_pack_ref_delta(base_oid: [u8; 20], result: &[u8], base_len: usize) -> Vec<u8> {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(base_len as u64));
        delta.extend_from_slice(&encode_varint(result.len() as u64));
        delta.push(result.len() as u8);
        delta.extend_from_slice(result);

        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&1u32.to_be_bytes());
        out.extend_from_slice(&encode_entry_header(7, result.len()));
        out.extend_from_slice(&base_oid);
        out.extend_from_slice(&zlib_compress(&delta));
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    fn build_pack_ofs_delta(base_offset: u64, result: &[u8]) -> Vec<u8> {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(0));
        delta.extend_from_slice(&encode_varint(result.len() as u64));
        delta.push(result.len() as u8);
        delta.extend_from_slice(result);

        let mut out = Vec::new();
        out.extend_from_slice(b"PACK");
        out.extend_from_slice(&2u32.to_be_bytes());
        out.extend_from_slice(&2u32.to_be_bytes());

        out.extend_from_slice(&encode_entry_header(3, 0));
        out.extend_from_slice(&zlib_compress(&[]));

        let delta_offset = out.len() as u64;
        out.extend_from_slice(&encode_entry_header(6, result.len()));
        out.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        out.extend_from_slice(&zlib_compress(&delta));
        out.extend_from_slice(&[0u8; 20]);
        out
    }

    #[test]
    fn load_cross_pack_ref_delta() {
        let base_oid = [0x11; 20];
        let delta_oid = [0x22; 20];

        let base_bytes = b"base";
        let result_bytes = b"base!";

        let pack_base = build_pack_blob(base_bytes);
        let pack_delta = build_pack_ref_delta(base_oid, result_bytes, base_bytes.len());

        let temp = tempdir().unwrap();
        let pack_base_path = temp.path().join("pack-base.pack");
        let pack_delta_path = temp.path().join("pack-delta.pack");
        fs::write(&pack_base_path, &pack_base).unwrap();
        fs::write(&pack_delta_path, &pack_delta).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-base");
        builder.add_pack(b"pack-delta");
        builder.add_object(base_oid, 0, 12);
        builder.add_object(delta_oid, 1, 12);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut io = PackIo::from_parts(
            midx,
            vec![pack_base_path, pack_delta_path],
            Vec::new(),
            limits,
        )
        .unwrap();

        let base = io.load_object(&OidBytes::sha1(base_oid)).unwrap().unwrap();
        assert_eq!(base.0, ObjectKind::Blob);
        assert_eq!(base.1, base_bytes);

        let delta = io.load_object(&OidBytes::sha1(delta_oid)).unwrap().unwrap();
        assert_eq!(delta.0, ObjectKind::Blob);
        assert_eq!(delta.1, result_bytes);
    }

    #[test]
    fn cross_pack_ref_delta_single_hop() {
        let mut builder = MultiPackFixture::builder();
        let pack_base = builder.add_pack(b"pack-base");
        let pack_delta = builder.add_pack(b"pack-delta");

        let base = builder.add_blob(pack_base, b"base");
        // Mixed delta: copies 4 bytes from base ("base") then appends "!".
        // Resolved content = "base!" — depends on actual base bytes.
        let delta = builder.add_ref_delta_mixed(pack_delta, base, 4, b"!");

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let base_loaded = io.load_object(&fixture.oid(base)).unwrap().unwrap();
        let delta_loaded = io.load_object(&fixture.oid(delta)).unwrap().unwrap();

        assert_eq!(base_loaded.0, ObjectKind::Blob);
        assert_eq!(base_loaded.1, fixture.expected(base).unwrap().1);
        assert_eq!(delta_loaded.0, ObjectKind::Blob);
        assert_eq!(delta_loaded.1, b"base!");
        assert_eq!(delta_loaded.1, fixture.expected(delta).unwrap().1);
    }

    #[test]
    fn cross_pack_ref_delta_two_hop() {
        let mut builder = MultiPackFixture::builder();
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_c, b"root");
        // Mixed delta: copies "root" from base, appends "-mid".
        // Resolved = "root-mid" — verifies base content was fetched correctly.
        let mid = builder.add_ref_delta_mixed(pack_b, base, 4, b"-mid");
        // Mixed delta: copies "root-mid" from mid, appends "-leaf".
        // Resolved = "root-mid-leaf" — verifies two-hop base chain.
        let top = builder.add_ref_delta_mixed(pack_a, mid, 8, b"-leaf");

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let top_loaded = io.load_object(&fixture.oid(top)).unwrap().unwrap();
        assert_eq!(top_loaded.0, ObjectKind::Blob);
        assert_eq!(top_loaded.1, b"root-mid-leaf");
        assert_eq!(top_loaded.1, fixture.expected(top).unwrap().1);

        let mid_loaded = io.load_object(&fixture.oid(mid)).unwrap().unwrap();
        assert_eq!(mid_loaded.0, ObjectKind::Blob);
        assert_eq!(mid_loaded.1, b"root-mid");
        assert_eq!(mid_loaded.1, fixture.expected(mid).unwrap().1);
    }

    #[test]
    fn cross_pack_ref_delta_three_hop() {
        let mut builder = MultiPackFixture::builder();
        let pack_d = builder.add_pack(b"pack-d");
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_d, b"root");
        let hop_c = builder.add_ref_delta_mixed(pack_c, base, 4, b"-c");
        let hop_b = builder.add_ref_delta_mixed(pack_b, hop_c, 6, b"-b");
        let top = builder.add_ref_delta_mixed(pack_a, hop_b, 8, b"-a");

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let hop_c_loaded = io.load_object(&fixture.oid(hop_c)).unwrap().unwrap();
        assert_eq!(hop_c_loaded.0, ObjectKind::Blob);
        assert_eq!(hop_c_loaded.1, b"root-c");
        assert_eq!(hop_c_loaded.1, fixture.expected(hop_c).unwrap().1);

        let hop_b_loaded = io.load_object(&fixture.oid(hop_b)).unwrap().unwrap();
        assert_eq!(hop_b_loaded.0, ObjectKind::Blob);
        assert_eq!(hop_b_loaded.1, b"root-c-b");
        assert_eq!(hop_b_loaded.1, fixture.expected(hop_b).unwrap().1);

        let top_loaded = io.load_object(&fixture.oid(top)).unwrap().unwrap();
        assert_eq!(top_loaded.0, ObjectKind::Blob);
        assert_eq!(top_loaded.1, b"root-c-b-a");
        assert_eq!(top_loaded.1, fixture.expected(top).unwrap().1);
    }

    #[test]
    fn load_mixed_ofs_and_ref_delta_chain_from_fixture() {
        let mut builder = MultiPackFixture::builder();
        let pack_base = builder.add_pack(b"pack-base");
        let pack_delta = builder.add_pack(b"pack-delta");

        let base = builder.add_blob(pack_base, b"seed");
        let local = builder.add_ofs_delta(pack_base, base, b"local");
        let leaf = builder.add_ref_delta(pack_delta, local, b"leaf");

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let local_loaded = io.load_object(&fixture.oid(local)).unwrap().unwrap();
        assert_eq!(local_loaded.0, ObjectKind::Blob);
        assert_eq!(local_loaded.1, fixture.expected(local).unwrap().1);

        let leaf_loaded = io.load_object(&fixture.oid(leaf)).unwrap().unwrap();
        assert_eq!(leaf_loaded.0, ObjectKind::Blob);
        assert_eq!(leaf_loaded.1, fixture.expected(leaf).unwrap().1);
    }

    #[test]
    fn missing_external_base_returns_none_from_fixture() {
        let mut builder = MultiPackFixture::builder();
        let pack = builder.add_pack(b"pack-missing");
        let missing = builder.add_missing_ref_delta(
            pack,
            ObjectKind::Blob,
            stable_oid(b"missing-base"),
            4,
            b"unused",
        );

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let loaded = io.load_object(&fixture.oid(missing)).unwrap();
        assert!(loaded.is_none());
        assert!(fixture.expected(missing).is_none());
    }

    #[test]
    fn cross_pack_missing_intermediate_base() {
        let missing_base = stable_oid(b"missing-cross-pack-base");
        let missing_base_oid: [u8; 20] = missing_base.as_slice().try_into().unwrap();
        let mid_oid = [0x42; 20];
        let top_oid = [0x43; 20];

        let pack_mid = build_pack_ref_delta(missing_base_oid, b"unused-mid", 4);
        let pack_top = build_pack_ref_delta(mid_oid, b"unused-top", 10);

        let temp = tempdir().unwrap();
        let pack_mid_path = temp.path().join("pack-mid.pack");
        let pack_top_path = temp.path().join("pack-top.pack");
        fs::write(&pack_mid_path, &pack_mid).unwrap();
        fs::write(&pack_top_path, &pack_top).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-mid");
        builder.add_pack(b"pack-top");
        builder.add_object(mid_oid, 0, 12);
        builder.add_object(top_oid, 1, 12);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let mut io = PackIo::from_parts(
            midx,
            vec![pack_mid_path, pack_top_path],
            Vec::new(),
            test_limits(),
        )
        .unwrap();

        let missing_mid = io.load_object(&OidBytes::sha1(mid_oid)).unwrap();
        assert!(missing_mid.is_none());

        let missing_top = io.load_object(&OidBytes::sha1(top_oid)).unwrap();
        assert!(missing_top.is_none());
    }

    #[test]
    fn fixture_golden_values_match_pack_io() {
        let mut builder = MultiPackFixture::builder();
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_c, b"base");
        let mid = builder.add_ref_delta(pack_b, base, b"middle");
        let top = builder.add_ref_delta(pack_a, mid, b"leaf");

        let fixture = builder.build().unwrap();
        let mut io = fixture.pack_io(test_limits()).unwrap();

        let mut count = 0;
        for (handle, oid, kind, expected) in fixture.golden_values() {
            let loaded = io.load_object(&oid).unwrap().unwrap();
            assert_eq!(loaded.0, kind);
            assert_eq!(loaded.1, expected);
            assert_eq!(fixture.oid(handle), oid);
            count += 1;
        }
        assert_eq!(count, 3);

        assert_eq!(fixture.expected(top).unwrap().1, b"leaf");
    }

    #[test]
    fn cross_pack_depth_exhaustion_at_boundary() {
        let mut builder = MultiPackFixture::builder();
        let pack_d = builder.add_pack(b"pack-d");
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_d, b"root");
        let hop_c = builder.add_ref_delta_mixed(pack_c, base, 4, b"-c");
        let hop_b = builder.add_ref_delta_mixed(pack_b, hop_c, 6, b"-b");
        let top = builder.add_ref_delta_mixed(pack_a, hop_b, 8, b"-a");

        let fixture = builder.build().unwrap();

        let fail_limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 2);
        let mut fail_io = fixture.pack_io(fail_limits).unwrap();

        let err = fail_io.load_object(&fixture.oid(top)).unwrap_err();
        assert!(matches!(
            err,
            PackIoError::DeltaDepthExceeded { max_depth: 2 }
        ));

        let success_limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 3);
        let mut success_io = fixture.pack_io(success_limits).unwrap();
        let loaded = success_io.load_object(&fixture.oid(top)).unwrap().unwrap();
        assert_eq!(loaded.0, ObjectKind::Blob);
        assert_eq!(loaded.1, b"root-c-b-a");
        assert_eq!(loaded.1, fixture.expected(top).unwrap().1);
    }

    #[test]
    fn load_loose_object_falls_back_when_missing_in_midx() {
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");
        fs::create_dir_all(&objects_dir).unwrap();

        let oid = OidBytes::sha1([0x55; 20]);
        write_loose_object(&objects_dir, oid, "blob", b"loose-bytes");

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-empty");
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let pack_path = temp.path().join("pack-empty.pack");
        fs::write(&pack_path, b"").unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut io = PackIo::from_parts(midx, vec![pack_path], vec![objects_dir], limits).unwrap();

        let loaded = io.load_object(&oid).unwrap().unwrap();
        assert_eq!(loaded.0, ObjectKind::Blob);
        assert_eq!(loaded.1, b"loose-bytes");
    }

    #[test]
    fn load_base_reports_some_none_and_error() {
        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");
        fs::create_dir_all(&objects_dir).unwrap();

        let present_oid = OidBytes::sha1([0x51; 20]);
        let missing_oid = OidBytes::sha1([0x52; 20]);
        let corrupt_oid = OidBytes::sha1([0x53; 20]);
        write_loose_object(&objects_dir, present_oid, "blob", b"loose-base");
        write_loose_bytes(&objects_dir, corrupt_oid, b"not-a-zlib-stream");

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-empty");
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let pack_path = temp.path().join("pack-empty.pack");
        fs::write(&pack_path, b"").unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut io = PackIo::from_parts(midx, vec![pack_path], vec![objects_dir], limits).unwrap();

        let base = ExternalBaseProvider::load_base(&mut io, &present_oid)
            .unwrap()
            .expect("expected Some(ExternalBase)");
        assert_eq!(base.kind, ObjectKind::Blob);
        assert_eq!(base.bytes, b"loose-base");

        let missing = ExternalBaseProvider::load_base(&mut io, &missing_oid).unwrap();
        assert!(missing.is_none());

        let err = ExternalBaseProvider::load_base(&mut io, &corrupt_oid).unwrap_err();
        assert!(
            matches!(err, PackExecError::ExternalBase(ref detail) if !detail.is_empty()),
            "ExternalBase error should contain a non-empty detail describing the failure"
        );
    }

    #[test]
    fn ref_delta_resolves_loose_base() {
        let base_oid = [0x66; 20];
        let delta_oid = [0x77; 20];

        let base_bytes = b"base";
        let result_bytes = b"base!";

        let temp = tempdir().unwrap();
        let objects_dir = temp.path().join("objects");
        fs::create_dir_all(&objects_dir).unwrap();

        write_loose_object(&objects_dir, OidBytes::sha1(base_oid), "blob", base_bytes);

        let pack_delta = build_pack_ref_delta(base_oid, result_bytes, base_bytes.len());
        let pack_delta_path = temp.path().join("pack-delta.pack");
        fs::write(&pack_delta_path, &pack_delta).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-delta");
        builder.add_object(delta_oid, 0, 12);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 8);
        let mut io =
            PackIo::from_parts(midx, vec![pack_delta_path], vec![objects_dir], limits).unwrap();

        let delta = io.load_object(&OidBytes::sha1(delta_oid)).unwrap().unwrap();
        assert_eq!(delta.0, ObjectKind::Blob);
        assert_eq!(delta.1, result_bytes);
    }

    #[test]
    fn delta_depth_exceeded_is_reported() {
        let base_oid = [0x11; 20];
        let delta_oid = [0x22; 20];

        let result_bytes = b"delta";
        let pack = build_pack_ofs_delta(12, result_bytes);

        let temp = tempdir().unwrap();
        let pack_path = temp.path().join("pack-depth.pack");
        fs::write(&pack_path, &pack).unwrap();

        let mut builder = MidxBuilder::default();
        builder.add_pack(b"pack-depth");
        builder.add_object(base_oid, 0, 12);
        builder.add_object(delta_oid, 0, 12 + 1 + zlib_compress(&[]).len() as u64);
        let midx_bytes = builder.build();
        let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

        let limits = PackIoLimits::new(PackDecodeLimits::new(64, 1024, 1024), 0);
        let mut io = PackIo::from_parts(
            midx,
            vec![pack_path],
            vec![temp.path().to_path_buf()],
            limits,
        )
        .unwrap();

        let err = io.load_object(&OidBytes::sha1(delta_oid)).unwrap_err();
        assert!(matches!(
            err,
            PackIoError::DeltaDepthExceeded { max_depth: 0 }
        ));
    }
}
