//! Shared repository path and object-byte utilities.
//!
//! This module consolidates directory-listing and pack-resolution helpers that
//! were previously duplicated across `object_store`, `runner_exec`, `pack_io`,
//! and `commit_loader`, plus shared OID/loose-object parsing routines used by
//! `object_store` and `commit_parse`. Fallible path helpers return `io::Error`
//! so callers can convert to their domain error type with `.map_err()` or `?`
//! (when `From<io::Error>` is implemented).

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use super::midx::MidxView;
use super::object_id::{ObjectFormat, OidBytes};
use super::pack_inflate::ObjectKind;
use super::repo::GitRepoPaths;

// ---------------------------------------------------------------------------
// Directory collection
// ---------------------------------------------------------------------------

/// Collect pack directories from the primary and alternate object dirs.
///
/// The primary `pack_dir` is returned first, followed by `<alternate>/pack`
/// for each alternate objects directory. Alternates equal to the main objects
/// dir are skipped to avoid duplicate scanning.
pub fn collect_pack_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.pack_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.join("pack"));
    }
    dirs
}

/// Collect loose object directories from the primary and alternate object dirs.
///
/// The primary objects dir is returned first, followed by each alternate.
/// Alternates equal to the main objects dir are skipped to avoid duplicate
/// scanning.
pub fn collect_loose_dirs(paths: &GitRepoPaths) -> Vec<PathBuf> {
    let mut dirs = Vec::with_capacity(1 + paths.alternate_object_dirs.len());
    dirs.push(paths.objects_dir.clone());
    for alternate in &paths.alternate_object_dirs {
        if alternate == &paths.objects_dir {
            continue;
        }
        dirs.push(alternate.clone());
    }
    dirs
}

// ---------------------------------------------------------------------------
// Pack file listing (fallible — returns io::Error)
// ---------------------------------------------------------------------------

/// List pack file names from the provided pack directories.
///
/// Returns raw file names (as bytes) for `.pack` files. Names are converted
/// through [`std::ffi::OsStr::to_string_lossy`], so non-UTF-8 bytes are
/// replaced with U+FFFD — acceptable because git pack file names are always
/// ASCII hex. Missing pack directories are ignored; other IO errors are
/// returned.
pub(super) fn list_pack_files(pack_dirs: &[PathBuf]) -> Result<Vec<Vec<u8>>, io::Error> {
    let mut names = Vec::new();

    for dir in pack_dirs {
        let entries = match fs::read_dir(dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };

        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            if !file_type.is_file() {
                continue;
            }

            let file_name = entry.file_name();
            if is_pack_file(&file_name) {
                names.push(file_name.to_string_lossy().as_bytes().to_vec());
            }
        }
    }

    Ok(names)
}

/// Resolve pack file paths referenced by a multi-pack-index.
///
/// The MIDX stores pack basenames (with `.idx` suffix); this function strips
/// the suffix, appends `.pack`, and searches `pack_dirs` in order. The first
/// match wins, so `pack_dirs` order is significant (primary before alternates).
///
/// # Errors
///
/// Returns `io::Error` with `NotFound` kind if any MIDX-referenced pack
/// cannot be located in the provided directories.
pub(super) fn resolve_pack_paths(
    midx: &MidxView<'_>,
    pack_dirs: &[PathBuf],
) -> Result<Vec<PathBuf>, io::Error> {
    let mut paths = Vec::with_capacity(midx.pack_count() as usize);

    for name in midx.pack_names() {
        match find_pack_path(name, pack_dirs) {
            Some(path) => paths.push(path),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("pack file not found for {}", String::from_utf8_lossy(name)),
                ));
            }
        }
    }

    Ok(paths)
}

/// Convert a MIDX pack name to the corresponding `.pack` file name.
///
/// MIDX pack names are typically `<basename>.idx`; this strips `.idx`/`.pack`
/// and returns `<basename>.pack`.
pub(super) fn pack_data_file_name(name: &[u8]) -> String {
    let mut base = strip_pack_suffix(name);
    base.extend_from_slice(b".pack");
    String::from_utf8_lossy(&base).into_owned()
}

/// Find the first matching `.pack` path for `name` across `pack_dirs`.
///
/// Search order is stable and follows `pack_dirs`.
pub(super) fn find_pack_path(name: &[u8], pack_dirs: &[PathBuf]) -> Option<PathBuf> {
    let file_name = pack_data_file_name(name);
    for dir in pack_dirs {
        let candidate = dir.join(&file_name);
        if is_file(&candidate) {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Byte-level utilities (infallible)
// ---------------------------------------------------------------------------

/// Strip a `.pack` or `.idx` suffix from a pack-related file name.
///
/// Both suffixes are handled because the MIDX stores pack basenames with
/// `.idx` suffixes, while we need `.pack` paths for mmap. Returns the
/// input unchanged (as a new `Vec`) if neither suffix matches.
pub(super) fn strip_pack_suffix(name: &[u8]) -> Vec<u8> {
    if name.ends_with(b".pack") {
        name[..name.len() - 5].to_vec()
    } else if name.ends_with(b".idx") {
        name[..name.len() - 4].to_vec()
    } else {
        name.to_vec()
    }
}

/// Encode a nibble (0--15) as a lowercase hex ASCII byte.
pub(super) fn hex_digit(val: u8) -> u8 {
    match val {
        0..=9 => b'0' + val,
        10..=15 => b'a' + (val - 10),
        _ => b'?',
    }
}

/// Encode an OID as a hex byte vector.
///
/// Each byte of the OID is expanded to two lowercase hex ASCII bytes.
pub(super) fn oid_to_hex(oid: &OidBytes) -> Vec<u8> {
    let mut out = Vec::with_capacity(oid.len() as usize * 2);
    for &b in oid.as_slice() {
        out.push(hex_digit(b >> 4));
        out.push(hex_digit(b & 0x0f));
    }
    out
}

/// Hashes an OID for power-of-two hash-table probing.
///
/// OIDs are already high-entropy hashes, so the first 8 bytes are sufficient
/// as a stable probe key.
pub(super) fn hash_oid(oid: &OidBytes) -> u64 {
    let bytes = oid.as_slice();
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    u64::from_le_bytes(buf)
}

/// Parses a non-empty ASCII decimal sequence with overflow checks.
///
/// Returns `None` for empty input, non-digit bytes, or arithmetic overflow.
pub(super) fn parse_decimal(bytes: &[u8]) -> Option<u64> {
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

/// Error taxonomy for loose object parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LooseObjectParseError {
    MissingHeaderTerminator,
    MissingKind,
    MissingSize,
    InvalidHeader,
    InvalidSize,
    SizeExceedsCap { size: usize, max_payload: usize },
    SizeMismatch,
    UnknownType,
}

/// Parses an inflated loose object into kind + payload.
///
/// Expects the loose format `<type> <size>\0<payload>` and verifies that the
/// payload size matches the header.
pub(super) fn parse_loose_object(
    bytes: &[u8],
    max_payload: usize,
) -> Result<(ObjectKind, Vec<u8>), LooseObjectParseError> {
    let nul = bytes
        .iter()
        .position(|&b| b == 0)
        .ok_or(LooseObjectParseError::MissingHeaderTerminator)?;

    let header = &bytes[..nul];
    let mut parts = header.split(|&b| b == b' ');
    let kind_bytes = parts.next().ok_or(LooseObjectParseError::MissingKind)?;
    let size_bytes = parts.next().ok_or(LooseObjectParseError::MissingSize)?;
    if parts.next().is_some() {
        return Err(LooseObjectParseError::InvalidHeader);
    }

    let size = parse_decimal(size_bytes).ok_or(LooseObjectParseError::InvalidSize)? as usize;
    if size > max_payload {
        return Err(LooseObjectParseError::SizeExceedsCap { size, max_payload });
    }

    let payload = &bytes[nul + 1..];
    if payload.len() != size {
        return Err(LooseObjectParseError::SizeMismatch);
    }

    let kind = match kind_bytes {
        b"commit" => ObjectKind::Commit,
        b"tree" => ObjectKind::Tree,
        b"blob" => ObjectKind::Blob,
        b"tag" => ObjectKind::Tag,
        _ => return Err(LooseObjectParseError::UnknownType),
    };

    Ok((kind, payload.to_vec()))
}

/// Error taxonomy for hex OID parsing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum HexOidParseError {
    InvalidHex { byte: u8 },
    InvalidOidLength { found: usize, expected: usize },
}

/// Parses a hex-encoded OID for the requested object format.
pub(super) fn parse_hex_oid(
    hex: &[u8],
    format: ObjectFormat,
) -> Result<OidBytes, HexOidParseError> {
    let expected_len = format.hex_len() as usize;
    if hex.len() != expected_len {
        return Err(HexOidParseError::InvalidOidLength {
            found: hex.len(),
            expected: expected_len,
        });
    }

    let oid_len = format.oid_len() as usize;
    let mut bytes = [0u8; 32];

    for i in 0..oid_len {
        let hi = decode_hex_digit(hex[i * 2])
            .ok_or(HexOidParseError::InvalidHex { byte: hex[i * 2] })?;
        let lo = decode_hex_digit(hex[i * 2 + 1]).ok_or(HexOidParseError::InvalidHex {
            byte: hex[i * 2 + 1],
        })?;
        bytes[i] = (hi << 4) | lo;
    }

    Ok(match format {
        ObjectFormat::Sha1 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes[..20]);
            OidBytes::sha1(arr)
        }
        ObjectFormat::Sha256 => OidBytes::sha256(bytes),
    })
}

/// 256-byte lookup table for hex digit decoding.
///
/// Valid hex digits map to 0..=15; all other bytes map to 0xFF.
static HEX_DECODE: [u8; 256] = {
    let mut table = [0xFFu8; 256];
    let mut i = 0u16;
    while i < 256 {
        let b = i as u8;
        table[i as usize] = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => 0xFF,
        };
        i += 1;
    }
    table
};

/// Converts a hex ASCII byte to its numeric value.
#[inline]
pub(super) fn decode_hex_digit(b: u8) -> Option<u8> {
    let v = HEX_DECODE[b as usize];
    (v != 0xFF).then_some(v)
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Returns `true` if the file name has a `.pack` extension.
fn is_pack_file(name: &std::ffi::OsStr) -> bool {
    Path::new(name).extension().is_some_and(|ext| ext == "pack")
}

/// Returns `true` if `path` exists and is a regular file.
fn is_file(path: &Path) -> bool {
    fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decimal_rejects_empty_non_digit_and_overflow() {
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"12a3"), None);
        assert_eq!(parse_decimal(b"18446744073709551616"), None);
    }

    #[test]
    fn parse_loose_object_validates_header_and_payload() {
        let good = b"tree 3\0abc";
        let (kind, payload) = parse_loose_object(good, 8).unwrap();
        assert_eq!(kind, ObjectKind::Tree);
        assert_eq!(payload, b"abc");

        let err = parse_loose_object(b"tree 4\0abc", 8).unwrap_err();
        assert_eq!(err, LooseObjectParseError::SizeMismatch);
    }

    #[test]
    fn parse_hex_oid_supports_sha1_and_sha256() {
        let sha1 = b"1234567890abcdef1234567890abcdef12345678";
        let parsed = parse_hex_oid(sha1, ObjectFormat::Sha1).unwrap();
        assert_eq!(parsed.len(), 20);

        let sha256 = b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let parsed = parse_hex_oid(sha256, ObjectFormat::Sha256).unwrap();
        assert_eq!(parsed.len(), 32);
    }

    #[test]
    fn hash_oid_uses_first_8_bytes_le() {
        let oid = OidBytes::sha1([
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(hash_oid(&oid), 0x8877665544332211);
    }
}
