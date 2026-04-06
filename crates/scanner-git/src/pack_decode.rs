//! Pack decode primitives for bounded object inflation.
//!
//! This module provides thin wrappers around pack header parsing and zlib
//! inflation with explicit size caps. It does not perform delta resolution
//! on its own; callers should use `pack_delta` to apply deltas and enforce
//! depth limits at a higher level.
//!
//! For delta entries, `EntryHeader.size` is the uncompressed delta payload
//! size; the delta stream itself encodes base and result sizes.
//!
//! The helpers here do not verify pack checksums; they operate on already
//! loaded pack bytes and return precise errors for size and parsing issues.

use crate::pack_inflate_libdeflate;

use super::pack_inflate::{
    inflate_exact_with, inflate_limited, inflate_limited_with, EntryHeader, EntryKind, PackFile,
};
use super::pack_inflate::{InflateError, PackParseError};

use flate2::Decompress;

/// Limits for pack object decoding.
///
/// `max_delta_bytes` caps the inflated delta stream (not the final object).
/// Callers typically set it to the same value as `max_object_bytes` to keep
/// delta buffers bounded.
#[derive(Clone, Copy, Debug)]
pub struct PackDecodeLimits {
    /// Maximum header bytes to parse for an entry.
    pub max_header_bytes: usize,
    /// Maximum object size (inflated) allowed for any entry.
    pub max_object_bytes: usize,
    /// Maximum delta payload size (inflated) for delta entries.
    ///
    /// This cap applies to the delta stream itself, not the final object.
    pub max_delta_bytes: usize,
}

impl PackDecodeLimits {
    /// Creates a new limits struct.
    #[must_use]
    pub const fn new(
        max_header_bytes: usize,
        max_object_bytes: usize,
        max_delta_bytes: usize,
    ) -> Self {
        Self {
            max_header_bytes,
            max_object_bytes,
            max_delta_bytes,
        }
    }
}

/// Pack decode error taxonomy.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum PackDecodeError {
    /// Pack header parsing failed.
    #[error("{0}")]
    PackParse(#[from] PackParseError),
    /// Zlib inflation failed or exceeded a limit.
    #[error("{0}")]
    Inflate(#[from] InflateError),
    /// Object size exceeds the configured cap.
    #[error("object size {size} exceeds cap {max}")]
    ObjectTooLarge { size: u64, max: usize },
    /// Delta payload size exceeds the configured cap (delta stream size).
    #[error("delta payload size {size} exceeds cap {max}")]
    DeltaTooLarge { size: u64, max: usize },
}

/// Parses an entry header and enforces the object size cap.
///
/// # Errors
/// - `PackDecodeError::PackParse` on invalid header data.
/// - `PackDecodeError::ObjectTooLarge` if a non-delta entry exceeds the limit.
/// - `PackDecodeError::DeltaTooLarge` if a delta payload exceeds the limit.
pub fn entry_header_at(
    pack: &PackFile<'_>,
    offset: u64,
    limits: &PackDecodeLimits,
) -> Result<EntryHeader, PackDecodeError> {
    let header = pack.entry_header_at(offset, limits.max_header_bytes)?;
    match header.kind {
        EntryKind::NonDelta { .. } => {
            if header.size > limits.max_object_bytes as u64 {
                return Err(PackDecodeError::ObjectTooLarge {
                    size: header.size,
                    max: limits.max_object_bytes,
                });
            }
        }
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => {
            if header.size > limits.max_delta_bytes as u64 {
                return Err(PackDecodeError::DeltaTooLarge {
                    size: header.size,
                    max: limits.max_delta_bytes,
                });
            }
        }
    }
    Ok(header)
}

/// Inflates the payload for an entry header using caller-provided
/// decompressors, bypassing TLS.
///
/// Callers are expected to pass a header parsed from `pack` (typically via
/// [`entry_header_at`]) so `data_start`, `kind`, and `size` match the bytes at
/// that offset.
///
/// Non-delta entries (`EntryKind::NonDelta`) are inflated with an exact-size
/// contract of `header.size` bytes. Small non-delta entries route through
/// the libdeflate backend; larger non-delta entries continue to use the
/// caller-provided `Decompress`. Delta entries (`EntryKind::OfsDelta` and
/// `EntryKind::RefDelta`) are inflated as raw delta streams with a hard cap
/// of `limits.max_delta_bytes`.
///
/// When `libde` is `Some`, the libdeflate fast path uses the provided
/// decompressor directly. When `None`, the thread-local libdeflate
/// decompressor is used as a fallback. The caller-provided `Decompress` is
/// bypassed entirely when the libdeflate fast path is selected.
///
/// This function does not enforce `limits.max_object_bytes` for non-delta
/// entries and does not parse delta varints/result sizes; those checks happen
/// in higher-level decode/resolve paths.
///
/// # Returns
/// - `Ok(consumed)` where `consumed` is the number of compressed bytes read
///   from `pack.slice_from(header.data_start)` until zlib stream end.
/// - `out` is cleared and then filled with inflated bytes:
///   - Non-delta: full object payload (`header.size` bytes).
///   - Delta: delta payload bytes (not the resolved base+delta result object).
///
/// # Errors
/// - `PackDecodeError::Inflate(InflateError::LimitExceeded)` if:
///   - non-delta output grows beyond `header.size`, or
///   - delta output grows beyond `limits.max_delta_bytes`.
/// - `PackDecodeError::Inflate(InflateError::TruncatedInput)` for truncated
///   zlib streams.
/// - `PackDecodeError::Inflate(InflateError::Stalled)` when inflate makes no
///   progress before reaching stream end.
/// - `PackDecodeError::Inflate(InflateError::Backend)` on backend/zlib errors.
///
/// # Panics
/// Panics if `header.data_start` is out of bounds for `pack` (bounds check in
/// `PackFile::slice_from`).
/// When `libde` is `None`, may panic on same-thread reentrancy because the
/// thread-local libdeflate decompressor is guarded by `RefCell`.
pub fn inflate_entry_payload_with(
    de: &mut Decompress,
    libde: Option<&mut pack_inflate_libdeflate::LibdeflateDecompressor>,
    pack: &PackFile<'_>,
    header: &EntryHeader,
    out: &mut Vec<u8>,
    limits: &PackDecodeLimits,
) -> Result<usize, PackDecodeError> {
    if pack_inflate_libdeflate::use_libdeflate_for_header(header) {
        // `de` is unused: libdeflate uses its own thread-local decompressor.
        let slice = pack.slice_from(header.data_start);
        // Safe truncation: `use_libdeflate_for_header` gates on size <= 256 KB,
        // which fits in any `usize`.
        let expected = header.size as usize;
        return match libde {
            Some(libde) => {
                pack_inflate_libdeflate::inflate_nondelta_exact_with(libde, slice, expected, out)
            }
            None => pack_inflate_libdeflate::inflate_nondelta_exact(slice, expected, out),
        };
    }

    match header.kind {
        EntryKind::NonDelta { .. } => {
            // Safe truncation: `entry_header_at` rejects sizes above
            // `max_object_bytes` (a `usize`), so `header.size` fits.
            let expected = header.size as usize;
            let consumed =
                inflate_exact_with(de, pack.slice_from(header.data_start), out, expected)?;
            Ok(consumed)
        }
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => {
            let consumed = inflate_limited_with(
                de,
                pack.slice_from(header.data_start),
                out,
                limits.max_delta_bytes,
            )?;
            Ok(consumed)
        }
    }
}

/// Inflates the payload for an entry header using the thread-local
/// `Decompress`.
///
/// Header and behavior contracts are identical to
/// [`inflate_entry_payload_with`]:
/// - Non-delta entries inflate exactly `header.size` bytes and route small
///   payloads through the thread-local libdeflate backend.
/// - Delta entries inflate a raw delta stream capped by
///   `limits.max_delta_bytes`.
///
/// # Returns
/// - `Ok(consumed)` where `consumed` is the number of compressed bytes read
///   from `pack.slice_from(header.data_start)` until zlib stream end.
/// - `out` is cleared and then filled with inflated payload bytes for the
///   selected entry kind.
///
/// # Errors
/// - Propagates `PackDecodeError::Inflate(...)` from
///   [`inflate_entry_payload_with`] with the same variants and conditions.
///
/// # Panics
/// - Panics if `header.data_start` is out of bounds for `pack` (bounds check in
///   `PackFile::slice_from`).
/// - May panic if called reentrantly on the same thread because the
///   thread-local inflate scratch and thread-local libdeflate scratch both use
///   `RefCell` borrowing.
pub fn inflate_entry_payload(
    pack: &PackFile<'_>,
    header: &EntryHeader,
    out: &mut Vec<u8>,
    limits: &PackDecodeLimits,
) -> Result<usize, PackDecodeError> {
    super::pack_inflate::with_tls_decompress(|de| {
        inflate_entry_payload_with(de, None, pack, header, out, limits)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::delta_test_helpers::{
        encode_entry_header, make_add_delta, zlib_compress, SyntheticPackBuilder,
    };
    use crate::object_id::OidBytes;
    use crate::pack_inflate_libdeflate::{LibdeflateDecompressor, LIBDEFLATE_THRESHOLD_BYTES};
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn test_limits(max_object_bytes: usize) -> PackDecodeLimits {
        PackDecodeLimits::new(64, max_object_bytes, max_object_bytes)
    }

    fn build_pack(entries: &[Vec<u8>]) -> (Vec<u8>, Vec<u64>) {
        let mut pack = Vec::new();
        let mut offsets = Vec::with_capacity(entries.len());

        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        for entry in entries {
            offsets.push(pack.len() as u64);
            pack.extend_from_slice(entry);
        }

        pack.extend_from_slice(&[0u8; 20]);
        (pack, offsets)
    }

    fn single_entry_pack(entry: Vec<u8>) -> (Vec<u8>, u64) {
        let (pack, offsets) = build_pack(&[entry]);
        (pack, offsets[0])
    }

    fn non_delta_entry(declared_size: usize, compressed: &[u8]) -> Vec<u8> {
        let mut entry = encode_entry_header(3, declared_size);
        entry.extend_from_slice(compressed);
        entry
    }

    #[test]
    fn inflate_limited_errors_on_overrun() {
        let input = b"hello world hello world";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(input).unwrap();
        let compressed = encoder.finish().unwrap();

        let mut out = Vec::with_capacity(4);
        let err = inflate_limited(&compressed, &mut out, 4).unwrap_err();
        assert_eq!(err, InflateError::LimitExceeded);
    }

    #[test]
    fn empty_nondelta_payload_inflates_via_libdeflate() {
        let compressed = zlib_compress(&[]);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(0, &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();

        assert!(pack_inflate_libdeflate::use_libdeflate_for_header(&header));
        let consumed =
            inflate_entry_payload(&pack, &header, &mut out, &limits).expect("inflate entry");

        assert_eq!(consumed, compressed.len());
        assert!(out.is_empty());
    }

    #[test]
    fn exact_size_nondelta_roundtrip_returns_compressed_bytes_consumed() {
        let payload = b"exact size roundtrip via libdeflate".to_vec();
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        let consumed =
            inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits).unwrap();

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn short_output_nondelta_returns_truncated_input() {
        let payload = b"short output".to_vec();
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) =
            single_entry_pack(non_delta_entry(payload.len() + 1, &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        let err = inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits)
            .expect_err("expected truncated exact-size decode");

        assert_eq!(err, PackDecodeError::Inflate(InflateError::TruncatedInput));
        assert!(out.is_empty());
    }

    #[test]
    fn corrupt_small_nondelta_reports_backend_error() {
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(8, b"\x78\x9c\xff\xff"));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::from("stale");
        let mut de = Decompress::new(true);

        let err = inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits)
            .expect_err("expected corrupt stream error");

        assert_eq!(err, PackDecodeError::Inflate(InflateError::Backend));
        assert!(out.is_empty());
    }

    #[test]
    fn threshold_sized_nondelta_routes_through_libdeflate() {
        let payload = vec![0x5a; LIBDEFLATE_THRESHOLD_BYTES];
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        assert!(pack_inflate_libdeflate::use_libdeflate_for_header(&header));
        let consumed =
            inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits).unwrap();

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn threshold_plus_one_nondelta_routes_through_flate2() {
        let payload = vec![0x33; LIBDEFLATE_THRESHOLD_BYTES + 1];
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES + 1);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        assert!(!pack_inflate_libdeflate::use_libdeflate_for_header(&header));
        let consumed =
            inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits).unwrap();

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn delta_entries_stay_on_flate2_path_and_decode_unchanged() {
        let base = b"base payload";
        let delta = make_add_delta(base.len(), b"XYZ");
        let compressed_delta = zlib_compress(&delta);

        let mut builder = SyntheticPackBuilder::new();
        builder.add_non_delta(3, base);
        let delta_idx = builder.add_ofs_delta(0, &delta);
        let (pack_bytes, offsets) = builder.build();
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offsets[delta_idx], &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        assert!(!pack_inflate_libdeflate::use_libdeflate_for_header(&header));
        let consumed =
            inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits).unwrap();

        assert_eq!(consumed, compressed_delta.len());
        assert_eq!(out, delta);
    }

    #[test]
    fn libdeflate_tls_reentrancy_panics_predictably() {
        let payload = b"reentrant libdeflate".to_vec();
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");

        let result = catch_unwind(AssertUnwindSafe(|| {
            crate::pack_inflate_libdeflate::hold_tls_borrow_for_test(|| {
                let mut out = Vec::new();
                let _ = inflate_entry_payload(&pack, &header, &mut out, &limits);
            });
        }));

        assert!(result.is_err());
    }

    #[test]
    fn libdeflate_reports_consumed_bytes_before_trailing_garbage() {
        let payload = b"payload before trailing bytes".to_vec();
        let compressed = zlib_compress(&payload);
        let mut entry = non_delta_entry(payload.len(), &compressed);
        entry.extend_from_slice(b"trailing bytes that should stay unread");
        let (pack_bytes, offset) = single_entry_pack(entry);
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        let consumed =
            inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits).unwrap();

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn undersized_header_nondelta_returns_limit_exceeded() {
        // Compress a payload larger than the declared header size.
        // libdeflate gets an output buffer sized to declared_size (4 bytes),
        // but the actual stream decompresses to more bytes. This is a
        // size-limit violation (decompressed data exceeds declared size),
        // not a backend driver error.
        let payload = b"this payload is much larger than the declared size in header";
        let compressed = zlib_compress(payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(4, &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        // Verify this routes through libdeflate (declared size 4 <= threshold)
        assert!(crate::pack_inflate_libdeflate::use_libdeflate_for_header(
            &header
        ));

        let err = inflate_entry_payload_with(&mut de, None, &pack, &header, &mut out, &limits)
            .expect_err("expected limit-exceeded error from undersized header");

        assert_eq!(err, PackDecodeError::Inflate(InflateError::LimitExceeded));
        assert!(out.is_empty());
    }

    #[test]
    fn tls_variant_roundtrip_matches_with_variant() {
        let payload = b"non-trivial payload for TLS inflate_entry_payload roundtrip".to_vec();
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();

        let consumed =
            inflate_entry_payload(&pack, &header, &mut out, &limits).expect("inflate entry");

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn caller_provided_libde_roundtrip() {
        let mut libde = LibdeflateDecompressor::new();
        let payload = b"roundtrip through caller-provided libdeflate decompressor".to_vec();
        let compressed = zlib_compress(&payload);
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(payload.len(), &compressed));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        let consumed = inflate_entry_payload_with(
            &mut de,
            Some(&mut libde),
            &pack,
            &header,
            &mut out,
            &limits,
        )
        .expect("inflate with caller-provided libde");

        assert_eq!(consumed, compressed.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn caller_provided_libde_corrupt_returns_backend_error() {
        let mut libde = LibdeflateDecompressor::new();
        let (pack_bytes, offset) = single_entry_pack(non_delta_entry(8, b"\x78\x9c\xff\xff"));
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header = entry_header_at(&pack, offset, &limits).expect("parse header");
        let mut out = Vec::new();
        let mut de = Decompress::new(true);

        let err = inflate_entry_payload_with(
            &mut de,
            Some(&mut libde),
            &pack,
            &header,
            &mut out,
            &limits,
        )
        .expect_err("expected backend error from corrupt zlib data");

        assert_eq!(err, PackDecodeError::Inflate(InflateError::Backend));
        assert!(out.is_empty());
    }

    #[test]
    fn ref_delta_routes_through_flate2() {
        let base = b"base payload for ref-delta";
        let delta = make_add_delta(base.len(), b"REF");
        let base_oid = OidBytes::sha1([0xAA; 20]);

        let mut builder = SyntheticPackBuilder::new();
        builder.add_non_delta(3, base);
        let delta_idx = builder.add_ref_delta(base_oid, &delta);
        let (pack_bytes, offsets) = builder.build();
        let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
        let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
        let header =
            entry_header_at(&pack, offsets[delta_idx], &limits).expect("parse ref-delta header");

        assert!(
            !pack_inflate_libdeflate::use_libdeflate_for_header(&header),
            "REF_DELTA entries must bypass libdeflate"
        );
    }

    #[test]
    fn all_nondelta_object_kinds_route_through_libdeflate() {
        // Type bytes: 1=Commit, 2=Tree, 3=Blob, 4=Tag.
        for type_byte in 1u8..=4 {
            let payload = b"kind routing payload";
            let compressed = zlib_compress(payload);
            let mut entry = encode_entry_header(type_byte, payload.len());
            entry.extend_from_slice(&compressed);
            let (pack_bytes, offset) = single_entry_pack(entry);
            let pack = PackFile::parse(&pack_bytes, 20).expect("parse pack");
            let limits = test_limits(LIBDEFLATE_THRESHOLD_BYTES);
            let header = entry_header_at(&pack, offset, &limits).expect("parse header");

            assert!(
                pack_inflate_libdeflate::use_libdeflate_for_header(&header),
                "non-delta type byte {type_byte} should route through libdeflate"
            );
        }
    }

    #[test]
    fn libdeflate_decompressor_reuse_across_payloads() {
        let mut libde = LibdeflateDecompressor::new();

        let payload_a = b"first payload for reuse test".to_vec();
        let compressed_a = zlib_compress(&payload_a);
        let mut out = Vec::new();
        let consumed_a = pack_inflate_libdeflate::inflate_nondelta_exact_with(
            &mut libde,
            &compressed_a,
            payload_a.len(),
            &mut out,
        )
        .expect("first inflate");
        assert_eq!(consumed_a, compressed_a.len());
        assert_eq!(out, payload_a);

        let payload_b = b"second, different payload for reuse".to_vec();
        let compressed_b = zlib_compress(&payload_b);
        let consumed_b = pack_inflate_libdeflate::inflate_nondelta_exact_with(
            &mut libde,
            &compressed_b,
            payload_b.len(),
            &mut out,
        )
        .expect("second inflate reusing same decompressor");
        assert_eq!(consumed_b, compressed_b.len());
        assert_eq!(out, payload_b);
    }
}
