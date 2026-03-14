//! Tests for pack inflate and delta helpers (`pack_inflate.rs`).
//!
//! Split into a sibling file for readability. Property-based tests cover
//! continuous input spaces for inflate round-trips, delta copy operations,
//! and delta add instructions. Specific unit tests serve as documentation
//! anchors and error-path coverage.

use super::*;
use crate::delta_test_helpers::{
    make_add_delta, make_copy_delta, push_varint, push_varint_u64, zlib_compress,
    SyntheticPackBuilder,
};
use crate::object_id::OidBytes;

use proptest::prelude::*;

const PROPTEST_CASES: u32 = 256;

// ── Property-based tests ───────────────────────────────────────────────

/// Strategy producing `(base, offset, size)` triples where the copy range is
/// always valid: `0 <= offset`, `1 <= size`, `offset + size <= base.len()`.
fn base_with_slice_range() -> impl Strategy<Value = (Vec<u8>, usize, usize)> {
    prop::collection::vec(any::<u8>(), 1..512usize)
        .prop_flat_map(|base| {
            let n = base.len();
            (Just(base), 0..n)
        })
        .prop_flat_map(|(base, off)| {
            let remaining = base.len() - off;
            (Just(base), Just(off), 1..=remaining)
        })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(PROPTEST_CASES))]

    /// inflate(compress(data)) == data for arbitrary byte sequences 0..4096.
    ///
    /// Subsumes the specific round-trip tests for basic data, exact-max-out,
    /// and empty data. The `max_out` is set to the uncompressed length, which
    /// is the tightest valid bound.
    #[test]
    fn inflate_roundtrip(data in prop::collection::vec(any::<u8>(), 0..4096)) {
        let compressed = zlib_compress(&data);
        let mut de = flate2::Decompress::new(true);
        let mut out = Vec::new();
        let consumed = inflate_limited_with(&mut de, &compressed, &mut out, data.len())
            .expect("inflate roundtrip");
        prop_assert_eq!(consumed, compressed.len());
        prop_assert_eq!(out, data);
    }

    /// A copy-from-base delta always reproduces `base[off..off+size]`.
    ///
    /// Subsumes the specific full-copy and partial-copy tests with continuous
    /// coverage over random bases and valid (offset, size) ranges.
    #[test]
    fn apply_delta_copy_preserves_slice(
        (base, off, size) in base_with_slice_range(),
    ) {
        let delta = make_copy_delta(base.len(), off, size);
        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, size).expect("copy slice");
        prop_assert_eq!(&out[..], &base[off..off + size]);
    }

    /// An add-literal delta always outputs the literal bytes unchanged.
    ///
    /// The `make_add_delta` helper caps literal length at 127 (single-byte
    /// add instruction), so the strategy range matches.
    #[test]
    fn apply_delta_add_roundtrip(
        literal in prop::collection::vec(any::<u8>(), 1..=127usize),
    ) {
        let base = vec![0u8; literal.len()];
        let delta = make_add_delta(base.len(), &literal);
        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, 1024).expect("add literal");
        prop_assert_eq!(out, literal);
    }
}

// ── decode_copy_params ─────────────────────────────────────────────────

#[test]
fn decode_copy_params_reads_all_selected_fields() {
    let delta = [0x11_u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let cmd = 0x80 | 0x01 | 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40;
    let mut pos = 0_usize;
    let (off, size) = decode_copy_params(&delta, &mut pos, cmd).expect("decode copy params");
    assert_eq!(off, 0x4433_2211);
    assert_eq!(size, 0x0077_6655);
    assert_eq!(pos, delta.len());
}

#[test]
fn decode_copy_params_zero_size_expands_to_64k() {
    let delta = [0x2a_u8];
    let cmd = 0x80 | 0x01; // copy with 1-byte offset, implicit 64 KiB size
    let mut pos = 0_usize;
    let (off, size) = decode_copy_params(&delta, &mut pos, cmd).expect("decode copy params");
    assert_eq!(off, 0x2a);
    assert_eq!(size, 0x1_0000);
    assert_eq!(pos, 1);
}

#[test]
fn decode_copy_params_truncated_when_flagged_bytes_missing() {
    let delta = [0xaa_u8, 0xbb];
    let cmd = 0x80 | 0x01 | 0x02 | 0x10;
    let mut pos = 0_usize;
    let err = decode_copy_params(&delta, &mut pos, cmd).expect_err("expected truncation");
    assert_eq!(err, DeltaError::Truncated);
    assert_eq!(
        pos,
        delta.len(),
        "position should match legacy truncation behavior"
    );
}

/// Exhaustive test covering all 128 (off_mask x size_mask) combinations.
///
/// For each combination we build a delta payload with known byte values
/// and verify decode_copy_params produces the expected offset and size.
#[test]
fn decode_copy_params_all_128_mask_combos() {
    // off_mask: 4 bits (0..16), size_mask: 3 bits (0..8) -> 128 combos.
    for off_mask in 0u8..16 {
        for size_mask in 0u8..8 {
            let cmd = 0x80 | off_mask | (size_mask << 4);
            let needed = (off_mask.count_ones() + size_mask.count_ones()) as usize;

            // Build payload: byte values 0x10, 0x20, 0x30, ... so each is distinct.
            let payload: Vec<u8> = (0..needed).map(|i| ((i as u8) + 1) * 0x10).collect();

            let mut pos = 0usize;
            let (off, size) = decode_copy_params(&payload, &mut pos, cmd)
                .unwrap_or_else(|_| panic!("off_mask={off_mask:#x} size_mask={size_mask:#x}"));
            assert_eq!(
                pos, needed,
                "pos mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
            );

            // Reconstruct expected offset.
            let mut expected_off: usize = 0;
            let mut idx = 0;
            if (off_mask & 0x01) != 0 {
                expected_off |= payload[idx] as usize;
                idx += 1;
            }
            if (off_mask & 0x02) != 0 {
                expected_off |= (payload[idx] as usize) << 8;
                idx += 1;
            }
            if (off_mask & 0x04) != 0 {
                expected_off |= (payload[idx] as usize) << 16;
                idx += 1;
            }
            if (off_mask & 0x08) != 0 {
                expected_off |= (payload[idx] as usize) << 24;
                idx += 1;
            }
            assert_eq!(
                off, expected_off,
                "off mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
            );

            // Reconstruct expected size.
            let mut expected_size: usize = 0;
            if (size_mask & 0x01) != 0 {
                expected_size |= payload[idx] as usize;
                idx += 1;
            }
            if (size_mask & 0x02) != 0 {
                expected_size |= (payload[idx] as usize) << 8;
                idx += 1;
            }
            if (size_mask & 0x04) != 0 {
                expected_size |= (payload[idx] as usize) << 16;
                idx += 1;
            }
            if expected_size == 0 {
                expected_size = 0x10000;
            }
            assert_eq!(
                size, expected_size,
                "size mismatch for off_mask={off_mask:#x} size_mask={size_mask:#x}"
            );
            let _ = idx; // suppress unused warning
        }
    }
}

// ── apply_delta: happy paths ───────────────────────────────────────────

/// Anchor: simplest delta usage — full copy reproduces the base.
#[test]
fn apply_delta_copy_instruction() {
    let base = b"Hello, World!";
    // Copy entire base
    let delta = make_copy_delta(base.len(), 0, base.len());

    let mut out = Vec::new();
    apply_delta(base, &delta, &mut out, 1024).expect("apply_delta copy");
    assert_eq!(out, base);
}

#[test]
fn apply_delta_mixed_copy_and_add() {
    let base = b"ABCDEFGHIJ";
    let mut delta = Vec::new();
    // Header: base_size=10, result_size=9 ("ABCDE" + "XYZ" + "J")
    push_varint(10, &mut delta);
    push_varint(9, &mut delta);
    // Copy 5 bytes from offset 0 ("ABCDE")
    delta.push(0x80 | 0x01 | 0x10); // copy, 1-byte offset, 1-byte size
    delta.push(0x00); // offset = 0
    delta.push(0x05); // size = 5
                      // Add 3 literal bytes ("XYZ")
    delta.push(0x03);
    delta.extend_from_slice(b"XYZ");
    // Copy 1 byte from offset 9 ("J")
    delta.push(0x80 | 0x01 | 0x10); // copy
    delta.push(0x09); // offset = 9
    delta.push(0x01); // size = 1

    let mut out = Vec::new();
    apply_delta(base, &delta, &mut out, 1024).expect("apply_delta mixed");
    assert_eq!(&out, b"ABCDEXYZJ");
}

#[test]
fn apply_delta_empty_delta_body() {
    // Delta with base_size=0, result_size=0, and no instructions.
    let base: &[u8] = &[];
    let mut delta = Vec::new();
    push_varint(0, &mut delta);
    push_varint(0, &mut delta);

    let mut out = Vec::new();
    apply_delta(base, &delta, &mut out, 1024).expect("empty delta");
    assert!(out.is_empty());
}

#[test]
fn apply_delta_output_reuses_vec() {
    // Verify out is cleared and old contents don't leak.
    let base = b"ABCD";
    let delta = make_copy_delta(4, 0, 4);

    let mut out = Vec::from("leftover garbage data that should be cleared");
    apply_delta(base, &delta, &mut out, 1024).expect("reuse vec");
    assert_eq!(&out, b"ABCD");
}

// ── apply_delta: error paths ───────────────────────────────────────────

#[test]
fn apply_delta_base_size_mismatch() {
    let base = b"short";
    let mut delta = Vec::new();
    push_varint(100, &mut delta); // claims base is 100 bytes
    push_varint(5, &mut delta);

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
    assert_eq!(err, DeltaError::BaseSizeMismatch);
}

#[test]
fn apply_delta_rejects_base_size_truncation_candidate() {
    // 2^32 would truncate to 0 on 32-bit if converted with `as usize`.
    let mut delta = Vec::new();
    push_varint_u64(u64::from(u32::MAX) + 1, &mut delta);
    push_varint(0, &mut delta);

    let mut out = Vec::new();
    let err = apply_delta(&[], &delta, &mut out, 0).unwrap_err();
    assert_eq!(err, DeltaError::BaseSizeMismatch);
}

#[test]
fn apply_delta_rejects_result_size_truncation_candidate() {
    // 2^32 would truncate to 0 on 32-bit if converted with `as usize`.
    let mut delta = Vec::new();
    push_varint(0, &mut delta);
    push_varint_u64(u64::from(u32::MAX) + 1, &mut delta);

    let mut out = Vec::new();
    let err = apply_delta(&[], &delta, &mut out, 0).unwrap_err();
    assert_eq!(err, DeltaError::OutputOverrun);
}

#[test]
fn delta_sizes_checks_result_size_usize_conversion() {
    let mut delta = Vec::new();
    push_varint(0, &mut delta);
    let large = u64::from(u32::MAX) + 1;
    push_varint_u64(large, &mut delta);

    let parsed = delta_sizes(&delta);
    if usize::BITS == 32 {
        assert_eq!(parsed.unwrap_err(), DeltaError::OutputOverrun);
    } else {
        assert_eq!(
            parsed.unwrap(),
            (
                0,
                usize::try_from(large).expect("value must fit on non-32-bit targets")
            )
        );
    }
}

#[test]
fn apply_delta_result_exceeds_max_out() {
    let base = b"base";
    let mut delta = Vec::new();
    push_varint(4, &mut delta);
    push_varint(1000, &mut delta); // result_size 1000

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 100).unwrap_err(); // max_out 100
    assert_eq!(err, DeltaError::OutputOverrun);
}

#[test]
fn apply_delta_bad_command_zero() {
    let base = b"data";
    let mut delta = Vec::new();
    push_varint(4, &mut delta);
    push_varint(4, &mut delta);
    delta.push(0x00); // command zero is invalid

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
    assert_eq!(err, DeltaError::BadCommandZero);
}

#[test]
fn apply_delta_copy_out_of_range() {
    let base = b"short";
    let mut delta = Vec::new();
    push_varint(5, &mut delta);
    push_varint(10, &mut delta);
    // Copy 10 bytes from offset 0, but base is only 5 bytes
    delta.push(0x80 | 0x01 | 0x10);
    delta.push(0x00); // offset 0
    delta.push(0x0a); // size 10

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
    assert_eq!(err, DeltaError::CopyOutOfRange);
}

#[test]
fn apply_delta_truncated_add() {
    let base = b"data";
    let mut delta = Vec::new();
    push_varint(4, &mut delta);
    push_varint(5, &mut delta);
    delta.push(0x05); // add 5 bytes, but supply none

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
    assert_eq!(err, DeltaError::Truncated);
}

#[test]
fn apply_delta_result_size_mismatch() {
    let base = b"ABCDEFGHIJ";
    let mut delta = Vec::new();
    push_varint(10, &mut delta);
    push_varint(10, &mut delta); // promises 10 bytes
                                 // But only copy 5
    delta.push(0x80 | 0x01 | 0x10);
    delta.push(0x00);
    delta.push(0x05);

    let mut out = Vec::new();
    let err = apply_delta(base, &delta, &mut out, 1024).unwrap_err();
    assert_eq!(err, DeltaError::ResultSizeMismatch);
}

// ── apply_delta_into ───────────────────────────────────────────────────

#[test]
fn apply_delta_into_copy_zero_size_round_trip() {
    let base = vec![0xa5_u8; 0x1_0000];
    let mut delta = Vec::new();
    push_varint(base.len(), &mut delta);
    push_varint(base.len(), &mut delta);
    delta.push(0x80); // copy from offset 0, implicit 64 KiB

    let mut out = Vec::new();
    let written = apply_delta_into(&base, &delta, base.len(), |chunk| {
        out.extend_from_slice(chunk);
        Ok(())
    })
    .expect("apply delta");

    assert_eq!(written, base.len());
    assert_eq!(out, base);
}

// ── inflate_limited_with ───────────────────────────────────────────────

/// Anchor: simplest inflate round-trip (documents basic usage).
#[test]
fn inflate_limited_with_basic_round_trip() {
    let original = b"Hello, this is test data for inflate_limited_with!";
    let compressed = zlib_compress(original);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let consumed =
        inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate basic");

    assert_eq!(consumed, compressed.len());
    assert_eq!(&out, original);
}

#[test]
fn inflate_limited_with_exceeds_max_out() {
    // Data decompresses to 256 bytes but max_out is 100.
    let original = vec![0xCD_u8; 256];
    let compressed = zlib_compress(&original);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let err = inflate_limited_with(&mut de, &compressed, &mut out, 100).unwrap_err();

    assert_eq!(err, InflateError::LimitExceeded);
    // Partial output may have been written, but it must not exceed max_out.
    assert!(out.len() <= 100);
}

#[test]
fn inflate_limited_with_empty_input() {
    // Empty compressed data is not valid zlib — should error.
    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let result = inflate_limited_with(&mut de, &[], &mut out, 1024);

    assert!(result.is_err());
}

#[test]
fn inflate_limited_with_corrupt_input() {
    // Garbage bytes are not valid zlib.
    let garbage = [0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA];
    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let result = inflate_limited_with(&mut de, &garbage, &mut out, 1024);

    assert!(result.is_err());
}

#[test]
fn inflate_limited_with_reuses_decompress() {
    // Call inflate_limited_with twice with the same Decompress instance.
    // The function should reset internally.
    let original1 = b"First payload";
    let original2 = b"Second payload, slightly different";
    let compressed1 = zlib_compress(original1);
    let compressed2 = zlib_compress(original2);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();

    inflate_limited_with(&mut de, &compressed1, &mut out, 1024).expect("inflate first");
    assert_eq!(&out, original1);

    inflate_limited_with(&mut de, &compressed2, &mut out, 1024).expect("inflate second");
    assert_eq!(&out, original2.as_slice());
}

#[test]
fn inflate_limited_with_zero_max_out_allows_empty_stream() {
    let compressed = zlib_compress(&[]);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let consumed = inflate_limited_with(&mut de, &compressed, &mut out, 0).expect("inflate empty");

    assert_eq!(consumed, compressed.len());
    assert!(out.is_empty());
}

#[test]
fn inflate_limited_with_zero_max_out_rejects_non_empty_stream() {
    let compressed = zlib_compress(b"non-empty output");

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let err = inflate_limited_with(&mut de, &compressed, &mut out, 0).unwrap_err();

    assert_eq!(err, InflateError::LimitExceeded);
    assert!(out.is_empty());
}

#[test]
fn inflate_limited_with_zero_max_out_header_only_zlib_is_truncated() {
    // Bare zlib header without any deflate block or trailer.
    let malformed = b"\x78\x01";

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let err = inflate_limited_with(&mut de, malformed, &mut out, 0).unwrap_err();

    assert_eq!(err, InflateError::TruncatedInput);
    assert!(out.is_empty());
}

#[test]
fn inflate_limited_with_clears_existing_output() {
    // out has stale data; inflate_limited_with should clear it.
    let original = b"fresh output";
    let compressed = zlib_compress(original);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::from("stale garbage that should be cleared");
    inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate clear");
    assert_eq!(&out, original);
}

// ── inflate_stream ─────────────────────────────────────────────────────

#[test]
fn inflate_stream_undersized_expected_always_errors() {
    // Verifies: when inflate_limited produces `exact` bytes, calling
    // inflate_stream with expected = exact - 1 must return an error.
    let original = b"test data for under-size check";
    let compressed = zlib_compress(original);

    // Step 1: establish the true output length via inflate_limited.
    let mut limited_out = Vec::new();
    inflate_limited(&compressed, &mut limited_out, 1024).expect("inflate_limited");
    let exact = limited_out.len();
    assert!(exact > 0);

    // Step 2: inflate_stream with exact - 1 must fail.
    let mut under_out = Vec::new();
    let result = inflate_stream(&compressed, exact - 1, |chunk| {
        under_out.extend_from_slice(chunk);
        Ok(())
    });
    assert!(
        result.is_err(),
        "inflate_stream(expected={}) should fail when data decompresses to {} bytes",
        exact - 1,
        exact,
    );
}

// ── Pack header / entry parsing ────────────────────────────────────────

#[test]
fn ref_delta_entry_header_parses_oid() {
    let base_data = b"hello base";
    let delta_data = make_add_delta(base_data.len(), b"XY");

    let base_oid = OidBytes::try_from_slice(&[0xAB; 20]).unwrap();

    let mut builder = SyntheticPackBuilder::new();
    builder.add_non_delta(3, base_data);
    let ref_idx = builder.add_ref_delta(base_oid, &delta_data);

    let (pack, offsets) = builder.build();
    let pf = PackFile::parse(&pack, 20).expect("parse pack");

    let header = pf
        .entry_header_at(offsets[ref_idx], 64)
        .expect("parse ref delta header");

    assert_eq!(
        header.kind,
        EntryKind::RefDelta { base_oid },
        "should parse REF_DELTA with correct base OID"
    );
    assert_eq!(header.size, delta_data.len() as u64);
    // data_start must point past the 20-byte OID to the compressed
    // delta payload.
    let slice = pf.slice_from(header.data_start);
    assert!(
        !slice.is_empty(),
        "data_start should point to compressed delta bytes"
    );
}

// ── Safety / Miri targets ──────────────────────────────────────────────

/// Miri target: exercises inflate_limited_with spare-capacity write + set_len.
#[test]
fn inflate_limited_with_miri_roundtrip() {
    use flate2::write::ZlibEncoder;
    use flate2::Compression;
    use std::io::Write;

    let original = b"hello miri roundtrip test data";
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::fast());
    encoder.write_all(original).unwrap();
    let compressed = encoder.finish().unwrap();

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let consumed = inflate_limited_with(&mut de, &compressed, &mut out, 256).unwrap();
    assert_eq!(out, original);
    assert_eq!(consumed, compressed.len());
}

/// Miri target: exercises apply_delta raw-pointer copy and insert paths.
#[test]
fn apply_delta_miri_copy_and_insert() {
    let base = b"ABCDEFGHIJ";
    // Delta: base_size=10, result_size=8, copy 4 bytes from off=2, insert 4 literal bytes.
    let delta: &[u8] = &[
        10, // base_size varint
        8,  // result_size varint
        0x80 | 0x01 | 0x10,
        2,
        4, // copy: off=2, size=4 -> "CDEF"
        4,
        b'X',
        b'Y',
        b'Z',
        b'W', // insert 4 bytes -> "XYZW"
    ];
    let mut out = Vec::new();
    apply_delta(base, delta, &mut out, 64).unwrap();
    assert_eq!(&out, b"CDEFXYZW");
}

#[test]
fn poison_spare_capacity_writes_debug_pattern() {
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(b"hello");
    super::poison_spare_capacity(&mut buf);

    // The logical content must be unchanged.
    assert_eq!(&buf[..5], b"hello");
    assert_eq!(buf.len(), 5);

    // In debug builds, spare bytes should be 0xDE.
    // In release builds, poison_spare_capacity is a no-op, so the spare
    // region is uninitialized — reading it would be UB.
    #[cfg(debug_assertions)]
    {
        let spare = buf.spare_capacity_mut();
        for (i, slot) in spare.iter().enumerate() {
            // SAFETY: we just wrote 0xDE to every spare slot in debug mode.
            let val = unsafe { slot.assume_init() };
            assert_eq!(val, 0xDE, "spare byte {i} not poisoned");
        }
    }
}

#[test]
fn inflate_with_poison_round_trip() {
    // Verify that poisoning spare capacity does not break inflate.
    let original = b"inflate with poison test payload data";
    let compressed = zlib_compress(original);

    let mut de = flate2::Decompress::new(true);
    let mut out = Vec::new();
    let consumed =
        inflate_limited_with(&mut de, &compressed, &mut out, 1024).expect("inflate with poison");

    assert_eq!(consumed, compressed.len());
    assert_eq!(&out[..], original.as_slice());
}

#[test]
fn apply_delta_with_poison_round_trip() {
    // Verify that poisoning spare capacity does not break delta application.
    let base = b"ABCDEFGHIJ";
    let delta = make_copy_delta(base.len(), 0, base.len());

    let mut out = Vec::new();
    apply_delta(base, &delta, &mut out, 1024).expect("apply delta with poison");
    assert_eq!(&out[..], base.as_slice());
    // Mixed copy+add delta is already exercised by
    // `apply_delta_mixed_copy_and_add`; no need to duplicate it here.
}
