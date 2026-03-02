//! Integration tests for pack trailer/checksum corruption behavior.
//!
//! The pack format ends with a SHA-1 (20-byte) or SHA-256 (32-byte) trailer
//! containing a checksum of the pack contents. Currently `PackFile::parse`
//! does **not** verify the trailer checksum -- it only requires the trailer
//! bytes to exist so that `data_end` can be computed correctly.
//!
//! These tests document that behavior: corrupt trailers are accepted while
//! truncated trailers produce `TooSmall` errors.

use scanner_git::pack_inflate::{PackFile, PackParseError};

/// Build a minimal valid pack buffer: 12-byte header + zeroed trailer.
///
/// The header encodes `PACK`, version 2, and 0 objects. The trailer is
/// `oid_len` zero bytes standing in for the checksum.
fn build_minimal_pack(oid_len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"PACK");
    buf.extend_from_slice(&2u32.to_be_bytes()); // version 2
    buf.extend_from_slice(&0u32.to_be_bytes()); // 0 objects
    buf.extend(vec![0u8; oid_len]); // zeroed trailer
    buf
}

// ---------------------------------------------------------------------------
// SHA-1 (oid_len = 20)
// ---------------------------------------------------------------------------

/// A pack with a corrupt SHA-1 trailer still parses successfully.
///
/// This documents the current behavior: `PackFile::parse` does not verify the
/// checksum bytes -- it only checks that enough bytes exist after the header
/// to account for the trailer length. Flipping every bit in the trailer has
/// no effect on parsing.
#[test]
fn corrupt_sha1_trailer_still_parses() {
    let mut pack = build_minimal_pack(20);
    assert!(
        PackFile::parse(&pack, 20).is_ok(),
        "baseline pack should parse"
    );

    // Flip every bit in the 20-byte trailer region.
    let trailer_start = pack.len() - 20;
    for byte in &mut pack[trailer_start..] {
        *byte = !*byte;
    }

    // Current behavior: parse succeeds despite corrupt checksum.
    // If checksum verification is added in the future this assertion will
    // break, signaling that these tests need to be updated.
    assert!(
        PackFile::parse(&pack, 20).is_ok(),
        "corrupt SHA-1 trailer should not cause a parse failure (no checksum verification)"
    );
}

/// A pack missing even one byte of its SHA-1 trailer triggers `TooSmall`.
///
/// The minimum pack size is 12 (header) + 20 (trailer) = 32 bytes. A buffer
/// of 31 bytes is rejected.
#[test]
fn truncated_sha1_trailer_triggers_too_small() {
    let full = build_minimal_pack(20);
    assert_eq!(full.len(), 32, "full SHA-1 pack should be 32 bytes");

    // Remove the last byte so the trailer is only 19 bytes.
    let truncated = &full[..full.len() - 1];
    assert_eq!(truncated.len(), 31);

    let err = PackFile::parse(truncated, 20).expect_err("should fail on truncated trailer");
    assert_eq!(err, PackParseError::TooSmall);
}

// ---------------------------------------------------------------------------
// SHA-256 (oid_len = 32)
// ---------------------------------------------------------------------------

/// A pack with a corrupt SHA-256 trailer still parses successfully.
///
/// Same rationale as the SHA-1 variant: no checksum verification is performed,
/// so arbitrary trailer bytes are accepted as long as the overall length is
/// sufficient.
#[test]
fn corrupt_sha256_trailer_still_parses() {
    let mut pack = build_minimal_pack(32);
    assert!(
        PackFile::parse(&pack, 32).is_ok(),
        "baseline pack should parse"
    );

    // Flip every bit in the 32-byte trailer region.
    let trailer_start = pack.len() - 32;
    for byte in &mut pack[trailer_start..] {
        *byte = !*byte;
    }

    assert!(
        PackFile::parse(&pack, 32).is_ok(),
        "corrupt SHA-256 trailer should not cause a parse failure (no checksum verification)"
    );
}

/// A pack missing even one byte of its SHA-256 trailer triggers `TooSmall`.
///
/// The minimum pack size is 12 (header) + 32 (trailer) = 44 bytes. A buffer
/// of 43 bytes is rejected.
#[test]
fn truncated_sha256_trailer_triggers_too_small() {
    let full = build_minimal_pack(32);
    assert_eq!(full.len(), 44, "full SHA-256 pack should be 44 bytes");

    // Remove the last byte so the trailer is only 31 bytes.
    let truncated = &full[..full.len() - 1];
    assert_eq!(truncated.len(), 43);

    let err = PackFile::parse(truncated, 32).expect_err("should fail on truncated trailer");
    assert_eq!(err, PackParseError::TooSmall);
}
