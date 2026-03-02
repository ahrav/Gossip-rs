//! Regression tests for pathological zlib variants in pack files.
//!
//! Each test loads a synthetic `.pack` file from the regression corpus,
//! parses the entry header, and inflates (or attempts to inflate) the
//! zlib payload. The expected behavior is verified against the known
//! properties of each pathological variant.
//!
//! Corpus regeneration: `python3 scripts/gen_git_pack_corpus.py`

use scanner_git::pack_inflate::{InflateError, PackFile, inflate_limited};

/// OID length for SHA-1 packs used by the corpus generator.
const OID_LEN: usize = 20;

/// First entry offset (immediately after the 12-byte pack header).
const FIRST_ENTRY_OFFSET: u64 = 12;

/// Safety bound for entry header parsing.
const MAX_HEADER_BYTES: usize = 64;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Parse a pack file from raw bytes, panicking on failure.
fn load_pack(bytes: &[u8]) -> PackFile<'_> {
    PackFile::parse(bytes, OID_LEN).expect("regression pack should parse")
}

// ---------------------------------------------------------------------------
// Valid packs: inflate must succeed and produce the expected output
// ---------------------------------------------------------------------------

/// A minimal blob containing a single byte (`X`) compressed with zlib.
///
/// Verifies that the inflate path handles very short literal runs correctly
/// and produces exactly the declared payload.
#[test]
fn tiny_zlib_block_inflates_single_byte() {
    static PACK: &[u8] = include_bytes!("../regression/git_packs/tiny_zlib_block.pack");
    let pack = load_pack(PACK);

    let header = pack
        .entry_header_at(FIRST_ENTRY_OFFSET, MAX_HEADER_BYTES)
        .expect("entry header");
    assert_eq!(header.size, 1, "declared size should be 1 byte");

    let zlib_input = pack.slice_from(header.data_start);
    let mut out = Vec::with_capacity(header.size as usize);
    let consumed = inflate_limited(zlib_input, &mut out, header.size as usize)
        .expect("inflate should succeed");

    assert_eq!(out, b"X", "decompressed payload should be a single 'X'");
    assert!(consumed > 0, "should consume at least some input bytes");
}

/// A blob whose zlib stream is followed by a second concatenated zlib stream.
///
/// `inflate_limited` should stop at `StreamEnd` of the first stream and
/// return the correct decompressed payload (`ABCD`). The trailing second
/// stream is ignored.
#[test]
fn concat_zlib_streams_stops_at_first_stream_end() {
    static PACK: &[u8] = include_bytes!("../regression/git_packs/concat_zlib_streams.pack");
    let pack = load_pack(PACK);

    let header = pack
        .entry_header_at(FIRST_ENTRY_OFFSET, MAX_HEADER_BYTES)
        .expect("entry header");
    assert_eq!(
        header.size, 4,
        "declared size should match first block (ABCD)"
    );

    let zlib_input = pack.slice_from(header.data_start);
    let mut out = Vec::with_capacity(header.size as usize);
    let consumed = inflate_limited(zlib_input, &mut out, header.size as usize)
        .expect("inflate should succeed");

    assert_eq!(out, b"ABCD", "should decompress only the first stream");
    // The consumed bytes should be less than the full zlib region because the
    // second concatenated stream is left untouched.
    assert!(
        consumed < zlib_input.len(),
        "consumed ({consumed}) should be less than total zlib region ({})",
        zlib_input.len()
    );
}

/// A blob whose decompressed size is exactly 1024 bytes (a power-of-two
/// boundary that might trip buffer management).
///
/// Verifies correct inflate at a common boundary size.
#[test]
fn zlib_output_cap_1024_inflates_exact_boundary() {
    static PACK: &[u8] = include_bytes!("../regression/git_packs/zlib_output_cap_1024.pack");
    let pack = load_pack(PACK);

    let header = pack
        .entry_header_at(FIRST_ENTRY_OFFSET, MAX_HEADER_BYTES)
        .expect("entry header");
    assert_eq!(header.size, 1024, "declared size should be 1024");

    let zlib_input = pack.slice_from(header.data_start);
    let mut out = Vec::with_capacity(header.size as usize);
    inflate_limited(zlib_input, &mut out, header.size as usize).expect("inflate should succeed");

    assert_eq!(out.len(), 1024, "output should be exactly 1024 bytes");
    assert!(out.iter().all(|&b| b == b'A'), "all bytes should be 'A'");
}

// ---------------------------------------------------------------------------
// Truncated packs: inflate must fail with TruncatedInput
// ---------------------------------------------------------------------------

/// A blob whose zlib stream is cut at roughly 60% of the compressed data,
/// in the middle of a deflate block.
///
/// `inflate_limited` must detect the premature end and return
/// `InflateError::TruncatedInput`.
#[test]
fn truncated_zlib_mid_block_returns_truncated_input() {
    static PACK: &[u8] = include_bytes!("../regression/git_packs/truncated_zlib_mid_block.pack");
    let pack = load_pack(PACK);

    let header = pack
        .entry_header_at(FIRST_ENTRY_OFFSET, MAX_HEADER_BYTES)
        .expect("entry header");
    // The declared size is 1300 bytes (b"Hello World! " * 100).
    assert_eq!(header.size, 1300, "declared size should be 1300");

    let zlib_input = pack.slice_from(header.data_start);
    let mut out = Vec::with_capacity(header.size as usize);
    let result = inflate_limited(zlib_input, &mut out, header.size as usize);

    assert!(
        result.is_err(),
        "inflate should fail on mid-block truncation"
    );
    assert_eq!(
        result.unwrap_err(),
        InflateError::TruncatedInput,
        "error variant should be TruncatedInput"
    );
}

// ---------------------------------------------------------------------------
// Edge case: zero-length zlib
// ---------------------------------------------------------------------------

/// A blob with declared size 0 and only a bare zlib header (`78 01`) with no
/// deflate blocks.
///
/// The inflate path should either succeed with an empty output or return an
/// error (TruncatedInput or Backend) because the zlib stream has no final
/// block. We accept any of those outcomes as valid behavior for this
/// degenerate input.
#[test]
fn zero_length_zlib_header_only() {
    static PACK: &[u8] = include_bytes!("../regression/git_packs/zero_length_zlib.pack");
    let pack = load_pack(PACK);

    let header = pack
        .entry_header_at(FIRST_ENTRY_OFFSET, MAX_HEADER_BYTES)
        .expect("entry header");
    assert_eq!(header.size, 0, "declared size should be 0");

    let zlib_input = pack.slice_from(header.data_start);
    let mut out = Vec::new();
    let result = inflate_limited(zlib_input, &mut out, 0);

    match result {
        Ok(_) => {
            assert!(
                out.is_empty(),
                "successful inflate of zero-length should produce empty output"
            );
        }
        Err(InflateError::TruncatedInput | InflateError::Backend) => {
            // Acceptable: the bare header without a final deflate block is
            // legitimately broken input.
        }
        Err(other) => {
            panic!("unexpected error variant for zero-length zlib: {other:?}");
        }
    }
}
