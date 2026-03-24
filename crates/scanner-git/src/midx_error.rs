//! Error types for multi-pack index parsing and lookup.
//!
//! These errors cover MIDX parsing, validation, and lookup failures.
//! Variants signal that the MIDX file or its inputs are inconsistent
//! with the Git MIDX format.

use std::fmt;

/// A 4-byte MIDX chunk identifier with human-readable Display.
///
/// Prints as ASCII when all bytes are graphic (non-space printable), otherwise as hex.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ChunkId(pub [u8; 4]);

impl ChunkId {
    /// Creates a ChunkId from a 4-byte array.
    #[inline]
    pub const fn new(bytes: [u8; 4]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.iter().all(|&b| b.is_ascii_graphic()) {
            for &b in &self.0 {
                write!(f, "{}", b as char)?;
            }
            Ok(())
        } else {
            write!(
                f,
                "[{:02x}, {:02x}, {:02x}, {:02x}]",
                self.0[0], self.0[1], self.0[2], self.0[3]
            )
        }
    }
}

impl fmt::Debug for ChunkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ChunkId({})", self)
    }
}

/// Maximum number of missing pack names stored in `MidxIncomplete`.
const MAX_MISSING_PACK_NAMES: usize = 10;

/// Errors from MIDX parsing and lookup.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MidxError {
    /// MIDX file is corrupt or malformed.
    #[error("corrupt MIDX: {detail}")]
    MidxCorrupt { detail: &'static str },
    /// MIDX version is not supported.
    #[error("unsupported MIDX version: {version} (expected 1)")]
    UnsupportedMidxVersion { version: u8 },
    /// MIDX hash version doesn't match repository format.
    #[error(
        "MIDX hash version mismatch: MIDX uses {midx_oid_len}-byte OIDs, repo uses {repo_oid_len}"
    )]
    OidLengthMismatch { midx_oid_len: u8, repo_oid_len: u8 },
    /// Input OID has wrong length for the configured MIDX format.
    #[error("input OID length {got} doesn't match MIDX OID length {expected}")]
    InputOidLengthMismatch { got: u8, expected: u8 },
    /// MIDX doesn't reference all pack files.
    #[error("MIDX incomplete: {missing_count} pack(s) not in MIDX (sample: {missing_packs:?})")]
    MidxIncomplete {
        missing_count: usize,
        /// Sample of missing pack basenames (bounded by `MAX_MISSING_PACK_NAMES`).
        missing_packs: Vec<String>,
    },
    /// Required MIDX chunk is missing.
    #[error("MIDX missing required chunk: {chunk_id}")]
    MissingChunk { chunk_id: ChunkId },
    /// Duplicate MIDX chunk ID found.
    #[error("MIDX has duplicate chunk: {chunk_id}")]
    DuplicateChunk { chunk_id: ChunkId },
    /// MIDX chunk has invalid size.
    #[error("MIDX chunk {chunk_id} has invalid size: {actual} (expected {expected})")]
    InvalidChunkSize {
        chunk_id: ChunkId,
        actual: u64,
        expected: u64,
    },
    /// MIDX file exceeds size limit.
    #[error("MIDX too large: {size} bytes (max: {max})")]
    MidxTooLarge { size: u64, max: u64 },
    /// MIDX PNAM chunk has wrong number of pack names.
    #[error("MIDX PNAM pack count mismatch: found {found} names, header says {expected}")]
    PnamCountMismatch { found: u32, expected: u32 },
    /// Pack count exceeds u16 limit.
    #[error("too many packs: {count} (tool max: 65535)")]
    PackCountOverflow { count: u32 },
    /// Pack position in OOFF entry is out of bounds.
    #[error("OOFF pack_pos out of bounds: {pack_pos} >= pack_count {pack_count}")]
    PackPosOutOfBounds { pack_pos: u32, pack_count: u32 },
    /// LOFF index out of bounds.
    #[error("LOFF index out of bounds: {index} >= {count}")]
    LoffIndexOutOfBounds { index: u32, count: u32 },
    /// Input OIDs are not strictly sorted.
    ///
    /// Used when validating sorted OID streams (for example, during
    /// sorted-input validation in MIDX building or mapping bridge).
    #[error("input OIDs not strictly sorted")]
    InputNotSorted,
    /// Duplicate input OID.
    ///
    /// Used when validating de-duplication requirements for input streams.
    #[error("duplicate input OID")]
    DuplicateInputOid,
}

impl MidxError {
    /// Constructs a corruption error with a static detail string.
    #[inline]
    pub const fn corrupt(detail: &'static str) -> Self {
        Self::MidxCorrupt { detail }
    }

    /// Constructs a `MidxIncomplete` error. Callers should bound `missing_packs`
    /// to [`missing_packs_limit()`] entries.
    pub fn midx_incomplete(missing_count: usize, missing_packs: Vec<String>) -> Self {
        Self::MidxIncomplete {
            missing_count,
            missing_packs,
        }
    }

    /// Returns the maximum number of missing pack names recorded for diagnostics.
    pub fn missing_packs_limit() -> usize {
        MAX_MISSING_PACK_NAMES
    }
}
