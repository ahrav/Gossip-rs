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
#[derive(Debug)]
#[non_exhaustive]
pub enum MidxError {
    /// MIDX file is corrupt or malformed.
    MidxCorrupt { detail: &'static str },
    /// MIDX version is not supported.
    UnsupportedMidxVersion { version: u8 },
    /// MIDX hash version doesn't match repository format.
    OidLengthMismatch { midx_oid_len: u8, repo_oid_len: u8 },
    /// Input OID has wrong length for the configured MIDX format.
    InputOidLengthMismatch { got: u8, expected: u8 },
    /// MIDX doesn't reference all pack files.
    MidxIncomplete {
        missing_count: usize,
        /// Sample of missing pack basenames (bounded by `MAX_MISSING_PACK_NAMES`).
        missing_packs: Vec<String>,
    },
    /// Required MIDX chunk is missing.
    MissingChunk { chunk_id: ChunkId },
    /// Duplicate MIDX chunk ID found.
    DuplicateChunk { chunk_id: ChunkId },
    /// MIDX chunk has invalid size.
    InvalidChunkSize {
        chunk_id: ChunkId,
        actual: u64,
        expected: u64,
    },
    /// MIDX file exceeds size limit.
    MidxTooLarge { size: u64, max: u64 },
    /// MIDX PNAM chunk has wrong number of pack names.
    PnamCountMismatch { found: u32, expected: u32 },
    /// Pack count exceeds u16 limit.
    PackCountOverflow { count: u32 },
    /// Pack position in OOFF entry is out of bounds.
    PackPosOutOfBounds { pack_pos: u32, pack_count: u32 },
    /// LOFF index out of bounds.
    LoffIndexOutOfBounds { index: u32, count: u32 },
    /// Input OIDs are not strictly sorted.
    ///
    /// Used when validating sorted OID streams (for example, during
    /// sorted-input validation in MIDX building or mapping bridge).
    InputNotSorted,
    /// Duplicate input OID.
    ///
    /// Used when validating de-duplication requirements for input streams.
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

impl fmt::Display for MidxError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MidxCorrupt { detail } => write!(f, "corrupt MIDX: {detail}"),
            Self::UnsupportedMidxVersion { version } => {
                write!(f, "unsupported MIDX version: {version} (expected 1)")
            }
            Self::OidLengthMismatch {
                midx_oid_len,
                repo_oid_len,
            } => write!(
                f,
                "MIDX hash version mismatch: MIDX uses {midx_oid_len}-byte OIDs, repo uses {repo_oid_len}"
            ),
            Self::InputOidLengthMismatch { got, expected } => {
                write!(f, "input OID length {got} doesn't match MIDX OID length {expected}")
            }
            Self::MidxIncomplete {
                missing_count,
                missing_packs,
            } => write!(
                f,
                "MIDX incomplete: {missing_count} pack(s) not in MIDX (sample: {:?})",
                missing_packs
            ),
            Self::MissingChunk { chunk_id } => {
                write!(f, "MIDX missing required chunk: {chunk_id}")
            }
            Self::DuplicateChunk { chunk_id } => {
                write!(f, "MIDX has duplicate chunk: {chunk_id}")
            }
            Self::InvalidChunkSize {
                chunk_id,
                actual,
                expected,
            } => write!(
                f,
                "MIDX chunk {chunk_id} has invalid size: {actual} (expected {expected})"
            ),
            Self::MidxTooLarge { size, max } => {
                write!(f, "MIDX too large: {size} bytes (max: {max})")
            }
            Self::PnamCountMismatch { found, expected } => write!(
                f,
                "MIDX PNAM pack count mismatch: found {found} names, header says {expected}"
            ),
            Self::PackCountOverflow { count } => {
                write!(f, "too many packs: {count} (tool max: 65535)")
            }
            Self::PackPosOutOfBounds {
                pack_pos,
                pack_count,
            } => write!(
                f,
                "OOFF pack_pos out of bounds: {pack_pos} >= pack_count {pack_count}"
            ),
            Self::LoffIndexOutOfBounds { index, count } => {
                write!(f, "LOFF index out of bounds: {index} >= {count}")
            }
            Self::InputNotSorted => write!(f, "input OIDs not strictly sorted"),
            Self::DuplicateInputOid => write!(f, "duplicate input OID"),
        }
    }
}

impl std::error::Error for MidxError {}
