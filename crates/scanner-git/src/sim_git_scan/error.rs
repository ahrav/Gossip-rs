//! Shared error types for Git simulation adapters.

use std::fmt;

/// Errors produced while adapting the Git simulation model.
#[derive(Debug)]
pub enum SimGitError {
    /// OID length does not match the declared object format.
    InvalidOidLength { expected: usize, got: usize },
    /// Duplicate object ID encountered while building a map.
    DuplicateOid { kind: &'static str },
    /// Required object was missing from the model.
    MissingObject { kind: &'static str },
    /// Pack bytes were missing for a pack id.
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Duplicate pack id encountered while assembling pack bytes.
    DuplicatePackId { pack_id: u16 },
    /// Pack count mismatch between metadata and bytes.
    PackCountMismatch { expected: usize, actual: usize },
    /// MIDX parse failed.
    Midx(String),
}

impl fmt::Display for SimGitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOidLength { expected, got } => {
                write!(f, "invalid OID length {got} (expected {expected})")
            }
            Self::DuplicateOid { kind } => write!(f, "duplicate {kind} OID"),
            Self::MissingObject { kind } => write!(f, "missing {kind} object"),
            Self::PackIdOutOfRange {
                pack_id,
                pack_count,
            } => {
                write!(f, "pack id {pack_id} out of range (count {pack_count})")
            }
            Self::DuplicatePackId { pack_id } => {
                write!(f, "duplicate pack id {pack_id}")
            }
            Self::PackCountMismatch { expected, actual } => {
                write!(f, "pack count mismatch: expected {expected}, got {actual}")
            }
            Self::Midx(msg) => write!(f, "midx error: {msg}"),
        }
    }
}

impl std::error::Error for SimGitError {}
