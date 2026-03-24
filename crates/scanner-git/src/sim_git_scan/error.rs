//! Shared error types for Git simulation adapters.

/// Errors produced while adapting the Git simulation model.
#[derive(Debug, thiserror::Error)]
pub enum SimGitError {
    /// OID length does not match the declared object format.
    #[error("invalid OID length {got} (expected {expected})")]
    InvalidOidLength { expected: usize, got: usize },
    /// Duplicate object ID encountered while building a map.
    #[error("duplicate {kind} OID")]
    DuplicateOid { kind: &'static str },
    /// Required object was missing from the model.
    #[error("missing {kind} object")]
    MissingObject { kind: &'static str },
    /// Pack bytes were missing for a pack id.
    #[error("pack id {pack_id} out of range (count {pack_count})")]
    PackIdOutOfRange { pack_id: u16, pack_count: usize },
    /// Duplicate pack id encountered while assembling pack bytes.
    #[error("duplicate pack id {pack_id}")]
    DuplicatePackId { pack_id: u16 },
    /// Pack count mismatch between metadata and bytes.
    #[error("pack count mismatch: expected {expected}, got {actual}")]
    PackCountMismatch { expected: usize, actual: usize },
    /// MIDX parse failed.
    #[error("midx error: {0}")]
    Midx(String),
}
