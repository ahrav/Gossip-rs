use crate::identity::ObservationId;

use super::done_ledger::DoneLedgerKey;

/// Validation errors for persistence-boundary value types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistenceInputError {
    /// A bounded string field was empty.
    #[error("{field} must not be empty")]
    Empty { field: &'static str },
    /// A bounded field exceeded its maximum size.
    #[error("{field} too large ({size} bytes, max {max})")]
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    /// A supposedly safe code contained a disallowed byte.
    #[error("{field} contains invalid byte 0x{byte:02X} at index {index}")]
    InvalidByte {
        field: &'static str,
        index: usize,
        byte: u8,
    },
    /// Occurrence span length must be non-zero.
    #[error("OccurrenceRecord.byte_length must be non-zero")]
    ZeroSpanLength,
    /// A provided observation id does not match the canonical derived value.
    #[error(
        "observation_id does not match canonical derivation (expected {expected:?}, got {actual:?})"
    )]
    ObservationIdMismatch {
        expected: ObservationId,
        actual: ObservationId,
    },
    /// `findings_count` contradicts `DoneLedgerStatus`.
    ///
    /// `ScannedWithFindings` requires `findings_count > 0` and
    /// `ScannedClean` requires `findings_count == 0`.
    #[error("findings_count {findings_count} is inconsistent with status {status}")]
    InconsistentFindingsCount {
        status: &'static str,
        findings_count: u32,
    },
    /// A failure or skip status requires an error code, but none was provided.
    #[error("status {status} requires an error code, but none was provided")]
    MissingErrorCode { status: &'static str },
    /// A scanned (success) status must not carry an error code.
    #[error("status {status} must not carry an error code")]
    UnexpectedErrorCode { status: &'static str },
    /// A child record references a parent that does not exist in the batch.
    #[error("{child_type} references a {parent_type} not present in the batch")]
    OrphanedReference {
        child_type: &'static str,
        parent_type: &'static str,
    },
    /// Records in the batch belong to different tenants.
    #[error("records in the batch belong to different tenants")]
    InconsistentTenant,
    /// Provenance timestamps are out of order (`started_at > finished_at`).
    #[error("provenance started_at ({started_at}) must not exceed finished_at ({finished_at})")]
    ProvenanceOrdering { started_at: u64, finished_at: u64 },
    /// Two records with different keys were passed to a merge operation.
    #[error(
        "merge requires records with the same key (existing: {existing:?}, incoming: {incoming:?})"
    )]
    KeyMismatch {
        existing: Box<DoneLedgerKey>,
        incoming: Box<DoneLedgerKey>,
    },
}
