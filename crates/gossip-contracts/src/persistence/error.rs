//! Validation errors for persistence-boundary value types.
//!
//! Defines the errors that can occur when converting or validating data that
//! crosses the persistence boundary, ensuring that only well-formed data enters
//! the storage layer.

use crate::identity::ObservationId;

use super::done_ledger::DoneLedgerKey;

/// Validation errors for persistence-boundary value types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PersistenceInputError {
    /// A bounded string field was empty.
    #[error("{field} must not be empty")]
    Empty {
        /// The name of the field that was empty.
        field: &'static str,
    },
    /// A bounded field exceeded its maximum size.
    #[error("{field} too large ({size} bytes, max {max})")]
    TooLarge {
        /// The name of the field.
        field: &'static str,
        /// The actual size of the field.
        size: usize,
        /// The maximum allowed size.
        max: usize,
    },
    /// A supposedly safe code contained a disallowed byte.
    #[error("{field} contains invalid byte 0x{byte:02X} at index {index}")]
    InvalidByte {
        /// The name of the field.
        field: &'static str,
        /// The index of the invalid byte.
        index: usize,
        /// The invalid byte value.
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
        /// The expected derived observation ID.
        expected: ObservationId,
        /// The actual observation ID provided.
        actual: ObservationId,
    },
    /// `findings_count` contradicts `DoneLedgerStatus`.
    ///
    /// `ScannedWithFindings` requires `findings_count > 0` and
    /// `ScannedClean` requires `findings_count == 0`.
    #[error("findings_count {findings_count} is inconsistent with status {status}")]
    InconsistentFindingsCount {
        /// The status that contradicts the findings count.
        status: &'static str,
        /// The invalid findings count.
        findings_count: u32,
    },
    /// A failure or skip status requires an error code, but none was provided.
    #[error("status {status} requires an error code, but none was provided")]
    MissingErrorCode {
        /// The status that requires an error code.
        status: &'static str,
    },
    /// A scanned (success) status must not carry an error code.
    #[error("status {status} must not carry an error code")]
    UnexpectedErrorCode {
        /// The status that unexpected carried an error code.
        status: &'static str,
    },
    /// A child record references a parent that does not exist in the batch.
    #[error("{child_type} references a {parent_type} not present in the batch")]
    OrphanedReference {
        /// The type of the child record.
        child_type: &'static str,
        /// The type of the parent record.
        parent_type: &'static str,
    },
    /// Records in the batch belong to different tenants.
    #[error("records in the batch belong to different tenants")]
    InconsistentTenant,
    /// Provenance timestamps are out of order (`started_at > finished_at`).
    #[error("provenance started_at ({started_at}) must not exceed finished_at ({finished_at})")]
    ProvenanceOrdering {
        /// The started_at timestamp.
        started_at: u64,
        /// The finished_at timestamp.
        finished_at: u64,
    },
    /// Two records with different keys were passed to a merge operation.
    #[error(
        "merge requires records with the same key (existing: {existing:?}, incoming: {incoming:?})"
    )]
    KeyMismatch {
        /// The key of the existing record.
        existing: Box<DoneLedgerKey>,
        /// The key of the incoming record.
        incoming: Box<DoneLedgerKey>,
    },
}
