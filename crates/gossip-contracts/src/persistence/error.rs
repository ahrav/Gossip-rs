use std::{error::Error, fmt};

use crate::identity::ObservationId;

/// Validation errors for persistence-boundary value types.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistenceInputError {
    /// A bounded string field was empty.
    Empty { field: &'static str },
    /// A bounded field exceeded its maximum size.
    TooLarge {
        field: &'static str,
        size: usize,
        max: usize,
    },
    /// A supposedly safe code contained a disallowed byte.
    InvalidByte {
        field: &'static str,
        index: usize,
        byte: u8,
    },
    /// Occurrence span length must be non-zero.
    ZeroSpanLength,
    /// A provided observation id does not match the canonical derived value.
    ObservationIdMismatch {
        expected: ObservationId,
        actual: ObservationId,
    },
    /// `findings_count` contradicts `DoneLedgerStatus`.
    ///
    /// `ScannedWithFindings` requires `findings_count > 0` and
    /// `ScannedClean` requires `findings_count == 0`.
    InconsistentFindingsCount {
        status: &'static str,
        findings_count: u32,
    },
    /// A failure or skip status requires an error code, but none was provided.
    MissingErrorCode { status: &'static str },
    /// A scanned (success) status must not carry an error code.
    UnexpectedErrorCode { status: &'static str },
    /// A child record references a parent that does not exist in the batch.
    OrphanedReference {
        child_type: &'static str,
        parent_type: &'static str,
    },
    /// Records in the batch belong to different tenants.
    InconsistentTenant,
}

impl fmt::Display for PersistenceInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { field } => write!(f, "{field} must not be empty"),
            Self::TooLarge { field, size, max } => {
                write!(f, "{field} too large ({size} bytes, max {max})")
            }
            Self::InvalidByte { field, index, byte } => write!(
                f,
                "{field} contains invalid byte 0x{byte:02X} at index {index}"
            ),
            Self::ZeroSpanLength => write!(f, "OccurrenceRecord.byte_length must be non-zero"),
            Self::ObservationIdMismatch { expected, actual } => write!(
                f,
                "observation_id does not match canonical derivation (expected {expected:?}, got {actual:?})"
            ),
            Self::InconsistentFindingsCount {
                status,
                findings_count,
            } => write!(
                f,
                "findings_count {findings_count} is inconsistent with status {status}"
            ),
            Self::MissingErrorCode { status } => {
                write!(
                    f,
                    "status {status} requires an error code, but none was provided"
                )
            }
            Self::UnexpectedErrorCode { status } => {
                write!(f, "status {status} must not carry an error code")
            }
            Self::OrphanedReference {
                child_type,
                parent_type,
            } => write!(
                f,
                "{child_type} references a {parent_type} not present in the batch"
            ),
            Self::InconsistentTenant => {
                write!(f, "records in the batch belong to different tenants")
            }
        }
    }
}

impl Error for PersistenceInputError {}
