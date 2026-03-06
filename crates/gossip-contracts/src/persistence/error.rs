use std::{error::Error, fmt};

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
    /// `findings_count` contradicts `DoneLedgerStatus`.
    ///
    /// `ScannedWithFindings` requires `findings_count > 0` and
    /// `ScannedClean` requires `findings_count == 0`.
    InconsistentFindingsCount {
        status: &'static str,
        findings_count: u32,
    },
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
            Self::InconsistentFindingsCount {
                status,
                findings_count,
            } => write!(
                f,
                "findings_count {findings_count} is inconsistent with status {status}"
            ),
        }
    }
}

impl Error for PersistenceInputError {}
