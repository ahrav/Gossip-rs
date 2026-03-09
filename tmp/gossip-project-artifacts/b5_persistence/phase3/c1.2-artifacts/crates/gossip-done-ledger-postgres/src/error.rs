//! Error types for the PostgreSQL done-ledger backend and migrations.

use std::{error::Error, fmt};

use gossip_contracts::persistence::PersistenceInputError;

/// Conversion failures at the Rust <-> Postgres storage boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DoneLedgerPgConversionError {
    /// A value that must preserve natural numeric ordering exceeded `i64::MAX`.
    OutOfRangeForBigInt { field: &'static str, value: u64 },
    /// A supposedly non-negative `BIGINT` column contained a negative value.
    NegativeStoredValue { field: &'static str, value: i64 },
    /// A `BYTEA` column did not contain the expected fixed-width hash size.
    InvalidByteLength {
        field: &'static str,
        expected: usize,
        actual: usize,
    },
    /// A stored status rank did not correspond to any known `DoneLedgerStatus`.
    UnknownStatusRank { rank: i16 },
    /// A stored `findings_count` did not fit into `u32`.
    FindingsCountOutOfRange { value: i32 },
    /// An input `findings_count` exceeded Postgres `INTEGER` range.
    FindingsCountTooLarge { value: u32 },
}

impl fmt::Display for DoneLedgerPgConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRangeForBigInt { field, value } => {
                write!(f, "{field} value {value} exceeds BIGINT range")
            }
            Self::NegativeStoredValue { field, value } => {
                write!(f, "{field} stored negative BIGINT value {value}")
            }
            Self::InvalidByteLength {
                field,
                expected,
                actual,
            } => write!(
                f,
                "{field} stored invalid byte length {actual} (expected {expected})"
            ),
            Self::UnknownStatusRank { rank } => {
                write!(f, "stored unknown done-ledger status rank {rank}")
            }
            Self::FindingsCountOutOfRange { value } => {
                write!(f, "stored findings_count {value} does not fit in u32")
            }
            Self::FindingsCountTooLarge { value } => {
                write!(f, "input findings_count {value} exceeds PostgreSQL INTEGER range")
            }
        }
    }
}

impl Error for DoneLedgerPgConversionError {}

/// Migration failure surfaced by the Postgres done-ledger crate.
#[derive(Debug)]
pub enum DoneLedgerPgMigrationError {
    /// Underlying PostgreSQL driver error.
    Postgres(postgres::Error),
    /// The migration table contains a version whose checksum no longer matches
    /// the embedded SQL bytes.
    ChecksumMismatch {
        version: &'static str,
        expected_hex: String,
        found_hex: String,
    },
}

impl fmt::Display for DoneLedgerPgMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(err) => write!(f, "postgres migration error: {err}"),
            Self::ChecksumMismatch {
                version,
                expected_hex,
                found_hex,
            } => write!(
                f,
                "migration checksum mismatch for version {version}: expected {expected_hex}, found {found_hex}"
            ),
        }
    }
}

impl Error for DoneLedgerPgMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(err) => Some(err),
            Self::ChecksumMismatch { .. } => None,
        }
    }
}

impl From<postgres::Error> for DoneLedgerPgMigrationError {
    fn from(value: postgres::Error) -> Self {
        Self::Postgres(value)
    }
}

/// Unified backend error for the PostgreSQL done-ledger implementation.
#[derive(Debug)]
pub enum DoneLedgerPgError {
    /// Underlying PostgreSQL client failure.
    Postgres(postgres::Error),
    /// Embedded migration application failed.
    Migration(DoneLedgerPgMigrationError),
    /// The backend's internal client mutex was poisoned by a panic.
    MutexPoisoned,
    /// The caller exceeded the contract's recommended batch size.
    BatchTooLarge {
        operation: &'static str,
        len: usize,
        max: usize,
    },
    /// An input record failed persistence-layer validation before any SQL ran.
    InvalidRecord {
        index: usize,
        source: PersistenceInputError,
    },
    /// A value could not be represented faithfully at the SQL boundary.
    Conversion(DoneLedgerPgConversionError),
    /// A row read back from the database violated contract invariants.
    PersistedRecordInvalid {
        context: &'static str,
        source: PersistenceInputError,
    },
}

impl fmt::Display for DoneLedgerPgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(err) => write!(f, "postgres done-ledger error: {err}"),
            Self::Migration(err) => write!(f, "postgres done-ledger migration failed: {err}"),
            Self::MutexPoisoned => {
                write!(f, "postgres done-ledger client mutex is poisoned")
            }
            Self::BatchTooLarge {
                operation,
                len,
                max,
            } => write!(
                f,
                "{operation} batch too large: {len} records (max {max})"
            ),
            Self::InvalidRecord { index, source } => {
                write!(f, "invalid done-ledger record at index {index}: {source}")
            }
            Self::Conversion(err) => write!(f, "postgres done-ledger conversion error: {err}"),
            Self::PersistedRecordInvalid { context, source } => {
                write!(f, "persisted done-ledger row invalid during {context}: {source}")
            }
        }
    }
}

impl Error for DoneLedgerPgError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(err) => Some(err),
            Self::Migration(err) => Some(err),
            Self::MutexPoisoned => None,
            Self::BatchTooLarge { .. } => None,
            Self::InvalidRecord { source, .. } => Some(source),
            Self::Conversion(err) => Some(err),
            Self::PersistedRecordInvalid { source, .. } => Some(source),
        }
    }
}

impl From<postgres::Error> for DoneLedgerPgError {
    fn from(value: postgres::Error) -> Self {
        Self::Postgres(value)
    }
}

impl From<DoneLedgerPgMigrationError> for DoneLedgerPgError {
    fn from(value: DoneLedgerPgMigrationError) -> Self {
        Self::Migration(value)
    }
}

impl From<DoneLedgerPgConversionError> for DoneLedgerPgError {
    fn from(value: DoneLedgerPgConversionError) -> Self {
        Self::Conversion(value)
    }
}
