//! Migration error types for the PostgreSQL done-ledger crate.

use std::{error::Error, fmt};

/// Unified error type for schema migration operations.
#[derive(Debug)]
pub enum DoneLedgerPgMigrationError {
    /// Underlying PostgreSQL driver error.
    Postgres(postgres::Error),
    /// The migration history table contains a version entry whose checksum no
    /// longer matches the embedded migration bytes.
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
