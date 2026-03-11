//! Error surface for the findings Postgres schema and migration layers.

use std::{error::Error, fmt};

use gossip_contracts::persistence::PersistenceInputError;

use crate::pg_int::PgIntConversionError;

/// Errors produced while validating or projecting findings records into the
/// PostgreSQL row model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingsPgSchemaError {
    /// Contract-level findings batch validation failed.
    Persistence(PersistenceInputError),
    /// A `u64` value could not be represented by the chosen `BIGINT`
    /// encoding strategy for a given column.
    PgIntConversion(PgIntConversionError),
}

impl fmt::Display for FindingsPgSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persistence(err) => write!(f, "findings schema validation failed: {err}"),
            Self::PgIntConversion(err) => {
                write!(f, "findings schema integer conversion failed: {err}")
            }
        }
    }
}

impl Error for FindingsPgSchemaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(err) => Some(err),
            Self::PgIntConversion(err) => Some(err),
        }
    }
}

impl From<PersistenceInputError> for FindingsPgSchemaError {
    fn from(value: PersistenceInputError) -> Self {
        Self::Persistence(value)
    }
}

impl From<PgIntConversionError> for FindingsPgSchemaError {
    fn from(value: PgIntConversionError) -> Self {
        Self::PgIntConversion(value)
    }
}

/// Migration failure surfaced by the Postgres findings crate.
#[derive(Debug)]
pub enum FindingsPgMigrationError {
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

impl fmt::Display for FindingsPgMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(err) => write!(f, "postgres findings migration error: {err}"),
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

impl Error for FindingsPgMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(err) => Some(err),
            Self::ChecksumMismatch { .. } => None,
        }
    }
}

impl From<postgres::Error> for FindingsPgMigrationError {
    fn from(value: postgres::Error) -> Self {
        Self::Postgres(value)
    }
}
