//! Error surface for the Postgres findings backend, schema layer, and migrations.

use std::{error::Error, fmt};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::PersistenceInputError,
};

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

/// Unified backend error for the PostgreSQL findings implementation.
#[derive(Debug)]
pub enum FindingsPgError {
    /// Underlying PostgreSQL driver error.
    Postgres(postgres::Error),
    /// Embedded migration application failed.
    Migration(FindingsPgMigrationError),
    /// The backend's internal client mutex was poisoned by a panic.
    MutexPoisoned,
    /// The caller exceeded the contract's recommended batch size.
    BatchTooLarge { len: usize, max: usize },
    /// Batch validation or row projection failed before any SQL ran.
    Schema(FindingsPgSchemaError),
    /// A `COUNT(*)` or other non-negative `BIGINT` read produced an invalid value.
    CountOutOfRange { table: &'static str, value: i64 },
    /// Existing finding row conflicts with the content-addressed identity.
    FindingConflict { tenant_id: TenantId, finding_id: FindingId },
    /// Existing occurrence row conflicts with the content-addressed identity.
    OccurrenceConflict {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    },
    /// Existing observation row conflicts with the policy-scoped identity.
    ObservationConflict {
        tenant_id: TenantId,
        observation_id: ObservationId,
    },
}

impl fmt::Display for FindingsPgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(err) => write!(f, "postgres findings error: {err}"),
            Self::Migration(err) => write!(f, "postgres findings migration failed: {err}"),
            Self::MutexPoisoned => write!(f, "postgres findings client mutex is poisoned"),
            Self::BatchTooLarge { len, max } => {
                write!(f, "findings batch too large: {len} records (max {max})")
            }
            Self::Schema(err) => write!(f, "findings schema/projection failed: {err}"),
            Self::CountOutOfRange { table, value } => {
                write!(f, "COUNT(*) for table {table} returned invalid value {value}")
            }
            Self::FindingConflict {
                tenant_id,
                finding_id,
            } => write!(
                f,
                "finding conflict for tenant {tenant_id:?}, finding {finding_id:?}"
            ),
            Self::OccurrenceConflict {
                tenant_id,
                occurrence_id,
            } => write!(
                f,
                "occurrence conflict for tenant {tenant_id:?}, occurrence {occurrence_id:?}"
            ),
            Self::ObservationConflict {
                tenant_id,
                observation_id,
            } => write!(
                f,
                "observation conflict for tenant {tenant_id:?}, observation {observation_id:?}"
            ),
        }
    }
}

impl Error for FindingsPgError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(err) => Some(err),
            Self::Migration(err) => Some(err),
            Self::MutexPoisoned => None,
            Self::BatchTooLarge { .. } => None,
            Self::Schema(err) => Some(err),
            Self::CountOutOfRange { .. } => None,
            Self::FindingConflict { .. } => None,
            Self::OccurrenceConflict { .. } => None,
            Self::ObservationConflict { .. } => None,
        }
    }
}

impl From<postgres::Error> for FindingsPgError {
    fn from(value: postgres::Error) -> Self {
        Self::Postgres(value)
    }
}

impl From<FindingsPgMigrationError> for FindingsPgError {
    fn from(value: FindingsPgMigrationError) -> Self {
        Self::Migration(value)
    }
}

impl From<FindingsPgSchemaError> for FindingsPgError {
    fn from(value: FindingsPgSchemaError) -> Self {
        Self::Schema(value)
    }
}
