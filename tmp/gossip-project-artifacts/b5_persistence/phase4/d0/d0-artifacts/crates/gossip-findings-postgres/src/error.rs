//! Error surface for the findings Postgres schema layer.

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
