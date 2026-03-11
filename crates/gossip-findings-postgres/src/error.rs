//! Error types for findings-specific PostgreSQL schema projection and migration
//! work.
//!
//! Schema-plan code uses [`FindingsPgSchemaError`] to surface contract
//! validation failures and storage-boundary conversion problems. Migration code
//! uses [`FindingsPgMigrationError`] to distinguish driver/SQL failures from
//! checksum-integrity violations in embedded migrations.

use std::{error::Error, fmt};

use gossip_contracts::persistence::PersistenceInputError;
pub use gossip_pg_common::migration::MigrationOperation;

use crate::types::PgU64ConversionError;

/// Schema validation and row-projection failures for findings persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingsPgSchemaError {
    /// Contracts-layer validation rejected the input batch.
    Persistence(PersistenceInputError),
    /// A `u64` field could not be represented as a PostgreSQL `BIGINT`
    /// according to its storage mode.
    PgU64Conversion(PgU64ConversionError),
}

impl fmt::Display for FindingsPgSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persistence(source) => write!(f, "{source}"),
            Self::PgU64Conversion(source) => write!(f, "{source}"),
        }
    }
}

impl Error for FindingsPgSchemaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(source) => Some(source),
            Self::PgU64Conversion(source) => Some(source),
        }
    }
}

impl From<PersistenceInputError> for FindingsPgSchemaError {
    fn from(value: PersistenceInputError) -> Self {
        Self::Persistence(value)
    }
}

impl From<PgU64ConversionError> for FindingsPgSchemaError {
    fn from(value: PgU64ConversionError) -> Self {
        Self::PgU64Conversion(value)
    }
}

/// Error type for findings PostgreSQL schema migrations.
#[derive(Debug)]
pub enum FindingsPgMigrationError {
    /// PostgreSQL driver or SQL execution error, tagged with the operation
    /// that failed.
    Postgres {
        /// Which migration step produced the error.
        operation: MigrationOperation,
        /// The underlying driver error.
        source: postgres::Error,
    },
    /// An already-applied migration's embedded SQL no longer matches the
    /// checksum recorded in the database.
    ChecksumMismatch {
        /// Version string of the migration with the mismatched checksum.
        version: &'static str,
        /// BLAKE3 hex digest of the embedded SQL text.
        expected_hex: String,
        /// BLAKE3 hex digest recorded in the migrations table.
        found_hex: String,
    },
    /// The stored checksum length is invalid for a BLAKE3 digest.
    CorruptedHistoryRecord {
        /// Version string of the migration with the corrupted checksum.
        version: &'static str,
        /// Actual byte length of the stored checksum.
        found_len: usize,
    },
}

impl FindingsPgMigrationError {
    /// Wrap a PostgreSQL driver error with the operation that produced it.
    ///
    /// No callers yet — the migration runner that will use this constructor
    /// has not been implemented. Matches the sibling crate's API surface
    /// (`DoneLedgerPgMigrationError::postgres`).
    #[allow(dead_code)]
    pub(crate) fn postgres(op: MigrationOperation, source: postgres::Error) -> Self {
        Self::Postgres {
            operation: op,
            source,
        }
    }
}

impl fmt::Display for FindingsPgMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres {
                operation, source, ..
            } => write!(
                f,
                "postgres findings migration {operation} failed: {source}"
            ),
            Self::ChecksumMismatch {
                version,
                expected_hex,
                found_hex,
            } => write!(
                f,
                "migration checksum mismatch for version {version}: expected {expected_hex}, found {found_hex}"
            ),
            Self::CorruptedHistoryRecord { version, found_len } => write!(
                f,
                "corrupted migration history: version {version} checksum is {found_len} bytes, expected 32"
            ),
        }
    }
}

impl Error for FindingsPgMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres { source, .. } => Some(source),
            Self::ChecksumMismatch { .. } | Self::CorruptedHistoryRecord { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schema_error_display_uses_persistence_source_message() {
        let inner = PersistenceInputError::Empty { field: "tenant_id" };
        let expected = inner.to_string();
        let err = FindingsPgSchemaError::from(inner);
        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn schema_error_source_exposes_persistence_error() {
        let inner = PersistenceInputError::TooLarge {
            field: "location_display",
            size: 4097,
            max: 4096,
        };
        let expected = inner.to_string();
        let err = FindingsPgSchemaError::from(inner);

        let source = err.source().expect("schema error should expose source");
        assert_eq!(source.to_string(), expected);
    }

    #[test]
    fn schema_error_display_uses_conversion_source_message() {
        let inner = PgU64ConversionError::OrderedOutOfRange {
            field: "seen_at",
            value: u64::MAX,
        };
        let expected = inner.to_string();
        let err = FindingsPgSchemaError::from(inner);

        assert_eq!(err.to_string(), expected);
    }

    #[test]
    fn schema_error_source_exposes_conversion_error() {
        let inner = PgU64ConversionError::NegativeStoredValue {
            field: "byte_offset",
            value: -1,
        };
        let expected = inner.to_string();
        let err = FindingsPgSchemaError::from(inner);

        let source = err.source().expect("schema error should expose source");
        assert_eq!(source.to_string(), expected);
    }

    #[test]
    fn checksum_mismatch_display_includes_version_and_hashes() {
        let err = FindingsPgMigrationError::ChecksumMismatch {
            version: "0001_findings_schema",
            expected_hex: "aa".repeat(32),
            found_hex: "bb".repeat(32),
        };

        let msg = err.to_string();
        assert!(msg.contains("0001_findings_schema"));
        assert!(msg.contains(&"aa".repeat(32)));
        assert!(msg.contains(&"bb".repeat(32)));
    }

    #[test]
    fn checksum_mismatch_has_no_source() {
        let err = FindingsPgMigrationError::ChecksumMismatch {
            version: "0001_findings_schema",
            expected_hex: String::new(),
            found_hex: String::new(),
        };

        assert!(err.source().is_none());
    }

    #[test]
    fn corrupted_history_record_display_includes_lengths() {
        let err = FindingsPgMigrationError::CorruptedHistoryRecord {
            version: "0001_findings_schema",
            found_len: 7,
        };

        let msg = err.to_string();
        assert!(msg.contains("0001_findings_schema"));
        assert!(msg.contains("7"));
        assert!(msg.contains("32"));
    }

    #[test]
    fn corrupted_history_record_has_no_source() {
        let err = FindingsPgMigrationError::CorruptedHistoryRecord {
            version: "0001_findings_schema",
            found_len: 0,
        };

        assert!(err.source().is_none());
    }
}
