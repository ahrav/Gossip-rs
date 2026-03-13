//! Error types for findings-specific PostgreSQL schema projection and migration
//! work.
//!
//! Schema-plan code uses [`FindingsPgSchemaError`] to surface contract
//! validation failures and storage-boundary conversion problems. Migration code
//! uses [`FindingsPgMigrationError`] to distinguish driver/SQL failures from
//! checksum-integrity violations in embedded migrations.

use std::{error::Error, fmt};

use gossip_contracts::persistence::PersistenceInputError;
pub use gossip_pg_common::migration::{
    MigrationOperation, PgMigrationError as FindingsPgMigrationError,
};

use crate::types::PgU64ConversionError;

/// Schema validation and row-projection failures for findings persistence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FindingsPgSchemaError {
    /// Contracts-layer validation rejected the input batch.
    Persistence(PersistenceInputError),
    /// A `u64` field could not be represented as a PostgreSQL `BIGINT`
    /// according to its storage mode.
    PgU64Conversion(PgU64ConversionError),
    /// The combined occurrence span (`byte_offset + byte_length`) exceeds
    /// the PostgreSQL signed `BIGINT` maximum, matching the SQL
    /// `occurrences_span_no_overflow_ck` constraint.
    SpanOverflow {
        /// The non-negative `byte_offset` that individually fits in `i64`.
        byte_offset: i64,
        /// The positive `byte_length` that individually fits in `i64`.
        byte_length: i64,
    },
}

impl fmt::Display for FindingsPgSchemaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Persistence(source) => write!(f, "{source}"),
            Self::PgU64Conversion(source) => write!(f, "{source}"),
            Self::SpanOverflow {
                byte_offset,
                byte_length,
            } => write!(
                f,
                "occurrence span overflow: byte_offset ({byte_offset}) + byte_length ({byte_length}) \
                 exceeds i64::MAX ({max})",
                max = i64::MAX
            ),
        }
    }
}

impl Error for FindingsPgSchemaError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Persistence(source) => Some(source),
            Self::PgU64Conversion(source) => Some(source),
            Self::SpanOverflow { .. } => None,
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
    fn span_overflow_display_includes_offset_and_length() {
        let err = FindingsPgSchemaError::SpanOverflow {
            byte_offset: i64::MAX - 1,
            byte_length: 3,
        };

        let msg = err.to_string();
        assert!(
            msg.contains("span overflow"),
            "should mention span overflow"
        );
        assert!(
            msg.contains(&(i64::MAX - 1).to_string()),
            "should include byte_offset"
        );
        assert!(msg.contains('3'), "should include byte_length");
    }

    #[test]
    fn span_overflow_has_no_source() {
        let err = FindingsPgSchemaError::SpanOverflow {
            byte_offset: i64::MAX - 1,
            byte_length: 3,
        };

        assert!(err.source().is_none());
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
