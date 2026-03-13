//! Error types for findings-specific PostgreSQL schema projection, backend, and
//! migration work.
//!
//! Schema-plan code uses [`FindingsPgSchemaError`] to surface contract
//! validation failures and storage-boundary conversion problems. Migration code
//! uses [`FindingsPgMigrationError`] to distinguish driver/SQL failures from
//! checksum-integrity violations in embedded migrations. Backend code uses
//! [`FindingsPgError`] to unify schema, migration, SQL-driver, and identity
//! conflict failures behind a single `FindingsSink` error surface.

use std::{error::Error, fmt};

use gossip_contracts::{
    identity::{FindingId, ObservationId, OccurrenceId, TenantId},
    persistence::PersistenceInputError,
};
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

/// Unified backend error for the PostgreSQL findings implementation.
#[derive(Debug)]
pub enum FindingsPgError {
    /// PostgreSQL client failure.
    Postgres(postgres::Error),
    /// Embedded migration application failed.
    Migration(FindingsPgMigrationError),
    /// Internal client mutex was poisoned by a panic.
    MutexPoisoned,
    /// Input batch exceeded the recommended maximum.
    BatchTooLarge { len: usize, max: usize },
    /// Batch validation or row projection failed before SQL mutation.
    Schema(FindingsPgSchemaError),
    /// A persisted row count did not fit the non-negative count domain.
    CountOutOfRange { table: &'static str, value: i64 },
    /// A finding primary key mapped to a different immutable natural key.
    FindingConflict {
        tenant_id: TenantId,
        finding_id: FindingId,
    },
    /// An occurrence primary key mapped to a different immutable natural key.
    OccurrenceConflict {
        tenant_id: TenantId,
        occurrence_id: OccurrenceId,
    },
    /// An observation primary key mapped to a different immutable natural key.
    ObservationConflict {
        tenant_id: TenantId,
        observation_id: ObservationId,
    },
}

impl fmt::Display for FindingsPgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(source) => {
                if let Some(db_err) = source.as_db_error() {
                    write!(
                        f,
                        "postgres findings operation failed: {} ({})",
                        db_err.severity(),
                        db_err.code().code()
                    )
                } else {
                    write!(f, "postgres findings connection/protocol error")
                }
            }
            Self::Migration(source) => match source {
                FindingsPgMigrationError::Postgres { operation, source } => {
                    if let Some(db_err) = source.as_db_error() {
                        write!(
                            f,
                            "postgres findings migration {operation} failed: {} ({})",
                            db_err.severity(),
                            db_err.code().code()
                        )
                    } else {
                        write!(
                            f,
                            "postgres findings migration {operation} connection/protocol error"
                        )
                    }
                }
                other => write!(f, "postgres findings migration failed: {other}"),
            },
            Self::MutexPoisoned => f.write_str("postgres findings client mutex is poisoned"),
            Self::BatchTooLarge { len, max } => {
                write!(f, "findings batch too large: {len} records (limit {max})")
            }
            Self::Schema(source) => {
                write!(f, "invalid findings batch for postgres backend: {source}")
            }
            Self::CountOutOfRange { table, value } => {
                write!(f, "stored count for {table} out of range: {value}")
            }
            Self::FindingConflict {
                tenant_id,
                finding_id,
            } => write!(
                f,
                "content-addressed finding identity conflict for tenant {tenant_id} and finding {finding_id}"
            ),
            Self::OccurrenceConflict {
                tenant_id,
                occurrence_id,
            } => write!(
                f,
                "content-addressed occurrence identity conflict for tenant {tenant_id} and occurrence {occurrence_id}"
            ),
            Self::ObservationConflict {
                tenant_id,
                observation_id,
            } => write!(
                f,
                "policy-scoped observation identity conflict for tenant {tenant_id} and observation {observation_id}"
            ),
        }
    }
}

impl Error for FindingsPgError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(source) => Some(source),
            Self::Migration(source) => Some(source),
            Self::Schema(source) => Some(source),
            Self::MutexPoisoned
            | Self::BatchTooLarge { .. }
            | Self::CountOutOfRange { .. }
            | Self::FindingConflict { .. }
            | Self::OccurrenceConflict { .. }
            | Self::ObservationConflict { .. } => None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use gossip_contracts::{
        identity::{FindingId, ObservationId, OccurrenceId, TenantId},
        persistence::RECOMMENDED_MAX_BATCH_SIZE,
    };

    fn tenant_id() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn finding_id() -> FindingId {
        FindingId::from_bytes([0x22; 32])
    }

    fn occurrence_id() -> OccurrenceId {
        OccurrenceId::from_bytes([0x33; 32])
    }

    fn observation_id() -> ObservationId {
        ObservationId::from_bytes([0x44; 32])
    }

    fn timeout_postgres_error() -> postgres::Error {
        postgres::Error::__private_api_timeout()
    }

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

    #[test]
    fn backend_error_display_redacts_connection_details_for_postgres_errors() {
        let err = FindingsPgError::Postgres(timeout_postgres_error());

        assert_eq!(
            err.to_string(),
            "postgres findings connection/protocol error"
        );
    }

    #[test]
    fn backend_error_display_redacts_migration_wrapped_postgres_errors() {
        // A migration-wrapped postgres error must redact the same way as a
        // direct postgres error — the raw `postgres::Error` text ("timeout
        // waiting for server") must not appear in the Display output.
        let err = FindingsPgError::Migration(FindingsPgMigrationError::postgres(
            MigrationOperation::Connect,
            timeout_postgres_error(),
        ));

        let msg = err.to_string();
        assert!(
            !msg.contains("timeout waiting for server"),
            "migration-wrapped postgres error must not leak raw driver text, got: {msg}"
        );
    }

    #[test]
    fn backend_error_display_describes_migration_failures() {
        let err = FindingsPgError::Migration(FindingsPgMigrationError::ChecksumMismatch {
            version: "0001_findings_schema",
            expected_hex: "aa".repeat(32),
            found_hex: "bb".repeat(32),
        });

        let msg = err.to_string();
        assert!(msg.contains("postgres findings migration failed"));
        assert!(msg.contains("0001_findings_schema"));
    }

    #[test]
    fn backend_error_display_describes_mutex_poisoning() {
        let err = FindingsPgError::MutexPoisoned;

        assert_eq!(
            err.to_string(),
            "postgres findings client mutex is poisoned"
        );
    }

    #[test]
    fn backend_error_display_describes_batch_limits() {
        let err = FindingsPgError::BatchTooLarge {
            len: RECOMMENDED_MAX_BATCH_SIZE + 1,
            max: RECOMMENDED_MAX_BATCH_SIZE,
        };

        assert_eq!(
            err.to_string(),
            format!(
                "findings batch too large: {} records (limit {})",
                RECOMMENDED_MAX_BATCH_SIZE + 1,
                RECOMMENDED_MAX_BATCH_SIZE
            )
        );
    }

    #[test]
    fn backend_error_display_describes_schema_failures() {
        let err = FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
            PersistenceInputError::Empty { field: "tenant_id" },
        ));

        assert_eq!(
            err.to_string(),
            "invalid findings batch for postgres backend: tenant_id must not be empty"
        );
    }

    #[test]
    fn backend_error_display_describes_out_of_range_counts() {
        let err = FindingsPgError::CountOutOfRange {
            table: "findings",
            value: -1,
        };

        assert_eq!(
            err.to_string(),
            "stored count for findings out of range: -1"
        );
    }

    #[test]
    fn backend_error_display_describes_identity_conflicts() {
        let cases: &[(FindingsPgError, &[&str])] = &[
            (
                FindingsPgError::FindingConflict {
                    tenant_id: tenant_id(),
                    finding_id: finding_id(),
                },
                &[
                    "content-addressed finding identity conflict",
                    "TenantId(11111111..)",
                    "FindingId(22222222..)",
                ],
            ),
            (
                FindingsPgError::OccurrenceConflict {
                    tenant_id: tenant_id(),
                    occurrence_id: occurrence_id(),
                },
                &[
                    "content-addressed occurrence identity conflict",
                    "TenantId(11111111..)",
                    "OccurrenceId(33333333..)",
                ],
            ),
            (
                FindingsPgError::ObservationConflict {
                    tenant_id: tenant_id(),
                    observation_id: observation_id(),
                },
                &[
                    "policy-scoped observation identity conflict",
                    "TenantId(11111111..)",
                    "ObservationId(44444444..)",
                ],
            ),
        ];

        for (err, expected_substrings) in cases {
            let msg = err.to_string();
            for sub in *expected_substrings {
                assert!(msg.contains(sub), "{msg} should contain {sub}");
            }
        }
    }

    #[test]
    fn backend_error_source_exposes_wrapped_errors() {
        let postgres = FindingsPgError::Postgres(timeout_postgres_error());
        let migration = FindingsPgError::Migration(FindingsPgMigrationError::ChecksumMismatch {
            version: "0001_findings_schema",
            expected_hex: "aa".repeat(32),
            found_hex: "bb".repeat(32),
        });
        let schema = FindingsPgError::Schema(FindingsPgSchemaError::Persistence(
            PersistenceInputError::Empty { field: "tenant_id" },
        ));

        assert_eq!(
            postgres
                .source()
                .expect("postgres variant should expose source")
                .to_string(),
            "timeout waiting for server"
        );
        assert_eq!(
            migration
                .source()
                .expect("migration variant should expose source")
                .to_string(),
            FindingsPgMigrationError::ChecksumMismatch {
                version: "0001_findings_schema",
                expected_hex: "aa".repeat(32),
                found_hex: "bb".repeat(32),
            }
            .to_string()
        );
        assert_eq!(
            schema
                .source()
                .expect("schema variant should expose source")
                .to_string(),
            "tenant_id must not be empty"
        );
    }

    #[test]
    fn backend_error_source_is_none_for_non_wrapped_variants() {
        let cases = [
            FindingsPgError::MutexPoisoned,
            FindingsPgError::BatchTooLarge { len: 11, max: 10 },
            FindingsPgError::CountOutOfRange {
                table: "findings",
                value: -1,
            },
            FindingsPgError::FindingConflict {
                tenant_id: tenant_id(),
                finding_id: finding_id(),
            },
            FindingsPgError::OccurrenceConflict {
                tenant_id: tenant_id(),
                occurrence_id: occurrence_id(),
            },
            FindingsPgError::ObservationConflict {
                tenant_id: tenant_id(),
                observation_id: observation_id(),
            },
        ];

        for err in cases {
            assert!(err.source().is_none(), "{err} should not expose a source");
        }
    }
}
