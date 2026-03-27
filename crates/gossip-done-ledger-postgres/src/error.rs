//! Error types for the PostgreSQL done-ledger backend and migration subsystem.
//!
//! All errors produced during schema migration are funneled through
//! [`DoneLedgerPgMigrationError`], which distinguishes between transport/SQL
//! failures and migration-integrity violations. Each driver error carries a
//! [`MigrationOperation`] tag that identifies which step failed (connect,
//! configure, DDL, advisory lock, etc.). Backend operation failures are
//! exposed through [`DoneLedgerPgError`].

use std::fmt;

use gossip_contracts::persistence::PersistenceInputError;
pub use gossip_pg_common::migration::{
    MigrationOperation, PgMigrationError as DoneLedgerPgMigrationError,
};

use crate::types::{PgByteDecodeError, PgU64ConversionError};

/// Conversion failures at the Rust ↔ PostgreSQL storage boundary.
///
/// These errors arise when decoding a `Row` returned by PostgreSQL into
/// Rust domain types, or when encoding Rust values for SQL parameters.
/// Most variants pinpoint the column and the nature of the mismatch so
/// that data-corruption or schema-drift issues can be diagnosed without
/// inspecting raw SQL results.
#[derive(Debug, thiserror::Error)]
pub enum DoneLedgerPgConversionError {
    /// Numeric `u64`/`BIGINT` conversion failed.
    #[error("{0}")]
    U64Conversion(#[from] PgU64ConversionError),
    /// BYTEA column decode: unexpected byte length.
    #[error("{0}")]
    ByteDecode(#[from] PgByteDecodeError),
    /// A persisted status rank did not map to a known `DoneLedgerStatus`.
    #[error("stored unknown done-ledger status rank {rank}")]
    UnknownStatusRank { rank: i16 },
    /// A persisted `findings_count` value did not fit in `u32`.
    #[error("stored findings_count {value} does not fit in u32")]
    FindingsCountOutOfRange { value: i64 },
}

/// Unified backend error for the PostgreSQL done-ledger implementation.
///
/// This is the `DoneLedger::Error` associated type for [`DoneLedgerPg`].
/// Variants fall into four categories:
///
/// - **Infrastructure** — connection failures, mutex poisoning, migration
///   errors ([`Postgres`](Self::Postgres), [`Migration`](Self::Migration),
///   [`MutexPoisoned`](Self::MutexPoisoned)).
/// - **Input validation** — caller-supplied records that violate batch-size
///   limits or contract invariants ([`BatchTooLarge`](Self::BatchTooLarge),
///   [`InvalidRecord`](Self::InvalidRecord)).
/// - **Merge logic** — duplicate-key folding produced an invalid composite
///   record ([`InvalidMergedRecord`](Self::InvalidMergedRecord)).
/// - **Decode-time** — a persisted row cannot be interpreted as a valid
///   domain record ([`Conversion`](Self::Conversion),
///   [`PersistedRecordInvalid`](Self::PersistedRecordInvalid)).
///
/// [`DoneLedgerPg`]: crate::DoneLedgerPg
#[derive(Debug, thiserror::Error)]
pub enum DoneLedgerPgError {
    /// PostgreSQL client failure.
    Postgres(#[from] postgres::Error),
    /// Embedded migration application failed.
    Migration(#[from] DoneLedgerPgMigrationError),
    /// Internal client mutex was poisoned by a panic.
    MutexPoisoned,
    /// Input batch exceeded the supported maximum.
    BatchTooLarge {
        operation: &'static str,
        len: usize,
        max: usize,
    },
    /// Input record failed validation before SQL mutation.
    InvalidRecord {
        index: usize,
        #[source]
        source: PersistenceInputError,
    },
    /// Duplicate-key merge produced an invalid record shape.
    InvalidMergedRecord {
        #[source]
        source: PersistenceInputError,
    },
    /// Rust ↔ SQL conversion failed.
    ///
    /// When this occurs during batch encoding (write path), `record_index`
    /// identifies which record in the batch triggered the failure. During
    /// decode (read path), `record_index` is `None`.
    Conversion {
        record_index: Option<usize>,
        #[source]
        source: DoneLedgerPgConversionError,
    },
    /// Provenance timestamps violate the `finished_at >= started_at` ordering
    /// invariant, which would be rejected by the database CHECK constraint.
    ProvenanceInvalid {
        index: usize,
        started_at: u64,
        finished_at: u64,
    },
    /// Persisted row failed decode-time contract validation.
    PersistedRecordInvalid {
        context: &'static str,
        #[source]
        source: PersistenceInputError,
    },
}

impl fmt::Display for DoneLedgerPgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres(source) => {
                if let Some(db_err) = source.as_db_error() {
                    write!(
                        f,
                        "postgres done-ledger operation failed: {} ({})",
                        db_err.severity(),
                        db_err.code().code()
                    )
                } else {
                    // IO/connection errors may embed connection strings — redact details.
                    // Full diagnostics remain available via `Error::source()`.
                    write!(f, "postgres done-ledger connection/protocol error")
                }
            }
            Self::Migration(source) => write!(f, "postgres done-ledger migration failed: {source}"),
            Self::MutexPoisoned => f.write_str("postgres done-ledger client mutex is poisoned"),
            Self::BatchTooLarge {
                operation,
                len,
                max,
            } => write!(
                f,
                "{operation} batch too large: {len} records (limit {max})"
            ),
            Self::InvalidRecord { index, source } => {
                write!(f, "invalid done-ledger record at index {index}: {source}")
            }
            Self::InvalidMergedRecord { source } => {
                write!(
                    f,
                    "merged done-ledger record violates contract invariants: {source}"
                )
            }
            Self::ProvenanceInvalid {
                index,
                started_at,
                finished_at,
            } => write!(
                f,
                "record at index {index}: started_at ({started_at}) exceeds finished_at ({finished_at})"
            ),
            Self::Conversion {
                record_index: Some(idx),
                source,
            } => {
                write!(
                    f,
                    "postgres done-ledger conversion failed at record index {idx}: {source}"
                )
            }
            Self::Conversion {
                record_index: None,
                source,
            } => {
                write!(f, "postgres done-ledger conversion failed: {source}")
            }
            Self::PersistedRecordInvalid { context, source } => {
                write!(
                    f,
                    "persisted done-ledger row invalid during {context}: {source}"
                )
            }
        }
    }
}

impl From<DoneLedgerPgConversionError> for DoneLedgerPgError {
    fn from(value: DoneLedgerPgConversionError) -> Self {
        Self::Conversion {
            record_index: None,
            source: value,
        }
    }
}

impl From<PgByteDecodeError> for DoneLedgerPgError {
    fn from(value: PgByteDecodeError) -> Self {
        Self::Conversion {
            record_index: None,
            source: DoneLedgerPgConversionError::ByteDecode(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use super::*;

    #[test]
    fn checksum_mismatch_display_includes_version_and_hashes() {
        let err = DoneLedgerPgMigrationError::ChecksumMismatch {
            version: "0001_test",
            expected_hex: "aa".repeat(32),
            found_hex: "bb".repeat(32),
        };
        let msg = err.to_string();
        assert!(msg.contains("0001_test"), "should contain version: {msg}");
        assert!(
            msg.contains(&"aa".repeat(32)),
            "should contain expected hex: {msg}"
        );
        assert!(
            msg.contains(&"bb".repeat(32)),
            "should contain found hex: {msg}"
        );
    }

    #[test]
    fn checksum_mismatch_error_source_is_none() {
        let err = DoneLedgerPgMigrationError::ChecksumMismatch {
            version: "0001_test",
            expected_hex: String::new(),
            found_hex: String::new(),
        };
        assert!(
            err.source().is_none(),
            "ChecksumMismatch should have no source error"
        );
    }

    #[test]
    fn corrupted_history_record_display() {
        let err = DoneLedgerPgMigrationError::CorruptedHistoryRecord {
            version: "0001_test",
            found_len: 31,
        };
        let msg = err.to_string();
        assert!(msg.contains("0001_test"), "should contain version: {msg}");
        assert!(msg.contains("31"), "should contain actual length: {msg}");
        assert!(msg.contains("32"), "should contain expected length: {msg}");
    }

    #[test]
    fn corrupted_history_record_error_source_is_none() {
        let err = DoneLedgerPgMigrationError::CorruptedHistoryRecord {
            version: "0001_test",
            found_len: 0,
        };
        assert!(
            err.source().is_none(),
            "CorruptedHistoryRecord should have no source error"
        );
    }

    #[test]
    fn conversion_error_byte_decode_delegates_display() {
        let inner = PgByteDecodeError::InvalidByteLength {
            field: "tenant_id",
            expected: 32,
            actual: 31,
        };
        let err = DoneLedgerPgConversionError::ByteDecode(inner);
        assert_eq!(
            err.to_string(),
            inner.to_string(),
            "ByteDecode Display should delegate to the inner PgByteDecodeError"
        );
    }

    #[test]
    fn conversion_error_byte_decode_exposes_source() {
        let inner = PgByteDecodeError::InvalidByteLength {
            field: "ovid_hash",
            expected: 32,
            actual: 0,
        };
        let err = DoneLedgerPgConversionError::ByteDecode(inner);
        let source = err
            .source()
            .expect("ByteDecode should expose inner error as source");
        assert!(
            source.is::<PgByteDecodeError>(),
            "source should be PgByteDecodeError"
        );
    }
}
