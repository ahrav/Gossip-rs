//! Error types for the PostgreSQL done-ledger backend and migration subsystem.
//!
//! All errors produced during schema migration are funneled through
//! [`DoneLedgerPgMigrationError`], which distinguishes between transport/SQL
//! failures and migration-integrity violations. Each driver error carries a
//! [`MigrationOperation`] tag that identifies which step failed (connect,
//! configure, DDL, advisory lock, etc.). Backend operation failures are
//! exposed through [`DoneLedgerPgError`].

use std::{error::Error, fmt};

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
#[derive(Debug)]
pub enum DoneLedgerPgConversionError {
    /// Numeric `u64`/`BIGINT` conversion failed.
    U64Conversion(PgU64ConversionError),
    /// BYTEA column decode: unexpected byte length.
    ByteDecode(PgByteDecodeError),
    /// A persisted status rank did not map to a known `DoneLedgerStatus`.
    UnknownStatusRank { rank: i16 },
    /// A persisted `findings_count` value did not fit in `u32`.
    FindingsCountOutOfRange { value: i64 },
}

impl fmt::Display for DoneLedgerPgConversionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::U64Conversion(source) => write!(f, "{source}"),
            Self::ByteDecode(source) => write!(f, "{source}"),
            Self::UnknownStatusRank { rank } => {
                write!(f, "stored unknown done-ledger status rank {rank}")
            }
            Self::FindingsCountOutOfRange { value } => {
                write!(f, "stored findings_count {value} does not fit in u32")
            }
        }
    }
}

impl Error for DoneLedgerPgConversionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::U64Conversion(source) => Some(source),
            Self::ByteDecode(source) => Some(source),
            Self::UnknownStatusRank { .. } | Self::FindingsCountOutOfRange { .. } => None,
        }
    }
}

impl From<PgU64ConversionError> for DoneLedgerPgConversionError {
    fn from(value: PgU64ConversionError) -> Self {
        Self::U64Conversion(value)
    }
}

impl From<PgByteDecodeError> for DoneLedgerPgConversionError {
    fn from(value: PgByteDecodeError) -> Self {
        Self::ByteDecode(value)
    }
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
#[derive(Debug)]
pub enum DoneLedgerPgError {
    /// PostgreSQL client failure.
    Postgres(postgres::Error),
    /// Embedded migration application failed.
    Migration(DoneLedgerPgMigrationError),
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
        source: PersistenceInputError,
    },
    /// Duplicate-key merge produced an invalid record shape.
    InvalidMergedRecord { source: PersistenceInputError },
    /// Rust ↔ SQL conversion failed.
    ///
    /// When this occurs during batch encoding (write path), `record_index`
    /// identifies which record in the batch triggered the failure. During
    /// decode (read path), `record_index` is `None`.
    Conversion {
        record_index: Option<usize>,
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

impl Error for DoneLedgerPgError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres(source) => Some(source),
            Self::Migration(source) => Some(source),
            Self::MutexPoisoned | Self::BatchTooLarge { .. } | Self::ProvenanceInvalid { .. } => {
                None
            }
            Self::InvalidRecord { source, .. }
            | Self::InvalidMergedRecord { source }
            | Self::PersistedRecordInvalid { source, .. } => Some(source),
            Self::Conversion { source, .. } => Some(source),
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
}
