//! Error types for the PostgreSQL done-ledger migration subsystem.
//!
//! All errors produced during schema migration are funneled through
//! [`DoneLedgerPgMigrationError`], which distinguishes between transport/SQL
//! failures and migration-integrity violations. Each driver error carries a
//! [`MigrationOperation`] tag that identifies which step failed (connect,
//! configure, DDL, advisory lock, etc.).

use std::{error::Error, fmt};

/// Labels the migration step that produced a PostgreSQL driver error.
///
/// Paired with the driver error in [`DoneLedgerPgMigrationError::Postgres`]
/// to provide structured failure context without losing the underlying cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum MigrationOperation {
    /// Initial TCP/TLS connection to the database.
    Connect,
    /// Session or transaction configuration (`SET LOCAL`, `BEGIN`).
    Configure,
    /// Creating or querying the migration history table.
    HistoryTable,
    /// Acquiring the transaction-scoped advisory lock.
    AdvisoryLock,
    /// Executing a migration's SQL body.
    ApplyMigration,
    /// Inserting or querying the migration history record.
    RecordMigration,
    /// Committing the migration transaction.
    Commit,
}

impl fmt::Display for MigrationOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Connect => f.write_str("connect"),
            Self::Configure => f.write_str("configure"),
            Self::HistoryTable => f.write_str("history_table"),
            Self::AdvisoryLock => f.write_str("advisory_lock"),
            Self::ApplyMigration => f.write_str("apply_migration"),
            Self::RecordMigration => f.write_str("record_migration"),
            Self::Commit => f.write_str("commit"),
        }
    }
}

/// Error type for schema migration operations.
///
/// There are three failure classes:
///
/// - **Driver errors** — connection failures, SQL syntax errors, constraint
///   violations, or transaction conflicts raised by PostgreSQL during
///   migration execution. Each carries a [`MigrationOperation`] tag
///   identifying which step failed.
///
/// - **Checksum mismatches** — the BLAKE3 hash of an embedded migration's
///   SQL text no longer matches the hash recorded in the
///   `done_ledger_schema_migrations` history table. This catches accidental
///   in-place edits to an already-applied migration file, which would leave
///   the running schema out of sync with the embedded SQL.
///
/// - **Corrupted history records** — the stored checksum blob has an
///   unexpected byte length, indicating data corruption or a manual edit
///   to the migration history table.
#[derive(Debug)]
pub enum DoneLedgerPgMigrationError {
    /// PostgreSQL driver or SQL execution error, tagged with the operation
    /// that failed.
    Postgres {
        /// Which migration step produced the error.
        operation: MigrationOperation,
        /// The underlying driver error.
        source: postgres::Error,
    },
    /// An already-applied migration's embedded SQL has changed since it was
    /// first applied. The `expected_hex` field is the BLAKE3 hash of the
    /// current embedded SQL; `found_hex` is the hash stored in the database
    /// when the migration was first executed.
    ChecksumMismatch {
        /// Version string of the migration with the mismatched checksum.
        version: &'static str,
        /// BLAKE3 hex digest of the embedded SQL text (what the code expects).
        expected_hex: String,
        /// BLAKE3 hex digest recorded in the history table (what was applied).
        found_hex: String,
    },
    /// The stored checksum for an already-applied migration has an unexpected
    /// byte length, indicating data corruption or a manual edit to the
    /// migration history table.
    CorruptedHistoryRecord {
        /// Version string of the migration with the corrupted checksum.
        version: &'static str,
        /// Actual byte length of the stored checksum (expected 32).
        found_len: usize,
    },
}

impl DoneLedgerPgMigrationError {
    /// Wrap a PostgreSQL driver error with the operation that produced it.
    pub(crate) fn postgres(op: MigrationOperation, source: postgres::Error) -> Self {
        Self::Postgres {
            operation: op,
            source,
        }
    }
}

impl fmt::Display for DoneLedgerPgMigrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Postgres {
                operation, source, ..
            } => write!(f, "postgres migration {operation} failed: {source}"),
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

impl Error for DoneLedgerPgMigrationError {
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
    fn migration_operation_display() {
        assert_eq!(MigrationOperation::Connect.to_string(), "connect");
        assert_eq!(MigrationOperation::Configure.to_string(), "configure");
        assert_eq!(
            MigrationOperation::HistoryTable.to_string(),
            "history_table"
        );
        assert_eq!(
            MigrationOperation::AdvisoryLock.to_string(),
            "advisory_lock"
        );
        assert_eq!(
            MigrationOperation::ApplyMigration.to_string(),
            "apply_migration"
        );
        assert_eq!(
            MigrationOperation::RecordMigration.to_string(),
            "record_migration"
        );
        assert_eq!(MigrationOperation::Commit.to_string(), "commit");
    }
}
