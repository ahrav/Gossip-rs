//! Error types for the PostgreSQL done-ledger migration subsystem.
//!
//! All errors produced during schema migration are funneled through
//! [`DoneLedgerPgMigrationError`], which distinguishes between transport/SQL
//! failures and migration-integrity violations. The `From<postgres::Error>`
//! impl allows `?` propagation from any driver call inside a migration
//! transaction.

use std::{error::Error, fmt};

/// Error type for schema migration operations.
///
/// There are two failure classes:
///
/// - **Driver errors** — connection failures, SQL syntax errors, constraint
///   violations, or transaction conflicts raised by PostgreSQL during
///   migration execution.
///
/// - **Checksum mismatches** — the BLAKE3 hash of an embedded migration's
///   SQL text no longer matches the hash recorded in the
///   `done_ledger_schema_migrations` history table. This catches accidental
///   in-place edits to an already-applied migration file, which would leave
///   the running schema out of sync with the embedded SQL.
#[derive(Debug)]
pub enum DoneLedgerPgMigrationError {
    /// PostgreSQL driver or SQL execution error.
    Postgres(postgres::Error),
    /// An already-applied migration's embedded SQL has changed since it was
    /// first applied. The `expected_hex` field is the BLAKE3 hash of the
    /// current embedded SQL; `found_hex` is the hash stored in the database
    /// from the original application.
    ChecksumMismatch {
        /// Version string of the migration with the mismatched checksum.
        version: &'static str,
        /// BLAKE3 hex digest of the embedded SQL text (what the code expects).
        expected_hex: String,
        /// BLAKE3 hex digest recorded in the history table (what was applied).
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
}
