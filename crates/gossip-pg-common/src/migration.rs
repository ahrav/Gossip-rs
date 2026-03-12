//! Migration-operation taxonomy shared by all PostgreSQL migration runners.
//!
//! Each variant of [`MigrationOperation`] labels a discrete step in the
//! migration transaction so that driver errors carry structured context
//! identifying *where* the failure occurred.

use std::fmt;

/// Known advisory lock keys for PostgreSQL migration runners.
///
/// Each PostgreSQL persistence backend acquires a transaction-scoped advisory
/// lock during migration. Keys must be globally unique within any database
/// instance that hosts multiple gossip-rs backends.
pub const ADVISORY_LOCK_KEYS: &[(&str, i64)] = &[
    ("GSDLPGM1", 0x4753444c_50474d31), // done-ledger
    ("GFPGMIG1", 0x47465047_4d494731), // findings
];

/// Labels the migration step that produced a PostgreSQL driver error.
///
/// Paired with a driver error in a crate-specific migration error type
/// (e.g. `DoneLedgerPgMigrationError::Postgres`) to provide structured
/// failure context without losing the underlying cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// Querying the migration history table for an existing record.
    QueryMigration,
    /// Inserting a newly-applied migration record into the history table.
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
            Self::QueryMigration => f.write_str("query_migration"),
            Self::RecordMigration => f.write_str("record_migration"),
            Self::Commit => f.write_str("commit"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_keys_are_globally_unique() {
        let mut seen = std::collections::HashSet::new();
        for &(label, key) in super::ADVISORY_LOCK_KEYS {
            assert!(seen.insert(key), "duplicate advisory lock key for {label}");
        }
    }

    #[test]
    fn migration_operation_display_matches_sql_step_names() {
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
            MigrationOperation::QueryMigration.to_string(),
            "query_migration"
        );
        assert_eq!(
            MigrationOperation::RecordMigration.to_string(),
            "record_migration"
        );
        assert_eq!(MigrationOperation::Commit.to_string(), "commit");
    }
}
