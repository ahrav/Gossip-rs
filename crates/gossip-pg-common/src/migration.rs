//! Shared forward-only embedded migration runner for PostgreSQL backends.
//!
//! PostgreSQL-backed persistence crates compile SQL migrations into the binary
//! and apply them transactionally at startup. This module centralises the
//! shared runner, checksum verification, and error surface so individual
//! backends only need to supply their migration slice plus backend-specific
//! configuration such as the history-table name and advisory-lock key.

use std::{error::Error, fmt, time::Duration};

use blake3::Hash;
use postgres::{Client, Transaction};

/// Known advisory lock keys for PostgreSQL migration runners.
///
/// Each PostgreSQL persistence backend acquires a transaction-scoped advisory
/// lock during migration. Keys must be globally unique within any database
/// instance that hosts multiple gossip-rs backends.
pub const ADVISORY_LOCK_KEYS: &[(&str, i64)] = &[
    ("GSDLPGM1", 0x4753444c_50474d31), // done-ledger
    ("GFPGMIG1", 0x47465047_4d494731), // findings
];

/// Default cap for DDL lock acquisition during migrations.
pub const DEFAULT_MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Backend-specific parameters for the shared migration runner.
///
/// Each PostgreSQL backend keeps its own migration history table and advisory
/// lock key so separate subsystems can coexist in the same database without
/// colliding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MigrationConfig {
    history_table: &'static str,
    advisory_lock_key: i64,
}

impl MigrationConfig {
    /// Build a migration-runner configuration from a history table name and
    /// transaction-scoped advisory lock key.
    #[inline]
    #[must_use]
    pub const fn new(history_table: &'static str, advisory_lock_key: i64) -> Self {
        Self {
            history_table,
            advisory_lock_key,
        }
    }

    /// History table used to record applied migration checksums.
    #[inline]
    #[must_use]
    pub const fn history_table(self) -> &'static str {
        self.history_table
    }

    /// Transaction-scoped advisory lock key that serialises concurrent runners.
    #[inline]
    #[must_use]
    pub const fn advisory_lock_key(self) -> i64 {
        self.advisory_lock_key
    }
}

/// A single forward-only SQL migration compiled into the binary.
///
/// Each migration is identified by a unique `version` string and carries the
/// full SQL text. The [`checksum`](Self::checksum) method produces a BLAKE3
/// digest of the SQL bytes, which the runner records in the history table to
/// detect post-application edits.
///
/// Migrations are forward-only: schema repair happens by appending a new
/// migration, never by mutating or deleting an existing version.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
}

impl EmbeddedMigration {
    /// Create a migration descriptor from a version string and SQL text.
    ///
    /// Both arguments are `'static` because migrations are compiled into the
    /// binary, usually through [`include_str!`].
    #[inline]
    pub const fn new(version: &'static str, sql: &'static str) -> Self {
        Self { version, sql }
    }

    /// Unique version identifier for this migration.
    ///
    /// Used as the primary key in the schema-migration history table.
    #[inline]
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// The full SQL text that this migration executes.
    #[inline]
    #[must_use]
    pub const fn sql(self) -> &'static str {
        self.sql
    }

    /// BLAKE3 digest of the SQL text, used for tamper detection.
    ///
    /// Computed fresh each call because migrations are evaluated only during
    /// process startup or test bootstrap, where recomputation is negligible.
    #[must_use]
    pub fn checksum(self) -> Hash {
        blake3::hash(self.sql.as_bytes())
    }
}

/// Error type for PostgreSQL schema migration operations.
#[derive(Debug)]
pub enum PgMigrationError {
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

impl PgMigrationError {
    /// Wrap a PostgreSQL driver error with the operation that produced it.
    #[must_use]
    pub fn postgres(operation: MigrationOperation, source: postgres::Error) -> Self {
        Self::Postgres { operation, source }
    }
}

impl fmt::Display for PgMigrationError {
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

impl Error for PgMigrationError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Postgres { source, .. } => Some(source),
            Self::ChecksumMismatch { .. } | Self::CorruptedHistoryRecord { .. } => None,
        }
    }
}

/// Labels the migration step that produced a PostgreSQL driver error.
///
/// Paired with a driver error in [`PgMigrationError::Postgres`] to provide
/// structured failure context without losing the underlying cause.
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

/// Build the `CREATE TABLE IF NOT EXISTS` DDL for the migration history table.
///
/// Derives the table name from [`MigrationConfig`] so schema renames stay
/// compiler-visible instead of silently drifting across string literals.
#[must_use]
pub(crate) fn create_migrations_table_sql(config: MigrationConfig) -> String {
    format!(
        r#"
CREATE TABLE IF NOT EXISTS {table} (
    version      TEXT PRIMARY KEY,
    checksum     BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#,
        table = config.history_table()
    )
}

/// Build the `SELECT checksum` query for a single migration version.
#[must_use]
pub(crate) fn select_migration_checksum_sql(config: MigrationConfig) -> String {
    format!(
        "SELECT checksum FROM {table} WHERE version = $1",
        table = config.history_table()
    )
}

/// Build the `INSERT` statement that records a newly-applied migration.
#[must_use]
pub(crate) fn insert_migration_sql(config: MigrationConfig) -> String {
    format!(
        "INSERT INTO {table}(version, checksum) VALUES ($1, $2)",
        table = config.history_table()
    )
}

/// Compare the stored checksum against the embedded migration checksum.
///
/// Returns `Ok(())` on an exact byte match,
/// [`PgMigrationError::CorruptedHistoryRecord`] if the stored blob is not
/// exactly 32 bytes, or [`PgMigrationError::ChecksumMismatch`] if it is
/// 32 bytes long but differs from the expected digest.
pub fn verify_stored_checksum(
    version: &'static str,
    expected_checksum: Hash,
    found_checksum: &[u8],
) -> Result<(), PgMigrationError> {
    if found_checksum == expected_checksum.as_bytes() {
        return Ok(());
    }

    let found_array: [u8; 32] =
        found_checksum
            .try_into()
            .map_err(|_| PgMigrationError::CorruptedHistoryRecord {
                version,
                found_len: found_checksum.len(),
            })?;

    Err(PgMigrationError::ChecksumMismatch {
        version,
        expected_hex: expected_checksum.to_hex().to_string(),
        found_hex: Hash::from_bytes(found_array).to_hex().to_string(),
    })
}

/// Apply all embedded migrations using the default DDL lock timeout.
///
/// Idempotent: already-applied migrations are skipped after checksum
/// verification. Multiple concurrent callers are serialized by the advisory
/// lock, so this is safe to call from parallel startup paths.
///
/// # Errors
///
/// Returns an error if any migration SQL fails or if an already-applied
/// migration's checksum no longer matches the embedded source.
pub fn apply_all_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    config: MigrationConfig,
) -> Result<(), PgMigrationError> {
    apply_migrations(client, migrations, DEFAULT_MIGRATION_LOCK_TIMEOUT, config)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// `lock_timeout` caps how long DDL statements wait for conflicting locks. The
/// timeout is formatted in milliseconds in `SET LOCAL lock_timeout`, so
/// sub-second precision is preserved. Non-zero sub-millisecond durations are
/// clamped to 1ms to prevent silent timeout disabling. A zero duration
/// explicitly disables the timeout.
///
/// ## Transaction protocol
///
/// 1. Begin a transaction.
/// 2. Clear inherited `lock_timeout` so the advisory lock wait is unbounded.
/// 3. Acquire `pg_advisory_xact_lock` to serialize concurrent runners.
/// 4. Set `lock_timeout` so DDL does not block forever on table-level locks.
/// 5. Bootstrap the history table with `CREATE TABLE IF NOT EXISTS`.
/// 6. For each migration: apply if absent, or verify the stored checksum.
/// 7. Commit. On any error PostgreSQL rolls the transaction back.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
    config: MigrationConfig,
) -> Result<(), PgMigrationError> {
    let mut tx = client
        .transaction()
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::Configure, e))?;

    // Clear any inherited session-level lock_timeout so the advisory lock
    // wait is truly unbounded. Pooled or reused connections may carry a
    // non-zero lock_timeout from prior use, and PostgreSQL applies
    // lock_timeout to advisory lock acquisition.
    tx.batch_execute("SET LOCAL lock_timeout = '0'")
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::Configure, e))?;

    // The advisory lock serialises concurrent migration runners (including
    // the very first bootstrap on an empty database). The wait is
    // intentionally unbounded: concurrent startup paths must queue rather
    // than spuriously failing if the DDL timeout budget expires.
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&config.advisory_lock_key()],
    )
    .map_err(|e| PgMigrationError::postgres(MigrationOperation::AdvisoryLock, e))?;

    // Apply the caller's DDL lock_timeout now that serialisation is held.
    // PostgreSQL lock_timeout accepts millisecond values up to i32::MAX (~24.8 days).
    // Clamp non-zero sub-millisecond durations to 1ms so that truncation
    // does not silently disable the timeout (PostgreSQL treats '0ms' as
    // "wait indefinitely").
    let raw_ms = lock_timeout.as_millis();
    let timeout_ms: u128 = if lock_timeout.is_zero() {
        0
    } else if raw_ms == 0 {
        1
    } else {
        raw_ms.min(i32::MAX as u128)
    };
    tx.batch_execute(&format!("SET LOCAL lock_timeout = '{timeout_ms}ms'"))
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::Configure, e))?;

    tx.batch_execute(&create_migrations_table_sql(config))
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::HistoryTable, e))?;
    apply_migration_set(&mut tx, migrations, config)?;
    tx.commit()
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::Commit, e))?;
    Ok(())
}

/// Iterate through a migration slice within an already-locked transaction.
fn apply_migration_set(
    tx: &mut Transaction<'_>,
    migrations: &[EmbeddedMigration],
    config: MigrationConfig,
) -> Result<(), PgMigrationError> {
    let select_sql = select_migration_checksum_sql(config);
    let insert_sql = insert_migration_sql(config);
    for migration in migrations.iter().copied() {
        apply_or_verify_migration(tx, migration, &select_sql, &insert_sql)?;
    }
    Ok(())
}

/// Apply a single migration if it has not been applied, or verify its
/// checksum if it has.
fn apply_or_verify_migration(
    tx: &mut Transaction<'_>,
    migration: EmbeddedMigration,
    select_sql: &str,
    insert_sql: &str,
) -> Result<(), PgMigrationError> {
    let expected_checksum = migration.checksum();
    let version = migration.version();
    let row = tx
        .query_opt(select_sql, &[&version])
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::QueryMigration, e))?;

    if let Some(row) = row {
        let found_checksum: Vec<u8> = row
            .try_get(0)
            .map_err(|e| PgMigrationError::postgres(MigrationOperation::QueryMigration, e))?;
        verify_stored_checksum(version, expected_checksum, &found_checksum)?;
        return Ok(());
    }

    tx.batch_execute(migration.sql())
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::ApplyMigration, e))?;
    let checksum_bytes: &[u8] = expected_checksum.as_bytes();
    tx.execute(insert_sql, &[&version, &checksum_bytes])
        .map_err(|e| PgMigrationError::postgres(MigrationOperation::RecordMigration, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_keys_are_globally_unique() {
        let mut seen_keys = std::collections::HashSet::new();
        let mut seen_labels = std::collections::HashSet::new();
        for &(label, key) in super::ADVISORY_LOCK_KEYS {
            assert!(
                seen_keys.insert(key),
                "duplicate advisory lock key for {label}"
            );
            assert!(
                seen_labels.insert(label),
                "duplicate advisory lock label: {label}"
            );
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

    #[test]
    fn embedded_migration_preserves_version_and_sql() {
        let migration = EmbeddedMigration::new("0001_test", "SELECT 1;");
        assert_eq!(migration.version(), "0001_test");
        assert_eq!(migration.sql(), "SELECT 1;");
    }

    #[test]
    fn checksum_verification_accepts_matching_bytes() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        let checksum = migration.checksum();

        let result = verify_stored_checksum(migration.version(), checksum, checksum.as_bytes());

        assert!(result.is_ok());
    }

    #[test]
    fn checksum_verification_reports_mismatch_with_hex_payloads() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        let checksum = migration.checksum();
        let mut mismatched = checksum.as_bytes().to_vec();
        mismatched[0] ^= 0xFF;

        let error = verify_stored_checksum(migration.version(), checksum, &mismatched)
            .expect_err("mismatched checksum must return an error");

        match error {
            PgMigrationError::ChecksumMismatch {
                version,
                expected_hex,
                found_hex,
            } => {
                assert_eq!(version, "0001");
                assert_eq!(expected_hex.len(), 64);
                assert_eq!(found_hex.len(), 64);
                assert_ne!(expected_hex, found_hex);
            }
            other => panic!("expected ChecksumMismatch, got: {other}"),
        }
    }

    #[test]
    fn corrupted_history_record_on_short_blob() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        let checksum = migration.checksum();

        let error = verify_stored_checksum(migration.version(), checksum, &[0u8; 31])
            .expect_err("31-byte blob must produce CorruptedHistoryRecord");

        match error {
            PgMigrationError::CorruptedHistoryRecord { version, found_len } => {
                assert_eq!(version, "0001");
                assert_eq!(found_len, 31);
            }
            other => panic!("expected CorruptedHistoryRecord, got: {other}"),
        }
    }

    #[test]
    fn corrupted_history_record_on_long_blob() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        let checksum = migration.checksum();

        let error = verify_stored_checksum(migration.version(), checksum, &[0u8; 33])
            .expect_err("33-byte blob must produce CorruptedHistoryRecord");

        match error {
            PgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
                assert_eq!(found_len, 33);
            }
            other => panic!("expected CorruptedHistoryRecord, got: {other}"),
        }
    }

    #[test]
    fn corrupted_history_record_on_empty_blob() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        let checksum = migration.checksum();

        let error = verify_stored_checksum(migration.version(), checksum, &[])
            .expect_err("empty blob must produce CorruptedHistoryRecord");

        match error {
            PgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
                assert_eq!(found_len, 0);
            }
            other => panic!("expected CorruptedHistoryRecord, got: {other}"),
        }
    }

    #[test]
    fn checksum_is_deterministic() {
        let migration = EmbeddedMigration::new("0001", "CREATE TABLE t (id INT);");
        assert_eq!(migration.checksum(), migration.checksum());
    }

    #[test]
    fn checksum_is_32_bytes() {
        let migration = EmbeddedMigration::new("0001", "SELECT 1;");
        assert_eq!(migration.checksum().as_bytes().len(), 32);
    }

    #[test]
    fn checksum_changes_with_sql_content() {
        let first = EmbeddedMigration::new("0001", "SELECT 1;");
        let second = EmbeddedMigration::new("0001", "SELECT 2;");
        assert_ne!(first.checksum(), second.checksum());
    }

    #[test]
    fn create_table_sql_uses_history_table_name() {
        let config = MigrationConfig::new("test_schema_migrations", 1234);
        let sql = create_migrations_table_sql(config);

        assert!(sql.contains("CREATE TABLE IF NOT EXISTS test_schema_migrations"));
        assert!(sql.contains("checksum     BYTEA NOT NULL"));
        assert!(sql.contains("applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()"));
    }

    #[test]
    fn select_sql_uses_history_table_name() {
        let config = MigrationConfig::new("test_schema_migrations", 1234);
        assert_eq!(
            select_migration_checksum_sql(config),
            "SELECT checksum FROM test_schema_migrations WHERE version = $1"
        );
    }

    #[test]
    fn insert_sql_uses_history_table_name() {
        let config = MigrationConfig::new("test_schema_migrations", 1234);
        assert_eq!(
            insert_migration_sql(config),
            "INSERT INTO test_schema_migrations(version, checksum) VALUES ($1, $2)"
        );
    }
}
