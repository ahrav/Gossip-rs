//! Forward-only embedded SQL migrations for the Postgres findings backend.
//!
//! Migrations are compiled into the binary via [`include_str!`] and identified
//! by a stable version string (for example `"0001_findings_schema"`). Each
//! migration's SQL is checksummed with BLAKE3 so that in-place edits to an
//! already-applied file are detected at startup rather than silently drifting
//! the running schema away from the embedded source.
//!
//! ## Concurrency and idempotence
//!
//! Multiple processes may race to apply migrations at startup. Safety is
//! ensured by combining three mechanisms:
//!
//! 1. **History table** — `findings_schema_migrations` records every applied
//!    version with its BLAKE3 checksum.
//! 2. **Advisory lock** — a transaction-scoped `pg_advisory_xact_lock` on
//!    [`MIGRATION_ADVISORY_LOCK_KEY`] serialises concurrent migration attempts
//!    so only one transaction mutates the schema at a time. The lock is
//!    acquired before any DDL, so first-boot schema creation and steady-state
//!    checksum verification follow the same serialization rule.
//! 3. **Checksum gate** — if a version already appears in the history table,
//!    the runner verifies its checksum matches the embedded SQL.
//!    A mismatch produces [`FindingsPgMigrationError::ChecksumMismatch`].
//!
//! All migrations in a single [`apply_migrations`] call run inside one
//! transaction: either every migration succeeds or the entire batch rolls back.
//!
//! Because migrations execute inside one transaction, migration SQL must not
//! use commands that require running outside a transaction block (for example
//! `CREATE INDEX CONCURRENTLY`).
//!
//! [`MIGRATION_ADVISORY_LOCK_KEY`]: crate::schema::MIGRATION_ADVISORY_LOCK_KEY
//! [`FindingsPgMigrationError::ChecksumMismatch`]:
//!     crate::FindingsPgMigrationError::ChecksumMismatch

use std::time::Duration;

use blake3::Hash;
use postgres::{Client, Transaction};

use crate::{
    FindingsPgMigrationError, MigrationOperation,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

/// Build the `CREATE TABLE IF NOT EXISTS` DDL for the migration history table.
///
/// Derives the table name from [`SCHEMA_MIGRATIONS_TABLE`] so schema renames
/// stay compiler-visible instead of silently drifting across string literals.
fn create_migrations_table_sql() -> String {
    format!(
        r#"
CREATE TABLE IF NOT EXISTS {table} (
    version      TEXT PRIMARY KEY,
    checksum     BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#,
        table = SCHEMA_MIGRATIONS_TABLE
    )
}

/// Build the `SELECT checksum` query for a single migration version.
fn select_migration_checksum_sql() -> String {
    format!(
        "SELECT checksum FROM {table} WHERE version = $1",
        table = SCHEMA_MIGRATIONS_TABLE
    )
}

/// Build the `INSERT` statement that records a newly-applied migration.
fn insert_migration_sql() -> String {
    format!(
        "INSERT INTO {table}(version, checksum) VALUES ($1, $2)",
        table = SCHEMA_MIGRATIONS_TABLE
    )
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

/// Complete ordered set of embedded migrations for this crate.
///
/// Migrations are applied in array order. New entries must be appended so
/// existing version ordering remains stable across deployments.
pub const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration::new(
    "0001_findings_schema",
    include_str!("../migrations/0001_findings_schema.sql"),
)];

/// Connect to PostgreSQL (plaintext, no TLS) and apply all embedded migrations.
///
/// This convenience wrapper exists for integration tests and local development.
/// Production callers that need TLS or connection pooling should construct
/// their own [`Client`] and call [`apply_all_migrations`] directly.
///
/// # Security
///
/// This function uses `postgres::NoTls`, so it must not be used when the
/// database connection crosses an untrusted network.
///
/// # Errors
///
/// Returns [`FindingsPgMigrationError::Postgres`] on connection or SQL failure,
/// or [`FindingsPgMigrationError::ChecksumMismatch`] if an already-applied
/// migration's embedded SQL no longer matches the recorded checksum.
#[cfg(feature = "test-utils")]
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, FindingsPgMigrationError> {
    let mut client = Client::connect(database_url, postgres::NoTls)
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::Connect, e))?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

/// Default cap for DDL lock acquisition during migrations.
const DEFAULT_MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply all crate-embedded migrations inside a single advisory-locked
/// transaction.
///
/// Idempotent: already-applied migrations are skipped after checksum
/// verification. Multiple concurrent callers are serialized by the advisory
/// lock, so this is safe to call from parallel startup paths.
///
/// # Errors
///
/// Returns an error if any migration SQL fails or if an already-applied
/// migration's checksum no longer matches the embedded source.
pub fn apply_all_migrations(client: &mut Client) -> Result<(), FindingsPgMigrationError> {
    apply_migrations(client, MIGRATIONS, DEFAULT_MIGRATION_LOCK_TIMEOUT)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// This is the core entry point. [`apply_all_migrations`] delegates here with
/// the crate-level [`MIGRATIONS`] slice, while tests can pass ad hoc migration
/// sets without mutating the global constant.
///
/// `lock_timeout` caps how long DDL statements wait for conflicting locks. The
/// timeout is formatted in milliseconds in `SET LOCAL lock_timeout`, so
/// sub-second precision is preserved. A zero duration disables the timeout.
///
/// ## Transaction protocol
///
/// 1. Begin a transaction.
/// 2. Acquire `pg_advisory_xact_lock` to serialize concurrent runners.
/// 3. Set `lock_timeout` so DDL does not block forever on table-level locks.
/// 4. Bootstrap the history table with `CREATE TABLE IF NOT EXISTS`.
/// 5. For each migration: apply if absent, or verify the stored checksum.
/// 6. Commit. On any error PostgreSQL rolls the transaction back.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
) -> Result<(), FindingsPgMigrationError> {
    let mut tx = client
        .transaction()
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::Configure, e))?;

    // The advisory lock is taken before any DDL or timeout configuration so
    // every migration runner follows the same serialization rule, including
    // the very first bootstrap on an empty database.
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&MIGRATION_ADVISORY_LOCK_KEY],
    )
    .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::AdvisoryLock, e))?;

    // `lock_timeout` guards only the DDL path. Advisory-lock waits stay
    // unbounded so concurrent startup paths serialize instead of spuriously
    // failing after the timeout budget expires.
    // PostgreSQL lock_timeout accepts millisecond values up to i32::MAX (~24.8 days).
    let timeout_ms = lock_timeout.as_millis().min(i32::MAX as u128);
    tx.batch_execute(&format!("SET LOCAL lock_timeout = '{timeout_ms}ms'"))
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::Configure, e))?;

    tx.batch_execute(&create_migrations_table_sql())
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::HistoryTable, e))?;
    apply_migration_set(&mut tx, migrations)?;
    tx.commit()
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::Commit, e))?;
    Ok(())
}

/// Iterate through a migration slice within an already-locked transaction.
fn apply_migration_set(
    tx: &mut Transaction<'_>,
    migrations: &[EmbeddedMigration],
) -> Result<(), FindingsPgMigrationError> {
    let select_sql = select_migration_checksum_sql();
    let insert_sql = insert_migration_sql();
    for migration in migrations.iter().copied() {
        apply_or_verify_migration(tx, migration, &select_sql, &insert_sql)?;
    }
    Ok(())
}

/// Apply a single migration if it has not been applied, or verify its
/// checksum if it has.
///
/// Under the advisory lock these branches are mutually exclusive, so there is
/// no time-of-check/time-of-use race between the history-table lookup and the
/// first insertion of a migration record.
fn apply_or_verify_migration(
    tx: &mut Transaction<'_>,
    migration: EmbeddedMigration,
    select_sql: &str,
    insert_sql: &str,
) -> Result<(), FindingsPgMigrationError> {
    let expected_checksum = migration.checksum();
    let version = migration.version();
    let row = tx
        .query_opt(select_sql, &[&version])
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::QueryMigration, e))?;

    if let Some(row) = row {
        let found_checksum: Vec<u8> = row.try_get(0).map_err(|e| {
            FindingsPgMigrationError::postgres(MigrationOperation::QueryMigration, e)
        })?;
        verify_stored_checksum(version, expected_checksum, &found_checksum)?;
        return Ok(());
    }

    tx.batch_execute(migration.sql())
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::ApplyMigration, e))?;
    let checksum_bytes: &[u8] = expected_checksum.as_bytes();
    tx.execute(insert_sql, &[&version, &checksum_bytes])
        .map_err(|e| FindingsPgMigrationError::postgres(MigrationOperation::RecordMigration, e))?;
    Ok(())
}

/// Compare the stored checksum against the embedded migration checksum.
///
/// Returns `Ok(())` on an exact byte match,
/// [`FindingsPgMigrationError::CorruptedHistoryRecord`] if the stored blob is
/// not exactly 32 bytes, or [`FindingsPgMigrationError::ChecksumMismatch`] if
/// it is 32 bytes long but differs from the expected digest.
fn verify_stored_checksum(
    version: &'static str,
    expected_checksum: Hash,
    found_checksum: &[u8],
) -> Result<(), FindingsPgMigrationError> {
    if found_checksum == expected_checksum.as_bytes() {
        return Ok(());
    }

    let found_array: [u8; 32] = found_checksum.try_into().map_err(|_| {
        FindingsPgMigrationError::CorruptedHistoryRecord {
            version,
            found_len: found_checksum.len(),
        }
    })?;

    Err(FindingsPgMigrationError::ChecksumMismatch {
        version,
        expected_hex: expected_checksum.to_hex().to_string(),
        found_hex: Hash::from_bytes(found_array).to_hex().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::schema::{
        FINDINGS_TABLE, FINDINGS_TENANT_SECRET_HASH_INDEX, FINDINGS_TENANT_STABLE_ITEM_ID_INDEX,
        OBSERVATIONS_TABLE, OBSERVATIONS_TENANT_OCCURRENCE_ID_INDEX,
        OBSERVATIONS_TENANT_OVID_HASH_INDEX, OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX,
        OBSERVATIONS_TENANT_RUN_SHARD_INDEX, OBSERVATIONS_TENANT_SEEN_AT_INDEX, OCCURRENCES_TABLE,
        OCCURRENCES_TENANT_FINDING_ID_INDEX, OCCURRENCES_TENANT_OBJECT_VERSION_ID_INDEX,
    };

    use super::{EmbeddedMigration, FindingsPgMigrationError, MIGRATIONS, verify_stored_checksum};

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
            FindingsPgMigrationError::ChecksumMismatch {
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
            FindingsPgMigrationError::CorruptedHistoryRecord { version, found_len } => {
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
            FindingsPgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
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
            FindingsPgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
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
    fn migrations_have_unique_versions_and_nonempty_sql() {
        assert!(!MIGRATIONS.is_empty(), "MIGRATIONS must not be empty");

        let mut seen = HashSet::new();
        for migration in MIGRATIONS {
            assert!(
                !migration.version().is_empty(),
                "migration version must not be empty"
            );
            assert!(
                !migration.sql().is_empty(),
                "migration SQL must not be empty"
            );
            assert!(
                seen.insert(migration.version()),
                "duplicate migration version: {}",
                migration.version()
            );
            assert_eq!(migration.checksum().as_bytes().len(), 32);
        }
    }

    #[test]
    fn migration_checksums_are_stable() {
        let expected: &[(&str, &str)] = &[(
            "0001_findings_schema",
            "0e4db3e9eb0d1755c5ba77931c322c9da182faedfe1957d334e6668f5db7dcdb",
        )];

        assert_eq!(
            expected.len(),
            MIGRATIONS.len(),
            "every embedded migration must have a golden checksum entry"
        );

        for (version, golden_hex) in expected {
            let migration = MIGRATIONS
                .iter()
                .find(|migration| migration.version() == *version)
                .unwrap_or_else(|| panic!("migration {version} not found in MIGRATIONS"));
            let actual_hex = migration.checksum().to_hex().to_string();
            assert_eq!(
                actual_hex, *golden_hex,
                "checksum changed for migration {version} — if this is intentional, \
                 update the golden value"
            );
        }
    }

    #[test]
    fn migration_sql_uses_schema_index_names_and_keeps_policy_hash_out_of_occurrences() {
        let sql = MIGRATIONS[0].sql();

        for table_name in [FINDINGS_TABLE, OCCURRENCES_TABLE, OBSERVATIONS_TABLE] {
            let create_stmt = format!("CREATE TABLE {table_name}");
            assert!(
                sql.contains(&create_stmt),
                "embedded migration must contain `{create_stmt}`"
            );
        }

        for index_name in [
            FINDINGS_TENANT_SECRET_HASH_INDEX,
            FINDINGS_TENANT_STABLE_ITEM_ID_INDEX,
            OCCURRENCES_TENANT_FINDING_ID_INDEX,
            OCCURRENCES_TENANT_OBJECT_VERSION_ID_INDEX,
            OBSERVATIONS_TENANT_SEEN_AT_INDEX,
            OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX,
            OBSERVATIONS_TENANT_OCCURRENCE_ID_INDEX,
            OBSERVATIONS_TENANT_OVID_HASH_INDEX,
            OBSERVATIONS_TENANT_RUN_SHARD_INDEX,
        ] {
            assert!(
                sql.contains(index_name),
                "embedded migration must use schema constant index name {index_name}"
            );
        }

        let occurrences_sql = sql
            .split("CREATE TABLE occurrences")
            .nth(1)
            .and_then(|tail| tail.split("CREATE TABLE observations").next())
            .expect("occurrences table definition must exist");
        assert!(
            !occurrences_sql.contains("policy_hash"),
            "occurrences table must remain policy-independent"
        );

        let observations_sql = sql
            .split("CREATE TABLE observations")
            .nth(1)
            .expect("observations table definition must exist");
        assert!(
            observations_sql.contains("policy_hash      BYTEA  NOT NULL"),
            "observations table must keep policy_hash as a required BYTEA column"
        );
        assert!(
            observations_sql.contains("location_display TEXT")
                && observations_sql.contains("location_url     TEXT"),
            "location fields must remain nullable TEXT columns"
        );
        assert!(
            observations_sql.contains("CONSTRAINT observations_location_display_ck")
                && observations_sql.contains("CONSTRAINT observations_location_url_ck")
                && observations_sql.contains("octet_length(location_display) BETWEEN 1 AND 4096")
                && observations_sql.contains("octet_length(location_url) BETWEEN 1 AND 4096"),
            "location fields must keep their byte-length bounds"
        );
        assert!(
            observations_sql.contains("run_id           BIGINT NOT NULL")
                && observations_sql.contains("shard_id         BIGINT NOT NULL"),
            "run_id and shard_id must remain required BIGINT columns"
        );
        assert!(
            !observations_sql.contains("CHECK (run_id >= 0)")
                && !observations_sql.contains("CHECK (shard_id >= 0)"),
            "run_id and shard_id must not gain non-negative CHECK constraints"
        );
    }
}
