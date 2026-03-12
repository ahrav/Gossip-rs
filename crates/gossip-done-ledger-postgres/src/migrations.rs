//! Forward-only embedded SQL migrations for the Postgres done-ledger backend.
//!
//! Migrations are compiled into the binary via [`include_str!`] and identified
//! by a stable version string (e.g. `"0001_done_ledger_entries"`). Each
//! migration's SQL is checksummed with BLAKE3 so that in-place edits to an
//! already-applied file are detected at startup rather than silently diverging
//! the running schema from the embedded source.
//!
//! ## Concurrency and idempotence
//!
//! Multiple processes may race to apply migrations at startup. Safety is
//! ensured by combining three mechanisms:
//!
//! 1. **History table** — `done_ledger_schema_migrations` records every
//!    applied version with its BLAKE3 checksum.
//! 2. **Advisory lock** — a transaction-scoped `pg_advisory_xact_lock` on
//!    [`MIGRATION_ADVISORY_LOCK_KEY`] serialises concurrent migration
//!    attempts so only one transaction mutates the schema at a time.
//!    The advisory lock is acquired before any DDL, so it is the
//!    primary serialization mechanism in all cases — including initial
//!    bootstrap when no tables exist yet (advisory locks are purely
//!    in-memory and have no table dependency).
//! 3. **Checksum gate** — if a version already appears in the history table,
//!    the runner verifies its checksum matches the embedded SQL.
//!    A mismatch produces [`DoneLedgerPgMigrationError::ChecksumMismatch`].
//!
//! All migrations in a single [`apply_migrations`] call run inside one
//! transaction: either every migration succeeds or the entire batch rolls
//! back.
//!
//! Because migrations execute inside one transaction, migration SQL must not
//! use commands that require running outside a transaction block (for example
//! `CREATE INDEX CONCURRENTLY`).
//!
//! [`MIGRATION_ADVISORY_LOCK_KEY`]: crate::schema::MIGRATION_ADVISORY_LOCK_KEY
//! [`DoneLedgerPgMigrationError::ChecksumMismatch`]: crate::DoneLedgerPgMigrationError::ChecksumMismatch

use std::time::Duration;

use blake3::Hash;
use postgres::{Client, Transaction};

use crate::{
    DoneLedgerPgMigrationError, MigrationOperation,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

/// Build the `CREATE TABLE IF NOT EXISTS` DDL for the migration history
/// table.  Derives the table name from [`SCHEMA_MIGRATIONS_TABLE`] so a
/// rename propagates through the compiler rather than silently drifting.
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
/// digest of the SQL bytes, which the migration runner stores alongside the
/// version in the history table to detect post-application edits.
///
/// Migrations are forward-only: there is no rollback/down mechanism. Schema
/// changes that need reversal require a new forward migration.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
}

impl EmbeddedMigration {
    /// Create a migration descriptor from a version string and SQL text.
    ///
    /// Both arguments are `'static` because migrations are compiled-in
    /// constants (typically via [`include_str!`]).
    #[inline]
    pub const fn new(version: &'static str, sql: &'static str) -> Self {
        Self { version, sql }
    }

    /// Unique version identifier for this migration (e.g. `"0001_done_ledger_entries"`).
    ///
    /// Used as the primary key in the `done_ledger_schema_migrations` history
    /// table.
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
    /// Computed fresh each call (no caching) because migrations are applied
    /// at most once per process lifetime.
    #[must_use]
    pub fn checksum(self) -> Hash {
        blake3::hash(self.sql.as_bytes())
    }
}

/// Complete ordered set of embedded migrations for this crate.
///
/// Migrations are applied in array order. New migrations must be appended —
/// never inserted before existing entries — because the runner processes
/// them sequentially and the history table records each version independently.
pub const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration::new(
    "0001_done_ledger_entries",
    include_str!("../migrations/0001_done_ledger_entries.sql"),
)];

/// Connect to PostgreSQL (plaintext, no TLS) and apply all embedded migrations.
///
/// Convenience wrapper that opens a synchronous connection and delegates to
/// [`apply_all_migrations`]. Useful for integration tests and local
/// development where TLS is unnecessary. Production callers that need TLS
/// or connection pooling should construct their own [`Client`] and call
/// [`apply_all_migrations`] directly.
///
/// # Security
///
/// This function connects over plaintext TCP (`NoTls`). It must not be
/// used in production deployments where the database connection traverses
/// an untrusted network. Production callers should construct a TLS-enabled
/// [`Client`] and call [`apply_all_migrations`] directly.
///
/// # Errors
///
/// Returns [`DoneLedgerPgMigrationError::Postgres`] on connection or SQL
/// failure, or [`DoneLedgerPgMigrationError::ChecksumMismatch`] if an
/// already-applied migration's SQL text has changed.
#[cfg(feature = "test-utils")]
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, DoneLedgerPgMigrationError> {
    let mut client = Client::connect(database_url, postgres::NoTls)
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::Connect, e))?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

/// Default cap for DDL lock acquisition during migrations.
const DEFAULT_MIGRATION_LOCK_TIMEOUT: Duration = Duration::from_secs(5);

/// Apply all crate-embedded migrations inside a single advisory-locked
/// transaction.
///
/// Idempotent: already-applied migrations are skipped after checksum
/// verification. Multiple concurrent callers are serialised by the advisory
/// lock, so this is safe to call from parallel startup paths.
///
/// # Errors
///
/// Returns an error if any migration SQL fails or if a checksum mismatch
/// is detected for an already-applied migration.
pub fn apply_all_migrations(client: &mut Client) -> Result<(), DoneLedgerPgMigrationError> {
    apply_migrations(client, MIGRATIONS, DEFAULT_MIGRATION_LOCK_TIMEOUT)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// This is the core migration entry-point. [`apply_all_migrations`] delegates
/// here with the crate-level [`MIGRATIONS`] slice. The separate parameter
/// allows tests to supply custom migration sets without mutating the global
/// constant.
///
/// `lock_timeout` caps how long DDL statements wait for conflicting table-level
/// locks. The timeout is formatted in milliseconds in the `SET LOCAL
/// lock_timeout` statement, so sub-second precision is preserved. A zero
/// duration disables the timeout (Postgres interprets `'0ms'` as "wait
/// indefinitely").
///
/// ## Transaction protocol
///
/// 1. Begin a transaction.
/// 2. Acquire `pg_advisory_xact_lock` to serialise concurrent runners
///    (waits indefinitely — not subject to `lock_timeout`).
/// 3. Set `lock_timeout` to prevent indefinite blocking on DDL locks.
/// 4. `CREATE TABLE IF NOT EXISTS` the history table (idempotent bootstrap).
/// 5. For each migration: apply if absent, or verify checksum if present.
/// 6. Commit. On any error the transaction rolls back automatically.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
) -> Result<(), DoneLedgerPgMigrationError> {
    let mut tx = client
        .transaction()
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::Configure, e))?;

    // Serialize all concurrent migration runners.  Advisory locks are
    // purely in-memory (no table dependency), so this works even during
    // the very first bootstrap when no tables exist yet.  Acquired
    // *before* lock_timeout is set so that legitimate concurrent
    // runners wait as long as needed rather than timing out after 5 s.
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&MIGRATION_ADVISORY_LOCK_KEY],
    )
    .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::AdvisoryLock, e))?;

    // Cap how long DDL statements wait for conflicting locks.  Without
    // this, a future migration that issues ALTER TABLE / CREATE INDEX
    // could block indefinitely if another session holds a conflicting
    // lock, causing a cascading connection-queue stall.  LOCAL scopes
    // the timeout to this transaction only.  Set *after* the advisory
    // lock so the timeout applies only to DDL, not to the advisory
    // lock wait itself.
    let timeout_ms = lock_timeout.as_millis();
    tx.batch_execute(&format!("SET LOCAL lock_timeout = '{timeout_ms}ms'"))
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::Configure, e))?;

    tx.batch_execute(&create_migrations_table_sql())
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::HistoryTable, e))?;
    apply_migration_set(&mut tx, migrations)?;
    tx.commit()
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::Commit, e))?;
    Ok(())
}

/// Iterate through a migration slice within an already-locked transaction,
/// applying or verifying each in order. Pre-builds the SQL strings once
/// so they are reused across migrations.
fn apply_migration_set(
    tx: &mut Transaction<'_>,
    migrations: &[EmbeddedMigration],
) -> Result<(), DoneLedgerPgMigrationError> {
    let select_sql = select_migration_checksum_sql();
    let insert_sql = insert_migration_sql();
    for migration in migrations.iter().copied() {
        apply_or_verify_migration(tx, migration, &select_sql, &insert_sql)?;
    }
    Ok(())
}

/// Apply a single migration if it has not been applied, or verify its
/// checksum if it has. The two branches are mutually exclusive within a
/// single advisory-locked transaction, so there is no TOCTOU window.
fn apply_or_verify_migration(
    tx: &mut Transaction<'_>,
    migration: EmbeddedMigration,
    select_sql: &str,
    insert_sql: &str,
) -> Result<(), DoneLedgerPgMigrationError> {
    let expected_checksum = migration.checksum();
    let version = migration.version();
    let row = tx
        .query_opt(select_sql, &[&version])
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::QueryMigration, e))?;

    if let Some(row) = row {
        // Migration already applied — verify the embedded SQL has not changed.
        let found_checksum: Vec<u8> = row.try_get(0).map_err(|e| {
            DoneLedgerPgMigrationError::postgres(MigrationOperation::QueryMigration, e)
        })?;
        verify_stored_checksum(version, expected_checksum, &found_checksum)?;
        return Ok(());
    }

    // First application: execute the SQL and record its checksum.
    tx.batch_execute(migration.sql())
        .map_err(|e| DoneLedgerPgMigrationError::postgres(MigrationOperation::ApplyMigration, e))?;
    let checksum_bytes: &[u8] = expected_checksum.as_bytes();
    tx.execute(insert_sql, &[&version, &checksum_bytes])
        .map_err(|e| {
            DoneLedgerPgMigrationError::postgres(MigrationOperation::RecordMigration, e)
        })?;
    Ok(())
}

/// Compare the BLAKE3 digest stored in the history table against the digest
/// of the embedded SQL. Returns `Ok(())` on match, `CorruptedHistoryRecord`
/// if the stored blob is not exactly 32 bytes, or `ChecksumMismatch` if it
/// is 32 bytes but differs from the expected digest.
fn verify_stored_checksum(
    version: &'static str,
    expected_checksum: Hash,
    found_checksum: &[u8],
) -> Result<(), DoneLedgerPgMigrationError> {
    if found_checksum == expected_checksum.as_bytes() {
        return Ok(());
    }

    let found_array: [u8; 32] = found_checksum.try_into().map_err(|_| {
        DoneLedgerPgMigrationError::CorruptedHistoryRecord {
            version,
            found_len: found_checksum.len(),
        }
    })?;

    Err(DoneLedgerPgMigrationError::ChecksumMismatch {
        version,
        expected_hex: expected_checksum.to_hex().to_string(),
        found_hex: Hash::from_bytes(found_array).to_hex().to_string(),
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::{
        DoneLedgerPgMigrationError, EmbeddedMigration, MIGRATIONS, verify_stored_checksum,
    };

    // ── verify_stored_checksum ──────────────────────────────────────

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
            DoneLedgerPgMigrationError::ChecksumMismatch {
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
            DoneLedgerPgMigrationError::CorruptedHistoryRecord { version, found_len } => {
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
            DoneLedgerPgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
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
            DoneLedgerPgMigrationError::CorruptedHistoryRecord { found_len, .. } => {
                assert_eq!(found_len, 0);
            }
            other => panic!("expected CorruptedHistoryRecord, got: {other}"),
        }
    }

    // ── checksum properties ─────────────────────────────────────────

    #[test]
    fn checksum_is_deterministic() {
        let m = EmbeddedMigration::new("0001", "CREATE TABLE t (id INT);");
        assert_eq!(m.checksum(), m.checksum());
    }

    #[test]
    fn checksum_is_32_bytes() {
        let m = EmbeddedMigration::new("0001", "SELECT 1;");
        assert_eq!(m.checksum().as_bytes().len(), 32);
    }

    #[test]
    fn checksum_changes_with_sql_content() {
        let a = EmbeddedMigration::new("0001", "SELECT 1;");
        let b = EmbeddedMigration::new("0001", "SELECT 2;");
        assert_ne!(a.checksum(), b.checksum());
    }

    // ── MIGRATIONS array integrity ─────────────────────────────────

    #[test]
    fn migrations_have_unique_versions_and_nonempty_sql() {
        assert!(!MIGRATIONS.is_empty(), "MIGRATIONS must not be empty");

        let mut seen = HashSet::new();
        for m in MIGRATIONS {
            assert!(
                !m.version().is_empty(),
                "migration version must not be empty"
            );
            assert!(!m.sql().is_empty(), "migration SQL must not be empty");
            assert!(
                seen.insert(m.version()),
                "duplicate migration version: {}",
                m.version()
            );
            // Checksum must be computable (not panic) and 32 bytes.
            assert_eq!(m.checksum().as_bytes().len(), 32);
        }
    }

    #[test]
    fn migration_checksums_are_stable() {
        // Golden-value test: pin the BLAKE3 hex for each migration.
        // If a migration's SQL changes, this test will fail, forcing
        // the author to acknowledge the checksum change and update the
        // golden value here.
        let expected: &[(&str, &str)] = &[(
            "0001_done_ledger_entries",
            "d3fa0005a34d48934210df493a5ad56e3e524c9aff33d8498b9fd16bf50cf3b9",
        )];

        assert_eq!(
            expected.len(),
            MIGRATIONS.len(),
            "every embedded migration must have a golden checksum entry"
        );

        for (version, golden_hex) in expected {
            let m = MIGRATIONS
                .iter()
                .find(|m| m.version() == *version)
                .unwrap_or_else(|| panic!("migration {version} not found in MIGRATIONS"));
            let actual_hex = m.checksum().to_hex().to_string();
            assert_eq!(
                actual_hex, *golden_hex,
                "checksum changed for migration {version} — if this is intentional, \
                 update the golden value"
            );
        }
    }

    // ── UPSERT SQL discriminant alignment ───────────────────────────

    #[test]
    fn upsert_sql_case_branches_use_correct_scanned_discriminants() {
        use gossip_contracts::persistence::DoneLedgerStatus;

        let scanned_ranks: Vec<u8> = (0..=u8::MAX)
            .filter_map(|rank| {
                let status = DoneLedgerStatus::from_rank(rank)?;
                status.is_scanned().then_some(rank)
            })
            .collect();

        let upsert = crate::schema::UPSERT_SQL;
        for rank in &scanned_ranks {
            let needle = format!("= {rank}");
            assert!(
                upsert.contains(&needle),
                "UPSERT_SQL must reference scanned rank {rank} in a CASE branch, \
                 but no `= {rank}` found"
            );
        }
    }

    /// Verify that the Rust lattice merge is equivalent to `max(rank)` for
    /// all status pairs, which is the semantic contract that lets the SQL
    /// `GREATEST(EXCLUDED.status, done_ledger_entries.status)` expression
    /// produce identical results.
    #[test]
    fn rust_status_merge_is_equivalent_to_max_on_ranks() {
        use gossip_contracts::persistence::DoneLedgerStatus;

        let all_ranks: Vec<u8> = (0..=u8::MAX)
            .filter(|&rank| DoneLedgerStatus::from_rank(rank).is_some())
            .collect();

        for &a_rank in &all_ranks {
            let a = DoneLedgerStatus::from_rank(a_rank).unwrap();
            for &b_rank in &all_ranks {
                let b = DoneLedgerStatus::from_rank(b_rank).unwrap();
                assert_eq!(
                    a.merge(b).rank(),
                    a_rank.max(b_rank),
                    "Rust lattice merge must equal max(rank) for ({a:?}, {b:?})"
                );
            }
        }
    }

    /// Guard that `UPSERT_SQL` uses `GREATEST` for the status merge column.
    /// Without this, the Rust-side max-on-ranks equivalence (tested above)
    /// would not be enough — someone could change the SQL to use a different
    /// expression without breaking the Rust test.
    #[test]
    fn upsert_sql_uses_greatest_for_status_merge() {
        let upsert = crate::schema::UPSERT_SQL;
        assert!(
            upsert.contains("GREATEST(EXCLUDED.status, done_ledger_entries.status)"),
            "UPSERT_SQL must merge status via GREATEST(EXCLUDED.status, \
             done_ledger_entries.status)"
        );
    }

    // ── SQL/Rust status discriminant alignment ──────────────────────

    #[test]
    fn sql_status_discriminants_match_rust_enum() {
        use gossip_contracts::persistence::DoneLedgerStatus;

        // These are the exact discriminant values used in the SQL CHECK
        // constraint: `status IN (1, 2, 3, 10, 11)`.
        let sql_discriminants: &[u8] = &[1, 2, 3, 10, 11];

        // Every SQL discriminant must round-trip through from_rank.
        for &rank in sql_discriminants {
            assert!(
                DoneLedgerStatus::from_rank(rank).is_some(),
                "SQL discriminant {rank} has no matching DoneLedgerStatus variant"
            );
        }

        // Derive the full Rust variant set from from_rank() so this test
        // automatically catches new variants without a manual list update.
        let rust_ranks: Vec<u8> = (0..=u8::MAX)
            .filter(|&rank| DoneLedgerStatus::from_rank(rank).is_some())
            .collect();

        assert_eq!(
            sql_discriminants,
            rust_ranks.as_slice(),
            "SQL CHECK constraint discriminants drifted from DoneLedgerStatus::from_rank"
        );
    }
}
