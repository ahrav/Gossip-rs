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
//!    During initial bootstrap (history table does not yet exist),
//!    PostgreSQL's DDL lock on the `CREATE TABLE` provides equivalent
//!    serialization; the advisory lock becomes the primary guard on
//!    subsequent startups when the `CREATE TABLE IF NOT EXISTS` is a no-op.
//! 3. **Checksum gate** — if a version already appears in the history table,
//!    the runner verifies its checksum matches the embedded SQL.
//!    A mismatch produces [`DoneLedgerPgMigrationError::ChecksumMismatch`].
//!
//! All migrations in a single [`apply_migrations`] call run inside one
//! transaction: either every migration succeeds or the entire batch rolls
//! back.
//!
//! [`MIGRATION_ADVISORY_LOCK_KEY`]: crate::schema::MIGRATION_ADVISORY_LOCK_KEY
//! [`DoneLedgerPgMigrationError::ChecksumMismatch`]: crate::DoneLedgerPgMigrationError::ChecksumMismatch

use blake3::Hash;
use postgres::{Client, Transaction};

use crate::{
    DoneLedgerPgMigrationError,
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
/// # Errors
///
/// Returns [`DoneLedgerPgMigrationError::Postgres`] on connection or SQL
/// failure, or [`DoneLedgerPgMigrationError::ChecksumMismatch`] if an
/// already-applied migration's SQL text has changed.
#[cfg(feature = "test-utils")]
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, DoneLedgerPgMigrationError> {
    let mut client = Client::connect(database_url, postgres::NoTls)?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

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
    apply_migrations(client, MIGRATIONS)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// This is the core migration entry-point. [`apply_all_migrations`] delegates
/// here with the crate-level [`MIGRATIONS`] slice. The separate parameter
/// allows tests to supply custom migration sets without mutating the global
/// constant.
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
) -> Result<(), DoneLedgerPgMigrationError> {
    let mut tx = client.transaction()?;

    // Serialize all concurrent migration runners.  Advisory locks are
    // purely in-memory (no table dependency), so this works even during
    // the very first bootstrap when no tables exist yet.  Acquired
    // *before* lock_timeout is set so that legitimate concurrent
    // runners wait as long as needed rather than timing out after 5 s.
    tx.query_one(
        "SELECT pg_advisory_xact_lock($1)",
        &[&MIGRATION_ADVISORY_LOCK_KEY],
    )?;

    // Cap how long DDL statements wait for conflicting locks.  Without
    // this, a future migration that issues ALTER TABLE / CREATE INDEX
    // could block indefinitely if another session holds a conflicting
    // lock, causing a cascading connection-queue stall.  LOCAL scopes
    // the timeout to this transaction only.  Set *after* the advisory
    // lock so the timeout applies only to DDL, not to the advisory
    // lock wait itself.
    tx.batch_execute("SET LOCAL lock_timeout = '5s'")?;

    tx.batch_execute(&create_migrations_table_sql())?;
    apply_migration_set(&mut tx, migrations)?;
    tx.commit()?;
    Ok(())
}

fn apply_migration_set(
    tx: &mut Transaction<'_>,
    migrations: &[EmbeddedMigration],
) -> Result<(), DoneLedgerPgMigrationError> {
    for migration in migrations.iter().copied() {
        apply_or_verify_migration(tx, migration)?;
    }
    Ok(())
}

/// Apply a single migration if it has not been applied, or verify its
/// checksum if it has. The two branches are mutually exclusive within a
/// single advisory-locked transaction, so there is no TOCTOU window.
fn apply_or_verify_migration(
    tx: &mut Transaction<'_>,
    migration: EmbeddedMigration,
) -> Result<(), DoneLedgerPgMigrationError> {
    let expected_checksum = migration.checksum();
    let version = migration.version();
    let select_sql = select_migration_checksum_sql();
    let row = tx.query_opt(&select_sql, &[&version])?;

    if let Some(row) = row {
        // Migration already applied — verify the embedded SQL has not changed.
        let found_checksum: Vec<u8> = row.get(0);
        verify_stored_checksum(version, expected_checksum, &found_checksum)?;
        return Ok(());
    }

    // First application: execute the SQL and record its checksum.
    tx.batch_execute(migration.sql())?;
    let checksum_bytes: &[u8] = expected_checksum.as_bytes();
    let insert_sql = insert_migration_sql();
    tx.execute(&insert_sql, &[&version, &checksum_bytes])?;
    Ok(())
}

/// Compare the BLAKE3 digest stored in the history table against the digest
/// of the embedded SQL. Returns `Ok(())` on match, or a `ChecksumMismatch`
/// error with both digests rendered as hex for diagnostic output.
fn verify_stored_checksum(
    version: &'static str,
    expected_checksum: Hash,
    found_checksum: &[u8],
) -> Result<(), DoneLedgerPgMigrationError> {
    if found_checksum == expected_checksum.as_bytes() {
        return Ok(());
    }

    Err(DoneLedgerPgMigrationError::ChecksumMismatch {
        version,
        expected_hex: expected_checksum.to_hex().to_string(),
        found_hex: encode_hex(found_checksum),
    })
}

/// Lowercase hex encoding for arbitrary byte slices. Used to render the
/// database-side checksum in error messages (the embedded-side checksum
/// uses `blake3::Hash::to_hex` directly).
///
/// Kept as a manual implementation to avoid adding a `hex` crate
/// dependency for a single error-path call site.
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{DoneLedgerPgMigrationError, EmbeddedMigration, verify_stored_checksum};

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
            DoneLedgerPgMigrationError::Postgres(err) => {
                panic!("unexpected Postgres error variant: {err}");
            }
        }
    }
}
