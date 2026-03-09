//! Forward-only embedded SQL migrations for the Postgres done-ledger backend.
//!
//! ## Idempotence model
//!
//! Idempotence is enforced by a dedicated migration history table plus an
//! advisory transaction lock:
//!
//! 1. create the history table if needed,
//! 2. take a transaction-scoped advisory lock,
//! 3. check whether each embedded migration version has already been applied,
//! 4. if absent, apply the SQL and record its checksum,
//! 5. if present, require checksum equality.
//!
//! This is stricter than sprinkling `IF NOT EXISTS` through every migration,
//! because it detects in-place edits to an already-published migration file.

use blake3::Hash;
use postgres::{Client, NoTls};

use crate::{DoneLedgerPgMigrationError, schema::MIGRATION_ADVISORY_LOCK_KEY};

const CREATE_MIGRATIONS_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS done_ledger_schema_migrations (
    version      TEXT PRIMARY KEY,
    checksum     BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// One embedded forward-only SQL migration.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
}

impl EmbeddedMigration {
    /// Create a new embedded migration descriptor.
    #[inline]
    pub const fn new(version: &'static str, sql: &'static str) -> Self {
        Self { version, sql }
    }

    /// Stable migration version string.
    #[inline]
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Raw SQL contents.
    #[inline]
    #[must_use]
    pub const fn sql(self) -> &'static str {
        self.sql
    }

    /// BLAKE3 checksum of the SQL bytes.
    #[must_use]
    pub fn checksum(self) -> Hash {
        blake3::hash(self.sql.as_bytes())
    }
}

/// Embedded migration set for the crate.
pub const MIGRATIONS: &[EmbeddedMigration] = &[
    EmbeddedMigration::new(
        "0001_done_ledger_entries",
        include_str!("../migrations/0001_done_ledger_entries.sql"),
    ),
];

/// Connect to Postgres and apply all embedded migrations.
///
/// This is primarily a convenience entry-point for integration tests and local
/// development. Production code may prefer to construct its own [`Client`] and
/// call [`apply_all_migrations`] directly.
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, DoneLedgerPgMigrationError> {
    let mut client = Client::connect(database_url, NoTls)?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

/// Apply all embedded migrations inside one transaction guarded by a
/// transaction-scoped advisory lock.
///
/// Safe to call repeatedly. Already-applied migrations are skipped after
/// checksum verification.
pub fn apply_all_migrations(
    client: &mut Client,
) -> Result<(), DoneLedgerPgMigrationError> {
    let mut tx = client.transaction()?;
    tx.batch_execute(CREATE_MIGRATIONS_TABLE_SQL)?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_ADVISORY_LOCK_KEY])?;

    for migration in MIGRATIONS {
        let expected_checksum = migration.checksum();
        let version = migration.version();
        let row = tx.query_opt(
            "SELECT checksum FROM done_ledger_schema_migrations WHERE version = $1",
            &[&version],
        )?;

        if let Some(row) = row {
            let found: Vec<u8> = row.get(0);
            if found.as_slice() != expected_checksum.as_bytes() {
                return Err(DoneLedgerPgMigrationError::ChecksumMismatch {
                    version: migration.version(),
                    expected_hex: expected_checksum.to_hex().to_string(),
                    found_hex: encode_hex(&found),
                });
            }
            continue;
        }

        tx.batch_execute(migration.sql())?;
        let checksum_bytes: &[u8] = expected_checksum.as_bytes();
        tx.execute(
            "INSERT INTO done_ledger_schema_migrations(version, checksum) VALUES ($1, $2)",
            &[&version, &checksum_bytes],
        )?;
    }

    tx.commit()?;
    Ok(())
}

// Tests intentionally omitted for this task.
// Add integration coverage in C1.3 for:
// - apply_all_migrations() from scratch
// - idempotent second run
// - checksum mismatch detection
// - schema round-trip smoke test against a local Postgres instance

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
