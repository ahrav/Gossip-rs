//! Forward-only embedded SQL migrations for the Postgres findings backend.
//!
//! Idempotence is enforced by a migration history table plus a transaction-
//! scoped advisory lock:
//!
//! 1. ensure the history table exists,
//! 2. take the advisory lock,
//! 3. compare embedded checksums against recorded checksums,
//! 4. apply only missing migrations,
//! 5. commit atomically.

use blake3::Hash;
use postgres::{Client, NoTls};

use crate::{
    error::FindingsPgMigrationError,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

const CREATE_MIGRATIONS_TABLE_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS findings_schema_migrations (
    version      TEXT PRIMARY KEY,
    checksum     BYTEA NOT NULL CHECK (octet_length(checksum) = 32),
    applied_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

/// One embedded forward-only migration.
#[derive(Clone, Copy, Debug)]
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
}

impl EmbeddedMigration {
    #[inline]
    pub const fn new(version: &'static str, sql: &'static str) -> Self {
        Self { version, sql }
    }

    #[inline]
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    #[inline]
    #[must_use]
    pub const fn sql(self) -> &'static str {
        self.sql
    }

    #[must_use]
    pub fn checksum(self) -> Hash {
        blake3::hash(self.sql.as_bytes())
    }
}

/// Embedded migration set for the crate.
pub const MIGRATIONS: &[EmbeddedMigration] = &[
    EmbeddedMigration::new(
        "0001_findings_schema",
        include_str!("../migrations/0001_findings_schema.sql"),
    ),
];

/// Convenience entrypoint: connect to Postgres and apply all migrations.
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, FindingsPgMigrationError> {
    let mut client = Client::connect(database_url, NoTls)?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

/// Apply all embedded migrations under a transaction-scoped advisory lock.
pub fn apply_all_migrations(client: &mut Client) -> Result<(), FindingsPgMigrationError> {
    let mut tx = client.transaction()?;
    tx.batch_execute(CREATE_MIGRATIONS_TABLE_SQL)?;
    tx.query_one("SELECT pg_advisory_xact_lock($1)", &[&MIGRATION_ADVISORY_LOCK_KEY])?;

    for migration in MIGRATIONS {
        let row = tx.query_opt(
            "SELECT checksum FROM findings_schema_migrations WHERE version = $1",
            &[&migration.version()],
        )?;
        let expected = migration.checksum();

        if let Some(row) = row {
            let found: Vec<u8> = row.get(0);
            if found.as_slice() != expected.as_bytes() {
                return Err(FindingsPgMigrationError::ChecksumMismatch {
                    version: migration.version(),
                    expected_hex: expected.to_hex().to_string(),
                    found_hex: hex_encode(&found),
                });
            }
            continue;
        }

        tx.batch_execute(migration.sql())?;
        let checksum: &[u8] = expected.as_bytes();
        tx.execute(
            "INSERT INTO findings_schema_migrations(version, checksum) VALUES ($1, $2)",
            &[&migration.version(), &checksum],
        )?;
    }

    tx.commit()?;
    Ok(())
}

/// Return the logical migration history table name.
#[inline]
#[must_use]
pub const fn schema_migrations_table() -> &'static str {
    SCHEMA_MIGRATIONS_TABLE
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}
