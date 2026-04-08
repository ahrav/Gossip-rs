//! Forward-only embedded SQL migrations for the Postgres Git persistence
//! backend.
//!
//! This module owns the git-persistence-specific migration slice and
//! configuration, then delegates execution to the shared runner in
//! [`gossip_pg_common::migration`]. The advisory-lock, checksum-verification,
//! and history-table protocol are therefore identical across all PostgreSQL
//! backends while this crate still keeps control over its migration versions
//! and schema assertions.

use std::time::Duration;

use gossip_pg_common::migration::{
    MigrationConfig, apply_all_migrations as apply_all_pg_migrations,
    apply_migrations as apply_pg_migrations,
};
use postgres::Client;

use crate::{
    GitPersistencePgMigrationError,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

pub use gossip_pg_common::migration::EmbeddedMigration;

/// Complete ordered set of embedded migrations for this crate.
///
/// Migrations are applied in array order. New entries must be appended so
/// existing version ordering remains stable across deployments.
pub const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration::new(
    "0001_git_kv",
    include_str!("../migrations/0001_git_kv.sql"),
)];

/// Git-persistence-specific parameters for the shared migration runner.
const MIGRATION_CONFIG: MigrationConfig =
    MigrationConfig::new(SCHEMA_MIGRATIONS_TABLE, MIGRATION_ADVISORY_LOCK_KEY);

/// Connect to PostgreSQL (plaintext, no TLS) and apply all embedded
/// migrations.
///
/// This convenience wrapper exists for integration tests and local
/// development. Production callers that need TLS or connection pooling should
/// construct their own [`Client`] and call [`apply_all_migrations`] directly.
///
/// # Security
///
/// This function uses `postgres::NoTls`, so it must not be used when the
/// database connection crosses an untrusted network.
///
/// # Errors
///
/// Returns [`GitPersistencePgMigrationError::Postgres`] on connection or SQL
/// failure, or [`GitPersistencePgMigrationError::ChecksumMismatch`] if an
/// already-applied migration's embedded SQL no longer matches the recorded
/// checksum.
#[cfg(feature = "test-utils")]
pub fn connect_and_apply_migrations(
    database_url: &str,
) -> Result<Client, GitPersistencePgMigrationError> {
    let mut client = Client::connect(database_url, postgres::NoTls).map_err(|e| {
        GitPersistencePgMigrationError::postgres(crate::MigrationOperation::Connect, e)
    })?;
    apply_all_migrations(&mut client)?;
    Ok(client)
}

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
pub fn apply_all_migrations(client: &mut Client) -> Result<(), GitPersistencePgMigrationError> {
    apply_all_pg_migrations(client, MIGRATIONS, MIGRATION_CONFIG)
}

/// Apply a caller-supplied migration slice with a caller-supplied lock
/// timeout inside a single advisory-locked transaction.
///
/// Unlike [`apply_all_migrations`], which uses the crate's default
/// [`MIGRATIONS`] slice and lock timeout, this function accepts both as
/// parameters — useful for tests that pass ad hoc migration sets.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
) -> Result<(), GitPersistencePgMigrationError> {
    apply_pg_migrations(client, migrations, lock_timeout, MIGRATION_CONFIG)
}

#[cfg(test)]
mod tests {
    use crate::schema::{GIT_KV_TABLE, MAX_KEY_OCTETS, MAX_VALUE_OCTETS};

    use super::MIGRATIONS;

    #[test]
    fn migration_checksums_are_stable() {
        let expected: &[(&str, &str)] = &[(
            "0001_git_kv",
            "1c250629e25a495f9b42416deca5f19bc4cb02552a1d0c0cf6c18825b26c4801",
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
    fn migration_sql_uses_schema_table_and_size_constraints() {
        let sql = MIGRATIONS[0].sql();

        let create_stmt = format!("CREATE TABLE {GIT_KV_TABLE}");
        assert!(
            sql.contains(&create_stmt),
            "embedded migration must contain `{create_stmt}`"
        );

        let key_limit = format!("octet_length(key) <= {MAX_KEY_OCTETS}");
        assert!(
            sql.contains(&key_limit),
            "embedded migration must contain `{key_limit}`"
        );

        let value_limit = format!("octet_length(value) <= {MAX_VALUE_OCTETS}");
        assert!(
            sql.contains(&value_limit),
            "embedded migration must contain `{value_limit}`"
        );

        assert_eq!(
            sql.matches("CREATE INDEX").count(),
            0,
            "exact-key git persistence should not create secondary indexes"
        );
    }
}
