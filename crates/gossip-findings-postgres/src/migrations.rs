//! Forward-only embedded SQL migrations for the Postgres findings backend.
//!
//! This module owns the findings-specific migration slice and configuration,
//! then delegates execution to the shared runner in
//! [`gossip_pg_common::migration`]. The advisory-lock, checksum-verification,
//! and history-table protocol are therefore identical across all PostgreSQL
//! backends while the findings crate still keeps control over its migration
//! versions and schema assertions.

use std::time::Duration;

use gossip_pg_common::migration::{
    MigrationConfig, apply_all_migrations as apply_all_pg_migrations,
    apply_migrations as apply_pg_migrations,
};
use postgres::Client;

use crate::{
    FindingsPgMigrationError,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

pub use gossip_pg_common::migration::EmbeddedMigration;

/// Complete ordered set of embedded migrations for this crate.
///
/// Migrations are applied in array order. New entries must be appended so
/// existing version ordering remains stable across deployments.
pub const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration::new(
    "0001_findings_schema",
    include_str!("../migrations/0001_findings_schema.sql"),
)];

/// Findings-specific parameters for the shared migration runner.
const MIGRATION_CONFIG: MigrationConfig =
    MigrationConfig::new(SCHEMA_MIGRATIONS_TABLE, MIGRATION_ADVISORY_LOCK_KEY);

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
        .map_err(|e| FindingsPgMigrationError::postgres(crate::MigrationOperation::Connect, e))?;
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
pub fn apply_all_migrations(client: &mut Client) -> Result<(), FindingsPgMigrationError> {
    apply_all_pg_migrations(client, MIGRATIONS, MIGRATION_CONFIG)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// This is the core entry point. [`apply_all_migrations`] delegates here with
/// the crate-level [`MIGRATIONS`] slice, while tests can pass ad hoc migration
/// sets without mutating the global constant.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
) -> Result<(), FindingsPgMigrationError> {
    apply_pg_migrations(client, migrations, lock_timeout, MIGRATION_CONFIG)
}

#[cfg(test)]
mod tests {
    use crate::schema::{
        FINDINGS_TABLE, FINDINGS_TENANT_SECRET_HASH_INDEX, FINDINGS_TENANT_STABLE_ITEM_ID_INDEX,
        OBSERVATIONS_TABLE, OBSERVATIONS_TENANT_OCCURRENCE_ID_INDEX,
        OBSERVATIONS_TENANT_OVID_HASH_INDEX, OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX,
        OBSERVATIONS_TENANT_RUN_SHARD_INDEX, OBSERVATIONS_TENANT_SEEN_AT_INDEX, OCCURRENCES_TABLE,
        OCCURRENCES_TENANT_FINDING_ID_INDEX, OCCURRENCES_TENANT_OBJECT_VERSION_ID_INDEX,
    };

    use super::MIGRATIONS;

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

        assert!(
            !sql.contains("UNIQUE (tenant_id, policy_hash, occurrence_id)"),
            "occurrence identity must not include policy_hash"
        );
    }
}
