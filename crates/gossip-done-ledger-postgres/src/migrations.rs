//! Forward-only embedded SQL migrations for the Postgres done-ledger backend.
//!
//! This module owns the done-ledger migration slice and configuration, then
//! delegates execution to the shared runner in
//! [`gossip_pg_common::migration`]. The backend therefore keeps its schema SQL
//! and domain-specific assertions while sharing the advisory-lock, checksum,
//! and history-table protocol with other PostgreSQL persistence crates.

use std::time::Duration;

use gossip_pg_common::migration::{
    MigrationConfig, apply_all_migrations as apply_all_pg_migrations,
    apply_migrations as apply_pg_migrations,
};
use postgres::Client;

use crate::{
    DoneLedgerPgMigrationError,
    schema::{MIGRATION_ADVISORY_LOCK_KEY, SCHEMA_MIGRATIONS_TABLE},
};

pub use gossip_pg_common::migration::EmbeddedMigration;

/// Complete ordered set of embedded migrations for this crate.
///
/// Migrations are applied in array order. New migrations must be appended so
/// existing version ordering remains stable across deployments.
pub const MIGRATIONS: &[EmbeddedMigration] = &[EmbeddedMigration::new(
    "0001_done_ledger_entries",
    include_str!("../migrations/0001_done_ledger_entries.sql"),
)];

/// Done-ledger-specific parameters for the shared migration runner.
const MIGRATION_CONFIG: MigrationConfig =
    MigrationConfig::new(SCHEMA_MIGRATIONS_TABLE, MIGRATION_ADVISORY_LOCK_KEY);

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
/// an untrusted network.
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
        .map_err(|e| DoneLedgerPgMigrationError::postgres(crate::MigrationOperation::Connect, e))?;
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
/// Returns an error if any migration SQL fails or if a checksum mismatch
/// is detected for an already-applied migration.
pub fn apply_all_migrations(client: &mut Client) -> Result<(), DoneLedgerPgMigrationError> {
    apply_all_pg_migrations(client, MIGRATIONS, MIGRATION_CONFIG)
}

/// Apply a caller-supplied migration slice inside a single advisory-locked
/// transaction.
///
/// This is the core migration entry-point. [`apply_all_migrations`] delegates
/// here with the crate-level [`MIGRATIONS`] slice. The separate parameter
/// allows tests to supply custom migration sets without mutating the global
/// constant.
///
/// # Errors
///
/// Returns an error on SQL execution failure or checksum mismatch.
pub fn apply_migrations(
    client: &mut Client,
    migrations: &[EmbeddedMigration],
    lock_timeout: Duration,
) -> Result<(), DoneLedgerPgMigrationError> {
    apply_pg_migrations(client, migrations, lock_timeout, MIGRATION_CONFIG)
}

#[cfg(test)]
mod tests {
    use super::MIGRATIONS;

    #[test]
    fn migration_checksums_are_stable() {
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
}
