//! Canonical table, index, and lock-key constants for the PostgreSQL
//! done-ledger schema.
//!
//! All PostgreSQL object names used by this crate are defined here as
//! constants. Backend query code, integration tests, and migration SQL
//! should reference these constants rather than hard-coding name strings, so
//! that a rename propagates through the compiler instead of hiding as
//! silent drift between SQL and Rust.

/// Main done-ledger table storing one row per `(tenant, policy, object-version)`.
///
/// Schema defined in `migrations/0001_done_ledger_entries.sql`.
pub const DONE_LEDGER_ENTRIES_TABLE: &str = "done_ledger_entries";

/// History table that records which embedded migrations have been applied,
/// along with their BLAKE3 checksums and application timestamps.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "done_ledger_schema_migrations";

/// Primary-key column order for `done_ledger_entries`.
///
/// Mirrors the field order of [`DoneLedgerKey`] from the contracts layer:
/// `(tenant_id, policy_hash, ovid_hash)`. All three are fixed-length 32-byte
/// `BYTEA` columns, so the composite B-tree is prefix-searchable for
/// tenant-scoped and tenant+policy-scoped queries.
///
/// [`DoneLedgerKey`]: gossip_contracts::persistence::DoneLedgerKey
pub const DONE_LEDGER_PRIMARY_KEY_COLUMNS: &[&str] = &["tenant_id", "policy_hash", "ovid_hash"];

/// Index for tenant+policy retention/age scans.
///
/// Covers `(tenant_id, policy_hash, finished_at DESC, ovid_hash)` — the
/// trailing `ovid_hash` makes the index cover the primary-key lookup so
/// that retention scans can operate as index-only scans.
///
/// `finished_at` doubles as the logical "scanned_at" timestamp for
/// retention and scan-history queries. A dedicated `scanned_at` column is
/// intentionally omitted — it would be a physical duplicate of
/// `finished_at` costing 8 bytes per row with no semantic benefit.
pub const DONE_LEDGER_TENANT_POLICY_FINISHED_AT_INDEX: &str =
    "done_ledger_entries_tenant_policy_finished_at_idx";

/// Index for operational debugging by `(run_id, shard_id)`.
///
/// Covers `(run_id, shard_id, tenant_id, policy_hash, ovid_hash)` to
/// support provenance lookups that answer "which rows did a specific
/// pipeline run + shard produce?"
pub const DONE_LEDGER_RUN_SHARD_INDEX: &str = "done_ledger_entries_run_shard_idx";

/// PostgreSQL advisory-lock key for serialising migration application.
///
/// Fixed 64-bit constant chosen to be unlikely to collide with advisory
/// locks used by other subsystems. The ASCII mnemonic is `"GSDLPGM1"`
/// (Gossip-Schema-Done-Ledger-PostGres-Migrations-1). The lock is acquired
/// per-transaction via `pg_advisory_xact_lock`, so it is automatically
/// released when the migration transaction commits or rolls back.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4753444c_50474d31; // "GSDLPGM1"

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_key_matches_ascii_mnemonic() {
        let bytes = MIGRATION_ADVISORY_LOCK_KEY.to_be_bytes();
        let ascii = std::str::from_utf8(&bytes).expect("lock key bytes should be valid ASCII");
        assert_eq!(ascii, "GSDLPGM1");
    }

    #[test]
    fn primary_key_column_order() {
        assert_eq!(
            DONE_LEDGER_PRIMARY_KEY_COLUMNS,
            &["tenant_id", "policy_hash", "ovid_hash"]
        );
    }

    #[test]
    fn table_name_format() {
        assert!(
            DONE_LEDGER_ENTRIES_TABLE.starts_with("done_ledger_"),
            "entries table should use done_ledger_ prefix"
        );
        assert!(
            SCHEMA_MIGRATIONS_TABLE.starts_with("done_ledger_"),
            "migrations table should use done_ledger_ prefix"
        );
    }
}
