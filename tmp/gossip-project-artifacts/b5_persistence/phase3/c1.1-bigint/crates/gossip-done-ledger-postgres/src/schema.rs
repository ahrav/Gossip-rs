//! Schema-level constants for the PostgreSQL done-ledger backend.
//!
//! Keeping table/index names in one place prevents string drift between the
//! migration SQL, future backend queries, and integration tests.

/// Durable done-ledger table name.
pub const DONE_LEDGER_ENTRIES_TABLE: &str = "done_ledger_entries";

/// Migration history table name.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "done_ledger_schema_migrations";

/// Hot-path point lookup primary key order.
///
/// This mirrors `gossip_contracts::persistence::DoneLedgerKey`:
/// `(tenant_id, policy_hash, ovid_hash)`.
pub const DONE_LEDGER_PRIMARY_KEY_COLUMNS: &[&str] =
    &["tenant_id", "policy_hash", "ovid_hash"];

/// Secondary index used for tenant+policy age/retention scans.
pub const DONE_LEDGER_TENANT_POLICY_SCANNED_AT_INDEX: &str =
    "done_ledger_entries_tenant_policy_scanned_at_idx";

/// Secondary index used for operational debugging by `(run_id, shard_id)`.
pub const DONE_LEDGER_RUN_SHARD_INDEX: &str = "done_ledger_entries_run_shard_idx";

/// Advisory lock key guarding migration application.
///
/// This is a fixed 64-bit value derived once for the logical namespace
/// `gossip-done-ledger-postgres:migrations`. It prevents two processes from
/// attempting to apply embedded migrations concurrently.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4753444c_50474d31; // "GSDLPGM1"
