//! Shared schema names and SQL fragments for the PostgreSQL done-ledger.

/// Durable done-ledger table name.
pub const DONE_LEDGER_ENTRIES_TABLE: &str = "done_ledger_entries";

/// Migration history table name.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "done_ledger_schema_migrations";

/// Secondary index used for retention scans and tenant-policy diagnostics.
pub const DONE_LEDGER_TENANT_POLICY_SCANNED_AT_INDEX: &str =
    "done_ledger_entries_tenant_policy_scanned_at_idx";

/// Secondary index used for provenance / debugging lookups by run + shard.
pub const DONE_LEDGER_RUN_SHARD_INDEX: &str = "done_ledger_entries_run_shard_idx";

/// Transaction-scoped advisory lock key guarding migration application.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4753_444c_5047_4d31; // "GSDLPGM1"

/// Point-read SQL used by [`crate::DoneLedgerPg::batch_get`].
pub const SELECT_ONE_SQL: &str = r#"
SELECT
    tenant_id,
    policy_hash,
    ovid_hash,
    status,
    bytes_scanned,
    findings_count,
    run_id,
    shard_id,
    fence_epoch,
    started_at,
    finished_at,
    error_code
FROM done_ledger_entries
WHERE tenant_id = $1
  AND policy_hash = $2
  AND ovid_hash = $3
"#;

/// Monotonic UPSERT implementing the `DoneLedgerStatus` lattice.
///
/// The `>=` tie-break intentionally prefers the incoming row, matching
/// `DoneLedgerRecord::merge_with(existing)`.
pub const UPSERT_SQL: &str = r#"
INSERT INTO done_ledger_entries (
    tenant_id,
    policy_hash,
    ovid_hash,
    status,
    bytes_scanned,
    findings_count,
    run_id,
    shard_id,
    fence_epoch,
    started_at,
    finished_at,
    error_code
) VALUES (
    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12
)
ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE SET
    status = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.status
        ELSE done_ledger_entries.status
    END,
    bytes_scanned = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.bytes_scanned
        ELSE done_ledger_entries.bytes_scanned
    END,
    findings_count = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.findings_count
        ELSE done_ledger_entries.findings_count
    END,
    run_id = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.run_id
        ELSE done_ledger_entries.run_id
    END,
    shard_id = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.shard_id
        ELSE done_ledger_entries.shard_id
    END,
    fence_epoch = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.fence_epoch
        ELSE done_ledger_entries.fence_epoch
    END,
    started_at = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.started_at
        ELSE done_ledger_entries.started_at
    END,
    finished_at = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.finished_at
        ELSE done_ledger_entries.finished_at
    END,
    error_code = CASE
        WHEN EXCLUDED.status >= done_ledger_entries.status THEN EXCLUDED.error_code
        ELSE done_ledger_entries.error_code
    END
"#;
