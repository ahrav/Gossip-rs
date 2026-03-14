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

/// Positional `batch_get` query used by [`crate::DoneLedgerPg`].
///
/// Uses `ANY($3::bytea[])` so one round-trip can fetch all requested
/// object-version hashes. PostgreSQL returns matching rows in arbitrary
/// order; the Rust caller restores positional alignment by indexing the
/// result set into a `HashMap<OvidHash, DoneLedgerRecord>` and projecting
/// back onto the input slice.
pub const BATCH_GET_SQL: &str = r#"
SELECT
    tenant_id,
    policy_hash,
    ovid_hash,
    status,
    bytes_scanned,
    findings_count,
    fence_epoch,
    started_at,
    finished_at,
    run_id,
    shard_id,
    error_code
FROM done_ledger_entries
WHERE tenant_id = $1
  AND policy_hash = $2
  AND ovid_hash = ANY($3::bytea[])
"#;

/// Bulk monotonic done-ledger UPSERT used by [`crate::DoneLedgerPg`].
///
/// Accepts 12 array parameters (one per column) and uses `unnest()` to
/// expand them into rows. This sends a single SQL statement per batch
/// regardless of batch size, avoiding the per-row round-trip cost of a
/// loop-based approach and sidestepping the PostgreSQL 65,535 bind-parameter
/// limit that a dynamic multi-row `VALUES` clause would hit at ~5,400 rows.
///
/// Merge behavior mirrors the in-memory reference backend so that the
/// Rust [`DoneLedgerRecord::merge`](gossip_contracts::persistence::DoneLedgerRecord::merge) method and the SQL `ON CONFLICT`
/// clause produce identical results for the same inputs:
///
/// - **Status** — lattice-merged via `GREATEST` (higher rank = more
///   terminal state). Status discriminants used in the SQL:
///   - `10` = `ScannedClean` (resets `findings_count` to 0)
///   - `11` = `ScannedWithFindings` (clamps `findings_count >= 1`)
///   - `1`, `2`, `3` = non-scanned states (keep `findings_count` max)
/// - **`bytes_scanned`** — non-regressing (`GREATEST`)
/// - **`findings_count`** — status-aware: reset, floor, or max depending
///   on the merged status (see the `CASE` expression)
/// - **Provenance** (`run_id`, `shard_id`, `fence_epoch`, `started_at`,
///   `finished_at`) — winner is selected by status rank, then
///   `finished_at`, then `started_at` (three-way tie-break)
/// - **`error_code`** — cleared (`NULL`) when merged status is scanned;
///   otherwise taken from the provenance winner, falling back to the
///   loser's error code via `COALESCE`
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
)
SELECT * FROM unnest(
    $1::bytea[],
    $2::bytea[],
    $3::bytea[],
    $4::smallint[],
    $5::bigint[],
    $6::int[],
    $7::bigint[],
    $8::bigint[],
    $9::bigint[],
    $10::bigint[],
    $11::bigint[],
    $12::text[]
)
ON CONFLICT (tenant_id, policy_hash, ovid_hash) DO UPDATE SET
    status = GREATEST(EXCLUDED.status, done_ledger_entries.status),
    bytes_scanned = GREATEST(EXCLUDED.bytes_scanned, done_ledger_entries.bytes_scanned),
    findings_count = CASE
        WHEN GREATEST(EXCLUDED.status, done_ledger_entries.status) = 10 THEN 0
        WHEN GREATEST(EXCLUDED.status, done_ledger_entries.status) = 11 THEN
            GREATEST(EXCLUDED.findings_count, done_ledger_entries.findings_count, 1)
        ELSE GREATEST(EXCLUDED.findings_count, done_ledger_entries.findings_count)
    END,
    -- Provenance-winner predicate (status rank > finished_at > started_at) is
    -- repeated per column because ON CONFLICT DO UPDATE SET does not support
    -- CTEs or local variables. All 6 CASE arms MUST use the identical condition
    -- so every provenance field is sourced from the same winner. Edits to one
    -- CASE branch must be mirrored in all others. The Rust-side function
    -- DoneLedgerRecord::merge must remain in exact parity with this logic.
    run_id = CASE
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN EXCLUDED.run_id
        ELSE done_ledger_entries.run_id
    END,
    shard_id = CASE
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN EXCLUDED.shard_id
        ELSE done_ledger_entries.shard_id
    END,
    fence_epoch = CASE
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN EXCLUDED.fence_epoch
        ELSE done_ledger_entries.fence_epoch
    END,
    started_at = CASE
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN EXCLUDED.started_at
        ELSE done_ledger_entries.started_at
    END,
    finished_at = CASE
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN EXCLUDED.finished_at
        ELSE done_ledger_entries.finished_at
    END,
    error_code = CASE
        WHEN GREATEST(EXCLUDED.status, done_ledger_entries.status) IN (10, 11) THEN NULL
        WHEN (
            EXCLUDED.status > done_ledger_entries.status
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at > done_ledger_entries.finished_at
            )
            OR (
                EXCLUDED.status = done_ledger_entries.status
                AND EXCLUDED.finished_at = done_ledger_entries.finished_at
                AND EXCLUDED.started_at > done_ledger_entries.started_at
            )
        ) THEN COALESCE(EXCLUDED.error_code, done_ledger_entries.error_code)
        ELSE COALESCE(done_ledger_entries.error_code, EXCLUDED.error_code)
    END
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_key_matches_ascii_mnemonic() {
        let bytes = MIGRATION_ADVISORY_LOCK_KEY.to_be_bytes();
        let ascii = std::str::from_utf8(&bytes).expect("lock key bytes should be valid ASCII");
        assert_eq!(ascii, "GSDLPGM1");
    }

    /// Both SQL query constants must embed the canonical table name.
    /// This guards against silent drift if the table constant is renamed
    /// but the SQL literals are not updated in lockstep.
    #[test]
    fn sql_constants_reference_canonical_table_name() {
        assert!(
            BATCH_GET_SQL.contains(DONE_LEDGER_ENTRIES_TABLE),
            "BATCH_GET_SQL must reference the DONE_LEDGER_ENTRIES_TABLE constant value"
        );
        assert!(
            UPSERT_SQL.contains(DONE_LEDGER_ENTRIES_TABLE),
            "UPSERT_SQL must reference the DONE_LEDGER_ENTRIES_TABLE constant value"
        );
    }
}
