//! Canonical table, size-limit, and SQL constants for the PostgreSQL Git
//! persistence schema.
//!
//! All PostgreSQL object names used by this crate are defined here as
//! constants. Backend query code, integration tests, and migration SQL should
//! reference these constants rather than hard-coding name strings, so schema
//! changes stay compiler-visible.

/// Main key/value table storing one opaque value per opaque key.
///
/// Schema defined in `migrations/0001_git_kv.sql`.
pub const GIT_KV_TABLE: &str = "git_kv";

/// History table that records which embedded migrations have been applied,
/// along with their BLAKE3 checksums and application timestamps.
pub const SCHEMA_MIGRATIONS_TABLE: &str = "git_persistence_schema_migrations";

/// Maximum stored key length in bytes.
///
/// Scanner-owned Git persistence keys are expected to remain well below this
/// ceiling; the CHECK constraint exists to catch accidental misuse rather than
/// enforce a fixed-width encoding.
pub const MAX_KEY_OCTETS: usize = 256;

/// Maximum stored value length in bytes.
///
/// Seen bitmaps and checkpoint blobs may grow to multiple MiB, but values
/// larger than this threshold indicate an unexpected persistence payload.
pub const MAX_VALUE_OCTETS: usize = 16 * 1024 * 1024;

/// PostgreSQL advisory-lock key for serialising migration application.
///
/// Fixed 64-bit constant chosen to be unlikely to collide with advisory
/// locks used by other subsystems. The ASCII mnemonic is `"GGPKVM01"`
/// (Gossip-Git-Postgres-Key-Value-Migrations-01). The lock is acquired
/// per-transaction via `pg_advisory_xact_lock`, so it is automatically
/// released when the migration transaction commits or rolls back.
pub const MIGRATION_ADVISORY_LOCK_KEY: i64 = 0x4747504b_564d3031; // "GGPKVM01"

/// Single-key lookup query used by
/// [`GitPersistenceBackend::get`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend::get).
///
/// Bind parameters:
///
/// - `$1::bytea` — opaque key bytes.
///
/// Result shape:
///
/// - zero rows when the key is absent;
/// - one row with the stored `value` when the key exists.
pub const GET_SQL: &str = r#"
SELECT value FROM git_kv
WHERE key = $1
"#;

/// Batch lookup query used by
/// [`GitPersistenceBackend::multi_get`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend::multi_get).
///
/// Bind parameters:
///
/// - `$1::bytea[]` — list of requested keys.
///
/// Result shape:
///
/// - one row per present key (`key`, `value`);
/// - missing keys are omitted;
/// - PostgreSQL may return rows in arbitrary order, so callers restore
///   positional alignment in Rust.
pub const MULTI_GET_SQL: &str = r#"
SELECT key, value FROM git_kv
WHERE key = ANY($1::bytea[])
"#;

/// Bulk upsert query used by
/// [`GitPersistenceBackend::apply_batch`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend::apply_batch).
///
/// Bind parameters:
///
/// - `$1::bytea[]` — key column values;
/// - `$2::bytea[]` — value column values.
///
/// `unnest()` expands the parallel arrays into rows on the server side so the
/// backend can write N `Put` operations in one round-trip. Conflicting keys
/// overwrite the existing value.
pub const UPSERT_SQL: &str = r#"
INSERT INTO git_kv (key, value)
SELECT * FROM unnest($1::bytea[], $2::bytea[])
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
"#;

/// Bulk delete query used by
/// [`GitPersistenceBackend::apply_batch`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend::apply_batch).
///
/// Bind parameters:
///
/// - `$1::bytea[]` — keys to remove.
///
/// Deleting a key that is already absent is a no-op.
pub const DELETE_SQL: &str = r#"
DELETE FROM git_kv
WHERE key = ANY($1::bytea[])
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advisory_lock_key_matches_ascii_mnemonic() {
        let bytes = MIGRATION_ADVISORY_LOCK_KEY.to_be_bytes();
        let ascii = std::str::from_utf8(&bytes).expect("lock key bytes should be valid ASCII");
        assert_eq!(ascii, "GGPKVM01");
    }

    /// All SQL query constants must embed the canonical table name.
    /// This guards against silent drift if the table constant is renamed
    /// but the SQL literals are not updated in lockstep.
    #[test]
    fn sql_constants_reference_canonical_table_name() {
        assert!(
            GET_SQL.contains(GIT_KV_TABLE),
            "GET_SQL must reference the GIT_KV_TABLE constant value"
        );
        assert!(
            MULTI_GET_SQL.contains(GIT_KV_TABLE),
            "MULTI_GET_SQL must reference the GIT_KV_TABLE constant value"
        );
        assert!(
            UPSERT_SQL.contains(GIT_KV_TABLE),
            "UPSERT_SQL must reference the GIT_KV_TABLE constant value"
        );
        assert!(
            DELETE_SQL.contains(GIT_KV_TABLE),
            "DELETE_SQL must reference the GIT_KV_TABLE constant value"
        );
    }
}
