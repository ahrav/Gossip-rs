//! PostgreSQL-backed findings persistence backend, schema, and migrations.
//!
//! This crate owns the durable write-path for the Phase V findings model:
//!
//! 1. `findings`      - stable identity, policy-independent
//! 2. `occurrences`   - version + span identity, policy-independent
//! 3. `observations`  - policy-scoped detection / provenance layer
//!
//! The concrete [`FindingsSinkPg`] backend writes those layers in-order inside a
//! single PostgreSQL transaction:
//!
//! - findings first,
//! - then occurrences,
//! - then observations.
//!
//! That ordering matches the foreign-key graph and keeps failure atomic.
//!
//! ## Idempotency model
//!
//! - `findings` and `occurrences` are immutable-by-identity: replays succeed and
//!   do not duplicate rows.
//! - `observations` are policy-scoped upserts: replaying the same observation
//!   merges metadata (`seen_at`, `run_id`, `shard_id`, `fence_epoch`, optional
//!   safe location) rather than inserting duplicates.
//!
//! ## Why this crate is synchronous in the MVP
//!
//! `postgres::Client` is synchronous and `!Sync`, so the backend wraps a single
//! client in `Arc<Mutex<_>>`. That is deliberate: returning a
//! [`ReadyCommitHandle`](gossip_contracts::persistence::ReadyCommitHandle)
//! only after the SQL transaction commits preserves the persistence contract's
//! “no early ACK” rule.

#![forbid(unsafe_code)]

mod backend;
mod error;
mod pg_int;
mod read_api;
pub mod migrations;
pub mod schema;

pub use backend::FindingsSinkPg;
pub use error::{FindingsPgError, FindingsPgMigrationError, FindingsPgSchemaError};
pub use migrations::{
    EmbeddedMigration, MIGRATIONS, apply_all_migrations, connect_and_apply_migrations,
};
pub use pg_int::{
    PgIntConversionError, pg_i64_bits_to_u64, pg_i64_nonnegative_to_u64, u64_to_pg_i64_bits,
    u64_to_pg_i64_checked,
};
pub use schema::{
    FINDINGS_CANONICAL_UNIQUE_COLUMNS, FINDINGS_COLUMNS, FINDINGS_INSERT_SQL,
    FINDINGS_PRIMARY_KEY_COLUMNS, FINDINGS_TABLE, FINDINGS_TENANT_SECRET_HASH_INDEX,
    FINDINGS_TENANT_STABLE_ITEM_INDEX, MIGRATION_ADVISORY_LOCK_KEY,
    OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS, OBSERVATIONS_COLUMNS, OBSERVATIONS_COUNT_SQL,
    OBSERVATIONS_INSERT_OR_MERGE_SQL, OBSERVATIONS_PRIMARY_KEY_COLUMNS, OBSERVATIONS_TABLE,
    OBSERVATIONS_TENANT_OCCURRENCE_INDEX, OBSERVATIONS_TENANT_OVID_INDEX,
    OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX, OBSERVATIONS_TENANT_RUN_SHARD_INDEX,
    OBSERVATIONS_TENANT_SEEN_AT_INDEX, OCCURRENCES_CANONICAL_UNIQUE_COLUMNS,
    OCCURRENCES_COLUMNS, OCCURRENCES_COUNT_SQL, OCCURRENCES_INSERT_SQL,
    OCCURRENCES_PRIMARY_KEY_COLUMNS, OCCURRENCES_TABLE, OCCURRENCES_TENANT_FINDING_INDEX,
    OCCURRENCES_TENANT_OBJECT_VERSION_INDEX, OPTIONAL_SECRET_TRIAGE_PRIMARY_KEY_COLUMNS,
    OPTIONAL_SECRET_TRIAGE_TABLE, SCHEMA_MIGRATIONS_TABLE, SELECT_FINDINGS_COUNT_SQL,
    COUNT_OBSERVATIONS_BY_TENANT_POLICY_SQL, LIST_FINDINGS_NEEDING_TRIAGE_SQL,
    FindingRow, FindingsSchemaPlan, ObservationRow, OccurrenceRow, ProjectedFindingsBatch,
    TRUNCATE_ALL_SQL,
};

pub use read_api::{ObservationCountByPolicy, PendingTriageFinding};
