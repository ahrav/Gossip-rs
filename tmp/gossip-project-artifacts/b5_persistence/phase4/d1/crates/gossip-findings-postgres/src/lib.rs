//! PostgreSQL findings persistence schema, migrations, and row projections.
//!
//! This crate packages the findings-side durable relational shape for the Phase
//! V query plane and commit path. The schema is intentionally normalized into
//! three write-path layers that match the current contracts model:
//!
//! 1. `findings`      - stable finding identity, policy-independent
//! 2. `occurrences`   - version + span identity, policy-independent
//! 3. `observations`  - policy-scoped detection/provenance layer
//!
//! The key rule is structural, not stylistic:
//!
//! - `occurrences` MUST NOT contain `policy_hash`
//! - `observations` MUST contain `policy_hash`
//!
//! That keeps the durable schema aligned with the persistence contracts and the
//! Phase V model where policy-scoped state lives in observations rather than in
//! stable finding identity.
//!
//! ## What D1 provides
//!
//! - the D0 schema plan and row projections,
//! - forward-only embedded SQL migrations,
//! - a migration runner with checksum verification and advisory locking,
//! - Postgres BIGINT conversion helpers reused by the future `FindingsSinkPg`.
//!
//! ## What D1 intentionally does not provide yet
//!
//! - the concrete `FindingsSink` backend implementation (D2),
//! - integration tests for replay/dedupe semantics (D3),
//! - query-plane read APIs (D4).

#![forbid(unsafe_code)]

mod error;
mod pg_int;
pub mod migrations;
pub mod schema;

pub use error::{FindingsPgMigrationError, FindingsPgSchemaError};
pub use migrations::{
    EmbeddedMigration, MIGRATIONS, apply_all_migrations, connect_and_apply_migrations,
};
pub use pg_int::{
    PgIntConversionError, pg_i64_bits_to_u64, pg_i64_nonnegative_to_u64, u64_to_pg_i64_bits,
    u64_to_pg_i64_checked,
};
pub use schema::{
    FINDINGS_CANONICAL_UNIQUE_COLUMNS, FINDINGS_COLUMNS, FINDINGS_PRIMARY_KEY_COLUMNS,
    FINDINGS_TABLE, FINDINGS_TENANT_SECRET_HASH_INDEX, FINDINGS_TENANT_STABLE_ITEM_INDEX,
    MIGRATION_ADVISORY_LOCK_KEY, OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS,
    OBSERVATIONS_COLUMNS, OBSERVATIONS_PRIMARY_KEY_COLUMNS, OBSERVATIONS_TABLE,
    OBSERVATIONS_TENANT_OCCURRENCE_INDEX, OBSERVATIONS_TENANT_OVID_INDEX,
    OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX, OBSERVATIONS_TENANT_RUN_SHARD_INDEX,
    OBSERVATIONS_TENANT_SEEN_AT_INDEX, OCCURRENCES_CANONICAL_UNIQUE_COLUMNS,
    OCCURRENCES_COLUMNS, OCCURRENCES_PRIMARY_KEY_COLUMNS, OCCURRENCES_TABLE,
    OCCURRENCES_TENANT_FINDING_INDEX, OCCURRENCES_TENANT_OBJECT_VERSION_INDEX,
    OPTIONAL_SECRET_TRIAGE_PRIMARY_KEY_COLUMNS, OPTIONAL_SECRET_TRIAGE_TABLE,
    SCHEMA_MIGRATIONS_TABLE, FindingRow, FindingsSchemaPlan, ObservationRow, OccurrenceRow,
    ProjectedFindingsBatch,
};
