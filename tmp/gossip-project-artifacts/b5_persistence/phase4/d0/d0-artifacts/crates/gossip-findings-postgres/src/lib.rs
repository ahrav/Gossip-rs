//! PostgreSQL findings-backend schema plan for gossip-rs.
//!
//! This crate starts with **D0: schema finalization** for the findings
//! persistence backend. It deliberately stops short of shipping migrations or a
//! concrete [`gossip_contracts::persistence::FindingsSink`] implementation.
//! Those land in later tickets (D1/D2).
//!
//! The goal of D0 is to lock the durable relational shape so later work cannot
//! accidentally reintroduce the old bug where policy-scoped state leaks into
//! occurrence identity.
//!
//! ## Locked model
//!
//! The schema is intentionally normalized into three write-path layers:
//!
//! 1. `findings`      — stable finding identity, policy-independent
//! 2. `occurrences`   — version + span identity, still policy-independent
//! 3. `observations`  — policy-scoped detection/provenance layer
//!
//! The key rule is simple:
//!
//! - `occurrences` **must not** contain `policy_hash`
//! - `observations` **must** contain `policy_hash`
//!
//! That keeps the durable schema aligned with the current contracts model:
//! [`FindingId`](gossip_contracts::identity::FindingId) is stable across policy
//! changes, while [`ObservationId`](gossip_contracts::identity::ObservationId)
//! captures policy-scoped detection events.
//!
//! ## What this crate provides in D0
//!
//! - Canonical table / column / index names for the Postgres backend
//! - Canonical natural-key uniqueness sets for defense-in-depth
//! - Row projection structs with explicit Postgres-friendly primitive types
//! - Batch projection from [`gossip_contracts::persistence::FindingsUpsertBatch`]
//!   after contract-level validation
//! - Shared `u64 <-> BIGINT` conversion helpers reused by later D1/D2 work
//!
//! ## What this crate intentionally does not provide yet
//!
//! - SQL migrations (D1)
//! - Postgres write implementation of `FindingsSink` (D2)
//! - Query-plane rollups / materialized aggregates
//! - User triage state implementation beyond reserving the future table name

#![forbid(unsafe_code)]

mod error;
mod pg_int;
pub mod schema;

pub use error::FindingsPgSchemaError;
pub use pg_int::{
    PgIntConversionError, pg_i64_bits_to_u64, pg_i64_nonnegative_to_u64, u64_to_pg_i64_bits,
    u64_to_pg_i64_checked,
};
pub use schema::{
    FINDINGS_CANONICAL_UNIQUE_COLUMNS, FINDINGS_COLUMNS, FINDINGS_PRIMARY_KEY_COLUMNS,
    FINDINGS_TABLE, FINDINGS_TENANT_SECRET_HASH_INDEX, FINDINGS_TENANT_STABLE_ITEM_INDEX,
    OBSERVATIONS_CANONICAL_UNIQUE_COLUMNS, OBSERVATIONS_COLUMNS,
    OBSERVATIONS_PRIMARY_KEY_COLUMNS, OBSERVATIONS_TABLE,
    OBSERVATIONS_TENANT_OCCURRENCE_INDEX, OBSERVATIONS_TENANT_OVID_INDEX,
    OBSERVATIONS_TENANT_POLICY_SEEN_AT_INDEX, OBSERVATIONS_TENANT_RUN_SHARD_INDEX,
    OCCURRENCES_CANONICAL_UNIQUE_COLUMNS, OCCURRENCES_COLUMNS,
    OCCURRENCES_PRIMARY_KEY_COLUMNS, OCCURRENCES_TABLE, OCCURRENCES_TENANT_FINDING_INDEX,
    OCCURRENCES_TENANT_OBJECT_VERSION_INDEX, OPTIONAL_SECRET_TRIAGE_PRIMARY_KEY_COLUMNS,
    OPTIONAL_SECRET_TRIAGE_TABLE, FindingRow, FindingsSchemaPlan, ObservationRow,
    OccurrenceRow, ProjectedFindingsBatch,
};
