//! PostgreSQL findings support: schema, migrations, and `u64` ↔ `BIGINT`
//! conversion helpers.
//!
//! The findings persistence contract stores three normalized layers:
//! stable finding identity, version-scoped occurrences, and policy-scoped
//! observations. This crate owns the PostgreSQL-facing pieces needed to map
//! that contract into SQL without yet implementing a concrete
//! [`FindingsSink`](gossip_contracts::persistence::FindingsSink) backend.
//!
//! ## Scope
//!
//! This crate includes:
//!
//! - findings-specific backend, migration, and schema-projection error types
//!   in [`FindingsPgError`], [`FindingsPgMigrationError`], and
//!   [`FindingsPgSchemaError`],
//! - canonical table, column, and index names plus row projections and
//!   write-path SQL constants in [`schema`],
//! - forward-only checksum-verified embedded migrations in [`migrations`],
//! - and `u64` ↔ `BIGINT` conversion helpers in [`types`].
//!
//! The crate deliberately stops at the storage boundary. Write-path batching,
//! query APIs, and backend conformance wiring live in follow-on crates or
//! modules that consume these primitives.
//!
//! ## Path to conformance
//!
//! A concrete PostgreSQL findings backend built on this crate must pass the
//! findings-specific persistence harness
//! ([`run_findings_conformance`](gossip_contracts::persistence::run_findings_conformance)).
//! That harness proves idempotent replay, enforces the occurrence/observation
//! foreign-key shape, and verifies observation-merge semantics under repeated
//! writes.
//!
//! ## `u64` ↔ `BIGINT` storage strategy
//!
//! PostgreSQL has no unsigned 64-bit integer type. The crate therefore uses
//! the same split storage strategy as the sibling Postgres persistence
//! backends:
//!
//! - ordered counters and timestamps use checked non-negative `BIGINT` so SQL
//!   ordering matches the logical ordering seen by Rust callers;
//! - equality-only identifiers use raw bit-pattern `BIGINT` storage so the
//!   full `u64` domain remains available without widening indexes.
//!
//! See [`types`] for the exact conversion rules and error surfaces.

#![forbid(unsafe_code)]

mod error;
pub mod migrations;
pub mod schema;
pub mod types;

pub use error::{
    FindingsPgError, FindingsPgMigrationError, FindingsPgSchemaError, MigrationOperation,
};
#[cfg(feature = "test-utils")]
pub use migrations::connect_and_apply_migrations;
pub use migrations::{EmbeddedMigration, MIGRATIONS, apply_all_migrations, apply_migrations};
pub use schema::{
    FINDINGS_INSERT_SQL, OBSERVATIONS_COUNT_SQL, OBSERVATIONS_INSERT_OR_MERGE_SQL,
    OCCURRENCES_COUNT_SQL, OCCURRENCES_INSERT_SQL, SELECT_FINDINGS_COUNT_SQL, TRUNCATE_ALL_SQL,
};
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};

#[cfg(test)]
mod test_postgres;
#[cfg(test)]
mod tests;
