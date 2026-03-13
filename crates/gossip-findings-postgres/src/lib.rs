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
//! - Rust-side batch projection, tenant validation, duplicate folding, and
//!   observation-merge helpers in `backend`,
//! - forward-only checksum-verified embedded migrations in [`migrations`],
//! - and `u64` ↔ `BIGINT` conversion helpers in [`types`].
//!
//! The crate deliberately stops short of a concrete
//! [`FindingsSink`](gossip_contracts::persistence::FindingsSink)
//! implementation. It provides the schema, migrations, conversion helpers,
//! and Rust-side write-path preprocessing that a backend can compose into an
//! actual sink.
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

mod backend;
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
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};

#[cfg(test)]
mod test_postgres;
#[cfg(test)]
mod tests;
