//! PostgreSQL findings backend, schema, migrations, and `u64` ↔ `BIGINT`
//! conversion helpers.
//!
//! The findings persistence contract stores three normalized layers:
//! stable finding identity, version-scoped occurrences, and policy-scoped
//! observations. This crate owns both the PostgreSQL-facing schema/migration
//! pieces and the concrete [`FindingsSinkPg`] backend that maps the
//! contracts-layer model into SQL.
//!
//! ## Scope
//!
//! This crate includes:
//!
//! - the concrete [`FindingsSinkPg`] implementation of
//!   [`FindingsSink`](gossip_contracts::persistence::FindingsSink),
//! - findings-specific backend, migration, and schema-projection error types
//!   in [`FindingsPgError`], [`FindingsPgMigrationError`], and
//!   [`FindingsPgSchemaError`],
//! - canonical table, column, and index names plus write- and read-path SQL
//!   constants in [`schema`],
//! - Rust-side batch projection, tenant validation, duplicate folding, and
//!   observation-merge helpers in `backend`,
//! - typed result rows for the current query-plane surface in [`read_api`],
//! - forward-only checksum-verified embedded migrations in [`migrations`],
//! - and `u64` ↔ `BIGINT` conversion helpers in [`types`].
//!
//! Production callers typically provide their own TLS-enabled
//! [`postgres::Client`] and construct [`FindingsSinkPg`] via
//! [`FindingsSinkPg::from_client`]. The `test-utils` feature additionally
//! exposes plaintext convenience constructors for local development and test
//! setups.
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
pub mod read_api;
pub mod schema;
pub mod types;

pub use backend::FindingsSinkPg;
pub use error::{
    FindingsPgError, FindingsPgMigrationError, FindingsPgSchemaError, MigrationOperation,
};
#[cfg(feature = "test-utils")]
pub use migrations::connect_and_apply_migrations;
pub use migrations::{EmbeddedMigration, MIGRATIONS, apply_all_migrations, apply_migrations};
pub use read_api::{ObservationCountByPolicy, PendingTriageFinding};
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};

#[cfg(test)]
mod test_postgres;
#[cfg(test)]
mod tests;
