//! PostgreSQL done-ledger backend: schema, migrations, and type-mapping helpers.
//!
//! The done-ledger records whether a specific object-version has been processed
//! under a given tenant and scan policy (see [`DoneLedger`] for the full
//! contract). This crate provides the PostgreSQL-specific pieces needed to back
//! that contract.
//!
//! ## Scope
//!
//! This crate is **infrastructure-only**: it provides the PostgreSQL schema
//! definition, forward-only migration runner, and `u64` ↔ `BIGINT`
//! type-mapping helpers. It does **not** implement the [`DoneLedger`] trait.
//! A complete backend crate should depend on this crate for schema setup and
//! type conversion, then implement [`DoneLedger`] against a live
//! `postgres::Client`.
//!
//! ## Path to conformance
//!
//! Any backend implementing [`DoneLedger`] must pass the persistence
//! conformance harness ([`run_conformance`]) to verify lattice-merge
//! semantics, idempotent upsert, and batch-get positional alignment. See
//! `gossip-persistence-inmemory/tests/conformance.rs` for a working example.
//!
//! [`run_conformance`]: gossip_contracts::persistence::run_conformance
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`schema`] | Canonical table/index names for query construction and tests |
//! | [`migrations`] | Forward-only, checksum-verified embedded SQL migration runner |
//! | [`types`] | `u64 ↔ BIGINT` conversion functions with two storage modes |
//!
//! ## `u64` ↔ `BIGINT` storage strategy
//!
//! PostgreSQL has no unsigned 64-bit integer type. The naïve alternative,
//! `NUMERIC(20,0)`, increases storage width, bloats B-tree indexes, and
//! replaces native integer arithmetic with arbitrary-precision comparisons.
//! This crate avoids that cost by splitting `u64` fields into two categories:
//!
//! - **Bit-pattern mode** — equality/grouping identifiers (`RunId`, `ShardId`)
//!   are stored as raw two's-complement `BIGINT` values. The sign bit is
//!   irrelevant because the only SQL operations on these columns are `=` and
//!   `GROUP BY`.
//!
//! - **Ordered non-negative mode** — monotonic counters and timestamps
//!   (`FenceEpoch`, `started_at`, `finished_at`, `bytes_scanned`) are stored as
//!   non-negative `BIGINT` (range `0..=i64::MAX`). This preserves SQL `ORDER BY`
//!   and `>=` / `BETWEEN` semantics without reinterpretation.
//!
//! See the [`types`] module for the conversion functions and their error modes.
//!
//! ## Driver choice
//!
//! The crate uses the synchronous [`postgres`] client. Synchronous I/O keeps
//! durable-before-return semantics straightforward and avoids coupling the
//! migration surface to a specific async runtime.
//!
//! [`DoneLedger`]: gossip_contracts::persistence::DoneLedger
//! [`postgres`]: https://docs.rs/postgres

#![forbid(unsafe_code)]

mod error;
pub mod migrations;
pub mod schema;
pub mod types;

pub use error::DoneLedgerPgMigrationError;
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
