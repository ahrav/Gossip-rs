//! PostgreSQL done-ledger backend: schema, migrations, and type-mapping helpers.
//!
//! The done-ledger records whether a specific object-version has been processed
//! under a given tenant and scan policy (see [`DoneLedger`] for the full
//! contract). This crate provides the PostgreSQL-specific pieces needed to back
//! that contract:
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
pub use migrations::{
    EmbeddedMigration, MIGRATIONS, apply_all_migrations, apply_migrations,
    connect_and_apply_migrations,
};
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};
