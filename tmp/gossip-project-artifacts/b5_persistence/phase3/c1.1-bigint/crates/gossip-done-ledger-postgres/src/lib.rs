//! PostgreSQL done-ledger backend scaffolding and schema migrations.
//!
//! This crate currently provides the durable SQL schema, a forward-only
//! embedded migration runner, and Rust-side conversion helpers for mapping the
//! contracts layer's `u64` identifiers/counters onto PostgreSQL `BIGINT`
//! columns without paying the `NUMERIC` tax.
//!
//! ## Why this crate does not use `NUMERIC(20,0)` for `u64`
//!
//! Using `NUMERIC` for hot-path ledger fields is the wrong tradeoff here.
//! It increases storage cost, bloats indexes, and turns native integer
//! comparisons into slower arbitrary-precision arithmetic. This crate instead
//! uses two explicit mappings:
//!
//! - equality/grouping identifiers such as `RunId` and `ShardId` are stored as
//!   raw `BIGINT` bit patterns (`u64 <-> i64` reinterpretation), because the
//!   sign bit is irrelevant for equality semantics;
//! - ordered counters and times such as `FenceEpoch`, `started_at`, and
//!   `finished_at` are stored as non-negative `BIGINT`, preserving SQL ordering
//!   and range semantics.
//!
//! The actual [`DoneLedger`] implementation lands in C1.2; this crate already
//! provides the durable schema and migration surface that backend code will use
//! directly.
//!
//! [`DoneLedger`]: gossip_contracts::persistence::DoneLedger

#![forbid(unsafe_code)]

mod error;
pub mod migrations;
pub mod schema;
pub mod types;

pub use error::DoneLedgerPgMigrationError;
pub use migrations::{
    EmbeddedMigration, MIGRATIONS, apply_all_migrations, connect_and_apply_migrations,
};
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};
