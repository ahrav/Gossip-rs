//! PostgreSQL MVP backend for the persistence done-ledger.
//!
//! This crate provides a strictly synchronous [`DoneLedgerPg`] implementation
//! of [`gossip_contracts::persistence::DoneLedger`]. Submission and durability
//! are therefore the same event for this backend: `batch_upsert(...)` performs
//! the SQL transaction inline and returns a [`ReadyCommitHandle`]
//! only after the transaction commits.
//!
//! ## Storage choices
//!
//! The schema intentionally uses `BIGINT`, not `NUMERIC`, for all 64-bit
//! contract fields:
//!
//! - `run_id` and `shard_id` are stored as bit-cast signed `BIGINT` values.
//!   These fields are used for equality/grouping, not numeric ordering.
//! - `bytes_scanned`, `fence_epoch`, `started_at`, and `finished_at` are stored
//!   as non-negative `BIGINT` values so SQL ordering matches the contract's
//!   natural ordering.
//!
//! ## Merge semantics
//!
//! The backend implements the done-ledger lattice exactly as specified by
//! [`DoneLedgerStatus::merge`](gossip_contracts::persistence::DoneLedgerStatus::merge):
//! a higher-ranked status wins, and equal-ranked incoming rows replace the
//! existing row. In particular, scanned states dominate failed/skipped states.
//!
//! ## Concurrency model
//!
//! `postgres::Client` is synchronous and `!Sync`, so the backend wraps a single
//! client in `Arc<Mutex<_>>`. This is correct for the MVP and keeps the trait's
//! `&self` surface honest: there is no early acknowledgement and no hidden
//! background worker.

#![forbid(unsafe_code)]

mod backend;
mod error;
pub mod migrations;
pub mod schema;

pub use backend::DoneLedgerPg;
pub use error::{
    DoneLedgerPgConversionError, DoneLedgerPgError, DoneLedgerPgMigrationError,
};
pub use migrations::{
    EmbeddedMigration, MIGRATIONS, apply_all_migrations, connect_and_apply_migrations,
};

#[cfg(test)]
mod tests;
