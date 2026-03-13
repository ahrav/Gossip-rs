//! Shared PostgreSQL primitives for gossip-rs persistence crates.
//!
//! This crate owns the types and helpers that are common across all
//! PostgreSQL-backed persistence backends (`gossip-done-ledger-postgres`,
//! `gossip-findings-postgres`, and any future backends). Centralising these
//! definitions prevents structural duplication and ensures that conversion
//! semantics and migration-operation taxonomies stay consistent across
//! backends.
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`types`] | `u64 ↔ BIGINT` conversion error and helper functions |
//! | [`migration`] | Shared embedded migration runner, checksum verification, and migration error types |
//! | [`test_support`] | Shared PostgreSQL testcontainer lifecycle and isolated test-database helpers |

#![forbid(unsafe_code)]

pub mod migration;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod types;

pub use migration::{
    EmbeddedMigration, MigrationConfig, MigrationOperation, PgMigrationError, apply_all_migrations,
    apply_migrations,
};
pub use types::PgU64ConversionError;
