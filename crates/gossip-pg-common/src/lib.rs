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
//! | [`migration`] | [`MigrationOperation`](migration::MigrationOperation) taxonomy shared by all migration runners |

#![forbid(unsafe_code)]

pub mod migration;
pub mod types;
