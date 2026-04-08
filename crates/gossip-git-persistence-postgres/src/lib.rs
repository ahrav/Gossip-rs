//! PostgreSQL Git persistence backend: schema, migrations, and test support.
//!
//! The Git runtime persists opaque scanner-owned keys and values that back
//! ref watermarks, committed/staging seen bitmaps, and mid-scan checkpoints.
//! This crate provides the PostgreSQL-specific pieces needed to satisfy
//! [`GitPersistenceBackend`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend)
//! for that runtime-owned key/value state.
//!
//! ## Scope
//!
//! This crate includes:
//!
//! - a synchronous PostgreSQL
//!   [`GitPersistenceBackend`](gossip_scanner_runtime::git_persistence::GitPersistenceBackend)
//!   implementation ([`GitPersistencePg`]),
//! - canonical table and SQL constants in [`schema`],
//! - forward-only checksum-verified embedded migrations in [`migrations`],
//! - and crate-local PostgreSQL test helpers used by the integration tests.
//!
//! ## Driver choice
//!
//! The crate uses the synchronous [`postgres`] client. Synchronous I/O keeps
//! durable-before-return semantics straightforward and matches the existing
//! PostgreSQL persistence crates. Convenience constructors (`connect`,
//! `connect_and_migrate`) use `NoTls` and are gated behind the `test-utils`
//! feature; production callers should pass a TLS-configured client through
//! [`GitPersistencePg::from_client`].
//!
//! ## Modules
//!
//! | Module | Visibility | Responsibility |
//! |--------|------------|----------------|
//! | `backend` | private (types re-exported) | [`GitPersistencePg`] implementation over synchronous `postgres::Client` |
//! | [`schema`] | public | Canonical table names, size limits, and SQL query constants |
//! | [`migrations`] | public | Forward-only, checksum-verified embedded SQL migration runner |
//!
//! [`postgres`]: https://docs.rs/postgres

#![forbid(unsafe_code)]

mod backend;
mod error;
pub mod migrations;
pub mod schema;

pub use backend::GitPersistencePg;
pub use error::{GitPersistencePgError, GitPersistencePgMigrationError, MigrationOperation};
#[cfg(feature = "test-utils")]
pub use migrations::connect_and_apply_migrations;
pub use migrations::{apply_all_migrations, apply_migrations};

#[cfg(test)]
mod test_postgres;
#[cfg(test)]
mod tests;
