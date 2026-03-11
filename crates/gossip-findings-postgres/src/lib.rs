//! PostgreSQL findings support: error types, schema and migration namespaces,
//! and `u64` ↔ `BIGINT` conversion helpers.
//!
//! This crate provides the storage-boundary infrastructure for findings
//! persistence:
//!
//! - findings-specific migration and schema-projection error types in
//!   [`FindingsPgMigrationError`] and [`FindingsPgSchemaError`],
//! - `u64` ↔ `BIGINT` conversion helpers in [`types`],
//! - the public [`schema`] namespace for canonical names and row projections,
//! - and the public [`migrations`] namespace for embedded SQL migration support.

#![forbid(unsafe_code)]

mod error;
pub mod migrations;
pub mod schema;
pub mod types;

pub use error::{FindingsPgMigrationError, FindingsPgSchemaError, MigrationOperation};
pub use types::{
    PgU64ConversionError, pg_bigint_nonnegative_to_u64, pg_bigint_to_u64_bits,
    u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};
