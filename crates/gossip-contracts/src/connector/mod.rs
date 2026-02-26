//! Connector boundary value types shared between connector runtimes and
//! coordinator-facing contracts.
//!
//! This module intentionally stays narrow: it exports validated wrapper types
//! for connector-originated bytes (`ItemKey`, `ItemRef`, `TokenBytes`) plus
//! shared input-validation errors and size limits.
//!
//! ## Invariants
//!
//! - Boundary byte wrappers are always non-empty and bounded by hard limits.
//! - `Debug`/`Display` output is redacted (length + short hash prefix), never
//!   raw bytes.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` mirror coordination cursor
//!   limits so connector paging state and cursor updates cannot drift.
//!
//! ## Ownership boundary
//!
//! `gossip-contracts` defines value contracts and validation rules only.
//! Runtime connector implementations and orchestration logic live in runtime
//! crates.

mod types;

pub use types::{
    ConnectorInputError, ItemKey, ItemRef, MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_TOKEN_SIZE,
    TokenBytes,
};
