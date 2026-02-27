//! Connector boundary value types shared between connector runtimes and
//! coordinator-facing contracts.
//!
//! This module intentionally stays narrow: it exports validated wrapper types
//! for connector-originated bytes (`ItemKey`, `ItemRef`, `TokenBytes`) plus
//! cursor/version/display metadata types used by connector enumeration flows.
//!
//! ## Surface split
//!
//! The connector contract surface is intentionally split in two:
//!
//! - `types.rs` defines validated value wrappers and paging/value invariants
//!   (including toxic-byte redaction and size bounds).
//! - `api.rs` defines operation-outcome classification and optional capability
//!   negotiation (`ErrorClass`, `EnumerateError`, `ReadError`,
//!   `ConnectorCapabilities`).
//!
//! Re-exporting both sets here gives runtime crates a single import boundary
//! while keeping invariants and policy signaling concerns separated.
//!
//! ## Invariants
//!
//! - Boundary byte wrappers are always non-empty and bounded by hard limits.
//! - `Debug`/`Display` output is redacted (length + short hash prefix), never
//!   raw bytes.
//! - `Cursor` owns paging state and bridges safely to coordination's borrowed
//!   `CursorUpdate`.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` mirror coordination cursor
//!   limits so connector paging state and cursor updates stay aligned.
//!   Alignment is verified by `types::tests::constants_align_with_coordination_limits`.
//!
//! ## Public surface
//!
//! - Byte wrappers: [`ItemKey`], [`ItemRef`], [`TokenBytes`]
//! - Paging bridge: [`Cursor`]
//! - Version semantics: [`VersionId`]
//! - Optional metadata: [`ContentHints`], [`Location`]
//! - Enumeration composites: [`ScanItem`], [`EnumerationPage`]
//! - Scan budgets: [`Budgets`]
//! - Validation errors: [`ConnectorInputError`]
//! - Connector API errors: [`ErrorClass`], [`EnumerateError`], [`ReadError`]
//! - Connector feature flags: [`ConnectorCapabilities`]
//!
//! These types are intentionally composable: a connector validates once at the
//! boundary, then hands strongly-typed values across crate boundaries without
//! repeating raw-byte checks.
//!
//! ## Ownership boundary
//!
//! `gossip-contracts` defines value contracts and validation rules only.
//! Runtime connector implementations and orchestration decisions (retry,
//! scheduling, backoff policy) live in runtime crates.

mod api;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, EnumerationPage, ItemKey, ItemRef,
    Location, MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE,
    MAX_LOCATION_URL_SIZE, MAX_TOKEN_SIZE, ScanItem, TokenBytes, VersionId,
};
