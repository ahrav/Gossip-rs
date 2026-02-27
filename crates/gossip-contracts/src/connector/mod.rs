//! Connector contract types and page-validation diagnostics shared between
//! connector runtimes and coordinator-facing contracts.
//!
//! This module intentionally stays narrow: it exports validated wrapper types for
//! connector-originated bytes (`ItemKey`, `ItemRef`, `TokenBytes`), cursor and
//! metadata types used by enumeration/read flows, and page-level validation
//! diagnostics used to reject malformed connector pages.
//!
//! ## Surface split
//!
//! The connector contract surface is intentionally split into focused layers:
//!
//! - `types.rs` defines validated value wrappers and paging/value invariants
//!   (including toxic-byte redaction and size bounds).
//! - `api.rs` defines operation-outcome classification, optional capability
//!   negotiation, and runtime connector trait contracts plus their conservative
//!   defaults (`ErrorClass`, `EnumerateError`, `ReadError`,
//!   `ConnectorCapabilities`, `EnumerationConnector`, `ReadConnector`,
//!   `ConnectorInstance`).
//! - `page_validator.rs` defines log-safe page-validation diagnostics plus
//!   validation helpers (`validate_page` and generic `validate_page_range`).
//!
//! Re-exporting all three layers here gives runtime crates a single import boundary
//! while keeping invariants and policy signaling concerns separated.
//!
//! ## Trait composition
//!
//! See [`EnumerationConnector`] for the rationale behind the enumeration/read
//! trait split and [`ConnectorInstance`] for the convenience supertrait.
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
//!   Alignment is covered by connector type tests.
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
//! - Page-validation diagnostics: [`PageValidationError`],
//!   [`PageValidationViolation`], [`PageValidationDetails`],
//!   [`CursorWhich`], [`ToxicDigest`]
//! - Page-validation trait: [`page_validator::PageItem`] (stays module-qualified;
//!   used by generic [`page_validator::validate_page_range`])
//! - Page-validation helper: [`validate_page`] (generic
//!   `validate_page_range` stays module-qualified to avoid widening the root
//!   surface)
//! - Connector API errors: [`ErrorClass`], [`EnumerateError`], [`ReadError`]
//! - Connector feature flags: [`ConnectorCapabilities`]
//! - Runtime connector traits: [`EnumerationConnector`], [`ReadConnector`],
//!   [`ConnectorInstance`] (`choose_split_point` defaults to no hint;
//!   `read_range` defaults to unsupported)
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
pub(crate) mod conformance;
pub mod page_validator;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

pub use api::{
    ConnectorCapabilities, ConnectorInstance, EnumerateError, EnumerationConnector, ErrorClass,
    ReadConnector, ReadError,
};
pub use page_validator::{
    CursorWhich, PageValidationDetails, PageValidationError, PageValidationViolation, ToxicDigest,
    validate_page,
};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, EnumerationPage, ItemKey, ItemRef,
    Location, MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE,
    MAX_LOCATION_URL_SIZE, MAX_TOKEN_SIZE, ScanItem, TokenBytes, VersionId,
};
