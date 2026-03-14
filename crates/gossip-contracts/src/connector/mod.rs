//! Connector contract types shared between connector runtimes and
//! coordinator-facing contracts.
//!
//! This module exports validated wrapper types for connector-originated bytes
//! (`ItemKey`, `ItemRef`, `TokenBytes`), cursor and metadata types used by
//! enumeration/read flows, and a log-safe digest type ([`ToxicDigest`]) for
//! redacting untrusted connector data in diagnostics.
//!
//! ## Surface split
//!
//! The connector contract surface is split into focused layers:
//!
//! - `types.rs` defines validated value wrappers, paging/value invariants
//!   (including toxic-byte redaction and size bounds), and [`ToxicDigest`].
//! - `api.rs` defines operation-outcome classification and optional capability
//!   negotiation (`ErrorClass`, `EnumerateError`, `ReadError`,
//!   `ConnectorCapabilities`).
//! - `common.rs` defines shared paging vocabulary reused across connector
//!   families (`PageBuf`, `PageState`, `PagingCapabilities`,
//!   `KeyedPageItem`, `validate_filled_page`).
//! - `ordered.rs` defines the ordered-content family contract
//!   (`ordered::OrderedContentCapabilities`,
//!   `ordered::OrderedContentSource`).
//!
//! `api.rs` and `types.rs` remain internal organization units; their public
//! items are re-exported here so runtime crates keep a single import boundary
//! while family-specific contracts stay namespaced.
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
//! - Pooled toxic-byte wrappers retain a shared page slab (`PooledByteSlab`);
//!   any key/ref/token clones that escape a page keep that slab alive.
//!
//! ## Public surface
//!
//! - Byte wrappers: [`ItemKey`], [`ItemRef`], [`TokenBytes`]
//! - Pooled slab owner for page-scoped toxic-byte wrappers: [`PooledByteSlab`]
//! - Shared paging vocabulary: [`PageBuf`], [`PageState`], [`PagingCapabilities`],
//!   [`KeyedPageItem`], [`PageShapeError`]
//! - Paging bridge: [`Cursor`]
//! - Version semantics: [`VersionId`]
//! - Optional metadata: [`ContentHints`], [`Location`]
//! - Enumeration composites: [`ScanItem`]
//! - Scan budgets: [`Budgets`]
//! - Validation errors: [`ConnectorInputError`]
//! - Log-safe digest: [`ToxicDigest`]
//! - Connector API errors: [`ErrorClass`], [`EnumerateError`], [`ReadError`]
//! - Connector feature flags: [`ConnectorCapabilities`]
//! - Ordered-content family contract: [`ordered::OrderedContentCapabilities`],
//!   [`ordered::OrderedContentSource`]
//!
//! These types are intentionally composable: a connector validates once at the
//! boundary, then hands strongly-typed values across crate boundaries without
//! repeating raw-byte checks.
//!
//! ## Ownership boundary
//!
//! `gossip-contracts` defines connector value contracts, shared paging
//! vocabulary, and family-specific trait surfaces only. Runtime connector
//! implementations and orchestration decisions (retry, scheduling, backoff
//! policy) live in runtime crates.

mod api;
pub mod common;
pub mod ordered;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
pub use common::{
    KeyedPageItem, PageBuf, PageShapeError, PageState, PagingCapabilities, validate_filled_page,
};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, ItemKey, ItemRef, Location,
    MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
    MAX_TOKEN_SIZE, PooledByteSlab, ScanItem, TokenBytes, ToxicDigest, VersionId,
};
