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
//! - `types.rs` defines validated value wrappers, item metadata/value
//!   invariants (including toxic-byte redaction and size bounds), and
//!   [`ToxicDigest`].
//! - `api.rs` defines operation-outcome classification and optional capability
//!   negotiation (`ErrorClass`, `EnumerateError`, `ReadError`,
//!   `ConnectorCapabilities`).
//! - `common.rs` defines shared paging vocabulary reused across connector
//!   families and exposed at [`common`] ([`PageBuf`], [`PageState`],
//!   [`PagingCapabilities`], [`KeyedPageItem`], [`validate_filled_page`]).
//! - `ordered.rs` defines the ordered-content family contract
//!   ([`ordered::OrderedContentCapabilities`],
//!   [`ordered::OrderedContentSource`]).
//! - `git.rs` defines the Git family contract
//!   ([`git::RepoKey`], [`git::RepoLocator`], [`git::GitRepoTarget`],
//!   [`git::GitSelection`], [`git::LocalMirror`],
//!   [`git::GitExecutionLimits`], [`git::GitRunOutcome`],
//!   [`git::GitRunError`], [`git::GitDiscoveryCapabilities`],
//!   [`git::GitRepoDiscoverySource`],
//!   [`git::GitMirrorManager`], [`git::GitRepoExecutor`]).
//!
//! `api.rs` and `types.rs` remain internal organization units; their public
//! items are re-exported here so runtime crates keep a single import boundary
//! for shared nouns and error taxonomy. [`common`] is public because the paging
//! vocabulary is reused across families, while the family contracts stay
//! namespaced under [`ordered`] and [`git`].
//!
//! Family modules compose from the shared layers instead of inheriting a
//! single universal connector model: [`ordered`] and [`git`] depend on
//! [`common`], `types.rs`, and `api.rs` for paging, value wrappers, and error
//! classification.
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
//! - Git family types and contracts: [`git::RepoKey`], [`git::RepoLocator`],
//!   [`git::GitRepoTarget`], [`git::GitSelection`], [`git::LocalMirror`],
//!   [`git::GitExecutionLimits`], [`git::GitRunOutcome`],
//!   [`git::GitRunError`], [`git::GitDiscoveryCapabilities`],
//!   [`git::GitRepoDiscoverySource`],
//!   [`git::GitMirrorManager`], [`git::GitRepoExecutor`]
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

use crate::identity::{
    ConnectorInstanceIdHash, ConnectorTag, ItemIdentityKey, StableItemId,
};

mod api;
pub mod common;
pub mod git;
pub mod ordered;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
// Re-export for use by `define_connector_error!` macro via `$crate::connector::` path.
#[doc(hidden)]
pub use api::fmt_sanitized_message;
pub use common::{
    KeyedPageItem, PageBuf, PageShapeError, PageState, PagingCapabilities, validate_filled_page,
};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, ItemKey, ItemRef, Location,
    MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
    MAX_TOKEN_SIZE, PooledByteSlab, ScanItem, TokenBytes, ToxicDigest, VersionId,
};

// ---------------------------------------------------------------------------
// Canonical connector-tag constants
// ---------------------------------------------------------------------------

/// Connector tag for filesystem-sourced items.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
pub const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

/// Connector tag for git-sourced items.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
pub const GIT_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"gitlocal");

/// Connector tag for the deterministic in-memory connector kind.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
pub const IN_MEMORY_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"inmem");

// ---------------------------------------------------------------------------
// Stable-item identity helpers
// ---------------------------------------------------------------------------

/// Derive a [`StableItemId`] from a connector tag, connector-instance scope,
/// and ordered item key.
///
/// This wraps [`ItemIdentityKey`] so runtime and connector callsites do not
/// reimplement stable-item derivation ad hoc and accidentally omit the
/// connector-instance scope.
#[inline]
#[must_use]
pub fn derive_stable_item_id(
    connector_tag: ConnectorTag,
    connector_instance: ConnectorInstanceIdHash,
    item_key: &ItemKey,
) -> StableItemId {
    ItemIdentityKey::new(connector_tag, connector_instance, item_key.as_bytes()).stable_id()
}

/// Derive a filesystem-scoped [`StableItemId`] from a connector instance and
/// ordered item key.
///
/// Filesystem items must always be domain-separated with
/// [`FILESYSTEM_CONNECTOR_TAG`] and scoped by a connector-instance hash so the
/// same relative path under different filesystem roots cannot collide.
#[inline]
#[must_use]
pub fn derive_filesystem_stable_item_id(
    connector_instance: ConnectorInstanceIdHash,
    item_key: &ItemKey,
) -> StableItemId {
    derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, connector_instance, item_key)
}

#[cfg(test)]
mod identity_tests;
