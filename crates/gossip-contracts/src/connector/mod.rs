//! Connector contract types shared between connector runtimes and coordinator-facing contracts.
//!
//! # Purpose
//!
//! This module exports validated wrapper types for connector-originated bytes
//! (`ItemKey`, `ItemRef`, `TokenBytes`), cursor and metadata types used by
//! enumeration/read flows, and a log-safe digest type
//! ([`ToxicDigest`](crate::connector::ToxicDigest)) for
//! redacting untrusted connector data in diagnostics.
//!
//! # Public Surface
//!
//! - [`common`](crate::connector::common) provides the shared paging vocabulary
//!   ([`PageBuf`](crate::connector::PageBuf),
//!   [`PageState`](crate::connector::PageState)) and page-shape validators.
//! - [`ordered`](crate::connector::ordered) and
//!   [`git`](crate::connector::git) define the family-specific source traits.
//! - [`Cursor`](crate::connector::Cursor),
//!   [`Budgets`](crate::connector::Budgets),
//!   [`ScanItem`](crate::connector::ScanItem), and
//!   [`VersionId`](crate::connector::VersionId) model the paging and item
//!   metadata exchanged between connectors and runtimes.
//! - [`ConnectorCapabilities`](crate::connector::ConnectorCapabilities),
//!   [`EnumerateError`](crate::connector::EnumerateError), and
//!   [`ReadError`](crate::connector::ReadError) describe source capabilities
//!   and failure boundaries.
//!
//! The contract surface is split into focused, composable layers rather than a single
//! universal connector model. It isolates connector value contracts, shared paging
//! vocabulary, and family-specific trait surfaces from orchestration decisions
//! (retry, scheduling, backoff policy), which live in runtime crates.
//!
//! # Invariants
//!
//! - Boundary byte wrappers are always non-empty and bounded by hard limits.
//! - `Debug`/`Display` output of untrusted bytes is redacted (length + short hash prefix).
//! - `Cursor` owns paging state and safely bridges to coordination's borrowed `CursorUpdate`.
//! - `MAX_ITEM_KEY_SIZE` and `MAX_TOKEN_SIZE` strictly mirror coordination cursor limits
//!   to ensure connector paging state and cursor updates stay aligned.
//! - Pooled toxic-byte wrappers retain a shared page slab (`PooledByteSlab`); key/ref/token
//!   clones that escape a page keep that slab alive.
//! - Connector tag byte literals are stable identity domains; changing a tag changes
//!   every derived [`crate::identity::StableItemId`] in that connector family.
//!
//! # Design Trade-offs
//!
//! - **Composition over Inheritance:** Family modules (`ordered`, `git`) compose from shared
//!   layers (`common`, `types`, `api`) instead of implementing a monolithic connector trait.
//!   This prevents leaking unrelated methods across distinct source families.
//! - **Boundary Validation:** Connectors validate untrusted byte wrappers once at the boundary,
//!   handing strongly-typed values across crate boundaries to avoid repeating raw-byte checks.
//!
//! # Compatibility Contract
//!
//! This crate intentionally keeps connector-facing cursor byte limits aligned with
//! coordination-facing limits. If one side changes (`MAX_ITEM_KEY_SIZE`,
//! `MAX_TOKEN_SIZE`), the other must be updated in lockstep.

use crate::identity::ConnectorTag;

mod api;
pub mod common;
pub mod conformance;
pub mod git;
pub mod ordered;
mod types;

/// Hidden helper re-export used by `define_connector_error!` through the
/// `$crate::connector::` path.
#[doc(hidden)]
pub use api::fmt_sanitized_message;
pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
pub use common::{
    KeyedPageItem, PageBuf, PageSequenceViolation, PageShapeError, PageState, PagingCapabilities,
    validate_filled_page, validate_page_sequence,
};
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, ItemKey, ItemRef, Location,
    MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
    MAX_TOKEN_SIZE, PooledByteSlab, ScanItem, TokenBytes, ToxicDigest, VersionId,
};

/// Connector tag for filesystem-sourced items.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
/// The ASCII payload is part of the stable ID domain contract.
pub const FILESYSTEM_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"fslocal");

/// Connector tag for git-sourced items.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
/// The ASCII payload is part of the stable ID domain contract.
pub const GIT_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"gitlocal");

/// Connector tag for the deterministic in-memory connector kind.
///
/// Domain-separates [`crate::identity::StableItemId`] derivation so that
/// identity hashes are disjoint from items produced by other connector types.
/// The ASCII payload is part of the stable ID domain contract.
pub const IN_MEMORY_CONNECTOR_TAG: ConnectorTag = ConnectorTag::from_ascii(b"inmem");
