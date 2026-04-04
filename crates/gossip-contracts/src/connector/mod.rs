//! Connector contract types shared between connector runtimes and
//! coordinator-facing contracts.
//!
//! This module exports validated wrapper types for connector-originated bytes
//! (`ItemKey`, `ItemRef`, `TokenBytes`), cursor and metadata types used by
//! enumeration/read flows, and a log-safe digest type
//! ([`ToxicDigest`](crate::connector::ToxicDigest)) for
//! redacting untrusted connector data in diagnostics.
//!
//! ## Surface split
//!
//! The connector contract surface is split into focused layers:
//!
//! - `types.rs` defines validated value wrappers, item metadata/value
//!   invariants (including toxic-byte redaction and size bounds), and
//!   [`ToxicDigest`](crate::connector::ToxicDigest).
//! - `api.rs` defines operation-outcome classification and optional capability
//!   negotiation ([`ErrorClass`](crate::connector::ErrorClass),
//!   [`EnumerateError`](crate::connector::EnumerateError),
//!   [`ReadError`](crate::connector::ReadError),
//!   [`ConnectorCapabilities`](crate::connector::ConnectorCapabilities)).
//! - `common.rs` defines shared paging vocabulary reused across connector
//!   families and exposed at [`common`](crate::connector::common)
//!   ([`PageBuf`](crate::connector::PageBuf),
//!   [`PageState`](crate::connector::PageState),
//!   [`PagingCapabilities`](crate::connector::PagingCapabilities),
//!   [`KeyedPageItem`](crate::connector::KeyedPageItem),
//!   [`validate_filled_page`](crate::connector::validate_filled_page)).
//! - `conformance.rs` provides the reusable ordered-content conformance
//!   harness
//!   ([`conformance::run_ordered_content_conformance`](crate::connector::conformance::run_ordered_content_conformance),
//!   [`conformance::drain_ordered_source`](crate::connector::conformance::drain_ordered_source)).
//! - `ordered.rs` defines the ordered-content family contract
//!   ([`ordered::OrderedContentCapabilities`](crate::connector::ordered::OrderedContentCapabilities),
//!   [`ordered::OrderedContentSource`](crate::connector::ordered::OrderedContentSource)).
//! - `git.rs` defines the Git family contract
//!   ([`git::RepoKey`](crate::connector::git::RepoKey),
//!   [`git::RepoLocator`](crate::connector::git::RepoLocator),
//!   [`git::GitRepoTarget`](crate::connector::git::GitRepoTarget),
//!   [`git::GitSelection`](crate::connector::git::GitSelection),
//!   [`git::LocalMirror`](crate::connector::git::LocalMirror),
//!   [`git::GitExecutionLimits`](crate::connector::git::GitExecutionLimits),
//!   [`git::GitRunOutcome`](crate::connector::git::GitRunOutcome),
//!   [`git::GitRunError`](crate::connector::git::GitRunError),
//!   [`git::GitDiscoveryCapabilities`](crate::connector::git::GitDiscoveryCapabilities),
//!   [`git::GitRepoDiscoverySource`](crate::connector::git::GitRepoDiscoverySource),
//!   [`git::GitMirrorManager`](crate::connector::git::GitMirrorManager),
//!   [`git::GitRepoExecutor`](crate::connector::git::GitRepoExecutor)).
//!
//! `api.rs` and `types.rs` remain internal organization units; their public
//! items are re-exported here so runtime crates keep a single import boundary
//! for shared nouns and error taxonomy. [`common`](crate::connector::common) is
//! public because the paging vocabulary is reused across families, while the
//! family contracts stay namespaced under
//! [`ordered`](crate::connector::ordered) and
//! [`git`](crate::connector::git). Conformance harnesses stay namespaced under
//! [`conformance`](crate::connector::conformance) as cross-cutting test
//! utilities consumed by multiple downstream crates.
//!
//! Family modules compose from the shared layers instead of inheriting a
//! single universal connector model:
//! [`ordered`](crate::connector::ordered) and
//! [`git`](crate::connector::git) depend on
//! [`common`](crate::connector::common), `types.rs`, and `api.rs` for paging,
//! value wrappers, and error classification.
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
//! - Byte wrappers: [`ItemKey`](crate::connector::ItemKey),
//!   [`ItemRef`](crate::connector::ItemRef),
//!   [`TokenBytes`](crate::connector::TokenBytes)
//! - Pooled slab owner for page-scoped toxic-byte wrappers:
//!   [`PooledByteSlab`](crate::connector::PooledByteSlab)
//! - Shared paging vocabulary: [`PageBuf`](crate::connector::PageBuf),
//!   [`PageState`](crate::connector::PageState),
//!   [`PagingCapabilities`](crate::connector::PagingCapabilities),
//!   [`KeyedPageItem`](crate::connector::KeyedPageItem),
//!   [`PageShapeError`](crate::connector::PageShapeError),
//!   [`PageSequenceViolation`](crate::connector::PageSequenceViolation)
//! - Paging bridge: [`Cursor`](crate::connector::Cursor)
//! - Version semantics: [`VersionId`](crate::connector::VersionId)
//! - Optional metadata: [`ContentHints`](crate::connector::ContentHints),
//!   [`Location`](crate::connector::Location)
//! - Enumeration composites: [`ScanItem`](crate::connector::ScanItem)
//! - Scan budgets: [`Budgets`](crate::connector::Budgets)
//! - Validation errors:
//!   [`ConnectorInputError`](crate::connector::ConnectorInputError)
//! - Log-safe digest: [`ToxicDigest`](crate::connector::ToxicDigest)
//! - Connector API errors: [`ErrorClass`](crate::connector::ErrorClass),
//!   [`EnumerateError`](crate::connector::EnumerateError),
//!   [`ReadError`](crate::connector::ReadError)
//! - Connector feature flags:
//!   [`ConnectorCapabilities`](crate::connector::ConnectorCapabilities)
//! - Ordered-content family contract:
//!   [`ordered::OrderedContentCapabilities`](crate::connector::ordered::OrderedContentCapabilities),
//!   [`ordered::OrderedContentSource`](crate::connector::ordered::OrderedContentSource)
//! - Ordered-content conformance harness (under
//!   [`conformance`](crate::connector::conformance)):
//!   [`conformance::run_ordered_content_conformance`](crate::connector::conformance::run_ordered_content_conformance),
//!   [`conformance::drain_ordered_source`](crate::connector::conformance::drain_ordered_source),
//!   [`conformance::drain_ordered_source_from`](crate::connector::conformance::drain_ordered_source_from),
//!   [`conformance::assert_repeatable_drain`](crate::connector::conformance::assert_repeatable_drain),
//!   [`conformance::assert_resume_after_corrupt_token`](crate::connector::conformance::assert_resume_after_corrupt_token),
//!   [`conformance::assert_no_forbidden_fragments`](crate::connector::conformance::assert_no_forbidden_fragments)
//! - Conformance snapshot types (under
//!   [`conformance`](crate::connector::conformance)):
//!   [`conformance::ObservedScanItem`](crate::connector::conformance::ObservedScanItem),
//!   [`conformance::OrderedContentDrain`](crate::connector::conformance::OrderedContentDrain),
//!   [`conformance::OrderedContentConformanceError`](crate::connector::conformance::OrderedContentConformanceError)
//! - Git family types and contracts:
//!   [`git::RepoKey`](crate::connector::git::RepoKey),
//!   [`git::RepoLocator`](crate::connector::git::RepoLocator),
//!   [`git::GitRepoTarget`](crate::connector::git::GitRepoTarget),
//!   [`git::GitSelection`](crate::connector::git::GitSelection),
//!   [`git::LocalMirror`](crate::connector::git::LocalMirror),
//!   [`git::GitExecutionLimits`](crate::connector::git::GitExecutionLimits),
//!   [`git::GitRunOutcome`](crate::connector::git::GitRunOutcome),
//!   [`git::GitRunError`](crate::connector::git::GitRunError),
//!   [`git::GitDiscoveryCapabilities`](crate::connector::git::GitDiscoveryCapabilities),
//!   [`git::GitRepoDiscoverySource`](crate::connector::git::GitRepoDiscoverySource),
//!   [`git::GitMirrorManager`](crate::connector::git::GitMirrorManager),
//!   [`git::GitRepoExecutor`](crate::connector::git::GitRepoExecutor)
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

use crate::identity::ConnectorTag;

mod api;
pub mod common;
pub mod conformance;
pub mod git;
pub mod ordered;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
// Re-export for use by `define_connector_error!` macro via `$crate::connector::` path.
#[doc(hidden)]
pub use api::fmt_sanitized_message;
pub use common::{
    KeyedPageItem, PageBuf, PageSequenceViolation, PageShapeError, PageState, PagingCapabilities,
    validate_filled_page, validate_page_sequence,
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
