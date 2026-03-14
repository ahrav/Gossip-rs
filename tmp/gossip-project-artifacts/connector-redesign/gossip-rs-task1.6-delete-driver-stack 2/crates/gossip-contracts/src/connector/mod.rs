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
//! - `common.rs` defines shared paging vocabulary reused by multiple connector
//!   families (`PageBuf`, `PageState`, `PagingCapabilities`,
//!   `KeyedPageItem`, `validate_filled_page`).
//! - `ordered.rs` defines the ordered-content source family contract
//!   (`OrderedContentCapabilities`, `OrderedContentSource`).
//! - `git.rs` defines the Git-specific family contracts and shared work-unit
//!   types (`RepoKey`, `RepoLocator`, `GitRepoTarget`, `GitRepoDiscoverySource`,
//!   `GitMirrorManager`, `GitRepoExecutor`).
//!
//! The supported public connector surface is organized around three public
//! family modules:
//!
//! - [`common`] for shared paging vocabulary,
//! - [`ordered`] for ordered content sources,
//! - [`git`] for Git repo discovery and execution families.
//!
//! `api.rs` and `types.rs` remain internal organizational units; their public
//! items are re-exported here as top-level convenience aliases. This keeps the
//! externally supported surface centered on the family model rather than the
//! internal file layout.
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
//! - Paging bridge: [`Cursor`]
//! - Version semantics: [`VersionId`]
//! - Optional metadata: [`ContentHints`], [`Location`]
//! - Enumeration composites: [`ScanItem`]
//! - Scan budgets: [`Budgets`]
//! - Validation errors: [`ConnectorInputError`]
//! - Log-safe digest: [`ToxicDigest`]
//! - Connector API errors: [`ErrorClass`], [`EnumerateError`], [`ReadError`]
//! - Connector feature flags: [`ConnectorCapabilities`]
//! - Shared paging primitives: [`PageBuf`], [`PageState`], [`PagingCapabilities`]
//! - Page-key projection + validation: [`KeyedPageItem`], [`PageShapeError`],
//!   [`validate_filled_page`]
//! - Ordered-content family contract: [`OrderedContentCapabilities`],
//!   [`OrderedContentSource`]
//! - Git family types: [`GitProvider`], [`RepoKey`], [`RepoLocator`],
//!   [`GitSelection`], [`GitRepoTarget`], [`LocalMirror`],
//!   [`GitExecutionLimits`], [`GitRunOutcome`], [`GitRunError`]
//! - Git family contracts: [`GitRepoDiscoverySource`], [`GitMirrorManager`],
//!   [`GitRepoExecutor`]
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
pub mod git;
pub mod ordered;
mod types;
// types_tests.rs is declared inside types.rs via #[path] attribute.

#[doc(inline)]
pub use api::{ConnectorCapabilities, EnumerateError, ErrorClass, ReadError};
#[doc(inline)]
pub use common::{
    KeyedPageItem, PageBuf, PageShapeError, PageState, PagingCapabilities,
    validate_filled_page,
};
#[doc(inline)]
pub use git::{
    GitExecutionLimits, GitMirrorManager, GitProvider, GitRepoDiscoverySource,
    GitRepoExecutor, GitRepoTarget, GitRunError, GitRunOutcome, GitSelection,
    LocalMirror, RepoKey, RepoLocator,
};
#[doc(inline)]
pub use ordered::{OrderedContentCapabilities, OrderedContentSource};
#[doc(inline)]
pub use types::{
    Budgets, ConnectorInputError, ContentHints, Cursor, ItemKey, ItemRef, Location,
    MAX_ITEM_KEY_SIZE, MAX_ITEM_REF_SIZE, MAX_LOCATION_DISPLAY_SIZE, MAX_LOCATION_URL_SIZE,
    MAX_TOKEN_SIZE, PooledByteSlab, ScanItem, TokenBytes, ToxicDigest, VersionId,
};


#[cfg(test)]
mod public_surface_tests {
    use super::*;

    struct OrderedStub;

    impl ordered::OrderedContentSource for OrderedStub {
        fn capabilities(&self) -> ordered::OrderedContentCapabilities {
            ordered::OrderedContentCapabilities::new(true, false, false, false)
        }

        fn fill_page(
            &mut self,
            _shard: &crate::coordination::ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
            _out: &mut common::PageBuf<ScanItem>,
        ) -> Result<common::PageState, EnumerateError> {
            Ok(common::PageState::Exhausted)
        }

        fn choose_split_point(
            &mut self,
            _shard: &crate::coordination::ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<ItemKey>, EnumerateError> {
            Ok(None)
        }

        fn open(
            &mut self,
            _item_ref: &ItemRef,
            _budgets: Budgets,
        ) -> Result<Box<dyn std::io::Read + Send>, ReadError> {
            Ok(Box::new(std::io::Cursor::new(Vec::<u8>::new())))
        }
    }

    struct GitDiscoveryStub;

    impl git::GitRepoDiscoverySource for GitDiscoveryStub {
        fn capabilities(&self) -> common::PagingCapabilities {
            common::PagingCapabilities::new(true, false, false)
        }

        fn fill_page(
            &mut self,
            _shard: &crate::coordination::ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
            _out: &mut common::PageBuf<git::GitRepoTarget>,
        ) -> Result<common::PageState, EnumerateError> {
            Ok(common::PageState::Exhausted)
        }

        fn choose_split_point(
            &mut self,
            _shard: &crate::coordination::ShardSpec,
            _after: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<ItemKey>, EnumerateError> {
            Ok(None)
        }
    }

    #[test]
    fn family_modules_are_publicly_reachable() {
        fn assert_ordered<T: ordered::OrderedContentSource>() {}
        fn assert_git<T: git::GitRepoDiscoverySource>() {}

        assert_ordered::<OrderedStub>();
        assert_git::<GitDiscoveryStub>();
    }

    #[test]
    fn convenience_reexports_match_family_modules() {
        let _caps: OrderedContentCapabilities =
            ordered::OrderedContentCapabilities::new(true, false, false, false);
        let _paging: PagingCapabilities = common::PagingCapabilities::new(true, false, false);
    }
}
