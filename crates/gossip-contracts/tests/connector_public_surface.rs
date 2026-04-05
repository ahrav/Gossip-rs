//! Integration tests verifying the public API surface of the connector module.
//!
//! This module ensures that shared paging types and family contracts are accessible
//! from their expected public paths and namespaced modules, preventing accidental
//! breakage of the public API boundaries.

use gossip_contracts::connector::{
    self, KeyedPageItem, PageBuf, PageShapeError, PageState, PagingCapabilities, ReadError,
    ScanItem,
    conformance::{
        ObservedScanItem, OrderedContentConformanceError, OrderedContentDrain,
        drain_ordered_source, drain_ordered_source_from, run_ordered_content_conformance,
    },
    git::GitRepoTarget,
    ordered::{OrderedContentCapabilities, OrderedContentSource},
    validate_filled_page,
};
use gossip_contracts::coordination::ShardSpec;

use std::io;

/// Verifies that common paging types can be resolved from both the flat root and the `common` submodule.
#[test]
fn shared_paging_types_are_available_from_flat_and_common_paths() {
    let _: Option<PageBuf<ScanItem>> = None;
    let _: Option<connector::common::PageBuf<ScanItem>> = None;
    let _: PageState = connector::common::PageState::Complete;
    let _: Option<PagingCapabilities> = None;
    let _: Option<connector::common::PagingCapabilities> = None;
    let _: Option<PageShapeError> = None;
    let _: Option<connector::common::PageShapeError> = None;

    // KeyedPageItem is accessible from both the flat re-export and the common submodule.
    let _: Option<&dyn KeyedPageItem> = None;
    let _: Option<&dyn connector::common::KeyedPageItem> = None;

    // validate_filled_page resolves from both paths (turbofish forces monomorphization).
    let _flat = validate_filled_page::<ScanItem>;
    let _common = connector::common::validate_filled_page::<ScanItem>;
}

/// Verifies that domain-specific contracts (such as OrderedContentSource) are exposed in their respective modules.
#[test]
fn family_contracts_are_available_from_namespaced_modules() {
    let _: Option<&dyn OrderedContentSource> = None;
    let _: Option<GitRepoTarget> = None;
    let _: Option<ObservedScanItem> = None;
    let _: Option<OrderedContentDrain> = None;
    let _: Option<OrderedContentConformanceError> = None;

    let _drain = drain_ordered_source::<UnusedSource>;
    let _drain_from = drain_ordered_source_from::<UnusedSource>;
    let _run = run_ordered_content_conformance::<fn() -> UnusedSource, UnusedSource>;
}

/// Minimal `OrderedContentSource` stub for compile-time API-surface checks.
/// `fill_page` returns terminal completion (`Ok(None)`), and `open` is unsupported.
struct UnusedSource;

impl OrderedContentSource for UnusedSource {
    fn capabilities(&self) -> OrderedContentCapabilities {
        OrderedContentCapabilities::default()
    }

    fn fill_page(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &connector::Cursor,
        _budgets: connector::Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, connector::EnumerateError> {
        Ok(None)
    }

    fn open(
        &mut self,
        _item_ref: &connector::ItemRef,
        _budgets: connector::Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        Err(ReadError::unsupported("unused"))
    }
}
