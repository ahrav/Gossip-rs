use gossip_contracts::connector::{
    self, FILESYSTEM_CONNECTOR_TAG, KeyedPageItem, ObservedScanItem, OrderedContentDrain,
    OrderedContentConformanceError, PageBuf, PageShapeError, PageState, PagingCapabilities,
    ScanItem, assert_no_item_ref_contains, assert_repeatable_drain,
    assert_resume_after_corrupt_token, derive_filesystem_stable_item_id, derive_stable_item_id,
    drain_ordered_source, git::GitRepoTarget, ordered::OrderedContentSource,
    run_ordered_content_conformance, validate_filled_page,
};
use gossip_contracts::identity::ConnectorInstanceIdHash;

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

#[test]
fn family_contracts_are_available_from_namespaced_modules() {
    let _: Option<&dyn OrderedContentSource> = None;
    let _: Option<GitRepoTarget> = None;
}

#[test]
fn stable_item_identity_helpers_are_available_from_connector_module() {
    let key = connector::ItemKey::try_from_slice(b"nested/file.txt").expect("item key");
    let connector_instance = ConnectorInstanceIdHash::from_instance_id_bytes(b"/scan/root");

    let filesystem = derive_filesystem_stable_item_id(connector_instance, &key);
    let generic = derive_stable_item_id(FILESYSTEM_CONNECTOR_TAG, connector_instance, &key);

    assert_eq!(filesystem, generic);
}

#[test]
fn ordered_content_conformance_helpers_are_available_from_connector_module() {
    let _: Option<OrderedContentDrain> = None;
    let _: Option<ObservedScanItem> = None;
    let _: Option<OrderedContentConformanceError> = None;

    let _run = run_ordered_content_conformance::<fn() -> UnusedSource, UnusedSource>;
    let _drain = drain_ordered_source::<UnusedSource>;
    let _repeatable = assert_repeatable_drain::<fn() -> UnusedSource, UnusedSource>;
    let _fallback = assert_resume_after_corrupt_token::<fn() -> UnusedSource, UnusedSource>;
    let _no_refs = assert_no_item_ref_contains;
}

struct UnusedSource;

impl gossip_contracts::connector::ordered::OrderedContentSource for UnusedSource {
    fn capabilities(&self) -> gossip_contracts::connector::ordered::OrderedContentCapabilities {
        Default::default()
    }

    fn fill_page(
        &mut self,
        _shard: &gossip_contracts::coordination::ShardSpec,
        _cursor: &gossip_contracts::connector::Cursor,
        _budgets: gossip_contracts::connector::Budgets,
    ) -> Result<Option<gossip_contracts::connector::PageBuf<gossip_contracts::connector::ScanItem>>, gossip_contracts::connector::EnumerateError> {
        Ok(None)
    }

    fn open(
        &mut self,
        _item_ref: &gossip_contracts::connector::ItemRef,
        _budgets: gossip_contracts::connector::Budgets,
    ) -> Result<Box<dyn std::io::Read + Send>, gossip_contracts::connector::ReadError> {
        Err(gossip_contracts::connector::ReadError::unsupported("unused"))
    }
}
