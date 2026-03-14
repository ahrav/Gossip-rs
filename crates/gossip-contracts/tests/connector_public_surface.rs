use gossip_contracts::connector::{
    self, KeyedPageItem, PageBuf, PageShapeError, PageState, PagingCapabilities, ScanItem,
    git::GitRepoTarget, ordered::OrderedContentSource, validate_filled_page,
};

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
