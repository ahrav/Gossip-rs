use gossip_contracts::connector::{
    self, PageBuf, PageShapeError, PageState, PagingCapabilities, ScanItem, git::GitRepoTarget,
    ordered::OrderedContentSource,
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
}

#[test]
fn family_contracts_are_available_from_namespaced_modules() {
    let _: Option<&dyn OrderedContentSource> = None;
    let _: Option<GitRepoTarget> = None;
}
