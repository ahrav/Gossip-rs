use crate::connector::{ItemRef, TokenBytes, VersionId};
use crate::identity::{ObjectVersionId, StableItemId};
use proptest::prelude::*;
use rstest::rstest;

use super::*;

fn scan_item_with_key(key_bytes: &[u8], seed: u8) -> ScanItem {
    let item_key = ItemKey::try_from_slice(key_bytes).unwrap();
    let item_ref = ItemRef::try_from_vec(vec![seed.wrapping_add(1)]).unwrap();
    let stable_item_id = StableItemId::from_bytes([seed; 32]);
    let version = VersionId::Strong(ObjectVersionId::from_version_bytes(&[seed, 1]));
    ScanItem::new(item_key, item_ref, stable_item_id, version).with_size_hint(u64::from(seed) + 1)
}

fn scan_items(keys: &[&[u8]]) -> Vec<ScanItem> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| scan_item_with_key(key, index as u8))
        .collect()
}

fn scan_items_from_vecs(keys: &[Vec<u8>]) -> Vec<ScanItem> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| scan_item_with_key(key, index as u8))
        .collect()
}

fn arb_key_bytes() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(any::<u8>(), 1..=32)
}

fn arb_sorted_unique_keys(min: usize, max: usize) -> impl Strategy<Value = Vec<Vec<u8>>> {
    proptest::collection::vec(arb_key_bytes(), min..=max)
        .prop_map(|mut keys| {
            keys.sort();
            keys.dedup();
            keys
        })
        .prop_filter("need enough unique keys", move |keys| keys.len() >= min)
}

#[rstest]
#[case::empty(PageShapeError::EmptyPage, "page must contain at least one item")]
#[case::unsorted(
    PageShapeError::UnsortedKeys { index: 2 },
    "page item keys must be strictly increasing (index 2)"
)]
#[case::duplicate(
    PageShapeError::DuplicateKeys { index: 1 },
    "page item keys must be unique (index 1)"
)]
#[case::out_of_bounds_below(
    PageShapeError::KeyOutsideShardBounds { index: 0, below_start: true },
    "page item key is below shard start bound (index 0)"
)]
#[case::out_of_bounds_above(
    PageShapeError::KeyOutsideShardBounds { index: 0, below_start: false },
    "page item key is at or above shard end bound (index 0)"
)]
#[case::inverted_bounds(
    PageShapeError::InvertedBounds,
    "shard bounds are inverted (start >= end)"
)]
fn page_shape_error_display(#[case] error: PageShapeError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

#[test]
fn page_buf_rejects_empty_pages() {
    assert_eq!(
        PageBuf::<ScanItem>::try_new(Vec::new(), PageState::Complete),
        Err(PageShapeError::EmptyPage)
    );
}

#[test]
fn page_buf_preserves_state_and_items() {
    let cursor = Cursor::with_last_key(ItemKey::try_from_slice(b"k-2").unwrap());
    let state = PageState::HasMore {
        cursor: cursor.clone(),
    };
    let page = PageBuf::try_new(scan_items(&[b"k-1", b"k-2"]), state.clone()).unwrap();

    assert_eq!(page.len(), 2);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"k-1");
    assert_eq!(
        page.iter()
            .map(|item| item.item_key().as_bytes().to_vec())
            .collect::<Vec<_>>(),
        vec![b"k-1".to_vec(), b"k-2".to_vec()]
    );
    assert_eq!(page.state(), &state);

    let (items, returned_state) = page.into_parts();
    assert_eq!(items.len(), 2);
    assert_eq!(returned_state, state);
}

#[test]
fn page_state_reports_completion_and_resume_cursor() {
    let complete = PageState::Complete;
    assert!(complete.is_complete());
    assert!(complete.next_cursor().is_none());

    let resume = Cursor::with_token(
        ItemKey::try_from_slice(b"k-9").unwrap(),
        TokenBytes::try_from_slice(b"tok-9").unwrap(),
    );
    let has_more = PageState::HasMore {
        cursor: resume.clone(),
    };
    assert!(!has_more.is_complete());
    assert_eq!(has_more.next_cursor(), Some(&resume));
}

#[test]
fn paging_capabilities_default_is_conservative() {
    let caps = PagingCapabilities::default();
    assert!(!caps.ordered_keys);
    assert!(!caps.resumable);
    assert!(!caps.splittable);
}

#[test]
fn paging_capabilities_fields_are_independent() {
    let caps = PagingCapabilities {
        ordered_keys: true,
        resumable: false,
        splittable: true,
    };
    assert!(caps.ordered_keys);
    assert!(!caps.resumable);
    assert!(caps.splittable);
}

#[test]
fn scan_item_implements_keyed_page_item() {
    let item = scan_item_with_key(b"alpha", 7);
    assert_eq!(KeyedPageItem::item_key(&item).as_bytes(), b"alpha");
    assert_eq!(KeyedPageItem::size_hint(&item), Some(8));
}

#[test]
fn validate_filled_page_accepts_sorted_items_within_bounds() {
    let items = scan_items(&[b"a", b"b", b"c"]);
    assert_eq!(validate_filled_page(&items, b"a", b"d"), Ok(()));
    assert_eq!(validate_filled_page(&items, b"", b""), Ok(()));
}

#[test]
fn validate_filled_page_rejects_empty_page() {
    let items: Vec<ScanItem> = Vec::new();
    assert_eq!(
        validate_filled_page(&items, b"", b""),
        Err(PageShapeError::EmptyPage)
    );
}

#[test]
fn validate_filled_page_rejects_unsorted_keys() {
    let items = scan_items(&[b"a", b"c", b"b"]);
    assert_eq!(
        validate_filled_page(&items, b"", b""),
        Err(PageShapeError::UnsortedKeys { index: 2 })
    );
}

#[test]
fn validate_filled_page_rejects_duplicate_keys() {
    let items = scan_items(&[b"a", b"b", b"b"]);
    assert_eq!(
        validate_filled_page(&items, b"", b""),
        Err(PageShapeError::DuplicateKeys { index: 2 })
    );
}

#[test]
fn validate_filled_page_rejects_inverted_shard_bounds() {
    let items = scan_items(&[b"a", b"b", b"c"]);
    assert_eq!(
        validate_filled_page(&items, b"z", b"a"),
        Err(PageShapeError::InvertedBounds)
    );
}

#[test]
fn validate_filled_page_rejects_equal_shard_bounds() {
    // Equal bounds define an empty half-open interval [x, x) — no key can satisfy it.
    let items = scan_items(&[b"m"]);
    assert_eq!(
        validate_filled_page(&items, b"m", b"m"),
        Err(PageShapeError::InvertedBounds)
    );
}

#[rstest]
#[case::before_start(scan_items(&[b"a", b"b"]), b"b", b"", PageShapeError::KeyOutsideShardBounds { index: 0, below_start: true })]
#[case::at_end(scan_items(&[b"a", b"c"]), b"", b"c", PageShapeError::KeyOutsideShardBounds { index: 1, below_start: false })]
#[case::single_at_end(scan_items(&[b"z"]), b"a", b"z", PageShapeError::KeyOutsideShardBounds { index: 0, below_start: false })]
fn validate_filled_page_rejects_out_of_bounds_keys(
    #[case] items: Vec<ScanItem>,
    #[case] start: &[u8],
    #[case] end: &[u8],
    #[case] expected: PageShapeError,
) {
    assert_eq!(validate_filled_page(&items, start, end), Err(expected));
}

#[test]
fn validate_filled_page_inclusive_start_boundary() {
    // key == shard_start is inside the half-open [start, end) interval.
    assert_eq!(
        validate_filled_page(&scan_items(&[b"m"]), b"m", b"z"),
        Ok(())
    );
}

#[test]
fn validate_filled_page_start_bounded_end_unbounded() {
    // Empty end means unbounded — all keys >= start are valid.
    assert_eq!(
        validate_filled_page(&scan_items(&[b"m", b"z"]), b"a", b""),
        Ok(())
    );
}

#[test]
fn validate_filled_page_start_unbounded_end_bounded() {
    // Empty start means unbounded — all keys < end are valid.
    assert_eq!(
        validate_filled_page(&scan_items(&[b"a", b"b"]), b"", b"c"),
        Ok(())
    );
}

#[test]
fn try_new_validated_accepts_valid_page() {
    let items = scan_items(&[b"a", b"b", b"c"]);
    let page = PageBuf::try_new_validated(items, PageState::Complete, b"a", b"d").unwrap();
    assert_eq!(page.len(), 3);
    assert!(page.state().is_complete());
}

#[test]
fn try_new_validated_rejects_empty() {
    assert_eq!(
        PageBuf::<ScanItem>::try_new_validated(Vec::new(), PageState::Complete, b"a", b"z"),
        Err(PageShapeError::EmptyPage)
    );
}

#[test]
fn try_new_validated_rejects_unsorted() {
    let items = scan_items(&[b"c", b"a"]);
    assert_eq!(
        PageBuf::try_new_validated(items, PageState::Complete, b"", b""),
        Err(PageShapeError::UnsortedKeys { index: 1 })
    );
}

#[test]
fn validate_filled_page_returns_empty_page_when_items_empty_and_bounds_inverted() {
    // Empty input should always yield EmptyPage, even when bounds are also inverted.
    let items: Vec<ScanItem> = Vec::new();
    assert_eq!(
        validate_filled_page(&items, b"z", b"a"),
        Err(PageShapeError::EmptyPage)
    );
}

#[test]
fn try_new_validated_returns_empty_page_when_items_empty_and_bounds_inverted() {
    // Same consistency requirement through the PageBuf constructor path.
    assert_eq!(
        PageBuf::<ScanItem>::try_new_validated(Vec::new(), PageState::Complete, b"z", b"a"),
        Err(PageShapeError::EmptyPage)
    );
}

#[test]
fn try_new_validated_rejects_inverted_bounds() {
    let items = scan_items(&[b"m"]);
    assert_eq!(
        PageBuf::try_new_validated(items, PageState::Complete, b"z", b"a"),
        Err(PageShapeError::InvertedBounds)
    );
}

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn sorted_unique_pages_validate_under_matching_bounds(keys in arb_sorted_unique_keys(1, 16)) {
        let items = scan_items_from_vecs(&keys);
        let start = keys.first().unwrap().clone();
        let mut end = keys.last().unwrap().clone();
        end.push(0);

        prop_assert_eq!(validate_filled_page(&items, &start, &end), Ok(()));
    }

    #[test]
    fn duplicate_keys_are_rejected_in_sorted_pages(keys in arb_sorted_unique_keys(1, 16)) {
        let mut dup_keys = keys.clone();
        let duplicate = dup_keys[0].clone();
        dup_keys.insert(1, duplicate);
        let items = scan_items_from_vecs(&dup_keys);

        prop_assert_eq!(
            validate_filled_page(&items, b"", b""),
            Err(PageShapeError::DuplicateKeys { index: 1 })
        );
    }

    #[test]
    fn descending_pair_is_rejected(keys in arb_sorted_unique_keys(2, 16)) {
        let mut unsorted = keys.clone();
        unsorted.swap(0, 1);
        let items = scan_items_from_vecs(&unsorted);

        prop_assert_eq!(
            validate_filled_page(&items, b"", b""),
            Err(PageShapeError::UnsortedKeys { index: 1 })
        );
    }
}
