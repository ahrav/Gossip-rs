use std::io::Read as _;
use std::time::{Duration, Instant};

use gossip_contracts::connector::conformance::{check_connector_conforms, ConformanceConfig};
use rstest::rstest;

use super::*;

// ---------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------

const TAG: ConnectorTag = ConnectorTag::from_ascii(b"inmemdet");

fn make_key(s: &[u8]) -> ItemKey {
    ItemKey::try_from_slice(s).expect("test key")
}

fn make_item(key: &[u8], data: &[u8]) -> MemItem {
    MemItem::new(make_key(key), Vec::from(data))
}

fn default_budgets() -> Budgets {
    Budgets::try_new(100, u64::MAX, None).unwrap()
}

fn small_page_budgets(max_items: usize) -> Budgets {
    Budgets::try_new(max_items, u64::MAX, None).unwrap()
}

/// Collect all items from a connector by paging until empty.
fn collect_all(
    connector: &mut InMemoryDeterministicConnector,
    start: &ItemKey,
    end: &ItemKey,
) -> Vec<ScanItem> {
    let mut all = Vec::new();
    let mut cursor = Cursor::initial();
    loop {
        let page = connector
            .enumerate_page_range(start, end, &cursor, default_budgets())
            .unwrap();
        if page.items().is_empty() {
            break;
        }
        cursor = page.next_cursor().clone();
        all.extend(page.into_parts().0);
    }
    all
}

/// Enumerate a single-item connector and return the first item's [`ItemRef`].
fn enumerate_single_item_ref(c: &mut InMemoryDeterministicConnector) -> ItemRef {
    let start = make_key(b"a");
    let end = make_key(b"z");
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    page.items()[0].item_ref().clone()
}

// ---------------------------------------------------------------
// Conformance harness integration (parameterized)
// ---------------------------------------------------------------

#[rstest]
#[case::default_config(
    vec![
        make_item(b"alpha", b"data-a"),
        make_item(b"bravo", b"data-b"),
        make_item(b"charlie", b"data-c"),
        make_item(b"delta", b"data-d"),
        make_item(b"echo", b"data-e"),
    ],
    true,
    ConformanceConfig::default(),
)]
#[case::no_tokens(
    vec![
        make_item(b"alpha", b"data-a"),
        make_item(b"bravo", b"data-b"),
        make_item(b"charlie", b"data-c"),
    ],
    false,
    ConformanceConfig::default(),
)]
#[case::small_pages(
    vec![
        make_item(b"a1", b"1"),
        make_item(b"b2", b"2"),
        make_item(b"c3", b"3"),
        make_item(b"d4", b"4"),
        make_item(b"e5", b"5"),
    ],
    true,
    ConformanceConfig {
        page_budgets: small_page_budgets(2),
        ..ConformanceConfig::default()
    },
)]
fn conformance_harness(
    #[case] items: Vec<MemItem>,
    #[case] tokens_enabled: bool,
    #[case] config: ConformanceConfig,
) {
    let start = make_key(b"a");
    let end = make_key(b"z");
    check_connector_conforms(
        || {
            let c = InMemoryDeterministicConnector::new(TAG, items.clone());
            if tokens_enabled {
                c
            } else {
                c.with_tokens(false)
            }
        },
        |c| c.caps(),
        |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
        &start,
        &end,
        config,
    )
    .expect("conformance harness should pass");
}

// ---------------------------------------------------------------
// Shard bounds (parameterized)
// ---------------------------------------------------------------

#[rstest]
#[case::between_items(b"b", b"d", vec![b"b".as_slice(), b"c"])]
#[case::exact_on_items(b"a", b"c", vec![b"a".as_slice(), b"b"])]
#[case::no_items_in_range(b"m", b"n", vec![])]
fn shard_bounds(#[case] start: &[u8], #[case] end: &[u8], #[case] expected: Vec<&[u8]>) {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"z", b"9"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let all = collect_all(&mut c, &make_key(start), &make_key(end));
    let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
    assert_eq!(keys, expected);
}

// ---------------------------------------------------------------
// Split point None cases (parameterized)
// ---------------------------------------------------------------

#[rstest]
#[case::fewer_than_two(vec![make_item(b"only", b"1")], Cursor::initial())]
#[case::empty_set(vec![], Cursor::initial())]
#[case::cursor_past_midpoint(
    vec![make_item(b"a", b"1"), make_item(b"b", b"2"), make_item(b"c", b"3")],
    Cursor::with_last_key(make_key(b"b")),
)]
fn split_point_returns_none(#[case] items: Vec<MemItem>, #[case] cursor: Cursor) {
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let split = c
        .choose_split_point_range(&make_key(b"a"), &make_key(b"z"), &cursor)
        .unwrap();
    assert!(split.is_none());
}

// ---------------------------------------------------------------
// read_range edge cases (parameterized)
// ---------------------------------------------------------------

#[rstest]
#[case::offset_beyond_length(1000, 32, Ok(0))]
#[case::zero_length_dst(0, 0, Ok(0))]
#[case::overflow_offset(u64::MAX, 16, Err(()))]
fn read_range_edge_cases(
    #[case] offset: u64,
    #[case] buf_size: usize,
    #[case] expected: Result<usize, ()>,
) {
    let mut c = InMemoryDeterministicConnector::new(TAG, vec![make_item(b"key", b"short payload")]);
    let item_ref = enumerate_single_item_ref(&mut c);
    let mut buf = vec![0u8; buf_size];
    let result = c.read_range(&item_ref, offset, &mut buf, default_budgets());
    match expected {
        Ok(n) => assert_eq!(result.unwrap(), n),
        Err(()) => assert!(result.is_err()),
    }
}

// ---------------------------------------------------------------
// Invalid ItemRef (parameterized)
// ---------------------------------------------------------------

const BAD_INDEX_BYTES: [u8; 8] = 999u64.to_be_bytes();

#[rstest]
#[case::out_of_bounds(&BAD_INDEX_BYTES)]
#[case::malformed(b"short")]
fn invalid_item_ref_returns_error(#[case] ref_bytes: &[u8]) {
    let mut c = InMemoryDeterministicConnector::new(TAG, vec![make_item(b"key", b"data")]);
    let bad_ref = ItemRef::try_from_slice(ref_bytes).unwrap();
    assert!(c.open(&bad_ref, default_budgets()).is_err());
    let mut buf = [0u8; 16];
    assert!(c
        .read_range(&bad_ref, 0, &mut buf, default_budgets())
        .is_err());
}

// ---------------------------------------------------------------
// Standalone tests
// ---------------------------------------------------------------

#[test]
fn empty_set_returns_empty_page() {
    let mut c = InMemoryDeterministicConnector::new(TAG, vec![]);
    let start = make_key(b"a");
    let end = make_key(b"z");
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(page.items().is_empty());
}

#[test]
fn single_item_enumeration_and_resume() {
    let items = vec![make_item(b"key", b"payload")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    // First page returns the single item.
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 1);
    assert_eq!(page.items()[0].item_key().as_bytes(), b"key");

    // Resume from the cursor returns empty (exhausted).
    let page2 = c
        .enumerate_page_range(&start, &end, page.next_cursor(), default_budgets())
        .unwrap();
    assert!(page2.items().is_empty());
}

#[test]
fn expired_budget_returns_empty_page() {
    let items = vec![make_item(b"key", b"payload")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), expired)
        .unwrap();
    assert!(page.items().is_empty());
}

#[test]
fn token_enabled_vs_disabled_parity() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
    ];
    let start = make_key(b"a");
    let end = make_key(b"z");

    let mut with_tokens = InMemoryDeterministicConnector::new(TAG, items.clone());
    let mut without_tokens = InMemoryDeterministicConnector::new(TAG, items).with_tokens(false);

    let items_a = collect_all(&mut with_tokens, &start, &end);
    let items_b = collect_all(&mut without_tokens, &start, &end);

    // Same items, same order.
    assert_eq!(items_a.len(), items_b.len());
    for (a, b) in items_a.iter().zip(items_b.iter()) {
        assert_eq!(a.item_key(), b.item_key());
        assert_eq!(a.stable_item_id(), b.stable_item_id());
        assert_eq!(a.version(), b.version());
    }
}

#[test]
fn split_point_valid_returns_key_between_bounds() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("should produce a split point");
    assert!(split > make_key(b"a"));
    assert!(split < make_key(b"z"));
}

#[test]
fn open_reads_full_content() {
    let items = vec![make_item(b"key", b"hello world")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let item_ref = enumerate_single_item_ref(&mut c);

    let mut reader = c.open(&item_ref, default_budgets()).unwrap();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"hello world");
}

#[test]
fn open_budget_exceeded_returns_error() {
    let items = vec![make_item(b"key", b"large payload here")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let item_ref = enumerate_single_item_ref(&mut c);

    // Budget smaller than the payload.
    let small_budget = Budgets::try_new(100, 5, None).unwrap();
    let result = c.open(&item_ref, small_budget);
    assert!(result.is_err());
}

#[test]
fn caps_reflect_token_setting() {
    let c_with = InMemoryDeterministicConnector::new(TAG, vec![]);
    assert!(c_with.caps().token_resume);

    let c_without = InMemoryDeterministicConnector::new(TAG, vec![]).with_tokens(false);
    assert!(!c_without.caps().token_resume);
}

#[test]
fn pagination_respects_max_items_budget() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"e", b"5"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    // Page size 2: should get 3 pages (2+2+1).
    let budgets = small_page_budgets(2);
    let mut cursor = Cursor::initial();
    let mut total = 0;
    let mut page_count = 0;
    loop {
        let page = c
            .enumerate_page_range(&start, &end, &cursor, budgets)
            .unwrap();
        if page.items().is_empty() {
            break;
        }
        assert!(page.items().len() <= 2);
        total += page.items().len();
        page_count += 1;
        cursor = page.next_cursor().clone();
    }
    assert_eq!(total, 5);
    assert_eq!(page_count, 3);
}

#[test]
fn determinism_same_input_same_output() {
    let items = vec![
        make_item(b"c", b"3"),
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
    ];
    let start = make_key(b"a");
    let end = make_key(b"z");

    let mut c1 = InMemoryDeterministicConnector::new(TAG, items.clone());
    let mut c2 = InMemoryDeterministicConnector::new(TAG, items);

    let items1 = collect_all(&mut c1, &start, &end);
    let items2 = collect_all(&mut c2, &start, &end);

    assert_eq!(items1.len(), items2.len());
    for (a, b) in items1.iter().zip(items2.iter()) {
        assert_eq!(a.item_key(), b.item_key());
        assert_eq!(a.item_ref(), b.item_ref());
        assert_eq!(a.stable_item_id(), b.stable_item_id());
        assert_eq!(a.version(), b.version());
    }
}

#[test]
fn different_tags_produce_different_stable_ids() {
    let tag_a = ConnectorTag::from_ascii(b"tagA");
    let tag_b = ConnectorTag::from_ascii(b"tagB");
    let key = make_key(b"same-key");

    let id_a = derive_stable_item_id(tag_a, &key);
    let id_b = derive_stable_item_id(tag_b, &key);
    assert_ne!(id_a, id_b);
}

// ---------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------

mod prop {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    /// Strategy: generate 0..max_items unique keys as short byte strings.
    fn item_vec_strategy(max_items: usize) -> impl Strategy<Value = Vec<MemItem>> {
        pvec(pvec(1u8..=127u8, 1..8usize), 0..max_items).prop_map(|key_vecs| {
            // Deduplicate keys.
            let mut seen = std::collections::HashSet::new();
            key_vecs
                .into_iter()
                .filter(|k| seen.insert(k.clone()))
                .map(|k| {
                    let data = k.clone();
                    make_item(&k, &data)
                })
                .collect()
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn full_enum_yields_sorted_input(items in item_vec_strategy(30)) {
            let start = make_key(b"\x01");
            let end = make_key(b"\x80");
            let mut expected_keys: Vec<Vec<u8>> = items
                .iter()
                .map(|i| i.key.as_bytes().to_vec())
                .collect();
            expected_keys.sort();
            expected_keys.dedup();
            // Filter to range [start, end).
            let expected_keys: Vec<Vec<u8>> = expected_keys
                .into_iter()
                .filter(|k| k.as_slice() >= b"\x01" && k.as_slice() < b"\x80")
                .collect();

            let mut c = InMemoryDeterministicConnector::new(TAG, items);
            let all = collect_all(&mut c, &start, &end);
            let got_keys: Vec<Vec<u8>> = all
                .iter()
                .map(|i| i.item_key().as_bytes().to_vec())
                .collect();

            prop_assert_eq!(got_keys, expected_keys);
        }

        #[test]
        fn token_vs_no_token_same_items(items in item_vec_strategy(20)) {
            let start = make_key(b"\x01");
            let end = make_key(b"\x80");

            let mut with = InMemoryDeterministicConnector::new(TAG, items.clone());
            let mut without = InMemoryDeterministicConnector::new(TAG, items)
                .with_tokens(false);

            let a = collect_all(&mut with, &start, &end);
            let b = collect_all(&mut without, &start, &end);

            prop_assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(b.iter()) {
                prop_assert_eq!(x.item_key(), y.item_key());
            }
        }

        #[test]
        fn split_point_strictly_between_cursor_and_end(
            items in item_vec_strategy(30),
        ) {
            let start = make_key(b"\x01");
            let end = make_key(b"\x80");
            let mut c = InMemoryDeterministicConnector::new(TAG, items);

            if let Ok(Some(split)) = c.choose_split_point_range(
                &start, &end, &Cursor::initial(),
            ) {
                prop_assert!(split > start);
                prop_assert!(split < end);
            }
        }

        #[test]
        fn determinism_property(items in item_vec_strategy(20)) {
            let start = make_key(b"\x01");
            let end = make_key(b"\x80");

            let mut c1 = InMemoryDeterministicConnector::new(TAG, items.clone());
            let mut c2 = InMemoryDeterministicConnector::new(TAG, items);

            let a = collect_all(&mut c1, &start, &end);
            let b = collect_all(&mut c2, &start, &end);

            prop_assert_eq!(a.len(), b.len());
            for (x, y) in a.iter().zip(b.iter()) {
                prop_assert_eq!(x.item_key(), y.item_key());
                prop_assert_eq!(x.item_ref(), y.item_ref());
                prop_assert_eq!(x.stable_item_id(), y.stable_item_id());
                prop_assert_eq!(x.version(), y.version());
            }
        }
    }
}
