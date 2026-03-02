use std::io::Read as _;
use std::time::{Duration, Instant};

use gossip_contracts::connector::conformance::{ConformanceConfig, check_connector_conforms};
use gossip_contracts::connector::{MAX_ITEM_KEY_SIZE, TokenBytes};
use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key, small_page_budgets};

// ---------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------

const TAG: ConnectorTag = ConnectorTag::from_ascii(b"inmemdet");

fn make_item(key: &[u8], data: &[u8]) -> MemItem {
    MemItem::new(make_key(key), Vec::from(data))
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

/// Collect all items from a connector via the trait entrypoint.
fn collect_all_via_shard(
    connector: &mut InMemoryDeterministicConnector,
    shard: &ShardSpec,
    budgets: Budgets,
) -> Vec<ScanItem> {
    let mut all = Vec::new();
    let mut cursor = Cursor::initial();
    loop {
        let page = connector.enumerate_page(shard, &cursor, budgets).unwrap();
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
#[case::full_read(0, 32, Ok(13))]
#[case::partial_read_from_offset(6, 32, Ok(7))]
#[case::offset_beyond_length(1000, 32, Ok(0))]
#[case::zero_length_dst(0, 0, Ok(0))]
#[case::overflow_offset(u64::MAX, 16, Err(()))]
fn read_range_edge_cases(
    #[case] offset: u64,
    #[case] buf_size: usize,
    #[case] expected: Result<usize, ()>,
) {
    let content = b"short payload"; // 13 bytes
    let mut c = InMemoryDeterministicConnector::new(TAG, vec![make_item(b"key", content)]);
    let item_ref = enumerate_single_item_ref(&mut c);
    let mut buf = vec![0u8; buf_size];
    let result = c.read_range(&item_ref, offset, &mut buf, default_budgets());
    match expected {
        Ok(n) => {
            let actual_n = result.unwrap();
            assert_eq!(actual_n, n);
            if n > 0 {
                let start = offset as usize;
                assert_eq!(&buf[..n], &content[start..start + n]);
            }
        }
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
    assert!(
        c.read_range(&bad_ref, 0, &mut buf, default_budgets())
            .is_err()
    );
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
fn enumerate_page_uses_pooled_toxic_wrappers() {
    let items = vec![
        make_item(b"alpha", b"payload-a"),
        make_item(b"bravo", b"payload-b"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    // Items emitted from a page should carry slot-backed wrappers.
    assert!(
        !page.items().is_empty(),
        "fixture should produce a non-empty page"
    );
    for item in page.items() {
        assert!(
            item.item_key().is_pooled(),
            "item_key should be slab-backed"
        );
        assert!(
            item.item_ref().is_pooled(),
            "item_ref should be slab-backed"
        );
    }

    let next = page.next_cursor();
    // The continuation cursor should share the same pooled backing as page items.
    assert!(
        next.last_key().is_some_and(|last_key| last_key.is_pooled()),
        "next cursor key should share pooled storage"
    );
    assert!(
        next.token().is_some_and(|token| token.is_pooled()),
        "token should be slab-backed when emitted"
    );
}

#[test]
fn expired_budget_returns_retryable_error() {
    let items = vec![make_item(b"key", b"payload")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let expired =
        Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), expired);
    assert!(result.is_err(), "expired budget should return an error");
}

// ---------------------------------------------------------------
// Duplicate key rejection
// ---------------------------------------------------------------

#[test]
#[should_panic(expected = "unique item keys")]
fn duplicate_keys_panic() {
    let items = vec![make_item(b"dup", b"first"), make_item(b"dup", b"second")];
    InMemoryDeterministicConnector::new(TAG, items);
}

// ---------------------------------------------------------------
// Inverted range rejection
// ---------------------------------------------------------------

#[test]
fn inverted_range_returns_error() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    // start > end is invalid.
    let start = make_key(b"z");
    let end = make_key(b"a");
    let result = c.enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets());
    assert!(result.is_err(), "inverted range should return an error");
}

#[test]
fn inverted_range_split_returns_error() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let start = make_key(b"z");
    let end = make_key(b"a");
    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
}

// ---------------------------------------------------------------
// Token resume fast path
// ---------------------------------------------------------------

#[test]
fn token_resume_fast_path_produces_correct_results() {
    // Verify that the O(1) token fast path produces identical results
    // to the O(log n) key-based fallback across multi-page enumeration.
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"e", b"5"),
    ];
    let start = make_key(b"a");
    let end = make_key(b"z");
    let budgets = small_page_budgets(2);

    let mut c_token = InMemoryDeterministicConnector::new(TAG, items.clone());
    let mut c_key = InMemoryDeterministicConnector::new(TAG, items).with_tokens(false);

    let mut cursor_t = Cursor::initial();
    let mut cursor_k = Cursor::initial();
    loop {
        let page_t = c_token
            .enumerate_page_range(&start, &end, &cursor_t, budgets)
            .unwrap();
        let page_k = c_key
            .enumerate_page_range(&start, &end, &cursor_k, budgets)
            .unwrap();

        assert_eq!(page_t.items().len(), page_k.items().len());
        for (a, b) in page_t.items().iter().zip(page_k.items()) {
            assert_eq!(a.item_key(), b.item_key());
            assert_eq!(a.item_ref(), b.item_ref());
        }

        if page_t.items().is_empty() {
            break;
        }
        cursor_t = page_t.next_cursor().clone();
        cursor_k = page_k.next_cursor().clone();
    }
}

#[test]
fn corrupt_token_falls_back_to_key_search() {
    // Construct a cursor with a valid last_key but a bogus token.
    // The connector should fall back to key-based search and still
    // return correct results.
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    // First page to get a real cursor pointing after "a".
    let page = c
        .enumerate_page_range(&start, &end, &Cursor::initial(), small_page_budgets(1))
        .unwrap();
    assert_eq!(page.items()[0].item_key().as_bytes(), b"a");

    // Forge a cursor with the correct last_key but a bogus token.
    let bogus_token = TokenBytes::try_from_slice(&999u64.to_be_bytes()).unwrap();
    let corrupt_cursor = Cursor::with_token(make_key(b"a"), bogus_token);

    // Should still resume correctly after "a".
    let page2 = c
        .enumerate_page_range(&start, &end, &corrupt_cursor, default_budgets())
        .unwrap();
    let keys: Vec<&[u8]> = page2
        .items()
        .iter()
        .map(|i| i.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"b".as_slice(), b"c".as_slice()]);
}

// ---------------------------------------------------------------
// Split point: byte-weight balancing
// ---------------------------------------------------------------

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
fn split_point_byte_weight_favors_heavy_items() {
    // Items: a=1 byte, b=1 byte, c=1000 bytes, d=1 byte.
    // Total bytes = 1003. Half = 501.
    // Cumulative: a=1, b=2, c=1002 (>= 501). Split at c.
    // Count-midpoint would split at index 2 (b), byte-weight splits at c.
    let items = vec![
        make_item(b"a", b"x"),
        make_item(b"b", b"y"),
        make_item(b"c", &vec![0u8; 1000]),
        make_item(b"d", b"z"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("should produce a split point");
    // Byte-weight median should land at "c" (where cumulative >= half).
    assert_eq!(split.as_bytes(), b"c");
}

// ---------------------------------------------------------------
// ReadConnector: open
// ---------------------------------------------------------------

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
fn open_succeeds_regardless_of_byte_budget() {
    // open() no longer eagerly rejects oversized items; budget
    // enforcement is the runtime's responsibility.
    let items = vec![make_item(b"key", b"large payload here")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let item_ref = enumerate_single_item_ref(&mut c);

    let small_budget = Budgets::try_new(100, 5, None).unwrap();
    let mut reader = c
        .open(&item_ref, small_budget)
        .expect("open should succeed");
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).unwrap();
    assert_eq!(buf, b"large payload here");
}

// ---------------------------------------------------------------
// Clone / sharing
// ---------------------------------------------------------------

#[test]
fn clone_shares_data() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let c1 = InMemoryDeterministicConnector::new(TAG, items);
    let mut c2 = c1.clone();

    let start = make_key(b"a");
    let end = make_key(b"z");

    let page = c2
        .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(page.items().len(), 2);
}

// ---------------------------------------------------------------
// Remaining standalone tests
// ---------------------------------------------------------------

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
// Budget clamping (F10)
// ---------------------------------------------------------------

#[test]
fn read_range_budget_clamps_read() {
    let mut c = InMemoryDeterministicConnector::new(TAG, vec![make_item(b"key", b"0123456789")]);
    let item_ref = enumerate_single_item_ref(&mut c);

    let clamped_budget = Budgets::try_new(100, 3, None).unwrap();
    let mut buf = [0u8; 10];
    let n = c
        .read_range(&item_ref, 0, &mut buf, clamped_budget)
        .unwrap();
    assert_eq!(n, 3);
    assert_eq!(&buf[..n], b"012");
}

// ---------------------------------------------------------------
// ShardSpec trait-method coverage (F11)
// ---------------------------------------------------------------

#[test]
fn enumerate_page_via_shard_spec() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let shard = ShardSpec::try_with_range(b"a", b"c").unwrap();
    let page = c
        .enumerate_page(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    let keys: Vec<&[u8]> = page
        .items()
        .iter()
        .map(|i| i.item_key().as_bytes())
        .collect();
    assert_eq!(keys, vec![b"a".as_slice(), b"b".as_slice()]);
}

#[test]
fn choose_split_point_via_shard_spec() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let shard = ShardSpec::try_with_range(b"a", b"z").unwrap();
    let split = c
        .choose_split_point(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(split.is_some(), "should produce a split point");
}

#[test]
fn enumerate_page_via_shard_spec_unbounded_bounds() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let shard = ShardSpec::try_with_range(b"", b"").unwrap();

    let all = collect_all_via_shard(&mut c, &shard, small_page_budgets(2));
    let keys: Vec<&[u8]> = all.iter().map(|item| item.item_key().as_bytes()).collect();
    assert_eq!(
        keys,
        vec![
            b"a".as_slice(),
            b"b".as_slice(),
            b"c".as_slice(),
            b"d".as_slice()
        ]
    );
}

#[test]
fn enumerate_page_via_shard_spec_one_sided_unbounded_resumes() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"e", b"5"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let shard = ShardSpec::try_with_range(b"c", b"").unwrap();
    let budgets = small_page_budgets(2);

    let page1 = c
        .enumerate_page(&shard, &Cursor::initial(), budgets)
        .expect("first page");
    assert_eq!(page1.items().len(), 2);
    assert_eq!(page1.items()[0].item_key().as_bytes(), b"c");
    assert_eq!(page1.items()[1].item_key().as_bytes(), b"d");

    let page2 = c
        .enumerate_page(&shard, page1.next_cursor(), budgets)
        .expect("second page");
    assert_eq!(page2.items().len(), 1);
    assert_eq!(page2.items()[0].item_key().as_bytes(), b"e");

    let page3 = c
        .enumerate_page(&shard, page2.next_cursor(), budgets)
        .expect("terminal page");
    assert!(
        page3.items().is_empty(),
        "resume should terminate without dupes"
    );
}

#[test]
fn choose_split_point_via_shard_spec_unbounded_and_one_sided() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"e", b"5"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let unbounded = ShardSpec::try_with_range(b"", b"").unwrap();
    let split_unbounded = c
        .choose_split_point(&unbounded, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(
        split_unbounded.is_some(),
        "unbounded split should produce a hint"
    );

    let one_sided = ShardSpec::try_with_range(b"c", b"").unwrap();
    let split_one_sided = c
        .choose_split_point(&one_sided, &Cursor::initial(), default_budgets())
        .unwrap();
    assert_eq!(
        split_one_sided
            .expect("one-sided range should split")
            .as_bytes(),
        b"d",
    );
}

#[test]
fn enumerate_page_trait_and_range_paths_match_across_pages() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
        make_item(b"e", b"5"),
    ];
    let mut via_trait = InMemoryDeterministicConnector::new(TAG, items.clone());
    let mut via_range = InMemoryDeterministicConnector::new(TAG, items);
    let shard = ShardSpec::try_with_range(b"b", b"z").unwrap();
    let start = make_key(b"b");
    let end = make_key(b"z");
    let budgets = small_page_budgets(2);

    let mut cursor_trait = Cursor::initial();
    let mut cursor_range = Cursor::initial();
    loop {
        let trait_page = via_trait
            .enumerate_page(&shard, &cursor_trait, budgets)
            .expect("trait enumerate_page");
        let range_page = via_range
            .enumerate_page_range(&start, &end, &cursor_range, budgets)
            .expect("range enumerate_page");

        assert_eq!(trait_page.items().len(), range_page.items().len());
        for (left, right) in trait_page.items().iter().zip(range_page.items()) {
            assert_eq!(left.item_key(), right.item_key());
            assert_eq!(left.item_ref(), right.item_ref());
            assert_eq!(left.stable_item_id(), right.stable_item_id());
            assert_eq!(left.version(), right.version());
        }
        assert_eq!(
            trait_page.next_cursor().last_key(),
            range_page.next_cursor().last_key()
        );
        assert_eq!(
            trait_page.next_cursor().token().map(TokenBytes::as_bytes),
            range_page.next_cursor().token().map(TokenBytes::as_bytes)
        );

        if trait_page.items().is_empty() {
            break;
        }
        cursor_trait = trait_page.next_cursor().clone();
        cursor_range = range_page.next_cursor().clone();
    }
}

#[test]
fn trait_methods_reject_oversized_non_empty_bounds() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let oversized_start = ShardSpec::from_raw_parts(
        vec![b'x'; MAX_ITEM_KEY_SIZE + 1].into_boxed_slice(),
        Box::<[u8]>::default(),
        Box::<[u8]>::default(),
    );
    let err = c
        .enumerate_page(&oversized_start, &Cursor::initial(), default_budgets())
        .expect_err("oversized non-empty start bound should fail");
    assert!(
        !err.is_retryable(),
        "oversized non-empty start bound should be permanent"
    );
    assert!(
        err.message().contains("invalid shard start bound"),
        "error should identify malformed start bound"
    );

    let oversized_end = ShardSpec::from_raw_parts(
        Box::<[u8]>::default(),
        vec![b'y'; MAX_ITEM_KEY_SIZE + 1].into_boxed_slice(),
        Box::<[u8]>::default(),
    );
    let err = c
        .choose_split_point(&oversized_end, &Cursor::initial(), default_budgets())
        .expect_err("oversized non-empty end bound should fail");
    assert!(
        !err.is_retryable(),
        "oversized non-empty end bound should be permanent"
    );
    assert!(
        err.message().contains("invalid shard end bound"),
        "error should identify malformed end bound"
    );
}

#[test]
fn trait_methods_accept_exact_max_size_bound() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);

    let exact_start = ShardSpec::from_raw_parts(
        vec![b'x'; MAX_ITEM_KEY_SIZE].into_boxed_slice(),
        Box::<[u8]>::default(),
        Box::<[u8]>::default(),
    );
    // Exact-max-size bound must be accepted (boundary is `>`, not `>=`).
    c.enumerate_page(&exact_start, &Cursor::initial(), default_budgets())
        .expect("exact MAX_ITEM_KEY_SIZE start bound should be accepted");

    let exact_end = ShardSpec::from_raw_parts(
        Box::<[u8]>::default(),
        vec![b'y'; MAX_ITEM_KEY_SIZE].into_boxed_slice(),
        Box::<[u8]>::default(),
    );
    c.choose_split_point(&exact_end, &Cursor::initial(), default_budgets())
        .expect("exact MAX_ITEM_KEY_SIZE end bound should be accepted");
}

// ---------------------------------------------------------------
// Degenerate split point (F12)
// ---------------------------------------------------------------

#[test]
fn split_point_degenerate_first_item_heavy() {
    // First item holds >50% weight. Byte-weighted median exits on first
    // item (split_idx == start_idx), triggering the count-based fallback.
    let items = vec![
        make_item(b"a", &vec![0u8; 1000]),
        make_item(b"b", b"x"),
        make_item(b"c", b"y"),
    ];
    let mut c = InMemoryDeterministicConnector::new(TAG, items);
    let start = make_key(b"a");
    let end = make_key(b"z");

    let split = c
        .choose_split_point_range(&start, &end, &Cursor::initial())
        .unwrap();
    let split = split.expect("should produce a split point");
    // Count-fallback: 3 items, midpoint at index 1 -> "b".
    assert_eq!(split.as_bytes(), b"b");
}

// ---------------------------------------------------------------
// Property-based tests
// ---------------------------------------------------------------

mod prop {
    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    use gossip_stdx::test_support::proptest_cases;

    /// Strategy: generate 0..max_items unique keys as short byte strings.
    fn item_vec_strategy(max_items: usize) -> impl Strategy<Value = Vec<MemItem>> {
        pvec(pvec(1u8..=127u8, 1..8usize), 0..max_items).prop_map(|key_vecs| {
            // Deduplicate keys to satisfy the unique-key invariant.
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
        #![proptest_config(ProptestConfig::with_cases(proptest_cases(64)))]

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
                .filter(|k| k.as_slice() >= &b"\x01"[..] && k.as_slice() < &b"\x80"[..])
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
