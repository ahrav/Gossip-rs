use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key};

// ---------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------

fn make_item(key: &[u8], data: &[u8]) -> MemItem {
    MemItem::new(make_key(key), Vec::from(data))
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
    let mut c = InMemoryDeterministicConnector::new(items);
    let split = c
        .choose_split_point_range(&make_key(b"a"), &make_key(b"z"), &cursor)
        .unwrap();
    assert!(split.is_none());
}

// ---------------------------------------------------------------
// Invalid ItemRef (parameterized)
// ---------------------------------------------------------------

const BAD_INDEX_BYTES: [u8; 8] = 999u64.to_be_bytes();

#[rstest]
#[case::out_of_bounds(&BAD_INDEX_BYTES)]
#[case::malformed(b"short")]
fn invalid_item_ref_returns_error(#[case] ref_bytes: &[u8]) {
    let mut c = InMemoryDeterministicConnector::new(vec![make_item(b"key", b"data")]);
    let bad_ref = ItemRef::try_from_slice(ref_bytes).unwrap();
    assert!(c.open(&bad_ref, default_budgets()).is_err());
    let mut buf = [0u8; 16];
    assert!(
        c.read_range(&bad_ref, 0, &mut buf, default_budgets())
            .is_err()
    );
}

// ---------------------------------------------------------------
// Duplicate key rejection
// ---------------------------------------------------------------

#[test]
#[should_panic(expected = "unique item keys")]
fn duplicate_keys_panic() {
    let items = vec![make_item(b"dup", b"first"), make_item(b"dup", b"second")];
    InMemoryDeterministicConnector::new(items);
}

#[test]
fn duplicate_keys_panic_redacts_item_key() {
    // Use a non-printable byte (\xff) so the negative assertions guard against
    // both `{:?}` byte-array leaks *and* any `from_utf8_lossy` string-form leaks.
    let key_bytes: &[u8] = b"dup\xffsecret";
    let items = vec![
        make_item(key_bytes, b"first"),
        make_item(key_bytes, b"second"),
    ];

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        InMemoryDeterministicConnector::new(items);
    }))
    .expect_err("duplicate keys should panic");

    let panic_msg = panic
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| panic.downcast_ref::<&str>().copied())
        .unwrap_or("");
    let redacted = format!("{}", make_key(key_bytes));
    let raw_bytes = format!("{:?}", key_bytes);

    assert!(
        panic_msg.contains("unique item keys"),
        "panic should explain the duplicate-key contract: {panic_msg}"
    );
    assert!(
        panic_msg.contains(&redacted),
        "panic should use redacted ItemKey formatting: {panic_msg}"
    );
    assert!(
        !panic_msg.contains(&raw_bytes),
        "panic leaked raw key bytes: {panic_msg}"
    );
    // Guard against from_utf8_lossy paths that would reveal partial key content.
    let lossy = String::from_utf8_lossy(key_bytes);
    assert!(
        !panic_msg.contains(lossy.as_ref()),
        "panic leaked lossy UTF-8 key representation: {panic_msg}"
    );
}

// ---------------------------------------------------------------
// Inverted range rejection
// ---------------------------------------------------------------

#[test]
fn inverted_range_split_returns_error() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(items);

    let start = make_key(b"z");
    let end = make_key(b"a");
    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
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
    let mut c = InMemoryDeterministicConnector::new(items);
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
    let mut c = InMemoryDeterministicConnector::new(items);
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
// Capabilities
// ---------------------------------------------------------------

#[test]
fn caps_reflect_token_setting() {
    let c_with = InMemoryDeterministicConnector::new(vec![]);
    assert!(c_with.caps().token_resume);

    let c_without = InMemoryDeterministicConnector::new(vec![]).with_tokens(false);
    assert!(!c_without.caps().token_resume);
}

// ---------------------------------------------------------------
// Identity derivation
// ---------------------------------------------------------------

#[test]
fn different_tags_produce_different_stable_ids() {
    use crate::common::derive_stable_item_id;
    use gossip_contracts::identity::ConnectorTag;

    let tag_a = ConnectorTag::from_ascii(b"tagA");
    let tag_b = ConnectorTag::from_ascii(b"tagB");
    let instance =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-a");
    let key = make_key(b"same-key");

    let id_a = derive_stable_item_id(tag_a, instance, &key);
    let id_b = derive_stable_item_id(tag_b, instance, &key);
    assert_ne!(id_a, id_b);
}

#[test]
fn different_instances_produce_different_stable_ids() {
    use crate::common::IN_MEMORY_CONNECTOR_TAG;
    use crate::common::derive_stable_item_id;

    let key = make_key(b"same-key");
    let instance_a =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-a");
    let instance_b =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-b");

    let id_a = derive_stable_item_id(IN_MEMORY_CONNECTOR_TAG, instance_a, &key);
    let id_b = derive_stable_item_id(IN_MEMORY_CONNECTOR_TAG, instance_b, &key);
    assert_ne!(id_a, id_b);
}

// ---------------------------------------------------------------
// ShardSpec-based split point
// ---------------------------------------------------------------

#[test]
fn choose_split_point_via_shard_spec() {
    let items = vec![
        make_item(b"a", b"1"),
        make_item(b"b", b"2"),
        make_item(b"c", b"3"),
        make_item(b"d", b"4"),
    ];
    let mut c = InMemoryDeterministicConnector::new(items);

    let shard = ShardSpec::try_with_range(b"a", b"z").unwrap();
    let split = c
        .choose_split_point(&shard, &Cursor::initial(), default_budgets())
        .unwrap();
    assert!(split.is_some(), "should produce a split point");
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
    let mut c = InMemoryDeterministicConnector::new(items);

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

// ---------------------------------------------------------------
// Degenerate split point
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
    let mut c = InMemoryDeterministicConnector::new(items);
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
        fn split_point_strictly_between_cursor_and_end(
            items in item_vec_strategy(30),
        ) {
            let start = make_key(b"\x01");
            let end = make_key(b"\x80");
            let mut c = InMemoryDeterministicConnector::new(items);

            if let Ok(Some(split)) = c.choose_split_point_range(
                &start, &end, &Cursor::initial(),
            ) {
                prop_assert!(split > start);
                prop_assert!(split < end);
            }
        }
    }
}
