//! Regression tests for the in-memory connector's deterministic behavior.
//!
//! The connector is used as a reference implementation in higher-level tests, so
//! this module focuses on invariants that other components rely on rather than on
//! exhaustive API documentation. In particular, these tests lock down:
//!
//! - split-point selection across empty, bounded, unbounded, and cursor-advanced
//!   ranges;
//! - rejection paths for malformed references and inverted ranges;
//! - duplicate-key enforcement, including panic-message redaction guarantees; and
//! - identity and capability behavior that must remain stable across connectors.
//!
//! Several cases intentionally exercise byte-weighted balancing instead of simple
//! item-count balancing. The degenerate cases also verify that the connector falls
//! back to a count-based split when a byte-weighted median would otherwise point at
//! the first eligible item and fail to advance the shard.

use rstest::rstest;

use super::*;
use crate::common::test_util::{default_budgets, make_key};

/// Builds a `MemItem` fixture from raw bytes.
///
/// Keys are normalized through `make_key` so test assertions match the same
/// canonical key representation used by connector code paths.
fn make_item(key: &[u8], data: &[u8]) -> MemItem {
    MemItem::new(make_key(key), Vec::from(data))
}

#[rstest]
#[case::fewer_than_two(vec![make_item(b"only", b"1")], Cursor::initial())]
#[case::empty_set(vec![], Cursor::initial())]
#[case::cursor_past_midpoint(
    vec![make_item(b"a", b"1"), make_item(b"b", b"2"), make_item(b"c", b"3")],
    Cursor::with_last_key(make_key(b"b")),
)]
/// Ensures `choose_split_point_range` yields `None` when the split cannot advance (too few items, empty set, or cursor past midpoint).
fn split_point_returns_none(#[case] items: Vec<MemItem>, #[case] cursor: Cursor) {
    let mut c = InMemoryDeterministicConnector::new(items);
    let split = c
        .choose_split_point_range(&make_key(b"a"), &make_key(b"z"), &cursor)
        .unwrap();
    assert!(split.is_none());
}

/// Well-formed `ItemRef` bytes that decode to an out-of-bounds item index.
///
/// This separates "shape is valid but index is invalid" from malformed-byte
/// cases so error handling is exercised for both rejection paths.
const BAD_INDEX_BYTES: [u8; 8] = 999u64.to_be_bytes();

#[rstest]
#[case::out_of_bounds(&BAD_INDEX_BYTES)]
#[case::malformed(b"short")]
/// Invalid reference bytes must cause both `open` and `read_range` to return errors without panic.
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

#[test]
#[should_panic(expected = "unique item keys")]
/// Confirms that constructing the connector panics when duplicate keys are provided.
fn duplicate_keys_panic() {
    let items = vec![make_item(b"dup", b"first"), make_item(b"dup", b"second")];
    InMemoryDeterministicConnector::new(items);
}

#[test]
/// Verifies the duplicate-key panic message references the contract while redacting raw key bytes.
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

#[test]
/// Passing a shard with `start > end` triggers an error instead of producing a split.
fn inverted_range_split_returns_error() {
    let items = vec![make_item(b"a", b"1"), make_item(b"b", b"2")];
    let mut c = InMemoryDeterministicConnector::new(items);

    let start = make_key(b"z");
    let end = make_key(b"a");
    let result = c.choose_split_point_range(&start, &end, &Cursor::initial());
    assert!(result.is_err(), "inverted range should return an error");
}

#[test]
/// A valid bounded range should produce a split strictly between the start and end keys.
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
/// Byte-weighted splitting favors heavy items even when count-based midpoints would differ.
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

#[test]
/// Token-resume capability reflects the connector's `with_tokens` configuration.
fn caps_reflect_token_setting() {
    let c_with = InMemoryDeterministicConnector::new(vec![]);
    assert!(c_with.caps().token_resume);

    let c_without = InMemoryDeterministicConnector::new(vec![]).with_tokens(false);
    assert!(!c_without.caps().token_resume);
}

#[test]
/// Different connector tags produce distinct stable IDs for the same key/instance.
fn different_tags_produce_different_stable_ids() {
    use gossip_contracts::identity::{ConnectorTag, ItemIdentityKey};

    let tag_a = ConnectorTag::from_ascii(b"tagA");
    let tag_b = ConnectorTag::from_ascii(b"tagB");
    let instance =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-a");
    let key = make_key(b"same-key");

    let id_a = ItemIdentityKey::new(tag_a, instance, key.as_bytes()).stable_id();
    let id_b = ItemIdentityKey::new(tag_b, instance, key.as_bytes()).stable_id();
    assert_ne!(id_a, id_b);
}

#[test]
/// Different connector instances (even with the same tag) yield unique stable IDs.
fn different_instances_produce_different_stable_ids() {
    use crate::IN_MEMORY_CONNECTOR_TAG;
    use gossip_contracts::identity::ItemIdentityKey;

    let key = make_key(b"same-key");
    let instance_a =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-a");
    let instance_b =
        gossip_contracts::identity::ConnectorInstanceIdHash::from_instance_id_bytes(b"dataset-b");

    let id_a =
        ItemIdentityKey::new(IN_MEMORY_CONNECTOR_TAG, instance_a, key.as_bytes()).stable_id();
    let id_b =
        ItemIdentityKey::new(IN_MEMORY_CONNECTOR_TAG, instance_b, key.as_bytes()).stable_id();
    assert_ne!(id_a, id_b);
}

#[test]
/// `choose_split_point` with a scoped `ShardSpec` should return a split hint when items exist.
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
/// Unbounded and one-sided shard specs must still expose a split hint if possible.
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

#[test]
/// When a byte-weighted median would not advance the shard, the connector falls back to the count midpoint.
fn split_point_degenerate_first_item_heavy() {
    // When the byte-weighted median lands on the first eligible item, the
    // connector must fall back to a count-based midpoint so the split still
    // advances beyond the shard start.
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
    // With three items, the fallback midpoint is the middle element.
    assert_eq!(split.as_bytes(), b"b");
}

mod prop {
    //! Property tests for split-point ordering guarantees.
    //!
    //! The strategy deliberately enforces unique keys because the connector
    //! constructor rejects duplicates. That keeps generated cases focused on
    //! split behavior instead of constructor precondition failures.

    use super::*;
    use proptest::collection::vec as pvec;
    use proptest::prelude::*;

    use gossip_stdx::test_support::proptest_cases;

    /// Generates test items while preserving the connector's unique-key invariant.
    fn item_vec_strategy(max_items: usize) -> impl Strategy<Value = Vec<MemItem>> {
        pvec(pvec(1u8..=127u8, 1..8usize), 0..max_items).prop_map(|key_vecs| {
            // The constructor rejects duplicate keys, so the strategy filters them
            // out before materializing `MemItem` values.
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
        /// Proptest ensures any returned split stays strictly between the cursor and end bounds.
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
