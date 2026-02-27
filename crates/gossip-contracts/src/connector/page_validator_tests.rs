use rstest::rstest;

use super::{
    CursorWhich, PageItem, PageValidationDetails, PageValidationError, PageValidationViolation,
    ToxicDigest, validate_page_range,
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Item {
    k: Vec<u8>,
}

impl PageItem<Vec<u8>> for Item {
    fn item_key(&self) -> &Vec<u8> {
        &self.k
    }
}

fn key(bytes: &[u8]) -> Vec<u8> {
    bytes.to_vec()
}

fn item(bytes: &[u8]) -> Item {
    Item { k: key(bytes) }
}

// -- Rejection cases --

#[rstest]
#[case::spec_range_invalid(
    b"z", b"a", None, &[] as &[&[u8]], None,
    PageValidationViolation::SpecRangeInvalid,
)]
#[case::input_cursor_out_of_range(
    b"c", b"z", Some(b"a" as &[u8]), &[] as &[&[u8]], Some(b"a" as &[u8]),
    PageValidationViolation::InputCursorOutOfRange,
)]
#[case::next_cursor_out_of_range(
    b"a", b"m", Some(b"b" as &[u8]), &[b"c" as &[u8]], Some(b"z" as &[u8]),
    PageValidationViolation::NextCursorOutOfRange,
)]
#[case::item_out_of_range(
    b"a", b"c", None, &[b"c" as &[u8]], Some(b"c" as &[u8]),
    PageValidationViolation::ItemKeyOutOfRange,
)]
#[case::unsorted_items(
    b"a", b"z", None, &[b"b" as &[u8], b"a"], Some(b"b" as &[u8]),
    PageValidationViolation::ItemsNotOrdered,
)]
#[case::item_not_after_cursor(
    b"a", b"z", Some(b"b" as &[u8]), &[b"b" as &[u8]], Some(b"b" as &[u8]),
    PageValidationViolation::ItemsNotAfterCursor,
)]
#[case::missing_next_cursor(
    b"a", b"z", None, &[b"b" as &[u8]], None,
    PageValidationViolation::NextCursorMissing,
)]
#[case::next_cursor_behind_last_item(
    b"a", b"z", None, &[b"b" as &[u8], b"d"], Some(b"c" as &[u8]),
    PageValidationViolation::NextCursorBehindLastItem,
)]
#[case::cursor_regression(
    b"a", b"z", Some(b"c" as &[u8]), &[b"d" as &[u8]], Some(b"b" as &[u8]),
    PageValidationViolation::CursorRegressed,
)]
#[case::empty_page_cursor_advance(
    b"a", b"z", Some(b"a" as &[u8]), &[] as &[&[u8]], Some(b"b" as &[u8]),
    PageValidationViolation::EmptyPageCursorAdvanced,
)]
#[case::item_below_start_boundary(
    b"d", b"z", None, &[b"c" as &[u8]], Some(b"d" as &[u8]),
    PageValidationViolation::ItemKeyOutOfRange,
)]
fn rejects_violation(
    #[case] start: &[u8],
    #[case] end: &[u8],
    #[case] input: Option<&[u8]>,
    #[case] item_keys: &[&[u8]],
    #[case] next: Option<&[u8]>,
    #[case] expected: PageValidationViolation,
) {
    let start = key(start);
    let end = key(end);
    let input = input.map(key);
    let next = next.map(key);
    let items: Vec<Item> = item_keys.iter().map(|k| item(k)).collect();

    let err = validate_page_range(&start, &end, input.as_ref(), &items, next.as_ref()).unwrap_err();
    assert_eq!(err.violation(), expected);
}

/// A key type where `PartialEq` and `AsRef<[u8]>` disagree.
///
/// `PartialEq` compares `(data, tag)`, but `AsRef<[u8]>` exposes only
/// `data`. Two `TaggedKey` values with the same `data` but different `tag`
/// are *unequal* by `PartialEq` yet *equal* at byte level.
#[derive(Clone, Debug)]
struct TaggedKey {
    data: Vec<u8>,
    tag: u8,
}

impl TaggedKey {
    fn new(data: &[u8], tag: u8) -> Self {
        Self {
            data: data.to_vec(),
            tag,
        }
    }
}

impl PartialEq for TaggedKey {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.tag == other.tag
    }
}

impl Eq for TaggedKey {}

impl PartialOrd for TaggedKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TaggedKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.data.cmp(&other.data).then(self.tag.cmp(&other.tag))
    }
}

impl AsRef<[u8]> for TaggedKey {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

struct TaggedItem {
    k: TaggedKey,
}

impl PageItem<TaggedKey> for TaggedItem {
    fn item_key(&self) -> &TaggedKey {
        &self.k
    }
}

/// Regression: the empty-page check must compare byte-level representations,
/// not `K::PartialEq`. Two cursors with the same bytes but different metadata
/// (tag) are "the same cursor" from the page contract's perspective.
#[test]
fn empty_page_check_uses_byte_comparison_not_partial_eq() {
    let start = TaggedKey::new(b"a", 0);
    let end = TaggedKey::new(b"z", 0);
    // Same data bytes, different tag => PartialEq says not-equal,
    // but byte-level comparison says equal.
    let input = TaggedKey::new(b"c", 1);
    let next = TaggedKey::new(b"c", 2);

    // Empty page: cursor bytes haven't changed, so this should be Ok.
    let items: Vec<TaggedItem> = Vec::new();
    let result = validate_page_range(&start, &end, Some(&input), &items, Some(&next));
    assert!(
        result.is_ok(),
        "empty page with byte-equal cursors should pass, but got: {result:?}"
    );
}

// -- Acceptance cases --

#[rstest]
#[case::valid_page(
    b"a", b"z", Some(b"b" as &[u8]), &[b"c" as &[u8], b"d"], Some(b"d" as &[u8]),
)]
#[case::unbounded_start(
    b"" as &[u8], b"m", None, &[b"a" as &[u8], b"b"], Some(b"b" as &[u8]),
)]
#[case::unbounded_end(
    b"m", b"" as &[u8], None, &[b"n" as &[u8], b"z"], Some(b"z" as &[u8]),
)]
#[case::fully_unbounded(
    b"" as &[u8], b"" as &[u8], None, &[b"a" as &[u8], b"m", b"z"], Some(b"z" as &[u8]),
)]
#[case::first_page_no_input_cursor(
    b"a", b"z", None, &[b"b" as &[u8], b"c"], Some(b"c" as &[u8]),
)]
#[case::single_item_page(
    b"a", b"z", None, &[b"c" as &[u8]], Some(b"c" as &[u8]),
)]
#[case::duplicate_keys(
    b"a", b"z", None, &[b"b" as &[u8], b"b"], Some(b"b" as &[u8]),
)]
#[case::empty_page_stable_cursor(
    b"a", b"z", Some(b"d" as &[u8]), &[] as &[&[u8]], Some(b"d" as &[u8]),
)]
#[case::next_cursor_equals_last_item(
    b"a", b"z", Some(b"b" as &[u8]), &[b"c" as &[u8], b"d"], Some(b"d" as &[u8]),
)]
#[case::extreme_low_bytes_unbounded_start(
    b"" as &[u8], b"z", None, &[b"\x00" as &[u8], b"a"], Some(b"a" as &[u8]),
)]
#[case::extreme_high_bytes_unbounded_end(
    b"a", b"" as &[u8], None, &[b"y" as &[u8], b"z", b"\xff"], Some(b"\xff" as &[u8]),
)]
#[case::extreme_bytes_fully_unbounded(
    b"" as &[u8], b"" as &[u8], None, &[b"\x00" as &[u8], b"\x80", b"\xff"], Some(b"\xff" as &[u8]),
)]
#[case::duplicate_keys_in_middle(
    b"a", b"z", None, &[b"m" as &[u8], b"m", b"n"], Some(b"n" as &[u8]),
)]
#[case::cursor_at_exact_end_boundary(
    b"a", b"m", None, &[b"b" as &[u8]], Some(b"m" as &[u8]),
)]
#[case::empty_page_no_cursors(
    b"a", b"z", None, &[] as &[&[u8]], None,
)]
#[case::item_at_start_boundary(
    b"b", b"z", None, &[b"b" as &[u8]], Some(b"b" as &[u8]),
)]
#[case::cursor_at_upper_bound_with_input(
    b"a", b"m", Some(b"b" as &[u8]), &[b"c" as &[u8]], Some(b"m" as &[u8]),
)]
fn accepts_valid_page(
    #[case] start: &[u8],
    #[case] end: &[u8],
    #[case] input: Option<&[u8]>,
    #[case] item_keys: &[&[u8]],
    #[case] next: Option<&[u8]>,
) {
    let start = key(start);
    let end = key(end);
    let input = input.map(key);
    let next = next.map(key);
    let items: Vec<Item> = item_keys.iter().map(|k| item(k)).collect();

    let result = validate_page_range(&start, &end, input.as_ref(), &items, next.as_ref());
    assert!(result.is_ok(), "expected Ok, got: {result:?}");
}

// -- ToxicDigest tests --

#[test]
fn toxic_digest_display_format() {
    let digest = ToxicDigest::of(b"hello");
    let display = format!("{digest}");

    // Format: `len=N, hash=XXXXXXXXXXXXXXXX` (16 hex chars).
    assert!(
        display.starts_with("len=5, hash="),
        "unexpected prefix: {display}"
    );
    let hash_part = &display["len=5, hash=".len()..];
    assert_eq!(hash_part.len(), 16, "hash prefix should be 16 hex chars");
    assert!(
        hash_part.chars().all(|c| c.is_ascii_hexdigit()),
        "hash should be hex: {hash_part}"
    );

    // Debug delegates to Display.
    assert_eq!(format!("{digest:?}"), display);
}

// -- Details assertions for rejection cases --

#[test]
fn rejects_out_of_range_item_key_details() {
    let start = key(b"a");
    let end = key(b"c");
    let items = vec![item(b"c")];
    let next = key(b"c");
    let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
    assert_eq!(err.violation(), PageValidationViolation::ItemKeyOutOfRange);
    match err.details() {
        PageValidationDetails::ItemOutOfRange {
            index,
            key,
            start,
            end,
        } => {
            assert_eq!(*index, 0);
            assert_eq!(*key, ToxicDigest::of(b"c"));
            assert_eq!(*start, ToxicDigest::of(b"a"));
            assert_eq!(*end, ToxicDigest::of(b"c"));
        }
        other => panic!("expected ItemOutOfRange, got: {other:?}"),
    }
    assert!(err.to_string().contains("item key out of range"));
}

#[test]
fn rejects_unsorted_items_details() {
    let start = key(b"a");
    let end = key(b"z");
    let items = vec![item(b"b"), item(b"a")];
    let next = key(b"b");
    let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
    assert_eq!(err.violation(), PageValidationViolation::ItemsNotOrdered);
    match err.details() {
        PageValidationDetails::ItemsNotOrdered { index, prev, next } => {
            assert_eq!(*index, 1);
            assert_eq!(*prev, ToxicDigest::of(b"b"));
            assert_eq!(*next, ToxicDigest::of(b"a"));
        }
        other => panic!("expected ItemsNotOrdered, got: {other:?}"),
    }
    assert!(err.to_string().contains("items not ordered"));
}

#[test]
fn rejects_item_not_after_cursor_details() {
    let start = key(b"a");
    let end = key(b"z");
    let input = key(b"b");
    let items = vec![item(b"b")];
    let next = key(b"b");
    let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::ItemsNotAfterCursor
    );
    match err.details() {
        PageValidationDetails::ItemsNotAfterCursor { cursor, first_item } => {
            assert_eq!(*cursor, ToxicDigest::of(b"b"));
            assert_eq!(*first_item, ToxicDigest::of(b"b"));
        }
        other => panic!("expected ItemsNotAfterCursor, got: {other:?}"),
    }
    assert!(err.to_string().contains("items must start strictly after"));
}

#[test]
fn rejects_next_cursor_behind_last_item_details() {
    let start = key(b"a");
    let end = key(b"z");
    let items = vec![item(b"b"), item(b"d")];
    let next = key(b"c");
    let err = validate_page_range(&start, &end, None, &items, Some(&next)).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::NextCursorBehindLastItem
    );
    match err.details() {
        PageValidationDetails::NextCursorBehindLastItem {
            next_cursor,
            last_item,
        } => {
            assert_eq!(*next_cursor, ToxicDigest::of(b"c"));
            assert_eq!(*last_item, ToxicDigest::of(b"d"));
        }
        other => panic!("expected NextCursorBehindLastItem, got: {other:?}"),
    }
    assert!(err.to_string().contains("next_cursor.last_key is behind"));
}

#[test]
fn rejects_cursor_regression_details() {
    let start = key(b"a");
    let end = key(b"z");
    let input = key(b"c");
    let items = vec![item(b"d")];
    let next = key(b"b");
    let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
    assert_eq!(err.violation(), PageValidationViolation::CursorRegressed);
    match err.details() {
        PageValidationDetails::CursorRegressed {
            input: d_input,
            next: d_next,
        } => {
            assert_eq!(*d_input, ToxicDigest::of(b"c"));
            assert_eq!(*d_next, ToxicDigest::of(b"b"));
        }
        other => panic!("expected CursorRegressed, got: {other:?}"),
    }
    assert!(err.to_string().contains("cursor regressed:"));
}

#[test]
fn rejects_empty_page_cursor_advance_details() {
    let start = key(b"a");
    let end = key(b"z");
    let input = key(b"a");
    let items: Vec<Item> = Vec::new();
    let next = key(b"b");
    let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::EmptyPageCursorAdvanced
    );
    match err.details() {
        PageValidationDetails::EmptyPageCursorAdvanced {
            input: d_input,
            next: d_next,
        } => {
            assert_eq!(*d_input, Some(ToxicDigest::of(b"a")));
            assert_eq!(*d_next, Some(ToxicDigest::of(b"b")));
        }
        other => panic!("expected EmptyPageCursorAdvanced, got: {other:?}"),
    }
    assert!(err.to_string().contains("empty page advanced cursor:"));
}

#[test]
fn rejects_spec_range_start_greater_than_end_details() {
    let start = key(b"z");
    let end = key(b"a");
    let items: Vec<Item> = Vec::new();
    let err = validate_page_range::<Vec<u8>, Item>(&start, &end, None, &items, None).unwrap_err();
    assert_eq!(err.violation(), PageValidationViolation::SpecRangeInvalid);
    match err.details() {
        PageValidationDetails::Spec {
            start: d_start,
            end: d_end,
        } => {
            assert_eq!(*d_start, ToxicDigest::of(b"z"));
            assert_eq!(*d_end, ToxicDigest::of(b"a"));
        }
        other => panic!("expected Spec, got: {other:?}"),
    }
    assert!(err.to_string().contains("invalid spec range:"));
}

#[test]
fn rejects_input_cursor_out_of_range_details() {
    let start = key(b"c");
    let end = key(b"z");
    let input = key(b"a");
    let items: Vec<Item> = Vec::new();
    let err = validate_page_range(&start, &end, Some(&input), &items, Some(&input)).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::InputCursorOutOfRange
    );
    match err.details() {
        PageValidationDetails::CursorOutOfRange {
            which,
            key,
            start,
            end,
        } => {
            assert_eq!(*which, CursorWhich::Input);
            assert_eq!(*key, ToxicDigest::of(b"a"));
            assert_eq!(*start, ToxicDigest::of(b"c"));
            assert_eq!(*end, ToxicDigest::of(b"z"));
        }
        other => panic!("expected CursorOutOfRange, got: {other:?}"),
    }
    assert!(err.to_string().contains("input cursor out of range:"));
}

#[test]
fn rejects_next_cursor_out_of_range_details() {
    let start = key(b"a");
    let end = key(b"m");
    let input = key(b"b");
    let items = vec![item(b"c")];
    let next = key(b"z");
    let err = validate_page_range(&start, &end, Some(&input), &items, Some(&next)).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::NextCursorOutOfRange
    );
    match err.details() {
        PageValidationDetails::CursorOutOfRange {
            which,
            key,
            start,
            end,
        } => {
            assert_eq!(*which, CursorWhich::Next);
            assert_eq!(*key, ToxicDigest::of(b"z"));
            assert_eq!(*start, ToxicDigest::of(b"a"));
            assert_eq!(*end, ToxicDigest::of(b"m"));
        }
        other => panic!("expected CursorOutOfRange, got: {other:?}"),
    }
    assert!(err.to_string().contains("next cursor out of range:"));
}

#[test]
fn rejects_missing_next_cursor_on_nonempty_page_details() {
    let start = key(b"a");
    let end = key(b"z");
    let items = vec![item(b"b")];
    let err = validate_page_range::<Vec<u8>, Item>(&start, &end, None, &items, None).unwrap_err();
    assert_eq!(err.violation(), PageValidationViolation::NextCursorMissing);
    assert_eq!(err.details(), &PageValidationDetails::NextCursorMissing);
    assert!(err.to_string().contains("next_cursor.last_key is missing"));
}

#[test]
fn toxic_digest_deterministic_and_display() {
    let d1 = ToxicDigest::of(b"same-input");
    let d2 = ToxicDigest::of(b"same-input");
    assert_eq!(d1, d2, "same input should produce equal digests");

    let d3 = ToxicDigest::of(b"different");
    assert_ne!(d1, d3, "different inputs should produce different digests");

    let display = format!("{d1}");
    assert!(
        display.starts_with("len=10, hash="),
        "unexpected: {display}"
    );
}

#[test]
fn toxic_digest_equality_semantics() {
    // Same content => equal.
    let a = ToxicDigest::of_bytes(b"payload");
    let b = ToxicDigest::of_bytes(b"payload");
    assert_eq!(a, b);

    // Different content, same length => not equal.
    let c = ToxicDigest::of_bytes(b"PAYLOAD");
    assert_ne!(a, c);

    // `of_bytes` and `of` agree for the same input.
    let via_of = ToxicDigest::of(b"payload");
    assert_eq!(a, via_of);
}

// -- Display format tests: all 10 match arms --

#[rstest]
#[case::spec_invalid(
    PageValidationViolation::SpecRangeInvalid,
    PageValidationDetails::Spec {
        start: ToxicDigest::of(b"z"),
        end: ToxicDigest::of(b"a"),
    },
    "invalid spec range: start=",
)]
#[case::input_cursor_out_of_range(
    PageValidationViolation::InputCursorOutOfRange,
    PageValidationDetails::CursorOutOfRange {
        which: CursorWhich::Input,
        key: ToxicDigest::of(b"k"),
        start: ToxicDigest::of(b"a"),
        end: ToxicDigest::of(b"z"),
    },
    "input cursor out of range:",
)]
#[case::next_cursor_out_of_range(
    PageValidationViolation::NextCursorOutOfRange,
    PageValidationDetails::CursorOutOfRange {
        which: CursorWhich::Next,
        key: ToxicDigest::of(b"k"),
        start: ToxicDigest::of(b"a"),
        end: ToxicDigest::of(b"z"),
    },
    "next cursor out of range:",
)]
#[case::item_key_out_of_range(
    PageValidationViolation::ItemKeyOutOfRange,
    PageValidationDetails::ItemOutOfRange {
        index: 3,
        key: ToxicDigest::of(b"k"),
        start: ToxicDigest::of(b"a"),
        end: ToxicDigest::of(b"z"),
    },
    "item key out of range at index 3:",
)]
#[case::items_not_ordered(
    PageValidationViolation::ItemsNotOrdered,
    PageValidationDetails::ItemsNotOrdered {
        index: 2,
        prev: ToxicDigest::of(b"b"),
        next: ToxicDigest::of(b"a"),
    },
    "items not ordered at index 2:",
)]
#[case::items_not_after_cursor(
    PageValidationViolation::ItemsNotAfterCursor,
    PageValidationDetails::ItemsNotAfterCursor {
        cursor: ToxicDigest::of(b"c"),
        first_item: ToxicDigest::of(b"c"),
    },
    "items must start strictly after",
)]
#[case::next_cursor_missing(
    PageValidationViolation::NextCursorMissing,
    PageValidationDetails::NextCursorMissing,
    "next_cursor.last_key is missing"
)]
#[case::next_cursor_behind_last(
    PageValidationViolation::NextCursorBehindLastItem,
    PageValidationDetails::NextCursorBehindLastItem {
        next_cursor: ToxicDigest::of(b"b"),
        last_item: ToxicDigest::of(b"d"),
    },
    "next_cursor.last_key is behind",
)]
#[case::cursor_regressed(
    PageValidationViolation::CursorRegressed,
    PageValidationDetails::CursorRegressed {
        input: ToxicDigest::of(b"c"),
        next: ToxicDigest::of(b"a"),
    },
    "cursor regressed:",
)]
#[case::empty_page_cursor_advanced(
    PageValidationViolation::EmptyPageCursorAdvanced,
    PageValidationDetails::EmptyPageCursorAdvanced {
        input: Some(ToxicDigest::of(b"a")),
        next: Some(ToxicDigest::of(b"b")),
    },
    "empty page advanced cursor:",
)]
fn display_format(
    #[case] violation: PageValidationViolation,
    #[case] details: PageValidationDetails,
    #[case] expected_prefix: &str,
) {
    let err = PageValidationError { violation, details };
    let msg = err.to_string();
    assert!(msg.starts_with(expected_prefix), "unexpected: {msg}");
}

#[test]
fn display_fallback_for_mismatched_pair() {
    // Deliberately inconsistent (violation, details) pair to exercise
    // the catch-all `_` arm. The arm contains a `debug_assert!(false, ...)`
    // that fires in debug builds, so we catch the panic and verify
    // the fallback format from the panic message.
    let err = PageValidationError {
        violation: PageValidationViolation::SpecRangeInvalid,
        details: PageValidationDetails::NextCursorMissing,
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| err.to_string()));
    match result {
        Ok(msg) => {
            // Release builds: debug_assert is stripped, fallback write runs.
            assert!(
                msg.contains("page validation violation: SpecRangeInvalid"),
                "fallback should name the violation: {msg}"
            );
        }
        Err(payload) => {
            // Debug builds: debug_assert fires before the write.
            let panic_msg = payload
                .downcast_ref::<String>()
                .map(|s| s.as_str())
                .or_else(|| payload.downcast_ref::<&str>().copied())
                .unwrap_or("");
            assert!(
                panic_msg.contains("mismatched (violation, details) pair"),
                "unexpected panic: {panic_msg}"
            );
        }
    }
}

// -- validate_page adapter tests --

#[test]
fn validate_page_accepts_valid_production_types() {
    use super::validate_page;
    use crate::connector::{Cursor, ItemKey, ItemRef, ScanItem};
    use crate::coordination::ShardSpec;
    use crate::identity::{ObjectVersionId, StableItemId};

    let spec = ShardSpec::from_raw_parts(
        b"a".to_vec().into_boxed_slice(),
        b"z".to_vec().into_boxed_slice(),
        Box::default(),
    );
    let input = Cursor::with_last_key(ItemKey::try_from_slice(b"b").unwrap());
    let items = vec![
        ScanItem::new(
            ItemKey::try_from_slice(b"c").unwrap(),
            ItemRef::try_from_slice(b"ref-c").unwrap(),
            StableItemId::from_bytes([0xAA; 32]),
            crate::connector::VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
        ),
        ScanItem::new(
            ItemKey::try_from_slice(b"d").unwrap(),
            ItemRef::try_from_slice(b"ref-d").unwrap(),
            StableItemId::from_bytes([0xBB; 32]),
            crate::connector::VersionId::Strong(ObjectVersionId::from_version_bytes(b"v2")),
        ),
    ];
    let next = Cursor::with_last_key(ItemKey::try_from_slice(b"d").unwrap());

    let result = validate_page(&spec, &input, &items, &next);
    assert!(
        result.is_ok(),
        "valid production page should pass: {result:?}"
    );
}

#[test]
fn validate_page_rejects_invalid_production_page() {
    use super::validate_page;
    use crate::connector::{Cursor, ItemKey, ItemRef, ScanItem};
    use crate::coordination::ShardSpec;
    use crate::identity::{ObjectVersionId, StableItemId};

    let spec = ShardSpec::from_raw_parts(
        b"a".to_vec().into_boxed_slice(),
        b"m".to_vec().into_boxed_slice(),
        Box::default(),
    );
    let input = Cursor::with_last_key(ItemKey::try_from_slice(b"b").unwrap());
    let items = vec![ScanItem::new(
        ItemKey::try_from_slice(b"c").unwrap(),
        ItemRef::try_from_slice(b"ref-c").unwrap(),
        StableItemId::from_bytes([0xAA; 32]),
        crate::connector::VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
    )];
    // z > end "m" — should fail.
    let next = Cursor::with_last_key(ItemKey::try_from_slice(b"z").unwrap());

    let err = validate_page(&spec, &input, &items, &next).unwrap_err();
    assert_eq!(
        err.violation(),
        PageValidationViolation::NextCursorOutOfRange
    );
}
