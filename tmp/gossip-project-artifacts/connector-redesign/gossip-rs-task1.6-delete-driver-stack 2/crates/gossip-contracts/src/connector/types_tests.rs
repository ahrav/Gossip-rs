use std::sync::Arc;

use gossip_stdx::ByteSlab;
use rstest::rstest;

use super::*;
use proptest::prelude::*;

#[test]
fn constants_align_with_coordination_limits() {
    use crate::coordination::{CursorMaxTokenSize, MAX_KEY_SIZE};
    assert_eq!(MAX_ITEM_KEY_SIZE, MAX_KEY_SIZE);
    assert_eq!(MAX_TOKEN_SIZE, CursorMaxTokenSize);
}

#[rstest]
#[case::empty(
    ConnectorInputError::Empty { field: "ItemKey" },
    "ItemKey must not be empty",
)]
#[case::too_large(
    ConnectorInputError::TooLarge { field: "ItemRef", size: 9_999, max: 10 },
    "ItemRef too large (9999 bytes, max 10)",
)]
#[case::token_without_last_key(
    ConnectorInputError::TokenWithoutLastKey,
    "token must not be present without last_key"
)]
#[case::zero_budget(
    ConnectorInputError::ZeroBudget { field: "Budgets.max_items" },
    "Budgets.max_items must be non-zero",
)]
fn connector_input_error_display(#[case] error: ConnectorInputError, #[case] expected: &str) {
    assert_eq!(error.to_string(), expected);
}

#[test]
fn cursor_initial_has_no_key_or_token() {
    let cursor = Cursor::initial();
    assert!(cursor.last_key().is_none());
    assert!(cursor.token().is_none());
    assert_eq!(cursor, Cursor::default());

    let update = cursor.as_update();
    assert!(update.last_key().is_none());
    assert!(update.token().is_none());
}

#[test]
fn cursor_try_from_update_rejects_token_without_last_key() {
    let invalid =
        crate::coordination::cursor::CursorUpdate::from_raw_parts_for_test(None, Some(b"tok-1"));
    assert_eq!(
        Cursor::try_from_update(invalid),
        Err(ConnectorInputError::TokenWithoutLastKey)
    );
}

#[test]
fn cursor_try_from_update_normalizes_empty_token_to_none() {
    let update =
        crate::coordination::cursor::CursorUpdate::from_raw_parts_for_test(Some(b"k-1"), Some(b""));
    let cursor = Cursor::try_from_update(update).unwrap();
    assert_eq!(cursor.last_key().unwrap().as_bytes(), b"k-1");
    assert!(cursor.token().is_none());
}

#[test]
fn version_id_helpers_work() {
    let object_version = ObjectVersionId::from_version_bytes(b"v1");
    let strong = VersionId::Strong(object_version);
    let weak = VersionId::Weak(object_version);
    assert!(strong.is_strong());
    assert!(!weak.is_strong());
    assert_eq!(strong.object_version_id(), object_version);
    assert_eq!(weak.object_version_id(), object_version);
}

#[rstest]
#[case::both_empty(Some(String::new()), Some(String::new()), None, None)]
#[case::media_only(Some("text/plain".to_owned()), Some(String::new()), Some("text/plain"), None)]
#[case::both_set(
    Some("application/json".to_owned()),
    Some("gzip".to_owned()),
    Some("application/json"),
    Some("gzip"),
)]
#[case::neither(None, None, None, None)]
fn content_hints_try_new_accessors(
    #[case] media_type: Option<String>,
    #[case] encoding: Option<String>,
    #[case] expected_media: Option<&str>,
    #[case] expected_encoding: Option<&str>,
) {
    let hints = ContentHints::try_new(media_type, encoding).unwrap();
    assert_eq!(hints.media_type(), expected_media);
    assert_eq!(hints.encoding(), expected_encoding);
}

#[test]
fn content_hints_enforce_size_limits() {
    assert!(ContentHints::try_new(Some("text/plain".to_owned()), None).is_ok());
    assert!(ContentHints::try_new(None, Some("gzip".to_owned())).is_ok());
    assert_eq!(
        ContentHints::try_new(Some("a".repeat(257)), None),
        Err(ConnectorInputError::TooLarge {
            field: "ContentHints.media_type",
            size: 257,
            max: 256,
        })
    );
    assert_eq!(
        ContentHints::try_new(None, Some("a".repeat(129))),
        Err(ConnectorInputError::TooLarge {
            field: "ContentHints.encoding",
            size: 129,
            max: 128,
        })
    );
}

#[test]
fn location_normalizes_empty_url_to_none() {
    let loc = Location::try_new("ok".to_owned(), Some(String::new())).unwrap();
    assert_eq!(loc.display(), "ok");
    assert_eq!(loc.url(), None);
}

#[test]
fn location_validates_required_and_size_limited_fields() {
    assert_eq!(
        Location::try_new(String::new(), None),
        Err(ConnectorInputError::Empty {
            field: "Location.display",
        })
    );
    assert_eq!(
        Location::try_new("x".repeat(MAX_LOCATION_DISPLAY_SIZE + 1), None),
        Err(ConnectorInputError::TooLarge {
            field: "Location.display",
            size: MAX_LOCATION_DISPLAY_SIZE + 1,
            max: MAX_LOCATION_DISPLAY_SIZE,
        })
    );
    assert_eq!(
        Location::try_new("ok".to_owned(), Some("u".repeat(MAX_LOCATION_URL_SIZE + 1))),
        Err(ConnectorInputError::TooLarge {
            field: "Location.url",
            size: MAX_LOCATION_URL_SIZE + 1,
            max: MAX_LOCATION_URL_SIZE,
        })
    );

    let loc = Location::try_new(
        "repo/path".to_owned(),
        Some("https://example.com".to_owned()),
    )
    .unwrap();
    assert_eq!(loc.display(), "repo/path");
    assert_eq!(loc.url(), Some("https://example.com"));
}

#[test]
fn constructors_reject_empty_values() {
    assert_eq!(
        ItemKey::try_from_slice(b""),
        Err(ConnectorInputError::Empty { field: "ItemKey" })
    );
    assert_eq!(
        ItemRef::try_from_slice(b""),
        Err(ConnectorInputError::Empty { field: "ItemRef" })
    );
    assert_eq!(
        TokenBytes::try_from_slice(b""),
        Err(ConnectorInputError::Empty {
            field: "TokenBytes"
        })
    );
}

#[test]
fn pooled_constructor_roundtrips_without_heap_owned_storage() {
    // One page-local slab supplies key/ref/token bytes for all wrappers.
    let mut slab = ByteSlab::with_capacity(128);
    let key_slot = slab.allocate(b"item-key").expect("allocate key");
    let ref_slot = slab.allocate(b"item-ref").expect("allocate ref");
    let token_slot = slab.allocate(b"token").expect("allocate token");
    let shared = Arc::new(PooledByteSlab::new(slab));

    let key = ItemKey::try_from_slot(key_slot, Arc::clone(&shared)).expect("pooled key");
    let iref = ItemRef::try_from_slot(ref_slot, Arc::clone(&shared)).expect("pooled item_ref");
    let token = TokenBytes::try_from_slot(token_slot, Arc::clone(&shared)).expect("pooled token");

    assert!(key.is_pooled());
    assert!(iref.is_pooled());
    assert!(token.is_pooled());
    assert_eq!(key.as_bytes(), b"item-key");
    assert_eq!(iref.as_bytes(), b"item-ref");
    assert_eq!(token.as_bytes(), b"token");
    assert!(
        key.clone().is_pooled(),
        "cloning pooled key should stay pooled"
    );
}

#[test]
fn pooled_wrapper_survives_slab_owner_drop() {
    // Verify that cloning a pooled wrapper keeps the slab alive even after
    // the original Arc reference is dropped. This exercises the Arc<PooledByteSlab>
    // lifetime semantics that the HOT page-emission path relies on.
    let mut slab = ByteSlab::with_capacity(128);
    let key_slot = slab.allocate(b"survivor-key").expect("allocate key");
    let ref_slot = slab.allocate(b"survivor-ref").expect("allocate ref");
    let shared = Arc::new(PooledByteSlab::new(slab));

    let key = ItemKey::try_from_slot(key_slot, Arc::clone(&shared)).expect("pooled key");
    let iref = ItemRef::try_from_slot(ref_slot, Arc::clone(&shared)).expect("pooled ref");

    // Clone before dropping the original shared reference.
    let key_clone = key.clone();
    let iref_clone = iref.clone();
    drop(key);
    drop(iref);
    drop(shared);

    // Clones must still resolve correctly from the slab.
    assert!(key_clone.is_pooled());
    assert!(iref_clone.is_pooled());
    assert_eq!(key_clone.as_bytes(), b"survivor-key");
    assert_eq!(iref_clone.as_bytes(), b"survivor-ref");
}

#[test]
fn pooled_constructor_rejects_empty_and_oversized_slots() {
    // Slot-backed constructors must enforce the same non-empty/size bounds as
    // vec/slice constructors.
    let oversized_len = MAX_ITEM_KEY_SIZE + 1;
    let mut slab = ByteSlab::with_capacity(oversized_len.next_power_of_two());
    let oversized_bytes = vec![0xAB; oversized_len];
    let oversized_slot = slab.allocate(&oversized_bytes).expect("allocate oversized");
    let shared = Arc::new(PooledByteSlab::new(slab));

    assert_eq!(
        ItemKey::try_from_slot(gossip_stdx::ByteSlot::EMPTY, Arc::clone(&shared)),
        Err(ConnectorInputError::Empty { field: "ItemKey" })
    );
    assert_eq!(
        ItemKey::try_from_slot(oversized_slot, Arc::clone(&shared)),
        Err(ConnectorInputError::TooLarge {
            field: "ItemKey",
            size: oversized_len,
            max: MAX_ITEM_KEY_SIZE,
        })
    );
}

#[test]
fn owned_and_pooled_satisfy_trait_consistency() {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut slab = ByteSlab::with_capacity(128);
    let key_slot = slab.allocate(b"shared-key").expect("allocate key");
    let ref_slot = slab.allocate(b"shared-ref").expect("allocate ref");
    let token_slot = slab.allocate(b"shared-token").expect("allocate token");
    let shared = Arc::new(PooledByteSlab::new(slab));

    let owned_key = ItemKey::try_from_slice(b"shared-key").unwrap();
    let pooled_key = ItemKey::try_from_slot(key_slot, Arc::clone(&shared)).unwrap();

    let owned_ref = ItemRef::try_from_slice(b"shared-ref").unwrap();
    let pooled_ref = ItemRef::try_from_slot(ref_slot, Arc::clone(&shared)).unwrap();

    let owned_token = TokenBytes::try_from_slice(b"shared-token").unwrap();
    let pooled_token = TokenBytes::try_from_slot(token_slot, Arc::clone(&shared)).unwrap();

    // PartialEq: Owned == Pooled for identical bytes.
    assert_eq!(owned_key, pooled_key);
    assert_eq!(owned_ref, pooled_ref);
    assert_eq!(owned_token, pooled_token);

    // Hash: both variants produce the same hash.
    fn hash_of(val: &impl Hash) -> u64 {
        let mut h = DefaultHasher::new();
        val.hash(&mut h);
        h.finish()
    }
    assert_eq!(hash_of(&owned_key), hash_of(&pooled_key));
    assert_eq!(hash_of(&owned_ref), hash_of(&pooled_ref));
    assert_eq!(hash_of(&owned_token), hash_of(&pooled_token));

    // Ord (ItemKey only — ItemRef/TokenBytes are unordered).
    assert_eq!(owned_key.cmp(&pooled_key), std::cmp::Ordering::Equal);
    assert_eq!(pooled_key.cmp(&owned_key), std::cmp::Ordering::Equal);
}

#[test]
fn item_key_lexicographic_ordering() {
    let a = ItemKey::try_from_vec(vec![0x00]).unwrap();
    let b = ItemKey::try_from_vec(vec![0x00, 0x01]).unwrap();
    let c = ItemKey::try_from_vec(vec![0x01]).unwrap();
    let d = ItemKey::try_from_vec(vec![0xFF]).unwrap();

    assert!(a < b, "prefix sorts before longer extension");
    assert!(b < c, "[0x00,0x01] sorts before [0x01]");
    assert!(c < d);
    assert_eq!(a.cmp(&a), std::cmp::Ordering::Equal);
}

#[test]
fn format_output_is_deterministic() {
    let key = ItemKey::try_from_vec(vec![0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
    let output = format!("{key}");
    let hash = blake3::hash(&[0xDE, 0xAD, 0xBE, 0xEF]);
    let b = hash.as_bytes();
    let expected = format!(
        "ItemKey(len=4, hash={:02x}{:02x}{:02x}{:02x}..)",
        b[0], b[1], b[2], b[3]
    );
    assert_eq!(output, expected);
}

#[test]
fn scan_item_new_defaults_optional_fields_to_none() {
    let scan_item = ScanItem::new(
        ItemKey::try_from_slice(b"item-key").unwrap(),
        ItemRef::try_from_slice(b"item-ref").unwrap(),
        StableItemId::from_bytes([0x11; 32]),
        VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
    );

    assert_eq!(scan_item.item_key().as_bytes(), b"item-key");
    assert_eq!(scan_item.item_ref().as_bytes(), b"item-ref");
    assert_eq!(
        scan_item.stable_item_id(),
        StableItemId::from_bytes([0x11; 32])
    );
    assert_eq!(
        scan_item.version(),
        VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1"))
    );
    assert_eq!(scan_item.size_hint(), None);
    assert_eq!(scan_item.content_hints(), None);
    assert_eq!(scan_item.location(), None);
}

#[test]
fn scan_item_builder_methods_chain() {
    let content_hints =
        ContentHints::try_new(Some("text/plain".to_owned()), Some("gzip".to_owned())).unwrap();
    let location = Location::try_new(
        "repo/path.txt".to_owned(),
        Some("https://example.invalid/path.txt".to_owned()),
    )
    .unwrap();
    let scan_item = ScanItem::new(
        ItemKey::try_from_slice(b"item-key-2").unwrap(),
        ItemRef::try_from_slice(b"item-ref-2").unwrap(),
        StableItemId::from_bytes([0x22; 32]),
        VersionId::Weak(ObjectVersionId::from_version_bytes(b"v2")),
    )
    .with_size_hint(4_096)
    .with_content_hints(content_hints.clone())
    .with_location(location.clone());

    assert_eq!(scan_item.size_hint(), Some(4_096));
    assert_eq!(scan_item.content_hints(), Some(&content_hints));
    assert_eq!(scan_item.location(), Some(&location));
}

#[rstest]
#[case::zero_items(0, 1024, "Budgets.max_items")]
#[case::zero_bytes(10, 0, "Budgets.max_bytes")]
fn budgets_try_new_rejects_zero(
    #[case] max_items: usize,
    #[case] max_bytes: u64,
    #[case] expected_field: &'static str,
) {
    assert_eq!(
        Budgets::try_new(max_items, max_bytes, None),
        Err(ConnectorInputError::ZeroBudget {
            field: expected_field,
        })
    );
}

#[test]
fn scan_item_into_parts_returns_owned_fields() {
    let content_hints = ContentHints::try_new(Some("text/plain".to_owned()), None).unwrap();
    let location = Location::try_new("repo/path.txt".to_owned(), None).unwrap();
    let item = ScanItem::new(
        ItemKey::try_from_slice(b"k").unwrap(),
        ItemRef::try_from_slice(b"r").unwrap(),
        StableItemId::from_bytes([0xAA; 32]),
        VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1")),
    )
    .with_size_hint(42)
    .with_content_hints(content_hints.clone())
    .with_location(location.clone());

    let (key, iref, sid, ver, sz, ch, loc) = item.into_parts();
    assert_eq!(key.as_bytes(), b"k");
    assert_eq!(iref.as_bytes(), b"r");
    assert_eq!(sid, StableItemId::from_bytes([0xAA; 32]));
    assert_eq!(
        ver,
        VersionId::Strong(ObjectVersionId::from_version_bytes(b"v1"))
    );
    assert_eq!(sz, Some(42));
    assert_eq!(ch.as_ref(), Some(&content_hints));
    assert_eq!(loc.as_ref(), Some(&location));
}

#[test]
fn budgets_is_expired_at_respects_deadline() {
    use std::time::Duration;

    let anchor = Instant::now();

    let none = Budgets::try_new(10, 1_024, None).unwrap();
    assert_eq!(none.max_items(), 10);
    assert_eq!(none.max_bytes(), 1_024);
    assert_eq!(none.deadline(), None);
    assert!(!none.is_expired_at(anchor));

    let deadline = anchor + Duration::from_secs(30);
    let future = Budgets::try_new(10, 1_024, Some(deadline)).unwrap();
    assert!(!future.is_expired_at(anchor));
    assert!(future.is_expired_at(deadline));
    assert!(future.is_expired_at(deadline + Duration::from_secs(1)));

    let past_deadline = anchor.checked_sub(Duration::from_secs(1)).unwrap_or(anchor);
    let past = Budgets::try_new(10, 1_024, Some(past_deadline)).unwrap();
    assert!(past.is_expired_at(anchor));

    let boundary = Budgets::try_new(10, 1_024, Some(anchor)).unwrap();
    assert!(boundary.is_expired_at(anchor));
}

/// Generates roundtrip + redaction and oversized-rejection proptests for
/// a toxic-byte wrapper type.
macro_rules! toxic_bytes_tests {
    (
        type = $ty:ident, max = $max:expr,
        roundtrip_test = $rt:ident,
        oversized_test = $ov:ident $(,)?
    ) => {
        proptest! {
            #![proptest_config(crate::test_util::miri_proptest_config())]

            #[test]
            fn $rt(
                bytes in proptest::collection::vec(any::<u8>(), 1..=$max),
            ) {
                let val = $ty::try_from_vec(bytes.clone()).unwrap();
                prop_assert_eq!(val.as_bytes(), &bytes[..]);
                prop_assert_eq!(val.as_ref(), &bytes[..]);

                // Also verify try_from_slice produces identical results.
                let from_slice = $ty::try_from_slice(&bytes).unwrap();
                prop_assert_eq!(from_slice.as_bytes(), &bytes[..]);

                let dbg = format!("{val:?}");
                let display = format!("{val}");
                let prefix = format!(
                    concat!(stringify!($ty), "(len={}, hash="),
                    bytes.len(),
                );
                prop_assert!(dbg.starts_with(&prefix), "Debug: {}", dbg);
                prop_assert!(display.starts_with(&prefix), "Display: {}", display);

                if bytes.len() >= 8 {
                    let raw = String::from_utf8_lossy(&bytes);
                    prop_assert!(
                        !dbg.contains(raw.as_ref()),
                        "leaked raw bytes in Debug",
                    );
                }

                prop_assert_eq!(dbg, display, "Debug and Display must match");
            }

            #[test]
            fn $ov(
                bytes in proptest::collection::vec(
                    any::<u8>(),
                    ($max + 1)..=($max + 512),
                ),
            ) {
                prop_assert_eq!(
                    $ty::try_from_vec(bytes.clone()),
                    Err(ConnectorInputError::TooLarge {
                        field: stringify!($ty),
                        size: bytes.len(),
                        max: $max,
                    })
                );
            }
        }
    };
}

/// Generates a valid `Cursor` from one of three variants: initial,
/// key-only, or key + token.
fn arb_cursor() -> impl Strategy<Value = Cursor> {
    prop_oneof![
        Just(Cursor::initial()),
        proptest::collection::vec(any::<u8>(), 1..=64)
            .prop_map(|b| Cursor::with_last_key(ItemKey::try_from_vec(b).unwrap())),
        (
            proptest::collection::vec(any::<u8>(), 1..=64),
            proptest::collection::vec(any::<u8>(), 1..=64),
        )
            .prop_map(|(k, t)| Cursor::with_token(
                ItemKey::try_from_vec(k).unwrap(),
                TokenBytes::try_from_vec(t).unwrap(),
            )),
    ]
}

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn cursor_roundtrips_through_update(cursor in arb_cursor()) {
        let update = cursor.as_update();
        let reparsed = Cursor::try_from_update(update).unwrap();
        prop_assert_eq!(reparsed, cursor);
    }
}

toxic_bytes_tests! {
    type = ItemKey, max = MAX_ITEM_KEY_SIZE,
    roundtrip_test = item_key_roundtrips_and_redacts,
    oversized_test = item_key_rejects_oversized,
}

toxic_bytes_tests! {
    type = ItemRef, max = MAX_ITEM_REF_SIZE,
    roundtrip_test = item_ref_roundtrips_and_redacts,
    oversized_test = item_ref_rejects_oversized,
}

toxic_bytes_tests! {
    type = TokenBytes, max = MAX_TOKEN_SIZE,
    roundtrip_test = token_bytes_roundtrips_and_redacts,
    oversized_test = token_bytes_rejects_oversized,
}
