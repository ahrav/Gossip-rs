use proptest::prelude::*;
use rstest::rstest;

use super::*;
use crate::coordination::shard_spec::{MAX_KEY_SIZE, ShardSpecInputError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct BytesKey(Vec<u8>);

impl KeyEncoding for BytesKey {
    fn encode_into(&self, buf: &mut KeyBuf) {
        buf.copy_from_slice(&self.0);
    }
}

#[test]
fn key_encoding_returns_encoded_bytes() {
    let key = BytesKey(vec![0xDE, 0xAD, 0xBE, 0xEF]);
    let mut buf = KeyBuf::new();
    key.encode_into(&mut buf);
    assert_eq!(buf.as_bytes(), [0xDE, 0xAD, 0xBE, 0xEF].as_slice());
}

#[test]
fn path_key_uses_identity_utf8_encoding() {
    let key = PathKey::new("src/lib.rs");
    let mut buf = KeyBuf::new();
    key.encode_into(&mut buf);
    assert_eq!(buf.as_bytes(), b"src/lib.rs");
}

#[test]
#[should_panic(expected = "path length")]
fn path_key_new_rejects_oversized_path() {
    let _ = PathKey::new(&"a".repeat(MAX_KEY_SIZE + 1));
}

#[test]
fn path_key_try_new_returns_none_for_oversized_path() {
    assert!(PathKey::try_new(&"a".repeat(MAX_KEY_SIZE + 1)).is_none());
}

#[test]
fn path_key_try_new_accepts_path_at_max_size() {
    let path = "a".repeat(MAX_KEY_SIZE);
    let key = PathKey::try_new(&path).expect("path at MAX_KEY_SIZE should succeed");
    assert_eq!(key.as_str().len(), MAX_KEY_SIZE);
}

#[test]
fn manifest_row_key_is_fixed_width_and_decodes() {
    let key = ManifestRowKey::new(42, 99);
    let mut buf = KeyBuf::new();
    key.encode_into(&mut buf);
    assert_eq!(buf.len(), ManifestRowKey::ENCODED_LEN);
    assert_eq!(decode_manifest_row_key(buf.as_bytes()), Some((42, 99)));
}

#[test]
fn decode_manifest_row_key_rejects_non_fixed_width_inputs() {
    assert_eq!(decode_manifest_row_key(&[]), None);
    assert_eq!(decode_manifest_row_key(&[0; 15]), None);
    assert_eq!(decode_manifest_row_key(&[0; 17]), None);
}

#[test]
fn shard_spec_from_manifest_range_encodes_boundaries() {
    let spec = shard_spec_from_manifest_range(7, 11, 12, b"meta")
        .expect("manifest range should encode into a valid shard spec");

    assert_eq!(
        decode_manifest_row_key(spec.key_range_start()),
        Some((7, 11))
    );
    assert_eq!(decode_manifest_row_key(spec.key_range_end()), Some((7, 12)));
    assert_eq!(spec.metadata(), b"meta");
}

#[test]
fn shard_spec_from_prefix_rejects_all_ff_prefix() {
    let err = shard_spec_from_prefix(&[u8::MAX, u8::MAX], b"meta")
        .expect_err("all-ff prefix should not have a lexicographic successor");
    assert_eq!(err, PrefixShardError::NoSuccessor);
}

#[test]
fn shard_spec_from_prefix_rejects_oversized_prefix() {
    let oversized = vec![0xAB; MAX_KEY_SIZE + 1];
    let err = shard_spec_from_prefix(&oversized, b"meta")
        .expect_err("oversized prefix should fail early");
    assert_eq!(
        err,
        PrefixShardError::PrefixTooLarge {
            size: oversized.len(),
            max: MAX_KEY_SIZE,
        }
    );
}

#[test]
fn shard_spec_from_keys_surfaces_oversized_encoded_boundary() {
    struct OversizedKey;

    impl KeyEncoding for OversizedKey {
        fn encode_into(&self, buf: &mut KeyBuf) {
            let oversized = [0u8; MAX_KEY_SIZE + 1];
            buf.copy_from_slice(&oversized);
        }
    }

    let err = shard_spec_from_keys(&OversizedKey, &ManifestRowKey::new(1, 1), b"meta")
        .expect_err("oversized encoded key should be rejected by ShardSpec validation");
    assert_eq!(
        err,
        ShardSpecInputError::KeyTooLarge {
            size: MAX_KEY_SIZE + 1,
            max: MAX_KEY_SIZE,
        }
    );
}

#[test]
fn prefix_successor_basic() {
    let mut buf = KeyBuf::new();
    assert_eq!(prefix_successor(b"abc", &mut buf), Some(b"abd".as_slice()));
    assert_eq!(
        prefix_successor(b"ab\xff", &mut buf),
        Some(b"ac".as_slice())
    );
    assert_eq!(prefix_successor(b"\xff\xff", &mut buf), None);
    assert_eq!(prefix_successor(b"", &mut buf), None);
}

#[test]
fn key_successor_prefers_append_when_capacity_available() {
    let mut buf = KeyBuf::new();
    assert_eq!(key_successor(b"abc", &mut buf), Some(b"abc\0".as_slice()));
}

#[test]
fn key_successor_uses_increment_when_at_max_size() {
    let mut key = vec![0; MAX_KEY_SIZE];
    key[MAX_KEY_SIZE - 1] = 0x7F;
    let mut expected = key.clone();
    expected[MAX_KEY_SIZE - 1] = 0x80;

    let mut buf = KeyBuf::new();
    assert_eq!(key_successor(&key, &mut buf), Some(expected.as_slice()));
}

#[test]
fn key_successor_none_for_all_ff_at_max_size() {
    let key = vec![u8::MAX; MAX_KEY_SIZE];
    let mut buf = KeyBuf::new();
    assert_eq!(key_successor(&key, &mut buf), None);
}

#[test]
fn byte_midpoint_rejects_oversized_inputs() {
    let oversized_a = vec![0x40; MAX_KEY_SIZE + 1];
    let oversized_b = vec![0xC0; MAX_KEY_SIZE + 1];

    let mut buf = KeyBuf::new();
    assert_eq!(
        byte_midpoint(&oversized_a, &oversized_b, &mut buf),
        None,
        "inputs exceeding MAX_KEY_SIZE should be rejected"
    );
}

#[test]
fn byte_midpoint_output_respects_max_key_size() {
    let a = vec![0x40; MAX_KEY_SIZE];
    let b = vec![0xC0; MAX_KEY_SIZE];

    let mut buf = KeyBuf::new();
    if let Some(mid) = byte_midpoint(&a, &b, &mut buf) {
        assert!(
            mid.len() <= MAX_KEY_SIZE,
            "midpoint length {} exceeds MAX_KEY_SIZE {}",
            mid.len(),
            MAX_KEY_SIZE
        );
    }
}

#[test]
fn byte_midpoint_carry_regression() {
    let mut buf = KeyBuf::new();
    assert_eq!(
        byte_midpoint(&[0x40], &[0xC0], &mut buf),
        Some([0x80].as_slice())
    );
}

#[test]
fn byte_midpoint_finds_interior_for_single_byte_gap() {
    let mut buf = KeyBuf::new();
    assert_eq!(
        byte_midpoint(&[0x01], &[0x02], &mut buf),
        Some([0x01, 0x00].as_slice())
    );
}

// -- rstest parameterized: byte_midpoint edge cases with different lengths --

#[rstest]
#[case::both_empty(&[], &[], None)]
#[case::empty_vs_nonempty(&[], &[0x02], Some(vec![0x01]))]
#[case::full_byte_range(&[0x00], &[0xFF], Some(vec![0x7F]))]
#[case::shared_leading_zero_prefix(&[0x00, 0x00], &[0x00, 0x02], Some(vec![0x00, 0x01]))]
#[case::second_byte_gap(&[0x01, 0x00], &[0x01, 0x04], Some(vec![0x01, 0x02]))]
#[case::different_lengths_close(&[0x01], &[0x01, 0x00], None)]
#[case::high_bytes_different_lengths(&[0xFF], &[0xFF, 0x02], Some(vec![0xFF, 0x01]))]
#[case::wide_gap_different_lengths(&[0x10], &[0x10, 0x80], Some(vec![0x10, 0x40]))]
fn byte_midpoint_edge_cases(#[case] a: &[u8], #[case] b: &[u8], #[case] expected: Option<Vec<u8>>) {
    let mut buf = KeyBuf::new();
    assert_eq!(byte_midpoint(a, b, &mut buf), expected.as_deref());
}

// -- rstest parameterized: PrefixShardError Display formatting --

#[rstest]
#[case::empty_prefix(PrefixShardError::EmptyPrefix, "non-empty prefix")]
#[case::prefix_too_large(
    PrefixShardError::PrefixTooLarge { size: 5000, max: 4096 },
    "5000 bytes, max 4096",
)]
#[case::no_successor(PrefixShardError::NoSuccessor, "all bytes are 0xFF")]
fn prefix_shard_error_display_contains(
    #[case] error: PrefixShardError,
    #[case] expected_substr: &str,
) {
    let msg = error.to_string();
    assert!(
        msg.contains(expected_substr),
        "expected Display output to contain {expected_substr:?}, got {msg:?}"
    );
}

#[test]
fn prefix_shard_error_source_delegates_for_invalid_shard_spec() {
    use std::error::Error;

    let inner = ShardSpecInputError::KeyTooLarge {
        size: 5000,
        max: MAX_KEY_SIZE,
    };
    let err = PrefixShardError::InvalidShardSpec(inner.clone());
    let source = err.source().expect("InvalidShardSpec should have a source");
    assert_eq!(source.to_string(), inner.to_string());

    // Non-delegating variants have no source.
    assert!(PrefixShardError::EmptyPrefix.source().is_none());
    assert!(PrefixShardError::NoSuccessor.source().is_none());
    assert!(
        PrefixShardError::PrefixTooLarge { size: 1, max: 4096 }
            .source()
            .is_none()
    );
}

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn prefix_successor_is_strictly_greater(prefix in proptest::collection::vec(any::<u8>(), 0..=32)) {
        let mut buf = KeyBuf::new();
        if let Some(succ) = prefix_successor(&prefix, &mut buf) {
            prop_assert!(succ > prefix.as_slice());
        } else {
            let no_successor = prefix.is_empty() || prefix.iter().all(|&byte| byte == u8::MAX);
            prop_assert!(no_successor);
        }
    }

    #[test]
    fn prefix_successor_is_upper_bound_for_prefixed_keys(
        prefix in proptest::collection::vec(any::<u8>(), 1..=32),
        suffix in proptest::collection::vec(any::<u8>(), 0..=32),
    ) {
        prop_assume!(prefix.iter().any(|&byte| byte != u8::MAX));
        let mut buf = KeyBuf::new();
        let succ = prefix_successor(&prefix, &mut buf).expect("non-all-ff prefix has successor");

        let mut key = prefix.clone();
        key.extend_from_slice(&suffix);

        prop_assert!(key.as_slice() < succ);
    }

    #[test]
    fn path_key_encoding_preserves_logical_order(
        a in proptest::collection::vec(0u8..=127, 0..=64),
        b in proptest::collection::vec(0u8..=127, 0..=64),
    ) {
        let a = String::from_utf8(a).expect("ASCII bytes should always be valid UTF-8");
        let b = String::from_utf8(b).expect("ASCII bytes should always be valid UTF-8");
        prop_assume!(a < b);

        let mut a_buf = KeyBuf::new();
        let mut b_buf = KeyBuf::new();
        PathKey::new(&a).encode_into(&mut a_buf);
        PathKey::new(&b).encode_into(&mut b_buf);

        prop_assert!(a_buf.as_bytes() < b_buf.as_bytes());
    }

    #[test]
    fn manifest_row_key_encoding_preserves_logical_order(
        a_manifest_id in any::<u64>(),
        a_row in any::<u64>(),
        b_manifest_id in any::<u64>(),
        b_row in any::<u64>(),
    ) {
        let a = (a_manifest_id, a_row);
        let b = (b_manifest_id, b_row);
        prop_assume!(a < b);

        let mut a_buf = KeyBuf::new();
        let mut b_buf = KeyBuf::new();
        ManifestRowKey::new(a_manifest_id, a_row).encode_into(&mut a_buf);
        ManifestRowKey::new(b_manifest_id, b_row).encode_into(&mut b_buf);

        prop_assert!(a_buf.as_bytes() < b_buf.as_bytes());
        prop_assert_eq!(a_buf.len(), ManifestRowKey::ENCODED_LEN);
        prop_assert_eq!(b_buf.len(), ManifestRowKey::ENCODED_LEN);
    }

    #[test]
    fn byte_midpoint_is_strictly_between_when_present(
        a in proptest::collection::vec(any::<u8>(), 0..=32),
        b in proptest::collection::vec(any::<u8>(), 0..=32),
    ) {
        let mut buf = KeyBuf::new();
        if let Some(mid) = byte_midpoint(&a, &b, &mut buf) {
            prop_assert!(a.as_slice() < mid);
            prop_assert!(mid < b.as_slice());
        }
    }

    // -- key_successor property tests --

    /// `key_successor` result is strictly greater than the input when `Some`.
    #[test]
    fn key_successor_is_strictly_greater(
        key in proptest::collection::vec(any::<u8>(), 0..=MAX_KEY_SIZE),
    ) {
        let mut buf = KeyBuf::new();
        if let Some(succ) = key_successor(&key, &mut buf) {
            prop_assert!(
                succ > key.as_slice(),
                "successor {succ:?} must be > input {key:?}"
            );
        }
    }

    /// `key_successor` returns `None` only when the key exceeds `MAX_KEY_SIZE`
    /// or is all-`0xFF` at exactly `MAX_KEY_SIZE`.
    #[test]
    fn key_successor_none_only_when_expected(
        key in proptest::collection::vec(any::<u8>(), 0..=(MAX_KEY_SIZE + 8)),
    ) {
        let mut buf = KeyBuf::new();
        match key_successor(&key, &mut buf) {
            Some(_) => {
                prop_assert!(key.len() <= MAX_KEY_SIZE);
            }
            None => {
                let oversized = key.len() > MAX_KEY_SIZE;
                let all_ff_at_max = key.len() == MAX_KEY_SIZE
                    && key.iter().all(|&b| b == u8::MAX);
                prop_assert!(
                    oversized || all_ff_at_max,
                    "key_successor returned None unexpectedly for key of len {} \
                     (oversized={oversized}, all_ff_at_max={all_ff_at_max})",
                    key.len()
                );
            }
        }
    }

    /// Below `MAX_KEY_SIZE`, `key_successor` always appends `0x00`.
    #[test]
    fn key_successor_appends_zero_when_below_max(
        key in proptest::collection::vec(any::<u8>(), 0..MAX_KEY_SIZE),
    ) {
        let mut buf = KeyBuf::new();
        let succ = key_successor(&key, &mut buf).expect("below MAX_KEY_SIZE always has a successor");
        let mut expected = key.clone();
        expected.push(0x00);
        prop_assert_eq!(succ, expected.as_slice());
    }

    /// At `MAX_KEY_SIZE`, `key_successor` delegates to `prefix_successor`.
    #[test]
    fn key_successor_delegates_to_prefix_successor_at_max(
        key in proptest::collection::vec(any::<u8>(), MAX_KEY_SIZE..=MAX_KEY_SIZE),
    ) {
        let mut succ_buf = KeyBuf::new();
        let mut prefix_buf = KeyBuf::new();
        let succ = key_successor(&key, &mut succ_buf).map(|bytes| bytes.to_vec());
        let prefix = prefix_successor(&key, &mut prefix_buf).map(|bytes| bytes.to_vec());
        prop_assert_eq!(succ, prefix);
    }

    /// `byte_midpoint` with different-length inputs: the result (when `Some`)
    /// is always strictly between `a` and `b`.
    #[test]
    fn byte_midpoint_different_lengths_strictly_between(
        a in proptest::collection::vec(any::<u8>(), 0..=16),
        extra in proptest::collection::vec(any::<u8>(), 1..=16),
    ) {
        // Build `b` by extending `a` so lengths differ.
        let mut b = a.clone();
        b.extend_from_slice(&extra);
        // Ensure a < b (skip if not — the function returns None anyway).
        let mut buf = KeyBuf::new();
        if a.as_slice() < b.as_slice()
            && let Some(mid) = byte_midpoint(&a, &b, &mut buf)
        {
            prop_assert!(a.as_slice() < mid);
            prop_assert!(mid < b.as_slice());
        }
    }
}
