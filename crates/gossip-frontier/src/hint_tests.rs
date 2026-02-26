//! Tests for shard hint framing, metadata envelope helpers, and split-hint
//! propagation invariants.
//!
//! The suite covers both deterministic edge cases and proptest roundtrips so
//! docs in `hint.rs` stay aligned with wire-format and validation behavior.

use proptest::prelude::*;

use super::*;
use crate::key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PrefixShardError, decode_manifest_row_key,
};
use gossip_contracts::coordination::shard_spec::{
    MAX_KEY_SIZE, MAX_METADATA_SIZE, ShardSpec, ShardSpecInputError,
};

#[derive(Clone, Debug, PartialEq, Eq)]
enum OwnedHint {
    Range,
    Prefix(Vec<u8>),
    Manifest {
        manifest_id: u64,
        start_row: u64,
        end_row: u64,
    },
}

impl OwnedHint {
    /// Convert owned test data into the borrowed API shape used by
    /// [`ShardHint`].
    ///
    /// Keeping owned bytes in the test model avoids self-referential borrowed
    /// fixtures in property strategies.
    fn as_hint(&self) -> ShardHint<'_> {
        match self {
            Self::Range => ShardHint::Range,
            Self::Prefix(prefix) => ShardHint::Prefix {
                prefix: prefix.as_slice(),
            },
            Self::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => ShardHint::Manifest {
                manifest_id: *manifest_id,
                start_row: *start_row,
                end_row: *end_row,
            },
        }
    }
}

#[test]
fn shard_hint_range_roundtrip() {
    let hint = ShardHint::Range;
    let encoded = encode_hint(hint);
    assert_eq!(encoded, vec![0x00]);

    let (decoded, consumed) = ShardHint::decode(&encoded).expect("range hint should decode");
    assert_eq!(decoded, hint);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn shard_hint_prefix_roundtrip() {
    let prefix = vec![0xAA, 0xBB, 0xCC];
    let hint = ShardHint::Prefix {
        prefix: prefix.as_slice(),
    };
    let encoded = encode_hint(hint);
    assert_eq!(
        encoded,
        vec![0x01, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
    );

    let (decoded, consumed) = ShardHint::decode(&encoded).expect("prefix hint should decode");
    assert_eq!(
        decoded,
        ShardHint::Prefix {
            prefix: &encoded[5..8]
        }
    );
    assert_eq!(consumed, encoded.len());
}

#[test]
fn shard_hint_manifest_roundtrip() {
    let hint = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 11,
        end_row: 12,
    };
    let encoded = encode_hint(hint);

    let (decoded, consumed) = ShardHint::decode(&encoded).expect("manifest hint should decode");
    assert_eq!(decoded, hint);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn shard_hint_decode_rejects_empty_data() {
    assert_eq!(ShardHint::decode(&[]), Err(ShardHintDecodeError::EmptyData),);
}

#[test]
fn shard_hint_decode_rejects_unknown_tag() {
    assert_eq!(
        ShardHint::decode(&[0x7F]),
        Err(ShardHintDecodeError::UnknownTag(0x7F)),
    );
}

#[test]
fn shard_hint_decode_rejects_truncated_prefix_header() {
    assert_eq!(
        ShardHint::decode(&[0x01, 0x00, 0x00]),
        Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min: 5,
            actual: 3,
        }),
    );
}

#[test]
fn shard_hint_decode_rejects_truncated_prefix_payload() {
    assert_eq!(
        ShardHint::decode(&[0x01, 0x00, 0x00, 0x00, 0x03, 0xAB]),
        Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min: 8,
            actual: 6,
        }),
    );
}

#[test]
fn shard_hint_decode_rejects_truncated_manifest() {
    let mut truncated = vec![0x00; 24];
    truncated[0] = 0x02;
    assert_eq!(
        ShardHint::decode(&truncated),
        Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: 25,
            actual: 24,
        }),
    );
}

#[test]
fn shard_hint_decode_rejects_inverted_manifest_rows() {
    let data = encode_raw_manifest(5, 22, 10);
    assert_eq!(
        ShardHint::decode(&data),
        Err(ShardHintDecodeError::InvertedManifestRows {
            start_row: 22,
            end_row: 10,
        }),
    );
}

#[test]
fn shard_hint_decode_rejects_equal_manifest_rows() {
    let data = encode_raw_manifest(5, 10, 10);
    assert_eq!(
        ShardHint::decode(&data),
        Err(ShardHintDecodeError::InvertedManifestRows {
            start_row: 10,
            end_row: 10,
        }),
    );
}

#[test]
fn shard_hint_decode_returns_consumed_length_with_trailing_bytes() {
    let prefix = vec![0x01, 0x02];
    let mut bytes = encode_hint(ShardHint::Prefix {
        prefix: prefix.as_slice(),
    });
    let consumed_expected = bytes.len();
    bytes.extend_from_slice(&[0xFE, 0xED]);

    let (decoded, consumed) = ShardHint::decode(&bytes).expect("hint prefix should decode");
    assert_eq!(
        decoded,
        ShardHint::Prefix {
            prefix: &bytes[5..7]
        }
    );
    assert_eq!(consumed, consumed_expected);
}

#[test]
fn shard_metadata_decode_empty_defaults_to_range_hint() {
    let decoded = ShardMetadata::decode(&[]).expect("empty metadata should decode");
    assert_eq!(decoded.hint, ShardHint::Range);
    assert_eq!(decoded.connector_extra.len(), 0);
}

#[test]
fn shard_metadata_decode_rejects_non_empty_non_conforming_input() {
    let malformed_cases = vec![
        vec![0x00],
        vec![0x00, 0x00, 0x00, 0x02, 0x00],
        vec![0x00, 0x00, 0x00, 0x01, 0xFF],
        vec![0x00, 0x00, 0x00, 0x02, 0x00, 0xAB],
        vec![0x00, 0x00, 0x00, 0x05, 0x01, 0x00, 0x00, 0x00, 0x01],
    ];

    for metadata in malformed_cases {
        assert!(
            ShardMetadata::decode(&metadata).is_err(),
            "metadata should be rejected: {metadata:?}",
        );
    }
}

#[test]
fn shard_metadata_encode_decode_roundtrip() {
    let connector_extra = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let metadata = ShardMetadata::new(
        ShardHint::Manifest {
            manifest_id: 42,
            start_row: 100,
            end_row: 200,
        },
        connector_extra.as_slice(),
    );
    let encoded = encode_metadata(metadata);
    let decoded = ShardMetadata::decode(&encoded).expect("metadata should decode");
    assert_eq!(decoded.hint, metadata.hint);
    assert_eq!(decoded.connector_extra, connector_extra.as_slice());
}

#[test]
fn shard_metadata_encode_rejects_oversized_payload() {
    let connector_extra = vec![0xAB; MAX_METADATA_SIZE - 4];
    let metadata = ShardMetadata::new(ShardHint::Range, connector_extra.as_slice());
    let mut buf = MetadataBuf::new();

    assert_eq!(
        metadata.encode_into(&mut buf),
        Err(ShardEncodeError::MetadataTooLarge {
            size: MAX_METADATA_SIZE + 1,
            max: MAX_METADATA_SIZE,
        }),
    );
}

#[test]
fn range_shard_roundtrip_with_decode_helpers() {
    let mut scratch = ShardSpecScratch::new();
    let spec =
        range_shard_ref(b"a", b"z", b"ctx", &mut scratch).expect("range shard should be valid");
    assert_eq!(spec.key_range_start(), b"a");
    assert_eq!(spec.key_range_end(), b"z");

    let decoded = decode_metadata(spec).expect("metadata should decode");
    assert_eq!(decoded.hint, ShardHint::Range);
    assert_eq!(decoded.connector_extra, b"ctx");

    assert_eq!(
        decode_hint(spec).expect("hint should decode"),
        ShardHint::Range
    );
    assert_eq!(
        decode_connector_extra(spec).expect("connector extra should decode"),
        b"ctx"
    );
}

#[test]
fn range_shard_rejects_oversized_metadata() {
    let extra = vec![0xAB; MAX_METADATA_SIZE - 4];
    let mut scratch = ShardSpecScratch::new();
    let err = range_shard_ref(b"a", b"z", &extra, &mut scratch)
        .expect_err("oversized metadata should fail");
    assert_eq!(
        err,
        ShardSpecInputError::MetadataTooLarge {
            size: MAX_METADATA_SIZE + 1,
            max: MAX_METADATA_SIZE,
        }
    );
}

#[test]
fn prefix_shard_roundtrip_with_decode_helpers() {
    let prefix = b"src/";
    let mut scratch = ShardSpecScratch::new();
    let spec = prefix_shard_ref(prefix, b"bucket=prod", &mut scratch)
        .expect("prefix shard should be valid");

    assert_eq!(spec.key_range_start(), prefix);
    let mut expected_end_buf = KeyBuf::new();
    let expected_end = prefix_successor(prefix, &mut expected_end_buf)
        .expect("non-all-ff prefix should have successor");
    assert_eq!(spec.key_range_end(), expected_end);

    assert_eq!(
        decode_hint(spec).expect("hint should decode"),
        ShardHint::Prefix { prefix }
    );
    assert_eq!(
        decode_connector_extra(spec).expect("connector extra should decode"),
        b"bucket=prod"
    );
}

#[test]
fn prefix_shard_rejects_oversized_prefix_with_prefix_too_large() {
    // A prefix larger than MAX_KEY_SIZE should return PrefixTooLarge, not
    // InvalidShardSpec(MetadataTooLarge), regardless of how large it is.
    let prefix = vec![0xAB; MAX_KEY_SIZE + 1];
    let mut scratch = ShardSpecScratch::new();
    let err =
        prefix_shard_ref(&prefix, b"", &mut scratch).expect_err("oversized prefix should fail");
    assert!(
        matches!(err, PrefixShardError::PrefixTooLarge { .. }),
        "expected PrefixTooLarge, got {err:?}"
    );

    // Even a prefix that exceeds the metadata capacity should still report
    // the prefix-specific error, not a generic metadata error.
    let huge_prefix = vec![0xAB; MAX_METADATA_SIZE + 1];
    let err =
        prefix_shard_ref(&huge_prefix, b"", &mut scratch).expect_err("huge prefix should fail");
    assert!(
        matches!(err, PrefixShardError::PrefixTooLarge { .. }),
        "expected PrefixTooLarge for huge prefix, got {err:?}"
    );
}

#[test]
fn prefix_shard_rejects_all_ff_prefix() {
    let prefix = vec![0xFF; 8];
    let mut scratch = ShardSpecScratch::new();
    let err = prefix_shard_ref(&prefix, b"ctx", &mut scratch)
        .expect_err("all-ff prefix has no successor");
    assert_eq!(err, PrefixShardError::NoSuccessor);
}

#[test]
fn prefix_shard_rejects_empty_prefix() {
    let mut scratch = ShardSpecScratch::new();
    let err =
        prefix_shard_ref(b"", b"ctx", &mut scratch).expect_err("empty prefix should be rejected");
    assert_eq!(err, PrefixShardError::EmptyPrefix);
}

#[test]
fn manifest_shard_roundtrip_with_decode_helpers() {
    let mut scratch = ShardSpecScratch::new();
    let spec = manifest_shard_ref(42, 10, 20, b"blob", &mut scratch)
        .expect("manifest shard should be valid");
    let start = decode_manifest_row_key(spec.key_range_start())
        .expect("start should be a valid manifest row key");
    let end = decode_manifest_row_key(spec.key_range_end())
        .expect("end should be a valid manifest row key");

    assert_eq!(start, ManifestRowKey::new(42, 10));
    assert_eq!(end, ManifestRowKey::new(42, 20));

    assert_eq!(
        decode_hint(spec).expect("hint should decode"),
        ShardHint::Manifest {
            manifest_id: 42,
            start_row: 10,
            end_row: 20,
        }
    );
    assert_eq!(
        decode_connector_extra(spec).expect("connector extra should decode"),
        b"blob"
    );
}

#[test]
fn manifest_shard_rejects_inverted_rows() {
    let mut scratch = ShardSpecScratch::new();
    let err =
        manifest_shard_ref(9, 99, 10, b"ctx", &mut scratch).expect_err("inverted rows should fail");
    assert_eq!(
        err,
        ShardSpecInputError::InvertedRange {
            start_len: ManifestRowKey::ENCODED_LEN,
            end_len: ManifestRowKey::ENCODED_LEN,
        }
    );
}

#[test]
fn decode_helpers_propagate_malformed_metadata_errors() {
    let spec = ShardSpec::with_range_and_metadata(b"a", b"b", vec![0x00]);
    assert!(decode_metadata(&spec).is_err());
    assert!(decode_hint(&spec).is_err());
    assert!(decode_connector_extra(&spec).is_err());
}

#[test]
fn propagate_hint_on_split_range_stays_range() {
    let propagated = propagate_hint_on_split(&ShardHint::Range, b"a", b"b")
        .expect("range propagation should always succeed");
    assert_eq!(propagated, ShardHint::Range);
}

#[test]
fn propagate_hint_on_split_prefix_demotes_to_range() {
    let parent = ShardHint::Prefix { prefix: b"src/" };
    let propagated = propagate_hint_on_split(&parent, b"src/", b"src/z")
        .expect("valid prefix child bounds should propagate");
    assert_eq!(propagated, ShardHint::Range);
}

#[test]
fn propagate_hint_on_split_prefix_rejects_out_of_range_start() {
    let parent = ShardHint::Prefix { prefix: b"src/" };
    let err = propagate_hint_on_split(&parent, b"aaa", b"src/z")
        .expect_err("out-of-range start should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::Start
        }
    );
}

#[test]
fn propagate_hint_on_split_prefix_rejects_out_of_range_end() {
    let parent = ShardHint::Prefix { prefix: b"src/" };
    let err = propagate_hint_on_split(&parent, b"src/", b"zzz")
        .expect_err("out-of-range end should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::End
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_adjusts_child_rows() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(7, 25);
    let child_end = encode_manifest_row_key(7, 75);

    let propagated = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect("valid manifest child bounds should propagate");
    assert_eq!(
        propagated,
        ShardHint::Manifest {
            manifest_id: 7,
            start_row: 25,
            end_row: 75,
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_child_end_at_parent_end() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(7, 50);
    let child_end = encode_manifest_row_key(7, 100);

    let propagated = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect("child_end == parent.end_row should be valid for half-open intervals");
    assert_eq!(
        propagated,
        ShardHint::Manifest {
            manifest_id: 7,
            start_row: 50,
            end_row: 100,
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_non_manifest_boundaries() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let err = propagate_hint_on_split(&parent, b"not-a-row", b"also-not-a-row")
        .expect_err("non-manifest boundaries should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidManifestBoundary {
            boundary: SplitBoundary::Start
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_manifest_id_mismatch() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(8, 25);
    let child_end = encode_manifest_row_key(8, 75);

    let err = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect_err("manifest-id mismatch should fail");
    assert_eq!(
        err,
        HintPropagationError::ManifestIdMismatch {
            parent: 7,
            child: 8
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_out_of_parent_bounds() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 10,
        end_row: 20,
    };
    let child_start = encode_manifest_row_key(7, 0);
    let child_end = encode_manifest_row_key(7, 15);

    let err = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect_err("out-of-bounds child range should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidManifestBoundary {
            boundary: SplitBoundary::Start
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_empty_child_range() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(7, 50);
    let child_end = encode_manifest_row_key(7, 50);

    let err = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect_err("degenerate child range should fail");
    assert_eq!(
        err,
        HintPropagationError::EmptyManifestRange {
            start_row: 50,
            end_row: 50
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_non_manifest_end_boundary() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(7, 10);
    let err = propagate_hint_on_split(&parent, &child_start, b"not-a-row")
        .expect_err("non-manifest end boundary should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidManifestBoundary {
            boundary: SplitBoundary::End
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_end_manifest_id_mismatch() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 0,
        end_row: 100,
    };
    let child_start = encode_manifest_row_key(7, 25);
    let child_end = encode_manifest_row_key(99, 75);

    let err = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect_err("end manifest-id mismatch should fail");
    assert_eq!(
        err,
        HintPropagationError::ManifestIdMismatch {
            parent: 7,
            child: 99
        }
    );
}

#[test]
fn propagate_hint_on_split_manifest_rejects_end_row_beyond_parent() {
    let parent = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 10,
        end_row: 20,
    };
    let child_start = encode_manifest_row_key(7, 15);
    let child_end = encode_manifest_row_key(7, 25);

    let err = propagate_hint_on_split(&parent, &child_start, &child_end)
        .expect_err("end row beyond parent should fail");
    assert_eq!(
        err,
        HintPropagationError::InvalidManifestBoundary {
            boundary: SplitBoundary::End
        }
    );
}

proptest! {
    #![proptest_config(gossip_contracts::test_util::miri_proptest_config())]

    #[test]
    fn shard_hint_proptest_roundtrip(hint in arb_owned_hint()) {
        let mut buf = MetadataBuf::new();
        let encoded = hint
            .as_hint()
            .encode_into(&mut buf)
            .expect("encoded hint should fit metadata buffer")
            .to_vec();

        let (decoded, consumed) = ShardHint::decode(&encoded)
            .expect("encoded hint should decode");

        prop_assert_eq!(consumed, encoded.len());
        prop_assert_eq!(decoded, hint.as_hint());
    }

    #[test]
    fn shard_metadata_proptest_roundtrip(
        hint in arb_owned_hint(),
        connector_extra in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let metadata = ShardMetadata::new(hint.as_hint(), connector_extra.as_slice());
        let mut buf = MetadataBuf::new();
        let encoded = metadata
            .encode_into(&mut buf)
            .expect("bounded metadata should encode")
            .to_vec();

        let decoded = ShardMetadata::decode(&encoded)
            .expect("encoded metadata should decode");
        prop_assert_eq!(decoded.hint, hint.as_hint());
        prop_assert_eq!(decoded.connector_extra, connector_extra.as_slice());
    }

    #[test]
    fn prefix_shard_contains_all_keys_with_prefix(
        prefix in proptest::collection::vec(any::<u8>(), 1..=32),
        suffix in proptest::collection::vec(any::<u8>(), 0..=32),
    ) {
        prop_assume!(prefix.iter().any(|&byte| byte != u8::MAX));
        prop_assume!(prefix.len() + suffix.len() <= MAX_KEY_SIZE);

        let mut scratch = ShardSpecScratch::new();
        let spec = prefix_shard_ref(prefix.as_slice(), b"ctx", &mut scratch)
            .expect("prefix shard should be constructible for bounded prefix");
        let mut key = prefix.clone();
        key.extend_from_slice(&suffix);

        prop_assert!(key.starts_with(&prefix));
        prop_assert!(spec.contains_key(&key));
    }
}

fn arb_owned_hint() -> impl Strategy<Value = OwnedHint> {
    prop_oneof![
        Just(OwnedHint::Range),
        proptest::collection::vec(any::<u8>(), 0..=64).prop_map(OwnedHint::Prefix),
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(manifest_id, a, b)| {
            let (start_row, end_row) = ordered_rows(a, b);
            OwnedHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            }
        }),
    ]
}

/// Normalize two arbitrary rows into a valid half-open interval.
///
/// The equal-row case is widened to one row so generated manifest hints satisfy
/// `start_row < end_row`.
fn ordered_rows(a: u64, b: u64) -> (u64, u64) {
    if a < b {
        (a, b)
    } else if a > b {
        (b, a)
    } else if a == u64::MAX {
        (u64::MAX - 1, u64::MAX)
    } else {
        (a, a + 1)
    }
}

#[test]
fn shard_hint_encode_rejects_inverted_manifest_rows() {
    let hint = ShardHint::Manifest {
        manifest_id: 1,
        start_row: 22,
        end_row: 10,
    };
    let mut buf = MetadataBuf::new();
    assert_eq!(
        hint.encode_into(&mut buf),
        Err(ShardEncodeError::InvertedManifestRows {
            start_row: 22,
            end_row: 10,
        }),
    );
}

#[test]
fn shard_hint_encode_rejects_equal_manifest_rows() {
    let hint = ShardHint::Manifest {
        manifest_id: 1,
        start_row: 10,
        end_row: 10,
    };
    let mut buf = MetadataBuf::new();
    assert_eq!(
        hint.encode_into(&mut buf),
        Err(ShardEncodeError::InvertedManifestRows {
            start_row: 10,
            end_row: 10,
        }),
    );
}

/// Encode bypasses the invalid-row check by writing raw bytes, but decode
/// must still reject the frame. This confirms the encode/decode asymmetry:
/// the enum can represent inverted rows, encode refuses them, and decode
/// independently rejects them even if the wire bytes were hand-crafted.
#[test]
fn shard_hint_decode_rejects_raw_inverted_manifest() {
    let raw = encode_raw_manifest(42, 100, 50);
    assert_eq!(
        ShardHint::decode(&raw),
        Err(ShardHintDecodeError::InvertedManifestRows {
            start_row: 100,
            end_row: 50,
        }),
    );
}

/// Hand-build a manifest frame for decode-path tests.
///
/// This bypasses constructor/encode validation so tests can inject malformed
/// row bounds directly at the wire level.
fn encode_raw_manifest(manifest_id: u64, start_row: u64, end_row: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(25);
    data.push(0x02);
    data.extend_from_slice(&manifest_id.to_be_bytes());
    data.extend_from_slice(&start_row.to_be_bytes());
    data.extend_from_slice(&end_row.to_be_bytes());
    data
}

fn encode_manifest_row_key(manifest_id: u64, row: u64) -> Vec<u8> {
    let mut buf = KeyBuf::new();
    ManifestRowKey::new(manifest_id, row).encode_into(&mut buf);
    buf.as_bytes().to_vec()
}

fn encode_hint(hint: ShardHint<'_>) -> Vec<u8> {
    let mut buf = MetadataBuf::new();
    hint.encode_into(&mut buf)
        .expect("hint should encode")
        .to_vec()
}

fn encode_metadata(metadata: ShardMetadata<'_>) -> Vec<u8> {
    let mut buf = MetadataBuf::new();
    metadata
        .encode_into(&mut buf)
        .expect("metadata should encode")
        .to_vec()
}
