use proptest::prelude::*;

use super::*;
use crate::coordination::shard_spec::MAX_METADATA_SIZE;

#[test]
fn shard_hint_range_roundtrip() {
    let hint = ShardHint::Range;
    let encoded = hint.encode();
    assert_eq!(encoded, vec![0x00]);

    let (decoded, consumed) = ShardHint::decode(&encoded).expect("range hint should decode");
    assert_eq!(decoded, hint);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn shard_hint_prefix_roundtrip() {
    let hint = ShardHint::Prefix {
        prefix: vec![0xAA, 0xBB, 0xCC].into_boxed_slice(),
    };
    let encoded = hint.encode();
    assert_eq!(
        encoded,
        vec![0x01, 0x00, 0x00, 0x00, 0x03, 0xAA, 0xBB, 0xCC]
    );

    let (decoded, consumed) = ShardHint::decode(&encoded).expect("prefix hint should decode");
    assert_eq!(decoded, hint);
    assert_eq!(consumed, encoded.len());
}

#[test]
fn shard_hint_manifest_roundtrip() {
    let hint = ShardHint::Manifest {
        manifest_id: 7,
        start_row: 11,
        end_row: 12,
    };
    let encoded = hint.encode();

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
    let mut bytes = ShardHint::Prefix {
        prefix: vec![0x01, 0x02].into_boxed_slice(),
    }
    .encode();
    let consumed_expected = bytes.len();
    bytes.extend_from_slice(&[0xFE, 0xED]);

    let (decoded, consumed) = ShardHint::decode(&bytes).expect("hint prefix should decode");
    assert_eq!(
        decoded,
        ShardHint::Prefix {
            prefix: vec![0x01, 0x02].into_boxed_slice(),
        },
    );
    assert_eq!(consumed, consumed_expected);
}

#[test]
fn shard_metadata_decode_empty_defaults_to_range_hint() {
    let decoded = ShardMetadata::decode(&[]).expect("empty metadata should decode");
    assert_eq!(
        decoded,
        ShardMetadata {
            hint: ShardHint::Range,
            connector_extra: Box::new([]),
        },
    );
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
        assert_eq!(
            ShardMetadata::decode(&metadata),
            Err(ShardHintDecodeError::NotShardMetadataFormat),
            "metadata should be rejected: {metadata:?}",
        );
    }
}

#[test]
fn shard_metadata_encode_decode_roundtrip() {
    let metadata = ShardMetadata::new(
        ShardHint::Manifest {
            manifest_id: 42,
            start_row: 100,
            end_row: 200,
        },
        vec![0xDE, 0xAD, 0xBE, 0xEF],
    );
    let encoded = metadata.encode().expect("metadata should encode");
    let decoded = ShardMetadata::decode(&encoded).expect("metadata should decode");
    assert_eq!(decoded, metadata);
}

#[test]
fn shard_metadata_encode_rejects_oversized_payload() {
    let metadata = ShardMetadata::new(ShardHint::Range, vec![0xAB; MAX_METADATA_SIZE - 4]);
    assert_eq!(
        metadata.encode(),
        Err(MetadataEncodingError::MetadataTooLarge {
            size: MAX_METADATA_SIZE + 1,
            max: MAX_METADATA_SIZE,
        }),
    );
}

proptest! {
    #![proptest_config(crate::test_util::miri_proptest_config())]

    #[test]
    fn shard_hint_proptest_roundtrip(hint in arb_shard_hint()) {
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded)
            .expect("encoded hint should decode");
        prop_assert_eq!(decoded, hint);
        prop_assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn shard_metadata_proptest_roundtrip(
        hint in arb_shard_hint(),
        connector_extra in proptest::collection::vec(any::<u8>(), 0..=256),
    ) {
        let metadata = ShardMetadata::new(hint, connector_extra);
        let encoded = metadata.encode().expect("bounded metadata should encode");
        let decoded = ShardMetadata::decode(&encoded).expect("encoded metadata should decode");
        prop_assert_eq!(decoded, metadata);
    }
}

fn arb_shard_hint() -> impl Strategy<Value = ShardHint> {
    prop_oneof![
        Just(ShardHint::Range),
        proptest::collection::vec(any::<u8>(), 0..=64).prop_map(|prefix| ShardHint::Prefix {
            prefix: prefix.into_boxed_slice(),
        }),
        (any::<u64>(), any::<u64>(), any::<u64>()).prop_map(|(manifest_id, a, b)| {
            let (start_row, end_row) = ordered_rows(a, b);
            ShardHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            }
        }),
    ]
}

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

fn encode_raw_manifest(manifest_id: u64, start_row: u64, end_row: u64) -> Vec<u8> {
    let mut data = Vec::with_capacity(25);
    data.push(0x02);
    data.extend_from_slice(&manifest_id.to_be_bytes());
    data.extend_from_slice(&start_row.to_be_bytes());
    data.extend_from_slice(&end_row.to_be_bytes());
    data
}
