//! Integration tests for the Git engine adapter.

use regex::bytes::Regex;

use scanner_engine::{
    AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId, TransformMode,
    ValidatorKind, demo_tuning,
};
use scanner_git::scan_blob_chunked;

fn test_engine() -> Engine {
    let rule = RuleSpec {
        name: "tok",
        anchors: &[b"TOK_"],
        radius: 16,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: Some(1),
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"TOK_([A-Z0-9]{8})").unwrap(),
    };

    let transforms = vec![TransformConfig {
        id: TransformId::Base64,
        mode: TransformMode::Always,
        gate: Gate::AnchorsInDecoded,
        min_len: 16,
        max_spans_per_buffer: 4,
        max_encoded_len: 1024,
        max_decoded_bytes: 1024,
        plus_to_space: false,
        base64_allow_space_ws: false,
    }];

    Engine::new_with_anchor_policy(
        vec![rule],
        transforms,
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    )
}

#[test]
fn overlap_duplicates_are_deduped_per_blob() {
    let engine = test_engine();
    let overlap = engine.required_overlap();
    let chunk_bytes = overlap.saturating_add(16).max(overlap.saturating_add(1));

    let pattern = b"TOK_ABCDEFGH";
    let mut blob = vec![b'A'; overlap.saturating_add(pattern.len()).saturating_add(32)];
    let pos = overlap.saturating_sub(4);
    blob[pos..pos + pattern.len()].copy_from_slice(pattern);

    let reference =
        scan_blob_chunked(&engine, &blob, blob.len().max(overlap + 1)).expect("reference scan");
    let chunked = scan_blob_chunked(&engine, &blob, chunk_bytes).expect("chunked scan");

    assert_eq!(reference, chunked, "overlap duplicates must be deduped");
    assert!(chunked.windows(2).all(|w| w[0] < w[1]));
}
