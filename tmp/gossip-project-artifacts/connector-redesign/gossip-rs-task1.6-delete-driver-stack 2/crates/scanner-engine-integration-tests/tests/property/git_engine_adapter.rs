//! Property tests for Git engine adapter chunking invariance.

use std::sync::OnceLock;

use proptest::prelude::*;
use regex::bytes::Regex;

use scanner_engine::{AnchorPolicy, Engine, RuleSpec, ValidatorKind, demo_tuning};
use scanner_git::scan_blob_chunked;

/// Shared engine for property tests (expensive to build).
fn test_engine() -> &'static Engine {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    ENGINE.get_or_init(|| {
        let rule_a = RuleSpec {
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
            re: Regex::new(r"TOK_([A-Z0-9]{4,8})").unwrap(),
        };
        let rule_b = RuleSpec {
            name: "key",
            anchors: &[b"KEY_"],
            radius: 12,
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
            re: Regex::new(r"KEY_([a-z0-9]{6})").unwrap(),
        };
        Engine::new_with_anchor_policy(
            vec![rule_a, rule_b],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        )
    })
}

proptest! {
    #[test]
    fn chunking_invariance_randomized_set_equal_to_full_scan(
        blob in prop::collection::vec(any::<u8>(), 0..2048),
        chunk in 64usize..512,
    ) {
        let engine = test_engine();
        let overlap = engine.required_overlap();
        // Ensure chunk size always exceeds overlap so progress is guaranteed.
        let chunk_bytes = chunk.max(overlap.saturating_add(1));
        let reference = scan_blob_chunked(engine, &blob, blob.len().max(overlap + 1))
            .expect("reference scan");
        let chunked = scan_blob_chunked(engine, &blob, chunk_bytes)
            .expect("chunked scan");
        prop_assert_eq!(reference, chunked);
    }
}
