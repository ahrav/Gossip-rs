use crate::api::{
    AnchorPolicy, Gate, RuleSpec, TransformConfig, TransformId, TransformMode, Tuning,
};
use crate::engine::Engine;

// --------------------------
// Demo engine (rules + transforms)
// --------------------------

/// Anchor selection mode for demo rules.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorMode {
    /// Use the hand-curated anchors on each rule.
    Manual,
    /// Derive anchors from regex patterns (empty anchors trigger derivation).
    Derived,
}

/// Builds a demo engine with the full gitleaks rule set.
pub fn demo_engine() -> Engine {
    Engine::new(demo_rules(), demo_transforms(), demo_tuning())
}

/// Builds a demo engine with either manual or derived anchors.
pub fn demo_engine_with_anchor_mode(mode: AnchorMode) -> Engine {
    let policy = match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    Engine::new_with_anchor_policy(demo_rules(), demo_transforms(), demo_tuning(), policy)
}

/// Builds a demo engine with the specified anchor mode and tuning.
pub fn demo_engine_with_anchor_mode_and_tuning(mode: AnchorMode, tuning: Tuning) -> Engine {
    let policy = match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    Engine::new_with_anchor_policy(demo_rules(), demo_transforms(), tuning, policy)
}

/// Builds a demo engine with the specified anchor mode and transform depth cap.
pub fn demo_engine_with_anchor_mode_and_max_transform_depth(
    mode: AnchorMode,
    max_transform_depth: usize,
) -> Engine {
    let policy = match mode {
        AnchorMode::Manual => AnchorPolicy::ManualOnly,
        AnchorMode::Derived => AnchorPolicy::DerivedOnly,
    };
    let mut tuning = demo_tuning();
    tuning.max_transform_depth = max_transform_depth;
    Engine::new_with_anchor_policy(demo_rules(), demo_transforms(), tuning, policy)
}

pub fn demo_rules() -> Vec<RuleSpec> {
    crate::rules::builtin_rules()
}

pub fn demo_transforms() -> Vec<TransformConfig> {
    vec![
        TransformConfig {
            id: TransformId::UrlPercent,
            mode: TransformMode::Always,
            gate: Gate::AnchorsInDecoded,
            min_len: 16,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
        TransformConfig {
            id: TransformId::Base64,
            mode: TransformMode::Always,
            // Performance-first: gate base64 by anchors in decoded output.
            gate: Gate::AnchorsInDecoded,
            min_len: 32,
            max_spans_per_buffer: 8,
            max_encoded_len: 64 * 1024,
            max_decoded_bytes: 64 * 1024,
            plus_to_space: false,
            base64_allow_space_ws: false,
        },
    ]
}

pub fn demo_tuning() -> Tuning {
    Tuning {
        merge_gap: 64,
        max_windows_per_rule_variant: 16,
        pressure_gap_start: 128,
        max_anchor_hits_per_rule_variant: 2048,
        max_utf16_decoded_bytes_per_window: 64 * 1024,
        max_transform_depth: 3,
        max_total_decode_output_bytes: 512 * 1024,
        max_work_items: 256,
        max_findings_per_chunk: 8192,
        scan_utf16_variants: true,
    }
}
