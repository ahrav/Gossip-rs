//! Standalone scanner detection engine.
//!
//! This crate owns the core detection pipeline extracted from scanner-rs,
//! including rule loading, content policy, scan engine, and reusable scratch.
//! Migration-compatibility shims (for example `stdx::FixedVec` and
//! harness-gated re-exports) keep extracted scanner-rs modules building
//! without changing runtime behavior.
#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_macros)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(clippy::all)]
#![allow(rustdoc::broken_intra_doc_links)]
#![allow(rustdoc::private_intra_doc_links)]
#![allow(rustdoc::bare_urls)]
#![allow(rustdoc::redundant_explicit_links)]

/// Compatibility prelude used by extracted scanner-rs modules.
///
/// Re-exports `gossip_stdx` and keeps the historical `FixedVec` alias name.
pub mod stdx {
    pub use gossip_stdx::*;
    /// Back-compat alias to `InlineVec` used by pre-extraction modules.
    pub type FixedVec<T, const N: usize> = gossip_stdx::InlineVec<T, N>;
}

pub mod b64_yara_gate;
pub mod content_policy;
pub mod lsm;
pub mod perf_counters;
pub mod pool;
pub mod regex2anchor;
pub mod scratch_memory;
#[cfg(test)]
pub mod test_utils;
#[cfg(any(test, feature = "tiger-harness", feature = "test-support"))]
pub mod tiger_harness;

mod api;
#[cfg(any(test, feature = "test-support"))]
mod demo;
mod engine;
mod perf_stats;
mod rules;

#[cfg(feature = "b64-stats")]
pub use api::Base64DecodeStats;
pub use api::{
    AnchorPolicy, CharClassSpec, DecodeStep, DecodeSteps, DelimAfter, EntropySpec, FileId, Finding,
    FindingRec, Gate, LOCAL_CONTEXT_MAX_LOOKAROUND, LocalContextSpec, MAX_DECODE_STEPS,
    OfflineValidationSpec, OfflineVerdict, RuleSpec, STEP_ROOT, StepId, TailCharset,
    TransformConfig, TransformId, TransformMode, Tuning, TwoPhaseSpec, Utf16Endianness,
    ValidatorKind,
};

#[cfg(any(test, feature = "test-support"))]
pub use demo::{
    AnchorMode, demo_engine, demo_engine_with_anchor_mode,
    demo_engine_with_anchor_mode_and_max_transform_depth, demo_engine_with_anchor_mode_and_tuning,
    demo_rules, demo_transforms, demo_tuning,
};

#[cfg(feature = "bench")]
pub use engine::BenchHitAccPool;
#[cfg(feature = "tiger-harness")]
pub use engine::FuzzHitAccPool;
#[cfg(feature = "tiger-harness")]
pub use engine::fuzz_try_load;
#[cfg(feature = "stats")]
pub use engine::{AnchorPlanStats, VectorscanStats};
#[cfg(feature = "bench")]
pub use engine::{
    BenchEntropyState, BenchMergeRangesState, BenchPackedPatterns, BenchUtf16DecodeState,
    bench_build_entropy_state, bench_build_merge_ranges_state, bench_build_utf16_decode_state,
    bench_classify_window, bench_contains_all_memmem, bench_contains_any_memmem,
    bench_decode_utf16be, bench_decode_utf16be_with_state, bench_decode_utf16le,
    bench_decode_utf16le_with_state, bench_entropy_gate_passes,
    bench_entropy_gate_passes_with_state, bench_extract_secret_span_locs, bench_find_spans_into,
    bench_hash128, bench_map_utf16_decoded_offset, bench_merge_ranges, bench_merge_ranges_load,
    bench_merge_ranges_run, bench_offline_validate_aws_access_key,
    bench_offline_validate_pypi_token, bench_offline_validate_sentry_org_token,
    bench_offline_validate_slack_token, bench_pack_patterns_raw, bench_shannon_entropy,
    bench_shannon_entropy_with_state, bench_stream_decode_base64, bench_stream_decode_url,
};
pub use engine::{Engine, NormHash, ScanScratch};
#[cfg(feature = "tiger-harness")]
pub use engine::{fuzz_classify_window, fuzz_offline_validate};
