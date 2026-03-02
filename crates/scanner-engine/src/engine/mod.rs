//! Core scanning engine: compiles rule specs into anchors/gates and executes
//! bounded scans with reusable scratch allocations.
//!
//! # Algorithm
//! 1. Compile rules into anchor patterns, confirm-all literals, and keyword gates.
//! 2. Prefilter input buffers (Vectorscan / gates) to build candidate windows.
//! 3. Validate windows with regexes/validators and record compact findings.
//! 4. Optionally decode transform spans into derived buffers and repeat via BFS.
//! 5. Apply suppression policies at finding emission sites before final output.
//!
//! # Module Layout
//! - `core`: immutable engine configuration and compiled rule state.
//! - `scratch`: per-scan mutable buffers, counters, and decode provenance.
//! - `buffer_scan`, `window_validate`, `stream_decode`: runtime scan pipeline
//!   stages that populate and consume scratch state.
//! - `decode_state`, `work_items`, `hit_pool`: bounded scheduling/storage helpers
//!   for decoded work.
//! - `rule_repr`: compiled rule representation and gate metadata.
//! - `offline_validate`: offline (post-scan) validation for rules that require it.
//! - `transform`, `safelist`, `helpers`: supporting logic reused by scan stages.
//! - `vectorscan_prefilter`, `vs_cache`: Vectorscan database build/load/runtime
//!   integration.
//!
//! # Invariants
//! - The engine is immutable after construction; all mutable scan state lives in
//!   [`ScanScratch`], which is single-threaded and reused across scans.
//! - Scratch buffers are reused across scans and must be reset between scans.
//! - Decoded buffers are stored in an append-only slab; ranges and `StepId`
//!   references are only valid until the next `ScanScratch::reset_for_scan`.
//! - Offsets stored in hot paths use `u32`; callers must chunk inputs so buffer
//!   lengths fit in `u32`.
//! - `SpanU32` ranges and slab-backed buffer references are only valid until
//!   the next reset.
//! - All per-scan work is bounded by tuning limits: windows, hits, findings,
//!   decode output bytes, transform depth, and work items.
//! - UTF-16 anchors always contain at least one NUL byte, enabling a raw-only
//!   fast path for NUL-free buffers.
//!
//! # Span Semantics
//! - Raw findings report byte offsets in the scanned buffer.
//! - UTF-16 variant findings report spans in decoded UTF-8 bytes and attach a
//!   [`DecodeStep::Utf16Window`] that records the source UTF-16 window.
//! - Findings from decoded/transformed buffers report spans in derived buffers;
//!   the decode step chain provides provenance back to the root input.
//!
//! # Safety
//! - Unsafe slices are formed only from ranges validated against the root buffer,
//!   the decode slab, or scratch-owned temporary buffers; those buffers are not
//!   reallocated while the slices are in use.
//!
//! # Design Notes
//! - The engine favors predictable cost over perfect precision: span/anchor
//!   selection is permissive, while validation and gates enforce correctness.
//! - Prefilters (Vectorscan, base64 pre-gate) are conservative: they may admit
//!   false positives but must not drop true matches.
//! - Suppression policies (for example, safelist/value suppressor checks) are
//!   intended to be monotonic: they may remove candidate findings, but must not
//!   alter span/provenance for findings that remain.
//!
//! # Failure Modes and Limits
//! - Raw Vectorscan prefilter DB build failures are fatal (fallback disabled).
//! - UTF-16 prefilter DB build or scan failures disable UTF-16 anchor scans
//!   for the affected buffer.
//! - Budget enforcement may coalesce windows, skip deeper decode work, or drop
//!   findings; dropped findings are counted in
//!   [`ScanScratch::dropped_findings`].
//! - Stream decoding may fall back to full decode when window caps or budgets
//!   are exceeded; correctness is preserved at the cost of throughput.

// Internal compiled representation modules
mod decode_state;
mod hit_pool;
mod rule_repr;
mod work_items;

// Core engine and scratch modules
mod core;
pub(crate) mod offline_validate;
mod scratch;

// Scanning implementation modules (Engine impl extensions)
mod buffer_scan;
mod stream_decode;
mod window_validate;

// Supporting modules
mod helpers;
mod safelist;
mod simd_classify;
mod transform;
mod vectorscan_prefilter; // Vectorscan/Hyperscan prefilter DBs and FFI callbacks
mod vs_cache; // On-disk cache for serialized Vectorscan databases

#[cfg(test)]
mod tests;

// Public re-exports
pub use core::Engine;
pub use scratch::{NormHash, ScanScratch};

#[cfg(feature = "stats")]
pub use core::{AnchorPlanStats, VectorscanStats};

#[cfg(feature = "bench")]
pub use core::{
    BenchEntropyState, BenchMergeRangesState, BenchPackedPatterns, BenchUtf16DecodeState,
    bench_build_entropy_state, bench_build_merge_ranges_state, bench_build_utf16_decode_state,
    bench_contains_all_memmem, bench_contains_any_memmem, bench_decode_utf16be,
    bench_decode_utf16be_with_state, bench_decode_utf16le, bench_decode_utf16le_with_state,
    bench_entropy_gate_passes, bench_entropy_gate_passes_with_state,
    bench_extract_secret_span_locs, bench_find_spans_into, bench_hash128,
    bench_map_utf16_decoded_offset, bench_merge_ranges, bench_merge_ranges_load,
    bench_merge_ranges_run, bench_pack_patterns_raw, bench_shannon_entropy,
    bench_shannon_entropy_with_state, bench_stream_decode_base64, bench_stream_decode_url,
};
#[cfg(feature = "bench")]
pub use hit_pool::BenchHitAccPool;
#[cfg(feature = "bench")]
pub use offline_validate::{
    bench_offline_validate_aws_access_key, bench_offline_validate_pypi_token,
    bench_offline_validate_sentry_org_token, bench_offline_validate_slack_token,
};

#[cfg(feature = "bench")]
pub fn bench_classify_window(data: &[u8]) -> (u32, u32, u32, u32) {
    let p = simd_classify::classify_window(data);
    (p.lower, p.upper, p.digit, p.special)
}

#[cfg(feature = "tiger-harness")]
pub use hit_pool::FuzzHitAccPool;
#[cfg(feature = "tiger-harness")]
pub use vs_cache::fuzz_try_load;

/// Fuzz entry point: classify `data` into (lower, upper, digit, special) counts.
///
/// Wraps [`simd_classify::classify_window`] and returns a tuple to avoid
/// leaking the `pub(crate)` [`simd_classify::CharClassProfile`] type.
#[cfg(feature = "tiger-harness")]
pub fn fuzz_classify_window(data: &[u8]) -> (u32, u32, u32, u32) {
    let p = simd_classify::classify_window(data);
    (p.lower, p.upper, p.digit, p.special)
}

/// Fuzz entry point: run offline validation for `spec` on `secret` bytes.
///
/// Wraps [`offline_validate::validate`] to expose it to the fuzz harness
/// through the `tiger-harness` feature gate.
#[cfg(feature = "tiger-harness")]
pub fn fuzz_offline_validate(
    spec: crate::api::OfflineValidationSpec,
    secret: &[u8],
) -> crate::api::OfflineVerdict {
    offline_validate::validate(spec, secret)
}
