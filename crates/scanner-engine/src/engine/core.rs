//! Core scanning engine: compilation, prefiltering, and scan orchestration.
//!
//! ## Purpose
//!
//! Compile rule specs and transform configs into prefilter databases (Vectorscan),
//! gating structures (Base64 YARA gate, keyword/entropy gates), and compiled
//! regexes. Then drive bounded scans over raw and decoded buffers.
//!
//! ## Invariants
//!
//! - Inputs passed to `scan_*` must be chunked so `buf.len() <= u32::MAX`.
//! - [`ScanScratch`] is single-threaded and must not be shared across threads.
//! - The decode slab does not reallocate during a scan; all `unsafe` slice
//!   construction relies on this property.
//! - `scratch.out`, `scratch.drop_hint_end`, and `scratch.norm_hash` stay
//!   length-aligned throughout a scan; all finding writes preserve this
//!   lock-step invariant.
//!
//! ## Algorithm
//!
//! ### Build phase (`new` / `new_with_anchor_policy`)
//!
//! Compile each [`RuleSpec`](crate::api::RuleSpec) into a [`RuleCompiled`]
//! with precompiled regexes and optional gates.
//! Derive anchor patterns from regex analysis (or use manual anchors per
//! policy). Build deduped pattern maps for raw + UTF-16 variants.
//! Construct Vectorscan prefilter DBs (raw, UTF-16, stream, gate) and
//! the Base64 YARA pre-gate.
//!
//! ### Scan phase (`scan_chunk_into`)
//!
//! Run Vectorscan prefilter on root buffer to populate touched pairs.
//! Enqueue `ScanBuf(root)` into the work queue.
//! Process work items in FIFO order:
//!   - `ScanBuf`: validate regexes in prefilter windows (see
//!     [`buffer_scan`](super::buffer_scan)), then discover transform spans
//!     and enqueue `DecodeSpan` items.
//!   - `DecodeSpan`: decode the span, then enqueue a `ScanBuf` for the
//!     decoded output.
//! - Budgets (decode bytes, work items, depth) are enforced per-item so no
//!   single input forces unbounded work.
//! - Apply suppression/cap policies at finding emission time so most
//!   findings are handled inline, including offline structural validation
//!   which runs at each emission site in `window_validate.rs`.
//!
//! ## Design choices
//!
//! - Engine construction fails fast if required prefilter DBs cannot be built.
//! - Base64 pre-gates are conservative: they only skip decode work when no
//!   anchor *could* appear. Decoded-space validation remains authoritative.
//! - Raw regex patterns are included in the Vectorscan prefilter DB for rules
//!   with weak or missing literal anchors (< 5 bytes) or case-insensitive
//!   regexes. Rules with strong, case-sensitive anchors rely on anchor-pattern
//!   matching alone, reducing DB size.
//! - Suppression gates are monotonic: they may remove findings after validation
//!   but never mutate span or decode provenance for findings that remain.

use crate::api::*;
use crate::b64_yara_gate::{Base64YaraGate, Base64YaraGateConfig, PaddingPolicy, WhitespacePolicy};
use crate::regex2anchor::{
    AnchorDeriveConfig, TriggerPlan, UnfilterableReason, compile_trigger_plan,
};
use ahash::AHashMap;
#[cfg(feature = "stats")]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(feature = "bench")]
use super::helpers::contains_any_memmem;
use super::helpers::{build_log2_table, u64_to_usize};
#[cfg(feature = "bench")]
use super::rule_repr::PackedPatternsBuilder;
use super::rule_repr::{
    CharClassCompiled, ConfirmAllCompiled, EntropyCompiled, KeywordsCompiled, NO_GATE,
    PackedPatterns, RuleCold, RuleCompiled, Target, TwoPhaseCompiled, Variant, add_pat_owned,
    add_pat_raw, compile_confirm_all, compile_rule, derive_min_confidence, map_to_patterns,
    utf16be_bytes, utf16le_bytes,
};
use super::safelist::SafelistFilter;
use super::scratch::{DEDUP_RULE_ID_MAX, RootSpanMapCtx, ScanScratch};
use super::transform::{
    STREAM_DECODE_CHUNK_BYTES, base64_char_count, base64_skip_chars, find_spans_into,
    transform_quick_trigger,
};
use super::vectorscan_prefilter::{
    AnchorInput, VsAnchorDb, VsGateDb, VsPrefilterDb, VsStreamDb, VsUtf16StreamDb,
};
use super::work_items::{EncRef, WorkItem};
use crate::perf_counters as perf;
use std::ops::Range;
use std::time::Instant;

// --------------------------
// Statistics types
// --------------------------

/// Summary of anchor derivation choices during engine build.
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct AnchorPlanStats {
    /// Rules that used manual anchors (policy allowed).
    pub manual_rules: usize,
    /// Rules that used derived anchors from regex analysis.
    pub derived_rules: usize,
    /// Rules gated by a residue plan instead of anchors.
    pub residue_rules: usize,
    /// Rules that could not be gated soundly and require full validation.
    pub unfilterable_rules: usize,
}

/// Vectorscan usage counters for a scan run (feature: `stats`).
#[cfg(feature = "stats")]
#[derive(Clone, Copy, Debug, Default)]
pub struct VectorscanStats {
    /// Whether the Vectorscan DB compiled successfully.
    pub db_built: bool,
    /// Whether the UTF-16 Vectorscan DB compiled successfully.
    pub utf16_db_built: bool,
    /// Number of buffers where a Vectorscan scan was attempted.
    pub scans_attempted: u64,
    /// Number of Vectorscan scans that completed successfully.
    pub scans_ok: u64,
    /// Number of Vectorscan scans that errored.
    pub scans_err: u64,
    /// Number of buffers where a UTF-16 Vectorscan scan was attempted.
    pub utf16_scans_attempted: u64,
    /// Number of UTF-16 Vectorscan scans that completed successfully.
    pub utf16_scans_ok: u64,
    /// Number of UTF-16 Vectorscan scans that errored.
    pub utf16_scans_err: u64,
    /// Buffers scanned without the raw Vectorscan prefilter (full-buffer fallback).
    /// NOTE: Not yet wired in the scan pipeline; always reads zero.
    pub anchor_only: u64,
    /// Buffers that used raw Vectorscan and also ran a UTF-16 anchor scan.
    pub anchor_after_vs: u64,
    /// Buffers where raw Vectorscan was used and UTF-16 scan was skipped.
    pub anchor_skipped: u64,
    /// Stream decode spans that fell back to full decode.
    pub stream_force_full: u64,
    /// Stream decode spans that exceeded the per-rule window cap.
    pub stream_window_cap_exceeded: u64,
    /// Stream decode spans where the callback sink overflowed.
    pub stream_callback_overflow: u64,
}

/// Cache-line padded atomic counter to reduce false sharing between workers.
///
/// Each instance occupies exactly one 64-byte cache line so that concurrent
/// increments from different threads never contend on the same line. Without
/// this padding, adjacent `AtomicU64` counters in `VectorscanCounters` would
/// share a cache line and trigger false-sharing invalidations on every store.
#[cfg(feature = "stats")]
#[repr(align(64))]
#[derive(Default)]
pub(super) struct CachePaddedAtomicU64(AtomicU64);

#[cfg(feature = "stats")]
impl std::ops::Deref for CachePaddedAtomicU64 {
    type Target = AtomicU64;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

// Compile-time size/alignment guard: each counter occupies exactly one cache line.
#[cfg(feature = "stats")]
const _: () = assert!(
    std::mem::align_of::<CachePaddedAtomicU64>() == 64
        && std::mem::size_of::<CachePaddedAtomicU64>() == 64
);

/// Internal atomic counters used to build [`VectorscanStats`].
///
/// Each counter is cache-line padded ([`CachePaddedAtomicU64`]) to avoid
/// false sharing between concurrent worker threads.  Counters are updated
/// with `Relaxed` ordering during scans and snapshotted via [`snapshot`]
/// for reporting.  Individual counter reads are atomic but the snapshot as
/// a whole is not linearised -- callers should treat each field as
/// independently sampled.
///
/// [`snapshot`]: VectorscanCounters::snapshot
#[cfg(feature = "stats")]
#[derive(Default)]
pub(super) struct VectorscanCounters {
    pub(super) scans_attempted: CachePaddedAtomicU64,
    pub(super) scans_ok: CachePaddedAtomicU64,
    pub(super) scans_err: CachePaddedAtomicU64,
    pub(super) utf16_scans_attempted: CachePaddedAtomicU64,
    pub(super) utf16_scans_ok: CachePaddedAtomicU64,
    pub(super) utf16_scans_err: CachePaddedAtomicU64,
    pub(super) anchor_only: CachePaddedAtomicU64,
    pub(super) anchor_after_vs: CachePaddedAtomicU64,
    pub(super) anchor_skipped: CachePaddedAtomicU64,
    pub(super) stream_force_full: CachePaddedAtomicU64,
    pub(super) stream_window_cap_exceeded: CachePaddedAtomicU64,
    /// Stream decode spans where the callback sink overflowed
    /// (`vs_match_overflowed`), forcing a whole-buffer fallback.
    pub(super) stream_callback_overflow: CachePaddedAtomicU64,
}

#[cfg(feature = "stats")]
impl VectorscanCounters {
    /// Captures a best-effort snapshot of all counters with relaxed ordering.
    ///
    /// Individual counter values are atomic but not guaranteed to reflect the
    /// same point in time across counters.
    pub(super) fn snapshot(&self, db_built: bool, utf16_db_built: bool) -> VectorscanStats {
        VectorscanStats {
            db_built,
            utf16_db_built,
            scans_attempted: self.scans_attempted.load(Ordering::Relaxed),
            scans_ok: self.scans_ok.load(Ordering::Relaxed),
            scans_err: self.scans_err.load(Ordering::Relaxed),
            utf16_scans_attempted: self.utf16_scans_attempted.load(Ordering::Relaxed),
            utf16_scans_ok: self.utf16_scans_ok.load(Ordering::Relaxed),
            utf16_scans_err: self.utf16_scans_err.load(Ordering::Relaxed),
            anchor_only: self.anchor_only.load(Ordering::Relaxed),
            anchor_after_vs: self.anchor_after_vs.load(Ordering::Relaxed),
            anchor_skipped: self.anchor_skipped.load(Ordering::Relaxed),
            stream_force_full: self.stream_force_full.load(Ordering::Relaxed),
            stream_window_cap_exceeded: self.stream_window_cap_exceeded.load(Ordering::Relaxed),
            stream_callback_overflow: self.stream_callback_overflow.load(Ordering::Relaxed),
        }
    }
}

// --------------------------
// Engine
// --------------------------

/// Compiled scanning engine with derived anchors, rules, and transforms.
///
/// Build once, then reuse with per-scan scratch buffers to avoid allocations.
///
/// # Guarantees
/// - Immutable after construction; methods only borrow `&self`.
/// - `scan_chunk_*` methods reset the provided [`ScanScratch`] before use and
///   enforce per-scan tuning budgets.
///
/// # Invariants
/// - Input buffers must be chunked so `buf.len() <= u32::MAX`.
/// - [`ScanScratch`] is single-threaded; use one scratch per worker/thread.
///
/// # Performance
/// - Prefilters and gates bound work; regex validation runs only inside
///   candidate windows.
///
/// # Failure modes
/// - Construction panics if required prefilter DBs cannot be built.
pub struct Engine {
    /// Hot rule representation used in scan-loop validation.
    pub(super) rules_hot: Vec<RuleCompiled>,
    /// Cold per-rule metadata indexed in parallel with `rules_hot`.
    pub(super) rules_cold: Vec<RuleCold>,
    /// Ordered transform configurations; indices into this vector are used as
    /// `transform_idx` throughout work items, decode steps, and finding provenance.
    /// Frozen after construction.
    pub(super) transforms: Vec<TransformConfig>,
    /// Scan-time budgets and capacity knobs. Frozen after construction; all
    /// per-scan scratch sizing derives from these values.
    pub(crate) tuning: Tuning,

    /// Gate pools — indexed by `u32` IDs stored in [`RuleCompiled`], with
    /// [`NO_GATE`] (`u32::MAX`) as the absent sentinel.
    ///
    /// This indirection keeps `RuleCompiled` small (no inline allocations)
    /// while allowing gate data to be shared or deduplicated in the future.
    pub(super) confirm_all_gates: Vec<ConfirmAllCompiled>,
    pub(super) keyword_gates: Vec<KeywordsCompiled>,
    /// Value-level suppression patterns checked against extracted secret bytes.
    pub(super) value_suppressor_gates: Vec<PackedPatterns>,
    pub(super) entropy_gates: Vec<EntropyCompiled>,
    pub(super) two_phase_gates: Vec<TwoPhaseCompiled>,
    pub(super) local_context_gates: Vec<LocalContextSpec>,
    /// Offline structural validation specs (e.g. CRC-32, format checks).
    pub(super) offline_validation_gates: Vec<OfflineValidationSpec>,
    /// Character-class distribution gates (SIMD-accelerated pre-filter).
    pub(super) char_class_gates: Vec<CharClassCompiled>,
    /// Global context safelist evaluated at finding emission time.
    pub(super) safelist: SafelistFilter,

    /// Pre-computed `ln(i)/ln(2)` table for Shannon entropy calculation.
    ///
    /// Sized to `max(entropy_gate.max_len)` across all rules. Avoids
    /// per-window `f32::log2` calls in the entropy gate hot path.
    pub(super) entropy_log2: Vec<f32>,

    /// Unified Vectorscan prefilter DB for raw + anchor scanning.
    ///
    /// Combines literal anchor patterns with raw regex patterns (for rules
    /// with weak anchors) into a single multi-pattern DB. Always present
    /// after construction — build failures are fatal.
    pub(super) vs: Option<VsPrefilterDb>,
    /// Block-mode Vectorscan DB for UTF-16 anchor scanning.
    ///
    /// Only built when at least one rule has UTF-16 anchor variants.
    /// Absent when no UTF-16 anchors exist or compilation fails (non-fatal).
    pub(super) vs_utf16: Option<VsAnchorDb>,
    /// Stream-mode Vectorscan DB for UTF-16 anchor scanning in decoded streams.
    pub(super) vs_utf16_stream: Option<VsUtf16StreamDb>,
    /// Stream-mode Vectorscan DB for scanning decoded byte output.
    pub(super) vs_stream: Option<VsStreamDb>,
    /// Stream-mode Vectorscan DB for decoded-space anchor gating.
    ///
    /// Used with `Gate::AnchorsInDecoded` transforms to check whether
    /// decoded output contains any anchor before committing to full decode.
    pub(super) vs_gate: Option<VsGateDb>,
    /// Base64 pre-decode gate built from anchor patterns.
    ///
    /// Runs in *encoded space* and is deliberately conservative: if a decoded
    /// buffer would contain an anchor, at least one YARA-style base64
    /// permutation must appear in the encoded stream. False positives are
    /// allowed; false negatives are not. The decoded-space gate remains
    /// authoritative — this pre-gate only avoids wasteful decode work.
    pub(super) b64_gate: Option<Base64YaraGate>,

    /// Rules whose regex could not be given a sound prefilter gate.
    ///
    /// Contains `(rule_index, reason)` pairs in original rule order.
    /// These rules require full-buffer validation on every scan.
    unfilterable_rules: Vec<(usize, UnfilterableReason)>,
    #[cfg(feature = "stats")]
    /// Build-time summary of anchor selection decisions.
    anchor_plan_stats: AnchorPlanStats,
    #[cfg(feature = "stats")]
    /// Per-scan Vectorscan counters snapshotted via [`VectorscanCounters::snapshot`].
    pub(super) vs_stats: VectorscanCounters,

    /// True if any rule has UTF-16 anchor variants compiled.
    /// Controls whether UTF-16 scanning paths are active.
    pub(super) has_utf16_anchors: bool,
    /// Maximum window diameter (in bytes) across all rules and variants.
    ///
    /// For a rule with radius `R`, the diameter is `2R` (raw) or `4R` (UTF-16).
    /// Used to size validation buffers and compute required chunk overlap.
    pub(super) max_window_diameter_bytes: usize,
    /// Maximum match width reported by Vectorscan for any compiled pattern.
    ///
    /// Used to expand prefilter hit offsets into candidate windows. Falls
    /// back to the longest anchor pattern length when Vectorscan reports
    /// unbounded width.
    pub(super) max_prefilter_width: usize,
    /// Ring buffer size for stream-mode decoded scanning.
    ///
    /// Must accommodate the largest possible match span across all stream
    /// patterns, the longest anchor validation window, the longest encoded
    /// span, and the stream decode chunk size.
    pub(super) stream_ring_bytes: usize,
    /// True when at least one transform has a non-`Disabled` mode.
    ///
    /// When false, the zero-hit prefilter bypass can skip transform discovery
    /// entirely — no encoded secrets are possible if transforms are inactive.
    has_active_transforms: bool,
    /// 256-bit bitmap of all bytes appearing in any anchor pattern.
    ///
    /// Indexed as `set[byte >> 6] & (1 << (byte & 63))`. On the zero-hit
    /// path, URL-percent transforms only need to scan when at least one
    /// `%XX` triplet decodes to a byte in this set — otherwise no anchor
    /// could appear in decoded output.
    anchor_byte_set: [u64; 4],
    /// Pre-bucketed transform indices for the `ScanBuf` work-item path.
    ///
    /// Split by `(mode, id)` to avoid hot-loop branches:
    /// - `active_*`: all enabled transforms (used on zero-hit and no-findings paths)
    /// - `always_*`: only `TransformMode::Always` (used when findings already found)
    /// - `*_base64` / `*_non_base64`: separated so the caller can apply the
    ///   pre-decode gate only to Base64 spans
    scanbuf_transform_idxs_active_non_base64: Vec<usize>,
    scanbuf_transform_idxs_active_base64: Vec<usize>,
    scanbuf_transform_idxs_always_non_base64: Vec<usize>,
    scanbuf_transform_idxs_always_base64: Vec<usize>,
}

impl Engine {
    /// Compiles rule specs into an engine with Vectorscan prefilters and gates.
    ///
    /// Uses [`AnchorPolicy::PreferDerived`].
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated, or if
    /// the Vectorscan prefilter DB cannot be built.
    pub fn new(rules: Vec<RuleSpec>, transforms: Vec<TransformConfig>, tuning: Tuning) -> Self {
        Self::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::PreferDerived)
    }

    /// Compiles rule specs into an engine with a specific anchor policy.
    ///
    /// This is the primary construction entry point. Compilation proceeds in
    /// two passes (see the module-level "Build phase" docs):
    /// 1. Compile each [`RuleSpec`](crate::api::RuleSpec) into a
    ///    [`RuleCompiled`] with gates pooled into Engine-owned vectors.
    /// 2. Derive or select anchor patterns, build deduped pattern maps, and
    ///    construct Vectorscan prefilter DBs (raw, UTF-16, stream, gate) plus
    ///    the Base64 YARA pre-gate.
    ///
    /// # Policy behaviour
    /// - `AnchorPolicy::ManualOnly` uses only explicit anchors provided by rules.
    /// - `AnchorPolicy::DerivedOnly` ignores manual anchors and relies on derived
    ///   anchors/residue gates; rules that cannot be gated are reported via
    ///   [`Engine::unfilterable_rules`].
    /// - `AnchorPolicy::PreferDerived` derives anchors when possible and falls
    ///   back to manual anchors when derivation is unavailable.
    ///
    /// # Outputs
    /// Populates `residue_rules` and `unfilterable_rules` based on regex analysis
    /// and the selected policy.
    ///
    /// # Panics
    /// Panics if any rule, transform, or tuning invariants are violated, or if
    /// the Vectorscan prefilter DB cannot be built.
    pub fn new_with_anchor_policy(
        rules: Vec<RuleSpec>,
        transforms: Vec<TransformConfig>,
        tuning: Tuning,
        policy: AnchorPolicy,
    ) -> Self {
        tuning.assert_valid();
        assert!(
            tuning.max_transform_depth.saturating_add(1) <= MAX_DECODE_STEPS,
            "max_transform_depth exceeds MAX_DECODE_STEPS"
        );
        assert!(
            rules.len() <= (1usize << 24),
            "rule count {} exceeds 24-bit dedupe key budget",
            rules.len()
        );
        for r in &rules {
            r.assert_valid();
            if policy == AnchorPolicy::ManualOnly {
                assert!(
                    !r.anchors.is_empty(),
                    "rule {:?}: anchors must not be empty when using ManualOnly policy",
                    r.name,
                );
            }
        }
        for tc in &transforms {
            tc.assert_valid();
        }

        // Compile rules and pool gate objects into Engine-owned vectors.
        let mut confirm_all_gates: Vec<ConfirmAllCompiled> = Vec::new();
        let mut keyword_gates: Vec<KeywordsCompiled> = Vec::new();
        let mut value_suppressor_gates: Vec<PackedPatterns> = Vec::new();
        let mut entropy_gates: Vec<EntropyCompiled> = Vec::new();
        let mut two_phase_gates: Vec<TwoPhaseCompiled> = Vec::new();
        let mut local_context_gates: Vec<LocalContextSpec> = Vec::new();
        let mut offline_validation_gates: Vec<OfflineValidationSpec> = Vec::new();
        let mut char_class_gates: Vec<CharClassCompiled> = Vec::new();

        let mut rules_compiled: Vec<RuleCompiled> = Vec::with_capacity(rules.len());
        let mut rules_cold: Vec<RuleCold> = Vec::with_capacity(rules.len());
        for spec in rules.iter() {
            let (mut rule, gates) = compile_rule(spec);
            if let Some(tp) = gates.two_phase {
                assert!(two_phase_gates.len() < NO_GATE as usize);
                rule.two_phase = two_phase_gates.len() as u32;
                two_phase_gates.push(tp);
            }
            if let Some(kw) = gates.keywords {
                assert!(keyword_gates.len() < NO_GATE as usize);
                rule.keywords = keyword_gates.len() as u32;
                keyword_gates.push(kw);
            }
            if let Some(suppressors) = gates.value_suppressors {
                assert!(value_suppressor_gates.len() < NO_GATE as usize);
                rule.value_suppressors = value_suppressor_gates.len() as u32;
                value_suppressor_gates.push(suppressors);
            }
            if let Some(ent) = gates.entropy {
                assert!(entropy_gates.len() < NO_GATE as usize);
                rule.entropy = entropy_gates.len() as u32;
                entropy_gates.push(ent);
            }
            if let Some(ctx) = gates.local_context {
                assert!(local_context_gates.len() < NO_GATE as usize);
                rule.local_context = local_context_gates.len() as u32;
                local_context_gates.push(ctx);
            }
            if let Some(ov) = gates.offline_validation {
                assert!(offline_validation_gates.len() < NO_GATE as usize);
                rule.offline_validation = offline_validation_gates.len() as u32;
                offline_validation_gates.push(ov);
            }
            if let Some(cc) = gates.char_class {
                assert!(char_class_gates.len() < NO_GATE as usize);
                rule.char_class = char_class_gates.len() as u32;
                char_class_gates.push(cc);
            }
            let min_confidence = derive_min_confidence(spec);
            rules_compiled.push(rule);
            rules_cold.push(RuleCold {
                name: spec.name,
                min_confidence,
            });
        }
        debug_assert_eq!(rules_compiled.len(), rules_cold.len());

        let max_entropy_len = entropy_gates.iter().map(|e| e.max_len).max().unwrap_or(0);
        let entropy_log2 = build_log2_table(max_entropy_len);

        let raw_seed_radius_bytes = rules
            .iter()
            .map(|r| {
                let seed = if let Some(tp) = &r.two_phase {
                    tp.seed_radius
                } else {
                    r.radius
                };
                if seed > u32::MAX as usize {
                    u32::MAX
                } else {
                    seed as u32
                }
            })
            .collect::<Vec<_>>();

        let utf16_seed_radius_bytes = rules
            .iter()
            .map(|r| {
                let seed = if let Some(tp) = &r.two_phase {
                    tp.seed_radius
                } else {
                    r.radius
                };
                let bytes = seed.saturating_mul(2);
                if bytes > u32::MAX as usize {
                    u32::MAX
                } else {
                    bytes as u32
                }
            })
            .collect::<Vec<_>>();

        // Build deduped anchor pattern maps.
        //
        // `pat_map_all` holds raw + UTF-16 patterns (used for the prefilter DB
        // and Base64 YARA gate). `pat_map_utf16` holds only UTF-16 patterns
        // (used for the standalone UTF-16 anchor DB). Each map entry maps a
        // byte pattern to the list of (rule, variant) targets it covers.
        let mut pat_map_all: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(3).max(16));
        let mut pat_map_utf16: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(rules.len().saturating_mul(2).max(16));
        let mut unfilterable_rules: Vec<(usize, UnfilterableReason)> =
            Vec::with_capacity(rules.len());
        #[cfg(feature = "stats")]
        let mut anchor_plan_stats = AnchorPlanStats::default();
        let derive_cfg = AnchorDeriveConfig {
            utf8: false,
            ..AnchorDeriveConfig::default()
        };
        let allow_manual = matches!(
            policy,
            AnchorPolicy::ManualOnly | AnchorPolicy::PreferDerived
        );
        let allow_derive = matches!(
            policy,
            AnchorPolicy::DerivedOnly | AnchorPolicy::PreferDerived
        );

        for (rid, r) in rules.iter().enumerate() {
            assert!(
                rid <= DEDUP_RULE_ID_MAX as usize,
                "rule index exceeds dedup key capacity ({})",
                DEDUP_RULE_ID_MAX
            );
            let rid_u32 = rid as u32;
            let mut manual_used = false;
            let mut add_manual =
                |pat_map_all: &mut AHashMap<Vec<u8>, Vec<Target>>,
                 pat_map_utf16: &mut AHashMap<Vec<u8>, Vec<Target>>| {
                    if !allow_manual {
                        return;
                    }
                    if manual_used || r.anchors.is_empty() {
                        return;
                    }
                    manual_used = true;
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.manual_rules =
                            anchor_plan_stats.manual_rules.saturating_add(1);
                    }
                    for &a in r.anchors {
                        add_pat_raw(pat_map_all, a, Target::new(rid_u32, Variant::Raw));
                        add_pat_owned(
                            pat_map_all,
                            utf16le_bytes(a),
                            Target::new(rid_u32, Variant::Utf16Le),
                        );
                        add_pat_owned(
                            pat_map_all,
                            utf16be_bytes(a),
                            Target::new(rid_u32, Variant::Utf16Be),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16le_bytes(a),
                            Target::new(rid_u32, Variant::Utf16Le),
                        );
                        add_pat_owned(
                            pat_map_utf16,
                            utf16be_bytes(a),
                            Target::new(rid_u32, Variant::Utf16Be),
                        );
                    }
                };

            if !allow_derive {
                add_manual(&mut pat_map_all, &mut pat_map_utf16);
                continue;
            }

            let plan = match compile_trigger_plan(r.re.as_str(), &derive_cfg) {
                Ok(plan) => plan,
                Err(_) => {
                    unfilterable_rules.push((rid, UnfilterableReason::UnsupportedRegexFeatures));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                    continue;
                }
            };

            match plan {
                TriggerPlan::Anchored {
                    anchors,
                    mut confirm_all,
                } => {
                    if let Some(needle) = r.must_contain {
                        confirm_all.retain(|c| c.as_slice() != needle);
                    }
                    if let Some(compiled) = compile_confirm_all(confirm_all) {
                        assert!(confirm_all_gates.len() < NO_GATE as usize);
                        rules_compiled[rid].confirm_all = confirm_all_gates.len() as u32;
                        confirm_all_gates.push(compiled);
                    }
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.derived_rules =
                            anchor_plan_stats.derived_rules.saturating_add(1);
                    }
                    for anchor in anchors {
                        add_pat_raw(
                            &mut pat_map_all,
                            &anchor,
                            Target::new(rid_u32, Variant::Raw),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le),
                        );
                        add_pat_owned(
                            &mut pat_map_all,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16le_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Le),
                        );
                        add_pat_owned(
                            &mut pat_map_utf16,
                            utf16be_bytes(&anchor),
                            Target::new(rid_u32, Variant::Utf16Be),
                        );
                    }
                }
                TriggerPlan::Residue { gate: _ } => {
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.residue_rules =
                            anchor_plan_stats.residue_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                }
                TriggerPlan::Unfilterable { reason } => {
                    unfilterable_rules.push((rid, reason));
                    #[cfg(feature = "stats")]
                    {
                        anchor_plan_stats.unfilterable_rules =
                            anchor_plan_stats.unfilterable_rules.saturating_add(1);
                    }
                    add_manual(&mut pat_map_all, &mut pat_map_utf16);
                }
            }
        }

        let (anchor_patterns_all, pat_targets_all, pat_offsets_all) = map_to_patterns(pat_map_all);
        let (anchor_patterns_utf16, pat_targets_utf16, pat_offsets_utf16) =
            map_to_patterns(pat_map_utf16);
        let has_utf16_anchors = !anchor_patterns_utf16.is_empty();
        // Retained for diagnostic / debugging use; not referenced in production paths.
        let _has_any_anchors = !anchor_patterns_all.is_empty();
        let max_anchor_pat_len = anchor_patterns_all
            .iter()
            .map(|p| p.len())
            .max()
            .unwrap_or(0);

        // Build the base64 pre-gate from the same anchor universe as the decoded gate:
        // raw anchors plus UTF-16 variants. This keeps the pre-gate *sound* with
        // respect to anchor presence in decoded bytes, while allowing false positives.
        //
        // Padding/whitespace policy mirrors our span detection/decoder behavior:
        // - Stop at '=' (treat padding as end-of-span)
        // - Ignore RFC4648 whitespace (space is only allowed if the span finder allows it)
        let b64_gate = if anchor_patterns_all.is_empty() {
            None
        } else {
            Some(Base64YaraGate::build(
                anchor_patterns_all.iter().map(|p| p.as_slice()),
                Base64YaraGateConfig {
                    min_pattern_len: 0,
                    padding_policy: PaddingPolicy::StopAndHalt,
                    whitespace_policy: WhitespacePolicy::Rfc4648,
                },
            ))
        };

        // Warm regex caches at startup to avoid lazy allocations later.
        //
        // `regex::bytes::Regex` lazily builds its internal DFA cache on first
        // use. Calling `find_iter(..).next()` forces that lazy allocation here,
        // during engine construction, so that the first real scan does not pay
        // an allocation penalty on the hot path. A 1-byte buffer suffices
        // because the DFA cache is created regardless of whether a match occurs.
        let warm = [0u8; 1];
        for rule in &rules_compiled {
            let mut it = rule.re.find_iter(&warm);
            let _ = it.next();
        }

        let mut max_window_diameter_bytes = 0usize;
        for r in &rules {
            let base = if let Some(tp) = &r.two_phase {
                tp.full_radius
            } else {
                r.radius
            };
            // Account for raw (scale = 1) and UTF-16 (scale = 2) windows in bytes.
            for scale in [1usize, 2usize] {
                let diameter = base.saturating_mul(2).saturating_mul(scale);
                max_window_diameter_bytes = max_window_diameter_bytes.max(diameter);
            }
        }

        let max_decoded_cap = transforms
            .iter()
            .map(|tc| tc.max_decoded_bytes)
            .max()
            .unwrap_or(0);
        // Env: SCANNER_INIT_DIAG — when set, prints Vectorscan DB build timings
        // to stderr during engine construction (diagnostic / integration-test use).
        let init_diag = std::env::var_os("SCANNER_INIT_DIAG").is_some();
        let max_encoded_len = transforms
            .iter()
            .map(|tc| tc.max_encoded_len)
            .max()
            .unwrap_or(0);

        // Decide per-rule whether to include the raw regex in the Vectorscan
        // prefilter DB. The tradeoff:
        //
        //   Include regex  → Vectorscan can match directly, but DB is larger
        //                     and compilation/scan time scales with pattern count.
        //   Omit regex     → rely on literal anchor patterns alone, which is
        //                     cheaper but only works if anchors are strong enough
        //                     to avoid false negatives.
        //
        // A rule can safely omit its raw regex from the prefilter when ALL of:
        //   - It has at least one anchor pattern (otherwise nothing triggers).
        //   - Every anchor is >= 5 bytes. Below this, Vectorscan's Aho-Corasick
        //     automaton produces high false-positive rates, and short byte-exact
        //     anchors risk case-sensitivity mismatches with the regex.
        //   - The regex is NOT case-insensitive. Byte-exact anchors cannot
        //     match the alternate casings that `(?i)` would accept, so relying
        //     on anchors alone would cause false negatives.
        //
        // Rules that fail any check keep their regex in the prefilter DB.
        // The 5-byte threshold is empirically chosen; it may need revisiting if
        // rule sets change significantly.
        let use_raw_prefilter: Vec<bool> = rules
            .iter()
            .map(|r| {
                // Rule needs raw prefilter if:
                // No anchors at all
                if r.anchors.is_empty() {
                    return true;
                }
                // Regex is case-insensitive (anchors are byte-exact, won't match)
                let re_str = r.re.as_str();
                if re_str.starts_with("(?i)") || re_str.contains("(?i:") {
                    return true;
                }
                // Any anchor is shorter than 5 bytes (weak anchor)
                !r.anchors.iter().all(|a| a.len() >= 5)
            })
            .collect();

        // Build prefilter anchor patterns: include UTF-16 patterns (as before) plus
        // raw patterns ONLY for rules that skip raw regex prefiltering.
        // This ensures rules with strong anchors can still be found without their
        // regex in the prefilter DB, while not adding redundant raw anchors for
        // rules that already have their regex compiled.
        let mut pat_map_prefilter: AHashMap<Vec<u8>, Vec<Target>> =
            AHashMap::with_capacity(pat_targets_utf16.len().saturating_add(rules.len()));

        // Add all UTF-16 patterns (same as before).
        for (pat, targets) in anchor_patterns_utf16.iter().zip(
            pat_offsets_utf16
                .windows(2)
                .map(|w| &pat_targets_utf16[w[0] as usize..w[1] as usize]),
        ) {
            for &t in targets {
                add_pat_owned(&mut pat_map_prefilter, pat.clone(), t);
            }
        }

        // Add raw patterns only for rules that skip raw regex prefiltering.
        for (pat, targets) in anchor_patterns_all.iter().zip(
            pat_offsets_all
                .windows(2)
                .map(|w| &pat_targets_all[w[0] as usize..w[1] as usize]),
        ) {
            for &t in targets {
                let rid = t.rule_id();
                let var = t.variant();
                // Only add raw variant patterns for rules that skip raw regex.
                if var == Variant::Raw && !use_raw_prefilter[rid] {
                    add_pat_owned(&mut pat_map_prefilter, pat.clone(), t);
                }
            }
        }

        let (anchor_patterns_prefilter, pat_targets_prefilter, pat_offsets_prefilter) =
            map_to_patterns(pat_map_prefilter);
        let has_prefilter_anchors = !anchor_patterns_prefilter.is_empty();

        // Required: if the DB can't be built (e.g. regex incompatibility),
        // fail fast rather than falling back to full-buffer scans.
        let anchor_input = if has_prefilter_anchors {
            Some(AnchorInput {
                patterns: &anchor_patterns_prefilter,
                pat_targets: &pat_targets_prefilter,
                pat_offsets: &pat_offsets_prefilter,
                seed_radius_raw: &raw_seed_radius_bytes,
                seed_radius_utf16: &utf16_seed_radius_bytes,
            })
        } else {
            None
        };
        let t_vs = init_diag.then(Instant::now);
        let vs = Some(
            VsPrefilterDb::try_new(&rules, anchor_input, Some(&use_raw_prefilter))
                .expect("vectorscan prefilter db build failed (fallback disabled)"),
        );
        let vs_ms = t_vs.map(|t| t.elapsed().as_millis());
        let max_regex_width = vs
            .as_ref()
            .and_then(|db| db.max_match_width_bounded())
            .map(|w| w as usize);
        // Prefer Vectorscan's bounded width; fall back to longest anchor length.
        let max_prefilter_width = max_regex_width.unwrap_or(max_anchor_pat_len);
        let t_vs_stream = init_diag.then(Instant::now);
        let vs_stream = VsStreamDb::try_new_stream(&rules, max_decoded_cap).ok();
        let vs_stream_ms = t_vs_stream.map(|t| t.elapsed().as_millis());
        let needs_decoded_gate = transforms
            .iter()
            .any(|tc| tc.gate == Gate::AnchorsInDecoded);
        let t_vs_gate = init_diag.then(Instant::now);
        let vs_gate =
            if needs_decoded_gate && !anchor_patterns_all.is_empty() && vs_stream.is_some() {
                VsGateDb::try_new_gate(&anchor_patterns_all).ok()
            } else {
                None
            };
        let vs_gate_ms = t_vs_gate.map(|t| t.elapsed().as_millis());
        let max_stream_window_bytes = vs_stream
            .as_ref()
            .and_then(|db| {
                db.meta()
                    .iter()
                    .map(|m| {
                        let maxw = m.max_width as usize;
                        let rad = m.radius as usize;
                        maxw.saturating_add(rad.saturating_mul(2))
                    })
                    .max()
            })
            .unwrap_or(0);
        let max_anchor_window_bytes = max_window_diameter_bytes.saturating_add(max_anchor_pat_len);
        let stream_ring_bytes = max_stream_window_bytes
            .max(max_encoded_len)
            .max(max_anchor_window_bytes)
            .max(STREAM_DECODE_CHUNK_BYTES)
            .max(1);
        let t_vs_utf16 = init_diag.then(Instant::now);
        let vs_utf16 = if !has_utf16_anchors {
            None
        } else {
            match VsAnchorDb::try_new_utf16(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &raw_seed_radius_bytes,
                &utf16_seed_radius_bytes,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    // Env: SCANNER_VS_UTF16_DEBUG — prints UTF-16 Vectorscan
                    // build errors to stderr (non-fatal; block-mode fallback).
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 db build failed: {err}");
                    }
                    None
                }
            }
        };
        let vs_utf16_ms = t_vs_utf16.map(|t| t.elapsed().as_millis());
        let t_vs_utf16_stream = init_diag.then(Instant::now);
        let vs_utf16_stream = if !has_utf16_anchors {
            None
        } else {
            match VsUtf16StreamDb::try_new_utf16_stream(
                &anchor_patterns_utf16,
                &pat_targets_utf16,
                &pat_offsets_utf16,
                &raw_seed_radius_bytes,
                &utf16_seed_radius_bytes,
            ) {
                Ok(db) => Some(db),
                Err(err) => {
                    if std::env::var_os("SCANNER_VS_UTF16_DEBUG").is_some() {
                        eprintln!("vectorscan utf16 stream db build failed: {err}");
                    }
                    None
                }
            }
        };
        let vs_utf16_stream_ms = t_vs_utf16_stream.map(|t| t.elapsed().as_millis());
        if init_diag {
            eprintln!(
                "init_diag: vs_ms={} vs_stream_ms={} vs_gate_ms={} vs_utf16_ms={} vs_utf16_stream_ms={}",
                vs_ms.unwrap_or(0),
                vs_stream_ms.unwrap_or(0),
                vs_gate_ms.unwrap_or(0),
                vs_utf16_ms.unwrap_or(0),
                vs_utf16_stream_ms.unwrap_or(0),
            );
        }
        // Pre-bucket transform indices by (mode, id) so the scan-loop work-item
        // path avoids per-transform branches. See `scanbuf_transform_buckets`.
        let mut scanbuf_transform_idxs_active_non_base64 =
            Vec::with_capacity(transforms.len().min(8));
        let mut scanbuf_transform_idxs_active_base64 = Vec::with_capacity(transforms.len().min(8));
        let mut scanbuf_transform_idxs_always_non_base64 =
            Vec::with_capacity(transforms.len().min(8));
        let mut scanbuf_transform_idxs_always_base64 = Vec::with_capacity(transforms.len().min(8));
        for (idx, tc) in transforms.iter().enumerate() {
            if tc.mode == TransformMode::Disabled {
                continue;
            }
            let is_base64 = tc.id == TransformId::Base64;
            // `active` = all enabled transforms (superset); used on the zero-hit
            // bypass path and on the hit path when no findings have been found yet.
            if is_base64 {
                scanbuf_transform_idxs_active_base64.push(idx);
            } else {
                scanbuf_transform_idxs_active_non_base64.push(idx);
            }
            // `always` = only Always-mode transforms; used on the hit path when
            // findings have already been found (IfNoFindingsInThisBuffer transforms are skipped).
            if tc.mode == TransformMode::Always {
                if is_base64 {
                    scanbuf_transform_idxs_always_base64.push(idx);
                } else {
                    scanbuf_transform_idxs_always_non_base64.push(idx);
                }
            }
        }
        let has_active_transforms = !scanbuf_transform_idxs_active_non_base64.is_empty()
            || !scanbuf_transform_idxs_active_base64.is_empty();

        // Build anchor byte set for URL-percent gating.
        //
        // A decoded `%XX` byte can only contribute to an anchor match if that
        // byte value appears somewhere in at least one anchor pattern. This is a
        // superset check (no false negatives, possible false positives for
        // multi-byte patterns).
        //
        // Encoding: a 256-bit bitmap split across four `u64` words. Byte `b`
        // maps to `set[b >> 6] & (1 << (b & 63))`. The same encoding is used
        // by `url_percent_gate_check` at scan time.
        let mut anchor_byte_set = [0u64; 4];
        for pat in &anchor_patterns_all {
            for &b in pat.as_slice() {
                anchor_byte_set[(b >> 6) as usize] |= 1u64 << (b & 63);
            }
        }

        Self {
            rules_hot: rules_compiled,
            rules_cold,
            transforms,
            tuning,
            confirm_all_gates,
            keyword_gates,
            value_suppressor_gates,
            entropy_gates,
            two_phase_gates,
            local_context_gates,
            offline_validation_gates,
            char_class_gates,
            safelist: SafelistFilter::new(),
            entropy_log2,
            vs,
            vs_utf16,
            vs_utf16_stream,
            vs_stream,
            vs_gate,
            b64_gate,
            unfilterable_rules,
            #[cfg(feature = "stats")]
            anchor_plan_stats,
            #[cfg(feature = "stats")]
            vs_stats: VectorscanCounters::default(),
            has_utf16_anchors,
            max_window_diameter_bytes,
            max_prefilter_width,
            stream_ring_bytes,
            has_active_transforms,
            anchor_byte_set,
            scanbuf_transform_idxs_active_non_base64,
            scanbuf_transform_idxs_active_base64,
            scanbuf_transform_idxs_always_non_base64,
            scanbuf_transform_idxs_always_base64,
        }
    }

    /// Returns a summary of how anchors were chosen during compilation.
    #[cfg(feature = "stats")]
    pub fn anchor_plan_stats(&self) -> AnchorPlanStats {
        self.anchor_plan_stats
    }

    /// Returns Vectorscan usage counters (feature: `stats`).
    #[cfg(feature = "stats")]
    pub fn vectorscan_stats(&self) -> VectorscanStats {
        self.vs_stats
            .snapshot(self.vs.is_some(), self.vs_utf16.is_some())
    }

    /// Rules whose regex patterns could not be given a sound prefilter gate.
    ///
    /// The slice contains `(rule_index, reason)` pairs in original rule order.
    pub fn unfilterable_rules(&self) -> &[(usize, UnfilterableReason)] {
        &self.unfilterable_rules
    }

    // ── Gate pool accessors ────────────────────────────────────────────
    //
    // Centralised helpers that resolve `u32` gate indices (with `NO_GATE`
    // sentinel) into pool references using direct indexing; out-of-bounds
    // indices panic, which signals inconsistent compiled rule data.

    /// Resolves the confirm-all (multi-literal AND) gate for a rule.
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn confirm_all_gate(&self, idx: u32) -> Option<&ConfirmAllCompiled> {
        if idx == NO_GATE {
            None
        } else {
            Some(&self.confirm_all_gates[idx as usize])
        }
    }

    /// Resolves the keyword-any (literal OR) gate for a rule.
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn keyword_gate(&self, idx: u32) -> Option<&KeywordsCompiled> {
        if idx == NO_GATE {
            None
        } else {
            Some(&self.keyword_gates[idx as usize])
        }
    }

    /// Resolves the value-suppressor gate (packed literal patterns checked
    /// against extracted secret bytes to suppress known false positives).
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn value_suppressor_gate(&self, idx: u32) -> Option<&PackedPatterns> {
        if idx == NO_GATE {
            None
        } else {
            Some(&self.value_suppressor_gates[idx as usize])
        }
    }

    /// Resolves the entropy-family gate for a rule (Shannon, optional min-entropy,
    /// optional digit-penalty).
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn entropy_gate(&self, idx: u32) -> Option<EntropyCompiled> {
        if idx == NO_GATE {
            None
        } else {
            Some(self.entropy_gates[idx as usize])
        }
    }

    /// Resolves the local-context gate (surrounding-line pattern match).
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn local_context_gate(&self, idx: u32) -> Option<LocalContextSpec> {
        if idx == NO_GATE {
            None
        } else {
            Some(self.local_context_gates[idx as usize])
        }
    }

    /// Resolves the character-class distribution gate for a rule.
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn char_class_gate(&self, idx: u32) -> Option<CharClassCompiled> {
        if idx == NO_GATE {
            None
        } else {
            Some(self.char_class_gates[idx as usize])
        }
    }

    /// Returns whether a root finding should be suppressed by the global safelist.
    ///
    /// Only root-layer findings (`step_id == STEP_ROOT`) are checked; decoded
    /// findings return `false` immediately because their context may not be the
    /// original input bytes.
    ///
    /// `root_hint_start`/`root_hint_end` are absolute file offsets in the same
    /// coordinate space as `context_base_offset`. The hint range is clipped to
    /// `context_buf` bounds before the safelist is evaluated.
    ///
    /// # Caching
    ///
    /// `last_decision` is a single-entry `(start, end, suppressed)` cache that
    /// avoids redundant safelist evaluations when consecutive regex captures
    /// produce the same root-hint window. The cache is scoped to a single
    /// `for_each_capture_match` invocation; the caller is responsible for
    /// initialising it to `None` at the start of each match loop.
    #[inline]
    pub(super) fn suppress_root_finding_by_safelist(
        &self,
        context_buf: &[u8],
        context_base_offset: u64,
        step_id: StepId,
        root_hint_start: u64,
        root_hint_end: u64,
        last_decision: &mut Option<(u64, u64, bool)>,
    ) -> bool {
        debug_assert!(
            root_hint_start <= root_hint_end,
            "root_hint range is backwards: {root_hint_start}..{root_hint_end}",
        );

        if step_id != STEP_ROOT {
            return false;
        }

        let context_len_u64 = context_buf.len() as u64;
        let start = root_hint_start
            .saturating_sub(context_base_offset)
            .min(context_len_u64);
        let end = root_hint_end
            .saturating_sub(context_base_offset)
            .min(context_len_u64);

        if start >= end {
            return false;
        }

        if let Some((last_start, last_end, last_suppressed)) = last_decision.as_ref().copied() {
            if last_start == start && last_end == end {
                return last_suppressed;
            }
        }

        let suppressed = self
            .safelist
            .matcher()
            .is_match(&context_buf[start as usize..end as usize]);
        *last_decision = Some((start, end, suppressed));
        suppressed
    }

    /// Returns the `OfflineValidationSpec` for a gate pool index, or `None` if
    /// the index is `NO_GATE`.
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn offline_validation_gate(&self, idx: u32) -> Option<OfflineValidationSpec> {
        if idx == NO_GATE {
            None
        } else {
            Some(self.offline_validation_gates[idx as usize])
        }
    }

    /// Resolves the two-phase confirmation gate for a rule.
    ///
    /// Two-phase gates narrow the prefilter window in two steps: a cheap seed
    /// check at a small radius, then a full-radius regex validation only for
    /// confirmed seeds. This reduces expensive regex work on noisy prefilter
    /// hits.
    ///
    /// # Panics
    /// Panics on out-of-bounds index, indicating corrupted compiled rule data.
    #[inline(always)]
    pub(super) fn two_phase_gate(&self, idx: u32) -> Option<&TwoPhaseCompiled> {
        if idx == NO_GATE {
            None
        } else {
            Some(&self.two_phase_gates[idx as usize])
        }
    }

    /// Select which transform index buckets to iterate for a `ScanBuf` work item.
    ///
    /// The split implements a finding-aware optimization:
    /// - **No findings yet** (`found_any_in_this_buf = false`): run *all* enabled
    ///   transforms (`Active` + `Always` modes). Encoded secrets invisible to
    ///   the raw prefilter may exist in transform output.
    /// - **Findings found** (`found_any_in_this_buf = true`): run only
    ///   `TransformMode::Always` transforms. `IfNoFindingsInThisBuffer`
    ///   transforms are skipped because the raw prefilter already found
    ///   something — further transform work is unlikely to add value.
    ///
    /// Returns `(non_base64_indices, base64_indices)` where each slice contains
    /// indices into `self.transforms`. The two-bucket split lets the caller
    /// apply the encoded-space pre-gate (`b64_gate`) only to Base64 spans
    /// without branching per-transform in the span loop.
    ///
    /// The returned slices are disjoint and together cover exactly the
    /// transforms that should run for the given finding state.
    #[inline(always)]
    fn scanbuf_transform_buckets(&self, found_any_in_this_buf: bool) -> (&[usize], &[usize]) {
        if found_any_in_this_buf {
            (
                &self.scanbuf_transform_idxs_always_non_base64,
                &self.scanbuf_transform_idxs_always_base64,
            )
        } else {
            (
                &self.scanbuf_transform_idxs_active_non_base64,
                &self.scanbuf_transform_idxs_active_base64,
            )
        }
    }

    /// Single-buffer scan helper (allocation-free after startup).
    ///
    /// Findings are stored in `scratch` and returned as a shared slice. The
    /// returned slice is valid until `scratch` is reused for another scan.
    ///
    /// Equivalent to `scan_chunk_into` with `file_id = 0` and `base_offset = 0`.
    pub fn scan_chunk<'a>(&self, hay: &[u8], scratch: &'a mut ScanScratch) -> &'a [FindingRec] {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        scratch.findings()
    }

    /// Single-buffer scan helper that materializes findings into `out`.
    ///
    /// This clears `out` and appends all findings. `out` must have enough
    /// capacity to hold all findings; otherwise this will panic. Use
    /// `Vec::with_capacity(self.tuning.max_findings_per_chunk)` to pre-size.
    ///
    /// # Panics
    /// Panics if `out.capacity()` is smaller than the number of findings.
    pub fn scan_chunk_materialized(
        &self,
        hay: &[u8],
        scratch: &mut ScanScratch,
        out: &mut Vec<Finding>,
    ) {
        self.scan_chunk_into(hay, FileId(0), 0, scratch);
        let expected = scratch.findings().len();
        assert!(out.capacity() >= expected, "output capacity too small");
        out.clear();
        self.drain_findings_materialized(scratch, out);
    }

    /// Scans a buffer and appends findings into the provided scratch state.
    ///
    /// This is the top-level entry point for scanning a single chunk. It
    /// orchestrates the full pipeline: prefilter → regex validation →
    /// transform discovery → decode → recursive scan via a work queue.
    ///
    /// The scratch is reset before use and reuses its buffers to avoid per-call
    /// allocations. Findings are stored as compact [`FindingRec`] entries.
    /// When the per-chunk finding cap is exceeded, extra findings are dropped
    /// and counted in [`ScanScratch::dropped_findings`].
    ///
    /// `base_offset` is the absolute byte offset of `root_buf` within the file
    /// or stream and is used to compute `root_hint_*` fields for findings.
    ///
    /// # Preconditions
    /// - `root_buf.len() <= u32::MAX` (spans and offsets are `u32`-addressed).
    /// - `scratch` is exclusively owned for the duration of the call.
    ///
    /// # High-level flow
    /// Run Vectorscan prefilter on the root buffer.
    /// On zero hits: check if transform discovery is needed; if not, return
    /// immediately. This is the common fast path.
    /// On hits: reset per-scan state, enqueue root `ScanBuf`.
    /// Process the work queue in FIFO order (BFS over decode layers):
    ///   - `ScanBuf`: validate regexes in windows, discover transform spans,
    ///     enqueue `DecodeSpan` items.
    ///   - `DecodeSpan`: decode the span, enqueue a `ScanBuf` for output.
    ///
    /// Budget gates (decode bytes, work items, depth) are enforced per iteration
    /// so no single input can force unbounded work.
    ///
    /// # Effects
    /// - Resets `scratch`, overwriting any pending findings.
    /// - Enqueues decode work items and updates per-scan counters.
    ///
    /// # Aliasing model
    /// The work queue loop resolves buffer references to raw pointers to avoid
    /// holding borrows on `scratch.slab` while passing `scratch` mutably into
    /// `scan_rules_on_buffer`. See the inline `// SAFETY` comments for the full
    /// aliasing argument.
    pub fn scan_chunk_into(
        &self,
        root_buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &mut ScanScratch,
    ) {
        debug_assert!(
            root_buf.len() <= u32::MAX as usize,
            "scan_chunk_into: buffer length {} exceeds u32::MAX; \
             FindingRec span offsets would truncate",
            root_buf.len(),
        );

        // ── Step A: ensure VS scratch capacity (first call only) ────────
        scratch.ensure_capacity(self);

        // ── Step B: clear only prefilter state ──────────────────────────
        scratch
            .hit_acc_pool
            .reset_touched(scratch.touched_pairs.as_slice());
        scratch.touched_pairs.clear();

        // ── Step C: overlap tracking (always needed, cheap) ─────────────
        scratch.update_chunk_overlap(file_id, base_offset, root_buf.len());

        // ── Step D: run Vectorscan prefilter directly on root buffer ────
        let vs = self
            .vs
            .as_ref()
            .expect("vectorscan prefilter database unavailable (fallback disabled)");
        let mut vs_scratch_owned = scratch
            .vs_scratch
            .take()
            .expect("vectorscan scratch missing");
        #[cfg(feature = "stats")]
        self.vs_stats
            .scans_attempted
            .fetch_add(1, Ordering::Relaxed);
        let (result, _vs_nanos) =
            perf::time(|| vs.scan_raw(root_buf, scratch, &mut vs_scratch_owned));
        perf::record_scan_vs_prefilter(_vs_nanos);
        scratch.vs_scratch = Some(vs_scratch_owned);
        let saw_utf16 = match result {
            Ok(saw) => {
                #[cfg(feature = "stats")]
                self.vs_stats.scans_ok.fetch_add(1, Ordering::Relaxed);
                saw
            }
            Err(err) => {
                #[cfg(feature = "stats")]
                self.vs_stats.scans_err.fetch_add(1, Ordering::Relaxed);
                panic!("vectorscan scan failed with fallback disabled: {err}");
            }
        };

        // ── Step E: zero prefilter hits ───────────────────────────────────
        //
        // No Vectorscan pattern matched the root buffer. This means no regex
        // validation is needed. However, transform discovery (Base64, URL-percent)
        // MUST still run — encoded content may decode to secrets whose anchors
        // are invisible in the raw bytes.
        //
        // Fast-path bypass is only safe when:
        //   (a) no transforms are active, OR
        //   (b) every active transform's buffer-level gate rejects this buffer
        //       (meaning no anchor could appear in decoded form).
        if scratch.touched_pairs.is_empty() {
            perf::record_scan_zero_hit_chunk();

            let needs_transform_scan = self.has_active_transforms
                && (self
                    .scanbuf_transform_idxs_active_non_base64
                    .iter()
                    .any(|&tidx| {
                        let tc = &self.transforms[tidx];
                        root_buf.len() >= tc.min_len
                            && transform_quick_trigger(tc, root_buf)
                            && self.base64_buffer_gate(tc, root_buf)
                            && (tc.id != TransformId::UrlPercent
                                || self.url_percent_buffer_gate(tc, root_buf))
                    })
                    || self
                        .scanbuf_transform_idxs_active_base64
                        .iter()
                        .any(|&tidx| {
                            let tc = &self.transforms[tidx];
                            root_buf.len() >= tc.min_len
                                && transform_quick_trigger(tc, root_buf)
                                && self.base64_buffer_gate(tc, root_buf)
                        }));

            if !needs_transform_scan {
                perf::record_scan_prefilter_bypass();
                scratch.out.clear();
                scratch.norm_hash.clear();
                scratch.drop_hint_end.clear();
                return;
            }

            // Fall through: transforms need to scan this buffer.
            // scan_rules_on_buffer will be fast (zero touched_pairs = no regex work).
        }

        // ── Step F: reset for scan loop, set one-shot prefilter flag ─────
        scratch.root_prefilter_saw_utf16 = saw_utf16;
        scratch.root_prefilter_done = true;
        let ((), _reset_nanos) = perf::time(|| {
            // If prefilter found no rule hits, there is no accumulator state
            // to preserve (transform-only path), so use the full reset.
            // Otherwise preserve touched prefilter accumulators for the rule loop.
            if scratch.touched_pairs.is_empty() {
                scratch.reset_for_scan(self);
            } else {
                scratch.reset_for_scan_after_prefilter(self);
            }
        });
        perf::record_scan_reset(_reset_nanos);

        scratch.work_q.push(WorkItem::scan_root());

        // ── Work-queue loop ────────────────────────────────────────────
        //
        // Process items in FIFO order. Each `ScanBuf` may enqueue `DecodeSpan`
        // items (for transforms), and each `DecodeSpan` enqueues a `ScanBuf`
        // for the decoded output. This breadth-first traversal replaces
        // recursion, making depth and budget limits trivially enforceable.
        //
        // Budget gates checked per-iteration:
        //   • `total_decode_output_bytes` vs `max_total_decode_output_bytes`
        //   • `work_items_enqueued` vs `max_work_items` (inside ScanBuf arm)
        //   • `depth` vs `max_transform_depth` (inside ScanBuf arm)
        //
        // Tuning values are hoisted into locals before the loop. Although
        // `self` is `&Engine` (immutable), LLVM cannot prove that `&mut
        // ScanScratch` does not alias `self.tuning` fields, so it must
        // conservatively reload them on every iteration. Locals let the
        // register allocator keep these values in registers.
        let max_decode_bytes = self.tuning.max_total_decode_output_bytes;
        let max_work = self.tuning.max_work_items;
        let max_depth = self.tuning.max_transform_depth;
        while scratch.work_head < scratch.work_q.len() {
            if scratch.total_decode_output_bytes >= max_decode_bytes {
                break;
            }

            // Dequeue via copy + cursor advance (avoids shifting the Vec).
            // WorkItem is Copy (40 bytes of plain integers), so this reads
            // the slot without writing a default back — saving a 40-byte
            // store per iteration. The slot is never re-read because
            // work_head advances monotonically.
            //
            // SAFETY: `work_head < work_q.len()` is the loop condition
            // (checked on line above). `work_head` only increments by 1
            // per iteration, and `work_q` only grows (push) during the
            // loop body, never shrinks.
            //
            // NOTE: As of 2025-02, LLVM elides the bounds check on safe
            // indexing here (ccmp+b.hs pattern on AArch64). This unsafe
            // produces identical ASM and exists as a regression guard to
            // ensure the bounds check is never re-introduced by future
            // code changes. If this policy is revisited, revert to safe
            // indexing: `let item = scratch.work_q[scratch.work_head];`
            let item = unsafe { *scratch.work_q.get_unchecked(scratch.work_head) };
            scratch.work_head += 1;

            if !item.is_decode_span() {
                // ── ScanBuf path ──────────────────────────────────────────
                let step_id = item.step_id();
                let depth = item.depth() as usize;
                let transform_idx = item.transform_idx().map(|v| v as usize);
                let enc_ref = item.enc_ref();
                let root_hint: Option<Range<usize>> =
                    item.root_hint().map(|r| r.start as usize..r.end as usize);
                let buf_is_slab = item.buf_slab_range().is_some();

                let before = scratch.out.len();
                // Resolve the buffer reference to a raw pointer + length.
                //
                // We use raw pointers (and reconstruct a slice below) to avoid
                // holding a borrow on `scratch.slab` while we pass `scratch` mutably
                // into `scan_rules_on_buffer`. This is sound because:
                //
                //   - The slab is pre-allocated and never reallocated during a scan,
                //     so the pointer remains valid.
                //   - `scan_rules_on_buffer` writes only to scratch output buffers
                //     (findings, hit accumulators), never to the slab region backing
                //     `cur_buf`. No aliasing violation occurs.
                //   - `root_buf` is caller-owned and immutable for the scan duration.
                let (buf_ptr, buf_len, buf_offset) = if let Some(slab_range) = item.buf_slab_range()
                {
                    let start = slab_range.start as usize;
                    let end = slab_range.end as usize;
                    // SAFETY: The slab is pre-allocated and never reallocated during a
                    // scan; `scan_rules_on_buffer` only mutates output fields, not the
                    // slab region backing `cur_buf`. See the comment block above.
                    unsafe {
                        debug_assert!(end <= scratch.slab.buf.len());
                        let ptr = scratch.slab.buf.as_ptr().add(start);
                        (ptr, end.saturating_sub(start), start)
                    }
                } else {
                    (root_buf.as_ptr(), root_buf.len(), 0usize)
                };

                // SAFETY: see the comment block above for the full aliasing argument.
                let cur_buf = unsafe { std::slice::from_raw_parts(buf_ptr, buf_len) };

                // Build mapping context to translate decoded-space offsets back to root buffer
                // positions. This is used when reporting findings: the `root_hint` in a finding
                // should point to the *original* bytes in the root buffer, not intermediate
                // decoded buffers.
                //
                // For nested transforms (e.g., URL inside Base64), we need to map through
                // each decode layer. The context is only valid when the encoded span maps
                // 1:1 with the root hint (either directly from root, or through a slab
                // where lengths match).
                scratch.root_span_map_ctx =
                    match (transform_idx, enc_ref.as_ref(), root_hint.as_ref()) {
                        // Encoded bytes come directly from root buffer.
                        (Some(tidx), Some(er), Some(hint))
                            if !er.is_slab
                                && hint.start == er.lo as usize
                                && hint.end == er.hi as usize =>
                        {
                            let span = er.range_usize();
                            Some(RootSpanMapCtx::new(
                                &self.transforms[tidx],
                                &root_buf[span],
                                hint.start,
                                scratch.chunk_overlap_backscan,
                            ))
                        }
                        // Encoded bytes are in the slab (from a prior decode). The hint length
                        // must match the span length to ensure correct offset translation.
                        (Some(tidx), Some(er), Some(hint))
                            if er.is_slab
                                && (er.hi as usize) <= scratch.slab.buf.len()
                                && hint.end.saturating_sub(hint.start)
                                    == (er.hi as usize).saturating_sub(er.lo as usize) =>
                        {
                            let span = er.range_usize();
                            Some(RootSpanMapCtx::new(
                                &self.transforms[tidx],
                                &scratch.slab.buf[span],
                                hint.start,
                                scratch.chunk_overlap_backscan,
                            ))
                        }
                        _ => None,
                    };

                self.scan_rules_on_buffer(
                    cur_buf,
                    step_id,
                    root_hint.clone(),
                    base_offset,
                    file_id,
                    scratch,
                );
                scratch.root_span_map_ctx = None;
                let found_any_in_this_buf = scratch.out.len() > before;

                if depth >= max_depth {
                    continue;
                }
                if scratch.work_items_enqueued >= max_work {
                    continue;
                }
                // Decode bytes are only produced in the DecodeSpan arm, so this
                // budget is invariant while processing a ScanBuf item.
                if scratch.total_decode_output_bytes >= max_decode_bytes {
                    continue;
                }
                // Keep a local decrementing budget to avoid repeated loads of
                // `work_items_enqueued` and `max_work` in span inner loops.
                let mut remaining_work_items = max_work.saturating_sub(scratch.work_items_enqueued);
                if remaining_work_items == 0 {
                    continue;
                }
                let (non_base64_tidxs, base64_tidxs) =
                    self.scanbuf_transform_buckets(found_any_in_this_buf);

                for &tidx in non_base64_tidxs {
                    if remaining_work_items == 0 {
                        break;
                    }
                    let tc = &self.transforms[tidx];
                    if cur_buf.len() < tc.min_len {
                        continue;
                    }
                    if !transform_quick_trigger(tc, cur_buf) {
                        continue;
                    }

                    find_spans_into(tc, cur_buf, &mut scratch.spans);
                    if scratch.spans.is_empty() {
                        continue;
                    }

                    let span_len = scratch.spans.len().min(tc.max_spans_per_buffer);
                    for i in 0..span_len {
                        if remaining_work_items == 0 {
                            break;
                        }

                        let enc_span = scratch.spans[i].to_range();
                        let child_step_id = scratch.step_arena.push(
                            step_id,
                            DecodeStep::Transform {
                                transform_idx: tidx,
                                parent_span: enc_span.clone(),
                            },
                        );

                        // Compute the child's root hint. For nested transforms, use the
                        // mapping context to translate the encoded span back to root-buffer
                        // coordinates. This ensures findings report offsets into the original
                        // input, not intermediate decoded buffers.
                        let child_root_hint: Option<Range<usize>> =
                            if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                                Some(ctx.map_span(enc_span.clone()))
                            } else if root_hint.is_none() {
                                Some(enc_span.clone())
                            } else {
                                root_hint.clone()
                            };

                        let child_enc_ref = if buf_is_slab {
                            let start = buf_offset.saturating_add(enc_span.start);
                            let end = buf_offset.saturating_add(enc_span.end);
                            EncRef::slab(start as u32..end as u32)
                        } else {
                            EncRef::root(enc_span.start as u32..enc_span.end as u32)
                        };

                        let child_root_hint_u64: Option<Range<u64>> = child_root_hint
                            .as_ref()
                            .map(|r| r.start as u64..r.end as u64);

                        scratch.work_q.push(WorkItem::decode_span(
                            tidx as u16,
                            child_enc_ref,
                            child_step_id,
                            child_root_hint_u64,
                            (depth + 1) as u8,
                        ));
                        scratch.work_items_enqueued += 1;
                        remaining_work_items -= 1;
                    }
                }

                for &tidx in base64_tidxs {
                    if remaining_work_items == 0 {
                        break;
                    }
                    let tc = &self.transforms[tidx];
                    if cur_buf.len() < tc.min_len {
                        continue;
                    }
                    if !transform_quick_trigger(tc, cur_buf) {
                        continue;
                    }
                    if !self.base64_buffer_gate(tc, cur_buf) {
                        continue;
                    }

                    find_spans_into(tc, cur_buf, &mut scratch.spans);
                    if scratch.spans.is_empty() {
                        continue;
                    }

                    let span_len = scratch.spans.len().min(tc.max_spans_per_buffer);
                    for i in 0..span_len {
                        if remaining_work_items == 0 {
                            break;
                        }

                        let enc_span = scratch.spans[i].to_range();
                        let enc = &cur_buf[enc_span.clone()];
                        // Base64-only prefilter: cheap encoded-space gate.
                        // This is only used when the decoded gate is enabled, and it never
                        // replaces the decoded check. It exists to avoid paying decode cost
                        // when a span cannot possibly contain any anchor after decoding.
                        #[cfg(feature = "b64-stats")]
                        {
                            scratch.base64_stats.spans =
                                scratch.base64_stats.spans.saturating_add(1);
                            scratch.base64_stats.span_bytes = scratch
                                .base64_stats
                                .span_bytes
                                .saturating_add(enc.len() as u64);
                        }
                        if tc.gate == Gate::AnchorsInDecoded {
                            if let Some(gate) = &self.b64_gate {
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.pre_gate_checks =
                                        scratch.base64_stats.pre_gate_checks.saturating_add(1);
                                }
                                if !gate.hits(enc) {
                                    #[cfg(feature = "b64-stats")]
                                    {
                                        scratch.base64_stats.pre_gate_skip =
                                            scratch.base64_stats.pre_gate_skip.saturating_add(1);
                                        scratch.base64_stats.pre_gate_skip_bytes = scratch
                                            .base64_stats
                                            .pre_gate_skip_bytes
                                            .saturating_add(enc.len() as u64);
                                    }
                                    continue;
                                }
                                #[cfg(feature = "b64-stats")]
                                {
                                    scratch.base64_stats.pre_gate_pass =
                                        scratch.base64_stats.pre_gate_pass.saturating_add(1);
                                }
                            }
                        }

                        // Base64 alignment shifts.
                        //
                        // Base64 encodes in 4-character quanta. A span extracted from
                        // raw bytes may not start on a quantum boundary relative to
                        // the original encoding, so we try all four possible offsets
                        // (shift 0..3) to cover every alignment.
                        //
                        // For each shift, `base64_skip_chars` returns the byte offset
                        // to skip leading non-alphabet chars (whitespace, padding) plus
                        // `shift` alignment chars. Returns `None` when the span is too
                        // short to accommodate the shift — at that point larger shifts
                        // would also fail, so we `break` rather than `continue`.
                        // Duplicate start offsets (which can occur when whitespace
                        // collapses shifts) are deduplicated.
                        let mut span_starts = [0usize; 4];
                        let mut span_ends = [0usize; 4];
                        let mut span_count = 0usize;
                        let allow_space_ws = tc.base64_allow_space_ws;
                        for shift in 0..4usize {
                            let Some(rel) = base64_skip_chars(enc, shift, allow_space_ws) else {
                                break;
                            };
                            let start = enc_span.start.saturating_add(rel);
                            if start >= enc_span.end {
                                continue;
                            }
                            if span_starts[..span_count].contains(&start) {
                                continue;
                            }
                            let enc_aligned = &cur_buf[start..enc_span.end];
                            let remaining_chars = base64_char_count(enc_aligned, allow_space_ws);
                            if remaining_chars < tc.min_len {
                                continue;
                            }
                            span_starts[span_count] = start;
                            span_ends[span_count] = enc_span.end;
                            span_count += 1;
                            if span_count >= span_starts.len() {
                                break;
                            }
                        }

                        for idx in 0..span_count {
                            if remaining_work_items == 0 {
                                break;
                            }

                            let enc_span = span_starts[idx]..span_ends[idx];
                            let child_step_id = scratch.step_arena.push(
                                step_id,
                                DecodeStep::Transform {
                                    transform_idx: tidx,
                                    parent_span: enc_span.clone(),
                                },
                            );

                            // Compute the child's root hint. For nested transforms, use the
                            // mapping context to translate the encoded span back to root-buffer
                            // coordinates. This ensures findings report offsets into the original
                            // input, not intermediate decoded buffers.
                            let child_root_hint: Option<Range<usize>> =
                                if let Some(ctx) = scratch.root_span_map_ctx.as_ref() {
                                    Some(ctx.map_span(enc_span.clone()))
                                } else if root_hint.is_none() {
                                    Some(enc_span.clone())
                                } else {
                                    root_hint.clone()
                                };

                            let child_enc_ref = if buf_is_slab {
                                let start = buf_offset.saturating_add(enc_span.start);
                                let end = buf_offset.saturating_add(enc_span.end);
                                EncRef::slab(start as u32..end as u32)
                            } else {
                                EncRef::root(enc_span.start as u32..enc_span.end as u32)
                            };

                            let child_root_hint_u64: Option<Range<u64>> = child_root_hint
                                .as_ref()
                                .map(|r| r.start as u64..r.end as u64);

                            scratch.work_q.push(WorkItem::decode_span(
                                tidx as u16,
                                child_enc_ref,
                                child_step_id,
                                child_root_hint_u64,
                                (depth + 1) as u8,
                            ));
                            scratch.work_items_enqueued += 1;
                            remaining_work_items -= 1;
                        }
                    }
                }
            } else {
                // ── DecodeSpan path ───────────────────────────────────────
                let step_id = item.step_id();
                let depth = item.depth() as usize;
                let transform_idx = item.transform_idx().unwrap_or(0) as usize;
                let enc_ref = item.enc_ref().unwrap();
                let root_hint: Option<Range<usize>> =
                    item.root_hint().map(|r| r.start as usize..r.end as usize);

                #[cfg(feature = "perf-counters")]
                let _transform_start = std::time::Instant::now();

                if scratch.total_decode_output_bytes >= max_decode_bytes {
                    continue;
                }
                let tc = &self.transforms[transform_idx];
                if tc.mode == TransformMode::Disabled {
                    continue;
                }

                // Resolve the encoded span to a raw pointer + length.
                //
                // Same aliasing argument as the ScanBuf arm: root_buf is
                // caller-owned and immutable; the slab is pre-allocated and
                // never reallocated during a scan (DecodeSlab invariant).
                // `r.end` is bounds-checked against the backing buffer before
                // any pointer arithmetic; `r.start <= r.end` is guaranteed by
                // `EncRef::range_usize()`.
                let r = enc_ref.range_usize();
                let (enc_ptr, enc_len) = if !enc_ref.is_slab {
                    if r.end <= root_buf.len() {
                        // SAFETY: `r.start <= r.end <= root_buf.len()` checked
                        // above; root_buf is immutable for the scan duration.
                        let ptr = unsafe { root_buf.as_ptr().add(r.start) };
                        (ptr, r.end - r.start)
                    } else {
                        continue;
                    }
                } else if r.end <= scratch.slab.buf.len() {
                    // SAFETY: `r.start <= r.end <= slab.buf.len()` checked
                    // above; slab never reallocates during a scan.
                    let ptr = unsafe { scratch.slab.buf.as_ptr().add(r.start) };
                    (ptr, r.end - r.start)
                } else {
                    continue;
                };
                // SAFETY: pointer + length were validated by the bounds checks
                // above; the backing buffer is not mutated while this slice exists.
                let enc = unsafe { std::slice::from_raw_parts(enc_ptr, enc_len) };
                // True only when root_hint exactly names the encoded bytes being
                // decoded. This allows decoded matches to map back to precise
                // root spans; otherwise we keep coarse root_hint windows to avoid
                // fabricating exact offsets from partial context.
                let root_hint_maps_encoded = if !enc_ref.is_slab {
                    if let Some(hint) = root_hint.as_ref() {
                        hint.start == r.start && hint.end == r.end
                    } else {
                        false
                    }
                } else {
                    false
                };

                if let Some(vs_stream) = self.vs_stream.as_ref() {
                    self.decode_stream_and_scan(
                        vs_stream,
                        tc,
                        transform_idx,
                        &enc_ref,
                        enc,
                        step_id,
                        root_hint,
                        root_hint_maps_encoded,
                        depth,
                        base_offset,
                        file_id,
                        scratch,
                    );
                } else {
                    self.decode_span_fallback(
                        tc,
                        transform_idx,
                        &enc_ref,
                        enc,
                        step_id,
                        root_hint,
                        depth,
                        scratch,
                    );
                }

                #[cfg(feature = "perf-counters")]
                perf::record_scan_transform(_transform_start.elapsed().as_nanos() as u64);
            }
        }

        // Offline validation runs inline via `compute_offline_verdict()`
        // at each emission site in window_validate.rs, using the parent
        // step_id to correctly identify root-semantic findings (including
        // UTF-16 variants).
    }

    /// Scans a buffer and returns a shared view of finding records.
    ///
    /// Delegates to [`Engine::scan_chunk_into`]; the same preconditions apply
    /// (`buf.len() <= u32::MAX`, exclusive `scratch` ownership).
    ///
    /// The returned slice borrows `scratch` and is valid until `scratch` is
    /// reused for another scan.
    pub fn scan_chunk_records<'a>(
        &self,
        buf: &[u8],
        file_id: FileId,
        base_offset: u64,
        scratch: &'a mut ScanScratch,
    ) -> &'a [FindingRec] {
        self.scan_chunk_into(buf, file_id, base_offset, scratch);
        scratch.findings()
    }

    /// Returns the required overlap between chunks for correctness.
    ///
    /// The overlap must be large enough that any match straddling a chunk
    /// boundary is fully contained in at least one chunk. The formula is:
    ///
    /// ```text
    /// overlap = max_window_diameter + (max_prefilter_width - 1)
    /// ```
    ///
    /// - `max_window_diameter`: the largest validation window (2 × radius ×
    ///   variant scale) across all rules.
    /// - `max_prefilter_width - 1`: accounts for the widest prefilter pattern
    ///   straddling the boundary (a pattern of width W needs W-1 overlap bytes
    ///   to guarantee its start falls in the previous chunk).
    ///
    /// When scanning overlapping chunks, call
    /// [`ScanScratch::drop_prefix_findings`] with the new start offset to avoid
    /// emitting duplicates from the overlap prefix. The returned value is in
    /// bytes and already accounts for UTF-16 window scaling.
    pub fn required_overlap(&self) -> usize {
        self.max_window_diameter_bytes
            .saturating_add(self.max_prefilter_width.saturating_sub(1))
    }

    /// Returns the per-chunk finding cap configured in [`Tuning`].
    #[inline]
    pub fn max_findings_per_chunk(&self) -> usize {
        self.tuning.max_findings_per_chunk
    }

    /// Returns the [`TransformId`] for the transform at position `idx` in the
    /// engine's transform list.
    ///
    /// # Panics
    /// Panics if `idx >= self.transforms.len()`.
    #[cfg(feature = "sim-harness")]
    pub(crate) fn transform_id(&self, idx: usize) -> TransformId {
        self.transforms[idx].id
    }

    /// Returns the rule name for a rule id used in [`FindingRec`].
    ///
    /// Returns `"<unknown-rule>"` if `rule_id` is out of bounds.
    pub fn rule_name(&self, rule_id: u32) -> &str {
        self.rules_cold
            .get(rule_id as usize)
            .map(|r| r.name)
            .unwrap_or("<unknown-rule>")
    }

    /// Returns the effective per-rule minimum confidence threshold.
    ///
    /// The value is precomputed during engine construction and stored in
    /// `rules_cold`, so scan-loop code does not need to recompute threshold
    /// defaults from rule structure.
    ///
    /// Returns `0` if `rule_id` is out of bounds (the same fallback as "no
    /// threshold configured").
    pub fn rule_min_confidence(&self, rule_id: u32) -> i8 {
        self.rules_cold
            .get(rule_id as usize)
            .map(|r| r.min_confidence)
            .unwrap_or(0)
    }

    /// Allocates a fresh scratch state sized for this engine.
    ///
    /// The returned scratch must be used exclusively with `self`. Using it with
    /// a different `Engine` may panic or produce incorrect results because
    /// internal buffer sizes, gate pool indices, and Vectorscan scratch
    /// bindings are engine-specific.
    pub fn new_scratch(&self) -> ScanScratch {
        ScanScratch::new(self)
    }

    /// Cheap encoded-space gate for Base64 transforms.
    ///
    /// Returns `true` when the transform is not Base64 or when the encoded
    /// buffer could plausibly contain any anchor after decoding. This is a
    /// conservative optimization; decoded-space validation remains authoritative.
    #[inline]
    pub(super) fn base64_buffer_gate(&self, tc: &TransformConfig, buf: &[u8]) -> bool {
        if tc.id != TransformId::Base64 || tc.gate != Gate::AnchorsInDecoded {
            return true;
        }
        match &self.b64_gate {
            Some(gate) if gate.pattern_count() > 0 => gate.hits_anywhere(buf),
            _ => true,
        }
    }

    /// Cheap gate for URL-percent transforms on the zero-hit path.
    ///
    /// Returns `true` when the anchor byte set is empty (conservative fallback)
    /// or when at least one `%XX` triplet in the buffer decodes to a byte
    /// present in any anchor pattern.
    ///
    /// Also accepts when `plus_to_space` is enabled and `'+'` is present with
    /// space in the anchor byte set.
    ///
    /// This filters out buffers where `%` appears only in format specifiers
    /// (`%d`, `%s`) and no decoded anchor byte can be produced.
    #[inline]
    fn url_percent_buffer_gate(&self, tc: &TransformConfig, buf: &[u8]) -> bool {
        url_percent_gate_check(&self.anchor_byte_set, tc.plus_to_space, buf)
    }

    /// Drains compact findings from scratch and materializes provenance.
    ///
    /// Converts each [`FindingRec`] (compact, arena-backed) into a [`Finding`]
    /// (owned, with materialized decode steps) by walking the step arena.
    /// Appends to `out` without clearing it — the caller is responsible for
    /// clearing `out` if a fresh result set is desired.
    ///
    /// After draining, the normalization hash and drop-hint bookkeeping are
    /// cleared so `scratch` is ready for the next scan.
    pub fn drain_findings_materialized(&self, scratch: &mut ScanScratch, out: &mut Vec<Finding>) {
        for rec in scratch.out.drain() {
            let rule = &self.rules_cold[rec.rule_id as usize];
            scratch
                .step_arena
                .materialize(rec.step_id, &mut scratch.steps_buf);
            let mut steps = DecodeSteps::new();
            steps.extend_from_slice(scratch.steps_buf.as_slice());
            out.push(Finding {
                rule: rule.name,
                span: (rec.span_start as usize)..(rec.span_end as usize),
                root_span_hint: u64_to_usize(rec.root_hint_start)..u64_to_usize(rec.root_hint_end),
                decode_steps: steps,
            });
        }
        scratch.norm_hash.clear();
        scratch.drop_hint_end.clear();
    }
}

/// Decode a pair of ASCII hex digits into a byte value.
///
/// Returns `None` if either digit is not valid hexadecimal.
#[inline(always)]
pub(super) fn decode_hex_pair(hi: u8, lo: u8) -> Option<u8> {
    let h = match hi {
        b'0'..=b'9' => hi - b'0',
        b'A'..=b'F' => hi - b'A' + 10,
        b'a'..=b'f' => hi - b'a' + 10,
        _ => return None,
    };
    let l = match lo {
        b'0'..=b'9' => lo - b'0',
        b'A'..=b'F' => lo - b'A' + 10,
        b'a'..=b'f' => lo - b'a' + 10,
        _ => return None,
    };
    Some((h << 4) | l)
}

/// Standalone gate check for URL-percent transforms.
///
/// Scans `buf` for `%XX` triplets and checks whether any decoded byte value
/// appears in the anchor byte set. Returns `true` (allow scan) if:
/// - The anchor byte set is empty (conservative: no anchors compiled).
/// - `plus_to_space` is enabled, `'+'` appears, and space is an anchor byte.
/// - Any `%XX` triplet decodes to a byte in the anchor set.
/// - A truncated `%` triplet is at end-of-buffer (conservative).
///
/// Returns `false` only when we can prove no decoded byte would match any
/// anchor — this is the common case for format-specifier-heavy buffers
/// (`%d`, `%s`) that don't encode anchor-relevant bytes.
pub(super) fn url_percent_gate_check(
    anchor_byte_set: &[u64; 4],
    plus_to_space: bool,
    buf: &[u8],
) -> bool {
    if *anchor_byte_set == [0u64; 4] {
        return true;
    }
    // When plus_to_space is enabled, '+' decodes to space (0x20) without any
    // `%XX` escape. If space is an anchor byte, a bare '+' is enough to
    // require the full transform pass.
    if plus_to_space
        && memchr::memchr(b'+', buf).is_some()
        && (anchor_byte_set[(b' ' >> 6) as usize] & (1u64 << (b' ' & 63)) != 0)
    {
        return true;
    }
    let bytes = buf;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 < bytes.len() {
                if let Some(decoded) = decode_hex_pair(bytes[i + 1], bytes[i + 2]) {
                    if anchor_byte_set[(decoded >> 6) as usize] & (1u64 << (decoded & 63)) != 0 {
                        return true;
                    }
                    i += 3;
                    continue;
                }
            } else {
                return true; // truncated %XX — conservatively allow scan
            }
        }
        i += 1;
    }
    false
}

// --------------------------
// Benchmark helpers (feature = "bench")
// --------------------------
//
// The functions and types below expose internal hot-path routines to the
// benchmark harness. They are compiled out of production builds. Each wrapper
// delegates directly to the production implementation so benchmarks measure
// real code paths, not simplified stubs.

/// Benchmark helper to expose span detection for transform configs.
#[cfg(feature = "bench")]
pub fn bench_find_spans_into(
    tc: &TransformConfig,
    buf: &[u8],
    out: &mut Vec<std::ops::Range<usize>>,
) {
    find_spans_into(tc, buf, out);
}

/// Pre-packed literal patterns for benchmark-only memmem gate checks.
///
/// Wraps [`PackedPatterns`] so benchmarks compile literals once during setup
/// and measure only the `contains_any_memmem` / `contains_all_memmem`
/// hot-path check per timed iteration.
#[cfg(feature = "bench")]
#[derive(Clone, Debug)]
pub struct BenchPackedPatterns {
    patterns: PackedPatterns,
}

/// Build packed raw literal patterns for benchmark-only memmem checks.
#[cfg(feature = "bench")]
pub fn bench_pack_patterns_raw(patterns: &[&[u8]]) -> BenchPackedPatterns {
    let total_bytes = patterns.iter().map(|p| p.len()).sum();
    let mut builder = PackedPatternsBuilder::with_capacity(patterns.len(), total_bytes);
    for pat in patterns {
        builder.push_raw(pat);
    }
    BenchPackedPatterns {
        patterns: builder.build(),
    }
}

/// Benchmark helper that calls the same ANY-of memmem gate used in scan paths.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_contains_any_memmem(hay: &[u8], needles: &BenchPackedPatterns) -> bool {
    contains_any_memmem(hay, &needles.patterns)
}

/// Benchmark helper that calls the ALL-of memmem gate used in scan paths.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_contains_all_memmem(hay: &[u8], needles: &BenchPackedPatterns) -> bool {
    super::helpers::contains_all_memmem(hay, &needles.patterns)
}

/// Reusable benchmark state for entropy-gate micro-benchmarks.
///
/// Pre-builds the `log2` lookup table and owns an [`EntropyScratch`] histogram
/// buffer so that setup cost is excluded from timed iterations. The `max_len`
/// field tracks the table size; call [`ensure_max_len`] when the window size
/// changes between benchmark parameters.
///
/// [`ensure_max_len`]: BenchEntropyState::ensure_max_len
#[cfg(feature = "bench")]
pub struct BenchEntropyState {
    max_len: usize,
    log2_table: Vec<f32>,
    scratch: super::scratch::EntropyScratch,
}

#[cfg(feature = "bench")]
impl BenchEntropyState {
    #[inline]
    fn new(max_len: usize) -> Self {
        Self {
            max_len,
            log2_table: super::helpers::build_log2_table(max_len),
            scratch: super::scratch::EntropyScratch::new(),
        }
    }

    #[inline]
    fn ensure_max_len(&mut self, max_len: usize) {
        if self.max_len != max_len {
            self.max_len = max_len;
            self.log2_table = super::helpers::build_log2_table(max_len);
        }
    }
}

#[cfg(feature = "bench")]
thread_local! {
    static BENCH_ENTROPY_STATE: std::cell::RefCell<BenchEntropyState> =
        std::cell::RefCell::new(BenchEntropyState::new(0));
}

/// Build reusable benchmark entropy state so setup is outside timed iterations.
#[cfg(feature = "bench")]
pub fn bench_build_entropy_state(max_len: usize) -> BenchEntropyState {
    BenchEntropyState::new(max_len)
}

/// Benchmark helper for the entropy gate using reusable prebuilt state.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_entropy_gate_passes_with_state(
    min_bits: f32,
    min_len: usize,
    bytes: &[u8],
    state: &mut BenchEntropyState,
) -> bool {
    let spec = super::rule_repr::EntropyCompiled {
        min_bits_per_byte: min_bits,
        digit_penalty: false,
        min_len,
        max_len: state.max_len,
        min_entropy_bits_per_byte: None,
    };
    super::helpers::entropy_gate_outcome(&spec, bytes, &mut state.scratch, &state.log2_table)
        .allows_candidate()
}

/// Benchmark helper for `shannon_entropy_bits_per_byte` using reusable state.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_shannon_entropy_with_state(bytes: &[u8], state: &mut BenchEntropyState) -> f32 {
    super::helpers::shannon_entropy_bits_per_byte(bytes, &mut state.scratch, &state.log2_table)
}

/// Compatibility wrapper that reuses thread-local state across benchmark calls.
#[cfg(feature = "bench")]
pub fn bench_entropy_gate_passes(
    min_bits: f32,
    min_len: usize,
    max_len: usize,
    bytes: &[u8],
) -> bool {
    BENCH_ENTROPY_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.ensure_max_len(max_len);
        bench_entropy_gate_passes_with_state(min_bits, min_len, bytes, &mut state)
    })
}

/// Compatibility wrapper that reuses thread-local state across benchmark calls.
#[cfg(feature = "bench")]
pub fn bench_shannon_entropy(bytes: &[u8], max_len: usize) -> f32 {
    BENCH_ENTROPY_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.ensure_max_len(max_len);
        bench_shannon_entropy_with_state(bytes, &mut state)
    })
}

/// Reusable benchmark state for `merge_ranges_with_gap_sorted`.
///
/// Owns a pre-allocated [`ScratchVec<SpanU32>`] so that the benchmark inner
/// loop measures only the merge algorithm, not allocation overhead.  Call
/// [`bench_merge_ranges_load`] to populate the state from `(start, end)`
/// tuples, then [`bench_merge_ranges_run`] to execute the merge.
#[cfg(feature = "bench")]
pub struct BenchMergeRangesState {
    ranges: crate::scratch_memory::ScratchVec<super::hit_pool::SpanU32>,
}

#[cfg(feature = "bench")]
impl BenchMergeRangesState {
    #[inline]
    fn new(capacity: usize) -> Self {
        Self {
            ranges: crate::scratch_memory::ScratchVec::with_capacity(capacity)
                .expect("bench merge_ranges alloc"),
        }
    }

    #[inline]
    fn ensure_capacity(&mut self, capacity: usize) {
        if self.ranges.capacity() < capacity {
            self.ranges = crate::scratch_memory::ScratchVec::with_capacity(capacity)
                .expect("bench merge_ranges alloc");
        }
    }
}

#[cfg(feature = "bench")]
thread_local! {
    static BENCH_MERGE_STATE: std::cell::RefCell<BenchMergeRangesState> =
        std::cell::RefCell::new(BenchMergeRangesState::new(0));
}

/// Build reusable merge-range benchmark state.
#[cfg(feature = "bench")]
pub fn bench_build_merge_ranges_state(capacity: usize) -> BenchMergeRangesState {
    BenchMergeRangesState::new(capacity)
}

/// Load source ranges into reusable merge benchmark state.
#[cfg(feature = "bench")]
pub fn bench_merge_ranges_load(state: &mut BenchMergeRangesState, ranges: &[(u32, u32)]) {
    state.ensure_capacity(ranges.len());
    state.ranges.clear();
    for &(s, e) in ranges {
        state.ranges.push(super::hit_pool::SpanU32 {
            start: s,
            end: e,
            anchor_hint: s,
        });
    }
}

/// Run `merge_ranges_with_gap_sorted` on already-loaded benchmark state.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_merge_ranges_run(state: &mut BenchMergeRangesState, gap: u32) -> usize {
    super::helpers::merge_ranges_with_gap_sorted(&mut state.ranges, gap);
    state.ranges.len()
}

/// Benchmark wrapper for `merge_ranges_with_gap_sorted`.
///
/// Accepts a slice of `(start, end)` tuples and a gap, returns the number
/// of merged ranges.
#[cfg(feature = "bench")]
pub fn bench_merge_ranges(ranges: &[(u32, u32)], gap: u32) -> usize {
    BENCH_MERGE_STATE.with(|state| {
        let mut state = state.borrow_mut();
        bench_merge_ranges_load(&mut state, ranges);
        bench_merge_ranges_run(&mut state, gap)
    })
}

/// Reusable benchmark state for UTF-16 decode helpers.
///
/// Owns a pre-allocated output buffer so the benchmark inner loop measures
/// only decode throughput, not allocation overhead.  Call
/// [`bench_build_utf16_decode_state`] to create, then use the `*_with_state`
/// variants of the decode benchmarks.
#[cfg(feature = "bench")]
pub struct BenchUtf16DecodeState {
    max_out: usize,
    out: crate::scratch_memory::ScratchVec<u8>,
}

#[cfg(feature = "bench")]
impl BenchUtf16DecodeState {
    #[inline]
    fn new(max_out: usize) -> Self {
        Self {
            max_out,
            out: crate::scratch_memory::ScratchVec::with_capacity(max_out)
                .expect("bench utf16 alloc"),
        }
    }

    #[inline]
    fn ensure_max_out(&mut self, max_out: usize) {
        if self.max_out != max_out {
            self.max_out = max_out;
            if self.out.capacity() < max_out {
                self.out = crate::scratch_memory::ScratchVec::with_capacity(max_out)
                    .expect("bench utf16 alloc");
            }
        }
    }
}

#[cfg(feature = "bench")]
thread_local! {
    static BENCH_UTF16_STATE: std::cell::RefCell<BenchUtf16DecodeState> =
        std::cell::RefCell::new(BenchUtf16DecodeState::new(0));
}

/// Build reusable UTF-16 decode benchmark state.
#[cfg(feature = "bench")]
pub fn bench_build_utf16_decode_state(max_out: usize) -> BenchUtf16DecodeState {
    BenchUtf16DecodeState::new(max_out)
}

/// Benchmark helper for `decode_utf16le_to_buf` using reusable state.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_decode_utf16le_with_state(input: &[u8], state: &mut BenchUtf16DecodeState) -> usize {
    let _ = super::helpers::decode_utf16le_to_buf(input, state.max_out, &mut state.out);
    state.out.len()
}

/// Benchmark helper for `decode_utf16be_to_buf` using reusable state.
#[cfg(feature = "bench")]
#[inline(always)]
pub fn bench_decode_utf16be_with_state(input: &[u8], state: &mut BenchUtf16DecodeState) -> usize {
    let _ = super::helpers::decode_utf16be_to_buf(input, state.max_out, &mut state.out);
    state.out.len()
}

/// Benchmark wrapper for `decode_utf16le_to_buf`.
#[cfg(feature = "bench")]
pub fn bench_decode_utf16le(input: &[u8], max_out: usize) -> usize {
    BENCH_UTF16_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.ensure_max_out(max_out);
        bench_decode_utf16le_with_state(input, &mut state)
    })
}

/// Benchmark wrapper for `decode_utf16be_to_buf`.
#[cfg(feature = "bench")]
pub fn bench_decode_utf16be(input: &[u8], max_out: usize) -> usize {
    BENCH_UTF16_STATE.with(|state| {
        let mut state = state.borrow_mut();
        state.ensure_max_out(max_out);
        bench_decode_utf16be_with_state(input, &mut state)
    })
}

/// Benchmark wrapper for `map_utf16_decoded_offset`.
#[cfg(feature = "bench")]
pub fn bench_map_utf16_decoded_offset(input: &[u8], decoded_offset: usize, le: bool) -> usize {
    super::helpers::map_utf16_decoded_offset(input, decoded_offset, le)
}

/// Benchmark wrapper for `extract_secret_span_locs`.
#[cfg(feature = "bench")]
pub fn bench_extract_secret_span_locs(
    locs: &regex::bytes::CaptureLocations,
    secret_group: Option<u16>,
) -> (usize, usize) {
    let secret_group_raw = secret_group.unwrap_or_default();
    super::helpers::extract_secret_span_locs_raw(locs, secret_group_raw, secret_group.is_some())
}

/// Benchmark wrapper for `hash128`.
#[cfg(feature = "bench")]
pub fn bench_hash128(bytes: &[u8]) -> u128 {
    super::helpers::hash128(bytes)
}

#[cfg(feature = "bench")]
pub use super::transform::{bench_stream_decode_base64, bench_stream_decode_url};

#[cfg(test)]
#[path = "core_url_gate_tests.rs"]
mod url_gate_tests;

#[cfg(all(test, feature = "bench"))]
#[path = "core_bench_wrapper_tests.rs"]
mod bench_wrapper_tests;
