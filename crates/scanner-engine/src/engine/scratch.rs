//! Per-scan scratch state, entropy histogram, and root-span coordinate mapping.
//!
//! This module hosts [`ScanScratch`], the primary allocation amortization
//! vehicle for scans, [`EntropyScratch`] for entropy gating calculations, and
//! [`RootSpanMapCtx`] for translating decoded-byte offsets back to root-buffer
//! coordinates during transform scans. Scratch state is single-threaded and
//! reused across chunks to keep the hot path allocation-free.
//!
//! # Layout
//!
//! `ScanScratch` uses a `#[repr(C)]` layout with an explicit 64-byte cache-line
//! boundary separating hot-path fields (findings, work queue, hit accumulators)
//! from cold fields (decode slab, ring buffer, Vectorscan scratch). See the
//! struct-level docs for the full field map.
//!
//! # Lifecycle
//!
//! 1. Allocate via [`ScanScratch::new`] — pre-sizes all buffers to the engine's
//!    tuning parameters.
//! 2. Per-chunk: call [`ScanScratch::reset_for_scan`] (or
//!    [`ScanScratch::reset_for_scan_after_prefilter`]) to clear per-scan state
//!    while preserving allocations.
//! 3. Scan: the engine populates findings, work items, and decode steps.
//! 4. Drain: [`ScanScratch::drain_findings`] or
//!    [`ScanScratch::drain_findings_with_hashes`] extracts results.

#[cfg(feature = "sim-harness")]
use crate::api::StepId;
use crate::api::{
    DecodeStep, FileId, FindingRec, STEP_ROOT, TransformConfig, TransformId, TransformMode,
};
use crate::scratch_memory::ScratchVec;
use crate::stdx::{ByteRing, FixedSet128, TimingWheel};

#[cfg(feature = "b64-stats")]
use crate::api::Base64DecodeStats;

use super::decode_state::{DecodeSlab, StepArena};
use super::helpers::{hash128, pow2_at_least};
use super::hit_pool::{HitAccPool, SpanU32};
use super::transform::{STREAM_DECODE_CHUNK_BYTES, is_url_trigger, map_decoded_offset};
use super::vectorscan_prefilter::{VsScratch, VsStreamWindow};
use super::work_items::{PendingDecodeSpan, PendingWindow, SpanStreamEntry, WorkItem};
use regex::bytes::CaptureLocations;

use super::Engine;

/// Packed dedup key for finding deduplication.
///
/// Uses `#[repr(C)]` with `bytemuck::Pod` to guarantee a fixed 32-byte layout
/// aligned to the AEGIS-128L absorption rate (32 bytes = 2 × 128-bit AES
/// blocks) with no padding. This lets `hash128` process the key in a single
/// absorption step with no trailing partial-block handling, which is measurably
/// faster than the previous 33-byte packed layout.
///
/// The variant discriminator is packed into the high byte of
/// `rule_id_with_variant`. This requires `rule_id <= DEDUP_RULE_ID_MAX`.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct DedupKey {
    file_id: u32,
    /// Lower 24 bits: `rule_id`. Upper 8 bits: `variant_disc`.
    rule_id_with_variant: u32,
    span_start: u32,
    span_end: u32,
    root_hint_start: u64,
    root_hint_end: u64,
}

const _: () = assert!(std::mem::size_of::<DedupKey>() == 32);

/// Number of low bits reserved for rule IDs in `DedupKey::rule_id_with_variant`.
const DEDUP_RULE_ID_BITS: u32 = 24;
/// Maximum rule id that can be packed with an 8-bit variant discriminator.
pub(super) const DEDUP_RULE_ID_MAX: u32 = (1u32 << DEDUP_RULE_ID_BITS) - 1;

/// Packs a rule ID and variant discriminator into a single `u32`.
///
/// The lower [`DEDUP_RULE_ID_BITS`] (24) bits hold the rule ID; the upper 8
/// bits hold `variant_disc` (non-UTF16=0, Utf16Le=1, Utf16Be=2). This packing
/// ensures UTF-16 LE/BE findings that share the same span and root hint
/// produce distinct dedup keys.
///
/// # Panics
///
/// Panics if `rule_id > DEDUP_RULE_ID_MAX` (2²⁴ − 1 = 16,777,215).
#[inline(always)]
fn pack_rule_id_with_variant(rule_id: u32, variant_disc: u8) -> u32 {
    assert!(
        rule_id <= DEDUP_RULE_ID_MAX,
        "rule_id exceeds 24-bit dedup budget"
    );
    rule_id | (u32::from(variant_disc) << DEDUP_RULE_ID_BITS)
}

/// BLAKE3 digest of the raw secret bytes extracted after gate validation.
/// 32 bytes = 256 bits, matching BLAKE3's default output length.
///
/// Used for cross-chunk and cross-run deduplication: two findings with the
/// same `NormHash` are considered the same secret regardless of surrounding
/// context or encoding transform.
pub type NormHash = [u8; 32];

/// Internal multiplier for cross-chunk dedupe set sizing.
///
/// Dedupe sets must track more keys than the emit cap because many candidates
/// can be observed (and intentionally dropped) before the chunk cap is reached.
/// Keeping this budget separate from `max_findings` preserves cross-chunk
/// duplicate suppression under high candidate pressure.
const FINDING_DEDUPE_MULTIPLIER: usize = 32;

/// Scratch histogram for entropy gating.
///
/// Entropy gates reject candidate matches whose byte distribution is too
/// uniform or too skewed to be a real secret (e.g., all-zero padding).
/// The histogram is populated per candidate match and reset immediately
/// after the gate check.
///
/// # Invariants
/// - **All counters must be zero before and after each entropy check.**
///   The histogram loop increments bins and the reset zeroes the entire
///   array via `memset`. This trades O(256) reset cost for a branchless
///   histogram loop (no per-byte "first touch" tracking), which is a net
///   win since the histogram loop runs N times (N = input length) while
///   the reset runs once.
#[derive(Clone, Copy)]
pub(super) struct EntropyScratch {
    /// Byte-frequency histogram (256 bins, one per byte value).
    pub(super) counts: [u32; 256],
}

/// Context for mapping decoded spans back to root (encoded) coordinates.
///
/// During transform scans, findings are reported in decoded-byte coordinates.
/// This context captures the encoded span being decoded so that decoded offsets
/// can be translated back to root-buffer offsets for deduplication and output.
///
/// # Raw pointers
///
/// This type stores `*const TransformConfig` and `*const u8` (encoded bytes)
/// to avoid lifetime entanglement with the engine and buffer references.
/// Both pointers reference data owned by the `Engine` (immutable after
/// construction) and the current scan buffer, which outlive the context.
///
/// # Safety contract
/// - `tc` and `encoded_ptr`/`encoded_len` must remain valid while this
///   context is set. The scan loop in `core.rs` clears `root_span_map_ctx`
///   to `None` after each buffer scan completes.
/// - See the `unsafe impl Send` block below for cross-thread reasoning.
#[derive(Clone, Copy)]
pub(super) struct RootSpanMapCtx {
    /// Pointer to the Engine-owned `TransformConfig` for this decode layer.
    tc: *const TransformConfig,
    /// Start of the encoded byte span (in `root_buf` or slab).
    encoded_ptr: *const u8,
    /// Length of the encoded byte span in bytes.
    encoded_len: usize,
    /// Absolute offset of the encoded span's start within the root buffer.
    root_start: usize,
    /// Minimum overlap (in bytes) guaranteed by chunked scans; used to decide
    /// whether a trigger before the match would have appeared in the prior chunk.
    overlap_backscan: usize,
}

impl RootSpanMapCtx {
    /// Creates a new mapping context for the given transform and encoded span.
    pub(super) fn new(
        tc: &TransformConfig,
        encoded: &[u8],
        root_start: usize,
        overlap_backscan: usize,
    ) -> Self {
        Self {
            tc: tc as *const TransformConfig,
            encoded_ptr: encoded.as_ptr(),
            encoded_len: encoded.len(),
            root_start,
            overlap_backscan,
        }
    }

    /// Returns the transform kind for this context.
    ///
    /// # Safety
    ///
    /// The `tc` pointer is valid for the duration of the scan (the engine
    /// outlives all scan operations).
    pub(super) fn transform_id(&self) -> TransformId {
        // SAFETY: tc points to Engine-owned data valid for the scan duration.
        unsafe { &*self.tc }.id
    }

    /// Maps a decoded-byte span back to absolute root-buffer coordinates.
    ///
    /// `span` is expressed in decoded-byte space relative to this context's
    /// encoded segment. Offsets beyond decoded length are clamped by
    /// `map_decoded_offset` to the encoded segment end, so the returned root
    /// range is always within `[root_start, root_start + encoded_len]`.
    pub(super) fn map_span(&self, span: std::ops::Range<usize>) -> std::ops::Range<usize> {
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };
        // SAFETY: `encoded_ptr` and `encoded_len` were captured from a valid slice
        // that outlives the scan; no mutation occurs while this reference is live.
        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let start = map_decoded_offset(tc, encoded, span.start);
        let end = map_decoded_offset(tc, encoded, span.end);
        let root_start = self.root_start;
        (root_start + start)..(root_start + end)
    }

    /// Returns whether a URL-percent trigger (`%` or `+`) appears within the
    /// match span or within the guaranteed overlap prefix preceding it.
    ///
    /// This is intentionally asymmetric: it does not scan bytes *after* the
    /// match, because its only job is to decide whether the previous chunk
    /// could already have observed a trigger.
    ///
    /// Returns `None` if this context is not for a URL-percent transform.
    pub(super) fn has_trigger_before_or_in_match(
        &self,
        root_span: std::ops::Range<usize>,
    ) -> Option<bool> {
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };
        if tc.id != TransformId::UrlPercent {
            return None;
        }

        // SAFETY: `encoded_ptr`/`encoded_len` were captured from a valid slice
        // that outlives the scan; no mutation occurs while this reference is live.
        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let plus_to_space = tc.plus_to_space;
        let span_start = root_span
            .start
            .saturating_sub(self.root_start)
            .min(self.encoded_len);
        let span_end = root_span
            .end
            .saturating_sub(self.root_start)
            .min(self.encoded_len);
        let scan_start = span_start
            .saturating_sub(self.overlap_backscan)
            .min(self.encoded_len);
        let scan_end = span_end.min(self.encoded_len);

        if scan_start >= scan_end {
            return Some(false);
        }

        let mut has_trigger = false;
        for &b in &encoded[scan_start..scan_end] {
            if is_url_trigger(b, plus_to_space) {
                has_trigger = true;
                break;
            }
        }
        Some(has_trigger)
    }

    /// Returns an extended drop boundary for URL-percent matches, or `None`.
    ///
    /// # Returns
    /// - `Some(offset)` if a trigger (`%` or `+`) exists after the match span
    ///   and no trigger appears within the overlap prefix before the match.
    ///   The returned offset extends past the first post-match trigger.
    /// - `None` if this is not a URL-percent transform, or if a trigger already
    ///   exists within the overlap window (which means the prior chunk would
    ///   have included this trigger, so no extension is needed).
    ///
    /// # Rationale
    /// URL-percent runs can begin with raw ASCII before the first `%` or `+`.
    /// If the match lands in that raw prefix, the normal match-end boundary
    /// would allow a later chunk (starting at the trigger) to re-emit the
    /// same match. Extending the drop boundary past the trigger prevents
    /// duplicate findings across chunk boundaries.
    ///
    /// # Worked example
    ///
    /// ```text
    /// encoded: "token=AAAA%3Dvalue"
    ///                 ^^^^         ← match (raw ASCII prefix)
    ///                     ^        ← first trigger '%' at offset 14
    ///
    /// Chunk 1 overlap: 4 bytes before match — no trigger in overlap.
    /// → drop_hint_end = 15 (past the '%')
    ///
    /// Chunk 2 starts at the '%', re-decodes, and could re-find "AAAA".
    /// But drop_prefix_findings(15) discards it because 15 > match_end.
    ///
    /// If a trigger *did* exist in the overlap (e.g., "x%2Btoken=AAAA%3D"),
    /// the prior chunk already saw the trigger, so Chunk 2's transform
    /// start would not produce a novel decode — no extension needed.
    /// ```
    pub(super) fn drop_hint_end_for_match(
        &self,
        match_span: std::ops::Range<usize>,
    ) -> Option<usize> {
        // SAFETY: The engine-owned transform config lives for the duration
        // of the scan, and encoded bytes are valid while the map context is set.
        let tc = unsafe { &*self.tc };

        // Base64: extend drop boundary to the end of the encoded region.
        //
        // A base64 region is only fully decodable when the entire encoded span
        // (including `=` padding) is visible in the chunk. Findings within the
        // decoded output are therefore only discoverable once the chunk extends
        // past the encoded region boundary. Using `root_span_hint.end` alone
        // can leave `drop_hint_end` *inside* the encoded region, causing
        // `drop_prefix_findings` to incorrectly discard findings that were
        // never emitted by a prior (shorter) chunk.
        //
        // Extending to `root_start + encoded_len` ensures the finding survives
        // until the overlap window fully covers the encoded span.
        if tc.id == TransformId::Base64 {
            return Some(self.root_start + self.encoded_len);
        }

        if tc.id != TransformId::UrlPercent {
            return None;
        }

        // SAFETY: `encoded_ptr`/`encoded_len` were captured from a valid slice
        // that outlives the scan; no mutation occurs while this reference is live.
        let encoded = unsafe { std::slice::from_raw_parts(self.encoded_ptr, self.encoded_len) };
        let plus_to_space = tc.plus_to_space;
        let span_end = match_span
            .end
            .saturating_sub(self.root_start)
            .min(self.encoded_len);

        // If a trigger is already within the overlap backscan window (or inside
        // the match), a prior chunk would have had a trigger too, so avoid
        // widening the dedupe boundary and risking duplicates.
        if self
            .has_trigger_before_or_in_match(match_span.clone())
            .unwrap_or(false)
        {
            return None;
        }

        for (idx, &b) in encoded[span_end..].iter().enumerate() {
            if is_url_trigger(b, plus_to_space) {
                return Some(self.root_start + span_end + idx + 1);
            }
        }

        None
    }
}

// SAFETY: RootSpanMapCtx stores raw `*const` pointers (`tc`, `encoded_ptr`)
// which make the type !Send by default. The impl is sound because:
//   1. Both pointers reference Engine-owned data that is immutable after
//      construction and outlives all scratch instances (Engine: 'static).
//   2. The context is only populated during a scan and cleared to `None`
//      after each buffer scan completes (core.rs), so no pointer is live
//      when the scratch is moved between threads (e.g., thread-pool reuse).
//   3. Precedent: `RealEngineScratch` in scheduler/engine_impl.rs uses the
//      same pattern for the same reasons.
unsafe impl Send for RootSpanMapCtx {}

impl EntropyScratch {
    /// Returns a zeroed histogram.
    pub(super) fn new() -> Self {
        Self {
            counts: [0u32; 256],
        }
    }

    /// Zeroes all 256 histogram bins.
    ///
    /// This is O(256) via `memset`, which on modern ARM (stp loop) is very
    /// fast — typically 2-3 ns for 1 KiB. The constant cost eliminates the
    /// per-byte branch that the previous "touched list" approach required
    /// in the histogram loop.
    #[inline]
    pub(super) fn reset(&mut self) {
        self.counts = [0u32; 256];
    }
}

/// Zero-sized alignment marker that forces a 64-byte cache-line boundary
/// between the hot and cold regions of [`ScanScratch`].
///
/// Placed as a field inside a `#[repr(C)]` struct, this ensures the next
/// field begins on a fresh cache line. The `[u8; 0]` body contributes no
/// bytes to the struct size — only the `#[repr(align(64))]` attribute
/// matters, which the compiler satisfies by inserting padding before this
/// field (not after it) in the `#[repr(C)]` layout.
#[repr(align(64))]
struct CachelineBoundary {
    _pad: [u8; 0],
}

impl CachelineBoundary {
    const fn new() -> Self {
        Self { _pad: [] }
    }
}

/// Per-scan scratch state reused across chunks.
///
/// This is the main allocation amortization vehicle: it owns buffers for window
/// accumulation, decode slabs, and work queues.
///
/// # Guarantees
/// - Steady-state scans reuse allocations; buffers may grow only if the engine's
///   rule set or tuning increases between scans.
/// - Findings are recorded as compact [`FindingRec`] entries until drained or
///   materialized.
///
/// # Invariants
/// - Not thread-safe; use by a single worker at a time.
/// - Contents (including slices from [`ScanScratch::findings`]) are invalidated
///   by `reset_for_scan` and any draining/mutation method.
/// - **Parallel-array invariant**: `out`, `norm_hash`, and `drop_hint_end`
///   are kept length-aligned at all times. Every push, truncation, or drain
///   must maintain this lock-step relationship. Violating it corrupts finding
///   deduplication and materialization.
///
/// # Performance
/// - Fixed-capacity buffers cap per-scan work; overflow increments
///   [`ScanScratch::dropped_findings`].
///
/// # Layout — hot / cold split
///
/// `#[repr(C)]` preserves declared field order so the explicit 64-byte
/// boundary between hot and cold regions remains stable.
///
/// **Hot region** (before `_cold_boundary`): fields touched on *every* scan
/// chunk — output buffers, the work queue, hit accumulators, per-rule
/// capture locations, the prefilter scratch, and the merged-window buffers.
/// These dominate L1/L2 cache residency during the inner scan loop.
///
/// **Cold region** (after `_cold_boundary`): fields touched only when a
/// transform fires (decode slab, ring buffer, pending windows, stream
/// state), when emitting findings for cross-chunk deduplication (`seen_findings`), or for
/// Vectorscan scratch management. Separating them avoids polluting the
/// hot cache lines when transforms are inactive (the common case for
/// many file types).
///
/// **Per-chunk region** (after VS scratch fields): fields written once
/// per chunk or only under `perf-stats` / `debug_assertions`. Includes
/// safelist/offline suppression counters, the one-shot prefilter flags,
/// overlap metadata, and the capacity-validated sentinel. Placing these
/// after the cold region keeps them off cache lines touched by the inner
/// scan loop and the transform decode path.
///
/// The `_cold_boundary` marker forces the first cold field (`slab`) to
/// begin at a cache-line boundary, reducing false sharing between regions.
#[repr(C)]
pub struct ScanScratch {
    // ---------------- Hot scan-loop region ----------------
    /// Per-chunk finding records awaiting materialization.
    ///
    /// Compact records are stored here during scanning; they are expanded into
    /// full `Finding` structs with provenance during materialization. Fixed
    /// capacity prevents allocation in the hot path; overflow increments
    /// `findings_dropped` instead of reallocating.
    pub(super) out: ScratchVec<FindingRec>,
    /// Normalized hash for each finding (aligned with `out`).
    pub(super) norm_hash: ScratchVec<NormHash>,
    /// Drop boundary used by `drop_prefix_findings` (absolute offset in file).
    pub(super) drop_hint_end: ScratchVec<u64>,
    /// Per-chunk finding emission cap, derived from `tuning.max_findings_per_chunk`.
    pub(super) max_findings: usize,
    /// Number of findings that could not be emitted because the cap was reached.
    pub(super) findings_dropped: usize,
    /// Work queue for breadth-first buffer traversal.
    ///
    /// Contains the root buffer plus any decoded buffers from transforms.
    /// Append-only during a scan; `work_head` advances monotonically as items
    /// are consumed. Fixed capacity ensures no allocations during the scan
    /// loop; the tuning parameter `max_work_items` determines the upper bound.
    pub(super) work_q: ScratchVec<WorkItem>,
    /// Monotonically advancing cursor into `work_q`; items at indices
    /// `[0..work_head)` have been processed.
    pub(super) work_head: usize,
    /// Per-scan dedupe set used to detect duplicates within a single chunk scan.
    ///
    /// This resets every `scan_chunk_into` and lets us prefer more informative
    /// findings within a scan while suppressing repeats across chunks.
    pub(super) seen_findings_scan: FixedSet128,
    /// Cumulative decoded bytes produced so far in this scan (budget tracker
    /// against `tuning.max_total_decode_output_bytes`).
    pub(super) total_decode_output_bytes: usize,
    /// Number of work items enqueued so far (budget tracker against
    /// `tuning.max_work_items`).
    pub(super) work_items_enqueued: usize,
    /// Per-rule regex capture locations (reused to avoid per-scan allocations).
    pub(super) capture_locs: Vec<Option<CaptureLocations>>,
    /// Per-rule stream hit counts for decoded-window seeding.
    ///
    /// Indexing is `rule_id * 3 + variant_idx` (Raw/Utf16Le/Utf16Be).
    pub(super) stream_hit_counts: Vec<u32>,
    /// Scratch list of touched stream hit counters for fast reset.
    pub(super) stream_hit_touched: ScratchVec<u32>,
    pub(super) hit_acc_pool: HitAccPool, // Per-(rule, variant) hit accumulator pool.
    pub(super) touched_pairs: ScratchVec<u32>, // Scratch list of touched pairs (unique).
    pub(super) windows: ScratchVec<SpanU32>, // Merged windows for a pair.
    pub(super) expanded: ScratchVec<SpanU32>, // Expanded windows for two-phase rules.
    pub(super) spans: ScratchVec<SpanU32>, // Transform span candidates.
    /// Decode provenance arena.
    ///
    /// Stores parent-linked decode steps so findings can reconstruct their
    /// full transform chain without per-finding allocation. Fixed capacity
    /// bounds memory usage; the arena is reset between chunks.
    pub(super) step_arena: StepArena,
    /// UTF-16 to UTF-8 transcoding buffer.
    ///
    /// Used when scanning UTF-16LE/BE variants of the input buffer. Fixed
    /// capacity sized to the maximum window size ensures no allocation during
    /// variant scanning.
    pub(super) utf16_buf: ScratchVec<u8>,
    /// Scratch buffer for materializing decode step chains.
    ///
    /// When a finding is emitted, its `StepId` is traced through the arena to
    /// reconstruct the full decode path. This buffer holds the reversed chain
    /// during materialization. Capacity is bounded by `max_transform_depth`.
    pub(super) steps_buf: ScratchVec<DecodeStep>,
    // --------------- Cache-line boundary ----------------
    _cold_boundary: CachelineBoundary,

    // ---------------- Cold / conditional region ----------------
    /// Pre-allocated decoded-output slab. Never reallocated during a scan;
    /// all `unsafe` slice construction in the work-queue loop relies on this
    /// stability invariant.
    pub(super) slab: DecodeSlab,
    /// Bloom-style dedupe set for decoded buffer identity.
    ///
    /// Avoids re-scanning identical decoded output across different transform
    /// spans within a single chunk. Keyed on decoded content hash.
    pub(super) seen: FixedSet128,
    /// Bloom-style deduplication for output findings within a file.
    ///
    /// Prevents emitting the same finding multiple times when overlapping chunks
    /// or transform re-scans produce identical matches. The set is reset on file
    /// boundary transitions (new file).
    ///
    /// Key composition (32 bytes = one AEGIS-128L absorption block → 128-bit hash):
    /// - `file_id` (4 bytes) — scoped to current file
    /// - `rule_id | variant_disc << 24` (4 bytes) — rule + UTF-16 endianness discriminator
    /// - `span_start`, `span_end` (8 bytes) — root-level span (zeroed for mapped transforms)
    /// - `root_hint_start`, `root_hint_end` (16 bytes) — dedupe boundary in root coordinates
    ///
    /// Transform-derived findings use zeroed span coordinates when a precise
    /// root-span mapping exists because the same encoded region can decode to
    /// different offsets across chunk boundaries. When mapping is unavailable,
    /// the decoded span is included to keep distinct matches separate.
    pub(super) seen_findings: FixedSet128,
    /// Streaming decoded-byte ring buffer for window capture.
    pub(super) decode_ring: ByteRing,
    /// Temporary buffer for materializing decoded windows from the ring.
    pub(super) window_bytes: Vec<u8>,
    /// Reusable batch buffer for collecting drained pending windows.
    ///
    /// Used by `decode_stream_and_scan` to collect expired windows from the
    /// timing wheel before processing them, avoiding the need for raw-pointer
    /// aliasing during the drain callback.
    pub(super) drain_batch: Vec<PendingWindow>,
    /// Pending window timing wheel (exact, G=1) keyed by `hi` for decoded stream verification.
    pub(super) pending_windows: TimingWheel<PendingWindow, 1>,
    /// Max window horizon used to size the timing wheel (max window radius + stream chunk).
    pub(super) pending_window_horizon_bytes: u64,
    /// Match windows produced by the Vectorscan stream callback.
    pub(super) vs_stream_matches: Vec<VsStreamWindow>,
    /// Pending decode spans captured during streaming decode.
    pub(super) pending_spans: Vec<PendingDecodeSpan>,
    /// Span detectors for nested transforms in decoded streams.
    pub(super) span_streams: Vec<SpanStreamEntry>,
    /// Temporary findings buffer for a decoded stream (dedupe-aware).
    pub(super) tmp_findings: Vec<FindingRec>,
    /// Drop boundaries aligned with `tmp_findings`.
    pub(super) tmp_drop_hint_end: Vec<u64>,
    /// Normalized hashes aligned with `tmp_findings`.
    pub(super) tmp_norm_hash: Vec<NormHash>,
    /// Entropy histogram scratch. `None` when no rules have entropy gates,
    /// avoiding a 1 KiB heap allocation for engines that don't need it.
    pub(super) entropy_scratch: Option<Box<EntropyScratch>>,
    /// Active decoded→root coordinate mapping context (set during transform scans).
    ///
    /// Set by the scan loop before scanning a decoded buffer and cleared after
    /// each buffer scan completes. When `Some`, findings from decoded buffers
    /// use this context to map spans back to root-buffer offsets.
    pub(super) root_span_map_ctx: Option<RootSpanMapCtx>,
    /// Absolute byte offset of the most recent chunk within the current file.
    pub(super) last_chunk_start: u64,
    /// Length in bytes of the most recent chunk.
    pub(super) last_chunk_len: usize,
    /// File ID of the most recent chunk (used to detect file transitions
    /// and reset cross-chunk dedup state).
    pub(super) last_file_id: Option<FileId>,

    /// Per-thread Vectorscan scratch space for the unified prefilter DB.
    ///
    /// Vectorscan requires each scanning thread to have its own scratch memory.
    /// Used for raw-buffer scanning (anchors + regex patterns in block mode).
    pub(super) vs_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 anchor prefiltering.
    /// Used for UTF-16 variant anchor scanning in block mode on raw buffers.
    pub(super) vs_utf16_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for UTF-16 stream anchor scanning.
    /// Used for streaming UTF-16 anchor detection in decoded byte streams.
    pub(super) vs_utf16_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for stream-mode scanning.
    /// Used for decoded-stream regex prefiltering in streaming mode.
    pub(super) vs_stream_scratch: Option<VsScratch>,
    /// Per-thread Vectorscan scratch space for decoded gate scanning.
    /// Used for anchor gating in decoded transform output (e.g., base64 decoded bytes).
    pub(super) vs_gate_scratch: Option<VsScratch>,

    // --- Per-chunk / debug-only fields (set once per chunk or rarer) ---
    /// Findings removed by the global context safelist at emission time.
    /// Incremented only when both `perf-stats` and `debug_assertions` are
    /// enabled; accessor returns 0 otherwise.
    pub(super) safelist_suppressed: usize,
    /// Findings removed by the secret-bytes safelist at emission time.
    /// Incremented only when both `perf-stats` and `debug_assertions` are
    /// enabled; accessor returns 0 otherwise.
    pub(super) secret_bytes_safelist_suppressed: usize,
    /// Findings removed by the UUID-format quick-reject at emission time.
    /// Incremented only when both `perf-stats` and `debug_assertions` are
    /// enabled; accessor returns 0 otherwise.
    pub(super) uuid_format_suppressed: usize,
    /// Findings removed by post-scan offline structural validation.
    /// Incremented only when both `perf-stats` and `debug_assertions` are
    /// enabled; accessor returns 0 otherwise.
    pub(super) offline_suppressed: usize,
    /// Findings removed by the per-rule confidence-threshold check at emission time.
    /// Incremented only when both `perf-stats` and `debug_assertions` are
    /// enabled; accessor returns 0 otherwise.
    pub(super) confidence_suppressed: usize,
    /// Set by `scan_chunk_into` after running the Vectorscan prefilter on the
    /// root buffer. Consumed (one-shot) by the first `scan_rules_on_buffer`
    /// call so that the root buffer skips redundant prefiltering. Transform
    /// buffer calls see `false` and run the full prefilter as normal.
    pub(super) root_prefilter_done: bool,
    /// Whether the root prefilter detected UTF-16 anchor hits. Paired with
    /// `root_prefilter_done`; only meaningful when that flag is `true`.
    pub(super) root_prefilter_saw_utf16: bool,
    /// Overlap size inferred from the previous chunk in the same file.
    ///
    /// Used to determine whether a transform trigger before a match would have
    /// appeared in the prior chunk, so dedupe boundaries can be widened only
    /// when needed.
    pub(super) chunk_overlap_backscan: usize,
    /// Set after the first `reset_for_scan` validates capacities.
    ///
    /// Since the `Engine` is immutable after construction, capacity checks
    /// are idempotent — they only matter on the first call. Subsequent calls
    /// skip the validation block for reduced per-chunk overhead.
    capacity_validated: bool,

    /// Per-scan Base64 decode/gate instrumentation counters (feature: `b64-stats`).
    #[cfg(feature = "b64-stats")]
    pub(super) base64_stats: Base64DecodeStats,
}

/// Normalize `root_hint_end` for dedup key construction.
///
/// Only Base64 transforms have 4/3 padding rules that cause the encoded-region
/// length to vary by up to 3 bytes for identical decoded content. Other
/// transforms (e.g. UrlPercent) preserve length exactly and must not be
/// normalized.
///
/// For Base64 non-root findings, snaps `root_hint_end` to the padding-free
/// minimum if the actual encoded length exceeds it by 1–3 bytes.
#[inline(always)]
fn normalize_root_hint_end_for_dedup(rec: &FindingRec, leaf_transform: Option<TransformId>) -> u64 {
    if rec.step_id == STEP_ROOT {
        return rec.root_hint_end;
    }
    if leaf_transform != Some(TransformId::Base64) {
        return rec.root_hint_end;
    }
    let decoded_len = rec.span_end.saturating_sub(rec.span_start) as u64;
    // Base64 encodes 3 bytes → 4 chars; inverse: min_encoded = ⌈decoded × 4/3⌉.
    let min_encoded = (decoded_len * 4).div_ceil(3);
    let actual_encoded = rec.root_hint_end.saturating_sub(rec.root_hint_start);
    if actual_encoded > min_encoded && actual_encoded <= min_encoded.saturating_add(3) {
        rec.root_hint_start.saturating_add(min_encoded)
    } else {
        rec.root_hint_end
    }
}

impl ScanScratch {
    /// Allocates scratch state sized to the given engine's rules and tuning.
    ///
    /// All fixed-capacity buffers are pre-allocated here. Subsequent scans
    /// reuse these allocations unless the engine's configuration has grown.
    pub(super) fn new(engine: &Engine) -> Self {
        let rules_len = engine.rules_hot.len();
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        let max_findings = engine.tuning.max_findings_per_chunk;
        let pair_count = rules_len.checked_mul(3).expect("rule pair count overflow");
        let hit_acc_pool =
            HitAccPool::new(pair_count, engine.tuning.max_anchor_hits_per_rule_variant)
                .expect("hit accumulator pool allocation failed");

        let max_steps = engine.tuning.max_work_items.saturating_add(
            rules_len.saturating_mul(2 * engine.tuning.max_windows_per_rule_variant),
        );
        // Decoded-buffer identity dedupe set: sized to ~2× the max work items
        // (each work item can produce a decoded buffer). Power-of-two for
        // efficient modular hashing. Floor of 1024 keeps the set effective
        // even when work-item limits are small.
        let seen_cap = pow2_at_least(
            engine
                .tuning
                .max_work_items
                .next_power_of_two()
                .saturating_mul(2)
                .max(1024),
        );
        let findings_cap = pow2_at_least(
            max_findings
                .max(1)
                .saturating_mul(FINDING_DEDUPE_MULTIPLIER)
                .max(64),
        );
        // rules × 3 variants (Raw/Utf16Le/Utf16Be) × max windows per variant.
        let pending_window_cap = rules_len
            .saturating_mul(3)
            .saturating_mul(engine.tuning.max_windows_per_rule_variant)
            .max(16);
        // Keep callback staging capacity aligned with pending-window capacity:
        // stream callbacks can emit at most one staging entry per eventual
        // pending window, and overflow flips decode-stream fallback to full scan.
        let stream_match_cap = pending_window_cap;
        let max_radius_bytes = (engine.max_window_diameter_bytes / 2) as u64;
        let pending_window_horizon_bytes =
            max_radius_bytes.saturating_add(STREAM_DECODE_CHUNK_BYTES as u64);
        let has_active_transforms = engine
            .transforms
            .iter()
            .any(|tc| tc.mode != TransformMode::Disabled);
        let has_entropy_gates = !engine.entropy_gates.is_empty();

        Self {
            out: ScratchVec::with_capacity(max_findings).expect("scratch out allocation failed"),
            norm_hash: ScratchVec::with_capacity(max_findings)
                .expect("scratch norm_hash allocation failed"),
            drop_hint_end: ScratchVec::with_capacity(max_findings)
                .expect("scratch drop_hint_end allocation failed"),
            max_findings,
            findings_dropped: 0,
            work_q: ScratchVec::with_capacity(engine.tuning.max_work_items.saturating_add(1))
                .expect("scratch work_q allocation failed"),
            work_head: 0,
            slab: DecodeSlab::with_limit(engine.tuning.max_total_decode_output_bytes),
            seen: FixedSet128::with_pow2(seen_cap),
            seen_findings: FixedSet128::with_pow2(findings_cap),
            seen_findings_scan: FixedSet128::with_pow2(findings_cap),
            total_decode_output_bytes: 0,
            work_items_enqueued: 0,
            decode_ring: if has_active_transforms {
                ByteRing::with_capacity(engine.stream_ring_bytes)
            } else {
                ByteRing::with_capacity(1)
            },
            window_bytes: if has_active_transforms {
                Vec::with_capacity(engine.stream_ring_bytes)
            } else {
                Vec::new()
            },
            drain_batch: Vec::new(),
            pending_windows: if has_active_transforms {
                TimingWheel::new(pending_window_horizon_bytes, pending_window_cap)
            } else {
                TimingWheel::new(1, 16)
            },
            pending_window_horizon_bytes: if has_active_transforms {
                pending_window_horizon_bytes
            } else {
                1
            },
            vs_stream_matches: if has_active_transforms {
                Vec::with_capacity(stream_match_cap)
            } else {
                Vec::new()
            },
            pending_spans: if has_active_transforms {
                Vec::with_capacity(max_spans.max(16))
            } else {
                Vec::new()
            },
            span_streams: if has_active_transforms {
                Vec::with_capacity(engine.transforms.len())
            } else {
                Vec::new()
            },
            tmp_findings: if has_active_transforms {
                Vec::with_capacity(max_findings)
            } else {
                Vec::new()
            },
            tmp_drop_hint_end: if has_active_transforms {
                Vec::with_capacity(max_findings)
            } else {
                Vec::new()
            },
            tmp_norm_hash: if has_active_transforms {
                Vec::with_capacity(max_findings)
            } else {
                Vec::new()
            },
            capture_locs: engine
                .rules_hot
                .iter()
                .map(|rule| Some(rule.re.capture_locations()))
                .collect(),
            stream_hit_counts: vec![0u32; rules_len.saturating_mul(3)],
            stream_hit_touched: ScratchVec::with_capacity(rules_len.saturating_mul(3))
                .expect("scratch stream_hit_touched allocation failed"),
            hit_acc_pool,
            touched_pairs: ScratchVec::with_capacity(pair_count)
                .expect("scratch touched_pairs allocation failed"),
            windows: ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                .expect("scratch windows allocation failed"),
            expanded: ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed"),
            spans: ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed"),
            step_arena: StepArena {
                nodes: ScratchVec::with_capacity(max_steps)
                    .expect("scratch step_arena.nodes allocation failed"),
            },
            utf16_buf: ScratchVec::with_capacity(engine.tuning.max_utf16_decoded_bytes_per_window)
                .expect("scratch utf16_buf allocation failed"),
            entropy_scratch: if has_entropy_gates {
                Some(Box::new(EntropyScratch::new()))
            } else {
                None
            },
            steps_buf: ScratchVec::with_capacity(
                engine.tuning.max_transform_depth.saturating_add(1),
            )
            .expect("scratch steps_buf allocation failed"),
            vs_scratch: engine.vs.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan scratch allocation failed")
            }),
            vs_utf16_scratch: engine.vs_utf16.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan utf16 scratch allocation failed")
            }),
            vs_utf16_stream_scratch: engine.vs_utf16_stream.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan utf16 stream scratch allocation failed")
            }),
            vs_stream_scratch: engine.vs_stream.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan stream scratch allocation failed")
            }),
            vs_gate_scratch: engine.vs_gate.as_ref().map(|db| {
                db.alloc_scratch()
                    .expect("vectorscan gate scratch allocation failed")
            }),
            root_span_map_ctx: None,
            root_prefilter_done: false,
            root_prefilter_saw_utf16: false,
            chunk_overlap_backscan: 0,
            capacity_validated: false,
            _cold_boundary: CachelineBoundary::new(),
            safelist_suppressed: 0,
            secret_bytes_safelist_suppressed: 0,
            uuid_format_suppressed: 0,
            offline_suppressed: 0,
            confidence_suppressed: 0,
            last_chunk_start: 0,
            last_chunk_len: 0,
            last_file_id: None,
            #[cfg(feature = "b64-stats")]
            base64_stats: Base64DecodeStats::default(),
        }
    }

    /// Returns a mutable reference to the entropy scratch histogram,
    /// allocating it on first use.
    ///
    /// `entropy_scratch` is stored as `Option<Box<EntropyScratch>>` so
    /// engines with no entropy gates pay zero heap cost for the 1 KiB
    /// histogram. The first call from an entropy gate allocates the box;
    /// subsequent calls return the existing allocation.
    #[inline(always)]
    pub(super) fn ensure_entropy_scratch(&mut self) -> &mut EntropyScratch {
        self.entropy_scratch
            .get_or_insert_with(|| Box::new(EntropyScratch::new()))
            .as_mut()
    }

    /// Clears per-scan state and revalidates scratch capacities against the engine.
    ///
    /// This may reallocate scratch buffers if the engine's tuning, rule set, or
    /// Vectorscan databases grew since the last scan. All previously returned
    /// slices into scratch buffers are invalid after this call.
    ///
    /// After the first successful call, capacity validation is skipped because
    /// `Engine` is immutable after construction — all checks are idempotent.
    pub(super) fn reset_for_scan(&mut self, engine: &Engine) {
        self.reset_common();

        // ── Per-scan accumulator resets (must always run) ────────────────
        self.hit_acc_pool
            .reset_touched(self.touched_pairs.as_slice());
        self.touched_pairs.clear();
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        self.ensure_capacity(engine);
    }

    /// Resets per-scan state like `reset_for_scan` but **preserves** the
    /// prefilter results already stored in `hit_acc_pool` and `touched_pairs`.
    ///
    /// # Why a separate method?
    ///
    /// `scan_chunk_into` runs the Vectorscan prefilter *before* the per-rule
    /// scan loop. The prefilter populates `hit_acc_pool` with anchor hits and
    /// records which (rule, variant) pairs were touched in `touched_pairs`.
    /// A full `reset_for_scan` would discard that work. This method clears
    /// everything *except* the accumulator state, so the scan loop can
    /// immediately consume the prefilter results without re-scanning.
    pub(super) fn reset_for_scan_after_prefilter(&mut self, engine: &Engine) {
        self.reset_common();

        // ── Skip hit_acc_pool / touched_pairs reset ─────────────────────
        // Prefilter results are preserved; only clear the auxiliary buffers.
        self.windows.clear();
        self.expanded.clear();
        self.spans.clear();

        self.ensure_capacity(engine);
    }

    /// Clear all per-scan transient state.
    ///
    /// Shared by `reset_for_scan` and `reset_for_scan_after_prefilter`.
    /// Does **not** touch accumulators (`hit_acc_pool`, `touched_pairs`) or
    /// auxiliary buffers (`windows`, `expanded`, `spans`) — the caller
    /// decides whether to reset those based on whether prefilter results
    /// should be preserved.
    #[inline(always)]
    fn reset_common(&mut self) {
        debug_assert!(
            self.root_span_map_ctx.is_none(),
            "root_span_map_ctx must be cleared before scratch reuse"
        );
        self.out.clear();
        self.norm_hash.clear();
        self.drop_hint_end.clear();
        self.findings_dropped = 0;
        self.safelist_suppressed = 0;
        self.secret_bytes_safelist_suppressed = 0;
        self.uuid_format_suppressed = 0;
        self.offline_suppressed = 0;
        self.confidence_suppressed = 0;
        self.work_q.clear();
        self.work_head = 0;
        self.slab.reset();
        self.seen.reset();
        self.seen_findings_scan.reset();
        self.total_decode_output_bytes = 0;
        self.work_items_enqueued = 0;
        self.decode_ring.reset();
        self.window_bytes.clear();
        self.drain_batch.clear();
        self.pending_windows.reset();
        self.vs_stream_matches.clear();
        self.pending_spans.clear();
        self.span_streams.clear();
        self.tmp_findings.clear();
        self.tmp_drop_hint_end.clear();
        self.tmp_norm_hash.clear();
        // Sparse reset: zero only the stream-hit counters that were
        // incremented (O(touched) instead of O(rules × 3)).
        for idx in self.stream_hit_touched.drain() {
            let slot = idx as usize;
            if let Some(hit) = self.stream_hit_counts.get_mut(slot) {
                *hit = 0;
            }
        }
        self.step_arena.reset();
        self.utf16_buf.clear();
        if let Some(entropy) = self.entropy_scratch.as_mut() {
            entropy.reset();
        }
        self.root_span_map_ctx = None;
        #[cfg(feature = "b64-stats")]
        self.base64_stats.reset();
    }

    /// Idempotent capacity / Vectorscan-scratch validation.
    ///
    /// On the first call, validates and potentially reallocates all scratch
    /// buffers to match the engine's current tuning and rule set. Subsequent
    /// calls are no-ops because `Engine` is immutable after construction.
    ///
    /// Capacity policy is monotonic: buffers only grow (never shrink) so long
    /// scans do not thrash allocations. `reset_for_scan*` handles per-scan
    /// clears; this method handles structural compatibility with the engine:
    /// - Vectorscan scratch bindings still match the current DB pointers
    /// - per-rule/variant accumulators are large enough for current limits
    /// - bounded sidecar vectors (`out`, `norm_hash`, `drop_hint_end`) remain
    ///   aligned and large enough for `max_findings`
    pub(super) fn ensure_capacity(&mut self, engine: &Engine) {
        if self.capacity_validated {
            return;
        }

        // ── 1. Vectorscan scratch rebinding ───────────────────────────────
        //
        // Five DB/scratch pairs each check whether the scratch is still bound
        // to the current DB pointer and reallocate if not.
        macro_rules! rebind_vs_scratch {
            ($db_field:expr, $scratch_field:expr, $label:literal) => {
                match $db_field.as_ref() {
                    Some(db) => {
                        let need_alloc = match $scratch_field.as_ref() {
                            Some(s) => s.bound_db_ptr() != db.db_ptr(),
                            None => true,
                        };
                        if need_alloc {
                            $scratch_field = Some(db.alloc_scratch().expect(concat!(
                                "vectorscan ",
                                $label,
                                " scratch allocation failed"
                            )));
                        }
                    }
                    None => {
                        $scratch_field = None;
                    }
                }
            };
        }
        rebind_vs_scratch!(engine.vs, self.vs_scratch, "prefilter");
        rebind_vs_scratch!(engine.vs_utf16, self.vs_utf16_scratch, "utf16");
        rebind_vs_scratch!(
            engine.vs_utf16_stream,
            self.vs_utf16_stream_scratch,
            "utf16 stream"
        );
        rebind_vs_scratch!(engine.vs_stream, self.vs_stream_scratch, "stream");
        rebind_vs_scratch!(engine.vs_gate, self.vs_gate_scratch, "gate");

        // ── 2. Hit accumulator pool + per-rule/variant vectors ──────────
        //
        // `expected_pairs` = rules × 3 variants (Raw, Utf16Le, Utf16Be).
        let expected_pairs = engine.rules_hot.len().saturating_mul(3);
        let max_hits_u32 =
            u32::try_from(engine.tuning.max_anchor_hits_per_rule_variant).unwrap_or(u32::MAX);
        let accs_need_rebuild = self.hit_acc_pool.pair_count() != expected_pairs
            || self.hit_acc_pool.max_hits() < max_hits_u32;
        if accs_need_rebuild {
            self.hit_acc_pool = HitAccPool::new(
                expected_pairs,
                engine.tuning.max_anchor_hits_per_rule_variant,
            )
            .expect("hit accumulator pool allocation failed");
        }
        if self.touched_pairs.capacity() < expected_pairs {
            self.touched_pairs = ScratchVec::with_capacity(expected_pairs)
                .expect("scratch touched_pairs allocation failed");
        }
        let max_spans = engine
            .transforms
            .iter()
            .map(|tc| tc.max_spans_per_buffer)
            .max()
            .unwrap_or(0);
        if self.spans.capacity() < max_spans {
            self.spans =
                ScratchVec::with_capacity(max_spans).expect("scratch spans allocation failed");
        }
        if self.windows.capacity() < engine.tuning.max_anchor_hits_per_rule_variant {
            self.windows =
                ScratchVec::with_capacity(engine.tuning.max_anchor_hits_per_rule_variant)
                    .expect("scratch windows allocation failed");
        }
        if self.expanded.capacity() < engine.tuning.max_windows_per_rule_variant {
            self.expanded = ScratchVec::with_capacity(engine.tuning.max_windows_per_rule_variant)
                .expect("scratch expanded allocation failed");
        }
        let stream_hits_len = engine.rules_hot.len().saturating_mul(3);
        if self.stream_hit_counts.len() != stream_hits_len {
            self.stream_hit_counts = vec![0u32; stream_hits_len];
            self.stream_hit_touched =
                ScratchVec::with_capacity(stream_hits_len).expect("scratch stream hits");
        } else if self.stream_hit_touched.capacity() < stream_hits_len {
            self.stream_hit_touched =
                ScratchVec::with_capacity(stream_hits_len).expect("scratch stream hits");
        }
        // ── 3. Finding output buffers (parallel-array invariant) ─────────
        if self.max_findings != engine.tuning.max_findings_per_chunk {
            self.max_findings = engine.tuning.max_findings_per_chunk;
        }
        if self.out.capacity() < self.max_findings {
            self.out = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch out allocation failed");
        }
        if self.norm_hash.capacity() < self.max_findings {
            self.norm_hash = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch norm_hash allocation failed");
        }
        if self.drop_hint_end.capacity() < self.max_findings {
            self.drop_hint_end = ScratchVec::with_capacity(self.max_findings)
                .expect("scratch drop_hint_end allocation failed");
        }
        // ── 4. Work queue / decode step arena ───────────────────────────
        if self.work_q.capacity() < engine.tuning.max_work_items.saturating_add(1) {
            self.work_q = ScratchVec::with_capacity(engine.tuning.max_work_items.saturating_add(1))
                .expect("scratch work_q allocation failed");
        }
        let max_steps = engine.tuning.max_work_items.saturating_add(
            engine
                .rules_hot
                .len()
                .saturating_mul(2 * engine.tuning.max_windows_per_rule_variant),
        );
        if self.step_arena.nodes.capacity() < max_steps {
            self.step_arena.nodes = ScratchVec::with_capacity(max_steps)
                .expect("scratch step_arena.nodes allocation failed");
        }
        if self.utf16_buf.capacity() < engine.tuning.max_utf16_decoded_bytes_per_window {
            self.utf16_buf =
                ScratchVec::with_capacity(engine.tuning.max_utf16_decoded_bytes_per_window)
                    .expect("scratch utf16_buf allocation failed");
        }
        let steps_buf_cap = engine.tuning.max_transform_depth.saturating_add(1);
        if self.steps_buf.capacity() < steps_buf_cap {
            self.steps_buf = ScratchVec::with_capacity(steps_buf_cap)
                .expect("scratch steps_buf allocation failed");
        }
        // ── 5. Transform-conditional buffers ──────────────────────────
        //
        // Zero-cost when all transforms are disabled: ring buffer, pending
        // windows, stream matches, and temporary findings are sized to
        // their minimum.
        let has_active_transforms = engine
            .transforms
            .iter()
            .any(|tc| tc.mode != TransformMode::Disabled);
        if has_active_transforms {
            if self.decode_ring.capacity() < engine.stream_ring_bytes {
                self.decode_ring = ByteRing::with_capacity(engine.stream_ring_bytes);
            }
            if self.window_bytes.capacity() < engine.stream_ring_bytes {
                self.window_bytes
                    .reserve(engine.stream_ring_bytes - self.window_bytes.capacity());
            }
            let pending_window_cap = engine
                .rules_hot
                .len()
                .saturating_mul(3)
                .saturating_mul(engine.tuning.max_windows_per_rule_variant)
                .max(16);
            // Keep callback staging capacity aligned with pending-window capacity
            // (same invariant as in `new` above).
            let stream_match_cap = pending_window_cap;
            let max_radius_bytes = (engine.max_window_diameter_bytes / 2) as u64;
            let pending_window_horizon_bytes =
                max_radius_bytes.saturating_add(STREAM_DECODE_CHUNK_BYTES as u64);
            if self.pending_windows.capacity() < pending_window_cap
                || self.pending_window_horizon_bytes < pending_window_horizon_bytes
            {
                self.pending_windows =
                    TimingWheel::new(pending_window_horizon_bytes, pending_window_cap);
                self.pending_window_horizon_bytes = pending_window_horizon_bytes;
            }
            if self.vs_stream_matches.capacity() < stream_match_cap {
                self.vs_stream_matches
                    .reserve(stream_match_cap - self.vs_stream_matches.capacity());
            }
            if self.pending_spans.capacity() < max_spans.max(16) {
                self.pending_spans
                    .reserve(max_spans.max(16) - self.pending_spans.capacity());
            }
            if self.span_streams.capacity() < engine.transforms.len() {
                self.span_streams
                    .reserve(engine.transforms.len() - self.span_streams.capacity());
            }
            if self.tmp_findings.capacity() < self.max_findings {
                self.tmp_findings
                    .reserve(self.max_findings - self.tmp_findings.capacity());
            }
            if self.tmp_drop_hint_end.capacity() < self.max_findings {
                self.tmp_drop_hint_end
                    .reserve(self.max_findings - self.tmp_drop_hint_end.capacity());
            }
            if self.tmp_norm_hash.capacity() < self.max_findings {
                self.tmp_norm_hash
                    .reserve(self.max_findings - self.tmp_norm_hash.capacity());
            }
        }
        // ── 6. Entropy scratch + capture locations ──────────────────────
        if engine.entropy_gates.is_empty() {
            self.entropy_scratch = None;
        } else if self.entropy_scratch.is_none() {
            self.entropy_scratch = Some(Box::new(EntropyScratch::new()));
        }
        if self.capture_locs.len() != engine.rules_hot.len() {
            self.capture_locs = engine
                .rules_hot
                .iter()
                .map(|rule| Some(rule.re.capture_locations()))
                .collect();
        }

        self.capacity_validated = true;
    }

    /// Updates inferred overlap metadata for the current chunk.
    ///
    /// This infers the overlap length by comparing the current chunk start to
    /// the previous chunk end within the same file. Non-overlapping or
    /// out-of-order chunks set the overlap to zero.
    pub(super) fn update_chunk_overlap(
        &mut self,
        file_id: FileId,
        base_offset: u64,
        buf_len: usize,
    ) {
        // Reset finding dedup state on file transitions. This ensures findings
        // from a previous file don't suppress valid findings in the current file.
        //
        // Note: We do NOT reset when base_offset == 0 for the same file, as this
        // would break deduplication for chunked scans with large overlap where
        // base_offset = offset - tail_len can be 0 for continuation chunks.
        // Callers wanting to re-scan the same file should use reset_for_scan().
        if self.last_file_id != Some(file_id) {
            self.seen_findings.reset();
        }

        let mut overlap = 0usize;
        if self.last_file_id == Some(file_id) {
            let last_end = self
                .last_chunk_start
                .saturating_add(self.last_chunk_len as u64);
            if base_offset > self.last_chunk_start {
                if base_offset <= last_end {
                    overlap = (last_end - base_offset) as usize;
                }
            } else if base_offset == self.last_chunk_start && buf_len > self.last_chunk_len {
                // Growing-window case (overlap >= chunk): previous chunk is a prefix.
                overlap = self.last_chunk_len;
            }
        }

        self.chunk_overlap_backscan = overlap;
        self.last_file_id = Some(file_id);
        self.last_chunk_start = base_offset;
        self.last_chunk_len = buf_len;
    }

    /// Returns per-scan base64 decode/gate stats.
    #[cfg(feature = "b64-stats")]
    pub fn base64_stats(&self) -> Base64DecodeStats {
        self.base64_stats
    }

    /// Moves all findings into `out` without allocating.
    ///
    /// # Panics
    /// Panics if `out.capacity()` is smaller than the number of findings.
    pub fn drain_findings(&mut self, out: &mut Vec<FindingRec>) {
        out.clear();
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        assert!(
            out.capacity() >= self.out.len(),
            "output capacity too small"
        );
        out.extend(self.out.drain());
        self.norm_hash.clear();
        self.drop_hint_end.clear();
    }

    /// Moves all findings and aligned normalized hashes without allocating.
    ///
    /// # Panics
    /// Panics if either output vector capacity is smaller than the number of
    /// pending findings.
    pub fn drain_findings_with_hashes(
        &mut self,
        findings_out: &mut Vec<FindingRec>,
        norm_hash_out: &mut Vec<NormHash>,
    ) {
        findings_out.clear();
        norm_hash_out.clear();
        assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        assert!(
            findings_out.capacity() >= self.out.len(),
            "findings output capacity too small"
        );
        assert!(
            norm_hash_out.capacity() >= self.norm_hash.len(),
            "norm-hash output capacity too small"
        );
        findings_out.extend(self.out.drain());
        norm_hash_out.extend(self.norm_hash.drain());
        self.drop_hint_end.clear();
    }

    /// Returns the number of pending compact findings.
    pub fn pending_findings_len(&self) -> usize {
        self.out.len()
    }

    /// Moves all findings into `out`, reusing its allocation.
    ///
    /// See [`ScanScratch::drain_findings`] for capacity requirements.
    pub fn drain_findings_into(&mut self, out: &mut Vec<FindingRec>) {
        self.drain_findings(out);
    }

    /// Materialize decode steps for a finding into the scratch buffer.
    ///
    /// The returned slice is valid until the next call that materializes steps.
    #[cfg(feature = "sim-harness")]
    pub(crate) fn materialize_decode_steps(&mut self, step_id: StepId) -> &[DecodeStep] {
        self.step_arena.materialize(step_id, &mut self.steps_buf);
        self.steps_buf.as_slice()
    }

    /// Drops findings that end at or before the overlap prefix boundary.
    ///
    /// This is used with sliding-window or chunked scans: after advancing the
    /// scan window, remove findings wholly contained in the previous overlap
    /// prefix to avoid duplicate emission.
    ///
    /// # Preconditions
    /// - `new_bytes_start` is the absolute byte offset where the new, non-overlap
    ///   region begins (typically `base_offset + prefix_len`).
    ///
    /// # Effects
    /// - Compacts in place and preserves the relative order of remaining findings.
    ///
    /// For transform-derived findings, the drop boundary may be widened beyond
    /// the match span when a transform trigger occurs after the match and no
    /// trigger appears within the guaranteed overlap prefix before the match.
    /// This avoids dropping findings whose matches appear before late-appearing
    /// triggers (e.g., URL-percent runs with raw prefixes) while preventing
    /// duplicate emission when earlier triggers are already in the overlap.
    pub fn drop_prefix_findings(&mut self, new_bytes_start: u64) {
        if new_bytes_start == 0 {
            return;
        }
        self.retain_findings_aligned(|_rec, drop_end| drop_end > new_bytes_start);
    }

    /// Retains findings in place while keeping all aligned sidecars compacted.
    ///
    /// `keep` receives the finding record plus its aligned drop boundary and must
    /// return `true` to keep the row. Returns the number of rows removed.
    ///
    /// # Algorithm
    ///
    /// Two-pass compaction optimized for the common case where nothing is dropped:
    ///
    /// 1. **Scan pass** — linear scan to find the first dropped row. If none is
    ///    found, returns 0 without touching any sidecar arrays (fast path).
    /// 2. **Compact pass** — from the first drop index onward, copies surviving
    ///    rows into the gap left by dropped rows across all three parallel arrays
    ///    (`out`, `drop_hint_end`, `norm_hash`), then truncates.
    ///
    /// # Contract for `keep`
    ///
    /// `keep` is called exactly once per row. It must be side-effect free and
    /// deterministic for a given input pair.
    #[inline(always)]
    pub(super) fn retain_findings_aligned<F>(&mut self, mut keep: F) -> usize
    where
        F: FnMut(FindingRec, u64) -> bool,
    {
        debug_assert_eq!(
            self.out.len(),
            self.drop_hint_end.len(),
            "drop hint length mismatch"
        );
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );

        let len = self.out.len();
        // Fast path: if all rows are retained, avoid touching any sidecars.
        let mut first_drop_idx = len;
        for read_idx in 0..len {
            let rec = self.out[read_idx];
            let drop_end = self.drop_hint_end.as_slice()[read_idx];
            if !keep(rec, drop_end) {
                first_drop_idx = read_idx;
                break;
            }
        }

        if first_drop_idx == len {
            return 0;
        }

        // Compact in place over three parallel arrays
        // (out, drop_hint_end, norm_hash).
        let mut write_idx = first_drop_idx;
        for read_idx in (first_drop_idx + 1)..len {
            let rec = self.out[read_idx];
            let drop_end = self.drop_hint_end.as_slice()[read_idx];
            if !keep(rec, drop_end) {
                continue;
            }

            // `rec` is already a `Copy` of `self.out[read_idx]`, so this
            // assignment doesn't alias into the same ScratchVec.
            self.out[write_idx] = rec;
            self.drop_hint_end.as_mut_slice()[write_idx] = drop_end;
            let hash = self.norm_hash.as_slice()[read_idx];
            self.norm_hash.as_mut_slice()[write_idx] = hash;
            write_idx += 1;
        }

        self.out.truncate(write_idx);
        self.drop_hint_end.truncate(write_idx);
        self.norm_hash.truncate(write_idx);
        len - write_idx
    }

    /// Returns the drop-boundary offsets aligned 1:1 with [`findings()`].
    #[cfg(any(test, feature = "sim-harness"))]
    pub(crate) fn drop_hint_end(&self) -> &[u64] {
        self.drop_hint_end.as_slice()
    }

    /// Returns the normalized secret hashes aligned 1:1 with [`findings()`].
    pub(crate) fn norm_hashes(&self) -> &[NormHash] {
        self.norm_hash.as_slice()
    }

    /// Returns a shared view of accumulated finding records.
    ///
    /// The slice is invalidated by the next scan or any call that drains
    /// or mutates the scratch buffers.
    ///
    /// Order reflects scan traversal and is not guaranteed to be sorted by span.
    pub fn findings(&self) -> &[FindingRec] {
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        self.out.as_slice()
    }

    /// Returns the number of findings dropped due to capacity/cap enforcement.
    pub fn dropped_findings(&self) -> usize {
        self.findings_dropped
    }

    /// Returns the number of findings removed by emit-time safelist checks.
    ///
    /// Always returns 0 when the `perf-stats` feature is disabled.
    pub fn safelist_suppressed(&self) -> usize {
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            self.safelist_suppressed
        }
        #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
        {
            let _ = &self.safelist_suppressed;
            0
        }
    }

    /// Returns the number of findings removed by the secret-bytes safelist.
    ///
    /// Always returns 0 when the `perf-stats` feature is disabled.
    pub fn secret_bytes_safelist_suppressed(&self) -> usize {
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            self.secret_bytes_safelist_suppressed
        }
        #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
        {
            let _ = &self.secret_bytes_safelist_suppressed;
            0
        }
    }

    /// Returns the number of findings removed by the UUID-format quick-reject.
    ///
    /// Always returns 0 when the `perf-stats` feature is disabled.
    pub fn uuid_format_suppressed(&self) -> usize {
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            self.uuid_format_suppressed
        }
        #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
        {
            let _ = &self.uuid_format_suppressed;
            0
        }
    }

    /// Returns the number of root findings removed by offline validation.
    ///
    /// Always returns 0 when the `perf-stats` feature is disabled.
    pub fn offline_suppressed(&self) -> usize {
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            self.offline_suppressed
        }
        #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
        {
            let _ = &self.offline_suppressed;
            0
        }
    }

    /// Returns the number of findings removed by the per-rule confidence
    /// threshold.
    ///
    /// Always returns 0 when the `perf-stats` feature is disabled.
    pub fn confidence_suppressed(&self) -> usize {
        #[cfg(all(feature = "perf-stats", debug_assertions))]
        {
            self.confidence_suppressed
        }
        #[cfg(not(all(feature = "perf-stats", debug_assertions)))]
        {
            let _ = &self.confidence_suppressed;
            0
        }
    }

    /// Records a finding using `root_hint_end` as the default drop boundary.
    #[cfg(test)]
    pub(super) fn push_finding(&mut self, rec: FindingRec, norm_hash: NormHash) {
        self.push_finding_with_drop_hint(rec, norm_hash, rec.root_hint_end, rec.dedupe_with_span);
    }

    /// Records a finding with an explicit drop boundary, deduplicating against
    /// previously seen findings within the current file.
    ///
    /// # Deduplication Strategy
    ///
    /// Findings are keyed by a fixed 32-byte [`DedupKey`] composite:
    ///
    /// ```text
    /// ┌────────┬──────────────────────┬────────────┬──────────┬─────────────────┬───────────────┐
    /// │file_id │ rule_id_with_variant │ span_start │ span_end │ root_hint_start │ root_hint_end │
    /// │ 4B     │ 4B (24b rule + 8b v) │ 4B         │ 4B       │ 8B              │ 8B            │
    /// └────────┴──────────────────────┴────────────┴──────────┴─────────────────┴───────────────┘
    /// ```
    ///
    /// `rule_id_with_variant` packs a 24-bit rule id plus an 8-bit variant
    /// discriminator. Rule ids above `DEDUP_RULE_ID_MAX` are rejected.
    ///
    /// For transform-derived findings (`step_id != STEP_ROOT`), span coordinates
    /// are zeroed only when a precise root-span mapping is available. When
    /// mapping is unavailable (nested transforms with length-changing parents),
    /// the decoded span is included to avoid collapsing distinct matches that
    /// share the same coarse root hint window.
    ///
    /// # Why Not Just Span Coordinates?
    ///
    /// Chunked scanning with overlap can produce the "same" finding from different
    /// chunk perspectives. The root hint window captures the logical identity of
    /// where the secret lives in the original file, regardless of which chunk
    /// boundary happened to include it.
    ///
    /// # False Positives
    ///
    /// The underlying `FixedSet128` is a probabilistic structure (Bloom-like).
    /// Collisions may suppress distinct findings, but the dedupe table is sized
    /// to `FINDING_DEDUPE_MULTIPLIER × max_findings` to keep load low under
    /// high-candidate scans.
    ///
    /// `include_span` controls whether `span_start`/`span_end` participate in
    /// the dedupe key (used when root-span mapping is unavailable).
    ///
    /// Dedupe is split into two layers:
    /// - A per-file set (`seen_findings`) that suppresses cross-chunk repeats.
    /// - A per-scan set (`seen_findings_scan`) that enables within-scan replacement
    ///   (e.g., prefer transform findings) without re-emitting earlier chunks.
    ///
    /// Replacement lookup is `O(n)` in pending findings (linear scan of `out`)
    /// but bounded by `max_findings_per_chunk`, so it stays predictable.
    #[inline]
    pub(super) fn push_finding_with_drop_hint(
        &mut self,
        rec: FindingRec,
        norm_hash: NormHash,
        drop_hint_end: u64,
        include_span: bool,
    ) {
        crate::perf_counters::record_scan_finding();
        debug_assert_eq!(
            self.out.len(),
            self.norm_hash.len(),
            "norm hash length mismatch"
        );
        // For root-level findings, include the exact span in the dedup key.
        // For transform-derived findings with mapped root spans, zero the span
        // since decoded offsets can vary by chunk alignment. When mapping is
        // unavailable, include the span to preserve distinct matches.
        let include_span = include_span || rec.step_id == STEP_ROOT;
        let (span_start, span_end) = if include_span {
            (rec.span_start, rec.span_end)
        } else {
            (0, 0)
        };
        // Derive the leaf transform from the active root-span mapping context.
        // This is set during transform scans and cleared after each buffer scan.
        let leaf_transform = self
            .root_span_map_ctx
            .as_ref()
            .map(|ctx| ctx.transform_id());
        let normalized_root_hint_end = normalize_root_hint_end_for_dedup(&rec, leaf_transform);

        // Variant discriminator: distinguishes UTF-16 LE/BE findings that
        // otherwise share the same span and root_hint. Without this, both
        // endianness variants would hash to the same dedup key and one would
        // be falsely suppressed. The discriminator is stable across chunks
        // because it depends only on the decode step type, not arena indices.
        let variant_disc: u8 = if rec.step_id != STEP_ROOT {
            self.step_arena.nodes[rec.step_id.0 as usize].variant_discriminant()
        } else {
            0
        };

        // Build a 32-byte dedup key (one AEGIS-128L absorption block) and hash to 128 bits.
        debug_assert!(
            rec.rule_id < (1 << 24),
            "rule_id {:#x} overflows the 24-bit field; upper byte reserved for variant_disc",
            rec.rule_id,
        );
        let key = DedupKey {
            file_id: rec.file_id.0,
            rule_id_with_variant: pack_rule_id_with_variant(rec.rule_id, variant_disc),
            span_start,
            span_end,
            root_hint_start: rec.root_hint_start,
            root_hint_end: normalized_root_hint_end,
        };
        let hash = hash128(bytemuck::bytes_of(&key));
        // `insert` returns `true` if the key was newly added.
        // `seen_in_scan`: true if this key was already present in *this scan*.
        // `is_new`:       true if this key was newly added to the *cross-chunk* set.
        //
        //   is_new │ seen_in_scan │ Action
        //   ───────┼──────────────┼────────────────────────────────────────────
        //    true  │    false     │ Brand-new finding → emit normally (below)
        //    true  │    true      │ Impossible (new in file set can't be old in scan set)
        //    false │    false     │ Prior-chunk duplicate → suppress
        //    false │    true      │ Same-scan duplicate → attempt in-place replacement
        let seen_in_scan = !self.seen_findings_scan.insert(hash);
        let is_new = self.seen_findings.insert(hash);

        if !is_new && !seen_in_scan {
            // Prior-chunk duplicate — suppress to avoid cross-chunk repeats.
            return;
        }

        if !is_new {
            self.replace_same_scan_duplicate(
                rec,
                norm_hash,
                drop_hint_end,
                normalized_root_hint_end,
                leaf_transform,
            );
            return;
        }

        if self.out.len() < self.max_findings {
            debug_assert!(
                self.norm_hash.len() < self.norm_hash.capacity()
                    && self.drop_hint_end.len() < self.drop_hint_end.capacity(),
                "sidecar vector capacity desynced from max_findings ({}) -- \
                 out cap={}, norm_hash cap={}, drop_hint_end cap={}",
                self.max_findings,
                self.out.capacity(),
                self.norm_hash.capacity(),
                self.drop_hint_end.capacity(),
            );
            self.out.push(rec);
            self.norm_hash.push(norm_hash);
            self.drop_hint_end.push(drop_hint_end);
        } else {
            self.findings_dropped = self.findings_dropped.saturating_add(1);
        }
    }

    /// Same-scan duplicate replacement (cold path).
    ///
    /// Extracted from `push_finding_with_drop_hint` to keep the hot fast path
    /// compact for better register allocation and i-cache utilization.
    ///
    /// Replacement policy (most-informative-wins):
    /// 1. Transform findings replace RAW findings (transforms provide decoded
    ///    content that aids triage).
    /// 2. RAW findings never replace an existing transform finding.
    /// 3. Among same-type duplicates, the finding with the larger
    ///    `root_hint_end` wins (wider context window).
    #[cold]
    fn replace_same_scan_duplicate(
        &mut self,
        rec: FindingRec,
        norm_hash: NormHash,
        drop_hint_end: u64,
        normalized_root_hint_end: u64,
        leaf_transform: Option<TransformId>,
    ) {
        for (i, existing) in self.out.as_mut_slice().iter_mut().enumerate() {
            if existing.file_id != rec.file_id || existing.rule_id != rec.rule_id {
                continue;
            }

            // Match criteria vary by finding type:
            //   RAW vs RAW:       exact span + root_hint match
            //   transform vs RAW: root_hint_start match + ≤3-byte padding tolerance
            //   transform vs transform: normalized root_hint match
            let existing_matches = if rec.step_id == STEP_ROOT {
                existing.span_start == rec.span_start
                    && existing.span_end == rec.span_end
                    && existing.root_hint_start == rec.root_hint_start
                    && existing.root_hint_end == rec.root_hint_end
            } else if existing.step_id == STEP_ROOT {
                existing.root_hint_start == rec.root_hint_start
                    && existing.root_hint_end <= normalized_root_hint_end.saturating_add(3)
                    && existing.root_hint_end >= normalized_root_hint_end
            } else {
                existing.root_hint_start == rec.root_hint_start && {
                    let existing_normalized_end =
                        normalize_root_hint_end_for_dedup(existing, leaf_transform);
                    existing_normalized_end == normalized_root_hint_end
                }
            };

            if existing_matches {
                // Dedup replacement priority (highest wins):
                //   1. Transform > RAW (decoded content aids triage).
                //   2. Among same type, prefer wider context (larger root_hint_end).
                //   3. Equal span: keep the higher confidence_score.
                let should_replace = if rec.step_id != STEP_ROOT && existing.step_id == STEP_ROOT {
                    true
                } else if rec.step_id == STEP_ROOT && existing.step_id != STEP_ROOT {
                    false
                } else {
                    rec.root_hint_end > existing.root_hint_end
                        || (rec.root_hint_end == existing.root_hint_end
                            && rec.confidence_score > existing.confidence_score)
                };

                if should_replace {
                    *existing = rec;
                    self.drop_hint_end.as_mut_slice()[i] = drop_hint_end;
                    self.norm_hash.as_mut_slice()[i] = norm_hash;
                }
                return;
            }
        }
    }
}

#[cfg(test)]
#[path = "scratch_tests.rs"]
mod tests;
