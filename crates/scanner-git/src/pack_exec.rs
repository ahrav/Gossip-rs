//! Pack plan executor.
//!
//! Decodes pack objects in plan order, applies deltas with bounded buffers,
//! and emits decoded blob bytes to a caller-provided sink. All skips are
//! recorded with explicit reasons.
//!
//! # Execution model
//! - Offsets are decoded at most once during the planned pass; delta base
//!   cache misses may trigger on-demand re-decodes into scratch buffers.
//! - `inflate_buf`, `result_buf`, and `base_buf` are reused across offsets
//!   to avoid repeated allocations on the hot path.
//! - Oversized blobs and delta outputs are streamed into spill-backed mmaps
//!   under the caller-provided `spill_dir`, keeping resident memory bounded.
//! - When the allocation guard is enabled, per-offset decoding and sink
//!   emission must not allocate.
//!
//! Execution order is driven by `PackPlan.exec_order`: when absent (no
//! delta dependencies, or the DFS order matches the natural ascending
//! sequence), offsets are processed in ascending order and candidate gating
//! uses a single forward-only merge cursor over `candidate_offsets`. When
//! present, the executor precomputes exact per-offset candidate ranges to
//! preserve gating under out-of-order execution.
//!
//! # Invariants
//! - `plan.need_offsets` and `plan.candidate_offsets` are sorted by pack offset.
//! - `exec_order`, when present, is a permutation of `need_offsets` indices.
//! - The sink must not retain `bytes` slices beyond `emit` calls.
//! - Skip records are appended in execution order.
//!
//! The executor treats decode failures as per-offset skips and only returns
//! fatal errors for pack parsing or sink failures. External base provider
//! errors are recorded as skips for the affected offsets.
//!
//! # Plan assumptions
//! - `need_offsets` is sorted ascending.
//! - `candidate_offsets` is sorted ascending by offset and grouped per offset.
//! - `exec_order`, when present, indexes into `need_offsets`.
//!
//! # Buffer ownership
//! - `PackCache` stores decoded bytes when space permits.
//! - Otherwise, bytes live in a scratch buffer that is overwritten per offset.
//! - Sinks must consume `bytes` within the `emit` call.

#[cfg(test)]
use std::cell::Cell;
use std::fmt;
use std::path::Path;
use std::sync::Arc;

use crate::perf_stats;
use scanner_scheduler::AllocGuard;

use super::alloc_guard;
use super::blob_spill::BlobSpill;
use super::byte_arena::ByteArena;
use super::object_id::OidBytes;
use super::pack_cache::{CachedObject, PackCache};
use super::pack_candidates::PackCandidate;
use super::pack_decode::{inflate_entry_payload_with, PackDecodeError, PackDecodeLimits};
use super::pack_delta::apply_delta;
use super::pack_inflate::{
    apply_delta_into, delta_sizes, inflate_limited_with, inflate_stream, DeltaError, EntryHeader,
    EntryKind, ObjectKind, PackFile, PackHeader, PackParseError,
};
use super::pack_plan_model::{BaseLoc, CandidateAtOffset, DeltaDep, PackPlan, NONE_U32};
use super::pack_reader::PackReader;
use scanner_engine::perf_counters as perf;

/// External base object for REF deltas.
///
/// The bytes must contain the fully inflated base object and will be used as
/// the delta application base.
#[derive(Debug)]
pub struct ExternalBase {
    /// Git object kind of the resolved base object.
    pub kind: ObjectKind,
    /// Fully inflated base bytes used as delta input.
    pub bytes: Vec<u8>,
}

/// Provider for external REF delta bases.
///
/// Implementations may source bases from loose objects or other packs.
pub trait ExternalBaseProvider {
    /// Returns the base object for a given OID, or `None` if missing.
    ///
    /// Any error is recorded as `SkipReason::ExternalBaseError { detail }` for the
    /// affected offset; execution continues.
    fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError>;
}

/// Sink for decoded pack blobs.
///
/// The sink is invoked only for blob objects. Non-blob objects are recorded
/// as skips with `SkipReason::NotBlob`.
pub trait PackObjectSink {
    /// Receives a decoded blob candidate.
    ///
    /// The `bytes` slice is only valid for the duration of the call and may
    /// be backed by a cache entry, a scratch buffer, or a spill-backed mmap.
    /// Implementations must copy if they need to retain the bytes.
    /// `path` points into the caller-owned arena.
    ///
    /// When the allocation guard is enabled, `emit` must avoid heap
    /// allocation to preserve hot-path guarantees.
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError>;

    /// Called after all candidates for a pack are processed.
    fn finish(&mut self) -> Result<(), PackExecError> {
        Ok(())
    }
}

/// Pack executor error taxonomy (fatal only).
///
/// Decode errors do not appear here; they are tracked as `SkipReason`s.
#[derive(Debug, thiserror::Error)]
pub enum PackExecError {
    /// Pack header or index parsing failed.
    #[error("{0}")]
    PackParse(#[from] PackParseError),
    /// Pack bytes could not be read.
    #[error("pack read error: {0}")]
    PackRead(String),
    /// Scheduler task referenced a plan index outside the plan list.
    #[error("scheduler plan index out of range: index={index}, plan_count={plan_count}")]
    SchedulerPlanIndexOutOfRange { index: usize, plan_count: usize },
    /// Scheduler shard task referenced a plan index outside the plan list.
    #[error(
        "scheduler shard plan index out of range: plan_idx={plan_idx}, plan_count={plan_count}"
    )]
    SchedulerShardPlanIndexOutOfRange { plan_idx: usize, plan_count: usize },
    /// Scheduler shard metadata was unexpectedly missing for a plan.
    #[error("scheduler shard metadata missing: plan_idx={plan_idx}")]
    SchedulerShardMetadataMissing { plan_idx: usize },
    /// Scheduler shard metadata container was unavailable after execution.
    #[error("scheduler shard metadata unavailable")]
    SchedulerShardMetadataUnavailable,
    /// Scheduler shard task referenced a shard index outside the shard range list.
    #[error("scheduler shard index out of range: plan_idx={plan_idx}, shard_idx={shard_idx}, shard_count={shard_count}")]
    SchedulerShardIndexOutOfRange {
        plan_idx: usize,
        shard_idx: usize,
        shard_count: usize,
    },
    /// Scheduler finished but did not produce a plan output slot.
    #[error("scheduler plan output missing: plan_idx={plan_idx}")]
    SchedulerPlanOutputMissing { plan_idx: usize },
    /// Scheduler finished but did not produce a shard output slot.
    #[error("scheduler shard output missing: plan_idx={plan_idx}, shard_idx={shard_idx}")]
    SchedulerShardOutputMissing { plan_idx: usize, shard_idx: usize },
    /// Scheduler produced a different number of outputs than planned packs.
    #[error("scheduler output count mismatch: expected {expected}, got {got}")]
    SchedulerOutputCountMismatch { expected: usize, got: usize },
    /// Scheduler rejected enqueuing pack-plan tasks.
    #[error("scheduler task queue rejected work")]
    SchedulerTaskQueueRejected,
    /// Scheduler rejected enqueuing pack-shard tasks.
    #[error("scheduler shard queue rejected work")]
    SchedulerShardQueueRejected,
    /// The sink rejected an emitted blob.
    #[error("sink error: {0}")]
    Sink(String),
    /// External base provider returned a fatal error.
    #[error("external base error: {0}")]
    ExternalBase(String),
    /// Spill file creation or write failed.
    #[error("spill error: {0}")]
    Spill(#[source] std::io::Error),
}

/// Skip reason for a candidate offset.
///
/// These are non-fatal and recorded in the execution report.
#[derive(Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// Pack parsing failed for this offset.
    PackParse(PackParseError),
    /// Inflating or decoding this entry failed.
    Decode(PackDecodeError),
    /// Delta application failed after a successful decode.
    Delta(DeltaError),
    /// An OFS/REF delta base was expected in-pack but missing from cache.
    BaseMissing { base_offset: u64 },
    /// External base provider returned `None` for a REF delta.
    ExternalBaseMissing { oid: OidBytes },
    /// External base provider returned an error.
    ExternalBaseError { detail: String },
    /// Entry decoded successfully but is not a blob.
    NotBlob,
}

impl SkipReason {
    /// Returns whether this skip reason represents a pack-exec error.
    ///
    /// `NotBlob` is an expected type-classification outcome, not an error.
    ///
    /// `ExternalBaseMissing` (provider returned `None`) is treated as an
    /// error because all external bases should be resolvable by the time
    /// pack-exec runs — a missing base indicates a pack integrity problem
    /// or an incomplete MIDX, not a soft cache miss.
    #[inline]
    pub const fn is_error(&self) -> bool {
        !matches!(self, Self::NotBlob)
    }
}

/// Record of a skipped offset.
///
/// A single offset may appear multiple times if multiple candidates map to
/// the same offset and are all skipped.
#[derive(Debug)]
pub struct SkipRecord {
    pub offset: u64,
    pub reason: SkipReason,
}

/// Execution statistics.
#[derive(Debug, Default)]
pub struct PackExecStats {
    /// Offsets successfully decoded (including bases and non-blob kinds).
    pub decoded_offsets: u32,
    /// Candidates emitted to the sink.
    pub emitted_candidates: u32,
    /// Skip records emitted (may exceed unique offsets).
    pub skipped_offsets: u32,
    /// Cache hits when looking up delta base offsets.
    pub base_cache_hits: u32,
    /// Cache misses when looking up delta base offsets.
    pub base_cache_misses: u32,
    /// External base provider calls for REF deltas.
    pub external_base_calls: u32,
    /// On-demand base decode attempts triggered by cache misses.
    pub fallback_base_decodes: u32,
    /// Sum of delta-chain lengths walked during fallback decode attempts.
    pub fallback_chain_len_sum: u32,
    /// Maximum delta-chain length observed in fallback decode attempts.
    pub fallback_chain_len_max: u32,
    /// Cache insert attempts rejected (oversize entry or cache disabled).
    pub cache_insert_rejects: u32,
    /// Total rejected bytes across cache insert attempts.
    pub cache_reject_bytes_total: u64,
    /// Maximum rejected entry size.
    pub cache_reject_bytes_max: u32,
    /// Size histogram buckets (log2 sizes) for rejected cache inserts.
    pub cache_reject_size_buckets: [u64; CACHE_REJECT_BUCKETS],
    /// Large blobs streamed without full in-memory decode.
    pub large_blob_streamed_count: u32,
    /// Large blobs spilled to disk for scanning.
    pub large_blob_spilled_count: u32,
    /// Total bytes across large blob handling (stream + spill).
    pub large_blob_bytes: u64,
    // --- Timing fields (nanoseconds) ---
    // Populated only when the `git-perf` feature is enabled; otherwise zero.
    /// Wall-clock nanoseconds spent in cache.get() lookups.
    pub cache_lookup_nanos: u64,
    /// Wall-clock nanoseconds spent in fallback base resolution.
    pub fallback_resolve_nanos: u64,
    /// Wall-clock nanoseconds spent in sink.emit() calls.
    pub sink_emit_nanos: u64,
}

/// Pack execution report.
#[derive(Debug, Default)]
pub struct PackExecReport {
    /// Aggregate stats for this pack execution.
    pub stats: PackExecStats,
    /// Per-offset skip records (may include repeated offsets), in execution order.
    pub skips: Vec<SkipRecord>,
}

/// Hot-path counters buffered outside `PackExecStats`.
///
/// Separated from [`PackExecStats`] for cache-line density: these six `u32`
/// counters (24 bytes) are the only fields bumped on every offset iteration.
/// Keeping them in a small, `Copy` struct avoids polluting the same cache
/// line as the infrequently updated timing and histogram fields in
/// `PackExecStats`. The counters are merged into the full stats struct
/// exactly once, after the plan execution loop completes.
#[derive(Clone, Copy, Debug, Default)]
struct PackExecHotStats {
    decoded_offsets: u32,
    emitted_candidates: u32,
    skipped_offsets: u32,
    base_cache_hits: u32,
    base_cache_misses: u32,
    external_base_calls: u32,
}

impl PackExecHotStats {
    #[inline(always)]
    fn inc_decoded(&mut self) {
        self.decoded_offsets = self.decoded_offsets.saturating_add(1);
    }

    #[inline(always)]
    fn inc_emitted(&mut self) {
        self.emitted_candidates = self.emitted_candidates.saturating_add(1);
    }

    #[inline(always)]
    fn inc_skipped(&mut self) {
        self.skipped_offsets = self.skipped_offsets.saturating_add(1);
    }

    #[inline(always)]
    fn inc_base_cache_hit(&mut self) {
        self.base_cache_hits = self.base_cache_hits.saturating_add(1);
    }

    #[inline(always)]
    fn inc_base_cache_miss(&mut self) {
        self.base_cache_misses = self.base_cache_misses.saturating_add(1);
    }

    #[inline(always)]
    fn inc_external_base_call(&mut self) {
        self.external_base_calls = self.external_base_calls.saturating_add(1);
    }

    #[inline]
    fn merge_into(self, stats: &mut PackExecStats) {
        // Exhaustiveness guard: adding a field to PackExecHotStats without
        // handling it here will produce a compile error.
        let PackExecHotStats {
            decoded_offsets,
            emitted_candidates,
            skipped_offsets,
            base_cache_hits,
            base_cache_misses,
            external_base_calls,
        } = self;

        perf_stats::sat_add_u32(&mut stats.decoded_offsets, decoded_offsets);
        perf_stats::sat_add_u32(&mut stats.emitted_candidates, emitted_candidates);
        perf_stats::sat_add_u32(&mut stats.skipped_offsets, skipped_offsets);
        perf_stats::sat_add_u32(&mut stats.base_cache_hits, base_cache_hits);
        perf_stats::sat_add_u32(&mut stats.base_cache_misses, base_cache_misses);
        perf_stats::sat_add_u32(&mut stats.external_base_calls, external_base_calls);
    }
}

/// Number of cache reject size buckets (log2 of byte size).
pub const CACHE_REJECT_BUCKETS: usize = 32;

/// Aggregate cache reject histogram across pack-exec reports.
#[derive(Debug, Default, Clone)]
pub struct CacheRejectHistogram {
    /// Total number of rejected cache insert attempts.
    pub rejects: u64,
    /// Total bytes across all rejected cache insert attempts.
    pub bytes_total: u64,
    /// Largest rejected entry size (bytes).
    pub bytes_max: u32,
    /// Log2 bucketed reject counts (`[2^i, 2^(i+1)-1]`, bucket 0 includes size 0/1).
    pub buckets: [u64; CACHE_REJECT_BUCKETS],
}

impl CacheRejectHistogram {
    /// Formats the top-N buckets by count as `"[start-end:count, ...]"`.
    ///
    /// Ties are ordered by lower bucket index first to keep output stable.
    #[must_use]
    pub fn format_top(&self, top_n: usize) -> String {
        let mut entries: Vec<(usize, u64)> = self
            .buckets
            .iter()
            .enumerate()
            .filter_map(|(idx, &count)| (count > 0).then_some((idx, count)))
            .collect();
        entries.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));

        let mut out = String::from("[");
        for (pos, (idx, count)) in entries.into_iter().take(top_n).enumerate() {
            if pos > 0 {
                out.push_str(", ");
            }
            let (start, end) = cache_reject_bucket_range(idx);
            out.push_str(&format!("{start}-{end}:{count}"));
        }
        out.push(']');
        out
    }
}

impl PackExecStats {
    /// Whether heavyweight stat recording (merge, histogram) is active.
    ///
    /// Gated on both `perf-stats` *and* `debug_assertions` so that release
    /// builds skip the merge loop entirely, even when compiled with the
    /// feature flag.
    #[inline(always)]
    fn recording_enabled() -> bool {
        cfg!(all(feature = "perf-stats", debug_assertions))
    }

    #[inline]
    fn record_cache_reject(&mut self, size: usize) {
        perf_stats::sat_add_u32(&mut self.cache_insert_rejects, 1);
        perf_stats::sat_add_u64(&mut self.cache_reject_bytes_total, size as u64);
        let size_u32 = size.min(u32::MAX as usize) as u32;
        perf_stats::max_u32(&mut self.cache_reject_bytes_max, size_u32);
        let bucket = cache_reject_bucket_index(size_u32);
        perf_stats::sat_add_u64(&mut self.cache_reject_size_buckets[bucket], 1);
    }

    #[inline]
    fn merge_from(&mut self, other: &PackExecStats) {
        if !Self::recording_enabled() {
            let _ = other;
            return;
        }
        // Exhaustiveness guard: adding a field to PackExecStats without
        // handling it here will produce a compile error.
        let PackExecStats {
            decoded_offsets,
            emitted_candidates,
            skipped_offsets,
            base_cache_hits,
            base_cache_misses,
            external_base_calls,
            fallback_base_decodes,
            fallback_chain_len_sum,
            fallback_chain_len_max,
            cache_insert_rejects,
            cache_reject_bytes_total,
            cache_reject_bytes_max,
            ref cache_reject_size_buckets,
            large_blob_streamed_count,
            large_blob_spilled_count,
            large_blob_bytes,
            cache_lookup_nanos,
            fallback_resolve_nanos,
            sink_emit_nanos,
        } = *other;

        self.decoded_offsets = self.decoded_offsets.saturating_add(decoded_offsets);
        self.emitted_candidates = self.emitted_candidates.saturating_add(emitted_candidates);
        self.skipped_offsets = self.skipped_offsets.saturating_add(skipped_offsets);
        self.base_cache_hits = self.base_cache_hits.saturating_add(base_cache_hits);
        self.base_cache_misses = self.base_cache_misses.saturating_add(base_cache_misses);
        self.external_base_calls = self.external_base_calls.saturating_add(external_base_calls);
        self.fallback_base_decodes = self
            .fallback_base_decodes
            .saturating_add(fallback_base_decodes);
        self.fallback_chain_len_sum = self
            .fallback_chain_len_sum
            .saturating_add(fallback_chain_len_sum);
        self.fallback_chain_len_max = self.fallback_chain_len_max.max(fallback_chain_len_max);
        self.cache_insert_rejects = self
            .cache_insert_rejects
            .saturating_add(cache_insert_rejects);
        self.cache_reject_bytes_total = self
            .cache_reject_bytes_total
            .saturating_add(cache_reject_bytes_total);
        self.cache_reject_bytes_max = self.cache_reject_bytes_max.max(cache_reject_bytes_max);
        for (idx, count) in cache_reject_size_buckets.iter().enumerate() {
            self.cache_reject_size_buckets[idx] =
                self.cache_reject_size_buckets[idx].saturating_add(*count);
        }
        self.large_blob_streamed_count = self
            .large_blob_streamed_count
            .saturating_add(large_blob_streamed_count);
        self.large_blob_spilled_count = self
            .large_blob_spilled_count
            .saturating_add(large_blob_spilled_count);
        self.large_blob_bytes = self.large_blob_bytes.saturating_add(large_blob_bytes);
        self.cache_lookup_nanos = self.cache_lookup_nanos.saturating_add(cache_lookup_nanos);
        self.fallback_resolve_nanos = self
            .fallback_resolve_nanos
            .saturating_add(fallback_resolve_nanos);
        self.sink_emit_nanos = self.sink_emit_nanos.saturating_add(sink_emit_nanos);
    }
}

/// Accumulate wall-clock nanoseconds into a timing field.
///
/// The executor uses two independent feature flags for instrumentation:
///
/// - **`perf-stats`** — gates cheap counter increments (`sat_add_u32` and
///   friends). The cost is a single saturating add per offset; always safe
///   to enable in production debug builds.
/// - **`git-perf`** — gates wall-clock timing via `perf::time()`. Each
///   timing probe requires a clock read (typically `clock_gettime`), which
///   is measurably more expensive than a counter bump on high-throughput
///   pack decoding. This flag is intended for targeted profiling runs,
///   not routine builds.
///
/// `record_timing` bridges the two: it accepts the nanosecond value
/// produced by `perf::time()` and accumulates it into a `PackExecStats`
/// timing field, but only when `git-perf` is active. Without the flag
/// the function compiles to nothing and the `perf::time()` wrapper
/// returns `0` for the nanos component.
#[inline(always)]
fn record_timing(field: &mut u64, nanos: u64) {
    #[cfg(feature = "git-perf")]
    {
        *field = field.saturating_add(nanos);
    }
    #[cfg(not(feature = "git-perf"))]
    {
        let _ = (field, nanos);
    }
}

#[inline]
fn cache_reject_bucket_index(size: u32) -> usize {
    if size == 0 {
        return 0;
    }
    (31 - size.leading_zeros()) as usize
}

/// Returns the inclusive `(start, end)` byte range represented by bucket `idx`.
///
/// Bucket `0` represents both `0` and `1` bytes; bucket `31` saturates to `u32::MAX`.
fn cache_reject_bucket_range(idx: usize) -> (u32, u32) {
    if idx == 0 {
        return (0, 1);
    }
    let start = 1u32 << idx;
    let end = if idx >= 31 {
        u32::MAX
    } else {
        (1u32 << (idx + 1)) - 1
    };
    (start, end)
}

/// Record the length of a completed fallback delta-chain walk into stats.
///
/// Called once per `decode_base_from_pack` invocation, whether the walk
/// succeeded or failed, to track the distribution of chain depths.
#[inline]
fn record_fallback_chain(stats: &mut PackExecStats, chain_len: usize) {
    let chain_len = chain_len.min(u32::MAX as usize) as u32;
    perf_stats::sat_add_u32(&mut stats.fallback_chain_len_sum, chain_len);
    perf_stats::max_u32(&mut stats.fallback_chain_len_max, chain_len);
}

/// Aggregate cache reject histogram across pack-exec reports.
#[must_use]
pub fn aggregate_cache_reject_histogram(reports: &[PackExecReport]) -> CacheRejectHistogram {
    if !cfg!(all(feature = "perf-stats", debug_assertions)) {
        let _ = reports;
        return CacheRejectHistogram::default();
    }
    let mut out = CacheRejectHistogram::default();
    for report in reports {
        let stats = &report.stats;
        out.rejects = out
            .rejects
            .saturating_add(stats.cache_insert_rejects as u64);
        out.bytes_total = out
            .bytes_total
            .saturating_add(stats.cache_reject_bytes_total);
        out.bytes_max = out.bytes_max.max(stats.cache_reject_bytes_max);
        for (idx, count) in stats.cache_reject_size_buckets.iter().enumerate() {
            out.buckets[idx] = out.buckets[idx].saturating_add(*count);
        }
    }
    out
}

/// Merge per-shard reports in order into a single report.
#[must_use]
pub fn merge_pack_exec_reports(mut reports: Vec<PackExecReport>) -> PackExecReport {
    let mut merged = PackExecReport::default();
    for report in reports.drain(..) {
        merged.stats.merge_from(&report.stats);
        merged.skips.extend(report.skips);
    }
    merged
}

/// Packed half-open candidate index range `[start, end)` into
/// `PackPlan.candidate_offsets`, indexed by `need_offsets` position.
///
/// The "no candidates" sentinel is encoded as `(NONE_U32, NONE_U32)`
/// rather than wrapping in `Option<(u32, u32)>`. This avoids the 4-byte
/// discriminant that `Option` would add to every slot in the dense
/// `candidate_ranges` table (one entry per `need_offsets` element),
/// keeping the table compact and avoiding branch-heavy enum matching
/// on the hot path.
///
/// The sentinel is detected by checking `start == NONE_U32` alone;
/// consistency of `end` is ensured by construction (`missing()` and
/// `Default` both set both fields to `NONE_U32`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRange {
    start: u32,
    end: u32,
}

impl CandidateRange {
    /// Returns the sentinel range used for "no candidates for this offset".
    #[inline(always)]
    pub const fn missing() -> Self {
        Self {
            start: NONE_U32,
            end: NONE_U32,
        }
    }

    /// Packs a half-open candidate index range `[start, end)` into `u32` bounds.
    ///
    /// # Panics
    /// Panics when `start > end` or when either bound exceeds `u32::MAX`.
    #[inline(always)]
    pub fn from_bounds(start: usize, end: usize) -> Self {
        assert!(start <= end, "candidate range start must be <= end");
        let start = u32::try_from(start).expect("candidate range start exceeds u32::MAX");
        let end = u32::try_from(end).expect("candidate range end exceeds u32::MAX");
        Self { start, end }
    }

    /// Encodes an optional `(start, end)` range, mapping `None` to [`Self::missing`].
    #[inline(always)]
    pub fn from_option(range: Option<(usize, usize)>) -> Self {
        if let Some((start, end)) = range {
            Self::from_bounds(start, end)
        } else {
            Self::missing()
        }
    }

    /// Decodes this packed range into half-open bounds `[start, end)`.
    ///
    /// Returns `None` when the sentinel form from [`Self::missing`] is present.
    #[inline(always)]
    pub fn bounds(self) -> Option<(usize, usize)> {
        if self.start == NONE_U32 {
            return None;
        }
        debug_assert!(self.end != NONE_U32);
        Some((self.start as usize, self.end as usize))
    }

    /// Returns the number of candidates represented by this range.
    ///
    /// Missing ranges report `0`.
    #[inline(always)]
    pub fn candidate_count(self) -> usize {
        if let Some((start, end)) = self.bounds() {
            end.saturating_sub(start)
        } else {
            0
        }
    }
}

impl Default for CandidateRange {
    fn default() -> Self {
        Self::missing()
    }
}

/// Advances a forward-only candidate cursor to the next range for `offset`.
///
/// `candidate_offsets` must be sorted ascending by `offset`. `cand_idx` is
/// updated in-place and never moves backward.
#[inline(always)]
fn next_candidate_range(
    candidate_offsets: &[CandidateAtOffset],
    offset: u64,
    cand_idx: &mut usize,
) -> CandidateRange {
    while *cand_idx < candidate_offsets.len() && candidate_offsets[*cand_idx].offset < offset {
        *cand_idx += 1;
    }
    if *cand_idx < candidate_offsets.len() && candidate_offsets[*cand_idx].offset == offset {
        let start = *cand_idx;
        while *cand_idx < candidate_offsets.len() && candidate_offsets[*cand_idx].offset == offset {
            *cand_idx += 1;
        }
        CandidateRange::from_bounds(start, *cand_idx)
    } else {
        CandidateRange::missing()
    }
}

/// Reusable scratch state for pack execution.
///
/// Callers may allocate one `PackExecScratch` and pass it to multiple
/// sequential `execute_pack_plan_with_scratch*` calls. Between calls,
/// [`prepare`](Self::prepare) clears contents but retains heap capacity,
/// amortizing allocation across plans.
///
/// # Buffer rotation
///
/// The executor uses a three-buffer rotation scheme (inside [`DecodeBufs`])
/// to avoid per-offset heap allocations on the hot path:
///
/// - `inflate_buf` — receives raw zlib-inflated delta payloads. Non-delta
///   objects are inflated directly into `result_buf`. Sized to
///   `max_delta_bytes`.
/// - `result_buf` — holds the final decoded object bytes. For non-delta
///   entries the inflated payload is written here directly; for delta
///   entries the delta-applied output lands here. This is the buffer
///   handed to `cache.insert()` or read by the sink. Sized to
///   `max_object_bytes`.
/// - `base_buf` — holds the base object bytes during fallback delta chain
///   resolution. Swapped with `result_buf` as each delta frame is applied
///   so the previous output becomes the next base.
///
/// `delta_stack` collects `DeltaFrame`s during fallback chain walks
/// (base not in cache). The stack is unwound in reverse to apply deltas
/// from the root base outward.
///
/// # Plan-specific tables
///
/// `delta_deps_hot` and `external_base_oids` are rebuilt on every
/// [`prepare`](Self::prepare) call because `DeltaDepHot::external_oid_idx`
/// values are positional indices that are valid only for the specific plan
/// that produced them. The Vec capacity is retained so plans with similar
/// delta counts avoid reallocation.
///
/// `candidate_ranges` is populated once per plan (by
/// [`build_candidate_ranges`]) only when the plan uses out-of-order
/// execution. Each entry maps a `need_offsets` index to its contiguous
/// range in `candidate_offsets` via packed [`CandidateRange`] values.
#[derive(Debug, Default)]
pub struct PackExecScratch {
    bufs: DecodeBufs,
    delta_deps_hot: Vec<DeltaDepHot>,
    external_base_oids: Vec<OidBytes>,
    candidate_ranges: Vec<CandidateRange>,
}

impl Default for DecodeBufs {
    fn default() -> Self {
        // `init_decompress` wraps `Decompress::new(true)` in `catch_unwind`
        // to convert the opaque zlib-ng OOM panic into a clear expect message.
        // Panicking here is acceptable: `DecodeBufs` is constructed once per
        // executor run (COLD path) and there is no fallback decompressor for
        // flate2. `LibdeflateDecompressor::new()` returns `Option` because
        // libdeflate failures degrade gracefully to the flate2 path.
        Self {
            de: crate::pack_inflate::init_decompress()
                .expect("Decompress allocation (COLD path, once per executor)"),
            libde: crate::pack_inflate_libdeflate::LibdeflateDecompressor::new(),
            inflate_buf: Vec::new(),
            result_buf: Vec::new(),
            base_buf: Vec::new(),
            delta_stack: Vec::new(),
        }
    }
}

impl DecodeBufs {
    /// Ensures each buffer has at least the capacity required by `limits`
    /// and clears contents. Capacity only grows; existing allocations are
    /// never shrunk.
    fn prepare(&mut self, limits: &PackDecodeLimits, max_delta_depth: u8) {
        let inflate_target = limits.max_delta_bytes.max(1024);
        if self.inflate_buf.capacity() < inflate_target {
            self.inflate_buf
                .reserve(inflate_target - self.inflate_buf.capacity());
        }
        self.inflate_buf.clear();

        let result_target = limits.max_object_bytes.max(1024);
        if self.result_buf.capacity() < result_target {
            self.result_buf
                .reserve(result_target - self.result_buf.capacity());
        }
        self.result_buf.clear();

        let base_target = limits.max_object_bytes.max(1024);
        if self.base_buf.capacity() < base_target {
            self.base_buf
                .reserve(base_target - self.base_buf.capacity());
        }
        self.base_buf.clear();

        let depth_target = max_delta_depth as usize + 1;
        if self.delta_stack.capacity() < depth_target {
            self.delta_stack
                .reserve(depth_target - self.delta_stack.capacity());
        }
        self.delta_stack.clear();
    }
}

impl fmt::Debug for DecodeBufs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodeBufs")
            .field("inflate_buf_cap", &self.inflate_buf.capacity())
            .field("result_buf_cap", &self.result_buf.capacity())
            .field("base_buf_cap", &self.base_buf.capacity())
            .field("delta_stack_cap", &self.delta_stack.capacity())
            .finish()
    }
}

impl PackExecScratch {
    #[inline(always)]
    fn prepare_bufs(&mut self, limits: &PackDecodeLimits, max_delta_depth: u8) {
        self.bufs.prepare(limits, max_delta_depth);
        self.candidate_ranges.clear();
    }

    /// Prepares scratch buffers for the given plan and decode limits.
    ///
    /// Ensures that `inflate_buf`, `result_buf`, `base_buf`, and
    /// `delta_stack` have enough capacity for the plan's size limits and
    /// delta depth, without shrinking existing allocations. This is the
    /// mechanism that amortizes allocation cost when a single
    /// `PackExecScratch` is reused across multiple plan executions.
    ///
    /// **Delta-dep rebuild:** `delta_deps_hot` and `external_base_oids`
    /// are *always* cleared and rebuilt from the plan's `delta_deps` array,
    /// because the `DeltaDepHot::external_oid_idx` values are positional
    /// indices into `external_base_oids` — they are only valid for the
    /// specific plan that produced them. Reusing stale tables from a
    /// prior plan would silently mis-resolve external OIDs. The Vec
    /// capacity is retained across calls so that plans with similar delta
    /// counts avoid reallocation.
    ///
    /// `candidate_ranges` is cleared but not populated here; it is filled
    /// lazily by [`build_candidate_ranges`] only when the plan uses
    /// out-of-order execution (`exec_order.is_some()`).
    fn prepare(&mut self, plan: &PackPlan, limits: &PackDecodeLimits) {
        self.prepare_bufs(limits, plan.max_delta_depth);
        rebuild_delta_deps_hot(plan, &mut self.delta_deps_hot, &mut self.external_base_oids);
    }
}

/// Where the decoded bytes live after [`decode_offset`].
///
/// Each variant has different ownership and lifetime semantics:
///
/// - **`Cache`** — bytes were inserted into the `PackCache` and are owned
///   by the cache's backing storage. They remain valid until the cache
///   entry is evicted by a subsequent insert or the cache itself is
///   dropped. Because `decode_offset` returns metadata only (no slice),
///   callers must perform a second `cache_get()` to obtain a `&[u8]`.
///   In the common case of [`execute_offset_range_with_scratch`], this
///   second lookup is avoided on cache *hits* by reusing the bytes from
///   the initial probe.
///
/// - **`Scratch`** — bytes reside in `DecodeBufs::result_buf`, which is
///   cleared and overwritten on the next call to `decode_offset`. The
///   sink **must** consume these bytes (or copy them) within the current
///   `emit()` invocation; they are invalid afterward.
///
/// - **`Spill`** — bytes are backed by a temporary mmap file created
///   through [`BlobSpill`]. The `BlobSpill` handle inside this variant
///   owns the mapping; the bytes are valid for as long as this
///   `DecodedStorage` value exists. Used for objects exceeding
///   `limits.max_object_bytes` to keep resident memory bounded.
#[derive(Debug)]
enum DecodedStorage {
    /// Bytes are owned by the `PackCache`. Requires a `cache_get()` to
    /// obtain a `&[u8]` slice.
    Cache,
    /// Bytes live in `DecodeBufs::result_buf`. Valid only until the next
    /// `decode_offset` call overwrites the buffer.
    Scratch,
    /// Bytes live in an mmap-backed temp file. The `BlobSpill` handle
    /// owns the mapping and must outlive any slice borrows.
    Spill(BlobSpill),
}

/// Metadata for a decoded offset (kind + storage location).
#[derive(Debug)]
struct DecodedObject {
    kind: ObjectKind,
    storage: DecodedStorage,
}

#[cfg(test)]
thread_local! {
    static TEST_CACHE_GET_CALLS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
fn reset_test_cache_get_calls() {
    TEST_CACHE_GET_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
fn test_cache_get_calls() -> u64 {
    TEST_CACHE_GET_CALLS.with(Cell::get)
}

/// Thin wrapper around `cache.get()` that instruments call counts in tests.
///
/// All cache lookups in the executor **must** go through this function so
/// that the `delta_base_cache_lookup_counted_by_cache_get_wrapper` test can
/// verify that no code path bypasses the counter. In release builds this
/// compiles to a direct `cache.get()` call.
#[inline(always)]
fn cache_get(cache: &mut PackCache, offset: u64) -> Option<CachedObject<'_>> {
    #[cfg(test)]
    TEST_CACHE_GET_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    cache.get(offset)
}

/// Where resolved base bytes live during delta application.
///
/// Small bases are borrowed from the cache or `base_buf` (`Slice`).
/// Bases that exceed `max_object_bytes` are backed by a spill mmap; the
/// `BlobSpill` owns the mapping and must outlive any slice borrows.
///
/// The lifetime `'a` on `Slice` ties borrows to one of two sources:
/// - **Cache hit** — the `PackCache`'s internal storage; valid until the
///   entry is evicted or the cache is dropped.
/// - **Fallback decode** — `base_buf` within `DecodeBufs`; valid until
///   the next `decode_offset` call that may overwrite it.
///
/// `Spill` has no lifetime parameter because the `BlobSpill` owns its
/// backing mmap file; the bytes live as long as the handle exists.
enum BaseStorage<'a> {
    Slice(&'a [u8]),
    /// Spill-backed bytes; the spill must remain alive while referenced.
    Spill(BlobSpill),
}

impl BaseStorage<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Spill(spill) => spill.as_slice(),
        }
    }
}

/// Resolved base object: its git object kind plus the raw bytes.
///
/// Used as the input to `decode_delta_output`. The kind propagates
/// through the delta chain — the final reconstructed object inherits
/// the kind of the root non-delta base, even when multiple intermediate
/// OFS/REF deltas are applied.
///
/// Returned by [`decode_base_from_pack`] on the fallback path and by
/// inline cache hits in [`resolve_and_apply_delta`].
struct BaseBytes<'a> {
    kind: ObjectKind,
    storage: BaseStorage<'a>,
}

impl BaseBytes<'_> {
    fn bytes(&self) -> &[u8] {
        self.storage.as_slice()
    }
}

/// Compact delta-dependency view used on the hot decode path.
///
/// This is a flattened, cache-friendly projection of [`DeltaDep`] that
/// avoids the `BaseLoc` enum tag and moves external base OIDs into a
/// separate interned table. The result is a dense struct optimized for
/// sequential scan during offset iteration.
///
/// For pack-local (OFS) deltas, `base_offset` holds the base's pack
/// offset and `external_oid_idx` is [`NONE_U32`]. For external (REF)
/// deltas, `base_offset` is `0` (sentinel — the pack header occupies
/// `0..12` so no valid base starts there) and `external_oid_idx` is an
/// index into the companion `external_base_oids` table.
#[derive(Clone, Copy, Debug)]
struct DeltaDepHot {
    /// Pack offset of the base entry for OFS deltas.
    ///
    /// Only valid when `!self.is_external()`. Sentinel `0` is safe because
    /// the pack header occupies bytes `0..12`, so no valid base starts at
    /// offset 0.
    base_offset: u64,
    /// Index into the companion `external_base_oids` table, or
    /// [`NONE_U32`] for pack-local bases.
    external_oid_idx: u32,
    /// Byte offset where the delta entry's zlib payload starts.
    /// `0` means plan-time metadata was not available (synthetic plan).
    data_start: u64,
    /// Declared uncompressed delta payload size from the entry header.
    /// `0` when plan-time metadata is unavailable.
    delta_size: u64,
}

impl DeltaDepHot {
    #[inline]
    fn from_plan(dep: &DeltaDep, external_oid_idx: u32) -> Self {
        let base_offset = match dep.base {
            BaseLoc::Offset(base_offset) => base_offset,
            BaseLoc::External { .. } => 0,
        };
        Self {
            base_offset,
            external_oid_idx,
            data_start: dep.data_start,
            delta_size: dep.delta_size,
        }
    }

    #[inline(always)]
    fn has_header_meta(self) -> bool {
        self.data_start != 0
    }

    #[inline(always)]
    fn is_external(self) -> bool {
        self.external_oid_idx != NONE_U32
    }
}

/// Rebuild the hot delta-dep and external-OID tables from a plan.
///
/// Clears both Vecs (retaining capacity) and repopulates them from
/// `plan.delta_deps`. External OIDs are assigned sequential indices as
/// they are encountered, so the resulting `external_oid_idx` values in
/// `DeltaDepHot` are valid only when paired with the `external_base_oids`
/// table produced by the same call.
fn rebuild_delta_deps_hot(
    plan: &PackPlan,
    delta_deps_hot: &mut Vec<DeltaDepHot>,
    external_base_oids: &mut Vec<OidBytes>,
) {
    if delta_deps_hot.capacity() < plan.delta_deps.len() {
        delta_deps_hot.reserve(plan.delta_deps.len() - delta_deps_hot.capacity());
    }
    let external_base_oids_target = plan
        .delta_deps
        .iter()
        .filter(|dep| matches!(dep.base, BaseLoc::External { .. }))
        .count();
    if external_base_oids.capacity() < external_base_oids_target {
        external_base_oids.reserve(external_base_oids_target - external_base_oids.capacity());
    }
    delta_deps_hot.clear();
    external_base_oids.clear();
    for dep in &plan.delta_deps {
        let external_oid_idx = match dep.base {
            BaseLoc::Offset(_) => NONE_U32,
            BaseLoc::External { oid } => {
                let idx = external_base_oids.len();
                external_base_oids.push(oid);
                idx as u32
            }
        };
        delta_deps_hot.push(DeltaDepHot::from_plan(dep, external_oid_idx));
    }
}

/// Read-only, `Arc`-wrapped delta-dependency tables for one pack plan.
///
/// When a plan is executed in parallel shards, each shard needs access to
/// the same `delta_deps_hot` and `external_base_oids` tables. Without
/// this struct, every shard call to `PackExecScratch::prepare()` would
/// rebuild these tables from the plan — redundant work proportional to
/// the number of deltas. `PackPlanHotDeps` is built once per plan via
/// [`from_plan`](Self::from_plan) and cheaply cloned (via `Arc`) into
/// each shard's `execute_*_hot_deps` call. The `_hot_deps` entry points
/// call `prepare_bufs` (buffers only) instead of the full `prepare`
/// (which would overwrite the tables).
#[derive(Clone, Debug)]
pub(super) struct PackPlanHotDeps {
    delta_deps_hot: Arc<[DeltaDepHot]>,
    external_base_oids: Arc<[OidBytes]>,
}

impl PackPlanHotDeps {
    pub(super) fn from_plan(plan: &PackPlan) -> Self {
        let mut delta_deps_hot = Vec::new();
        let mut external_base_oids = Vec::new();
        rebuild_delta_deps_hot(plan, &mut delta_deps_hot, &mut external_base_oids);
        Self {
            delta_deps_hot: Arc::from(delta_deps_hot),
            external_base_oids: Arc::from(external_base_oids),
        }
    }

    #[inline(always)]
    fn delta_deps(&self) -> &[DeltaDepHot] {
        self.delta_deps_hot.as_ref()
    }

    #[inline(always)]
    fn external_base_oids(&self) -> &[OidBytes] {
        self.external_base_oids.as_ref()
    }

    #[cfg(test)]
    #[inline(always)]
    pub(super) fn delta_dep_count(&self) -> usize {
        self.delta_deps_hot.len()
    }

    #[cfg(test)]
    #[inline(always)]
    pub(super) fn external_oid_count(&self) -> usize {
        self.external_base_oids.len()
    }
}

/// One frame in the delta chain stack during fallback base resolution.
///
/// When the executor encounters a delta whose base is not cached, it
/// pushes a frame for each intermediate delta while walking toward the
/// root non-delta object. The stack is then unwound in reverse to apply
/// deltas from the root outward.
#[derive(Clone, Copy, Debug)]
struct DeltaFrame {
    /// Pack offset of this delta entry (used for cache insertion after
    /// applying the delta).
    offset: u64,
    /// Byte offset where the delta payload zlib stream starts.
    data_start: u64,
    /// Declared uncompressed delta payload size.
    delta_size: u64,
}

/// Immutable execution environment for pack decoding.
///
/// Bundles plan data, decode limits, and precomputed delta-dependency views
/// that are constant across all offsets in a single plan execution. Passed
/// by shared reference (`&DecodeEnv`) to collapse eight otherwise
/// register-consuming parameters into a single pointer, keeping hot decode
/// functions like [`decode_offset`] and [`resolve_and_apply_delta`] within
/// ARM's x0-x7 calling convention window (and reducing register pressure on
/// x86-64 as well).
struct DecodeEnv<'a> {
    pack: &'a PackFile<'a>,
    limits: &'a PackDecodeLimits,
    spill_dir: &'a Path,
    max_delta_depth: u8,
    need_offsets: &'a [u64],
    delta_deps: &'a [DeltaDepHot],
    external_base_oids: &'a [OidBytes],
    delta_dep_index: &'a [u32],
}

/// Mutable scratch buffers used during per-offset decoding.
///
/// Split from [`PackExecScratch`] as a separate struct so that callers can
/// hold an immutable reference to precomputed plan data (`delta_deps_hot`,
/// `external_base_oids`) while mutating working buffers — a pattern that
/// Rust's borrow checker requires separate structs for. Functions that
/// need split borrows across `base_buf` and `inflate_buf`/`result_buf`
/// destructure through individual field access.
///
/// The `de` (Decompress) instance is owned here rather than in a
/// `thread_local!` so that the executor can pass it by `&mut` through
/// the decode call chain without TLS overhead or reentrancy concerns.
struct DecodeBufs {
    de: flate2::Decompress,
    libde: Option<crate::pack_inflate_libdeflate::LibdeflateDecompressor>,
    inflate_buf: Vec<u8>,
    result_buf: Vec<u8>,
    base_buf: Vec<u8>,
    delta_stack: Vec<DeltaFrame>,
}

// ---------------------------------------------------------------------------
// Execution entry points
//
// The public surface has several variants to support different call-site
// constraints (scratch reuse, pre-parsed headers, shard parallelism). They
// compose as a layered hierarchy:
//
//   execute_pack_plan_with_reader   — top-level, reads pack via PackReader
//     execute_pack_plan             — accepts raw pack bytes, allocates scratch
//       execute_pack_plan_with_scratch — reuses caller-owned PackExecScratch
//         execute_pack_plan_with_scratch_from_header — + pre-parsed header
//
//   Shard variants (split work across disjoint index sets):
//     execute_pack_plan_with_scratch_indices       — explicit index list
//       ..._indices_from_header                    — + pre-parsed header
//       ..._indices_hot_deps                       — + shared PackPlanHotDeps
//     execute_pack_plan_with_scratch_range          — contiguous [start, end)
//       ..._range_from_header                      — + pre-parsed header
//       ..._range_hot_deps                         — + shared PackPlanHotDeps
//
// All variants eventually funnel through the internal
// `execute_pack_plan_with_selector_from_header`, which is parameterized by
// an index iterator and a candidate-range lookup closure.
//
// When adding a new entry point, wire it through the selector core to
// keep per-offset decode logic in one place.
// ---------------------------------------------------------------------------

/// Executes a pack plan against a `PackReader`.
///
/// The reader is used to materialize a contiguous pack byte buffer. This
/// enables deterministic fault injection for simulation without changing
/// the core decode logic.
///
/// Note: this reads the entire pack into memory; very large packs may exceed
/// addressable memory on 32-bit platforms. Spill-backed decoding uses the
/// process temp directory.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_reader<S: PackObjectSink, B: ExternalBaseProvider, R: PackReader>(
    plan: &PackPlan,
    reader: &mut R,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
) -> Result<PackExecReport, PackExecError> {
    let mut pack_bytes = Vec::new();
    read_pack_bytes(reader, &mut pack_bytes)?;
    let spill_dir = std::env::temp_dir();
    execute_pack_plan(
        plan,
        &pack_bytes,
        paths,
        limits,
        cache,
        external,
        sink,
        &spill_dir,
    )
}

/// Executes a pack plan against pack bytes.
///
/// The plan's `exec_order` is respected when present to satisfy forward
/// delta dependencies. Pack bytes must contain the full pack file.
///
/// `paths` must contain all path refs referenced by plan candidates.
/// `cache` is updated with decoded objects when capacity allows.
/// `spill_dir` is used for spill-backed large blob and delta outputs.
///
/// The returned report includes both successful decode stats and per-offset
/// skip reasons for non-fatal failures (decode errors, missing bases, and
/// external base provider errors).
///
/// For offsets with multiple candidates, `emit` is invoked once per candidate.
/// Non-blob objects record `SkipReason::NotBlob` for each candidate at the
/// offset.
///
/// # Errors
/// - `PackExecError::PackParse` for invalid pack headers.
/// - `PackExecError::Sink` for sink failures.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
) -> Result<PackExecReport, PackExecError> {
    let mut scratch = PackExecScratch::default();
    execute_pack_plan_with_scratch(
        plan,
        pack_bytes,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        &mut scratch,
    )
}

/// Parses and validates pack header metadata for a plan execution.
///
/// Callers executing multiple shard entry points over the same `pack_bytes`
/// can parse once, then pass the returned header to the `*_from_header`
/// variants to avoid redundant header validation.
#[inline]
pub fn parse_pack_header_for_plan(
    plan: &PackPlan,
    pack_bytes: &[u8],
) -> Result<PackHeader, PackExecError> {
    PackFile::parse_header(pack_bytes, plan.oid_len as usize).map_err(PackExecError::PackParse)
}

/// Shared execution core for all pack plan entry points.
///
/// Every public `execute_pack_plan_*` function ultimately calls this.
/// The two generic parameters abstract over the two axes of variation:
///
/// - `I: IntoIterator<Item = usize>` — which `need_offsets` indices to
///   decode (e.g., `0..n` for sequential, an explicit `&[usize]` for
///   shard execution, or `exec_order` for out-of-order plans).
/// - `R: FnMut(usize) -> CandidateRange` — how to resolve candidates
///   for a given need index (forward merge cursor for monotone execution,
///   precomputed table lookup for out-of-order or shard execution).
///
/// This design keeps the per-offset decode/emit logic in one place
/// regardless of how the outer entry point selects work.
#[allow(clippy::too_many_arguments)]
fn execute_pack_plan_with_selector_from_header<
    S: PackObjectSink,
    B: ExternalBaseProvider,
    I: IntoIterator<Item = usize>,
    R: FnMut(usize) -> CandidateRange,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    bufs: &mut DecodeBufs,
    delta_deps: &[DeltaDepHot],
    external_base_oids: &[OidBytes],
    expected_skip_items: usize,
    indices: I,
    mut range_for_idx: R,
) -> Result<PackExecReport, PackExecError> {
    let pack = PackFile::from_header(pack_bytes, pack_header);
    let mut report = PackExecReport::default();
    let skip_capacity = expected_skip_items.div_ceil(100).max(64);
    report.skips.reserve(skip_capacity.min(u32::MAX as usize));

    let alloc_guard_enabled = alloc_guard::enabled();
    let mut hot_stats = PackExecHotStats::default();

    let env = DecodeEnv {
        pack: &pack,
        limits,
        spill_dir,
        max_delta_depth: plan.max_delta_depth,
        need_offsets: &plan.need_offsets,
        delta_deps,
        external_base_oids,
        delta_dep_index: &plan.delta_dep_index,
    };

    for idx in indices {
        execute_offset_range_with_scratch(
            &env,
            plan,
            paths,
            cache,
            external,
            sink,
            bufs,
            &mut report,
            &mut hot_stats,
            alloc_guard_enabled,
            idx,
            range_for_idx(idx),
        )?;
    }

    sink.finish()?;
    hot_stats.merge_into(&mut report.stats);
    Ok(report)
}

/// Shared per-offset execution path for pack plan executors.
///
/// Decodes one `need_offsets[idx]`, then emits all candidates in `range`.
/// Non-fatal decode failures are recorded as skip records in `report`.
///
/// The function brackets the entire offset in an optional [`AllocGuard`]
/// (when `alloc_guard_enabled` is true) to enforce the zero-allocation
/// invariant on the hot path.
///
/// # Bytes resolution strategy
///
/// After decoding, the function must produce a `&[u8]` slice for the
/// sink. The strategy differs by how the offset was resolved:
///
/// - **Cache hit (initial probe)** — the `cache_get` at the top of the
///   function returned `Some(hit)`. The returned `hit.bytes` slice is
///   saved and reused directly for all candidates at this offset. No
///   second cache lookup occurs. (Verified by the
///   `*_cache_hit_probes_once` tests.)
///
/// - **Cache miss, decoded to `Cache`** — `decode_offset` inflated the
///   object and inserted it into the cache. A second `cache_get` is
///   required to borrow the bytes from the cache's backing storage.
///   If the entry was evicted between insert and this lookup (possible
///   in theory with a tiny cache), the fallback reads from `result_buf`.
///
/// - **Cache miss, decoded to `Scratch`** — bytes live in
///   `bufs.result_buf` and are read directly.
///
/// - **Cache miss, decoded to `Spill`** — bytes live in the `BlobSpill`
///   mmap and are read via `spill.as_slice()`.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
fn execute_offset_range_with_scratch<S: PackObjectSink, B: ExternalBaseProvider>(
    env: &DecodeEnv<'_>,
    plan: &PackPlan,
    paths: &ByteArena,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    bufs: &mut DecodeBufs,
    report: &mut PackExecReport,
    hot_stats: &mut PackExecHotStats,
    alloc_guard_enabled: bool,
    idx: usize,
    range: CandidateRange,
) -> Result<(), PackExecError> {
    let guard = if alloc_guard_enabled {
        Some(AllocGuard::new())
    } else {
        None
    };
    let offset = plan.need_offsets[idx];

    let (cache_result, lookup_nanos) = perf::time(|| cache_get(cache, offset));
    record_timing(&mut report.stats.cache_lookup_nanos, lookup_nanos);
    let (obj_kind, storage, cache_hit_bytes) = if let Some(hit) = cache_result {
        perf::record_cache_hit();
        (hit.kind, DecodedStorage::Cache, Some(hit.bytes))
    } else {
        perf::record_cache_miss();
        let decoded = decode_offset(env, offset, idx, cache, external, hot_stats, report, bufs)?;

        let Some(obj) = decoded else {
            return Ok(());
        };

        (obj.kind, obj.storage, None)
    };

    // Reuse the first probe's bytes on hit to avoid a redundant cache re-probe.
    let bytes: &[u8] = if let Some(bytes) = cache_hit_bytes {
        bytes
    } else {
        match &storage {
            DecodedStorage::Cache => cache_get(cache, offset)
                .map(|hit| hit.bytes)
                .unwrap_or(bufs.result_buf.as_slice()),
            DecodedStorage::Scratch => bufs.result_buf.as_slice(),
            DecodedStorage::Spill(spill) => spill.as_slice(),
        }
    };

    if let Some((start, end)) = range.bounds() {
        for cand_idx in start..end {
            let candidate = &plan.candidates[plan.candidate_offsets[cand_idx].cand_idx as usize];
            if obj_kind != ObjectKind::Blob {
                report.skips.push(SkipRecord {
                    offset,
                    reason: SkipReason::NotBlob,
                });
                hot_stats.inc_skipped();
                continue;
            }
            let path = paths.get(candidate.ctx.path_ref);
            let (emit_result, emit_nanos) = perf::time(|| sink.emit(candidate, path, bytes));
            emit_result?;
            record_timing(&mut report.stats.sink_emit_nanos, emit_nanos);
            hot_stats.inc_emitted();
        }
    }

    if let Some(guard) = guard {
        guard.assert_no_alloc();
    }

    Ok(())
}

/// Executes a pack plan using caller-provided scratch buffers.
///
/// Identical to [`execute_pack_plan`] but allows the caller to amortize
/// buffer allocations across multiple pack plans by reusing a single
/// [`PackExecScratch`]. The scratch is `prepare()`d at the start of
/// each call and may grow but never shrinks.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
) -> Result<PackExecReport, PackExecError> {
    let pack_header = parse_pack_header_for_plan(plan, pack_bytes)?;
    execute_pack_plan_with_scratch_from_header(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        scratch,
    )
}

/// Executes a pack plan using caller-provided scratch buffers and a pre-parsed
/// pack header.
///
/// `pack_header` must come from [`parse_pack_header_for_plan`] for the same
/// `plan` and `pack_bytes`.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_from_header<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
) -> Result<PackExecReport, PackExecError> {
    scratch.prepare(plan, limits);
    if let Some(order) = plan.exec_order.as_ref() {
        // Out-of-order execution: precompute exact candidate ranges by need index.
        build_candidate_ranges(plan, &mut scratch.candidate_ranges);
        let candidate_ranges = scratch.candidate_ranges.as_slice();
        let bufs = &mut scratch.bufs;
        let delta_deps = scratch.delta_deps_hot.as_slice();
        let external_base_oids = scratch.external_base_oids.as_slice();
        execute_pack_plan_with_selector_from_header(
            plan,
            pack_bytes,
            pack_header,
            paths,
            limits,
            cache,
            external,
            sink,
            spill_dir,
            bufs,
            delta_deps,
            external_base_oids,
            plan.candidate_offsets.len(),
            order.iter().copied().map(|idx| idx as usize),
            |idx| candidate_ranges[idx],
        )
    } else {
        // Monotone execution: merge candidate offsets with need offsets.
        let cand = &plan.candidate_offsets;
        let mut cand_idx = 0usize;
        let bufs = &mut scratch.bufs;
        let delta_deps = scratch.delta_deps_hot.as_slice();
        let external_base_oids = scratch.external_base_oids.as_slice();
        execute_pack_plan_with_selector_from_header(
            plan,
            pack_bytes,
            pack_header,
            paths,
            limits,
            cache,
            external,
            sink,
            spill_dir,
            bufs,
            delta_deps,
            external_base_oids,
            plan.candidate_offsets.len(),
            0..plan.need_offsets.len(),
            |idx| next_candidate_range(cand, plan.need_offsets[idx], &mut cand_idx),
        )
    }
}

/// Executes a pack plan for a subset of offsets in `exec_indices`.
///
/// This is the shard-parallel entry point: callers split `exec_order`
/// (or `0..need_offsets.len()`) into disjoint index slices and dispatch
/// each slice to a separate shard with its own scratch buffers and cache.
/// Results are merged afterward with [`merge_pack_exec_reports`].
///
/// # Arguments
///
/// - `exec_indices` — which `need_offsets` indices this shard decodes.
///   May be non-contiguous; order determines decode sequence.
/// - `candidate_ranges` — precomputed by [`build_candidate_ranges`],
///   indexed by `need_offsets` position. Must have length
///   `plan.need_offsets.len()`.
/// - each entry in `exec_indices` must be `< plan.need_offsets.len()`.
///
/// # Delta base resolution
///
/// Because each shard has an independent cache, delta bases decoded by a
/// different shard will not be present. The executor falls back to
/// `decode_base_from_pack` which re-inflates the chain from pack bytes.
/// For plans with deep delta chains, ensure related base/dependent pairs
/// land in the same shard to avoid redundant work.
///
/// # Errors
///
/// Same as [`execute_pack_plan_with_scratch`]: `PackParse` and `Sink`
/// errors are fatal; decode failures are recorded as skips.
///
/// # Panics
///
/// Panics if `exec_indices` contains an out-of-bounds index for
/// `plan.need_offsets` or `candidate_ranges`.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_indices<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    exec_indices: &[usize],
    candidate_ranges: &[CandidateRange],
) -> Result<PackExecReport, PackExecError> {
    let pack_header = parse_pack_header_for_plan(plan, pack_bytes)?;
    execute_pack_plan_with_scratch_indices_from_header(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        scratch,
        exec_indices,
        candidate_ranges,
    )
}

/// Executes shard indices using caller-provided scratch buffers and a
/// pre-parsed pack header.
///
/// `pack_header` must come from [`parse_pack_header_for_plan`] for the same
/// `plan` and `pack_bytes`.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_indices_from_header<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    exec_indices: &[usize],
    candidate_ranges: &[CandidateRange],
) -> Result<PackExecReport, PackExecError> {
    debug_assert_eq!(candidate_ranges.len(), plan.need_offsets.len());
    scratch.prepare(plan, limits);
    let bufs = &mut scratch.bufs;
    execute_pack_plan_with_scratch_indices_from_header_parts(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        exec_indices,
        candidate_ranges,
        scratch.delta_deps_hot.as_slice(),
        scratch.external_base_oids.as_slice(),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_pack_plan_with_scratch_indices_from_header_parts<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    bufs: &mut DecodeBufs,
    exec_indices: &[usize],
    candidate_ranges: &[CandidateRange],
    delta_deps: &[DeltaDepHot],
    external_base_oids: &[OidBytes],
) -> Result<PackExecReport, PackExecError> {
    let mut expected = exec_indices.len();
    for &idx in exec_indices {
        expected = expected.saturating_add(candidate_ranges[idx].candidate_count());
    }
    execute_pack_plan_with_selector_from_header(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        delta_deps,
        external_base_oids,
        expected,
        exec_indices.iter().copied(),
        |idx| candidate_ranges[idx],
    )
}

/// Executes a shard over explicit indices using precomputed plan-hot delta tables.
///
/// This entry point avoids rebuilding `delta_deps_hot` per shard call by
/// reusing `hot_deps` computed once per plan.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_pack_plan_with_scratch_indices_hot_deps<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    exec_indices: &[usize],
    candidate_ranges: &[CandidateRange],
    hot_deps: &PackPlanHotDeps,
) -> Result<PackExecReport, PackExecError> {
    let pack_header = parse_pack_header_for_plan(plan, pack_bytes)?;
    debug_assert_eq!(candidate_ranges.len(), plan.need_offsets.len());
    scratch.prepare_bufs(limits, plan.max_delta_depth);
    let bufs = &mut scratch.bufs;
    execute_pack_plan_with_scratch_indices_from_header_parts(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        exec_indices,
        candidate_ranges,
        hot_deps.delta_deps(),
        hot_deps.external_base_oids(),
    )
}

/// Executes a natural-order shard over `[start_idx, end_idx)` of `need_offsets`.
///
/// This variant avoids materializing `exec_indices` when a plan has no
/// `exec_order` permutation. Candidate ranges are discovered with a single
/// forward merge cursor over `candidate_offsets`.
///
/// `start_idx..end_idx` must be a valid half-open range over
/// `plan.need_offsets`.
///
/// # Errors
///
/// Same as [`execute_pack_plan_with_scratch`]: `PackParse` and `Sink`
/// errors are fatal; decode failures are recorded as skips.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_range<S: PackObjectSink, B: ExternalBaseProvider>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    start_idx: usize,
    end_idx: usize,
) -> Result<PackExecReport, PackExecError> {
    let pack_header = parse_pack_header_for_plan(plan, pack_bytes)?;
    execute_pack_plan_with_scratch_range_from_header(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        scratch,
        start_idx,
        end_idx,
    )
}

/// Executes a natural-order shard over `[start_idx, end_idx)` using a
/// pre-parsed pack header.
///
/// `pack_header` must come from [`parse_pack_header_for_plan`] for the same
/// `plan` and `pack_bytes`.
#[allow(clippy::too_many_arguments)]
pub fn execute_pack_plan_with_scratch_range_from_header<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    start_idx: usize,
    end_idx: usize,
) -> Result<PackExecReport, PackExecError> {
    debug_assert!(start_idx <= end_idx);
    debug_assert!(end_idx <= plan.need_offsets.len());
    scratch.prepare(plan, limits);
    let bufs = &mut scratch.bufs;
    execute_pack_plan_with_scratch_range_from_header_parts(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        start_idx,
        end_idx,
        scratch.delta_deps_hot.as_slice(),
        scratch.external_base_oids.as_slice(),
    )
}

#[allow(clippy::too_many_arguments)]
fn execute_pack_plan_with_scratch_range_from_header_parts<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    pack_header: PackHeader,
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    bufs: &mut DecodeBufs,
    start_idx: usize,
    end_idx: usize,
    delta_deps: &[DeltaDepHot],
    external_base_oids: &[OidBytes],
) -> Result<PackExecReport, PackExecError> {
    let mut expected = end_idx.saturating_sub(start_idx);
    if start_idx < end_idx {
        let first_offset = plan.need_offsets[start_idx];
        let last_offset = plan.need_offsets[end_idx - 1];
        let cand_start = plan
            .candidate_offsets
            .partition_point(|cand| cand.offset < first_offset);
        let cand_end = plan
            .candidate_offsets
            .partition_point(|cand| cand.offset <= last_offset);
        expected = expected.saturating_add(cand_end.saturating_sub(cand_start));
    }
    if start_idx >= end_idx {
        return execute_pack_plan_with_selector_from_header(
            plan,
            pack_bytes,
            pack_header,
            paths,
            limits,
            cache,
            external,
            sink,
            spill_dir,
            bufs,
            delta_deps,
            external_base_oids,
            expected,
            std::iter::empty::<usize>(),
            |_| CandidateRange::missing(),
        );
    }

    let cand = &plan.candidate_offsets;
    let first_offset = plan.need_offsets[start_idx];
    let mut cand_idx = cand.partition_point(|entry| entry.offset < first_offset);
    execute_pack_plan_with_selector_from_header(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        delta_deps,
        external_base_oids,
        expected,
        start_idx..end_idx,
        |idx| next_candidate_range(cand, plan.need_offsets[idx], &mut cand_idx),
    )
}

/// Executes a natural-order shard using precomputed plan-hot delta tables.
///
/// This entry point avoids rebuilding `delta_deps_hot` per shard call by
/// reusing `hot_deps` computed once per plan.
#[allow(clippy::too_many_arguments)]
pub(super) fn execute_pack_plan_with_scratch_range_hot_deps<
    S: PackObjectSink,
    B: ExternalBaseProvider,
>(
    plan: &PackPlan,
    pack_bytes: &[u8],
    paths: &ByteArena,
    limits: &PackDecodeLimits,
    cache: &mut PackCache,
    external: &mut B,
    sink: &mut S,
    spill_dir: &Path,
    scratch: &mut PackExecScratch,
    start_idx: usize,
    end_idx: usize,
    hot_deps: &PackPlanHotDeps,
) -> Result<PackExecReport, PackExecError> {
    let pack_header = parse_pack_header_for_plan(plan, pack_bytes)?;
    debug_assert!(start_idx <= end_idx);
    debug_assert!(end_idx <= plan.need_offsets.len());
    scratch.prepare_bufs(limits, plan.max_delta_depth);
    let bufs = &mut scratch.bufs;
    execute_pack_plan_with_scratch_range_from_header_parts(
        plan,
        pack_bytes,
        pack_header,
        paths,
        limits,
        cache,
        external,
        sink,
        spill_dir,
        bufs,
        start_idx,
        end_idx,
        hot_deps.delta_deps(),
        hot_deps.external_base_oids(),
    )
}

/// Read the entire pack into `out`, returning a fatal error on short reads.
fn read_pack_bytes<R: PackReader>(reader: &mut R, out: &mut Vec<u8>) -> Result<(), PackExecError> {
    let len_u64 = reader.len();
    let len = usize::try_from(len_u64).map_err(|_| {
        PackExecError::PackRead(format!("pack length {len_u64} exceeds addressable memory"))
    })?;
    out.clear();
    out.resize(len, 0);
    if len == 0 {
        return Ok(());
    }
    reader
        .read_exact_at(0, out)
        .map_err(|err| PackExecError::PackRead(err.to_string()))
}

/// Build candidate index ranges for each `need_offsets` entry.
///
/// Within sequential (non-shard) execution, this is called only when
/// `exec_order` reorders offsets. Shard-parallel entry points require
/// callers to precompute ranges unconditionally because they access
/// arbitrary index subsets. Avoids repeated scans of the candidate list
/// by leveraging sorted candidate offsets.
///
/// Assumes `candidate_offsets` is sorted ascending by offset.
/// Runs in `O(need_offsets.len() + candidate_offsets.len())`.
pub fn build_candidate_ranges(plan: &PackPlan, ranges: &mut Vec<CandidateRange>) {
    // Single pass over sorted offsets; each need offset maps to a contiguous
    // range in `candidate_offsets` (if any). Requires plan invariants:
    // `need_offsets` sorted unique and `candidate_offsets` sorted by offset.
    ranges.clear();
    ranges.resize(plan.need_offsets.len(), CandidateRange::missing());
    let mut cand_idx = 0usize;
    for (need_idx, &offset) in plan.need_offsets.iter().enumerate() {
        ranges[need_idx] = next_candidate_range(&plan.candidate_offsets, offset, &mut cand_idx);
    }
}

/// Reads and validates an entry header, normalizing parse failures into
/// `PackDecodeError::PackParse`.
#[inline]
fn read_entry_header(
    pack: &PackFile<'_>,
    offset: u64,
    max_header_bytes: usize,
) -> Result<EntryHeader, PackDecodeError> {
    pack.entry_header_at(offset, max_header_bytes)
        .map_err(PackDecodeError::PackParse)
}

/// Converts an entry size to `usize` and preserves object-vs-delta overflow
/// classification for diagnostics.
#[inline]
fn size_to_usize(size: u64, kind: EntryKind) -> Result<usize, PackDecodeError> {
    usize::try_from(size).map_err(|_| match kind {
        EntryKind::NonDelta { .. } => PackDecodeError::ObjectTooLarge {
            size,
            max: usize::MAX,
        },
        EntryKind::OfsDelta { .. } | EntryKind::RefDelta { .. } => PackDecodeError::DeltaTooLarge {
            size,
            max: usize::MAX,
        },
    })
}

/// Converts a delta payload size to `usize`, reporting overflow as `DeltaTooLarge`.
#[inline]
fn delta_size_to_usize(size: u64) -> Result<usize, PackDecodeError> {
    usize::try_from(size).map_err(|_| PackDecodeError::DeltaTooLarge {
        size,
        max: usize::MAX,
    })
}

/// Converts a pack byte offset to `usize` for slice indexing.
#[inline]
fn data_start_to_usize(data_start: u64) -> Result<usize, PackDecodeError> {
    usize::try_from(data_start)
        .map_err(|_| PackDecodeError::PackParse(PackParseError::OffsetOutOfRange(data_start)))
}

/// Inflated delta payload bytes, either in-memory or spill-backed.
///
/// Small payloads (≤ `limits.max_delta_bytes`) are inflated into
/// `inflate_buf` and borrowed as a `Slice`. Oversized payloads are
/// streamed into a spill-backed mmap to avoid holding the full delta
/// in resident memory. The choice is made once in
/// [`inflate_delta_payload`] and is transparent to callers via
/// `as_slice()`.
///
/// The lifetime `'a` on `Slice` borrows from `inflate_buf`; `Spill`
/// owns its backing and has no lifetime dependency.
enum DeltaPayload<'a> {
    Slice(&'a [u8]),
    Spill(BlobSpill),
}

impl DeltaPayload<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Slice(bytes) => bytes,
            Self::Spill(spill) => spill.as_slice(),
        }
    }
}

/// Inflate a delta entry's compressed payload into memory or a spill file.
///
/// If the declared delta size fits within `limits.max_delta_bytes`, the
/// payload is inflated into `inflate_buf` and returned as a borrowed
/// slice. Otherwise the payload is streamed into a spill-backed mmap to
/// keep resident memory bounded.
fn inflate_delta_payload<'a>(
    de: &mut flate2::Decompress,
    pack: &PackFile<'_>,
    data_start: u64,
    delta_size: u64,
    limits: &PackDecodeLimits,
    spill_dir: &Path,
    inflate_buf: &'a mut Vec<u8>,
) -> Result<DeltaPayload<'a>, PackDecodeError> {
    let delta_size = delta_size_to_usize(delta_size)?;
    let data_start = data_start_to_usize(data_start)?;
    if delta_size <= limits.max_delta_bytes {
        let consumed = inflate_limited_with(
            de,
            pack.slice_from(data_start),
            inflate_buf,
            limits.max_delta_bytes,
        )
        .map_err(PackDecodeError::Inflate)?;
        let _ = consumed;
        Ok(DeltaPayload::Slice(inflate_buf.as_slice()))
    } else {
        let mut spill = BlobSpill::new(spill_dir, delta_size)
            .map_err(|_| PackDecodeError::Inflate(super::pack_inflate::InflateError::Backend))?;
        let mut writer = spill.writer();
        inflate_stream(pack.slice_from(data_start), delta_size, |chunk| {
            writer
                .write(chunk)
                .map_err(|_| super::pack_inflate::InflateError::Backend)
        })
        .map_err(PackDecodeError::Inflate)?;
        writer
            .finish()
            .map_err(|_| PackDecodeError::Inflate(super::pack_inflate::InflateError::Backend))?;
        Ok(DeltaPayload::Spill(spill))
    }
}

/// Appends a non-fatal skip and updates hot-path skip counters.
#[inline]
fn record_skip(
    report: &mut PackExecReport,
    hot_stats: &mut PackExecHotStats,
    offset: u64,
    reason: SkipReason,
) {
    report.skips.push(SkipRecord { offset, reason });
    hot_stats.inc_skipped();
}

/// Maps internal delta decode failures into external skip taxonomy.
#[inline]
fn skip_reason_from_delta_error(err: DeltaDecodeError) -> SkipReason {
    match err {
        DeltaDecodeError::Decode(err) => SkipReason::Decode(err),
        DeltaDecodeError::Delta(err) => SkipReason::Delta(err),
    }
}

/// Offer decoded delta output to the cache and determine final storage.
///
/// Called after a successful delta application to decide where the
/// reconstructed bytes should live for the remainder of this offset's
/// processing:
///
/// - **`Scratch` or `Cache` input** — the output lives in `result_buf`.
///   The function attempts `cache.insert()`. On success the storage is
///   promoted to `Cache` (the sink will read from cache backing). On
///   failure (oversize entry or cache at capacity) the output stays in
///   `Scratch` and a cache-reject metric is recorded.
///
/// - **`Spill` input** — the output is already in a mmap-backed temp
///   file, too large for cache benefit. The spill is returned as-is
///   and a cache-reject metric is recorded directly.
fn finalize_decoded_delta(
    offset: u64,
    kind: ObjectKind,
    storage: DecodedStorage,
    out_len: usize,
    cache: &mut PackCache,
    result_buf: &mut [u8],
    stats: &mut PackExecStats,
) -> DecodedObject {
    if matches!(&storage, DecodedStorage::Spill(_)) {
        perf_stats::sat_add_u32(&mut stats.large_blob_spilled_count, 1);
        perf_stats::sat_add_u64(&mut stats.large_blob_bytes, out_len as u64);
    }
    match storage {
        DecodedStorage::Cache | DecodedStorage::Scratch => {
            if cache.insert(offset, kind, result_buf) {
                DecodedObject {
                    kind,
                    storage: DecodedStorage::Cache,
                }
            } else {
                stats.record_cache_reject(out_len);
                DecodedObject {
                    kind,
                    storage: DecodedStorage::Scratch,
                }
            }
        }
        DecodedStorage::Spill(spill) => {
            stats.record_cache_reject(out_len);
            DecodedObject {
                kind,
                storage: DecodedStorage::Spill(spill),
            }
        }
    }
}

/// Inflate a delta payload, apply it against known base bytes, and
/// return the output storage and length.
///
/// This is the "inflate + apply + inc_decoded" combo used by all code
/// paths that already have resolved base bytes in hand (cache hit,
/// external base, or fallback unwind). Converts any
/// [`DeltaDecodeError`] into the appropriate [`SkipReason`].
#[allow(clippy::too_many_arguments)]
fn decode_delta_against_base(
    de: &mut flate2::Decompress,
    env: &DecodeEnv<'_>,
    data_start: u64,
    delta_size: u64,
    base_bytes: &[u8],
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
) -> Result<(DecodedStorage, usize), SkipReason> {
    let (storage, out_len) = decode_delta_output(
        de,
        env,
        data_start,
        delta_size,
        base_bytes,
        inflate_buf,
        result_buf,
    )
    .map_err(skip_reason_from_delta_error)?;
    hot_stats.inc_decoded();
    Ok((storage, out_len))
}

/// Resolve an external REF base, apply the delta payload, and finalize
/// the decoded object. Returns `None` when the offset is skipped
/// (missing/error external base or delta decode failure).
#[allow(clippy::too_many_arguments)]
fn resolve_external_and_apply_delta<B: ExternalBaseProvider>(
    de: &mut flate2::Decompress,
    env: &DecodeEnv<'_>,
    offset: u64,
    base_oid: OidBytes,
    data_start: u64,
    delta_size: u64,
    cache: &mut PackCache,
    external: &mut B,
    hot_stats: &mut PackExecHotStats,
    report: &mut PackExecReport,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
) -> Result<Option<DecodedObject>, PackExecError> {
    hot_stats.inc_external_base_call();
    match external.load_base(&base_oid) {
        Ok(Some(base)) => {
            let (storage, out_len) = match decode_delta_against_base(
                de,
                env,
                data_start,
                delta_size,
                &base.bytes,
                inflate_buf,
                result_buf,
                hot_stats,
            ) {
                Ok(decoded) => decoded,
                Err(reason) => {
                    record_skip(report, hot_stats, offset, reason);
                    return Ok(None);
                }
            };
            let obj = finalize_decoded_delta(
                offset,
                base.kind,
                storage,
                out_len,
                cache,
                result_buf,
                &mut report.stats,
            );
            Ok(Some(obj))
        }
        Ok(None) => {
            record_skip(
                report,
                hot_stats,
                offset,
                SkipReason::ExternalBaseMissing { oid: base_oid },
            );
            Ok(None)
        }
        Err(err) => {
            record_skip(
                report,
                hot_stats,
                offset,
                SkipReason::ExternalBaseError {
                    detail: err.to_string(),
                },
            );
            Ok(None)
        }
    }
}

/// Resolve the base for an in-pack OFS delta, apply the delta, and
/// finalize the decoded object. Returns `None` when the decode is
/// skipped (non-fatal).
///
/// This encapsulates the common "cache-or-decode base → apply delta →
/// finalize" pipeline used by all three in-pack delta code paths in
/// [`decode_offset`]:
///
/// 1. **Cache hit** — base bytes are borrowed directly from `PackCache`.
/// 2. **Cache miss** — falls back to [`decode_base_from_pack`], which
///    walks the chain from `base_offset`, inflating and unwinding into
///    `base_buf` (or a spill mmap). Fallback timing is recorded into
///    `report.stats.fallback_resolve_nanos`.
///
/// After base resolution, [`decode_delta_against_base`] inflates the
/// delta payload and applies it; [`finalize_decoded_delta`] decides
/// whether the result goes into the cache, stays in scratch, or is
/// spill-backed.
#[allow(clippy::too_many_arguments)]
fn resolve_and_apply_delta<B: ExternalBaseProvider>(
    de: &mut flate2::Decompress,
    libde: Option<&mut crate::pack_inflate_libdeflate::LibdeflateDecompressor>,
    env: &DecodeEnv<'_>,
    offset: u64,
    base_offset: u64,
    data_start: u64,
    delta_size: u64,
    cache: &mut PackCache,
    external: &mut B,
    hot_stats: &mut PackExecHotStats,
    report: &mut PackExecReport,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    base_buf: &mut Vec<u8>,
    delta_stack: &mut Vec<DeltaFrame>,
) -> Result<Option<DecodedObject>, PackExecError> {
    let base = match cache_get(cache, base_offset) {
        Some(base) => {
            hot_stats.inc_base_cache_hit();
            BaseBytes {
                kind: base.kind,
                storage: BaseStorage::Slice(base.bytes),
            }
        }
        None => {
            hot_stats.inc_base_cache_miss();
            let (result, resolve_nanos) = perf::time(|| {
                decode_base_from_pack(
                    de,
                    libde,
                    env,
                    base_offset,
                    cache,
                    external,
                    hot_stats,
                    report,
                    inflate_buf,
                    result_buf,
                    base_buf,
                    delta_stack,
                )
            });
            record_timing(&mut report.stats.fallback_resolve_nanos, resolve_nanos);
            match result {
                Ok(base) => base,
                Err(reason) => {
                    record_skip(report, hot_stats, offset, reason);
                    return Ok(None);
                }
            }
        }
    };

    let (storage, out_len) = match decode_delta_against_base(
        de,
        env,
        data_start,
        delta_size,
        base.bytes(),
        inflate_buf,
        result_buf,
        hot_stats,
    ) {
        Ok(decoded) => decoded,
        Err(reason) => {
            record_skip(report, hot_stats, offset, reason);
            return Ok(None);
        }
    };

    let obj = finalize_decoded_delta(
        offset,
        base.kind,
        storage,
        out_len,
        cache,
        result_buf,
        &mut report.stats,
    );
    Ok(Some(obj))
}

/// Decodes a single offset, using the cache for bases and for storing results.
///
/// Returns `Ok(None)` for non-fatal issues (decode errors, missing bases, or
/// external base provider errors), with the skip recorded in the report.
/// Successful decodes return metadata describing where the bytes reside
/// (cache, scratch, or spill).
///
/// # Dispatch paths
///
/// The function attempts three paths, falling through as needed:
///
/// 1. **Planned-dep fast path** — when `delta_dep_index` maps this offset
///    to a [`DeltaDepHot`] with persisted header metadata (`has_header_meta`),
///    the entry header parse is skipped entirely. This path handles both
///    external REF deltas (routed to the external base provider via
///    [`resolve_external_and_apply_delta`]) and in-pack OFS deltas
///    (routed to [`resolve_and_apply_delta`]). Returns immediately.
///
/// 2. **Fallback header parse** — for offsets without a planned-dep entry
///    (or where `has_header_meta` is false, as in synthetic plans), the
///    raw entry header is parsed from pack bytes. The result branches by
///    entry kind:
///    - **Non-delta** — inflated directly into `result_buf` when the
///      object fits within `max_object_bytes`, or streamed to a spill
///      mmap for oversized objects. Offered to the cache on success.
///    - **OFS delta** — delegates to [`resolve_and_apply_delta`] using
///      the base offset from the header.
///    - **REF delta** — proceeds to path 3.
///
/// 3. **REF delta from header** — checks whether a planned-dep exists
///    with an in-pack base offset (i.e., the planner resolved the REF to
///    an OFS equivalent). If so, delegates to [`resolve_and_apply_delta`].
///    Otherwise, resolves the OID (preferring the interned OID from
///    `external_base_oids` over the raw header OID) and routes to the
///    external base provider via [`resolve_external_and_apply_delta`].
#[allow(clippy::too_many_arguments)]
fn decode_offset<B: ExternalBaseProvider>(
    env: &DecodeEnv<'_>,
    offset: u64,
    need_idx: usize,
    cache: &mut PackCache,
    external: &mut B,
    hot_stats: &mut PackExecHotStats,
    report: &mut PackExecReport,
    bufs: &mut DecodeBufs,
) -> Result<Option<DecodedObject>, PackExecError> {
    let planned_dep = delta_dep_at_index(env.delta_deps, env.delta_dep_index, need_idx);

    // Fast path: use plan-time persisted delta metadata when available.
    if let Some(dep) = planned_dep.filter(|dep| dep.has_header_meta()) {
        if dep.is_external() {
            let Some(base_oid) = env
                .external_base_oids
                .get(dep.external_oid_idx as usize)
                .copied()
            else {
                record_skip(
                    report,
                    hot_stats,
                    offset,
                    SkipReason::Decode(PackDecodeError::PackParse(PackParseError::Truncated)),
                );
                return Ok(None);
            };
            return resolve_external_and_apply_delta(
                &mut bufs.de,
                env,
                offset,
                base_oid,
                dep.data_start,
                dep.delta_size,
                cache,
                external,
                hot_stats,
                report,
                &mut bufs.inflate_buf,
                &mut bufs.result_buf,
            );
        }

        return resolve_and_apply_delta(
            &mut bufs.de,
            bufs.libde.as_mut(),
            env,
            offset,
            dep.base_offset,
            dep.data_start,
            dep.delta_size,
            cache,
            external,
            hot_stats,
            report,
            &mut bufs.inflate_buf,
            &mut bufs.result_buf,
            &mut bufs.base_buf,
            &mut bufs.delta_stack,
        );
    }

    // Fallback path for synthetic/manual plans without persisted metadata.
    let header = match read_entry_header(env.pack, offset, env.limits.max_header_bytes) {
        Ok(header) => header,
        Err(err) => {
            record_skip(report, hot_stats, offset, SkipReason::Decode(err));
            return Ok(None);
        }
    };

    match header.kind {
        EntryKind::NonDelta { kind } => {
            let size = match size_to_usize(header.size, header.kind) {
                Ok(size) => size,
                Err(err) => {
                    record_skip(report, hot_stats, offset, SkipReason::Decode(err));
                    return Ok(None);
                }
            };

            if size <= env.limits.max_object_bytes {
                bufs.result_buf.clear();
                if bufs.result_buf.capacity() < size {
                    bufs.result_buf.reserve(size - bufs.result_buf.capacity());
                }
                let (inflate_res, nanos) = perf::time(|| {
                    inflate_entry_payload_with(
                        &mut bufs.de,
                        bufs.libde.as_mut(),
                        env.pack,
                        &header,
                        &mut bufs.result_buf,
                        env.limits,
                    )
                });
                if let Err(err) = inflate_res {
                    record_skip(report, hot_stats, offset, SkipReason::Decode(err));
                    return Ok(None);
                }
                perf::record_pack_inflate(bufs.result_buf.len(), nanos);
                hot_stats.inc_decoded();

                if cache.insert(offset, kind, &bufs.result_buf) {
                    Ok(Some(DecodedObject {
                        kind,
                        storage: DecodedStorage::Cache,
                    }))
                } else {
                    report.stats.record_cache_reject(bufs.result_buf.len());
                    Ok(Some(DecodedObject {
                        kind,
                        storage: DecodedStorage::Scratch,
                    }))
                }
            } else {
                let mut spill =
                    BlobSpill::new(env.spill_dir, size).map_err(PackExecError::Spill)?;
                let mut writer = spill.writer();
                let (inflate_res, nanos) = perf::time(|| {
                    inflate_stream(env.pack.slice_from(header.data_start), size, |chunk| {
                        writer
                            .write(chunk)
                            .map_err(|_| super::pack_inflate::InflateError::Backend)
                    })
                });
                if let Err(err) = inflate_res {
                    record_skip(
                        report,
                        hot_stats,
                        offset,
                        SkipReason::Decode(PackDecodeError::Inflate(err)),
                    );
                    return Ok(None);
                }
                writer.finish().map_err(PackExecError::Spill)?;
                perf::record_pack_inflate(size, nanos);
                hot_stats.inc_decoded();
                report.stats.record_cache_reject(size);
                perf_stats::sat_add_u32(&mut report.stats.large_blob_spilled_count, 1);
                perf_stats::sat_add_u64(&mut report.stats.large_blob_bytes, size as u64);

                Ok(Some(DecodedObject {
                    kind,
                    storage: DecodedStorage::Spill(spill),
                }))
            }
        }
        EntryKind::OfsDelta { base_offset } => resolve_and_apply_delta(
            &mut bufs.de,
            bufs.libde.as_mut(),
            env,
            offset,
            base_offset,
            header.data_start as u64,
            header.size,
            cache,
            external,
            hot_stats,
            report,
            &mut bufs.inflate_buf,
            &mut bufs.result_buf,
            &mut bufs.base_buf,
            &mut bufs.delta_stack,
        ),
        EntryKind::RefDelta { base_oid } => {
            if let Some(dep) = planned_dep {
                if !dep.is_external() {
                    return resolve_and_apply_delta(
                        &mut bufs.de,
                        bufs.libde.as_mut(),
                        env,
                        offset,
                        dep.base_offset,
                        header.data_start as u64,
                        header.size,
                        cache,
                        external,
                        hot_stats,
                        report,
                        &mut bufs.inflate_buf,
                        &mut bufs.result_buf,
                        &mut bufs.base_buf,
                        &mut bufs.delta_stack,
                    );
                }
            }

            let resolved_oid = planned_dep
                .and_then(|dep| {
                    dep.is_external()
                        .then(|| {
                            env.external_base_oids
                                .get(dep.external_oid_idx as usize)
                                .copied()
                        })
                        .flatten()
                })
                .unwrap_or(base_oid);
            resolve_external_and_apply_delta(
                &mut bufs.de,
                env,
                offset,
                resolved_oid,
                header.data_start as u64,
                header.size,
                cache,
                external,
                hot_stats,
                report,
                &mut bufs.inflate_buf,
                &mut bufs.result_buf,
            )
        }
    }
}

/// Inflate a delta payload, apply it against `base_bytes`, and produce
/// the reconstructed object.
///
/// Returns the storage location of the output and its byte length. When
/// the output fits within `limits.max_object_bytes`, it is written into
/// `result_buf` (returned as `DecodedStorage::Scratch`). Otherwise it is
/// streamed into a spill-backed mmap (`DecodedStorage::Spill`).
///
/// `inflate_buf` is used as scratch for the raw delta payload; it may be
/// overwritten regardless of the outcome.
fn decode_delta_output(
    de: &mut flate2::Decompress,
    env: &DecodeEnv<'_>,
    data_start: u64,
    delta_size: u64,
    base_bytes: &[u8],
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
) -> Result<(DecodedStorage, usize), DeltaDecodeError> {
    let (payload_res, inflate_nanos) = perf::time(|| {
        inflate_delta_payload(
            de,
            env.pack,
            data_start,
            delta_size,
            env.limits,
            env.spill_dir,
            inflate_buf,
        )
    });
    let payload = payload_res.map_err(DeltaDecodeError::Decode)?;
    let delta_bytes = payload.as_slice();
    perf::record_pack_inflate(delta_bytes.len(), inflate_nanos);

    let (_, result_size) = delta_sizes(delta_bytes).map_err(DeltaDecodeError::Delta)?;
    if result_size <= env.limits.max_object_bytes {
        let (apply_res, apply_nanos) = perf::time(|| {
            apply_delta(
                base_bytes,
                delta_bytes,
                result_buf,
                env.limits.max_object_bytes,
            )
        });
        if let Err(err) = apply_res {
            return Err(DeltaDecodeError::Delta(err));
        }
        perf::record_delta_apply(result_buf.len(), apply_nanos);
        Ok((DecodedStorage::Scratch, result_buf.len()))
    } else {
        let mut spill = BlobSpill::new(env.spill_dir, result_size)
            .map_err(|_| DeltaDecodeError::Delta(DeltaError::OutputOverrun))?;
        let mut writer = spill.writer();
        let (apply_res, apply_nanos) = perf::time(|| {
            apply_delta_into(base_bytes, delta_bytes, result_size, |chunk| {
                writer.write(chunk).map_err(|_| DeltaError::OutputOverrun)
            })
        });
        if let Err(err) = apply_res {
            return Err(DeltaDecodeError::Delta(err));
        }
        writer
            .finish()
            .map_err(|_| DeltaDecodeError::Delta(DeltaError::OutputOverrun))?;
        perf::record_delta_apply(result_size, apply_nanos);
        Ok((DecodedStorage::Spill(spill), result_size))
    }
}

/// Lookup the delta dependency by `need_offsets` index using the dense index.
///
/// `delta_dep_index` stores either a real index into `delta_deps` or
/// [`NONE_U32`] for "no dependency metadata".
#[inline]
fn delta_dep_at_index(
    delta_deps: &[DeltaDepHot],
    delta_dep_index: &[u32],
    need_idx: usize,
) -> Option<DeltaDepHot> {
    if delta_dep_index.is_empty() {
        return None;
    }
    let idx = *delta_dep_index.get(need_idx)?;
    if idx == NONE_U32 {
        return None;
    }
    delta_deps.get(idx as usize).copied()
}

/// Apply stacked delta frames in reverse (root-outward) order.
///
/// After [`decode_base_from_pack`] resolves the root non-delta base,
/// this function iterates the delta stack from the deepest (closest to
/// root) to the shallowest (closest to the originally requested offset).
/// For each frame it inflates the delta payload and applies it against
/// the current base, producing the next-level reconstructed object.
///
/// Buffer rotation: after each application, `base_buf` and `result_buf`
/// are swapped so the output of one frame becomes the input base for the
/// next. Intermediate results are also offered to the cache (with
/// `base_kind` as the object kind, since kind is inherited from the
/// root). Oversized intermediates move through `base_spill` instead of
/// `base_buf`.
#[allow(clippy::too_many_arguments)]
fn unwind_delta_stack(
    de: &mut flate2::Decompress,
    env: &DecodeEnv<'_>,
    delta_stack: &[DeltaFrame],
    base_kind: ObjectKind,
    base_spill: &mut Option<BlobSpill>,
    cache: &mut PackCache,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    base_buf: &mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
    stats: &mut PackExecStats,
) -> Result<(), DeltaDecodeError> {
    for frame in delta_stack.iter().rev() {
        let base_bytes = base_spill
            .as_ref()
            .map(|spill| spill.as_slice())
            .unwrap_or_else(|| base_buf.as_slice());
        let (storage, out_len) = decode_delta_output(
            de,
            env,
            frame.data_start,
            frame.delta_size,
            base_bytes,
            inflate_buf,
            result_buf,
        )?;

        hot_stats.inc_decoded();
        match storage {
            DecodedStorage::Cache | DecodedStorage::Scratch => {
                std::mem::swap(base_buf, result_buf);
                *base_spill = None;
                if !cache.insert(frame.offset, base_kind, base_buf) {
                    stats.record_cache_reject(base_buf.len());
                }
            }
            DecodedStorage::Spill(spill) => {
                stats.record_cache_reject(out_len);
                *base_spill = Some(spill);
            }
        }
    }
    Ok(())
}

/// Load a REF-delta root base from the external provider.
///
/// Returns the base's object kind and an optional spill handle. Small
/// bases (≤ `max_object_bytes`) are copied into `base_buf`; oversized
/// bases are written to a spill-backed mmap. Either way, the returned
/// `Option<BlobSpill>` tells the caller where the bytes live.
///
/// Errors from the provider or spill I/O are converted to `SkipReason`
/// so the caller can record a non-fatal skip for the affected offset.
fn load_external_root_base<B: ExternalBaseProvider>(
    env: &DecodeEnv<'_>,
    oid: OidBytes,
    external: &mut B,
    base_buf: &mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
    stats: &mut PackExecStats,
) -> Result<(ObjectKind, Option<BlobSpill>), SkipReason> {
    hot_stats.inc_external_base_call();
    match external.load_base(&oid) {
        Ok(Some(base)) => {
            let base_len = base.bytes.len();
            if base_len <= env.limits.max_object_bytes {
                base_buf.clear();
                if base_buf.capacity() < base_len {
                    base_buf.reserve(base_len - base_buf.capacity());
                }
                base_buf.extend_from_slice(&base.bytes);
                hot_stats.inc_decoded();
                Ok((base.kind, None))
            } else {
                let mut spill = BlobSpill::new(env.spill_dir, base_len).map_err(|e| {
                    SkipReason::ExternalBaseError {
                        detail: format!("spill create: {e}"),
                    }
                })?;
                let mut writer = spill.writer();
                writer
                    .write(&base.bytes)
                    .map_err(|e| SkipReason::ExternalBaseError {
                        detail: format!("spill write: {e}"),
                    })?;
                writer.finish().map_err(|e| SkipReason::ExternalBaseError {
                    detail: format!("spill finish: {e}"),
                })?;
                hot_stats.inc_decoded();
                stats.record_cache_reject(base_len);
                Ok((base.kind, Some(spill)))
            }
        }
        Ok(None) => Err(SkipReason::ExternalBaseMissing { oid }),
        Err(err) => Err(SkipReason::ExternalBaseError {
            detail: err.to_string(),
        }),
    }
}

/// Unwind the accumulated delta stack against a resolved root base and
/// build the final [`BaseBytes`].
///
/// This is the shared tail of every "found root base" exit in
/// [`decode_base_from_pack`]: it applies deltas in reverse, records the
/// fallback chain metric, and constructs the return value.
#[allow(clippy::too_many_arguments)]
fn unwind_and_build_base<'b>(
    de: &mut flate2::Decompress,
    env: &DecodeEnv<'_>,
    delta_stack: &[DeltaFrame],
    base_kind: ObjectKind,
    mut base_spill: Option<BlobSpill>,
    cache: &mut PackCache,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    base_buf: &'b mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
    stats: &mut PackExecStats,
) -> Result<BaseBytes<'b>, SkipReason> {
    if let Err(err) = unwind_delta_stack(
        de,
        env,
        delta_stack,
        base_kind,
        &mut base_spill,
        cache,
        inflate_buf,
        result_buf,
        base_buf,
        hot_stats,
        stats,
    ) {
        record_fallback_chain(stats, delta_stack.len());
        return Err(skip_reason_from_delta_error(err));
    }

    record_fallback_chain(stats, delta_stack.len());
    let storage = match base_spill {
        Some(spill) => BaseStorage::Spill(spill),
        None => BaseStorage::Slice(base_buf.as_slice()),
    };
    Ok(BaseBytes {
        kind: base_kind,
        storage,
    })
}

/// Root base discovered while walking a fallback delta chain.
///
/// Returned by [`walk_delta_chain_to_root`] to tell the caller how to
/// materialize the root object. `Pack` carries enough metadata to
/// inflate directly from pack bytes; `External` requires a call to the
/// [`ExternalBaseProvider`].
#[derive(Clone, Copy, Debug)]
enum ChainRoot {
    /// Root is a non-delta entry in the current pack.
    Pack {
        offset: u64,
        kind: ObjectKind,
        size: u64,
        data_start: usize,
    },
    /// Root is a REF-delta base resolved via external provider.
    External { oid: OidBytes },
}

/// Walk delta links from `offset` toward the root base, collecting frames.
///
/// Starting at `offset`, each iteration either follows persisted plan
/// metadata (`DeltaDepHot` via `delta_dep_index`) or falls back to parsing
/// the raw entry header from pack bytes. For each delta encountered, a
/// [`DeltaFrame`] is pushed onto `delta_stack` (in forward/walk order,
/// i.e., shallowest first). The walk terminates when:
///
/// - A **non-delta** pack entry is found → returns `ChainRoot::Pack`.
/// - An **external REF base** is identified → returns `ChainRoot::External`.
/// - **`max_delta_depth`** is exceeded → returns `Err(BaseMissing)`.
/// - A **self-referential** base offset is detected → returns
///   `Err(BaseMissing)` to prevent infinite loops.
///
/// The returned [`ChainRoot`] tells the caller how to materialize the root
/// base bytes before unwinding the stack.
fn walk_delta_chain_to_root(
    env: &DecodeEnv<'_>,
    offset: u64,
    delta_stack: &mut Vec<DeltaFrame>,
    stats: &mut PackExecStats,
) -> Result<ChainRoot, SkipReason> {
    let mut current_offset = offset;
    loop {
        if delta_stack.len() >= env.max_delta_depth as usize {
            record_fallback_chain(stats, delta_stack.len());
            return Err(SkipReason::BaseMissing {
                base_offset: current_offset,
            });
        }

        // Fast path: follow persisted delta metadata when available.
        if let Ok(need_idx) = env.need_offsets.binary_search(&current_offset) {
            if let Some(dep) = delta_dep_at_index(env.delta_deps, env.delta_dep_index, need_idx)
                .filter(|dep| dep.has_header_meta())
            {
                if dep.is_external() {
                    let Some(base_oid) = env
                        .external_base_oids
                        .get(dep.external_oid_idx as usize)
                        .copied()
                    else {
                        record_fallback_chain(stats, delta_stack.len());
                        return Err(SkipReason::Decode(PackDecodeError::PackParse(
                            PackParseError::Truncated,
                        )));
                    };
                    delta_stack.push(DeltaFrame {
                        offset: current_offset,
                        data_start: dep.data_start,
                        delta_size: dep.delta_size,
                    });
                    return Ok(ChainRoot::External { oid: base_oid });
                }

                if dep.base_offset == current_offset {
                    return Err(SkipReason::BaseMissing {
                        base_offset: dep.base_offset,
                    });
                }
                delta_stack.push(DeltaFrame {
                    offset: current_offset,
                    data_start: dep.data_start,
                    delta_size: dep.delta_size,
                });
                current_offset = dep.base_offset;
                continue;
            }
        }

        let header = match read_entry_header(env.pack, current_offset, env.limits.max_header_bytes)
        {
            Ok(header) => header,
            Err(err) => {
                record_fallback_chain(stats, delta_stack.len());
                return Err(SkipReason::Decode(err));
            }
        };

        match header.kind {
            EntryKind::NonDelta { kind } => {
                return Ok(ChainRoot::Pack {
                    offset: current_offset,
                    kind,
                    size: header.size,
                    data_start: header.data_start,
                });
            }
            EntryKind::OfsDelta { base_offset } => {
                if base_offset == current_offset {
                    return Err(SkipReason::BaseMissing { base_offset });
                }
                delta_stack.push(DeltaFrame {
                    offset: current_offset,
                    data_start: header.data_start as u64,
                    delta_size: header.size,
                });
                current_offset = base_offset;
            }
            EntryKind::RefDelta { base_oid } => {
                let dep = env
                    .need_offsets
                    .binary_search(&current_offset)
                    .ok()
                    .and_then(|idx| delta_dep_at_index(env.delta_deps, env.delta_dep_index, idx));
                match dep {
                    Some(dep) if !dep.is_external() => {
                        delta_stack.push(DeltaFrame {
                            offset: current_offset,
                            data_start: if dep.has_header_meta() {
                                dep.data_start
                            } else {
                                header.data_start as u64
                            },
                            delta_size: if dep.has_header_meta() {
                                dep.delta_size
                            } else {
                                header.size
                            },
                        });
                        current_offset = dep.base_offset;
                    }
                    _ => {
                        delta_stack.push(DeltaFrame {
                            offset: current_offset,
                            data_start: header.data_start as u64,
                            delta_size: header.size,
                        });
                        let base_oid = dep
                            .and_then(|dep| {
                                dep.is_external()
                                    .then(|| {
                                        env.external_base_oids
                                            .get(dep.external_oid_idx as usize)
                                            .copied()
                                    })
                                    .flatten()
                            })
                            .unwrap_or(base_oid);
                        return Ok(ChainRoot::External { oid: base_oid });
                    }
                }
            }
        }
    }
}

/// Inflate a pack-local non-delta root base into memory or spill storage.
#[allow(clippy::too_many_arguments)]
fn materialize_pack_root_base(
    de: &mut flate2::Decompress,
    libde: Option<&mut crate::pack_inflate_libdeflate::LibdeflateDecompressor>,
    env: &DecodeEnv<'_>,
    root_offset: u64,
    kind: ObjectKind,
    size_u64: u64,
    data_start: usize,
    cache: &mut PackCache,
    base_buf: &mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
    stats: &mut PackExecStats,
) -> Result<(ObjectKind, Option<BlobSpill>), SkipReason> {
    let size = size_to_usize(size_u64, EntryKind::NonDelta { kind }).map_err(SkipReason::Decode)?;

    // Keep oversized bases in a spill-backed mmap instead of RAM.
    if size <= env.limits.max_object_bytes {
        base_buf.clear();
        if base_buf.capacity() < size {
            base_buf.reserve(size - base_buf.capacity());
        }
        let header = EntryHeader {
            size: size_u64,
            data_start,
            kind: EntryKind::NonDelta { kind },
        };
        let (inflate_res, nanos) = perf::time(|| {
            inflate_entry_payload_with(de, libde, env.pack, &header, base_buf, env.limits)
        });
        if let Err(err) = inflate_res {
            return Err(SkipReason::Decode(err));
        }
        perf::record_pack_inflate(base_buf.len(), nanos);
        hot_stats.inc_decoded();
        if !cache.insert(root_offset, kind, base_buf) {
            stats.record_cache_reject(base_buf.len());
        }
        Ok((kind, None))
    } else {
        let mut spill = BlobSpill::new(env.spill_dir, size).map_err(|_| {
            SkipReason::Decode(PackDecodeError::Inflate(
                super::pack_inflate::InflateError::Backend,
            ))
        })?;
        let mut writer = spill.writer();
        let (inflate_res, nanos) = perf::time(|| {
            inflate_stream(env.pack.slice_from(data_start), size, |chunk| {
                writer
                    .write(chunk)
                    .map_err(|_| super::pack_inflate::InflateError::Backend)
            })
        });
        if let Err(err) = inflate_res {
            return Err(SkipReason::Decode(PackDecodeError::Inflate(err)));
        }
        if writer.finish().is_err() {
            return Err(SkipReason::Decode(PackDecodeError::Inflate(
                super::pack_inflate::InflateError::Backend,
            )));
        }
        perf::record_pack_inflate(size, nanos);
        hot_stats.inc_decoded();
        stats.record_cache_reject(size);
        Ok((kind, Some(spill)))
    }
}

/// Materialize the resolved chain root into base bytes for unwind.
#[allow(clippy::too_many_arguments)]
fn materialize_root_base<B: ExternalBaseProvider>(
    de: &mut flate2::Decompress,
    libde: Option<&mut crate::pack_inflate_libdeflate::LibdeflateDecompressor>,
    env: &DecodeEnv<'_>,
    root: ChainRoot,
    cache: &mut PackCache,
    external: &mut B,
    base_buf: &mut Vec<u8>,
    hot_stats: &mut PackExecHotStats,
    stats: &mut PackExecStats,
) -> Result<(ObjectKind, Option<BlobSpill>), SkipReason> {
    match root {
        ChainRoot::Pack {
            offset,
            kind,
            size,
            data_start,
        } => materialize_pack_root_base(
            de, libde, env, offset, kind, size, data_start, cache, base_buf, hot_stats, stats,
        ),
        ChainRoot::External { oid } => {
            load_external_root_base(env, oid, external, base_buf, hot_stats, stats)
        }
    }
}

/// Decode a base object on demand by walking the delta chain from `offset`.
///
/// Called when a delta's base is not in the cache (fallback path). The
/// algorithm has two phases:
///
/// 1. **Walk forward** ([`walk_delta_chain_to_root`]) — starting at
///    `offset`, follow delta base pointers, pushing a [`DeltaFrame`] for
///    each intermediate delta. The walk prefers persisted plan metadata
///    (`DeltaDepHot`) when available and falls back to parsing entry
///    headers from pack bytes. Terminates when a non-delta entry or an
///    external REF base is reached, or `max_delta_depth` is exceeded.
///
/// 2. **Unwind backward** ([`unwind_and_build_base`]) — materializes the
///    root base (via [`materialize_root_base`]), then iterates the delta
///    stack in reverse. For each frame, the delta payload is inflated and
///    applied against the current base, writing output into `result_buf`.
///    After each application, `base_buf` and `result_buf` are swapped so
///    the latest output becomes the input base for the next frame.
///    Intermediate results are offered to the cache at each step.
///
/// # Oversized object handling
///
/// Both the root base and each intermediate delta output may exceed
/// `limits.max_object_bytes`. When this happens:
///
/// - **Root base** — `materialize_pack_root_base` or
///   `load_external_root_base` streams the object into a `BlobSpill`
///   mmap rather than `base_buf`. The spill handle is threaded through
///   `unwind_delta_stack` as `base_spill`.
///
/// - **Intermediate delta output** — `decode_delta_output` returns
///   `DecodedStorage::Spill(spill)` when the result exceeds the size
///   cap. During the unwind, the spill replaces `base_spill` and the
///   next frame reads from it instead of `base_buf`.
///
/// Returns the fully resolved base bytes (in `base_buf` or a spill) on
/// success, or a `SkipReason` for non-fatal failures. Callers record the
/// skip on the *original* dependent offset, not on intermediate chain
/// entries.
#[allow(clippy::too_many_arguments)]
fn decode_base_from_pack<'b, B: ExternalBaseProvider>(
    de: &mut flate2::Decompress,
    libde: Option<&mut crate::pack_inflate_libdeflate::LibdeflateDecompressor>,
    env: &DecodeEnv<'_>,
    offset: u64,
    cache: &mut PackCache,
    external: &mut B,
    hot_stats: &mut PackExecHotStats,
    report: &mut PackExecReport,
    inflate_buf: &mut Vec<u8>,
    result_buf: &mut Vec<u8>,
    base_buf: &'b mut Vec<u8>,
    delta_stack: &mut Vec<DeltaFrame>,
) -> Result<BaseBytes<'b>, SkipReason> {
    if env.max_delta_depth == 0 {
        return Err(SkipReason::BaseMissing {
            base_offset: offset,
        });
    }

    delta_stack.clear();
    perf_stats::sat_add_u32(&mut report.stats.fallback_base_decodes, 1);

    let root = walk_delta_chain_to_root(env, offset, delta_stack, &mut report.stats)?;
    let (base_kind, base_spill) = match materialize_root_base(
        de,
        libde,
        env,
        root,
        cache,
        external,
        base_buf,
        hot_stats,
        &mut report.stats,
    ) {
        Ok(root) => root,
        Err(reason) => {
            record_fallback_chain(&mut report.stats, delta_stack.len());
            return Err(reason);
        }
    };

    unwind_and_build_base(
        de,
        env,
        delta_stack,
        base_kind,
        base_spill,
        cache,
        inflate_buf,
        result_buf,
        base_buf,
        hot_stats,
        &mut report.stats,
    )
}

/// Non-fatal delta decode failure used as an internal error type within
/// the delta resolution pipeline.
///
/// This enum exists to distinguish between two failure modes that arise
/// during delta processing so that they map cleanly onto the external
/// skip taxonomy:
///
/// - `Decode` — the zlib inflate or entry header parse failed *before*
///   delta application could begin. Maps to [`SkipReason::Decode`].
/// - `Delta` — inflate succeeded but the delta instruction stream itself
///   was malformed, or the output exceeded size limits. Maps to
///   [`SkipReason::Delta`].
///
/// Both variants are non-fatal: the affected offset is skipped and
/// execution continues with the next offset. This type is deliberately
/// separate from [`PackExecError`] (which signals fatal, plan-aborting
/// failures like pack parse or sink errors) to enforce the distinction
/// at the type level. Conversion to [`SkipReason`] happens in
/// [`skip_reason_from_delta_error`].
#[derive(Debug)]
enum DeltaDecodeError {
    /// Inflation or header parsing failed before delta application.
    Decode(PackDecodeError),
    /// Delta application itself failed (e.g., output overrun, bad opcodes).
    Delta(DeltaError),
}

#[cfg(test)]
mod tests {
    use super::super::delta_test_helpers::{
        encode_entry_header, encode_entry_header_kind, encode_ofs_distance, encode_varint,
        zlib_compress,
    };
    use super::*;
    use crate::byte_arena::{ByteArena, ByteRef};
    use crate::multi_pack_test_helpers::{stable_oid, test_limits, MultiPackFixture};
    use crate::pack_plan_model::{CandidateAtOffset, DeltaKind, PackPlanStats};
    use crate::tree_candidate::{CandidateContext, ChangeKind};
    use std::collections::HashMap;

    #[derive(Default)]
    struct TestSink {
        emitted: Vec<OidBytes>,
    }

    impl PackObjectSink for TestSink {
        fn emit(
            &mut self,
            candidate: &PackCandidate,
            _path: &[u8],
            _bytes: &[u8],
        ) -> Result<(), PackExecError> {
            self.emitted.push(candidate.oid);
            Ok(())
        }
    }

    #[derive(Default)]
    struct CollectingSink {
        blobs: HashMap<OidBytes, Vec<u8>>,
    }

    impl PackObjectSink for CollectingSink {
        fn emit(
            &mut self,
            candidate: &PackCandidate,
            _path: &[u8],
            bytes: &[u8],
        ) -> Result<(), PackExecError> {
            self.blobs.insert(candidate.oid, bytes.to_vec());
            Ok(())
        }
    }

    #[derive(Default)]
    struct NoExternal;

    impl ExternalBaseProvider for NoExternal {
        fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
            panic!("unexpected external base lookup in test");
        }
    }

    fn ctx(path_ref: ByteRef) -> CandidateContext {
        CandidateContext {
            commit_id: 1,
            parent_idx: 0,
            change_kind: ChangeKind::Add,
            ctx_flags: 0,
            cand_flags: 0,
            path_ref,
        }
    }

    /// Builds a single-candidate `PackPlan` for a REF_DELTA with an external base.
    fn build_single_external_ref_plan(
        pack: &[u8],
        pack_id: u16,
        delta_offset: u64,
        candidate_oid: OidBytes,
        base_oid: OidBytes,
        candidate_ctx: CandidateContext,
    ) -> PackPlan {
        let candidate = PackCandidate {
            oid: candidate_oid,
            ctx: candidate_ctx,
            pack_id,
            offset: delta_offset,
        };
        let (data_start, delta_size) = delta_header_meta(pack, delta_offset);
        let need_offsets = vec![delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::External { oid: base_oid },
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        PackPlan {
            pack_id,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 1,
                forward_deps: 0,
                candidate_span: 0,
                ..PackPlanStats::empty()
            },
        }
    }

    #[test]
    fn cache_reject_bucket_index_maps_log2() {
        assert_eq!(cache_reject_bucket_index(0), 0);
        assert_eq!(cache_reject_bucket_index(1), 0);
        assert_eq!(cache_reject_bucket_index(2), 1);
        assert_eq!(cache_reject_bucket_index(3), 1);
        assert_eq!(cache_reject_bucket_index(4), 2);
        assert_eq!(cache_reject_bucket_index(7), 2);
        assert_eq!(cache_reject_bucket_index(8), 3);
    }

    fn build_insert_delta(result: &[u8], base_len: usize) -> Vec<u8> {
        let mut delta = Vec::new();
        delta.extend_from_slice(&encode_varint(base_len as u64));
        delta.extend_from_slice(&encode_varint(result.len() as u64));

        let mut remaining = result;
        while !remaining.is_empty() {
            let chunk = remaining.len().min(0x7f);
            delta.push(chunk as u8);
            delta.extend_from_slice(&remaining[..chunk]);
            remaining = &remaining[chunk..];
        }

        delta
    }

    fn exec_plan<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_indices<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        exec_indices: &[usize],
        candidate_ranges: &[CandidateRange],
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_indices(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            exec_indices,
            candidate_ranges,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_indices_hot_deps<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        exec_indices: &[usize],
        candidate_ranges: &[CandidateRange],
        hot_deps: &PackPlanHotDeps,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_indices_hot_deps(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            exec_indices,
            candidate_ranges,
            hot_deps,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_indices_from_header<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        pack_header: PackHeader,
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        exec_indices: &[usize],
        candidate_ranges: &[CandidateRange],
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_indices_from_header(
            plan,
            pack,
            pack_header,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            exec_indices,
            candidate_ranges,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_range<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        start_idx: usize,
        end_idx: usize,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_range(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            start_idx,
            end_idx,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_range_hot_deps<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        start_idx: usize,
        end_idx: usize,
        hot_deps: &PackPlanHotDeps,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_range_hot_deps(
            plan,
            pack,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            start_idx,
            end_idx,
            hot_deps,
        )
        .unwrap()
    }

    #[allow(clippy::too_many_arguments)]
    fn exec_plan_range_from_header<S: PackObjectSink, B: ExternalBaseProvider>(
        plan: &PackPlan,
        pack: &[u8],
        pack_header: PackHeader,
        arena: &ByteArena,
        limits: &PackDecodeLimits,
        cache: &mut PackCache,
        external: &mut B,
        sink: &mut S,
        scratch: &mut PackExecScratch,
        start_idx: usize,
        end_idx: usize,
    ) -> PackExecReport {
        let spill_dir = tempfile::tempdir().expect("spill dir");
        execute_pack_plan_with_scratch_range_from_header(
            plan,
            pack,
            pack_header,
            arena,
            limits,
            cache,
            external,
            sink,
            spill_dir.path(),
            scratch,
            start_idx,
            end_idx,
        )
        .unwrap()
    }

    fn build_pack(entries: &[(ObjectKind, &[u8])]) -> (Vec<u8>, Vec<u64>) {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        let mut offsets = Vec::with_capacity(entries.len());
        for (kind, data) in entries {
            offsets.push(bytes.len() as u64);
            bytes.extend_from_slice(&encode_entry_header_kind(*kind, data.len()));
            bytes.extend_from_slice(&zlib_compress(data));
        }

        bytes.extend_from_slice(&[0u8; 20]);
        (bytes, offsets)
    }

    fn candidate_span(offsets: &[CandidateAtOffset]) -> u64 {
        if offsets.is_empty() {
            0
        } else {
            let first = offsets.first().unwrap().offset;
            let last = offsets.last().unwrap().offset;
            last.saturating_sub(first)
        }
    }

    fn build_delta_dep_index(need_offsets: &[u64], delta_deps: &[DeltaDep]) -> Vec<u32> {
        let mut index = vec![NONE_U32; need_offsets.len()];
        if delta_deps.is_empty() {
            return index;
        }
        let mut dep_idx = 0usize;
        for (need_idx, &offset) in need_offsets.iter().enumerate() {
            while dep_idx < delta_deps.len() && delta_deps[dep_idx].offset < offset {
                dep_idx += 1;
            }
            if dep_idx < delta_deps.len() && delta_deps[dep_idx].offset == offset {
                index[need_idx] = dep_idx as u32;
                dep_idx += 1;
            }
        }
        index
    }

    fn delta_header_meta(pack: &[u8], offset: u64) -> (u64, u64) {
        let parsed = PackFile::parse(pack, 20).expect("pack parse");
        let header = parsed.entry_header_at(offset, 64).expect("entry header");
        (header.data_start as u64, header.size)
    }

    fn build_plan(
        need_offsets: Vec<u64>,
        candidates: Vec<PackCandidate>,
        candidate_offsets: Vec<CandidateAtOffset>,
        exec_order: Option<Vec<u32>>,
    ) -> PackPlan {
        let stats = PackPlanStats {
            candidate_count: candidates.len() as u32,
            need_count: need_offsets.len() as u32,
            external_bases: 0,
            forward_deps: exec_order.as_ref().map_or(0, |_| 1),
            candidate_span: candidate_span(&candidate_offsets),
            ..PackPlanStats::empty()
        };

        PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates,
            candidate_offsets,
            need_offsets,
            delta_deps: Vec::new(),
            delta_dep_index: vec![NONE_U32; stats.need_count as usize],
            exec_order,
            stats,
        }
    }

    fn assert_perf_u32(actual: u32, expected: u32) {
        if cfg!(all(feature = "perf-stats", debug_assertions)) {
            assert_eq!(actual, expected);
        } else {
            assert_eq!(actual, 0);
        }
    }

    #[test]
    fn candidate_range_from_bounds_preserves_values() {
        let range = CandidateRange::from_bounds(7, 11);
        assert_eq!(range.bounds(), Some((7, 11)));
        assert_eq!(range.candidate_count(), 4);
    }

    #[test]
    fn candidate_range_from_bounds_panics_when_start_after_end() {
        let result = std::panic::catch_unwind(|| CandidateRange::from_bounds(4, 3));
        assert!(result.is_err());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn candidate_range_from_bounds_panics_on_start_overflow() {
        let overflow = (u32::MAX as usize)
            .checked_add(1)
            .expect("64-bit usize should represent u32::MAX + 1");
        let result = std::panic::catch_unwind(|| CandidateRange::from_bounds(overflow, overflow));
        assert!(result.is_err());
    }

    #[cfg(target_pointer_width = "64")]
    #[test]
    fn candidate_range_from_bounds_panics_on_end_overflow() {
        let overflow = (u32::MAX as usize)
            .checked_add(1)
            .expect("64-bit usize should represent u32::MAX + 1");
        let result = std::panic::catch_unwind(|| CandidateRange::from_bounds(0, overflow));
        assert!(result.is_err());
    }

    #[test]
    fn merge_fast_path_emits_single_candidate() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x11; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(sink.emitted.len(), 1);
    }

    #[test]
    fn merge_fast_path_cache_hit_probes_once() {
        let object_bytes = b"cached";
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, object_bytes)]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x71; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(64 * 1024);
        assert!(cache.insert(offset, ObjectKind::Blob, object_bytes));
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        reset_test_cache_get_calls();
        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(object_bytes.as_slice())
        );
        assert_eq!(test_cache_get_calls(), 1);
    }

    #[test]
    fn shard_fast_path_cache_hit_probes_once() {
        let object_bytes = b"cached";
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, object_bytes)]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x72; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [0usize];

        let mut cache = PackCache::new(64 * 1024);
        assert!(cache.insert(offset, ObjectKind::Blob, object_bytes));
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();
        let mut scratch = PackExecScratch::default();

        reset_test_cache_get_calls();
        let report = exec_plan_indices(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
            &mut scratch,
            &exec_indices,
            &candidate_ranges,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(object_bytes.as_slice())
        );
        assert_eq!(test_cache_get_calls(), 1);
    }

    #[test]
    fn large_non_delta_blob_spills_and_scans() {
        let data = vec![b'a'; 64];
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, data.as_slice())]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x12; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();
        let limits = PackDecodeLimits::new(64, 16, 1024);

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_perf_u32(report.stats.large_blob_spilled_count, 1);
        crate::test_utils::assert_perf_u64(report.stats.large_blob_bytes, data.len() as u64);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(data.as_slice())
        );
    }

    #[test]
    fn large_delta_blob_spills_and_scans() {
        let base_bytes = b"base";
        let result_bytes = vec![b'Z'; 64];
        let delta_payload = build_insert_delta(&result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x13; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();
        let limits = PackDecodeLimits::new(64, 16, 1024);

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_perf_u32(report.stats.large_blob_spilled_count, 1);
        crate::test_utils::assert_perf_u64(
            report.stats.large_blob_bytes,
            result_bytes.len() as u64,
        );
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn merge_fast_path_emits_multiple_candidates_at_same_offset() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"hello")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset,
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset,
            },
        ];

        let plan = build_plan(
            vec![offset],
            candidates,
            vec![
                CandidateAtOffset {
                    offset,
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset,
                    cand_idx: 1,
                },
            ],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 2);
        assert_eq!(sink.emitted.len(), 2);
    }

    #[test]
    fn merge_fast_path_skips_non_blob_candidates() {
        let (pack, offsets) = build_pack(&[(ObjectKind::Tree, b"tree")]);
        let offset = offsets[0];

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x33; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 0);
        assert_eq!(report.skips.len(), 1);
        assert!(matches!(report.skips[0].reason, SkipReason::NotBlob));
        assert!(!report.skips[0].reason.is_error());
    }

    #[test]
    fn skip_reason_classifies_error_variants() {
        assert!(SkipReason::PackParse(PackParseError::BadSignature).is_error());
        assert!(SkipReason::ExternalBaseError {
            detail: "oops".to_string(),
        }
        .is_error());
        assert!(!SkipReason::NotBlob.is_error());
    }

    #[test]
    fn out_of_order_exec_uses_candidate_ranges() {
        let (pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            Some(vec![1, 0]),
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 2);
        assert_eq!(
            sink.emitted,
            vec![OidBytes::sha1([0x22; 20]), OidBytes::sha1([0x11; 20])]
        );
    }

    #[test]
    fn shard_exec_matches_sequential_order() {
        let (pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            None,
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report_seq = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );
        let emitted_seq = sink.emitted.clone();

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [0usize, 1usize];

        let mut shard_reports = Vec::new();
        let mut shard_emitted = Vec::new();
        for shard in exec_indices.chunks(1) {
            let mut cache = PackCache::new(0);
            let mut external = NoExternal;
            let mut sink = TestSink::default();
            let mut scratch = PackExecScratch::default();
            let report = exec_plan_indices(
                &plan,
                &pack,
                &arena,
                &PackDecodeLimits::new(64, 1024, 1024),
                &mut cache,
                &mut external,
                &mut sink,
                &mut scratch,
                shard,
                &candidate_ranges,
            );
            shard_reports.push(report);
            shard_emitted.extend(sink.emitted);
        }

        let merged = merge_pack_exec_reports(shard_reports);
        assert_eq!(
            merged.stats.emitted_candidates,
            report_seq.stats.emitted_candidates
        );
        assert_eq!(shard_emitted, emitted_seq);
    }

    #[test]
    fn shard_hot_deps_paths_match_existing_shard_paths() {
        let (pack, offsets) = build_pack(&[
            (ObjectKind::Blob, b"first"),
            (ObjectKind::Blob, b"second"),
            (ObjectKind::Blob, b"third"),
        ]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x31; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x32; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x33; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[2],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1], offsets[2]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
                CandidateAtOffset {
                    offset: offsets[2],
                    cand_idx: 2,
                },
            ],
            None,
        );

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let hot_deps = PackPlanHotDeps::from_plan(&plan);
        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let exec_indices = [1usize, 2usize];

        let mut cache_baseline = PackCache::new(0);
        let mut external_baseline = NoExternal;
        let mut sink_baseline = TestSink::default();
        let mut scratch_baseline = PackExecScratch::default();
        let report_baseline = exec_plan_indices(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache_baseline,
            &mut external_baseline,
            &mut sink_baseline,
            &mut scratch_baseline,
            &exec_indices,
            &candidate_ranges,
        );

        let mut cache_hot_idx = PackCache::new(0);
        let mut external_hot_idx = NoExternal;
        let mut sink_hot_idx = TestSink::default();
        let mut scratch_hot_idx = PackExecScratch::default();
        let report_hot_idx = exec_plan_indices_hot_deps(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache_hot_idx,
            &mut external_hot_idx,
            &mut sink_hot_idx,
            &mut scratch_hot_idx,
            &exec_indices,
            &candidate_ranges,
            &hot_deps,
        );

        let mut cache_hot_range = PackCache::new(0);
        let mut external_hot_range = NoExternal;
        let mut sink_hot_range = TestSink::default();
        let mut scratch_hot_range = PackExecScratch::default();
        let report_hot_range = exec_plan_range_hot_deps(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache_hot_range,
            &mut external_hot_range,
            &mut sink_hot_range,
            &mut scratch_hot_range,
            1,
            3,
            &hot_deps,
        );

        assert_eq!(
            report_hot_idx.stats.emitted_candidates,
            report_baseline.stats.emitted_candidates
        );
        assert_eq!(report_hot_idx.skips.len(), report_baseline.skips.len());
        assert_eq!(sink_hot_idx.emitted, sink_baseline.emitted);

        assert_eq!(
            report_hot_range.stats.emitted_candidates,
            report_baseline.stats.emitted_candidates
        );
        assert_eq!(report_hot_range.skips.len(), report_baseline.skips.len());
        assert_eq!(sink_hot_range.emitted, sink_baseline.emitted);
    }

    #[test]
    fn shard_range_exec_matches_index_exec_for_natural_order() {
        let (pack, offsets) = build_pack(&[
            (ObjectKind::Blob, b"first"),
            (ObjectKind::Blob, b"second"),
            (ObjectKind::Blob, b"third"),
        ]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x11; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x22; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x33; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[2],
            },
        ];

        let plan = build_plan(
            vec![offsets[0], offsets[1], offsets[2]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
                CandidateAtOffset {
                    offset: offsets[2],
                    cand_idx: 2,
                },
            ],
            None,
        );

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [1usize, 2usize];

        let mut cache_idx = PackCache::new(0);
        let mut external_idx = NoExternal;
        let mut sink_idx = TestSink::default();
        let mut scratch_idx = PackExecScratch::default();
        let report_idx = exec_plan_indices(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache_idx,
            &mut external_idx,
            &mut sink_idx,
            &mut scratch_idx,
            &exec_indices,
            &candidate_ranges,
        );

        let mut cache_range = PackCache::new(0);
        let mut external_range = NoExternal;
        let mut sink_range = TestSink::default();
        let mut scratch_range = PackExecScratch::default();
        let report_range = exec_plan_range(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache_range,
            &mut external_range,
            &mut sink_range,
            &mut scratch_range,
            1,
            3,
        );

        assert_eq!(
            report_range.stats.emitted_candidates,
            report_idx.stats.emitted_candidates
        );
        assert_eq!(report_range.skips.len(), report_idx.skips.len());
        assert_eq!(sink_range.emitted, sink_idx.emitted);
    }

    #[test]
    fn shard_indices_from_header_reuses_preparsed_header() {
        let (mut pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x41; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x42; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];
        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            None,
        );

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);

        let pack_header = parse_pack_header_for_plan(&plan, &pack).expect("pack header");
        pack[0] = b'X'; // force legacy entry points to fail if they re-parse

        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let mut emitted = Vec::new();
        for exec_indices in [&[0usize][..], &[1usize][..]] {
            let mut cache = PackCache::new(0);
            let mut external = NoExternal;
            let mut sink = TestSink::default();
            let mut scratch = PackExecScratch::default();
            let report = exec_plan_indices_from_header(
                &plan,
                &pack,
                pack_header,
                &arena,
                &limits,
                &mut cache,
                &mut external,
                &mut sink,
                &mut scratch,
                exec_indices,
                &candidate_ranges,
            );
            assert_perf_u32(report.stats.emitted_candidates, 1);
            emitted.extend(sink.emitted);
        }
        assert_eq!(
            emitted,
            vec![OidBytes::sha1([0x41; 20]), OidBytes::sha1([0x42; 20])]
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();
        let mut scratch = PackExecScratch::default();
        let spill_dir = tempfile::tempdir().expect("spill dir");
        let err = execute_pack_plan_with_scratch_indices(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
            spill_dir.path(),
            &mut scratch,
            &[0usize],
            &candidate_ranges,
        )
        .expect_err("legacy shard entry point should re-parse pack header");
        assert!(matches!(
            err,
            PackExecError::PackParse(PackParseError::BadSignature)
        ));
    }

    #[test]
    fn shard_range_from_header_reuses_preparsed_header() {
        let (mut pack, offsets) =
            build_pack(&[(ObjectKind::Blob, b"first"), (ObjectKind::Blob, b"second")]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidates = vec![
            PackCandidate {
                oid: OidBytes::sha1([0x51; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[0],
            },
            PackCandidate {
                oid: OidBytes::sha1([0x52; 20]),
                ctx: ctx(path_ref),
                pack_id: 0,
                offset: offsets[1],
            },
        ];
        let plan = build_plan(
            vec![offsets[0], offsets[1]],
            candidates,
            vec![
                CandidateAtOffset {
                    offset: offsets[0],
                    cand_idx: 0,
                },
                CandidateAtOffset {
                    offset: offsets[1],
                    cand_idx: 1,
                },
            ],
            None,
        );

        let pack_header = parse_pack_header_for_plan(&plan, &pack).expect("pack header");
        pack[0] = b'X'; // force legacy entry points to fail if they re-parse

        let limits = PackDecodeLimits::new(64, 1024, 1024);
        let mut emitted = Vec::new();
        for (start_idx, end_idx) in [(0usize, 1usize), (1usize, 2usize)] {
            let mut cache = PackCache::new(0);
            let mut external = NoExternal;
            let mut sink = TestSink::default();
            let mut scratch = PackExecScratch::default();
            let report = exec_plan_range_from_header(
                &plan,
                &pack,
                pack_header,
                &arena,
                &limits,
                &mut cache,
                &mut external,
                &mut sink,
                &mut scratch,
                start_idx,
                end_idx,
            );
            assert_perf_u32(report.stats.emitted_candidates, 1);
            emitted.extend(sink.emitted);
        }
        assert_eq!(
            emitted,
            vec![OidBytes::sha1([0x51; 20]), OidBytes::sha1([0x52; 20])]
        );

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();
        let mut scratch = PackExecScratch::default();
        let spill_dir = tempfile::tempdir().expect("spill dir");
        let err = execute_pack_plan_with_scratch_range(
            &plan,
            &pack,
            &arena,
            &limits,
            &mut cache,
            &mut external,
            &mut sink,
            spill_dir.path(),
            &mut scratch,
            0,
            1,
        )
        .expect_err("legacy shard entry point should re-parse pack header");
        assert!(matches!(
            err,
            PackExecError::PackParse(PackParseError::BadSignature)
        ));
    }

    #[test]
    fn shard_exec_decodes_delta_without_base_cached() {
        let base_bytes = b"";
        let result_bytes = b"TOK_ABCDEFGH";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x66; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        let mut candidate_ranges = Vec::new();
        build_candidate_ranges(&plan, &mut candidate_ranges);
        let exec_indices = [1usize];

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = TestSink::default();
        let mut scratch = PackExecScratch::default();
        let report = exec_plan_indices(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
            &mut scratch,
            &exec_indices,
            &candidate_ranges,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(sink.emitted, vec![OidBytes::sha1([0x66; 20])]);
    }

    #[test]
    fn delta_inflate_error_skips_without_emitting() {
        let base_bytes = b"BASE";

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, 4);
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&[0x78]); // truncated zlib stream
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x44; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 0);
        assert!(report.skips.iter().any(|skip| {
            matches!(skip.reason, SkipReason::Decode(PackDecodeError::Inflate(_)))
        }));
        assert!(cache.get(delta_offset).is_none());
    }

    #[test]
    fn ofs_delta_chain_decodes_within_limit() {
        let base_bytes = b"";
        let result_bytes = b"TOK_ABCDEFGH";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x55; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn ofs_delta_fallback_decodes_without_cache() {
        let base_bytes = b"base";
        let result_bytes = b"TOK_FALLBACK1";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x58; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 0,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        let mut cache = PackCache::new(0);
        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn ref_delta_external_base_decodes_within_limit() {
        let base_bytes = b"";
        let result_bytes = b"TOK_QWERTY12";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let base_oid = OidBytes::sha1([0x33; 20]);

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(7, delta_payload.len());
        delta_entry.extend_from_slice(base_oid.as_slice());
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x66; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::External { oid: base_oid },
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 1,
                forward_deps: 0,
                candidate_span: 0,
                ..PackPlanStats::empty()
            },
        };

        struct ExternalBaseProviderImpl {
            base_oid: OidBytes,
            base_bytes: Vec<u8>,
        }

        impl ExternalBaseProvider for ExternalBaseProviderImpl {
            fn load_base(&mut self, oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
                if *oid == self.base_oid {
                    Ok(Some(ExternalBase {
                        kind: ObjectKind::Blob,
                        bytes: self.base_bytes.clone(),
                    }))
                } else {
                    Ok(None)
                }
            }
        }

        let mut cache = PackCache::new(64 * 1024);
        let mut external = ExternalBaseProviderImpl {
            base_oid,
            base_bytes: base_bytes.to_vec(),
        };
        let mut sink = CollectingSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice())
        );
    }

    #[test]
    fn ref_delta_external_base_decodes_via_sim_pack_io_fixture() {
        let mut builder = MultiPackFixture::builder();
        let pack_c = builder.add_pack(b"pack-c");
        let pack_b = builder.add_pack(b"pack-b");
        let pack_a = builder.add_pack(b"pack-a");

        let base = builder.add_blob(pack_c, b"base-c");
        let mid = builder.add_ref_delta(pack_b, base, b"base-b");
        let top = builder.add_ref_delta(pack_a, mid, b"base-a");

        let fixture = builder.build().unwrap();
        let mut external = fixture.sim_pack_io(test_limits()).unwrap();

        let pack_idx = fixture.pack_index(top);
        let pack = fixture.pack_bytes(pack_idx);
        let delta_offset = fixture.offset(top);
        let base_oid = fixture.oid(mid);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"fixture.txt").unwrap();
        let candidate = PackCandidate {
            oid: fixture.oid(top),
            ctx: ctx(path_ref),
            pack_id: pack_idx as u16,
            offset: delta_offset,
        };

        let (data_start, delta_size) = delta_header_meta(pack, delta_offset);
        let need_offsets = vec![delta_offset];
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ref,
            base: BaseLoc::External { oid: base_oid },
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: pack_idx as u16,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: None,
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 1,
                external_bases: 1,
                forward_deps: 0,
                candidate_span: 0,
                ..PackPlanStats::empty()
            },
        };

        let mut cache = PackCache::new(64 * 1024);
        let mut sink = CollectingSink::default();
        let report = exec_plan(
            &plan,
            pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs
                .get(&fixture.oid(top))
                .map(|bytes| bytes.as_slice()),
            Some(fixture.expected(top).unwrap().1)
        );
    }

    #[test]
    fn missing_external_base_from_sim_pack_io_fixture_is_skipped() {
        let mut builder = MultiPackFixture::builder();
        let pack = builder.add_pack(b"pack-missing");
        let missing_base_oid = stable_oid(b"missing-base");
        let target =
            builder.add_missing_ref_delta(pack, ObjectKind::Blob, missing_base_oid, 4, b"unused");

        let fixture = builder.build().unwrap();
        let mut external = fixture.sim_pack_io(test_limits()).unwrap();

        let pack_idx = fixture.pack_index(target);
        let pack_bytes = fixture.pack_bytes(pack_idx);
        let delta_offset = fixture.offset(target);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"missing.txt").unwrap();
        let plan = build_single_external_ref_plan(
            pack_bytes,
            pack_idx as u16,
            delta_offset,
            fixture.oid(target),
            missing_base_oid,
            ctx(path_ref),
        );

        let mut cache = PackCache::new(64 * 1024);
        let mut sink = TestSink::default();
        let report = exec_plan(
            &plan,
            pack_bytes,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 0);
        assert!(sink.emitted.is_empty());
        assert!(report.skips.iter().any(|skip| {
            matches!(
                skip.reason,
                SkipReason::ExternalBaseMissing { oid } if oid == missing_base_oid
            )
        }));
    }

    #[test]
    fn truncated_non_delta_stream_is_skipped() {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(ObjectKind::Blob, 4));
        pack.extend_from_slice(&[0x78]); // truncated zlib stream
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x77; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 0);
        assert!(matches!(
            report.skips[0].reason,
            SkipReason::Decode(PackDecodeError::Inflate(_))
        ));
    }

    #[test]
    fn corrupt_pack_header_is_skipped() {
        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&1u32.to_be_bytes());

        let offset = pack.len() as u64;
        pack.push(0x80); // header continuation without following bytes
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x88; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset,
        };

        let plan = build_plan(
            vec![offset],
            vec![candidate],
            vec![CandidateAtOffset {
                offset,
                cand_idx: 0,
            }],
            None,
        );

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let mut sink = TestSink::default();

        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 0);
        assert!(matches!(
            report.skips[0].reason,
            SkipReason::Decode(PackDecodeError::PackParse(_))
        ));
    }

    #[cfg(debug_assertions)]
    #[test]
    fn alloc_guard_no_alloc_after_warmup() {
        use crate::alloc_guard;
        use crate::{
            demo_tuning, AnchorPolicy, Engine, Gate, RuleSpec, TransformConfig, TransformId,
            TransformMode, ValidatorKind,
        };
        use crate::{EngineAdapter, EngineAdapterConfig};
        use regex::bytes::Regex;

        struct Reset;
        impl Drop for Reset {
            fn drop(&mut self) {
                alloc_guard::set_enabled(false);
            }
        }

        if std::env::var("SCANNER_RS_ALLOC_GUARD").ok().as_deref() != Some("1") {
            eprintln!(
                "alloc guard test skipped; set SCANNER_RS_ALLOC_GUARD=1 and \
run with --test-threads=1 to enable"
            );
            return;
        }

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

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            transforms,
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let (pack, offsets) = build_pack(&[(ObjectKind::Blob, b"TOK_ABCDEFGH")]);
        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0x55; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: offsets[0],
        };

        let plan = build_plan(
            vec![offsets[0]],
            vec![candidate],
            vec![CandidateAtOffset {
                offset: offsets[0],
                cand_idx: 0,
            }],
            None,
        );

        let mut adapter = EngineAdapter::new(&engine, EngineAdapterConfig::default());
        adapter.reserve_results(1);
        adapter.reserve_findings(8);
        adapter.reserve_findings_buf(8);

        alloc_guard::set_enabled(false);
        let mut warm_cache = PackCache::new(64 * 1024);
        let mut warm_external = NoExternal;
        let _warm = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut warm_cache,
            &mut warm_external,
            &mut adapter,
        );
        adapter.clear_results();

        alloc_guard::set_enabled(true);
        let _reset = Reset;

        let mut cache = PackCache::new(64 * 1024);
        let mut external = NoExternal;
        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut adapter,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        let scanned = adapter.take_results();
        assert_eq!(scanned.blobs.len(), 1);
        assert!(!scanned.finding_arena.is_empty());
    }

    /// Regression: delta base lookups inside `decode_offset` must go through
    /// the `cache_get()` wrapper so test instrumentation counts them.
    /// Three call-sites (planned-dep fast-path, OfsDelta fallback, RefDelta
    /// planned-dep) were using `cache.get()` directly, bypassing the counter.
    #[test]
    fn delta_base_cache_lookup_counted_by_cache_get_wrapper() {
        let base_bytes = b"HELLO";
        let result_bytes = b"GOODBYE_WORLD";
        let delta_payload = build_insert_delta(result_bytes, base_bytes.len());

        let mut pack = Vec::new();
        pack.extend_from_slice(b"PACK");
        pack.extend_from_slice(&2u32.to_be_bytes());
        pack.extend_from_slice(&2u32.to_be_bytes());

        let base_offset = pack.len() as u64;
        pack.extend_from_slice(&encode_entry_header_kind(
            ObjectKind::Blob,
            base_bytes.len(),
        ));
        pack.extend_from_slice(&zlib_compress(base_bytes));

        let delta_offset = pack.len() as u64;
        let mut delta_entry = encode_entry_header(6, delta_payload.len());
        delta_entry.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
        delta_entry.extend_from_slice(&zlib_compress(&delta_payload));
        pack.extend_from_slice(&delta_entry);
        pack.extend_from_slice(&[0u8; 20]);

        let mut arena = ByteArena::with_capacity(64);
        let path_ref = arena.intern(b"file.txt").unwrap();
        let candidate = PackCandidate {
            oid: OidBytes::sha1([0xAA; 20]),
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: delta_offset,
        };

        let need_offsets = vec![base_offset, delta_offset];
        let (data_start, delta_size) = delta_header_meta(&pack, delta_offset);
        let delta_deps = vec![DeltaDep {
            offset: delta_offset,
            kind: DeltaKind::Ofs,
            base: BaseLoc::Offset(base_offset),
            data_start,
            delta_size,
        }];
        let delta_dep_index = build_delta_dep_index(&need_offsets, &delta_deps);
        let plan = PackPlan {
            pack_id: 0,
            oid_len: 20,
            max_delta_depth: 16,
            candidates: vec![candidate],
            candidate_offsets: vec![CandidateAtOffset {
                offset: delta_offset,
                cand_idx: 0,
            }],
            need_offsets,
            delta_deps,
            delta_dep_index,
            exec_order: Some(vec![0, 1]),
            stats: PackPlanStats {
                candidate_count: 1,
                need_count: 2,
                external_bases: 0,
                forward_deps: 1,
                candidate_span: delta_offset - base_offset,
                ..PackPlanStats::empty()
            },
        };

        // Pre-cache the base so the delta fast-path hits cache.get (line 1550).
        let mut cache = PackCache::new(64 * 1024);
        assert!(cache.insert(base_offset, ObjectKind::Blob, base_bytes));

        let mut external = NoExternal;
        let mut sink = CollectingSink::default();

        reset_test_cache_get_calls();
        let report = exec_plan(
            &plan,
            &pack,
            &arena,
            &PackDecodeLimits::new(64, 1024, 1024),
            &mut cache,
            &mut external,
            &mut sink,
        );

        assert_perf_u32(report.stats.emitted_candidates, 1);
        assert_eq!(
            sink.blobs.get(&candidate.oid).map(|b| b.as_slice()),
            Some(result_bytes.as_slice()),
        );

        // Expected cache_get wrapper calls when all lookups go through it:
        //   1. emit_one_offset(base): cache_get(cache, base_offset) → hit
        //   2. emit_one_offset(delta): cache_get(cache, delta_offset) → miss
        //   3. decode_offset: cache_get(cache, dep.base_offset) → hit (base lookup)
        //   4. emit_one_offset(delta) re-probe: cache_get(cache, delta_offset)
        //
        // If call #3 uses cache.get() directly, only 3 calls are counted.
        let calls = test_cache_get_calls();
        assert_eq!(
            calls, 4,
            "delta base lookup must go through cache_get wrapper; expected 4 calls, got {calls}",
        );
    }
}
