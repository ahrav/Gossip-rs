//! Streaming byte-weighted split-point estimation.
//!
//! # Purpose
//!
//! During filesystem pagination walks the connector needs a split key that
//! divides the key space into two roughly equal halves *by total byte weight*,
//! not by item count. The batch predecessor [`choose_split_index`] requires
//! all items in memory; this module provides [`StreamingSplitEstimator`], which
//! achieves the same goal in bounded memory over an arbitrarily long,
//! globally-sorted key stream.
//!
//! [`choose_split_index`]: crate::common::choose_split_index
//!
//! # Invariants
//!
//! - **Sample cap**: the number of retained samples never exceeds
//!   `sample_cap` (at least [`MIN_SAMPLE_CAP`]).
//! - **Monotonicity**: retained samples are strictly increasing in rank and
//!   non-decreasing in cumulative byte position at all times, including after
//!   compaction.
//! - **Key fidelity**: the estimator only returns *actually observed* keys; it
//!   never synthesizes or interpolates key bytes.
//! - **First-key guard**: the very first key observed is tracked separately so
//!   the "avoid degenerate first-item split" logic survives downsampling.
//!
//! # Sample-cap contract
//!
//! - [`StreamingSplitEstimator::new`] takes a retained-sample ceiling directly;
//!   it is not a compression ratio or an "accuracy level" enum.
//! - Values below [`MIN_SAMPLE_CAP`] are clamped upward so callers get a stable
//!   minimum-quality configuration instead of an unusably sparse sketch.
//! - [`StreamingSplitEstimator::DEFAULT_SAMPLE_CAP`] is the connector-facing
//!   default used by the filesystem connector.
//!
//! # Algorithm
//!
//! 1. **Dual-axis sampling** — each incoming `(key, file_size)` pair is tested
//!    against both a *rank stride* and a *byte stride*. The key is recorded if
//!    either cadence fires. A byte-triggered sample records the exact byte mark
//!    it straddles, giving better byte-space fidelity than rank alone.
//! 2. **Stride-doubling compaction** — when the sample buffer exceeds its cap,
//!    it is compacted to half capacity via nearest-neighbor selection on the
//!    cumulative-byte axis (falling back to rank when all byte positions are
//!    identical). Both strides are then doubled, so future observations are
//!    sampled at the coarser cadence.
//!    - **Plateau redistribution** — after nearest-neighbor selection,
//!      consecutive picks that landed on the same byte-axis value (a
//!      "plateau") are spread evenly across the plateau's rank extent.
//!      Without this step, byte-axis plateaus (e.g. a large run of
//!      zero-size files after a single heavy file) would cluster retained
//!      samples at the plateau's leading edge, degrading rank-axis
//!      diversity and causing the rank-fallback split to drift far from
//!      the true ordinal midpoint.
//! 3. **Estimation** — `estimate_split_key` binary-searches the retained
//!    samples for the key whose recorded position is closest to
//!    `total_bytes / 2`. If all items are zero-size it falls back to the
//!    rank midpoint.
//!
//! Because the buffer halves and the strides double together, the total number
//! of compaction events is logarithmic in stream length, and non-sampled
//! steady-state observations require no heap work.
//!
//! # Design choices
//!
//! - **Byte-weighted over count-balanced**: storage systems with skewed file
//!   sizes benefit from byte-balanced shards rather than item-balanced ones.
//! - **Sparse sample set over full sketch**: retaining concrete keys avoids
//!   the need to re-derive a split key from a quantile summary, at the cost
//!   of a tunable sample-cap parameter.
//! - **u128 arithmetic in interpolation**: avoids floating-point rounding
//!   issues at byte offsets above 2^53.
//! - **Single byte-mark per `observe` call**: each call to [`observe`] records
//!   at most one sample, even if the file's byte range spans multiple stride
//!   marks.  This is a deliberate trade-off for O(1) per-observation cost.
//!   For Zipf-like workloads dominated by a few very large files the byte
//!   axis may have gaps in that region, causing the estimator to rely more
//!   on the rank-axis fallback.  In practice the rank sample for the same
//!   file still captures it, and the dedicated Zipf-like accuracy regression
//!   test confirms <1% byte-weighted error on a 20 000-key stream.
//!
//! # Validation support
//!
//! Companion tests in `split_estimator_tests.rs` pin the estimator's weighted
//! accuracy and >2^53 byte-position precision. Cross-crate performance harnesses use
//! [`crate::benchmark_streaming_split_estimator_observe_fixed_size`] to drive
//! the same `observe` loop on a fixed-size stream, which keeps benchmark and
//! allocation-regression numbers focused on the estimator rather than on
//! filesystem traversal or random workload generation.

use std::fmt;
use std::mem;

/// Absolute floor on retained sample count.
///
/// Smaller caps remain mechanically correct, but they downsample so
/// aggressively that split accuracy becomes too noisy for pagination use.
const MIN_SAMPLE_CAP: usize = 128;

/// The coordinate axis used when spacing retained samples during compaction
/// and when searching for the nearest sample to a target position.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum SampleAxis {
    /// Space samples by ordinal rank (0-based item index in stream order).
    /// Used as a fallback when all cumulative byte positions are identical
    /// (e.g. all-zero-size streams).
    Rank,
    /// Space samples by cumulative byte position. Preferred whenever the
    /// byte range is non-degenerate, because it directly optimises for
    /// byte-balanced splits.
    Bytes,
}

/// A retained checkpoint from the key stream.
///
/// Each sample captures an observed key together with its position on both
/// the rank axis (ordinal index) and the byte axis (cumulative byte weight
/// at the point the key was sampled). Carrying both axes lets the estimator
/// use byte-space interpolation for accuracy while falling back to rank
/// when byte positions collapse.
#[derive(Clone)]
struct Sample {
    /// 0-based ordinal index of this key in stream order.
    rank: u64,
    /// Cumulative byte position at which this sample was recorded.
    ///
    /// When sampled by the byte-stride trigger this is the exact byte-stride
    /// mark that the file straddles; otherwise it is the cumulative byte total
    /// at the start of the file (a rank-triggered fallback position).
    cumulative_bytes: u64,
    key: Box<[u8]>,
}

#[derive(Clone, Copy)]
struct RedactedKeyLen(usize);

impl fmt::Debug for RedactedKeyLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{} bytes]", self.0)
    }
}

#[derive(Clone, Copy)]
struct RedactedOptionalKeyLen(Option<usize>);

impl fmt::Debug for RedactedOptionalKeyLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(len) => write!(f, "Some([{} bytes])", len),
            None => write!(f, "None"),
        }
    }
}

impl fmt::Debug for Sample {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sample")
            .field("rank", &self.rank)
            .field("cumulative_bytes", &self.cumulative_bytes)
            .field("key", &RedactedKeyLen(self.key.len()))
            .finish_non_exhaustive()
    }
}

impl Sample {
    fn new(rank: u64, cumulative_bytes: u64, key: &[u8]) -> Self {
        Self {
            rank,
            cumulative_bytes,
            key: Box::<[u8]>::from(key),
        }
    }

    /// Return this sample's coordinate on the given `axis`, enabling
    /// axis-generic compaction and search code.
    fn position(&self, axis: SampleAxis) -> u64 {
        match axis {
            SampleAxis::Rank => self.rank,
            SampleAxis::Bytes => self.cumulative_bytes,
        }
    }
}

/// Reduce `samples` to at most `cap` entries in-place.
///
/// Selection uses nearest-neighbor interpolation on the preferred axis
/// (cumulative bytes when the byte range is non-degenerate, rank otherwise).
/// This preserves the first and last samples and maximises spacing uniformity
/// on the axis that matters for split accuracy.
///
/// The old vector is consumed via [`mem::take`] so dropped samples are freed
/// before the compacted vector is written back, keeping peak memory at
/// roughly `old.len() + cap`.
fn compact_samples(samples: &mut Vec<Sample>, cap: usize) {
    if samples.len() <= cap {
        return;
    }

    let old = mem::take(samples);
    let keep = selected_sample_indices(&old, cap);
    let mut keep_iter = keep.into_iter();
    let mut next_keep = keep_iter.next();
    let mut compacted = Vec::with_capacity(cap);

    for (idx, sample) in old.into_iter().enumerate() {
        if Some(idx) == next_keep {
            compacted.push(sample);
            next_keep = keep_iter.next();
            if next_keep.is_none() && compacted.len() == cap {
                break;
            }
        }
    }

    *samples = compacted;
}

/// Choose `cap` indices from `samples` that are approximately evenly spaced
/// on the preferred axis (bytes or rank).
///
/// Returns a strictly-increasing `Vec<usize>` of length `cap`. When all
/// samples share the same axis value (degenerate case), falls back to
/// uniform index spacing.
///
/// The algorithm has two phases:
///
/// 1. **Nearest-neighbor selection** — walks the sample array once with a
///    forward cursor, snapping each ideal interpolated position to the
///    nearest actual sample. Two constraints keep the output well-formed:
///    - **Forward progress**: each pick must exceed the previous pick.
///    - **Room for remaining**: each pick is capped so enough indices remain
///      for the picks still to come.
///
/// 2. **Plateau redistribution** — a post-pass
///    ([`redistribute_plateau_picks`]) detects runs of picks that share the
///    same axis value and spreads them across the full plateau extent by
///    rank. This prevents the forward-progress constraint from bunching
///    plateau picks at the leading edge, which would destroy rank diversity
///    and make the rank-fallback split inaccurate on streams with large
///    zero-byte tails.
fn selected_sample_indices(samples: &[Sample], cap: usize) -> Vec<usize> {
    debug_assert!(samples.len() > cap);

    let len = samples.len();

    // Single-slot edge case: keep the most-recent sample (last index).
    // This must come before the loop because the `i == 0` endpoint branch
    // would otherwise `continue` past the `i + 1 == cap` check, silently
    // returning `[0]` instead of `[len - 1]`.
    if cap == 1 {
        return vec![len - 1];
    }
    let axis = preferred_axis(samples);
    let first = samples.first().expect("non-empty samples").position(axis);
    let last = samples.last().expect("non-empty samples").position(axis);

    // Degenerate: all samples have the same axis value. Fall back to
    // uniform index spacing so we still retain `cap` distinct entries.
    if first == last {
        return (0..cap).map(|i| i * (len - 1) / (cap - 1)).collect();
    }

    let mut picks = Vec::with_capacity(cap);
    let mut cursor = 0usize;
    let mut last_pick: Option<usize> = None;

    for i in 0..cap {
        // Endpoints: always preserve first and last sample regardless of
        // axis-value ties or plateau layout.
        if i == 0 {
            picks.push(0);
            last_pick = Some(0);
            continue;
        }
        if i + 1 == cap {
            picks.push(len - 1);
            break;
        }

        let target = interpolated_position(first, last, i, cap);

        while cursor + 1 < len && samples[cursor + 1].position(axis) < target {
            cursor += 1;
        }

        let mut pick = if cursor + 1 < len {
            let next = cursor + 1;
            let d_curr = samples[cursor].position(axis).abs_diff(target);
            let d_next = samples[next].position(axis).abs_diff(target);
            if d_next < d_curr { next } else { cursor }
        } else {
            cursor
        };

        // Forward-progress: never re-pick an index we already chose.
        if let Some(prev) = last_pick
            && pick <= prev
        {
            pick = prev + 1;
        }

        // Room constraint: leave enough indices for the remaining picks.
        let remaining = cap - i - 1;
        let max_pick = len - remaining - 1;
        if pick > max_pick {
            pick = max_pick;
        }

        picks.push(pick);
        last_pick = Some(pick);
        cursor = pick;
    }

    redistribute_plateau_picks(samples, &mut picks, axis);

    assert!(
        picks.windows(2).all(|w| w[0] < w[1]),
        "selected indices must be strictly increasing after plateau redistribution"
    );

    picks
}

/// Spread plateau-clustered picks across the full plateau rank extent.
///
/// Scans `picks` for maximal runs where every picked sample shares one axis
/// value. For each such run of length >= 2 it:
///
/// 1. Finds the full plateau extent in `samples` (all contiguous indices
///    with the same axis value).
/// 2. Constrains the usable range so it does not collide with adjacent
///    non-plateau picks (or the array boundaries).
/// 3. Computes evenly-spaced rank targets across the usable range via
///    [`interpolated_position`].
/// 4. Snaps each target to the nearest sample by rank
///    ([`nearest_by_rank_in_range`]), enforcing the strictly-increasing
///    invariant at each step with both a floor (forward progress) and a
///    ceiling (room for remaining picks).
///
/// O(picks.len() * plateau_extent) worst case.
///
/// # Invariants preserved
///
/// - `picks` remains strictly increasing after redistribution.
/// - Endpoint picks (first = 0, last = len − 1) are never moved.
/// - No-op when `picks.len() < 3`.
fn redistribute_plateau_picks(samples: &[Sample], picks: &mut [usize], axis: SampleAxis) {
    if picks.len() < 3 {
        // With 0–2 picks there cannot be a non-endpoint plateau cluster.
        return;
    }

    let sample_len = samples.len();
    let mut run_start = 0;

    while run_start < picks.len() {
        let plateau_val = samples[picks[run_start]].position(axis);

        // Find the end of this run (exclusive).
        let mut run_end = run_start + 1;
        while run_end < picks.len() && samples[picks[run_end]].position(axis) == plateau_val {
            run_end += 1;
        }

        let run_len = run_end - run_start;
        if run_len >= 2 {
            // Full plateau extent in the sample array.
            let mut p_start = picks[run_start];
            while p_start > 0 && samples[p_start - 1].position(axis) == plateau_val {
                p_start -= 1;
            }
            let mut p_end = picks[run_end - 1];
            while p_end + 1 < sample_len && samples[p_end + 1].position(axis) == plateau_val {
                p_end += 1;
            }

            // Constrain to avoid overlapping with adjacent non-plateau picks.
            let lower = if run_start > 0 {
                picks[run_start - 1] + 1
            } else {
                0
            };
            let upper = if run_end < picks.len() {
                picks[run_end] - 1
            } else {
                sample_len - 1
            };

            let eff_start = p_start.max(lower);
            let eff_end = p_end.min(upper);

            // Only redistribute when the effective range has enough room.
            if eff_end >= eff_start && eff_end - eff_start + 1 >= run_len {
                let rank_first = samples[eff_start].rank;
                let rank_last = samples[eff_end].rank;

                // Ranks are strictly increasing, so rank_first < rank_last
                // whenever eff_start < eff_end (which the size guard above
                // guarantees for run_len >= 2).
                for j in 0..run_len {
                    let target_rank = interpolated_position(rank_first, rank_last, j, run_len);
                    let new_pick =
                        nearest_by_rank_in_range(samples, eff_start, eff_end, target_rank);

                    // Enforce strictly increasing relative to previous pick.
                    let floor = if j > 0 {
                        picks[run_start + j - 1] + 1
                    } else if run_start > 0 {
                        picks[run_start - 1] + 1
                    } else {
                        0
                    };
                    // Leave room for the remaining picks within the plateau.
                    let ceil = eff_end - (run_len - 1 - j);

                    picks[run_start + j] = new_pick.max(floor).min(ceil);
                }
            }
        }

        run_start = run_end;
    }
}

/// Find the sample in `samples[lo..=hi]` whose rank is closest to `target`.
///
/// Linear scan over the plateau extent. Ties break to the earlier index
/// (lower rank) to preserve forward-progress in the caller.
///
/// Returns an absolute index into `samples`, not relative to `lo`.
fn nearest_by_rank_in_range(samples: &[Sample], lo: usize, hi: usize, target: u64) -> usize {
    let mut best = lo;
    let mut best_dist = samples[lo].rank.abs_diff(target);
    for (offset, sample) in samples[lo + 1..=hi].iter().enumerate() {
        let dist = sample.rank.abs_diff(target);
        if dist < best_dist {
            best = lo + 1 + offset;
            best_dist = dist;
        }
    }
    best
}

/// Choose the compaction/search axis: bytes when the range is non-degenerate,
/// rank otherwise. Checked on the first and last samples only (the array is
/// sorted, so if the endpoints differ the range is non-degenerate).
fn preferred_axis(samples: &[Sample]) -> SampleAxis {
    let first = samples.first().expect("non-empty samples");
    let last = samples.last().expect("non-empty samples");
    if first.cumulative_bytes != last.cumulative_bytes {
        SampleAxis::Bytes
    } else {
        SampleAxis::Rank
    }
}

/// Linearly interpolate between `first` and `last` to find the ideal target
/// position for the `idx`-th pick out of `cap` total picks.
///
/// Uses u128 intermediate arithmetic to avoid overflow when `last - first`
/// exceeds 2^63 and to avoid f64 precision loss above 2^53.
///
/// # Panics
///
/// Debug-asserts `cap >= 2`.
fn interpolated_position(first: u64, last: u64, idx: usize, cap: usize) -> u64 {
    debug_assert!(cap >= 2);
    debug_assert!(last >= first, "interpolation requires last >= first");

    if idx == 0 {
        return first;
    }
    if idx + 1 == cap {
        return last;
    }

    let span = last.saturating_sub(first) as u128;
    let numerator = span.saturating_mul(idx as u128);
    let denominator = (cap - 1) as u128;
    (first as u128 + numerator / denominator) as u64
}

/// Round `value` up to the next multiple of `stride` (saturating at
/// `u64::MAX`). Used after compaction to realign the next sampling marks
/// onto the (now-doubled) stride grid.
///
/// A zero `stride` is clamped to 1, making this a no-op identity.
fn align_to_stride(value: u64, stride: u64) -> u64 {
    let stride = stride.max(1);
    if value == u64::MAX {
        return value;
    }
    let remainder = value % stride;
    if remainder == 0 {
        value
    } else {
        value.saturating_add(stride - remainder)
    }
}

/// Bounded-memory estimator for byte-weighted split keys over streaming walks.
///
/// # Usage
///
/// Feed observed `(key, file_size)` pairs via [`observe`](Self::observe) in
/// globally sorted key order. Call [`estimate_split_key`](Self::estimate_split_key)
/// at any time to retrieve the retained key whose recorded position is
/// closest to the byte-weighted midpoint.
///
/// # Complexity
///
/// - **`observe`**: O(1) amortised. Compaction fires at most
///   O(log(stream_length / sample_cap)) times, each costing O(sample_cap).
/// - **`estimate_split_key`**: O(log sample_cap) binary search.
/// - **Memory**: O(sample_cap) samples, each carrying a heap-allocated key.
#[derive(Clone)]
pub(crate) struct StreamingSplitEstimator {
    sample_cap: usize,
    /// Sparse checkpoints retained from the stream. Each sample carries both
    /// ordinal rank and the byte-space search position associated with the
    /// same observed key.
    samples: Vec<Sample>,
    /// Rank sampling stride in observed items.
    rank_stride: u64,
    /// Byte sampling stride in cumulative byte space.
    byte_stride: u64,
    /// Next rank at which a sample should be recorded.
    next_rank_sample: u64,
    /// Next cumulative-byte mark whose straddling file should be sampled.
    next_byte_mark: u64,
    /// Total observed byte weight (saturating on overflow).
    total_bytes: u64,
    /// Total observed item count.
    count: u64,
    /// The very first key observed in stream order. Tracked explicitly so the
    /// "avoid degenerate first-item split" guard remains correct even if
    /// downsampling evicts the original first sample.
    first_observed_key: Option<Box<[u8]>>,
}

impl fmt::Debug for StreamingSplitEstimator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StreamingSplitEstimator")
            .field("sample_cap", &self.sample_cap)
            .field("samples_len", &self.samples.len())
            .field("rank_stride", &self.rank_stride)
            .field("byte_stride", &self.byte_stride)
            .field("next_rank_sample", &self.next_rank_sample)
            .field("next_byte_mark", &self.next_byte_mark)
            .field("total_bytes", &self.total_bytes)
            .field("count", &self.count)
            .field(
                "first_observed_key",
                &RedactedOptionalKeyLen(self.first_observed_key.as_ref().map(|key| key.len())),
            )
            .finish_non_exhaustive()
    }
}

impl StreamingSplitEstimator {
    /// Default retained sample count.
    /// Sufficient for <1% byte-weighted error on the crate's 20 000-key
    /// descending-size regression workload.
    pub(crate) const DEFAULT_SAMPLE_CAP: usize = 1024;

    /// Create a new streaming estimator.
    ///
    /// `sample_cap` controls how many key checkpoints are retained. Higher
    /// values use more memory and generally reduce split drift.
    ///
    /// This value is a hard ceiling on retained checkpoints after each public
    /// operation returns; it does not change how many observations callers feed
    /// into the estimator.
    ///
    /// Values below [`MIN_SAMPLE_CAP`] are rounded up to keep downsampling
    /// accurate enough for pagination workloads.
    pub(crate) fn new(sample_cap: usize) -> Self {
        let sample_cap = sample_cap.max(MIN_SAMPLE_CAP);
        Self {
            sample_cap,
            samples: Vec::new(),
            rank_stride: 1,
            byte_stride: 1,
            next_rank_sample: 0,
            next_byte_mark: 0,
            total_bytes: 0,
            count: 0,
            first_observed_key: None,
        }
    }

    /// Record one `(key, file_size)` observation from the streaming walk.
    ///
    /// Keys **must** be supplied in globally sorted (ascending) order.
    /// `file_size` may be zero; zero-size items are still counted for rank
    /// purposes but contribute no byte weight and cannot trigger a byte-stride
    /// sample.
    ///
    /// Callers should feed every key they want the eventual split hint to
    /// represent; omitted observations simply do not participate in the sketch.
    ///
    /// **Note:** at most one sample is recorded per call, even if `file_size`
    /// spans multiple byte-stride marks. This is an intentional O(1)
    /// amortised-cost trade-off; see the module-level "Design choices" section.
    ///
    /// If the sample buffer exceeds its cap after insertion, a compaction
    /// cycle runs (halve samples, double strides) before returning.
    pub(crate) fn observe(&mut self, key: &[u8], file_size: u64) {
        if self.first_observed_key.is_none() {
            self.first_observed_key = Some(Box::<[u8]>::from(key));
        }

        let rank = self.count;
        let cumulative_bytes = self.total_bytes;
        let end_bytes = self.total_bytes.saturating_add(file_size);

        // Dual-axis trigger: record if the rank cadence fires OR if this
        // file's byte interval [cumulative_bytes, end_bytes) straddles the
        // next byte mark.
        let sample_rank = rank >= self.next_rank_sample;
        let sample_bytes = file_size > 0
            && cumulative_bytes <= self.next_byte_mark
            && self.next_byte_mark < end_bytes;

        if sample_rank || sample_bytes {
            // Prefer the byte-stride mark as the recorded position when the
            // byte trigger fired; this gives tighter byte-space fidelity.
            let byte_position = if sample_bytes {
                self.next_byte_mark
            } else {
                cumulative_bytes
            };
            self.samples.push(Sample::new(rank, byte_position, key));
        }

        self.count = self.count.saturating_add(1);
        self.total_bytes = end_bytes;

        if self.samples.len() > self.sample_cap {
            self.grow_strides_and_compact();
        }
        self.realign_sample_marks();
    }

    /// Estimate the split key whose recorded byte position is closest to the
    /// byte-weighted midpoint.
    ///
    /// Returns `None` until at least two keys have been observed (a split
    /// requires at least one item on each side).
    ///
    /// When all observed files are zero-size the byte axis is degenerate, so
    /// the estimator falls back to the rank midpoint (`count / 2`).
    ///
    /// A special guard prevents returning the very first observed key: when
    /// weight is front-loaded (e.g. one huge file followed by many small
    /// ones), the byte-weighted median can land on item 0, which would
    /// produce a zero-item left shard. In that case the estimator falls back
    /// to the rank-based midpoint instead.
    pub(crate) fn estimate_split_key(&self) -> Option<&[u8]> {
        if self.count < 2 {
            return None;
        }

        let max_rank = self.count - 1;
        let midpoint_rank = self.count / 2;
        let rank_target = midpoint_rank.clamp(1, max_rank);

        if self.total_bytes == 0 {
            return Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target);
        }

        let target_weight = self.total_bytes / 2;
        let candidate = Self::nearest_sample(&self.samples, SampleAxis::Bytes, target_weight)
            .or_else(|| Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target))?;

        // Keep split semantics aligned with existing connectors: avoid
        // degenerate "first item" splits when weight is front-loaded.
        if self
            .first_observed_key
            .as_ref()
            .is_some_and(|first| candidate == first.as_ref())
        {
            return Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target);
        }

        Some(candidate)
    }

    /// Compact the sample buffer and double both strides.
    ///
    /// Called when a new sample pushes the buffer past `sample_cap`. The
    /// target is half the cap so the next batch of observations has room
    /// before the next compaction fires.
    fn grow_strides_and_compact(&mut self) {
        let target = self.downsample_target();
        compact_samples(&mut self.samples, target);
        self.rank_stride = self.rank_stride.saturating_mul(2).max(1);
        self.byte_stride = self.byte_stride.saturating_mul(2).max(1);
    }

    /// Snap the next rank and byte sampling marks to the current stride grid.
    /// Called after every `observe` to keep the cadence aligned.
    fn realign_sample_marks(&mut self) {
        self.next_rank_sample = align_to_stride(self.count, self.rank_stride);
        self.next_byte_mark = align_to_stride(self.total_bytes, self.byte_stride);
    }

    /// Target sample count after compaction: half the cap (rounded up).
    fn downsample_target(&self) -> usize {
        self.sample_cap.div_ceil(2)
    }

    /// Binary-search `samples` on the given `axis` for the entry whose
    /// position is closest to `target`, returning its key bytes.
    ///
    /// When the target falls between two samples the one with the smaller
    /// absolute distance wins (ties go to the earlier sample).
    fn nearest_sample(samples: &[Sample], axis: SampleAxis, target: u64) -> Option<&[u8]> {
        if samples.is_empty() {
            return None;
        }

        let idx = samples.partition_point(|sample| sample.position(axis) < target);
        if idx == 0 {
            return samples.first().map(|sample| sample.key.as_ref());
        }
        if idx >= samples.len() {
            return samples.last().map(|sample| sample.key.as_ref());
        }

        let prev = &samples[idx - 1];
        let next = &samples[idx];
        if prev.position(axis).abs_diff(target) <= next.position(axis).abs_diff(target) {
            Some(prev.key.as_ref())
        } else {
            Some(next.key.as_ref())
        }
    }

    #[cfg(test)]
    fn sample_len(&self) -> usize {
        self.samples.len()
    }

    #[cfg(test)]
    fn sample_cap(&self) -> usize {
        self.sample_cap
    }

    #[cfg(test)]
    fn sample_debug_view(&self) -> Vec<(u64, u64, Vec<u8>)> {
        self.samples
            .iter()
            .map(|sample| {
                (
                    sample.rank,
                    sample.cumulative_bytes,
                    sample.key.as_ref().to_vec(),
                )
            })
            .collect()
    }
}

impl Default for StreamingSplitEstimator {
    fn default() -> Self {
        Self::new(Self::DEFAULT_SAMPLE_CAP)
    }
}

#[cfg(test)]
#[path = "split_estimator_tests.rs"]
mod tests;
