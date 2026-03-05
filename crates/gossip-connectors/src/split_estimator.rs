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
//!   `compression * KEY_SAMPLE_FACTOR` (at least [`MIN_SAMPLE_CAP`]).
//! - **Monotonicity**: retained samples are strictly increasing in rank and
//!   non-decreasing in cumulative byte position at all times, including after
//!   compaction and merge.
//! - **Key fidelity**: the estimator only returns *actually observed* keys; it
//!   never synthesizes or interpolates key bytes.
//! - **First-key guard**: the very first key observed is tracked separately so
//!   the "avoid degenerate first-item split" logic survives downsampling.
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
//! 3. **Estimation** — `estimate_split_key` binary-searches the retained
//!    samples for the key closest to `total_bytes / 2`. If all items are
//!    zero-size it falls back to the rank midpoint.
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
//!   of a tunable `compression` parameter.
//! - **u128 arithmetic in interpolation**: avoids floating-point rounding
//!   issues at byte offsets above 2^53.

use std::mem;

/// Absolute floor on sample capacity to prevent degenerate compaction
/// behaviour at very low compression values.
const MIN_SAMPLE_CAP: usize = 64;

/// Multiplier applied to the user-supplied `compression` to derive the
/// retained-sample cap. A factor of 4 gives enough headroom for the
/// nearest-neighbor compaction to preserve byte-space fidelity across
/// repeated halving cycles.
const KEY_SAMPLE_FACTOR: usize = 4;

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
#[derive(Clone, Debug)]
struct Sample {
    /// 0-based ordinal index of this key in stream order.
    rank: u64,
    /// Cumulative byte position at which this sample was recorded.
    ///
    /// When `sampled_by_bytes` is true this is the exact byte-stride mark
    /// that the file straddles; otherwise it is the cumulative byte total
    /// at the start of the file (a rank-triggered fallback position).
    cumulative_bytes: u64,
    /// Marks whether `cumulative_bytes` came from a byte-stride checkpoint
    /// rather than a pure rank fallback. Merge uses this to phase-align the
    /// right-hand estimator's byte samples onto the global byte cadence.
    sampled_by_bytes: bool,
    key: Box<[u8]>,
}

impl Sample {
    fn new(rank: u64, cumulative_bytes: u64, sampled_by_bytes: bool, key: &[u8]) -> Self {
        Self {
            rank,
            cumulative_bytes,
            sampled_by_bytes,
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
/// The algorithm walks the sample array once with a forward cursor,
/// snapping each ideal interpolated position to the nearest actual sample.
/// Two constraints keep the output well-formed:
/// - **Forward progress**: each pick must exceed the previous pick.
/// - **Room for remaining**: each pick is capped so enough indices remain
///   for the picks still to come.
fn selected_sample_indices(samples: &[Sample], cap: usize) -> Vec<usize> {
    debug_assert!(samples.len() > cap);

    let len = samples.len();
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

    picks
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

    if idx == 0 {
        return first;
    }
    if idx + 1 == cap {
        return last;
    }

    let span = (last - first) as u128;
    let numerator = span.saturating_mul(idx as u128);
    let denominator = (cap - 1) as u128;
    (first as u128 + numerator / denominator) as u64
}

/// Round `value` up to the next multiple of `stride` (saturating at
/// `u64::MAX`). Used after compaction to realign the next sampling marks
/// onto the (now-doubled) stride grid.
///
/// # Panics
///
/// Debug-asserts `stride > 0`.
fn align_to_stride(value: u64, stride: u64) -> u64 {
    debug_assert!(stride > 0, "stride must remain non-zero");
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
/// at any time to retrieve the key closest to the byte-weighted median.
///
/// Two or more independent estimators covering non-overlapping, contiguous
/// key ranges can be combined with [`merge`](Self::merge) (append-style only).
///
/// # Complexity
///
/// - **`observe`**: O(1) amortised. Compaction fires at most
///   O(log(stream_length / sample_cap)) times, each costing O(sample_cap).
/// - **`estimate_split_key`**: O(log sample_cap) binary search.
/// - **`merge`**: O(sample_cap) for sample translation plus at most one
///   compaction pass.
/// - **Memory**: O(sample_cap) samples, each carrying a heap-allocated key.
#[derive(Clone, Debug)]
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

impl StreamingSplitEstimator {
    /// Default compression parameter yielding a sample cap of 1024.
    /// Sufficient for <1% byte-weighted error on Zipf-distributed streams
    /// of tens of thousands of keys (validated by property tests).
    pub(crate) const DEFAULT_COMPRESSION: usize = 256;

    /// Create a new streaming estimator.
    ///
    /// `compression` controls the sample-cap sizing: higher values retain more
    /// key checkpoints for better accuracy at the cost of more memory.
    /// Internally the requested compression is clamped to at least `32`, then
    /// multiplied by [`KEY_SAMPLE_FACTOR`] to derive the retained-sample cap.
    pub(crate) fn new(compression: usize) -> Self {
        let compression = compression.max(32);
        let sample_cap = compression
            .saturating_mul(KEY_SAMPLE_FACTOR)
            .max(MIN_SAMPLE_CAP);
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
            self.samples
                .push(Sample::new(rank, byte_position, sample_bytes, key));
        }

        self.count = self.count.saturating_add(1);
        self.total_bytes = end_bytes;

        if self.samples.len() > self.sample_cap {
            self.grow_strides_and_compact();
        }
        self.realign_sample_marks();
    }

    /// Estimate the split key closest to the byte-weighted median.
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
    pub(crate) fn estimate_split_key(&self) -> Option<Vec<u8>> {
        if self.count < 2 {
            return None;
        }

        let max_rank = self.count - 1;
        let midpoint_rank = self.count / 2;
        let rank_target = midpoint_rank.clamp(1, max_rank);

        if self.total_bytes == 0 {
            return Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target)
                .map(ToOwned::to_owned);
        }

        let target_weight = self.total_bytes / 2;
        let mut candidate = Self::nearest_sample(&self.samples, SampleAxis::Bytes, target_weight)
            .or_else(|| Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target))?
            .to_vec();

        // Keep split semantics aligned with existing connectors: avoid
        // degenerate "first item" splits when weight is front-loaded.
        if self
            .first_observed_key
            .as_ref()
            .is_some_and(|first| candidate.as_slice() == first.as_ref())
            && let Some(fallback) =
                Self::nearest_sample(&self.samples, SampleAxis::Rank, rank_target)
        {
            candidate = fallback.to_vec();
        }

        Some(candidate)
    }

    /// Append-merge `other` into `self`.
    ///
    /// `other` must represent keys that are strictly greater than every key
    /// in `self` (append-style merge over a contiguous global key order).
    ///
    /// All ranks and byte positions from `other` are shifted by the
    /// corresponding totals in `self`. Byte-triggered samples in `other`
    /// receive additional phase-alignment: their byte position is
    /// snapped to the next multiple of `other.byte_stride` above
    /// `self.total_bytes`, so that the merged byte axis remains monotonic
    /// and evenly cadenced despite the two estimators having been built
    /// independently.
    ///
    /// After translation, if the merged sample count exceeds the cap, one
    /// or more compaction cycles run to restore the bound.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn merge(&mut self, other: &Self) {
        if other.count == 0 {
            return;
        }

        if self.first_observed_key.is_none() {
            self.first_observed_key = other.first_observed_key.clone();
        }

        let rank_offset = self.count;
        let byte_offset = self.total_bytes;
        // Phase-align: the first byte-stride mark in the right-hand estimator
        // should land on a grid-aligned position relative to self's byte total.
        let other_byte_phase = align_to_stride(byte_offset, other.byte_stride);

        self.count = self.count.saturating_add(other.count);
        self.total_bytes = self.total_bytes.saturating_add(other.total_bytes);
        self.rank_stride = self.rank_stride.max(other.rank_stride);
        self.byte_stride = self.byte_stride.max(other.byte_stride);

        self.samples.reserve(other.samples.len());
        for sample in &other.samples {
            // Byte-triggered samples use the phase-aligned base so the merged
            // byte axis stays monotonic at stride boundaries. Rank-triggered
            // samples use a plain offset because their byte position was
            // already a "best-effort" cumulative snapshot.
            let cumulative_bytes = if sample.sampled_by_bytes {
                other_byte_phase.saturating_add(sample.cumulative_bytes)
            } else {
                byte_offset.saturating_add(sample.cumulative_bytes)
            };
            self.samples.push(Sample {
                rank: sample.rank.saturating_add(rank_offset),
                cumulative_bytes,
                sampled_by_bytes: sample.sampled_by_bytes,
                key: sample.key.clone(),
            });
        }

        while self.samples.len() > self.sample_cap {
            self.grow_strides_and_compact();
        }
        self.realign_sample_marks();
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
    /// Called after every `observe` and after merge to keep the cadence aligned.
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
        Self::new(Self::DEFAULT_COMPRESSION)
    }
}

#[cfg(test)]
#[path = "split_estimator_tests.rs"]
mod tests;
