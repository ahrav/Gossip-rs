//! Tests for [`StreamingSplitEstimator`].
//!
//! Coverage is layered so readers can map tests back to the estimator's
//! promises:
//! - unit/regression tests pin split semantics, redaction, and downsampling
//!   behavior on concrete workloads,
//! - precision tests exercise byte positions above `2^53`, where a
//!   float-based implementation would start collapsing adjacent integer marks,
//! - property tests fuzz the bounded-memory and monotonicity invariants over
//!   randomized streams.
//!
//! Across those layers, the suite reinforces three invariants that the
//! production estimator relies on:
//! - split keys must always be drawn from the observed stream and must never
//!   collapse either shard to empty,
//! - retained samples must remain rank-sorted and byte-monotone even after
//!   compaction, saturation, or plateau redistribution,
//! - batch-style construction and incremental observation must agree on the
//!   same retained sample set and estimated midpoint.
//!
//! The separate 1M-item allocation guard lives in
//! `tests/streaming_split_estimator_perf.rs` because it needs a process-wide
//! counting allocator and the doc-hidden benchmark hook exported from `lib.rs`.

use proptest::prelude::*;

use super::{MIN_SAMPLE_CAP, Sample, StreamingSplitEstimator};

/// Smallest sampling budget accepted by the estimator.
const SMALL_SAMPLE_CAP: usize = MIN_SAMPLE_CAP;
/// Mid-sized budget used by tests that want a stable cap without forcing the
/// default constructor path.
const MEDIUM_SAMPLE_CAP: usize = 512;
/// Default production sampling budget.
const LARGE_SAMPLE_CAP: usize = StreamingSplitEstimator::DEFAULT_SAMPLE_CAP;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Encodes a test ordinal as the fixed-width big-endian key shape used by the
/// estimator.
fn key_for_index(idx: usize) -> [u8; 8] {
    (idx as u64).to_be_bytes()
}

/// Decodes a fixed-width test key back into its ordinal for assertions.
fn index_from_key(key: &[u8]) -> usize {
    let bytes: [u8; 8] = key.try_into().expect("keys must be fixed-width u64 bytes");
    usize::try_from(u64::from_be_bytes(bytes)).expect("index conversion")
}

/// Returns the cumulative byte weight through `idx`, saturating in the same way
/// as the estimator's internal byte accounting.
fn cumulative_at(sizes: &[u64], idx: usize) -> u64 {
    sizes[..=idx]
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add)
}

/// Measures how far a chosen split is from a perfect 50/50 byte partition.
fn relative_weight_error(sizes: &[u64], idx: usize) -> f64 {
    let total = sizes.iter().copied().fold(0u64, u64::saturating_add);
    if total == 0 {
        return 0.0;
    }
    let observed = cumulative_at(sizes, idx) as f64;
    let half = total as f64 / 2.0;
    (observed - half).abs() / total as f64
}

/// Asserts the retained sample sketch preserves the monotone ordering expected
/// by split estimation and compaction.
fn assert_samples_sorted(estimator: &StreamingSplitEstimator) {
    let samples = estimator.sample_debug_view();
    assert!(
        samples.windows(2).all(|window| window[0].0 < window[1].0),
        "sample ranks must remain strictly increasing: {samples:?}"
    );
    assert!(
        samples.windows(2).all(|window| window[0].1 <= window[1].1),
        "sample byte positions must remain non-decreasing: {samples:?}"
    );
}

// ---------------------------------------------------------------------------
// Unit tests — specific edge cases and regression guards
// ---------------------------------------------------------------------------

/// Verify that with 5 equal-size (1 byte) files, the byte-weighted split
/// selects a file near the midpoint. With an odd count of equal-weight items
/// a perfect 50/50 is impossible, so either a 2/3 or 3/2 split is acceptable.
#[test]
fn equal_weight_files_split_near_midpoint() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    for idx in 0..5u64 {
        estimator.observe(&key_for_index(idx as usize), 1);
    }
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
    assert!(
        split_idx == 2 || split_idx == 3,
        "expected split near midpoint (index 2 or 3), got index {}",
        split_idx
    );
}

/// Ensures even with a weight spike at the end, the estimator's last-key guard
/// and rank fallback prevent an empty right shard.
#[test]
fn skewed_sizes_split_avoids_last_key_with_back_loaded_weight() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 5);
    estimator.observe(&key_for_index(1), 5);
    estimator.observe(&key_for_index(2), 100);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
    assert_eq!(
        split_idx, 1,
        "last-key guard should fall back to rank midpoint, got index {}",
        split_idx
    );
}

/// `estimate_split_key` must stay empty until at least two files are observed.
#[test]
fn estimate_requires_at_least_two_entries() {
    let mut estimator = StreamingSplitEstimator::default();
    assert!(estimator.estimate_split_key().is_none());

    let key0 = key_for_index(0);
    estimator.observe(&key0, 10);
    assert!(estimator.estimate_split_key().is_none());
}

/// When a single observation satisfies both rank and byte sampling cadences, only one sample is retained.
#[test]
fn observe_does_not_duplicate_samples_when_rank_and_byte_triggers_overlap() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 1);
    assert_eq!(
        estimator.sample_len(),
        1,
        "a single observation that satisfies both sampling rules should retain only one sample"
    );
}

/// A large first file should never become the split point even when it dominates the byte stream.
#[test]
fn estimator_avoids_first_item_on_heavy_lead_weight() {
    let mut estimator = StreamingSplitEstimator::new(MEDIUM_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 10_000_000);
    for idx in 1..64 {
        estimator.observe(&key_for_index(idx), 1);
    }
    let split = estimator.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(split);
    assert!(
        split_idx >= 1,
        "split must leave at least one key on the left"
    );
    assert!(
        split_idx < 64,
        "split index should stay within observed range"
    );
}

/// Verifies a Zipf-like distribution keeps the estimated split within 1% byte-weighted error despite the skew.
#[test]
fn zipf_like_stream_is_within_one_percent_weight_error() {
    let count = 20_000usize;
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    let mut sizes = Vec::with_capacity(count);
    for idx in 0..count {
        let size = (count - idx) as u64;
        sizes.push(size);
        let key = key_for_index(idx);
        estimator.observe(&key, size);
    }

    let split = estimator.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(split);
    let error = relative_weight_error(&sizes, split_idx);
    assert!(
        error <= 0.01,
        "expected <=1% weighted error, got {:.4} at index {}",
        error,
        split_idx
    );
}

/// With exactly two items the only valid split is at index 1 (the second key).
/// Splitting at index 0 would leave zero items on the left side.
#[test]
fn two_items_split_at_second_key() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 100);
    estimator.observe(&key_for_index(1), 1);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
    assert_eq!(
        split_idx, 1,
        "with two items, split must be at index 1, got {}",
        split_idx
    );
}

/// Two zero-sized items also split at index 1 (rank midpoint for count=2).
#[test]
fn two_zero_size_items_split_at_second_key() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 0);
    estimator.observe(&key_for_index(1), 0);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
    assert_eq!(
        split_idx, 1,
        "with two zero-size items, split must be at index 1, got {}",
        split_idx
    );
}

#[test]
fn sample_debug_redacts_key_bytes() {
    let key = b"/secret/customer/path";
    let sample = Sample::new(7, 42, key);

    let rendered = format!("{sample:?}");

    assert!(
        rendered.contains(&format!("[{} bytes]", key.len())),
        "sample Debug should include only the key length: {rendered}"
    );
    assert!(
        !rendered.contains("/secret/customer/path"),
        "sample Debug must redact raw key bytes: {rendered}"
    );
}

#[test]
fn estimator_debug_redacts_observed_keys() {
    let first = b"/secret/customer/path";
    let second = b"/secret/customer/path-2";
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.observe(first, 5);
    estimator.observe(second, 7);

    let rendered = format!("{estimator:?}");

    assert!(
        rendered.contains("samples_len: 2"),
        "estimator Debug should report structural sample counts: {rendered}"
    );
    assert!(
        rendered.contains(&format!("Some([{} bytes])", first.len())),
        "estimator Debug should redact the first key to a length summary: {rendered}"
    );
    assert!(
        !rendered.contains("/secret/customer/path"),
        "estimator Debug must redact raw first key bytes: {rendered}"
    );
    assert!(
        !rendered.contains("/secret/customer/path-2"),
        "estimator Debug must not leak retained sample keys: {rendered}"
    );
}

#[test]
fn requested_sample_cap_is_clamped_to_minimum() {
    let estimator = StreamingSplitEstimator::new(1);
    assert_eq!(
        estimator.sample_cap(),
        SMALL_SAMPLE_CAP,
        "requested caps below the minimum should round up"
    );
}

#[test]
fn from_sorted_entries_matches_manual_observe_path() {
    let entries: Vec<(Vec<u8>, u64)> = vec![
        (key_for_index(0).to_vec(), 7),
        (key_for_index(1).to_vec(), 0),
        (key_for_index(2).to_vec(), 13),
        (key_for_index(3).to_vec(), 5),
        (key_for_index(4).to_vec(), 1),
    ];

    let built = StreamingSplitEstimator::from_sorted_entries(
        1,
        entries.iter().map(|(key, size)| (key.as_slice(), *size)),
    );

    let mut observed = StreamingSplitEstimator::new(1);
    for (key, size) in &entries {
        observed.observe(key, *size);
    }

    assert_eq!(built.sample_cap(), observed.sample_cap());
    assert_eq!(built.sample_debug_view(), observed.sample_debug_view());
    assert_eq!(built.estimate_split_key(), observed.estimate_split_key());
}

#[test]
fn from_sorted_entries_estimates_split_for_materialized_range() {
    let keys: Vec<[u8; 8]> = (0..4).map(key_for_index).collect();
    let sizes = [1u64, 1, 1_000, 1];

    let estimator = StreamingSplitEstimator::from_sorted_entries(
        LARGE_SAMPLE_CAP,
        keys.iter()
            .zip(sizes)
            .map(|(key, size)| (key.as_slice(), size)),
    );

    let split = estimator
        .estimate_split_key()
        .expect("materialized range should produce a split");
    assert_eq!(index_from_key(split), 2);
}

/// Exercise the compaction path of `from_sorted_entries` with more entries
/// than MIN_SAMPLE_CAP.  Verifies that the constructor delegates compaction
/// correctly end-to-end, matching the manual `observe` path.
#[test]
fn from_sorted_entries_compacts_when_exceeding_sample_cap() {
    let n = SMALL_SAMPLE_CAP * 4;
    let keys: Vec<[u8; 8]> = (0..n).map(key_for_index).collect();
    let sizes: Vec<u64> = (0..n).map(|i| (i as u64) + 1).collect();

    let built = StreamingSplitEstimator::from_sorted_entries(
        SMALL_SAMPLE_CAP,
        keys.iter()
            .zip(sizes.iter())
            .map(|(k, &s)| (k.as_slice(), s)),
    );

    assert!(
        built.sample_len() <= built.sample_cap(),
        "sample count ({}) exceeded cap ({}) after from_sorted_entries with n={n}",
        built.sample_len(),
        built.sample_cap()
    );

    let mut observed = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    for (key, &size) in keys.iter().zip(sizes.iter()) {
        observed.observe(key, size);
    }
    assert_eq!(built.sample_cap(), observed.sample_cap());
    assert_eq!(built.sample_debug_view(), observed.sample_debug_view());
    assert_eq!(built.estimate_split_key(), observed.estimate_split_key());

    let split = built
        .estimate_split_key()
        .expect("should produce a split for n > 2");
    let split_idx = index_from_key(split);
    assert!(split_idx >= 1 && split_idx < n);
}

/// An empty iterator produces an estimator with no observations, so
/// `estimate_split_key` must return `None`.
#[test]
fn from_sorted_entries_empty_produces_none() {
    let estimator =
        StreamingSplitEstimator::from_sorted_entries(SMALL_SAMPLE_CAP, std::iter::empty());
    assert!(
        estimator.estimate_split_key().is_none(),
        "empty input must yield no split key"
    );
}

// ---------------------------------------------------------------------------
// Batch-connector accuracy: ranges exceeding DEFAULT_SAMPLE_CAP
// ---------------------------------------------------------------------------

/// Batch connectors pass the full range length as `sample_cap`, bypassing compaction so that their split matches an exact estimator even on large datasets.
#[test]
fn batch_range_cap_eliminates_split_drift() {
    let n = 2_000usize;
    assert!(
        n > LARGE_SAMPLE_CAP,
        "test must exceed DEFAULT_SAMPLE_CAP to be meaningful"
    );

    let sizes: Vec<u64> = (0..n).map(|i| (n - i) as u64).collect();
    let keys: Vec<[u8; 8]> = (0..n).map(key_for_index).collect();

    let make_iter = || {
        keys.iter()
            .zip(sizes.iter())
            .map(|(k, &s)| (k.as_slice(), s))
    };

    let exact = StreamingSplitEstimator::from_sorted_entries(n, make_iter());
    let exact_key = exact
        .estimate_split_key()
        .expect("exact estimator should produce a split");

    let capped = StreamingSplitEstimator::from_sorted_entries(LARGE_SAMPLE_CAP, make_iter());
    let capped_key = capped
        .estimate_split_key()
        .expect("capped estimator should produce a split");

    assert_ne!(
        index_from_key(exact_key),
        index_from_key(capped_key),
        "expected capped estimator to differ from exact on n={n}, \
         cap={LARGE_SAMPLE_CAP}"
    );

    let batch = StreamingSplitEstimator::from_sorted_entries(n, make_iter());
    assert_eq!(
        batch.estimate_split_key(),
        exact.estimate_split_key(),
        "batch-cap estimator must match exact estimator"
    );
}

// ---------------------------------------------------------------------------
// Downsampling regressions
// ---------------------------------------------------------------------------

/// After repeated downsampling, the estimator must still avoid returning the
/// very first observed key when weight is front-loaded.
#[test]
fn front_loaded_split_avoids_first_key_after_downsampling() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    let cap = estimator.sample_cap();
    let n = 2_000usize;
    assert!(
        n > cap,
        "test must exceed sample_cap to trigger downsampling"
    );

    estimator.observe(&key_for_index(0), 100_000_000);
    for idx in 1..n {
        estimator.observe(&key_for_index(idx), 1);
    }

    let split = estimator.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(split);
    assert!(
        split_idx >= 1,
        "split must not return index 0 (the first observed key) after downsampling, got {}",
        split_idx
    );
}

#[test]
fn sample_count_stays_bounded_after_repeated_downsampling() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    let cap = estimator.sample_cap();
    let n = cap * 8;
    for idx in 0..n {
        estimator.observe(&key_for_index(idx), (idx as u64) + 1);
    }

    assert!(
        estimator.sample_len() <= cap,
        "sample count ({}) exceeded cap ({cap})",
        estimator.sample_len()
    );
    assert_samples_sorted(&estimator);

    let samples = estimator.sample_debug_view();
    assert_eq!(
        index_from_key(samples.first().expect("samples").2.as_slice()),
        0,
        "downsampling must preserve the first observed key"
    );
    assert_eq!(
        index_from_key(samples.last().expect("samples").2.as_slice()),
        n - 1,
        "downsampling must preserve the last observed key"
    );
}

#[test]
fn downsampling_when_barely_exceeding_cap_keeps_split_in_range() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    let cap = estimator.sample_cap();
    for idx in 0..(cap + 1) {
        estimator.observe(&key_for_index(idx), (idx as u64) + 1);
    }

    assert!(estimator.sample_len() <= cap);
    assert_samples_sorted(&estimator);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
    assert!(split_idx >= 1 && split_idx <= cap);
}

/// No cadence firing should leave samples and marks untouched.
#[test]
fn observe_leaves_marks_unchanged_when_no_cadence_fires() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 4;
    estimator.byte_stride = 10;
    estimator.count = 3;
    estimator.total_bytes = 13;
    estimator.next_rank_sample = 4;
    estimator.next_byte_mark = 20;

    estimator.observe(&key_for_index(3), 5);

    assert_eq!(
        estimator.sample_len(),
        0,
        "no cadence should mean no sample"
    );
    assert_eq!(estimator.count, 4);
    assert_eq!(estimator.total_bytes, 18);
    assert_eq!(
        estimator.next_rank_sample, 4,
        "rank mark should stay put until the pending cadence actually fires"
    );
    assert_eq!(
        estimator.next_byte_mark, 20,
        "byte mark should stay put when the file does not straddle it"
    );
}

/// A wide file that straddles multiple byte marks should realign the byte mark back onto the byte-stride grid.
#[test]
fn observe_realigns_byte_mark_after_wide_file_skips_multiple_cadences() {
    use super::align_to_stride;

    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 4;
    estimator.byte_stride = 10;
    estimator.count = 3;
    estimator.total_bytes = 12;
    estimator.next_rank_sample = 4;
    estimator.next_byte_mark = 20;

    estimator.observe(&key_for_index(3), 100);

    assert_eq!(
        estimator.sample_len(),
        1,
        "wide file should still emit one sample"
    );
    assert_eq!(
        estimator.next_rank_sample, 4,
        "rank mark should remain pending because only the byte cadence fired"
    );
    assert_eq!(
        estimator.next_byte_mark,
        align_to_stride(estimator.total_bytes, estimator.byte_stride),
        "byte mark must jump beyond every mark consumed by the wide file"
    );
    assert_eq!(estimator.next_byte_mark, 120);

    let samples = estimator.sample_debug_view();
    assert_eq!(samples[0].0, 3, "sample should retain the triggering rank");
    assert_eq!(
        samples[0].1, 20,
        "sample should retain the original byte mark that was straddled"
    );
}

/// When only the rank cadence fires, the rank mark must advance while the byte mark stays stationary.
#[test]
fn observe_advances_rank_mark_only_when_rank_cadence_fires_alone() {
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 4;
    estimator.byte_stride = 10;
    estimator.count = 4;
    estimator.total_bytes = 13;
    estimator.next_rank_sample = 4;
    estimator.next_byte_mark = 20;

    // end_bytes = 13 + 3 = 16, which does NOT straddle 20.
    estimator.observe(&key_for_index(4), 3);

    assert_eq!(
        estimator.sample_len(),
        1,
        "rank cadence should emit a sample"
    );
    assert_eq!(
        estimator.next_rank_sample, 8,
        "rank mark must advance by exactly one rank_stride from the firing rank"
    );
    assert_eq!(
        estimator.next_byte_mark, 20,
        "byte mark must remain unchanged when only the rank cadence fires"
    );
}

#[test]
fn compaction_realigns_marks_to_the_doubled_stride_grid() {
    use super::{Sample, align_to_stride};

    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 2;
    estimator.byte_stride = 5;
    estimator.count = 5;
    estimator.total_bytes = 13;
    estimator.next_rank_sample = 6;
    estimator.next_byte_mark = 15;
    estimator.samples = (0..(estimator.sample_cap() + 1))
        .map(|idx| Sample::new((idx as u64) * 2, (idx as u64) * 5, &key_for_index(idx)))
        .collect();

    estimator.grow_strides_and_compact();

    assert_eq!(estimator.rank_stride, 4);
    assert_eq!(estimator.byte_stride, 10);
    assert_eq!(
        estimator.next_rank_sample,
        align_to_stride(estimator.count, estimator.rank_stride),
        "rank mark should snap to the new stride grid after compaction"
    );
    assert_eq!(
        estimator.next_byte_mark,
        align_to_stride(estimator.total_bytes, estimator.byte_stride),
        "byte mark should snap to the new stride grid after compaction"
    );
    assert!(estimator.sample_len() <= estimator.sample_cap());
    assert_samples_sorted(&estimator);
}

// ---------------------------------------------------------------------------
// Extreme value, precision, and determinism tests
// ---------------------------------------------------------------------------

/// Very large file sizes (near u64::MAX / 2) should not overflow or panic.
#[test]
fn extreme_file_sizes_no_overflow() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    let huge = u64::MAX / 2;
    estimator.observe(&key_for_index(0), huge);
    estimator.observe(&key_for_index(1), huge);
    estimator.observe(&key_for_index(2), 1);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split with extreme sizes");
    let split_idx = index_from_key(split);
    assert!(
        (1..=2).contains(&split_idx),
        "split index should be 1 or 2, got {}",
        split_idx
    );
}

/// Regression guard for the `u128` byte-position path: adjacent byte marks
/// above `2^53` must stay distinguishable, or midpoint search would drift once
/// integer offsets stop round-tripping through `f64`.
#[test]
fn byte_positions_above_f64_precision_boundary_remain_distinguishable() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    let boundary = 1u64 << 53;

    estimator.observe(&key_for_index(0), boundary);
    estimator.observe(&key_for_index(1), 1);
    estimator.observe(&key_for_index(2), 1);
    estimator.observe(&key_for_index(3), boundary);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    assert_eq!(
        index_from_key(split),
        2,
        "adjacent byte offsets above 2^53 must remain distinguishable"
    );

    let samples = estimator.sample_debug_view();
    assert!(
        samples
            .iter()
            .any(|(_, bytes, key)| { *bytes == boundary && index_from_key(key.as_slice()) == 1 }),
        "expected sample at byte offset 2^53 for key 1"
    );
    assert!(
        samples.iter().any(|(_, bytes, key)| {
            *bytes == boundary + 1 && index_from_key(key.as_slice()) == 2
        }),
        "expected sample at byte offset 2^53 + 1 for key 2"
    );
}

// ---------------------------------------------------------------------------
// Internal helper tests
// ---------------------------------------------------------------------------

#[test]
fn align_to_stride_edge_cases() {
    use super::align_to_stride;

    assert_eq!(align_to_stride(0, 5), 0, "zero already aligned");
    assert_eq!(align_to_stride(1, 5), 5, "round up");
    assert_eq!(align_to_stride(5, 5), 5, "exact multiple");
    assert_eq!(align_to_stride(6, 5), 10, "round up past multiple");
    assert_eq!(align_to_stride(u64::MAX, 5), u64::MAX, "MAX passthrough");
    assert_eq!(
        align_to_stride(u64::MAX - 2, 4),
        u64::MAX,
        "saturating_add triggers"
    );
    assert_eq!(align_to_stride(0, 1), 0, "stride=1 is identity for 0");
    assert_eq!(align_to_stride(7, 1), 7, "stride=1 is identity");
}

#[test]
fn interpolated_position_edge_cases() {
    use super::interpolated_position;

    assert_eq!(interpolated_position(0, 100, 0, 5), 0, "first endpoint");
    assert_eq!(interpolated_position(0, 100, 4, 5), 100, "last endpoint");
    assert_eq!(interpolated_position(0, 100, 2, 5), 50, "midpoint");
    assert_eq!(interpolated_position(10, 110, 1, 3), 60, "non-zero first");
    // Verify no panic/overflow on large span via u128 path.
    let result = interpolated_position(0, u64::MAX, 1, 3);
    assert_eq!(
        result,
        u64::MAX / 2,
        "large span uses u128 arithmetic without overflow"
    );
}

// -- nearest_by_rank_in_range --

#[test]
fn nearest_by_rank_in_range_single_element() {
    use super::{Sample, nearest_by_rank_in_range};

    let samples = vec![Sample::new(42, 0, &key_for_index(0))];
    assert_eq!(
        nearest_by_rank_in_range(&samples, 0, 0, 42),
        0,
        "single element must return lo"
    );
    assert_eq!(
        nearest_by_rank_in_range(&samples, 0, 0, 100),
        0,
        "single element must return lo regardless of target"
    );
}

#[test]
fn nearest_by_rank_in_range_selects_closest() {
    use super::{Sample, nearest_by_rank_in_range};

    let samples: Vec<Sample> = (0..10)
        .map(|i| Sample::new(i * 10, 0, &key_for_index(i as usize)))
        .collect();

    // Target 25 is between rank 20 (idx 2) and rank 30 (idx 3).
    // 30 − 25 = 5, 25 − 20 = 5 → tie → earlier index wins.
    assert_eq!(
        nearest_by_rank_in_range(&samples, 0, 9, 25),
        2,
        "equidistant target should pick earlier index"
    );

    // Target 26 is closer to rank 30 (idx 3) than rank 20 (idx 2).
    assert_eq!(
        nearest_by_rank_in_range(&samples, 0, 9, 26),
        3,
        "target closer to higher rank should pick that index"
    );

    // Restrict range to [4, 7] (ranks 40..70), target 55.
    assert_eq!(
        nearest_by_rank_in_range(&samples, 4, 7, 55),
        5,
        "should snap to nearest within restricted range"
    );
}

#[test]
fn nearest_by_rank_in_range_tie_breaks_to_earlier() {
    use super::{Sample, nearest_by_rank_in_range};

    // Two samples equidistant from target.
    let samples = vec![
        Sample::new(10, 0, &key_for_index(0)),
        Sample::new(30, 0, &key_for_index(1)),
    ];
    // Target 20 is equidistant from 10 and 30.
    assert_eq!(
        nearest_by_rank_in_range(&samples, 0, 1, 20),
        0,
        "tie must break to earlier index"
    );
}

#[cfg(debug_assertions)]
#[test]
#[should_panic]
fn nearest_by_rank_in_range_panics_on_invalid_bounds() {
    use super::{Sample, nearest_by_rank_in_range};

    let samples = vec![
        Sample::new(0, 0, &key_for_index(0)),
        Sample::new(10, 0, &key_for_index(1)),
    ];
    // lo > hi should panic (slice indexing).
    nearest_by_rank_in_range(&samples, 1, 0, 5);
}

/// Compacting with `cap == len` is a no-op: no samples are evicted and every
/// field remains identical.
#[test]
fn compact_samples_noop_when_cap_equals_len() {
    use super::{Sample, compact_samples};

    let original: Vec<Sample> = (0..10)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
        .collect();
    let mut samples = original.clone();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    for (a, b) in samples.iter().zip(original.iter()) {
        assert_eq!(a.rank, b.rank);
        assert_eq!(a.recorded_byte_position, b.recorded_byte_position);
        assert_eq!(a.key, b.key);
    }
}

/// Compacting with `cap == len - 1` evicts exactly one sample. Endpoints and
/// monotonicity invariants must still hold in this most-constrained case.
#[test]
fn compact_samples_evicts_exactly_one_when_cap_is_len_minus_one() {
    use super::{Sample, compact_samples};

    let n = 20usize;
    let mut samples: Vec<Sample> = (0..n)
        .map(|i| Sample::new(i as u64, (i as u64) * 50, &key_for_index(i)))
        .collect();

    compact_samples(&mut samples, n - 1);

    assert_eq!(samples.len(), n - 1);
    assert_eq!(samples.first().unwrap().rank, 0);
    assert_eq!(samples.last().unwrap().rank, (n - 1) as u64);
    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].recorded_byte_position <= w[1].recorded_byte_position)
    );
}

#[test]
fn compact_samples_preserves_endpoints_and_monotonicity() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
        .collect();

    let original_first_key = samples.first().unwrap().key.clone();
    let original_last_key = samples.last().unwrap().key.clone();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    assert_eq!(samples.first().unwrap().key, original_first_key);
    assert_eq!(samples.last().unwrap().key, original_last_key);

    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].recorded_byte_position <= w[1].recorded_byte_position)
    );
}

#[test]
fn compact_samples_keeps_exact_indices_selected_for_compaction() {
    use super::{Sample, compact_samples, selected_sample_indices};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| {
            let bytes = if i < 12 { (i as u64) * 100 } else { 1_200 };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    let expected: Vec<_> = selected_sample_indices(&samples, 10)
        .into_iter()
        .map(|idx| {
            let sample = &samples[idx];
            (
                sample.rank,
                sample.recorded_byte_position,
                sample.key.clone(),
            )
        })
        .collect();

    compact_samples(&mut samples, 10);

    let actual: Vec<_> = samples
        .iter()
        .map(|sample| {
            (
                sample.rank,
                sample.recorded_byte_position,
                sample.key.clone(),
            )
        })
        .collect();

    assert_eq!(actual, expected);
}

/// Regression: when the last N samples share identical
/// `recorded_byte_position`
/// (a byte-position plateau), compaction must still preserve the actual last
/// sample. Nearest-neighbor tie-breaking must select `len - 1` (the true
/// last sample), not the first plateau entry.
#[test]
fn compact_samples_preserves_last_sample_when_byte_positions_repeat_at_end() {
    use super::{Sample, compact_samples};

    // 20 samples: first 12 have distinct increasing byte positions,
    // last 8 all share the same recorded byte position (plateau).
    let plateau_bytes = 1200_u64;
    let mut samples: Vec<Sample> = (0..20)
        .map(|i| {
            let bytes = if i < 12 {
                (i as u64) * 100
            } else {
                plateau_bytes
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    let original_last_key = samples.last().unwrap().key.clone();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    assert_eq!(
        &*samples.first().unwrap().key,
        key_for_index(0).as_slice(),
        "first sample must be preserved"
    );
    assert_eq!(
        samples.last().unwrap().key,
        original_last_key,
        "last sample must be preserved even in a trailing plateau"
    );
    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].recorded_byte_position <= w[1].recorded_byte_position)
    );
}

/// Compacting to 2 retains only the first and last sample, with strictly
/// increasing ranks.
#[test]
fn compact_samples_cap_two_preserves_first_and_last() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..10)
        .map(|i| Sample::new(i as u64, (i as u64) * 50, &key_for_index(i)))
        .collect();

    compact_samples(&mut samples, 2);

    assert_eq!(samples.len(), 2);
    assert_eq!(samples[0].rank, 0, "first sample preserved");
    assert_eq!(samples[1].rank, 9, "last sample preserved");
    assert!(
        samples[0].rank < samples[1].rank,
        "ranks must be strictly increasing"
    );
    assert!(
        samples[0].recorded_byte_position <= samples[1].recorded_byte_position,
        "byte positions must be non-decreasing"
    );
}

/// When all samples share byte position 0, `selected_sample_indices` falls
/// back to uniform index spacing. With 20 samples compacted to 5, the
/// expected picks are indices 0, 4, 9, 14, 19 (i.e. `i * 19 / 4`).
#[test]
fn compact_samples_all_identical_byte_positions_uses_index_spacing() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| Sample::new(i as u64, 0, &key_for_index(i)))
        .collect();

    compact_samples(&mut samples, 5);

    assert_eq!(samples.len(), 5);
    let ranks: Vec<u64> = samples.iter().map(|s| s.rank).collect();
    assert_eq!(ranks, vec![0, 4, 9, 14, 19]);
}

/// Half-reduction of a 512-sample stream preserves endpoints, monotonicity,
/// and approximately uniform rank spacing.
#[test]
fn compact_samples_typical_half_reduction() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..512)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
        .collect();

    compact_samples(&mut samples, 256);

    assert_eq!(samples.len(), 256);
    assert_eq!(samples.first().unwrap().rank, 0, "first sample preserved");
    assert_eq!(samples.last().unwrap().rank, 511, "last sample preserved");

    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].recorded_byte_position <= w[1].recorded_byte_position)
    );

    let gaps: Vec<u64> = samples.windows(2).map(|w| w[1].rank - w[0].rank).collect();
    let avg_gap = gaps.iter().sum::<u64>() as f64 / gaps.len() as f64;
    assert!(
        (1.5..=2.5).contains(&avg_gap),
        "average rank gap {avg_gap:.2} should be approximately 2.0"
    );
}

/// Regression: trailing samples saturated at `u64::MAX` must still preserve
/// the actual last sample after compaction.
#[test]
fn saturated_tail_preserves_last_sample() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| {
            let bytes = if i < 10 {
                (i as u64) * 1_000_000
            } else {
                u64::MAX
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    let original_last_key = samples.last().unwrap().key.clone();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    assert_eq!(
        &*samples.first().unwrap().key,
        key_for_index(0).as_slice(),
        "first sample must be preserved under u64::MAX saturation plateau"
    );
    assert_eq!(
        samples.last().unwrap().key,
        original_last_key,
        "last sample must be preserved under u64::MAX saturation plateau"
    );
    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
}

/// Compacting to a single slot must preserve the last sample (most-recent
/// observation), not the first.
#[test]
fn compact_to_single_slot_keeps_last_sample() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..5)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
        .collect();

    let original_last_key = samples.last().unwrap().key.clone();

    compact_samples(&mut samples, 1);

    assert_eq!(samples.len(), 1, "should compact down to exactly 1 sample");
    assert_eq!(
        samples[0].key, original_last_key,
        "the single retained sample must be the last (most-recent) observation"
    );
}

// ---------------------------------------------------------------------------
// Compaction edge-case tests — early-return paths
// ---------------------------------------------------------------------------

/// Empty sample vec is a no-op: `compact_samples` returns immediately.
#[test]
fn compact_samples_empty_vec_is_noop() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = vec![];
    compact_samples(&mut samples, 10);
    assert!(samples.is_empty());
}

/// Single-element vec is preserved unchanged when cap >= 1.
#[test]
fn compact_samples_single_element_preserved() {
    use super::{Sample, compact_samples};

    let mut samples = vec![Sample::new(0, 42, &key_for_index(0))];
    compact_samples(&mut samples, 10);
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].rank, 0);
    assert_eq!(samples[0].recorded_byte_position, 42);
}

/// When len == cap, no compaction is needed — identity operation.
#[test]
fn compact_samples_at_cap_is_identity() {
    use super::{Sample, compact_samples};

    let original: Vec<Sample> = (0..10)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
        .collect();
    let expected: Vec<_> = original
        .iter()
        .map(|s| (s.rank, s.recorded_byte_position, s.key.clone()))
        .collect();

    let mut samples = original;
    compact_samples(&mut samples, 10);

    let actual: Vec<_> = samples
        .iter()
        .map(|s| (s.rank, s.recorded_byte_position, s.key.clone()))
        .collect();
    assert_eq!(actual, expected);
}

// ---------------------------------------------------------------------------
// Saturation edge-case tests
// ---------------------------------------------------------------------------

/// Observing a `u64::MAX` file still respects the first-key guard.
#[test]
fn observe_with_max_file_size() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), u64::MAX);
    estimator.observe(&key_for_index(1), 1);
    estimator.observe(&key_for_index(2), 1);

    let split = estimator.estimate_split_key().expect("split expected");
    let split_idx = index_from_key(split);
    assert!(split_idx >= 1, "first-key guard must hold, got {split_idx}");
}

/// Saturated byte positions must still allow the estimator to find a valid split.
#[test]
fn recorded_byte_position_saturation() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), u64::MAX - 10);
    estimator.observe(&key_for_index(1), 20); // saturates to MAX
    estimator.observe(&key_for_index(2), 100); // already at MAX

    let split = estimator.estimate_split_key().expect("split expected");
    let split_idx = index_from_key(split);
    assert!(
        split_idx >= 1,
        "valid split required, got index {split_idx}"
    );
}

/// Saturating total bytes must realign the cadence marks to the stride grid without overflowing.
#[test]
fn observe_realigns_marks_after_u64_max_saturation() {
    use super::align_to_stride;

    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 4;
    estimator.byte_stride = 100;
    estimator.count = u64::MAX - 3;
    estimator.total_bytes = u64::MAX - 500;
    estimator.next_rank_sample = u64::MAX - 3;
    estimator.next_byte_mark = u64::MAX - 500;
    estimator.samples.push(Sample::new(0, 0, &key_for_index(0)));
    estimator.first_observed_key = Some(Box::from(key_for_index(0).as_slice()));

    estimator.observe(&key_for_index(1), 600);

    assert_eq!(
        estimator.total_bytes,
        u64::MAX,
        "total_bytes should saturate"
    );
    assert!(
        estimator.sample_len() >= 2,
        "cadence should have emitted a sample"
    );
    assert_eq!(
        estimator.next_rank_sample,
        align_to_stride(estimator.count, estimator.rank_stride),
        "rank mark must be realigned to stride grid after saturation"
    );
    assert_eq!(
        estimator.next_byte_mark,
        align_to_stride(estimator.total_bytes, estimator.byte_stride),
        "byte mark must be realigned to stride grid after saturation"
    );
    // When total_bytes == u64::MAX, align_to_stride returns u64::MAX.
    assert_eq!(
        estimator.next_byte_mark,
        u64::MAX,
        "byte mark should be pinned at u64::MAX when total_bytes is saturated"
    );
}

/// When the entry count saturates to `u64::MAX`, cadence marks must realign even without emitting a new sample.
#[test]
fn observe_realigns_marks_after_count_saturates_to_max() {
    use super::align_to_stride;

    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.rank_stride = 4;
    estimator.byte_stride = 100;
    estimator.count = u64::MAX - 1;
    estimator.total_bytes = 5000;
    estimator.next_rank_sample = u64::MAX;
    estimator.next_byte_mark = 6000;
    estimator.samples.push(Sample::new(0, 0, &key_for_index(0)));
    estimator.first_observed_key = Some(Box::from(key_for_index(0).as_slice()));

    estimator.observe(&key_for_index(1), 10);

    assert_eq!(
        estimator.count,
        u64::MAX,
        "count should saturate to u64::MAX"
    );
    assert_eq!(
        estimator.total_bytes, 5010,
        "total_bytes should advance normally (not saturated)"
    );
    assert_eq!(
        estimator.next_rank_sample,
        align_to_stride(estimator.count, estimator.rank_stride),
        "rank mark must be realigned after count saturates"
    );
    // count == u64::MAX → align_to_stride(u64::MAX, 4) == u64::MAX.
    assert_eq!(
        estimator.next_rank_sample,
        u64::MAX,
        "rank mark should be pinned at u64::MAX when count is saturated"
    );
    assert_eq!(
        estimator.next_byte_mark,
        align_to_stride(estimator.total_bytes, estimator.byte_stride),
        "byte mark must be realigned onto the stride grid after saturation"
    );
    // total_bytes == 5010, byte_stride == 100 → align_to_stride(5010, 100) == 5100.
    assert_eq!(
        estimator.next_byte_mark, 5100,
        "byte mark should snap forward to the next stride-aligned value"
    );
}

// ---------------------------------------------------------------------------
// Property tests — general invariants over randomised inputs
// ---------------------------------------------------------------------------

proptest! {
    /// For any stream of zero-size items with count >= 2, the estimated split
    /// key equals the ordinal midpoint `count / 2` (integer division).
    #[test]
    fn prop_zero_sizes_use_count_midpoint(count in 2..500usize) {
        let mut estimator = StreamingSplitEstimator::default();
        for idx in 0..count {
            estimator.observe(&key_for_index(idx), 0);
        }
        let key = estimator
            .estimate_split_key()
            .expect("should produce a split with count >= 2");
        prop_assert_eq!(
            index_from_key(key),
            count / 2,
            "zero-size stream of {} items should split at index {}",
            count,
            count / 2
        );
    }

    /// The estimated split key must always be one of the actually observed
    /// keys — the estimator must never synthesize or interpolate keys.
    #[test]
    fn prop_split_key_is_always_observed_key(count in 2..200usize) {
        let mut estimator = StreamingSplitEstimator::default();
        let mut observed_keys = Vec::with_capacity(count);
        for idx in 0..count {
            let key = key_for_index(idx);
            let size = (idx as u64) + 1;
            estimator.observe(&key, size);
            observed_keys.push(key.to_vec());
        }
        let split = estimator
            .estimate_split_key()
            .expect("should produce split with count >= 2");
        prop_assert!(
            observed_keys.iter().any(|k| k.as_slice() == split),
            "split key {:?} was not among the {} observed keys",
            split,
            count
        );
    }

    /// For any sample-cap setting and stream length (with mixed zero and
    /// non-zero sizes), the unified sample set remains bounded and sorted.
    ///
    /// Ranges are tuned to exercise downsampling paths while keeping wall-clock
    /// time under CI-friendly bounds.
    #[test]
    fn prop_sample_memory_bounded(
        sample_cap in MIN_SAMPLE_CAP..2048usize,
        count in 0..2_000usize,
    ) {
        let mut estimator = StreamingSplitEstimator::new(sample_cap);
        for idx in 0..count {
            let key = key_for_index(idx);
            let size = if idx % 3 == 0 { 0 } else { (idx as u64) + 1 };
            estimator.observe(&key, size);
        }

        prop_assert!(
            estimator.sample_len() <= estimator.sample_cap(),
            "samples ({}) exceeded cap ({})",
            estimator.sample_len(),
            estimator.sample_cap()
        );

        let samples = estimator.sample_debug_view();
        prop_assert!(
            samples.windows(2).all(|window| window[0].0 < window[1].0),
            "sample ranks must remain strictly increasing: {:?}",
            samples
        );
        prop_assert!(
            samples.windows(2).all(|window| window[0].1 <= window[1].1),
            "sample byte positions must remain non-decreasing: {:?}",
            samples
        );
    }

    /// Appending equal-size items should only move the estimated midpoint
    /// backward by at most one retained-sample gap when compaction reshapes
    /// the sketch.
    #[test]
    fn prop_split_estimate_stable_under_append(count in (MIN_SAMPLE_CAP + 1)..4_096usize) {
        let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
        let mut previous_split = None;

        estimator.observe(&key_for_index(0), 1);

        for idx in 1..count {
            estimator.observe(&key_for_index(idx), 1);

            let split = estimator
                .estimate_split_key()
                .expect("count >= 2 should always produce a split");
            let split_idx = index_from_key(split);

            if let Some(previous) = previous_split {
                let observed = idx + 1;
                let max_backward_jump = observed.div_ceil(estimator.sample_cap()) + 1;
                prop_assert!(
                    split_idx + max_backward_jump >= previous,
                    "split moved backward too far after append: prev={}, current={}, observed={}, cap={}, allowed_backstep={}",
                    previous,
                    split_idx,
                    observed,
                    estimator.sample_cap(),
                    max_backward_jump
                );
            }

            previous_split = Some(split_idx);
        }
    }

    /// After byte-axis compaction on a front-loaded stream with a zero-byte
    /// tail, the rank fallback must still land near the true rank midpoint.
    ///
    /// Regression guard for the plateau-aware redistribution fix: without
    /// redistribution, retained samples cluster at the start of the
    /// byte-position plateau, making the rank-axis search return a sample
    /// far from the actual midpoint rank.
    #[test]
    fn prop_compaction_preserves_rank_diversity_in_zero_tail(
        n in 500..4_000usize,
        cap_mult in 1..4usize,
    ) {
        let sample_cap = SMALL_SAMPLE_CAP * cap_mult;
        let mut estimator = StreamingSplitEstimator::new(sample_cap);

        // One huge file followed by N zero-byte files.
        estimator.observe(&key_for_index(0), 100_000_000);
        for idx in 1..=n {
            estimator.observe(&key_for_index(idx), 0);
        }

        let total_count = n + 1; // including the huge file
        let split = estimator
            .estimate_split_key()
            .expect("should produce split with count >= 2");
        let split_idx = index_from_key(split);

        // The split must not be the first key (first-key guard).
        prop_assert!(split_idx >= 1, "split must not be index 0, got {}", split_idx);

        // The rank fallback should land within a bounded distance of the
        // true rank midpoint (total_count / 2).
        let midpoint = total_count / 2;
        let tolerance = 2 * total_count / estimator.sample_cap();
        let distance = split_idx.abs_diff(midpoint);
        prop_assert!(
            distance <= tolerance,
            "rank fallback too far from midpoint: split_idx={}, midpoint={}, distance={}, tolerance={}, n={}, cap={}",
            split_idx, midpoint, distance, tolerance, n, sample_cap
        );
    }

    /// The split key must never equal the first or last observed key when
    /// count >= 3, because that would produce a degenerate empty left or
    /// right shard.
    #[test]
    fn prop_split_key_never_first_or_last_when_three_or_more(
        count in 3..500usize,
        size_range in 1..10_000u64,
    ) {
        let mut estimator = StreamingSplitEstimator::new(MIN_SAMPLE_CAP);
        let first_key = key_for_index(0);
        let last_key = key_for_index(count - 1);
        for idx in 0..count {
            estimator.observe(&key_for_index(idx), size_range);
        }
        if let Some(split) = estimator.estimate_split_key() {
            prop_assert!(split != first_key.as_slice(),
                "split must not be the first key (count={})", count);
            prop_assert!(split != last_key.as_slice(),
                "split must not be the last key (count={})", count);
        }
    }

    /// Same bounds invariant with zero-size files, exercising the rank-fallback
    /// path where byte-axis is degenerate.
    #[test]
    fn prop_split_key_never_first_or_last_zero_sizes(count in 3..500usize) {
        let mut estimator = StreamingSplitEstimator::new(MIN_SAMPLE_CAP);
        let first_key = key_for_index(0);
        let last_key = key_for_index(count - 1);
        for idx in 0..count {
            estimator.observe(&key_for_index(idx), 0);
        }
        if let Some(split) = estimator.estimate_split_key() {
            prop_assert!(split != first_key.as_slice(),
                "split must not be the first key (count={})", count);
            prop_assert!(split != last_key.as_slice(),
                "split must not be the last key (count={})", count);
        }
    }

    /// The in-place swap compaction must produce the same retained samples as
    /// a naive "collect selected indices into a new vec" approach.
    #[test]
    fn prop_compact_samples_matches_naive_collect(
        len in 3usize..200,
        cap_frac in 0.1f64..0.99,
    ) {
        use super::{Sample, compact_samples, selected_sample_indices};

        let cap = ((len as f64 * cap_frac) as usize).max(1).min(len - 1);
        let samples: Vec<Sample> = (0..len)
            .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
            .collect();

        // Compare the in-place algorithm against the simplest obviously-correct
        // specification: select indices first, then collect them into a new vec.
        let keep = selected_sample_indices(&samples, cap);
        let expected: Vec<_> = keep
            .iter()
            .map(|&idx| {
                (
                    samples[idx].rank,
                    samples[idx].recorded_byte_position,
                    samples[idx].key.clone(),
                )
            })
            .collect();

        let mut actual_samples = samples;
        compact_samples(&mut actual_samples, cap);
        let actual: Vec<_> = actual_samples
            .iter()
            .map(|s| (s.rank, s.recorded_byte_position, s.key.clone()))
            .collect();

        prop_assert_eq!(actual, expected);
    }

    /// `selected_sample_indices` must return strictly increasing indices for
    /// any valid (count > cap) input, including streams with uniform, ascending,
    /// and plateau byte positions.
    #[test]
    fn prop_selected_indices_strictly_increasing(
        count in 2..500usize,
        cap_mult in 1..4usize,
    ) {
        use super::selected_sample_indices;

        let cap = (MIN_SAMPLE_CAP * cap_mult).min(count);
        // Only test cases where compaction is triggered; cap >= count means no
        // compaction fires and the invariant is trivially satisfied.
        prop_assume!(count > cap);

        let samples: Vec<Sample> = (0..count)
            .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
            .collect();
        let indices = selected_sample_indices(&samples, cap);
        prop_assert!(
            indices.windows(2).all(|w| w[0] < w[1]),
            "indices must be strictly increasing: {:?}", indices
        );
    }

}

// ---------------------------------------------------------------------------
// Plateau redistribution tests
// ---------------------------------------------------------------------------

/// Plateau in the middle of the stream: a narrow leading region, a large
/// plateau occupying most of the byte range, and a narrow trailing region.
/// Compaction must spread picks within the mid-stream plateau by rank.
#[test]
fn plateau_redistribution_spreads_picks_across_mid_stream_plateau() {
    use super::{Sample, compact_samples};

    // 200 samples: 10 with a narrow byte range (0..9), 180 sharing the same
    // recorded byte position (the plateau), 10 resuming above the plateau.
    // The plateau at byte 5000 dominates the byte axis, so most interpolated
    // targets resolve to it, clustering picks there before redistribution.
    let plateau_bytes = 5_000u64;
    let mut samples: Vec<Sample> = (0..200)
        .map(|i| {
            let bytes = if i < 10 {
                i as u64
            } else if i < 190 {
                plateau_bytes
            } else {
                plateau_bytes + (i - 190) as u64 + 1
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    compact_samples(&mut samples, 20);

    assert_eq!(samples.len(), 20);

    // Collect ranks of retained samples that were in the plateau region
    // (original ranks 10..190).
    let plateau_ranks: Vec<u64> = samples
        .iter()
        .filter(|s| s.rank >= 10 && s.rank < 190)
        .map(|s| s.rank)
        .collect();

    assert!(
        plateau_ranks.len() >= 2,
        "at least 2 samples should be retained from the plateau, got {:?}",
        plateau_ranks
    );

    // The retained plateau samples should span a good range of the original
    // plateau (not be bunched at the start).
    let rank_span = plateau_ranks.last().unwrap() - plateau_ranks.first().unwrap();
    assert!(
        rank_span >= 50,
        "retained plateau samples should span a wide rank range, got span {} from {:?}",
        rank_span,
        plateau_ranks
    );
}

/// Multiple disjoint byte-position plateaus: each should be redistributed
/// independently.
#[test]
fn plateau_redistribution_handles_multiple_disjoint_plateaus() {
    use super::{Sample, compact_samples};

    // 100 samples: 10 at bytes=0, 40 at bytes=500, 40 at bytes=1000,
    // 10 with increasing bytes above 1000.
    let mut samples: Vec<Sample> = (0..100)
        .map(|i| {
            let bytes = if i < 10 {
                0u64
            } else if i < 50 {
                500
            } else if i < 90 {
                1000
            } else {
                1000 + ((i - 90) as u64 + 1) * 100
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    compact_samples(&mut samples, 20);

    assert_eq!(samples.len(), 20);

    // Samples from the second plateau (rank 10..50) should not all bunch at
    // rank 10–12.
    let plateau2_ranks: Vec<u64> = samples
        .iter()
        .filter(|s| s.rank >= 10 && s.rank < 50)
        .map(|s| s.rank)
        .collect();

    assert!(
        plateau2_ranks.len() >= 2,
        "second plateau must retain >= 2 samples for spread check, got {:?}",
        plateau2_ranks
    );
    let span = plateau2_ranks.last().unwrap() - plateau2_ranks.first().unwrap();
    assert!(
        span >= 10,
        "second plateau retained samples should be spread, got span {} from {:?}",
        span,
        plateau2_ranks
    );

    // Similarly for the third plateau (rank 50..90).
    let plateau3_ranks: Vec<u64> = samples
        .iter()
        .filter(|s| s.rank >= 50 && s.rank < 90)
        .map(|s| s.rank)
        .collect();

    assert!(
        plateau3_ranks.len() >= 2,
        "third plateau must retain >= 2 samples for spread check, got {:?}",
        plateau3_ranks
    );
    let span = plateau3_ranks.last().unwrap() - plateau3_ranks.first().unwrap();
    assert!(
        span >= 10,
        "third plateau retained samples should be spread, got span {} from {:?}",
        span,
        plateau3_ranks
    );

    assert_eq!(samples.first().unwrap().rank, 0);
    assert_eq!(samples.last().unwrap().rank, 99);
    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
}

/// Minimal plateau case: exactly 2 consecutive samples with the same byte
/// position. Redistribution must handle this without panicking and preserve
/// strict ordering.
#[test]
fn plateau_of_two_samples_is_handled() {
    use super::{Sample, compact_samples};

    // 20 samples, with indices 9 and 10 sharing a byte-position plateau.
    let mut samples: Vec<Sample> = (0..20)
        .map(|i| {
            let bytes = if i == 9 || i == 10 {
                900u64
            } else {
                (i as u64) * 100
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    assert_eq!(samples.first().unwrap().rank, 0);
    assert_eq!(samples.last().unwrap().rank, 19);
    assert!(
        samples.windows(2).all(|w| w[0].rank < w[1].rank),
        "ranks must remain strictly increasing: {:?}",
        samples.iter().map(|s| s.rank).collect::<Vec<_>>()
    );
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].recorded_byte_position <= w[1].recorded_byte_position),
        "byte positions must remain non-decreasing"
    );
}

/// Plateau with a large rank gap at the end. When `nearest_by_rank_in_range`
/// snaps two consecutive picks to the highest-rank sample, the `floor`
/// enforcement pushes the second pick past `eff_end` without a ceiling
/// constraint.
///
/// Layout (7 samples, compact to 6):
///   index 0: rank=0,     bytes=0    (leading boundary)
///   index 1: rank=1,     bytes=1000 ┐
///   index 2: rank=2,     bytes=1000 │ plateau
///   index 3: rank=3,     bytes=1000 │
///   index 4: rank=4,     bytes=1000 │
///   index 5: rank=10000, bytes=1000 ┘ large rank gap
///   index 6: rank=10001, bytes=2000   (trailing boundary)
///
/// The main loop assigns 4 of its 6 picks to the plateau. During
/// redistribution, interpolated rank targets pull the last two picks
/// towards index 5 (rank 10000). After the first is placed at index 5,
/// `floor` for the next pick becomes 6, exceeding `eff_end`=5.
#[test]
fn plateau_with_rank_gap_preserves_strict_ordering() {
    use super::{Sample, compact_samples};

    let mut samples = vec![
        Sample::new(0, 0, &key_for_index(0)),
        Sample::new(1, 1000, &key_for_index(1)),
        Sample::new(2, 1000, &key_for_index(2)),
        Sample::new(3, 1000, &key_for_index(3)),
        Sample::new(4, 1000, &key_for_index(4)),
        Sample::new(10000, 1000, &key_for_index(5)),
        Sample::new(10001, 2000, &key_for_index(6)),
    ];

    compact_samples(&mut samples, 6);

    assert_eq!(samples.len(), 6);
    assert!(
        samples.windows(2).all(|w| w[0].rank < w[1].rank),
        "ranks must remain strictly increasing after plateau redistribution: {:?}",
        samples.iter().map(|s| s.rank).collect::<Vec<_>>()
    );
}

/// Regression: when a plateau's effective range is a tight fit (exactly
/// run_len indices) and ranks are non-uniformly distributed, the floor
/// cascade can push picks past eff_end without the ceiling constraint.
#[test]
fn plateau_redistribution_clamps_to_effective_range() {
    use super::{Sample, SampleAxis, redistribute_plateau_picks};

    // 6 samples: 1 non-plateau, 4 plateau (tight fit), 1 non-plateau.
    // The plateau has ranks 1,2,3,1000 — a big gap that causes
    // nearest_by_rank to cluster early picks near index 3, leaving
    // no room for j=3 which gets pushed past eff_end by the floor.
    let samples = vec![
        Sample::new(0, 0, &key_for_index(0)),   // index 0: non-plateau
        Sample::new(1, 500, &key_for_index(1)), // index 1: plateau
        Sample::new(2, 500, &key_for_index(2)), // index 2: plateau
        Sample::new(3, 500, &key_for_index(3)), // index 3: plateau
        Sample::new(1000, 500, &key_for_index(4)), // index 4: plateau (rank gap)
        Sample::new(2000, 1000, &key_for_index(5)), // index 5: non-plateau
    ];

    // picks[0]=0 (non-plateau), picks[1..5] on plateau, picks[5]=5 (non-plateau).
    // The plateau run is picks[1..5], run_len=4.
    // eff_start=1, eff_end=4 → tight fit (4-1+1=4 == run_len).
    let mut picks = vec![0, 1, 2, 3, 4, 5];

    redistribute_plateau_picks(&samples, &mut picks, SampleAxis::Bytes);

    assert!(
        picks.windows(2).all(|w| w[0] < w[1]),
        "picks must be strictly increasing after redistribution, got {:?}",
        picks
    );
    assert!(
        picks.iter().all(|&p| p < samples.len()),
        "all picks must be valid indices, got {:?}",
        picks
    );
}

/// When the plateau starts at index 0 (all leading samples share the same
/// byte position), the `lower` constraint calculation takes the `else { 0 }`
/// branch. Verify that compaction still spreads picks across the leading
/// plateau by rank and preserves monotonicity.
#[test]
fn plateau_redistribution_spreads_picks_across_leading_plateau() {
    use super::{Sample, compact_samples};

    // 30 samples: first 15 at recorded byte position = 0 (the plateau),
    // then 15 with increasing byte positions.
    let mut samples: Vec<Sample> = (0..30)
        .map(|i| {
            let bytes = if i < 15 { 0u64 } else { (i - 14) as u64 * 100 };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);

    assert_eq!(
        samples.first().unwrap().rank,
        0,
        "first sample must be preserved"
    );
    assert_eq!(
        samples.last().unwrap().rank,
        29,
        "last sample must be preserved"
    );

    assert!(
        samples.windows(2).all(|w| w[0].rank < w[1].rank),
        "ranks must remain strictly increasing: {:?}",
        samples.iter().map(|s| s.rank).collect::<Vec<_>>()
    );

    let plateau_ranks: Vec<u64> = samples
        .iter()
        .filter(|s| s.rank < 15)
        .map(|s| s.rank)
        .collect();

    if plateau_ranks.len() >= 2 {
        let span = plateau_ranks.last().unwrap() - plateau_ranks.first().unwrap();
        assert!(
            span >= 5,
            "leading plateau retained samples should be spread, got span {} from {:?}",
            span,
            plateau_ranks
        );
    }
}

/// Exercise the `picks.len() < 3` early-return guard in
/// `redistribute_plateau_picks`. With 0, 1, or 2 picks there cannot be a
/// non-endpoint plateau cluster, so the function must be a no-op.
#[test]
fn redistribute_plateau_picks_early_return_for_small_pick_arrays() {
    use super::{Sample, SampleAxis, redistribute_plateau_picks};

    let samples: Vec<Sample> = (0..10)
        .map(|i| Sample::new(i as u64, 500, &key_for_index(i)))
        .collect();

    let mut empty: Vec<usize> = vec![];
    redistribute_plateau_picks(&samples, &mut empty, SampleAxis::Bytes);
    assert!(empty.is_empty());

    let mut one = vec![5];
    redistribute_plateau_picks(&samples, &mut one, SampleAxis::Bytes);
    assert_eq!(one, vec![5]);

    let mut two = vec![0, 9];
    redistribute_plateau_picks(&samples, &mut two, SampleAxis::Bytes);
    assert_eq!(two, vec![0, 9]);
}

/// Trailing plateau: 30 samples where the first 15 have increasing byte
/// positions and the last 15 share the same byte position. Compaction must
/// spread picks within the trailing plateau by rank, not bunch them at the
/// plateau's leading edge.
#[test]
fn plateau_redistribution_spreads_picks_across_trailing_plateau() {
    use super::{Sample, compact_samples};

    let shared_bytes = 1500u64;
    let mut samples: Vec<Sample> = (0..30)
        .map(|i| {
            let bytes = if i < 15 {
                (i as u64) * 100
            } else {
                shared_bytes
            };
            Sample::new(i as u64, bytes, &key_for_index(i))
        })
        .collect();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);

    assert_eq!(
        samples.first().unwrap().rank,
        0,
        "first sample must be preserved"
    );
    assert_eq!(
        samples.last().unwrap().rank,
        29,
        "last sample must be preserved"
    );

    assert!(
        samples.windows(2).all(|w| w[0].rank < w[1].rank),
        "ranks must remain strictly increasing: {:?}",
        samples.iter().map(|s| s.rank).collect::<Vec<_>>()
    );

    let trailing_ranks: Vec<u64> = samples
        .iter()
        .filter(|s| s.rank >= 15)
        .map(|s| s.rank)
        .collect();

    if trailing_ranks.len() >= 2 {
        let span = trailing_ranks.last().unwrap() - trailing_ranks.first().unwrap();
        assert!(
            span >= 5,
            "trailing plateau retained samples should be spread, got span {} from {:?}",
            span,
            trailing_ranks
        );
    }
}
