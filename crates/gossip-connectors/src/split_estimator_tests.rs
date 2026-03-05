//! Tests for [`StreamingSplitEstimator`].
//!
//! Unit tests cover specific edge cases (minimum entries, front-loaded weight,
//! zipf accuracy, merge consistency). Property tests verify general invariants
//! (memory boundedness, zero-size midpoint fallback, sample ordering) over
//! randomised inputs.

use proptest::prelude::*;

use super::StreamingSplitEstimator;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn key_for_index(idx: usize) -> [u8; 8] {
    (idx as u64).to_be_bytes()
}

fn index_from_key(key: &[u8]) -> usize {
    let bytes: [u8; 8] = key.try_into().expect("keys must be fixed-width u64 bytes");
    usize::try_from(u64::from_be_bytes(bytes)).expect("index conversion")
}

fn cumulative_at(sizes: &[u64], idx: usize) -> u64 {
    sizes[..=idx]
        .iter()
        .copied()
        .fold(0u64, u64::saturating_add)
}

fn relative_weight_error(sizes: &[u64], idx: usize) -> f64 {
    let total = sizes.iter().copied().fold(0u64, u64::saturating_add);
    if total == 0 {
        return 0.0;
    }
    let observed = cumulative_at(sizes, idx) as f64;
    let half = total as f64 / 2.0;
    (observed - half).abs() / total as f64
}

fn deterministic_size(idx: usize) -> u64 {
    ((idx as u64)
        .wrapping_mul(1_103_515_245)
        .wrapping_add(12_345)
        % 4_096)
        + 1
}

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
    let mut estimator = StreamingSplitEstimator::new(256);
    for idx in 0..5u64 {
        estimator.observe(&key_for_index(idx as usize), 1);
    }
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert!(
        split_idx == 2 || split_idx == 3,
        "expected split near midpoint (index 2 or 3), got index {}",
        split_idx
    );
}

#[test]
fn skewed_sizes_split_selects_straddling_file() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), 5);
    estimator.observe(&key_for_index(1), 5);
    estimator.observe(&key_for_index(2), 100);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert_eq!(
        split_idx, 2,
        "expected split at index 2 (file straddling the median), got index {}",
        split_idx
    );
}

#[test]
fn estimate_requires_at_least_two_entries() {
    let mut estimator = StreamingSplitEstimator::default();
    assert!(estimator.estimate_split_key().is_none());

    let key0 = key_for_index(0);
    estimator.observe(&key0, 10);
    assert!(estimator.estimate_split_key().is_none());
}

#[test]
fn observe_does_not_duplicate_samples_when_rank_and_byte_triggers_overlap() {
    let mut estimator = StreamingSplitEstimator::new(32);
    estimator.observe(&key_for_index(0), 1);
    assert_eq!(
        estimator.sample_len(),
        1,
        "a single observation that satisfies both sampling rules should retain only one sample"
    );
}

#[test]
fn estimator_avoids_first_item_on_heavy_lead_weight() {
    let mut estimator = StreamingSplitEstimator::new(128);
    estimator.observe(&key_for_index(0), 10_000_000);
    for idx in 1..64 {
        estimator.observe(&key_for_index(idx), 1);
    }
    let split = estimator.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(&split);
    assert!(
        split_idx >= 1,
        "split must leave at least one key on the left"
    );
    assert!(
        split_idx < 64,
        "split index should stay within observed range"
    );
}

#[test]
fn zipf_like_stream_is_within_one_percent_weight_error() {
    let count = 20_000usize;
    let mut estimator = StreamingSplitEstimator::new(256);
    let mut sizes = Vec::with_capacity(count);
    for idx in 0..count {
        let size = (count - idx) as u64;
        sizes.push(size);
        let key = key_for_index(idx);
        estimator.observe(&key, size);
    }

    let split = estimator.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(&split);
    let error = relative_weight_error(&sizes, split_idx);
    assert!(
        error <= 0.01,
        "expected <=1% weighted error, got {:.4} at index {}",
        error,
        split_idx
    );
}

#[test]
fn merge_matches_single_pass_for_append_order_streams() {
    let count = 8_000usize;
    let mut full = StreamingSplitEstimator::new(128);
    let mut left = StreamingSplitEstimator::new(128);
    let mut right = StreamingSplitEstimator::new(128);

    for idx in 0..count {
        let size = deterministic_size(idx);
        let key = key_for_index(idx);
        full.observe(&key, size);
        if idx < count / 2 {
            left.observe(&key, size);
        } else {
            right.observe(&key, size);
        }
    }

    let full_idx = index_from_key(&full.estimate_split_key().expect("full split"));
    left.merge(&right);
    assert_samples_sorted(&left);
    let merged_idx = index_from_key(&left.estimate_split_key().expect("merged split"));
    let delta = full_idx.abs_diff(merged_idx);
    assert!(
        delta <= (count / 100) + 2,
        "merge drift too large: full={}, merged={}, delta={}",
        full_idx,
        merged_idx,
        delta
    );
}

#[test]
fn merge_then_continue_observing_matches_single_pass() {
    let count = 12_000usize;
    let split_one = 4_000usize;
    let split_two = 8_000usize;
    let mut full = StreamingSplitEstimator::new(128);
    let mut prefix = StreamingSplitEstimator::new(128);
    let mut middle = StreamingSplitEstimator::new(128);

    for idx in 0..count {
        let size = deterministic_size(idx);
        let key = key_for_index(idx);
        full.observe(&key, size);
        if idx < split_one {
            prefix.observe(&key, size);
        } else if idx < split_two {
            middle.observe(&key, size);
        }
    }

    prefix.merge(&middle);
    assert_samples_sorted(&prefix);
    for idx in split_two..count {
        let size = deterministic_size(idx);
        let key = key_for_index(idx);
        prefix.observe(&key, size);
    }

    let full_idx = index_from_key(&full.estimate_split_key().expect("full split"));
    let continued_idx = index_from_key(&prefix.estimate_split_key().expect("continued split"));
    let delta = full_idx.abs_diff(continued_idx);
    assert!(
        delta <= (count / 100) + 2,
        "merge+continue drift too large: full={}, continued={}, delta={}",
        full_idx,
        continued_idx,
        delta
    );
}

/// With exactly two items the only valid split is at index 1 (the second key).
/// Splitting at index 0 would leave zero items on the left side.
#[test]
fn two_items_split_at_second_key() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), 100);
    estimator.observe(&key_for_index(1), 1);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert_eq!(
        split_idx, 1,
        "with two items, split must be at index 1, got {}",
        split_idx
    );
}

/// Two zero-sized items also split at index 1 (rank midpoint for count=2).
#[test]
fn two_zero_size_items_split_at_second_key() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), 0);
    estimator.observe(&key_for_index(1), 0);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert_eq!(
        split_idx, 1,
        "with two zero-size items, split must be at index 1, got {}",
        split_idx
    );
}

// ---------------------------------------------------------------------------
// Downsampling regressions
// ---------------------------------------------------------------------------

/// After repeated downsampling, the estimator must still avoid returning the
/// very first observed key when weight is front-loaded.
#[test]
fn front_loaded_split_avoids_first_key_after_downsampling() {
    let mut estimator = StreamingSplitEstimator::new(32);
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
    let split_idx = index_from_key(&split);
    assert!(
        split_idx >= 1,
        "split must not return index 0 (the first observed key) after downsampling, got {}",
        split_idx
    );
}

#[test]
fn sample_count_stays_bounded_after_repeated_downsampling() {
    let mut estimator = StreamingSplitEstimator::new(32);
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
    let mut estimator = StreamingSplitEstimator::new(32);
    let cap = estimator.sample_cap();
    for idx in 0..(cap + 1) {
        estimator.observe(&key_for_index(idx), (idx as u64) + 1);
    }

    assert!(estimator.sample_len() <= cap);
    assert_samples_sorted(&estimator);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert!(split_idx >= 1 && split_idx <= cap);
}

// ---------------------------------------------------------------------------
// Merge edge-case tests
// ---------------------------------------------------------------------------

/// Merging an empty estimator into a populated one is a no-op.
#[test]
fn merge_empty_into_populated() {
    let mut estimator = StreamingSplitEstimator::new(128);
    for idx in 0..100 {
        estimator.observe(&key_for_index(idx), (idx as u64) + 1);
    }
    let before = estimator.estimate_split_key().expect("split before merge");

    let empty = StreamingSplitEstimator::new(128);
    estimator.merge(&empty);

    let after = estimator.estimate_split_key().expect("split after merge");
    assert_eq!(before, after, "merge of empty estimator should be a no-op");
}

/// Merging two estimators where all files have zero size produces a valid
/// rank-based split.
#[test]
fn merge_with_all_zero_sizes() {
    let mut left = StreamingSplitEstimator::new(128);
    let mut right = StreamingSplitEstimator::new(128);
    for idx in 0..50 {
        left.observe(&key_for_index(idx), 0);
    }
    for idx in 50..100 {
        right.observe(&key_for_index(idx), 0);
    }
    left.merge(&right);
    let split = left.estimate_split_key().expect("merged split");
    let split_idx = index_from_key(&split);
    assert_eq!(
        split_idx, 50,
        "100 zero-size items should split at midpoint 50, got {}",
        split_idx
    );
}

// ---------------------------------------------------------------------------
// Merge byte-axis monotonicity tests
// ---------------------------------------------------------------------------

/// After merge, sample byte positions must remain non-decreasing. This test
/// constructs a scenario where `self.total_bytes % other.byte_stride != 0`
/// so that the phase-aligned offset differs from the plain byte offset,
/// which would cause inversions if byte-triggered and rank-triggered
/// samples received different translation bases.
#[test]
fn merge_preserves_byte_monotonicity_with_unaligned_offset() {
    // Use small compression so compaction fires early and strides grow.
    let mut left = StreamingSplitEstimator::new(32);
    let mut right = StreamingSplitEstimator::new(32);

    // Feed left enough items to accumulate a total_bytes that is unlikely
    // to be a multiple of right's byte_stride after compaction.
    // Use varied sizes so total_bytes is odd/unaligned.
    for idx in 0..200 {
        left.observe(&key_for_index(idx), deterministic_size(idx));
    }

    // Feed right enough items to trigger at least one compaction cycle,
    // which doubles byte_stride to >= 2. Use sizes that create interleaved
    // byte-triggered and rank-triggered samples.
    let right_cap = right.sample_cap();
    let right_count = right_cap * 3; // well past compaction threshold
    for idx in 0..right_count {
        let size = deterministic_size(200 + idx);
        right.observe(&key_for_index(200 + idx), size);
    }

    // The merge should produce a sample array with non-decreasing byte positions.
    left.merge(&right);
    assert_samples_sorted(&left);
}

/// Construct a scenario where `other` has a byte-triggered sample followed
/// by a rank-triggered sample whose byte delta is less than the stride, and
/// `self.total_bytes` creates a phase gap large enough to invert their
/// translated byte positions (if the merge used different offset bases).
///
/// This validates that the uniform-offset translation in `merge` preserves
/// the monotonicity invariant.
#[test]
fn merge_byte_monotonicity_with_close_mixed_triggers() {
    let mut right = StreamingSplitEstimator::new(32);
    let right_cap = right.sample_cap(); // 128

    // Push right through multiple compaction cycles to grow strides.
    // Use uniform small sizes so byte_stride grows predictably.
    let items_per_cycle = right_cap / 2;
    let target_cycles = 6;
    let total_items = items_per_cycle * target_cycles + right_cap;

    for idx in 0..total_items {
        right.observe(&key_for_index(10_000 + idx), 50);
    }

    let stride = right.byte_stride();

    // Add items with varying sizes to create interleaved byte-triggered
    // and rank-triggered samples naturally.
    for idx in 0..200 {
        let base = 10_000 + total_items + idx;
        let size = if idx % (stride as usize / 10).max(3) == 0 {
            stride * 2
        } else {
            1
        };
        right.observe(&key_for_index(base), size);
    }

    let right_stride = right.byte_stride();

    // Merge with left having total_bytes = 1 (maximally misaligned:
    // phase_gap = stride - 1, which is the largest possible gap).
    let mut left = StreamingSplitEstimator::new(32);
    left.observe(&key_for_index(0), 1);

    left.merge(&right);
    assert_samples_sorted(&left);

    // Verify the merged estimator still produces a valid split.
    if left.estimate_split_key().is_some() {
        let right_samples = right.sample_full_debug_view();
        let has_both_types =
            right_samples.iter().any(|s| s.2) && right_samples.iter().any(|s| !s.2);
        // This test is only meaningful if right had mixed trigger types.
        // If not, the test passes vacuously but is still correct.
        assert!(
            has_both_types || right_stride <= 1,
            "expected mixed trigger types with stride > 1"
        );
    }
}

/// Same scenario as above but with the existing merge test data — this adds
/// the missing `assert_samples_sorted` call to the append-order test.
#[test]
fn merge_append_order_preserves_byte_monotonicity() {
    let count = 8_000usize;
    let mut left = StreamingSplitEstimator::new(128);
    let mut right = StreamingSplitEstimator::new(128);

    for idx in 0..count {
        let size = deterministic_size(idx);
        let key = key_for_index(idx);
        if idx < count / 2 {
            left.observe(&key, size);
        } else {
            right.observe(&key, size);
        }
    }

    left.merge(&right);
    assert_samples_sorted(&left);
}

/// When both sides are at capacity, merge triggers compaction and the result
/// stays within bounds with sorted samples.
#[test]
fn merge_both_at_capacity_triggers_compaction() {
    let mut left = StreamingSplitEstimator::new(32);
    let mut right = StreamingSplitEstimator::new(32);
    let cap = left.sample_cap(); // 128

    // Feed cap entries to each side to fill them to capacity.
    for idx in 0..cap {
        left.observe(&key_for_index(idx), deterministic_size(idx));
    }
    for idx in cap..(cap * 2) {
        right.observe(&key_for_index(idx), deterministic_size(idx));
    }

    left.merge(&right);

    assert!(
        left.sample_len() <= left.sample_cap(),
        "merged samples ({}) exceeded cap ({})",
        left.sample_len(),
        left.sample_cap()
    );
    assert_samples_sorted(&left);

    let split = left.estimate_split_key().expect("split expected");
    let split_idx = index_from_key(&split);
    assert!(
        split_idx >= 1 && split_idx < cap * 2,
        "split index {split_idx} out of range"
    );
}

// ---------------------------------------------------------------------------
// First-key guard fallback tests
// ---------------------------------------------------------------------------

/// After merge + heavy compaction, the first-key guard still works.
#[test]
fn first_key_guard_survives_merge_and_compaction() {
    let mut left = StreamingSplitEstimator::new(32);
    let mut right = StreamingSplitEstimator::new(32);

    // Left has one huge file.
    left.observe(&key_for_index(0), 1_000_000_000);
    for idx in 1..100 {
        left.observe(&key_for_index(idx), 1);
    }

    // Right has many small files.
    for idx in 100..2000 {
        right.observe(&key_for_index(idx), 1);
    }

    left.merge(&right);
    let split = left.estimate_split_key().expect("split key expected");
    let split_idx = index_from_key(&split);
    assert!(
        split_idx >= 1,
        "first-key guard must survive merge, got index {}",
        split_idx
    );
}

// ---------------------------------------------------------------------------
// Extreme value tests
// ---------------------------------------------------------------------------

/// Very large file sizes (near u64::MAX / 2) should not overflow or panic.
#[test]
fn extreme_file_sizes_no_overflow() {
    let mut estimator = StreamingSplitEstimator::new(256);
    let huge = u64::MAX / 2;
    estimator.observe(&key_for_index(0), huge);
    estimator.observe(&key_for_index(1), huge);
    estimator.observe(&key_for_index(2), 1);
    let split = estimator
        .estimate_split_key()
        .expect("should produce split with extreme sizes");
    let split_idx = index_from_key(&split);
    assert!(
        (1..=2).contains(&split_idx),
        "split index should be 1 or 2, got {}",
        split_idx
    );
}

#[test]
fn byte_positions_above_f64_precision_boundary_remain_distinguishable() {
    let mut estimator = StreamingSplitEstimator::new(256);
    let boundary = 1u64 << 53;

    estimator.observe(&key_for_index(0), boundary);
    estimator.observe(&key_for_index(1), 1);
    estimator.observe(&key_for_index(2), 1);
    estimator.observe(&key_for_index(3), boundary);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    assert_eq!(
        index_from_key(&split),
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

#[test]
fn compact_samples_preserves_endpoints_and_monotonicity() {
    use super::{Sample, compact_samples};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, false, &key_for_index(i)))
        .collect();

    let original_first_key = samples.first().unwrap().key.clone();
    let original_last_key = samples.last().unwrap().key.clone();

    compact_samples(&mut samples, 10);

    assert_eq!(samples.len(), 10);
    assert_eq!(samples.first().unwrap().key, original_first_key);
    assert_eq!(samples.last().unwrap().key, original_last_key);

    // Ranks strictly increasing.
    assert!(samples.windows(2).all(|w| w[0].rank < w[1].rank));
    // Bytes non-decreasing.
    assert!(
        samples
            .windows(2)
            .all(|w| w[0].cumulative_bytes <= w[1].cumulative_bytes)
    );
}

// ---------------------------------------------------------------------------
// Saturation edge-case tests
// ---------------------------------------------------------------------------

#[test]
fn observe_with_max_file_size() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), u64::MAX);
    estimator.observe(&key_for_index(1), 1);
    estimator.observe(&key_for_index(2), 1);

    let split = estimator.estimate_split_key().expect("split expected");
    let split_idx = index_from_key(&split);
    assert!(split_idx >= 1, "first-key guard must hold, got {split_idx}");
}

#[test]
fn cumulative_bytes_saturation() {
    let mut estimator = StreamingSplitEstimator::new(256);
    estimator.observe(&key_for_index(0), u64::MAX - 10);
    estimator.observe(&key_for_index(1), 20); // saturates to MAX
    estimator.observe(&key_for_index(2), 100); // already at MAX

    let split = estimator.estimate_split_key().expect("split expected");
    let split_idx = index_from_key(&split);
    assert!(
        split_idx >= 1,
        "valid split required, got index {split_idx}"
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
            index_from_key(&key),
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
            observed_keys.iter().any(|k| k.as_slice() == split.as_slice()),
            "split key {:?} was not among the {} observed keys",
            split,
            count
        );
    }

    /// For any compression setting and stream length (with mixed zero and
    /// non-zero sizes), the unified sample set remains bounded and sorted.
    ///
    /// Ranges are tuned to exercise downsampling paths while keeping wall-clock
    /// time under CI-friendly bounds.
    #[test]
    fn prop_sample_memory_bounded(
        compression in 32..512usize,
        count in 0..2_000usize,
    ) {
        let mut estimator = StreamingSplitEstimator::new(compression);
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
}
