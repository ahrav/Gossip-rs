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
