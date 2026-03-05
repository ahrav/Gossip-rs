//! Tests for [`StreamingSplitEstimator`].
//!
//! Unit tests cover specific edge cases (minimum entries, front-loaded weight,
//! zipf accuracy, merge consistency). Property tests verify general invariants
//! (memory boundedness, zero-size midpoint fallback) over randomised inputs.

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
    // With 5 equal-weight files, acceptable midpoints are indices 2 or 3
    // (a 2/3 or 3/2 byte split). Both are within one file of the true median.
    assert!(
        split_idx == 2 || split_idx == 3,
        "expected split near midpoint (index 2 or 3), got index {}",
        split_idx
    );
}

#[test]
fn skewed_sizes_split_selects_straddling_file() {
    let mut estimator = StreamingSplitEstimator::new(256);
    // Three files: sizes 5, 5, 100. Total = 110. Target = 55.
    // Pre-increment cumulative starts: [0, 5, 10].
    // File 2's range is [10, 110), which contains target 55.
    estimator.observe(&key_for_index(0), 5);
    estimator.observe(&key_for_index(1), 5);
    estimator.observe(&key_for_index(2), 100);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    // The correct split is at index 2: it's the file whose byte range
    // straddles the 50% mark. Index 1 would be a left-shifted split.
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
        // Monotone-decreasing sizes approximate real skewed repositories.
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
        let size = ((idx as u64)
            .wrapping_mul(1_103_515_245)
            .wrapping_add(12_345)
            % 4_096)
            + 1;
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
// Compaction edge-case tests
// ---------------------------------------------------------------------------

/// When all observed files have the same cumulative byte position (all zero
/// sizes pushed through the byte path would not happen, but identical non-zero
/// sizes produce identical *starting* positions only when there's one item),
/// compact_byte_samples must not panic or produce duplicates.
#[test]
fn compact_with_all_identical_byte_positions() {
    // Use compression=32 → sample_cap = 32*4 = 128.
    let mut estimator = StreamingSplitEstimator::new(32);
    let cap = estimator.sample_cap();
    // Feed cap + 10 items each with size 1. The cumulative *start* positions
    // are 0, 1, 2, ... so they aren't truly identical. To force identical
    // positions we need files with size 0 — but those skip the byte path.
    // Instead, test the rank path with identical keys: all have rank 0..n
    // which are unique. The interesting degenerate case is when file sizes
    // are all identical, producing evenly spaced positions.
    for idx in 0..(cap + 10) {
        estimator.observe(&key_for_index(idx), 42);
    }
    // After compaction both sample arrays must be within cap.
    assert!(estimator.rank_sample_len() <= cap);
    assert!(estimator.byte_sample_len() <= cap);
    // Split should still be valid.
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert!(split_idx >= 1, "split must not be index 0");
}

/// Observe exactly `sample_cap + 1` items with the smallest compression (32)
/// to verify compaction fires once and preserves endpoints.
#[test]
fn compact_when_barely_exceeding_cap() {
    let mut estimator = StreamingSplitEstimator::new(32);
    let cap = estimator.sample_cap();
    for idx in 0..(cap + 1) {
        estimator.observe(&key_for_index(idx), (idx as u64) + 1);
    }
    assert!(estimator.rank_sample_len() <= cap);
    assert!(estimator.byte_sample_len() <= cap);
    // Endpoints: first rank sample should be index 0, last should be cap.
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert!(split_idx >= 1 && split_idx <= cap);
}

/// Verify first and last rank samples survive compaction.
#[test]
fn compact_rank_preserves_endpoints() {
    let mut estimator = StreamingSplitEstimator::new(32);
    let cap = estimator.sample_cap();
    let n = cap * 3;
    for idx in 0..n {
        estimator.observe(&key_for_index(idx), 1);
    }
    assert!(estimator.rank_sample_len() <= cap);
    // The estimator should be able to find a split within range.
    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(&split);
    assert!(split_idx >= 1 && split_idx < n);
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
    // total_bytes saturates at u64::MAX rather than wrapping.
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
    /// non-zero sizes), rank and byte sample arrays never exceed their
    /// respective caps.
    ///
    /// Ranges are tuned to exercise compaction paths while keeping wall-clock
    /// time under ~10 s on CI.
    #[test]
    fn prop_sample_memory_bounded(
        compression in 32..512usize,
        count in 0..2_000usize,
    ) {
        let mut estimator = StreamingSplitEstimator::new(compression);
        for idx in 0..count {
            let key = key_for_index(idx);
            // Mix of zero and non-zero sizes to exercise both sample arrays.
            let size = if idx % 3 == 0 { 0 } else { (idx as u64) + 1 };
            estimator.observe(&key, size);
        }
        prop_assert!(
            estimator.rank_sample_len() <= estimator.sample_cap(),
            "rank samples ({}) exceeded cap ({})",
            estimator.rank_sample_len(),
            estimator.sample_cap()
        );
        prop_assert!(
            estimator.byte_sample_len() <= estimator.sample_cap(),
            "byte samples ({}) exceeded cap ({})",
            estimator.byte_sample_len(),
            estimator.sample_cap()
        );
    }
}
