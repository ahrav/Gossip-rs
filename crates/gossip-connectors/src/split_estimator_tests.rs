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

    /// For any compression setting and stream length (with mixed zero and
    /// non-zero sizes), rank and byte sample arrays never exceed their
    /// respective caps, and the pending centroid buffer stays within its
    /// flush limit.
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
        prop_assert!(
            estimator.pending_len() <= estimator.pending_cap(),
            "pending centroids ({}) exceeded flush limit ({})",
            estimator.pending_len(),
            estimator.pending_cap()
        );
    }
}
