//! Tests for [`StreamingSplitEstimator`].
//!
//! Unit tests cover specific edge cases (minimum entries, front-loaded weight,
//! zipf accuracy). Property tests verify general invariants (memory
//! boundedness, zero-size midpoint fallback, sample ordering) over randomised
//! inputs.

use proptest::prelude::*;

use super::{Sample, StreamingSplitEstimator, MIN_SAMPLE_CAP};

const SMALL_SAMPLE_CAP: usize = MIN_SAMPLE_CAP;
const MEDIUM_SAMPLE_CAP: usize = 512;
const LARGE_SAMPLE_CAP: usize = StreamingSplitEstimator::DEFAULT_SAMPLE_CAP;

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

#[test]
fn skewed_sizes_split_selects_straddling_file() {
    let mut estimator = StreamingSplitEstimator::new(LARGE_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 5);
    estimator.observe(&key_for_index(1), 5);
    estimator.observe(&key_for_index(2), 100);

    let split = estimator
        .estimate_split_key()
        .expect("should produce split");
    let split_idx = index_from_key(split);
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
    let mut estimator = StreamingSplitEstimator::new(SMALL_SAMPLE_CAP);
    estimator.observe(&key_for_index(0), 1);
    assert_eq!(
        estimator.sample_len(),
        1,
        "a single observation that satisfies both sampling rules should retain only one sample"
    );
}

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

// ---------------------------------------------------------------------------
// Extreme value tests
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

#[test]
fn compact_samples_preserves_endpoints_and_monotonicity() {
    use super::{compact_samples, Sample};

    let mut samples: Vec<Sample> = (0..20)
        .map(|i| Sample::new(i as u64, (i as u64) * 100, &key_for_index(i)))
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
    assert!(samples
        .windows(2)
        .all(|w| w[0].cumulative_bytes <= w[1].cumulative_bytes));
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
    let split_idx = index_from_key(split);
    assert!(split_idx >= 1, "first-key guard must hold, got {split_idx}");
}

#[test]
fn cumulative_bytes_saturation() {
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

}
