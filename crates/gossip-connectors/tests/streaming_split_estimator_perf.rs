#![cfg(unix)]

//! Allocation regression guard for the streaming split estimator's `observe`
//! path.
//!
//! This integration test installs a process-wide [`CountingAllocator`] and
//! drives the estimator through the same doc-hidden benchmark hook that the
//! Criterion bench uses. The goal is not to pin an absolute runtime; it is to
//! catch shape regressions where a 1,000,000-item stream starts allocating
//! linearly instead of following the expected sublinear compaction pattern.

use gossip_connectors::benchmark_streaming_split_estimator_observe_fixed_size;
use scanner_scheduler::{CountingAllocator, alloc_stats};

#[global_allocator]
static GLOBAL_ALLOC: CountingAllocator = CountingAllocator;

/// Conservative heap-traffic bound for the fixed-size streaming workload.
///
/// The estimator doubles its sampling strides after each compaction, so the
/// number of refill/compact phases grows roughly with `log2(count)`. This
/// helper intentionally leaves slack for startup and final estimation; the test
/// is a regression tripwire, not a proof of the exact constant factor.
fn observe_allocation_upper_bound(sample_cap: usize, count: usize) -> u64 {
    let phases = u64::from(count.max(1).ilog2()) + 4;
    (sample_cap as u64) * phases
}

#[test]
fn observe_one_million_items_allocates_sublinearly() {
    let sample_cap = 128usize;
    let count = 1_000_000usize;

    let start = alloc_stats();
    let split = benchmark_streaming_split_estimator_observe_fixed_size(sample_cap, count, 1);
    let delta = alloc_stats().since(&start);

    assert!(
        split.is_some(),
        "million-item stream should still produce a split"
    );

    // Count only allocation-producing events. Deallocation churn can vary with
    // compaction timing, but regressions in the hot `observe` path show up as
    // extra alloc/realloc pressure.
    let heap_ops = delta.allocs + delta.reallocs;
    let upper_bound = observe_allocation_upper_bound(sample_cap, count);
    assert!(
        heap_ops <= upper_bound,
        "observe() should stay sublinear in allocator traffic at 1M items: heap_ops={} bound={} delta={:?}",
        heap_ops,
        upper_bound,
        delta
    );
}
