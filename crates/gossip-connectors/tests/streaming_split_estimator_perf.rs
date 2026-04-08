#![cfg(unix)]

//! Allocation regression guard for the streaming split estimator's `observe`
//! path.
//!
//! This integration test installs a process-wide [`CountingAllocator`] and
//! drives the estimator through the same doc-hidden benchmark hook that the
//! Criterion bench uses.
//!
//! # Purpose
//! Catch shape regressions where a 1,000,000-item stream starts allocating
//! linearly instead of following the expected sublinear compaction pattern.
//! The goal is not to pin an absolute runtime.
//!
//! # Invariants
//! - The workload must produce a split at the 1,000,000-item scale.
//! - Heap traffic must grow with the estimator's logarithmic compaction
//!   phases rather than with the full stream length.
//!
//! # Design Trade-offs
//! - Uses a process-wide allocator guard which restricts this test to isolated
//!   execution or single-threaded test runners.
//! - The assertion focuses purely on allocation-producing events (alloc, realloc)
//!   because deallocation churn can vary with compaction timing without indicating a
//!   regression in the hot `observe` path.

use gossip_connectors::benchmark_streaming_split_estimator_observe_fixed_size;
use scanner_scheduler::{CountingAllocator, alloc_stats};

#[global_allocator]
/// Process-wide allocator instrumentation for this integration test.
///
/// Integration tests run in a separate process, so this override does not affect
/// allocators in other test binaries.
static GLOBAL_ALLOC: CountingAllocator = CountingAllocator;

/// Calculates a conservative heap-traffic bound for the fixed-size streaming workload.
///
/// # What it does
/// Determines the maximum allowed heap allocation operations for a stream of a given length.
/// The `+ 4` phase slack intentionally absorbs setup and teardown effects so the
/// bound remains resilient to minor implementation details.
///
/// # Complexity
/// The estimator doubles its sampling strides after each compaction, so the
/// number of refill/compact phases grows strictly in `O(log(count))` time.
///
/// # Preconditions
/// - `sample_cap` must reflect the estimator's configured maximum sample capacity.
/// - `count` is the total number of items observed.
///
/// # Guarantees
/// Leaves intentional slack for startup and final estimation to act as a regression
/// tripwire rather than attempting a brittle exact-factor proof.
fn observe_allocation_upper_bound(sample_cap: usize, count: usize) -> u64 {
    let phases = u64::from(count.max(1).ilog2()) + 4;
    (sample_cap as u64) * phases
}

/// Verifies that the fixed-size streaming workload keeps allocator traffic
/// sublinear while still producing a split for one million observations.
///
/// # What it does
/// Drives the estimator with 1,000,000 items and asserts that heap allocation operations
/// fall within the conservative upper bound.
///
/// # Guarantees
/// - Asserts that a valid split is generated for the 1M-item stream.
/// - Asserts that the sum of `allocs` and `reallocs` remains bounded sublinearly.
///
/// # Test Isolation
/// Because this file installs a process-wide allocator, this assertion should
/// run without concurrently mutating allocator-heavy workloads in the same test
/// process.
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

    // Focus on alloc/realloc because deallocation churn varies independently of hot-path performance.
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
