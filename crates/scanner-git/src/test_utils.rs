//! Test helpers — delegates to [`gossip_stdx::test_support`].

pub use gossip_stdx::test_support::{
    for_each_permutation, proptest_cases, proptest_fuzz_multiplier, try_for_each_permutation,
};

/// Assert a `u64` perf counter in both perf-enabled and normal test builds.
///
/// Perf counters are only populated when the crate is built with both
/// `perf-stats` and `debug_assertions`. In ordinary test builds, the same
/// counters must stay at zero so metric assertions do not accidentally depend
/// on disabled instrumentation.
#[track_caller]
pub fn assert_perf_u64(actual: u64, expected: u64) {
    if cfg!(all(feature = "perf-stats", debug_assertions)) {
        assert_eq!(actual, expected);
    } else {
        assert_eq!(actual, 0);
    }
}
