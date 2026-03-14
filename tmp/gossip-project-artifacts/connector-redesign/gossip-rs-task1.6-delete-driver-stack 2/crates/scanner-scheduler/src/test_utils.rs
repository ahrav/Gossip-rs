//! Shared test helpers required by extracted property-test modules.

/// Return the proptest case count, respecting `PROPTEST_CASES` env var.
///
/// Delegates to [`gossip_stdx::test_support::proptest_cases`] — the
/// workspace-wide canonical implementation.
#[inline]
pub fn proptest_cases(default: u32) -> u32 {
    gossip_stdx::test_support::proptest_cases(default)
}
