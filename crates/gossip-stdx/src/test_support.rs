//! Shared test helpers for proptest configuration.
//!
//! Available under the `stdx-proptest` feature (for downstream crates) and
//! under `#[cfg(test)]` (for internal gossip-stdx tests). Provides helpers
//! that configure proptest case counts consistently across the workspace.

/// Read an environment variable as a `u32`.
fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

/// Returns `true` when running under CI (the `CI` env var is set).
fn is_ci() -> bool {
    std::env::var_os("CI").is_some()
}

/// Return the proptest case count, respecting the `PROPTEST_CASES` env var.
///
/// Precedence:
/// 1. Explicit `PROPTEST_CASES` env override (always honoured, clamped to >= 1).
/// 2. CI environment — uses the caller-supplied `default` (clamped to >= 1).
/// 3. Local development — clamps to `min(default, 4)` so `cargo test` stays
///    snappy during edit-compile-test cycles.
///
/// # Examples
///
/// ```text
/// In local dev (no CI, no env override) with default=64 → returns 4
/// In CI with default=64 → returns 64
/// With PROPTEST_CASES=256 → returns 256
/// ```
#[inline]
pub fn proptest_cases(default: u32) -> u32 {
    if let Some(value) = env_u32("PROPTEST_CASES") {
        return value.max(1);
    }
    if is_ci() {
        return default.max(1);
    }
    default.clamp(1, 4)
}

/// Return the proptest fuzz multiplier, respecting `PROPTEST_FUZZ_MULTIPLIER`.
///
/// Precedence:
/// 1. Explicit `PROPTEST_FUZZ_MULTIPLIER` env override (clamped to >= 1).
/// 2. CI environment — uses the caller-supplied `default` (clamped to >= 1).
/// 3. Local development — returns 1 (minimal fuzzing for fast iteration).
#[inline]
pub fn proptest_fuzz_multiplier(default: u32) -> u32 {
    if let Some(value) = env_u32("PROPTEST_FUZZ_MULTIPLIER") {
        return value.max(1);
    }
    if is_ci() {
        return default.max(1);
    }
    1
}

/// Returns a [`proptest::test_runner::Config`] tuned for the current
/// environment, with Miri-safe failure persistence.
///
/// Under Miri, uses `miri_cases` and disables file-based failure persistence
/// (Miri's default isolation mode blocks `getcwd`, which proptest's file
/// persister needs). Outside Miri, delegates to [`proptest_cases`] so the
/// `PROPTEST_CASES` env var, CI detection, and local-dev throttling all
/// apply normally.
///
/// Gated behind `#[cfg(test)]` because it returns a proptest type that
/// requires the `proptest` dev-dependency.
#[cfg(test)]
pub fn miri_proptest_config(miri_cases: u32) -> proptest::test_runner::Config {
    let cases = if cfg!(miri) {
        miri_cases
    } else {
        proptest_cases(256)
    };
    let mut config = proptest::test_runner::Config::with_cases(cases);
    if cfg!(miri) {
        config.failure_persistence = None;
    }
    config
}

/// Enumerates all permutations of `indices[start..]`, calling `visit` for each.
///
/// Uses recursive swap-based generation (Heap's algorithm variant).
/// The slice is restored to its original order after the call returns.
pub fn try_for_each_permutation<E>(
    indices: &mut [usize],
    start: usize,
    visit: &mut impl FnMut(&[usize]) -> Result<(), E>,
) -> Result<(), E> {
    if start == indices.len() {
        return visit(indices);
    }
    for index in start..indices.len() {
        indices.swap(start, index);
        try_for_each_permutation(indices, start + 1, visit)?;
        indices.swap(start, index);
    }
    Ok(())
}

/// Infallible variant of [`try_for_each_permutation`] for deterministic tests
/// that assert via `panic!` rather than returning `Result`.
pub fn for_each_permutation(
    indices: &mut [usize],
    start: usize,
    visit: &mut impl FnMut(&[usize]),
) {
    // Infallible is uninhabited — the Err branch is unreachable.
    try_for_each_permutation(indices, start, &mut |perm| {
        visit(perm);
        Ok::<(), std::convert::Infallible>(())
    })
    .unwrap()
}
