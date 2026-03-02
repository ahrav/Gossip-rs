//! Shared test helpers required by extracted property-test modules.

fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn is_ci() -> bool {
    std::env::var_os("CI").is_some()
}

/// Return the proptest case count, respecting `PROPTEST_CASES` env var.
///
/// Precedence: explicit env override > CI default > local-dev clamp (max 4).
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
