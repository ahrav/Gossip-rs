pub fn env_u32(name: &str) -> Option<u32> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn is_ci() -> bool {
    std::env::var_os("CI").is_some()
}

pub fn proptest_cases(default: u32) -> u32 {
    if let Some(value) = env_u32("PROPTEST_CASES") {
        return value.max(1);
    }
    if is_ci() {
        return default.max(1);
    }
    default.clamp(1, 4)
}

pub fn proptest_fuzz_multiplier(default: u32) -> u32 {
    if let Some(value) = env_u32("PROPTEST_FUZZ_MULTIPLIER") {
        return value.max(1);
    }
    if is_ci() {
        return default.max(1);
    }
    1
}
