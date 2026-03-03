//! Fuzz target for SIMD byte-classification (`classify_window`).
//!
//! Exercises the NEON/SSE2/scalar classification path with arbitrary byte
//! sequences and cross-checks against an inline scalar oracle. Invariants:
//!
//! 1. `lower + upper + digit + special == data.len()` (class sum equals length).
//! 2. Each class count matches the scalar reference for every input.
//!
//! Capped at 64 KiB to keep individual iterations fast while still covering
//! multi-epoch accumulator flushes (255 x 16 = 4080 bytes per epoch).

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 65_536 {
        return;
    }

    let (lower, upper, digit, special) = scanner_engine::fuzz_classify_window(data);

    // Invariant: sum of all classes equals input length.
    let sum = lower + upper + digit + special;
    assert_eq!(sum, data.len() as u32, "class sum != len");

    // Cross-check against scalar oracle.
    let mut exp_lower = 0u32;
    let mut exp_upper = 0u32;
    let mut exp_digit = 0u32;
    for &b in data {
        match b {
            b'a'..=b'z' => exp_lower += 1,
            b'A'..=b'Z' => exp_upper += 1,
            b'0'..=b'9' => exp_digit += 1,
            _ => {}
        }
    }
    let exp_special = data.len() as u32 - exp_lower - exp_upper - exp_digit;

    assert_eq!(lower, exp_lower, "lower mismatch");
    assert_eq!(upper, exp_upper, "upper mismatch");
    assert_eq!(digit, exp_digit, "digit mismatch");
    assert_eq!(special, exp_special, "special mismatch");
});
