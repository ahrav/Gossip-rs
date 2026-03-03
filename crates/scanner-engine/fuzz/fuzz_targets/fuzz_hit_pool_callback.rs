//! Fuzz target exercising the hit_pool push / take / reset cycle.
//!
//! This target stresses the `HitAccPool` accumulation logic with arbitrary
//! sequences of push/take/reset operations, covering the fast append path,
//! the coalesce overflow cold path, and the touched-bitset bookkeeping.
//!
//! Runs entirely in safe Rust (no FFI) so Miri and sanitizers can instrument it.

#![no_main]

use libfuzzer_sys::fuzz_target;

use scanner_engine::FuzzHitAccPool;

fuzz_target!(|data: &[u8]| {
    // Need at least 3 bytes: pair_count, max_hits, then ops.
    if data.len() < 3 {
        return;
    }

    let pair_count = (data[0] as usize).max(1).min(64);
    let max_hits = (data[1] as usize).max(1).min(128);

    let Some(mut pool) = FuzzHitAccPool::new(pair_count, max_hits) else {
        return;
    };

    // Each op is 10 bytes: [pair:1, start_lo:1, start_hi:1, end_lo:1, end_hi:1, hint:1, op_type:1, _pad:3]
    // Simplified: consume 7 bytes per op.
    let ops = &data[2..];
    let mut i = 0;
    while i + 7 <= ops.len() {
        let pair = ops[i] as usize;
        let start = u32::from_le_bytes([ops[i + 1], ops[i + 2], 0, 0]);
        let end = u32::from_le_bytes([ops[i + 3], ops[i + 4], 0, 0]);
        let hint = u32::from_le_bytes([ops[i + 5], 0, 0, 0]);
        let op_type = ops[i + 6];

        match op_type % 4 {
            0 | 1 => {
                // Push (most common op).
                pool.push(pair, start, end, hint);
            }
            2 => {
                // Take.
                pool.take(pair);
            }
            3 => {
                // Reset.
                pool.reset();
            }
            _ => unreachable!(),
        }

        i += 7;
    }

    // Final drain: take all pairs to exercise take_into paths.
    for pair in 0..pool.pair_count() {
        pool.take(pair);
    }
});
