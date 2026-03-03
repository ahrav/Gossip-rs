#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_engine::tiger_harness::{
    check_oracle_covered, correctness_engine, scan_chunked_records, scan_one_chunk_records,
    ChunkPattern, ChunkPlan,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // Seed controls deterministic chunk-plan generation; the rest is the input.
    let (seed_bytes, buf) = data.split_at(8);
    let seed = u64::from_le_bytes(seed_bytes.try_into().unwrap());

    let engine = correctness_engine();
    let oracle = scan_one_chunk_records(&engine, buf);

    const SIZES: &[usize] = &[1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 127, 128];
    let pick = |shift: u32| -> usize { SIZES[((seed >> shift) as usize) % SIZES.len()] };

    let s0 = pick(0);
    let s1 = pick(8);
    let s2 = pick(16);

    let overlap = engine.required_overlap();
    let big = overlap
        .saturating_add(1)
        .saturating_add(seed as usize % 512);
    let first_shift = 1 + ((seed >> 32) as usize % 64);

    // Use a small, diverse set of plans to shake out boundary conditions.
    let plans = vec![
        ChunkPlan::fixed(s0),
        ChunkPlan::alternating(s1, s2),
        ChunkPlan::random_range(seed, 1, s2.max(1)).with_first_chunk(first_shift),
        ChunkPlan {
            pattern: ChunkPattern::Sequence(vec![1, s0, 2, s1, 3, s2]),
            seed: 0,
            first_chunk_len: None,
        },
        ChunkPlan::fixed(big).with_first_chunk(first_shift),
    ];

    for plan in plans {
        let chunked = scan_chunked_records(&engine, buf, plan);
        if let Err(msg) = check_oracle_covered(&engine, &oracle, &chunked) {
            panic!("tiger fuzz coverage failure: {msg}");
        }
    }
});
