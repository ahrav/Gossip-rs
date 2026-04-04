#![no_main]

//! Fuzz target for decoding shard records.
//!
//! This target feeds arbitrary byte slices to the decoder to ensure:
//! 1. The decoder never panics on malformed input.
//! 2. The allocation rollback invariant is maintained (on error, no allocations are leaked in the `ByteSlab`).

use gossip_coordination_etcd::decode_shard_record;
use gossip_stdx::ByteSlab;
use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to `decode_shard_record` and assert:
/// 1. It never panics.
/// 2. On error, the slab has zero live allocations (rollback guarantee).
fuzz_target!(|data: &[u8]| {
    let mut slab = ByteSlab::with_capacity(4096);
    match decode_shard_record(data, &mut slab) {
        Ok(_record) => {
            // Valid decode — no additional invariant to check here since the
            // decoder already validates internally.
        }
        Err(_) => {
            assert_eq!(
                slab.live_count(),
                0,
                "slab must have zero live allocations after a failed decode (rollback guarantee)"
            );
        }
    }
});
