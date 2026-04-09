//! Fuzz target that monitors the serialization/deserialization stability of shard records.
//!
//! Drives `decode_shard_record`/`encode_shard_record` with arbitrary byte sequences so
//! malformed inputs are filtered by an early return while valid records must stay stable.
//! The goal is catching regressions where decoding and re-encoding would otherwise drift,
//! exposing invariants such as deterministic byte output, consistent field layout, and
//! repeatable use of `ByteSlab` storage for transient allocations.
#![no_main]

use gossip_coordination_etcd::{decode_shard_record, encode_shard_record};
use gossip_stdx::ByteSlab;
use libfuzzer_sys::fuzz_target;

/// Ensures that every successfully decoded shard record survives an encode/decode round trip.
///
/// Inputs are arbitrary `&[u8]`; invalid sequences are ignored so libFuzzer focuses on well-formed
/// shard records. For bytes that decode, the test re-encodes and decodes twice, asserting each
/// re-encoded buffer matches the previous one so the serialization schema remains deterministic.
/// The slab capacity is fixed at 4KiB to provide enough workspace for record data without
/// growing aggressively during fuzzing, which keeps memory usage and allocation paths stable.
fuzz_target!(|data: &[u8]| {
    let mut slab1 = ByteSlab::with_capacity(4096);
    let Ok(record1) = decode_shard_record(data, &mut slab1) else {
        return;
    };
    let reencoded = encode_shard_record(&record1, &slab1)
        .expect("successfully decoded shard record must re-encode");

    let mut slab2 = ByteSlab::with_capacity(4096);
    let record2 =
        decode_shard_record(&reencoded, &mut slab2).expect("re-encoded shard record must decode");
    let reencoded2 =
        encode_shard_record(&record2, &slab2).expect("re-decoded shard record must re-encode");

    assert_eq!(reencoded, reencoded2, "round-trip byte mismatch");
});
