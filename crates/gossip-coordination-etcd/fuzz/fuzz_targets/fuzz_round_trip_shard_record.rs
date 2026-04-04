//! Fuzzing target for shard record serialization round-trips.
//!
//! Ensures that any valid byte sequence parsed into a shard record
//! can be reliably re-encoded and re-decoded to the exact same bytes.
#![no_main]

use gossip_coordination_etcd::{decode_shard_record, encode_shard_record};
use gossip_stdx::ByteSlab;
use libfuzzer_sys::fuzz_target;

/// If `decode_shard_record` succeeds, re-encoding and re-decoding must
/// produce identical bytes.
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
