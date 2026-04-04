//! Fuzzing target for `RunRecord` serialization round-trips.
//!
//! Ensures that `decode_run_record` and `encode_run_record` are symmetric.
//! Any record successfully decoded from arbitrary fuzzer bytes must exactly
//! round-trip through encoding and re-decoding without data loss or mutation.

#![no_main]

use gossip_coordination_etcd::{decode_run_record, encode_run_record};
use libfuzzer_sys::fuzz_target;

/// If `decode_run_record` succeeds, re-encoding and re-decoding must
/// produce an identical record with identical bytes.
fuzz_target!(|data: &[u8]| {
    let Ok(record) = decode_run_record(data) else {
        return;
    };
    let reencoded = encode_run_record(&record);
    let record2 = decode_run_record(&reencoded).expect("re-encoded run record must decode");
    assert_eq!(record, record2, "round-trip record mismatch");
    assert_eq!(
        reencoded,
        encode_run_record(&record2),
        "round-trip byte mismatch"
    );
});
