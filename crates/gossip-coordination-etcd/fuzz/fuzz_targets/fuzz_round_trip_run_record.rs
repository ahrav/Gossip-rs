//! Fuzzing target for `RunRecord` serialization round-trips.
//!
//! Run records are the ground truth for coordinated operations stored in etcd.
//! This harness drives the `decode_run_record` path with arbitrary bytes and
//! asserts that any successful parse survives a full encode/decode cycle. It
//! guards both the structural equality of the decoded payload and the encoded
//! bytes, ensuring the serialization format remains stable.

#![no_main]

use gossip_coordination_etcd::{decode_run_record, encode_run_record};
use libfuzzer_sys::fuzz_target;

/// Verify that every successful decode yields a record whose encoding is
/// deterministic and equal to the original byte stream after another decode.
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
