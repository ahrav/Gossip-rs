#![no_main]

//! Fuzz target for `decode_run_record`.
//!
//! Ensures that the etcd run record decoder never panics, regardless of the
//! input bytes provided. This protects the coordination layer from malicious
//! or corrupted data originating from the etcd backend.

use gossip_coordination_etcd::decode_run_record;
use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to `decode_run_record` and assert it never panics.
fuzz_target!(|data: &[u8]| {
    let _ = decode_run_record(data);
});
