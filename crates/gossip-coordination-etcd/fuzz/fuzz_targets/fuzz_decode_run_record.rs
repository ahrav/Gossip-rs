#![no_main]

use gossip_coordination_etcd::decode_run_record_v1;
use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to `decode_run_record_v1` and assert it never panics.
fuzz_target!(|data: &[u8]| {
    let _ = decode_run_record_v1(data);
});
