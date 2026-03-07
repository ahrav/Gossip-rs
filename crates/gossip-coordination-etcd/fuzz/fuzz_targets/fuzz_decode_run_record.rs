#![no_main]

use gossip_coordination_etcd::decode_run_record;
use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to `decode_run_record` and assert it never panics.
fuzz_target!(|data: &[u8]| {
    let _ = decode_run_record(data);
});
