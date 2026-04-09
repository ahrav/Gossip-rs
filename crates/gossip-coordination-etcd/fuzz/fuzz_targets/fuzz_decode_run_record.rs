#![no_main]

//! Fuzz target for `decode_run_record`.
//!
//! This target models the trust boundary where raw bytes are read from etcd
//! and interpreted as a run record by the coordination layer.
//!
//! # Coverage intent
//! - Exercise `decode_run_record` with arbitrary byte slices, including empty,
//!   truncated, and malformed payloads.
//! - Assert panic-freedom for all inputs. Decode failures are expected to be
//!   represented as normal return values, not unwinds.
//!
//! # Invariant
//! `decode_run_record` must remain total over `&[u8]`: every input is accepted
//! by the API surface and handled without panicking.

use gossip_coordination_etcd::decode_run_record;
use libfuzzer_sys::fuzz_target;

/// Feed arbitrary bytes to `decode_run_record` and assert it never panics.
fuzz_target!(|data: &[u8]| {
    let _ = decode_run_record(data);
});
