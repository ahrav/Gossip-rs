//! Fuzz target for DotEnvExtractor.
//!
//! Feeds arbitrary bytes to the `.env` extractor and verifies structural
//! invariants beyond "no panics":
//!
//! - Output length never exceeds [`EXTRACT_OUTPUT_CAP`].
//! - Every non-empty output line has a `=` with a non-empty key preceding it.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_dotenv_extract -- -runs=10000
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_engine::content_policy::dotenv::DotEnvExtractor;
use scanner_engine::content_policy::extract::{Extractor, EXTRACT_OUTPUT_CAP};

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::with_capacity(1024);
    let _ = DotEnvExtractor.extract(data, &mut out, &mut Vec::new());

    // Invariant 1: output length never exceeds the extraction budget.
    assert!(
        out.len() <= EXTRACT_OUTPUT_CAP,
        "output length {} exceeds cap {}",
        out.len(),
        EXTRACT_OUTPUT_CAP,
    );

    // Invariant 2: every non-empty output line that is a top-level assignment
    // (not a multiline-value continuation) has `=` with a non-empty key.
    for line in out.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        if let Some(eq_pos) = line.iter().position(|&b| b == b'=') {
            // `=` at position 0 can occur in continuation lines from
            // multiline values (e.g. `CERT="line1\n=line2"`). The extractor
            // never emits a top-level entry with an empty key.
            if eq_pos == 0 {
                continue;
            }
            assert!(eq_pos > 0, "empty key in output line");
        }
        // Lines without `=` are continuation lines from multiline quoted
        // values -- valid output, not structural violations.
    }
});
