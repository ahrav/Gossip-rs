//! Fuzz target for PycExtractor.
//!
//! Feeds arbitrary bytes to the `.pyc` extractor and asserts it never panics.
//! The hand-rolled marshal parser uses manual offset arithmetic, making it
//! the #1 candidate for fuzz testing.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_pyc_extract -- -runs=10000
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_engine::content_policy::extract::Extractor;
use scanner_engine::content_policy::pyc::PycExtractor;

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::with_capacity(1024);
    let _ = PycExtractor.extract(data, &mut out, &mut Vec::new());
});
