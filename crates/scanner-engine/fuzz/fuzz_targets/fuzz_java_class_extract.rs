//! Fuzz target for JavaClassExtractor.
//!
//! Feeds arbitrary bytes to the `.class` extractor and asserts it never panics.
//! The hand-rolled constant pool parser uses manual offset arithmetic, making
//! it a prime candidate for fuzz testing.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_java_class_extract -- -runs=10000
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use scanner_engine::content_policy::extract::Extractor;
use scanner_engine::content_policy::java_class::JavaClassExtractor;

fuzz_target!(|data: &[u8]| {
    let mut out = Vec::with_capacity(1024);
    let _ = JavaClassExtractor.extract(data, &mut out, &mut Vec::new());
});
