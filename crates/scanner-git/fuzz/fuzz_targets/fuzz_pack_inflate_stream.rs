#![no_main]

//! Fuzz target for `inflate_stream` callback-based decompression.
//!
//! Exercises:
//! - `inflate_stream` with fuzzer-controlled expected sizes,
//! - cross-validation against `inflate_limited` for identical inputs,
//! - callback error propagation (simulated mid-stream failure), and
//! - boundary conditions around exact, under, and over expected sizes.
//!
//! The harness caps all allocations and output sizes to prevent unbounded
//! memory growth, allowing the fuzzer to explore edge cases safely.

use libfuzzer_sys::fuzz_target;
use scanner_git::pack_inflate::{inflate_limited, inflate_stream, InflateError};

const MAX_INPUT: usize = 64 * 1024;
const MAX_OUT: usize = 64 * 1024;

fuzz_target!(|data: &[u8]| {
    // Need at least 4 bytes: 2 for expected-size derivation, 2+ for zlib data.
    if data.len() < 4 || data.len() > MAX_INPUT {
        return;
    }

    // Derive a fuzzer-controlled expected size from the first 2 bytes.
    let derived_expected = u16::from_le_bytes([data[0], data[1]]) as usize;
    let derived_expected = derived_expected.min(MAX_OUT);
    let zlib_data = &data[2..];

    // --- 1. Exercise inflate_stream with the fuzzer-controlled expected size ---

    let mut stream_out = Vec::new();
    let stream_result = inflate_stream(zlib_data, derived_expected, |chunk| {
        stream_out.extend_from_slice(chunk);
        Ok(())
    });

    // If inflate_stream succeeds, the output must be exactly `derived_expected` bytes.
    if stream_result.is_ok() {
        assert_eq!(
            stream_out.len(),
            derived_expected,
            "inflate_stream succeeded but output size != expected"
        );
    }

    // --- 2. Exercise with expected = 0 (empty output) ---

    let mut zero_out = Vec::new();
    let zero_result = inflate_stream(zlib_data, 0, |chunk| {
        zero_out.extend_from_slice(chunk);
        Ok(())
    });
    if zero_result.is_ok() {
        assert!(
            zero_out.is_empty(),
            "inflate_stream with expected=0 succeeded but produced {} bytes",
            zero_out.len(),
        );
    }

    // --- 3. Cross-check against inflate_limited ---

    let mut limited_out = Vec::with_capacity(MAX_OUT);
    let limited_result = inflate_limited(zlib_data, &mut limited_out, MAX_OUT);

    if let Ok(limited_consumed) = limited_result {
        let exact = limited_out.len();

        // 3a. inflate_stream with exact expected size should agree.
        let mut exact_out = Vec::new();
        let exact_result = inflate_stream(zlib_data, exact, |chunk| {
            exact_out.extend_from_slice(chunk);
            Ok(())
        });
        match exact_result {
            Ok(stream_consumed) => {
                assert_eq!(
                    exact_out, limited_out,
                    "inflate_stream and inflate_limited disagree on output"
                );
                assert_eq!(
                    stream_consumed, limited_consumed,
                    "inflate_stream and inflate_limited disagree on bytes consumed"
                );
            }
            Err(e) => {
                panic!(
                    "inflate_limited succeeded ({exact} bytes, {limited_consumed} consumed) \
                     but inflate_stream failed with {e:?}"
                );
            }
        }

        // 3b. Expected = exact - 1: the stream decompresses to `exact` bytes,
        //     so inflate_stream must fail when given a shorter expected size.
        if exact > 0 {
            let mut under_out = Vec::new();
            let under_result = inflate_stream(zlib_data, exact - 1, |chunk| {
                under_out.extend_from_slice(chunk);
                Ok(())
            });
            assert!(
                under_result.is_err(),
                "inflate_stream(expected={}) succeeded, but inflate_limited produced {} bytes \
                 — the two functions disagree",
                exact - 1,
                exact,
            );
        }

        // 3c. Expected = exact + 1: the stream produces exactly `exact` bytes,
        //     so inflate_stream should fail (output size != expected).
        if exact < MAX_OUT {
            let mut over_out = Vec::new();
            let over_result = inflate_stream(zlib_data, exact + 1, |chunk| {
                over_out.extend_from_slice(chunk);
                Ok(())
            });
            assert!(
                over_result.is_err(),
                "inflate_stream should fail when expected ({}) exceeds actual output ({})",
                exact + 1,
                exact,
            );
        }
    }

    // --- 4. Callback error propagation ---
    //
    // Derive an error threshold from the third byte. Note: this is also the
    // first byte of zlib_data, so the threshold is correlated with the zlib
    // header. This is acceptable — the fuzzer still explores both code paths,
    // just with non-uniform probability.
    let error_threshold = data[2] as usize;
    let mut error_bytes = 0usize;
    let cb_result = inflate_stream(zlib_data, MAX_OUT, |chunk| {
        error_bytes = error_bytes.saturating_add(chunk.len());
        if error_bytes > error_threshold {
            Err(InflateError::Backend)
        } else {
            Ok(())
        }
    });
    // If the callback injected an error, inflate_stream must not report success.
    if error_bytes > error_threshold {
        assert!(
            cb_result.is_err(),
            "inflate_stream succeeded despite callback returning Err"
        );
    }
});
