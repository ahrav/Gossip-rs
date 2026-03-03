#![no_main]

//! Fuzz target for `apply_delta_into` streaming sink path.
//!
//! Exercises:
//! - Differential correctness: `apply_delta` and `apply_delta_into` must agree on
//!   both success/failure outcomes and output bytes.
//! - Chunk validation: every chunk emitted by the streaming sink must be non-empty.
//! - Result size consistency: declared `result_size` must match total emitted bytes.
//! - Callback error injection: the sink returns an error at a fuzzer-controlled byte
//!   threshold to exercise early-abort handling.

use libfuzzer_sys::fuzz_target;
use scanner_git::pack_inflate::{apply_delta, apply_delta_into, DeltaError};

const MAX_INPUT: usize = 64 * 1024;
const MAX_OUT: usize = 64 * 1024;
const MAX_BASE: usize = 32 * 1024;

/// Read a bounded LEB128-style varint from `data`.
///
/// Returns `None` if the encoding is truncated or exceeds 64 bits.
fn read_varint(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut shift: u32 = 0;
    let mut value: u64 = 0;
    for _ in 0..10 {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        value |= ((b & 0x7f) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some(value);
        }
        shift = shift.saturating_add(7);
        if shift > 63 {
            return None;
        }
    }
    None
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > MAX_INPUT {
        return;
    }

    // Split fuzz input into base and delta slices using data[1] as pivot.
    let split = (data[1] as usize) % (data.len() - 1) + 1;
    let (base, delta) = data.split_at(split);

    // Decode varint-encoded base_len and result_len from the delta header.
    let mut pos = 0usize;
    let base_len = read_varint(delta, &mut pos);
    let result_len = read_varint(delta, &mut pos);
    let (Some(base_len), Some(result_len)) = (base_len, result_len) else {
        return;
    };
    if base_len as usize > MAX_BASE || result_len as usize > MAX_OUT {
        return;
    }
    if base_len as usize > base.len() {
        return;
    }
    let base = &base[..base_len as usize];

    // --- 1. Differential: apply_delta vs apply_delta_into must agree ---
    let mut vec_out = Vec::with_capacity(result_len as usize);
    let vec_result = apply_delta(base, delta, &mut vec_out, MAX_OUT);

    let mut stream_out = Vec::new();
    let mut chunk_count = 0usize;
    let stream_result = apply_delta_into(base, delta, MAX_OUT, |chunk| {
        assert!(
            !chunk.is_empty(),
            "apply_delta_into must not emit empty chunks"
        );
        chunk_count += 1;
        stream_out.extend_from_slice(chunk);
        Ok(())
    });

    match (&vec_result, &stream_result) {
        (Ok(()), Ok(result_size)) => {
            assert_eq!(
                vec_out, stream_out,
                "apply_delta and apply_delta_into disagree on output bytes"
            );
            assert_eq!(
                *result_size,
                stream_out.len(),
                "result_size ({}) does not match total emitted bytes ({})",
                result_size,
                stream_out.len()
            );
        }
        (Err(_), Err(_)) => {
            // Both failed -- acceptable.
        }
        _ => {
            panic!(
                "apply_delta and apply_delta_into disagree on success/failure: vec={:?}, stream={:?}",
                vec_result, stream_result
            );
        }
    }

    // --- 2. Exercise callback error at fuzzer-controlled threshold ---
    let error_threshold = (data[0] as usize).saturating_mul(4);
    let mut err_bytes = 0usize;
    let _ = apply_delta_into(base, delta, MAX_OUT, |chunk| {
        err_bytes += chunk.len();
        if err_bytes > error_threshold {
            Err(DeltaError::Truncated) // Reuse existing variant for error injection
        } else {
            Ok(())
        }
    });
});
