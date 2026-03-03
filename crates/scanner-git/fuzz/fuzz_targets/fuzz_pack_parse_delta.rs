#![no_main]

//! Fuzz target for pack header parsing and delta application.
//!
//! Exercises:
//! - pack header parsing at random offsets,
//! - bounded inflation of arbitrary payloads, and
//! - delta application with length-checked inputs.
//!
//! The harness is intentionally permissive: it ignores decode errors and only
//! enforces conservative size caps so the fuzzer can explore edge cases without
//! allocating unbounded memory.

use libfuzzer_sys::fuzz_target;
use scanner_git::pack_inflate::{apply_delta, inflate_limited, PackFile};

const MAX_INPUT: usize = 64 * 1024;
const MAX_OUT: usize = 64 * 1024;
const MAX_BASE: usize = 32 * 1024;
const MAX_HEADER_BYTES: usize = 64;

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

    // Fuzz pack header parsing and entry header decoding.
    let oid_len = if (data[0] & 1) == 0 { 20 } else { 32 };
    if let Ok(pack) = PackFile::parse(data, oid_len) {
        let len = data.len();
        let mut idx = 1usize;
        for _ in 0..4 {
            let offset = 12 + (data[idx] as usize % len.saturating_sub(12).max(1));
            let _ = pack.entry_header_at(offset as u64, MAX_HEADER_BYTES);
            idx = (idx + 1) % data.len();
        }
    }

    // Fuzz generic inflate with a fixed output cap.
    let mut inflate_out = Vec::with_capacity(MAX_OUT);
    let _ = inflate_limited(data, &mut inflate_out, MAX_OUT);

    // Fuzz delta apply with independent base/delta slices and size guards.
    let split = (data[1] as usize) % (data.len() - 1) + 1;
    let (base, delta) = data.split_at(split);
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
    let mut delta_out = Vec::with_capacity(result_len as usize);
    let _ = apply_delta(base, delta, &mut delta_out, MAX_OUT);
});
