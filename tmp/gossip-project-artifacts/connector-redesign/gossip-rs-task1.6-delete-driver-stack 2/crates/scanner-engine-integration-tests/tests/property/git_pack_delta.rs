//! Property tests for git delta encode/apply roundtrip correctness.
//!
//! Generates random base and result buffers, encodes valid deltas using
//! insert-only, copy-only, and mixed command sequences, then verifies
//! that `apply_delta` and `apply_delta_into` reconstruct the expected output.

use proptest::prelude::*;

use scanner_git::DeltaError;
use scanner_git::pack_inflate::{apply_delta, apply_delta_into};

// ---------------------------------------------------------------------------
// Delta encoding helpers
// ---------------------------------------------------------------------------

fn encode_varint(mut value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
    out
}

fn build_insert_delta(base_len: usize, result: &[u8]) -> Vec<u8> {
    let mut delta = Vec::new();
    delta.extend(encode_varint(base_len as u64));
    delta.extend(encode_varint(result.len() as u64));
    let mut remaining = result;
    while !remaining.is_empty() {
        let chunk_len = remaining.len().min(127);
        delta.push(chunk_len as u8);
        delta.extend_from_slice(&remaining[..chunk_len]);
        remaining = &remaining[chunk_len..];
    }
    delta
}

fn build_copy_cmd(offset: usize, size: usize) -> Vec<u8> {
    let mut cmd: u8 = 0x80;
    let mut params = Vec::new();

    let off_bytes = (offset as u32).to_le_bytes();
    for (i, &b) in off_bytes.iter().enumerate() {
        if b != 0 {
            cmd |= 1 << i;
            params.push(b);
        }
    }

    let actual_size = if size == 0x10000 { 0u32 } else { size as u32 };
    let sz_bytes = actual_size.to_le_bytes();
    for (i, &b) in sz_bytes.iter().enumerate().take(3) {
        if b != 0 {
            cmd |= 1 << (4 + i);
            params.push(b);
        }
    }

    let mut out = vec![cmd];
    out.extend(params);
    out
}

fn build_copy_delta(base: &[u8], offset: usize, size: usize) -> Vec<u8> {
    let mut delta = Vec::new();
    delta.extend(encode_varint(base.len() as u64));
    delta.extend(encode_varint(size as u64));
    delta.extend(build_copy_cmd(offset, size));
    delta
}

/// Build a delta from a sequence of operations (copy or insert).
enum DeltaOp<'a> {
    Copy { offset: usize, size: usize },
    Insert(&'a [u8]),
}

fn build_mixed_delta(base_len: usize, result_len: usize, ops: &[DeltaOp<'_>]) -> Vec<u8> {
    let mut delta = Vec::new();
    delta.extend(encode_varint(base_len as u64));
    delta.extend(encode_varint(result_len as u64));
    for op in ops {
        match op {
            DeltaOp::Copy { offset, size } => {
                delta.extend(build_copy_cmd(*offset, *size));
            }
            DeltaOp::Insert(data) => {
                let mut remaining = *data;
                while !remaining.is_empty() {
                    let chunk_len = remaining.len().min(127);
                    delta.push(chunk_len as u8);
                    delta.extend_from_slice(&remaining[..chunk_len]);
                    remaining = &remaining[chunk_len..];
                }
            }
        }
    }
    delta
}

/// Apply delta via the streaming API and collect output.
fn apply_delta_into_vec(base: &[u8], delta: &[u8], max_out: usize) -> Result<Vec<u8>, DeltaError> {
    let mut collected = Vec::new();
    apply_delta_into(base, delta, max_out, |chunk| {
        collected.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok(collected)
}

// ---------------------------------------------------------------------------
// Property tests
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn pure_insert_roundtrip(
        base in prop::collection::vec(any::<u8>(), 0..256),
        result in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let delta = build_insert_delta(base.len(), &result);
        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, result.len() + 1).unwrap();
        prop_assert_eq!(&out, &result);
    }

    #[test]
    fn pure_copy_roundtrip(
        base in prop::collection::vec(any::<u8>(), 1..512),
        offset_frac in 0.0..1.0f64,
        size_frac in 0.01..1.0f64,
    ) {
        let max_offset = base.len().saturating_sub(1);
        let offset = (offset_frac * max_offset as f64) as usize;
        let max_size = base.len() - offset;
        if max_size == 0 {
            return Ok(());
        }
        let size = ((size_frac * max_size as f64) as usize).max(1).min(max_size);

        // size must not be zero and must fit in copy encoding (up to 0x10000 handled,
        // but we cap at base.len() which is at most 511).
        let delta = build_copy_delta(&base, offset, size);
        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, size + 1).unwrap();

        let expected = &base[offset..offset + size];
        prop_assert_eq!(&out[..], expected);
    }

    #[test]
    fn mixed_copy_insert_roundtrip(
        base in prop::collection::vec(any::<u8>(), 1..256),
        insert_data in prop::collection::vec(any::<u8>(), 1..128),
        copy_offset_frac in 0.0..1.0f64,
        copy_size_frac in 0.01..1.0f64,
        insert_first in any::<bool>(),
    ) {
        let max_offset = base.len().saturating_sub(1);
        let copy_offset = (copy_offset_frac * max_offset as f64) as usize;
        let max_copy = base.len() - copy_offset;
        if max_copy == 0 {
            return Ok(());
        }
        let copy_size = ((copy_size_frac * max_copy as f64) as usize).max(1).min(max_copy);

        let mut expected = Vec::new();
        let ops: Vec<DeltaOp<'_>> = if insert_first {
            expected.extend_from_slice(&insert_data);
            expected.extend_from_slice(&base[copy_offset..copy_offset + copy_size]);
            vec![
                DeltaOp::Insert(&insert_data),
                DeltaOp::Copy { offset: copy_offset, size: copy_size },
            ]
        } else {
            expected.extend_from_slice(&base[copy_offset..copy_offset + copy_size]);
            expected.extend_from_slice(&insert_data);
            vec![
                DeltaOp::Copy { offset: copy_offset, size: copy_size },
                DeltaOp::Insert(&insert_data),
            ]
        };

        let delta = build_mixed_delta(base.len(), expected.len(), &ops);
        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, expected.len() + 1).unwrap();
        prop_assert_eq!(&out, &expected);
    }

    #[test]
    fn empty_result_delta(
        base in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let mut delta = Vec::new();
        delta.extend(encode_varint(base.len() as u64));
        delta.extend(encode_varint(0));
        // No commands — result_size is 0 so the loop body is never entered.

        let mut out = Vec::new();
        apply_delta(&base, &delta, &mut out, 1).unwrap();
        prop_assert!(out.is_empty());
    }

    #[test]
    fn max_out_boundary_rejects_oversize(
        base in prop::collection::vec(any::<u8>(), 0..64),
        result in prop::collection::vec(any::<u8>(), 2..128),
    ) {
        let delta = build_insert_delta(base.len(), &result);
        let too_small = result.len() - 1;

        let mut out = Vec::new();
        let err = apply_delta(&base, &delta, &mut out, too_small);
        prop_assert!(
            matches!(err, Err(DeltaError::OutputOverrun)),
            "expected OutputOverrun, got {:?}",
            err
        );
    }

    #[test]
    fn apply_delta_and_apply_delta_into_agree(
        base in prop::collection::vec(any::<u8>(), 0..256),
        result in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let delta = build_insert_delta(base.len(), &result);
        let max_out = result.len() + 1;

        let mut vec_out = Vec::new();
        apply_delta(&base, &delta, &mut vec_out, max_out).unwrap();

        let stream_out = apply_delta_into_vec(&base, &delta, max_out).unwrap();

        prop_assert_eq!(&vec_out, &stream_out);
    }

    #[test]
    fn copy_roundtrip_agrees_between_apis(
        base in prop::collection::vec(any::<u8>(), 1..256),
        offset_frac in 0.0..1.0f64,
        size_frac in 0.01..1.0f64,
    ) {
        let max_offset = base.len().saturating_sub(1);
        let offset = (offset_frac * max_offset as f64) as usize;
        let max_size = base.len() - offset;
        if max_size == 0 {
            return Ok(());
        }
        let size = ((size_frac * max_size as f64) as usize).max(1).min(max_size);
        let delta = build_copy_delta(&base, offset, size);
        let max_out = size + 1;

        let mut vec_out = Vec::new();
        apply_delta(&base, &delta, &mut vec_out, max_out).unwrap();

        let stream_out = apply_delta_into_vec(&base, &delta, max_out).unwrap();

        prop_assert_eq!(&vec_out, &stream_out);
    }

    #[test]
    fn mixed_roundtrip_agrees_between_apis(
        base in prop::collection::vec(any::<u8>(), 1..256),
        insert_data in prop::collection::vec(any::<u8>(), 1..128),
        copy_offset_frac in 0.0..1.0f64,
        copy_size_frac in 0.01..1.0f64,
    ) {
        let max_offset = base.len().saturating_sub(1);
        let copy_offset = (copy_offset_frac * max_offset as f64) as usize;
        let max_copy = base.len() - copy_offset;
        if max_copy == 0 {
            return Ok(());
        }
        let copy_size = ((copy_size_frac * max_copy as f64) as usize).max(1).min(max_copy);

        let mut expected = Vec::new();
        expected.extend_from_slice(&insert_data);
        expected.extend_from_slice(&base[copy_offset..copy_offset + copy_size]);

        let ops = vec![
            DeltaOp::Insert(&insert_data),
            DeltaOp::Copy { offset: copy_offset, size: copy_size },
        ];

        let delta = build_mixed_delta(base.len(), expected.len(), &ops);
        let max_out = expected.len() + 1;

        let mut vec_out = Vec::new();
        apply_delta(&base, &delta, &mut vec_out, max_out).unwrap();

        let stream_out = apply_delta_into_vec(&base, &delta, max_out).unwrap();

        prop_assert_eq!(&vec_out, &stream_out);
    }
}
