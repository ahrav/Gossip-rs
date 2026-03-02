//! Git delta application helpers.
//!
//! Wraps the delta decoder from `pack_inflate` so pack decode callers can
//! apply deltas with explicit output caps. Callers are responsible for
//! enforcing delta chain depth and choosing base objects.
//!
//! The re-exported helpers validate base/result sizes and enforce a maximum
//! output size to avoid unbounded allocations on corrupt deltas.

// Re-exported so pack decode stages can enforce output caps without
// depending on `pack_inflate` directly.

/// Applies a Git delta buffer to a base object, enforcing a hard output cap.
///
/// The output buffer is cleared before writing; pass a reusable `Vec` to
/// avoid repeated allocations across delta applications.
pub use super::pack_inflate::apply_delta;
/// Errors returned by `apply_delta`.
///
/// These cover truncated inputs, size mismatches, and bounds violations.
pub use super::pack_inflate::DeltaError;

#[cfg(test)]
mod tests {
    use super::*;

    fn varint(mut value: u64) -> Vec<u8> {
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

    #[test]
    fn apply_delta_copies_and_inserts() {
        let base = b"abc";
        let mut delta = Vec::new();
        delta.extend_from_slice(&varint(base.len() as u64));
        delta.extend_from_slice(&varint(6));
        // Copy base (offset=0, size=3).
        delta.push(0x90);
        delta.push(0x03);
        // Insert "XYZ".
        delta.push(0x03);
        delta.extend_from_slice(b"XYZ");

        let mut out = Vec::new();
        apply_delta(base, &delta, &mut out, 16).unwrap();
        assert_eq!(out, b"abcXYZ");
    }
}
