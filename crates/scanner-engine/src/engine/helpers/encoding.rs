//! UTF-16 decode helpers (LE and BE variants).
//!
//! Provides decode routines for UTF-16 data into UTF-8, with replacement
//! characters for invalid sequences and output-size limits.

use crate::scratch_memory::ScratchVec;

#[derive(Debug)]
pub(crate) enum Utf16DecodeError {
    /// Output would exceed the configured maximum or buffer capacity.
    OutputTooLarge,
}

#[cfg(test)]
/// Decodes UTF-16LE into a UTF-8 `Vec`, enforcing a maximum output size.
///
/// # Behavior
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
pub(crate) fn decode_utf16le_to_vec(
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_vec_inner(input, max_out, true, &mut out)?;
    Ok(out)
}

#[cfg(test)]
/// Decodes UTF-16BE into a UTF-8 `Vec`, enforcing a maximum output size.
///
/// # Behavior
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
pub(crate) fn decode_utf16be_to_vec(
    input: &[u8],
    max_out: usize,
) -> Result<Vec<u8>, Utf16DecodeError> {
    let mut out = Vec::new();
    decode_utf16_to_vec_inner(input, max_out, false, &mut out)?;
    Ok(out)
}

#[cfg(test)]
fn decode_utf16_to_vec_inner(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut Vec<u8>,
) -> Result<(), Utf16DecodeError> {
    // Ignore a trailing odd byte; it cannot form a full UTF-16 code unit.
    let n = input.len() / 2;
    let iter = (0..n).map(|i| {
        let b0 = input[2 * i];
        let b1 = input[2 * i + 1];
        if le {
            u16::from_le_bytes([b0, b1])
        } else {
            u16::from_be_bytes([b0, b1])
        }
    });

    out.clear();
    for r in std::char::decode_utf16(iter) {
        let ch = r.unwrap_or('\u{FFFD}');
        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if out.len() + s.len() > max_out {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
    }
    Ok(())
}

/// Decodes UTF-16LE into the provided scratch buffer.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
pub(crate) fn decode_utf16le_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, true, out)
}

/// Decodes UTF-16BE into the provided scratch buffer.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - Replaces invalid sequences with U+FFFD.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
pub(crate) fn decode_utf16be_to_buf(
    input: &[u8],
    max_out: usize,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    decode_utf16_to_buf(input, max_out, false, out)
}

/// Reads one UTF-16 code unit from `input` at byte offset `off`.
#[inline(always)]
fn read_utf16_code_unit(input: &[u8], off: usize, le: bool) -> u16 {
    // SAFETY: caller guarantees `off + 1 < input.len()`.
    let b0 = unsafe { *input.get_unchecked(off) };
    // SAFETY: caller guarantees `off + 1 < input.len()`.
    let b1 = unsafe { *input.get_unchecked(off + 1) };
    if le {
        u16::from_le_bytes([b0, b1])
    } else {
        u16::from_be_bytes([b0, b1])
    }
}

/// Decodes one Unicode scalar value at UTF-16 code-unit index `i`.
///
/// Returns `(char, advance_units)` where `advance_units` is 1 for BMP or
/// replacement characters and 2 for valid surrogate pairs.
#[inline(always)]
fn decode_utf16_scalar_at(input: &[u8], i: usize, n: usize, le: bool) -> (char, usize) {
    debug_assert!(i < n, "caller must provide in-bounds UTF-16 index");
    let off = i * 2;
    let u = read_utf16_code_unit(input, off, le);

    if (0xD800..=0xDBFF).contains(&u) {
        // High surrogate — consume a pair only when followed by a valid low surrogate.
        if i + 1 < n {
            let off2 = (i + 1) * 2;
            // SAFETY: `i + 1 < n` and `n = input.len() / 2` imply
            // `off2 + 1 = 2*(i+1)+1 < 2*n <= input.len()`.
            let u2 = read_utf16_code_unit(input, off2, le);
            if (0xDC00..=0xDFFF).contains(&u2) {
                let high = (u - 0xD800) as u32;
                let low = (u2 - 0xDC00) as u32;
                let code = 0x10000 + ((high << 10) | low);
                // SAFETY: code is constructed from a valid surrogate pair.
                return (unsafe { char::from_u32_unchecked(code) }, 2);
            }
        }
        return ('\u{FFFD}', 1);
    }

    if (0xDC00..=0xDFFF).contains(&u) {
        // Lone low surrogate.
        ('\u{FFFD}', 1)
    } else {
        // SAFETY: non-surrogate BMP code units are valid scalar values.
        (unsafe { char::from_u32_unchecked(u as u32) }, 1)
    }
}

/// Maps a decoded UTF-8 offset back to the raw UTF-16 byte offset.
///
/// Returns the raw byte offset (half-open) such that decoding `input[0..offset]`
/// would produce at least `decoded_offset` UTF-8 bytes. The returned offset is
/// always aligned to complete UTF-16 scalar decoding steps (it never points
/// into the middle of a surrogate pair). If `decoded_offset` exceeds the
/// decoded length, returns the largest even byte offset.
///
/// Complexity is O(number of decoded scalars up to the target offset).
pub(crate) fn map_utf16_decoded_offset(input: &[u8], decoded_offset: usize, le: bool) -> usize {
    if decoded_offset == 0 {
        return 0;
    }
    let n = input.len() / 2;
    let mut decoded = 0usize;
    let mut i = 0usize;

    while i < n {
        let (ch, advance) = decode_utf16_scalar_at(input, i, n, le);

        // `decoded` is monotonically increasing; saturating add keeps behavior
        // defined even for pathological inputs near `usize::MAX`.
        decoded = decoded.saturating_add(ch.len_utf8());
        i += advance;
        if decoded >= decoded_offset {
            return i * 2;
        }
    }

    n * 2
}

/// Decodes UTF-16 into a scratch buffer, using replacement characters for
/// invalid sequences.
///
/// # Behavior
/// - Clears `out` before writing.
/// - Ignores a trailing odd byte (incomplete code unit).
/// - On error, `out` may contain a truncated prefix; treat its contents as unspecified.
///
/// # Errors
/// - `OutputTooLarge` if the result would exceed `max_out` or buffer capacity.
///
/// # Complexity
/// O(number of UTF-16 code units).
fn decode_utf16_to_buf(
    input: &[u8],
    max_out: usize,
    le: bool,
    out: &mut ScratchVec<u8>,
) -> Result<(), Utf16DecodeError> {
    // Ignore a trailing odd byte; it cannot form a full UTF-16 code unit.
    let n = input.len() / 2;
    out.clear();

    // Manual decode loop — avoids std::char::decode_utf16 iterator/Result overhead.
    let mut i = 0usize;
    while i < n {
        let (ch, advance) = decode_utf16_scalar_at(input, i, n, le);

        let mut buf = [0u8; 4];
        let s = ch.encode_utf8(&mut buf);
        if out.len() + s.len() > max_out {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        if out.len() + s.len() > out.capacity() {
            return Err(Utf16DecodeError::OutputTooLarge);
        }
        out.extend_from_slice(s.as_bytes());
        i += advance;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scratch_memory::ScratchVec;

    fn expected_map_utf16_offset(input: &[u8], decoded_offset: usize, le: bool) -> usize {
        if decoded_offset == 0 {
            return 0;
        }

        let n = input.len() / 2;
        let mut decoded = 0usize;
        let mut i = 0usize;

        while i < n {
            let off = i * 2;
            let u = if le {
                u16::from_le_bytes([input[off], input[off + 1]])
            } else {
                u16::from_be_bytes([input[off], input[off + 1]])
            };

            let (utf8_len, advance) = if (0xD800..=0xDBFF).contains(&u) {
                if i + 1 < n {
                    let off2 = (i + 1) * 2;
                    let u2 = if le {
                        u16::from_le_bytes([input[off2], input[off2 + 1]])
                    } else {
                        u16::from_be_bytes([input[off2], input[off2 + 1]])
                    };
                    if (0xDC00..=0xDFFF).contains(&u2) {
                        (4usize, 2usize)
                    } else {
                        (3usize, 1usize)
                    }
                } else {
                    (3usize, 1usize)
                }
            } else if (0xDC00..=0xDFFF).contains(&u) {
                (3usize, 1usize)
            } else {
                let ch = char::from_u32(u as u32).expect("non-surrogate BMP scalar");
                (ch.len_utf8(), 1usize)
            };

            decoded = decoded.saturating_add(utf8_len);
            i += advance;
            if decoded >= decoded_offset {
                return i * 2;
            }
        }

        n * 2
    }

    #[test]
    fn decode_utf16_to_buf_errors_when_capacity_is_too_small() {
        // "AB" in UTF-16LE.
        let input = [b'A', 0, b'B', 0];
        let mut out = ScratchVec::with_capacity(1).expect("scratch alloc");

        let err = decode_utf16le_to_buf(&input, 8, &mut out)
            .expect_err("decode should map capacity overflow to Utf16DecodeError::OutputTooLarge");
        assert!(matches!(err, Utf16DecodeError::OutputTooLarge));
    }

    #[test]
    fn decode_utf16_to_buf_succeeds_when_capacity_is_sufficient() {
        // "AB" in UTF-16LE.
        let input = [b'A', 0, b'B', 0];
        let mut out = ScratchVec::with_capacity(2).expect("scratch alloc");

        decode_utf16le_to_buf(&input, 8, &mut out).expect("decode should succeed");
        assert_eq!(out.as_slice(), b"AB");
    }

    #[test]
    fn map_utf16_decoded_offset_matches_bruteforce_utf16le() {
        // "A" + U+10000 surrogate pair + lone low surrogate + "z".
        let input = [0x41, 0x00, 0x00, 0xD8, 0x00, 0xDC, 0x00, 0xDC, 0x7A, 0x00];
        let full = decode_utf16le_to_vec(&input, usize::MAX).expect("decode");

        for decoded_offset in 0..=(full.len() + 3) {
            let mapped = map_utf16_decoded_offset(&input, decoded_offset, true);
            let expected = expected_map_utf16_offset(&input, decoded_offset, true);
            assert_eq!(mapped, expected, "decoded_offset={decoded_offset}");
        }
    }

    #[test]
    fn map_utf16_decoded_offset_matches_bruteforce_utf16be() {
        // Same scalar sequence as LE test but in BE encoding.
        let input = [0x00, 0x41, 0xD8, 0x00, 0xDC, 0x00, 0xDC, 0x00, 0x00, 0x7A];
        let full = decode_utf16be_to_vec(&input, usize::MAX).expect("decode");

        for decoded_offset in 0..=(full.len() + 3) {
            let mapped = map_utf16_decoded_offset(&input, decoded_offset, false);
            let expected = expected_map_utf16_offset(&input, decoded_offset, false);
            assert_eq!(mapped, expected, "decoded_offset={decoded_offset}");
        }
    }
}
