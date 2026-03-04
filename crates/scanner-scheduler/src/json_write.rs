//! Shared JSON write helpers for event encoding paths.

/// Write a byte slice as a JSON-escaped string, using lossy UTF-8 conversion.
#[inline]
pub fn write_json_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    let text = String::from_utf8_lossy(value);
    write_json_str(buf, &text);
}

/// Write a string as a JSON-quoted value, escaping control characters per RFC 8259 §7.
#[inline]
pub fn write_json_str(buf: &mut Vec<u8>, value: &str) {
    buf.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\x08' => buf.extend_from_slice(b"\\b"),
            b'\x0C' => buf.extend_from_slice(b"\\f"),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            0x00..=0x1F => {
                // RFC 8259 §7: remaining control characters as \uXXXX.
                const HEX: &[u8; 16] = b"0123456789abcdef";
                buf.extend_from_slice(b"\\u00");
                buf.push(HEX[(byte >> 4) as usize]);
                buf.push(HEX[(byte & 0x0F) as usize]);
            }
            _ => buf.push(byte),
        }
    }
    buf.push(b'"');
}

/// Write a `u64` as its decimal ASCII representation.
#[inline]
pub fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(value.to_string().as_bytes());
}

/// Write an `i8` as its decimal ASCII representation without heap allocation.
#[inline]
pub fn write_i8(buf: &mut Vec<u8>, value: i8) {
    // Stack buffer avoids heap allocation. i8 is at most 4 chars ("-128").
    let mut tmp = [0u8; 4];
    let mut pos = tmp.len();
    let neg = value < 0;
    // Widen to i16 to negate i8::MIN (-128) without overflow.
    let mut n = if neg { -(value as i16) } else { value as i16 } as u16;
    loop {
        pos -= 1;
        tmp[pos] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    if neg {
        pos -= 1;
        tmp[pos] = b'-';
    }
    buf.extend_from_slice(&tmp[pos..]);
}

/// Write an `f64` as its decimal ASCII representation.
#[inline]
pub fn write_f64(buf: &mut Vec<u8>, value: f64) {
    buf.extend_from_slice(value.to_string().as_bytes());
}

/// Cursor wrapper used by encoders that incrementally append JSON bytes.
pub struct BufCursor<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> BufCursor<'a> {
    /// Wrap an existing byte buffer as a cursor.
    #[inline]
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    /// Append a single byte to the buffer.
    #[inline]
    pub fn push_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    /// Append a byte slice to the buffer.
    #[inline]
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Consume the cursor and return the underlying buffer.
    #[inline]
    pub fn into_inner(self) -> &'a mut Vec<u8> {
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_json_str_escapes_control_characters() {
        let mut buf = Vec::new();
        write_json_str(&mut buf, "a\"b\\c\n");
        assert_eq!(String::from_utf8(buf).unwrap(), "\"a\\\"b\\\\c\\n\"");
    }

    #[test]
    fn write_json_str_escapes_all_rfc8259_control_chars() {
        // RFC 8259 §7: all control characters U+0000..U+001F MUST be escaped.
        // \n (0x0A), \r (0x0D), \t (0x09) get named escapes; the rest need \uXXXX.
        let input = "\x00\x08\x0C\x1F";
        let mut buf = Vec::new();
        write_json_str(&mut buf, input);
        let output = String::from_utf8(buf).unwrap();
        // \x08 → \b, \x0C → \f (named escapes); \x00 and \x1F → \uXXXX.
        assert_eq!(output, "\"\\u0000\\b\\f\\u001f\"");
    }

    #[test]
    fn buf_cursor_appends_bytes() {
        let mut buf = Vec::new();
        let mut cursor = BufCursor::new(&mut buf);
        cursor.push_bytes(b"abc");
        cursor.push_byte(b'd');
        assert_eq!(cursor.into_inner().as_slice(), b"abcd");
    }

    #[test]
    fn write_i8_handles_boundaries() {
        let cases: &[(i8, &str)] = &[
            (0, "0"),
            (1, "1"),
            (-1, "-1"),
            (127, "127"),
            (-128, "-128"),
            (85, "85"),
            (-42, "-42"),
        ];
        for &(input, expected) in cases {
            let mut buf = Vec::new();
            write_i8(&mut buf, input);
            assert_eq!(
                std::str::from_utf8(&buf).unwrap(),
                expected,
                "write_i8({input}) failed"
            );
        }
    }
}
