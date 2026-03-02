//! Shared JSON write helpers for event encoding paths.

#[inline]
pub fn write_json_bytes(buf: &mut Vec<u8>, value: &[u8]) {
    let text = String::from_utf8_lossy(value);
    write_json_str(buf, &text);
}

#[inline]
pub fn write_json_str(buf: &mut Vec<u8>, value: &str) {
    buf.push(b'"');
    for byte in value.bytes() {
        match byte {
            b'\\' => buf.extend_from_slice(b"\\\\"),
            b'"' => buf.extend_from_slice(b"\\\""),
            b'\n' => buf.extend_from_slice(b"\\n"),
            b'\r' => buf.extend_from_slice(b"\\r"),
            b'\t' => buf.extend_from_slice(b"\\t"),
            _ => buf.push(byte),
        }
    }
    buf.push(b'"');
}

#[inline]
pub fn write_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(value.to_string().as_bytes());
}

#[inline]
pub fn write_f64(buf: &mut Vec<u8>, value: f64) {
    buf.extend_from_slice(value.to_string().as_bytes());
}

/// Cursor wrapper used by encoders that incrementally append JSON bytes.
pub struct BufCursor<'a> {
    buf: &'a mut Vec<u8>,
}

impl<'a> BufCursor<'a> {
    #[inline]
    pub fn new(buf: &'a mut Vec<u8>) -> Self {
        Self { buf }
    }

    #[inline]
    pub fn push_byte(&mut self, byte: u8) {
        self.buf.push(byte);
    }

    #[inline]
    pub fn push_bytes(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

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
    fn buf_cursor_appends_bytes() {
        let mut buf = Vec::new();
        let mut cursor = BufCursor::new(&mut buf);
        cursor.push_bytes(b"abc");
        cursor.push_byte(b'd');
        assert_eq!(cursor.into_inner().as_slice(), b"abcd");
    }
}
