//! JSON write helpers for git event sinks.

use crate::object_id::OidBytes;

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

#[inline]
pub fn write_i8(buf: &mut Vec<u8>, value: i8) {
    buf.extend_from_slice(value.to_string().as_bytes());
}

#[inline]
pub fn write_oid_hex(buf: &mut Vec<u8>, oid: &OidBytes) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = oid.as_slice();
    buf.push(b'"');
    for &byte in bytes {
        buf.push(HEX[(byte >> 4) as usize]);
        buf.push(HEX[(byte & 0x0f) as usize]);
    }
    buf.push(b'"');
}
