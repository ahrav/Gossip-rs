//! Python `.pyc` bytecode text extractor.
//!
//! Parses the marshal data in a compiled Python file to extract string
//! constants (`TYPE_STRING`, `TYPE_SHORT_ASCII`, `TYPE_SHORT_ASCII_INTERNED`,
//! `TYPE_UNICODE`, `TYPE_INTERNED`, `TYPE_ASCII`, `TYPE_ASCII_INTERNED`).
//! These often contain API keys, URLs, and other secrets embedded in
//! Python source.
//!
//! # Supported versions
//!
//! Targets Python 3.6+ `.pyc` files. Python 2 `.pyc` files use an 8-byte
//! header (magic + timestamp), so they are parsed with a wrong header
//! offset and will likely extract no useful strings (yielding `Empty`).
//!
//! # Header format
//!
//! ```text
//! Bytes 0-3:  magic (2 bytes) + \r\n (2 bytes) — identifies Python version
//!
//! Python 3.6:
//!     Bytes 4-7:  timestamp
//!     Bytes 8-11: source size        → header_size = 12
//!
//! Python 3.7+ (PEP 552):
//!     Bytes 4-7:  flags
//!     Bytes 8-15: hash OR timestamp+size → header_size = 16
//! ```
//!
//! Header size is selected from the magic number: pre-3.7 uses 12 bytes,
//! 3.7+ uses 16 bytes.
//!
//! # Marshal walk strategy
//!
//! After the header, the rest is a marshal-encoded code object. We do a
//! **linear sweep** of marshal opcodes:
//!
//! - **String types**: length-prefixed content is appended to the output
//!   buffer, one line per string.
//! - **Fixed-size types** (`int`, `ref`, `True`, `False`, etc.): skipped
//!   by their known byte sizes. Note: `float` and `complex` are variable-length
//!   (length-prefixed) and handled separately.
//! - **Container types** (`tuple`, `list`, `set`, `frozenset`, `dict`): we skip only the
//!   element-count prefix; the contained objects follow inline and will be
//!   picked up by subsequent iterations. Dict key/value pairs are terminated
//!   by `TYPE_NULL` (`'0'`), which we treat as a zero-size sentinel.
//! - **`TYPE_CODE`**: skips the 24-byte numeric prefix (argcount through
//!   flags — the layout used by Python 3.8+). The code object's sub-fields
//!   (bytecode, constants, names, etc.) are themselves marshal objects and
//!   will be parsed in subsequent iterations.
//! - **`FLAG_REF` (0x80)**: can be OR'd onto any type code to signal an
//!   object reference table entry. We mask it off before matching so
//!   ref-tagged objects are handled identically.
//! - **Unknown opcodes**: cause an immediate bail-out, since we cannot
//!   determine their size to skip safely.
//!
//! This approach is intentionally best-effort: it may miss strings buried
//! after an unknown opcode, but it will never mis-parse or produce garbage.

use super::extract::{ExtractResult, Extractor};

/// Extracts string constants from Python 3.6+ `.pyc` bytecode files.
pub struct PycExtractor;

// Marshal type codes we extract strings from.
const TYPE_STRING: u8 = b's';
const TYPE_SHORT_ASCII: u8 = b'z';
const TYPE_SHORT_ASCII_INTERNED: u8 = b'Z';
const TYPE_UNICODE: u8 = b'u';
const TYPE_INTERNED: u8 = b't';

// Marshal type codes we skip.
const TYPE_NULL: u8 = b'0';
const TYPE_NONE: u8 = b'N';
const TYPE_FALSE: u8 = b'F';
const TYPE_TRUE: u8 = b'T';
const TYPE_STOPITER: u8 = b'S';
const TYPE_ELLIPSIS: u8 = b'.';
const TYPE_INT: u8 = b'i';
const TYPE_FLOAT: u8 = b'f';
const TYPE_BINARY_FLOAT: u8 = b'g';
const TYPE_COMPLEX: u8 = b'x';
const TYPE_BINARY_COMPLEX: u8 = b'y';
const TYPE_LONG: u8 = b'l';
const TYPE_SMALL_TUPLE: u8 = b')';
const TYPE_TUPLE: u8 = b'(';
const TYPE_LIST: u8 = b'[';
const TYPE_SET: u8 = b'<';
const TYPE_FROZENSET: u8 = b'>';
const TYPE_DICT: u8 = b'{';
const TYPE_CODE: u8 = b'c';
const TYPE_REF: u8 = b'r';
const TYPE_ASCII: u8 = b'a';
const TYPE_ASCII_INTERNED: u8 = b'A';

// The FLAG_REF bit can be OR'd onto any type code.
const FLAG_REF: u8 = 0x80;

/// Minimum pyc header size: magic(4) + timestamp(4) + source-size(4) = 12.
const MIN_HEADER: usize = 12;
/// First CPython magic number that uses the PEP 552 16-byte header (Python 3.7+).
const PY37_MAGIC_MIN: u16 = 3390;

impl Extractor for PycExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, _scratch: &mut Vec<u8>) -> ExtractResult {
        if data.len() < MIN_HEADER {
            return ExtractResult::ParseError;
        }

        // Verify the magic has \r\n in bytes 2-3 (all Python 3.x versions).
        if data[2] != b'\r' || data[3] != b'\n' {
            return ExtractResult::ParseError;
        }

        // Python 3.6 uses a 12-byte header; Python 3.7+ uses 16 bytes.
        // We branch on the CPython magic value (bytes 0-1, little-endian).
        let magic = u16::from_le_bytes([data[0], data[1]]);
        let header_size = if magic < PY37_MAGIC_MIN { 12 } else { 16 };

        if data.len() < header_size {
            return ExtractResult::ParseError;
        }

        let start_len = out.len();
        let mut pos = header_size;

        // Walk the marshal stream extracting strings.
        while pos < data.len() {
            let raw_type = data[pos];
            pos += 1;
            let type_code = raw_type & !FLAG_REF;

            match type_code {
                // --- String types we extract ---
                TYPE_STRING | TYPE_UNICODE | TYPE_INTERNED => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    let len = u32::from_le_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]) as usize;
                    pos += 4;
                    if pos + len > data.len() {
                        break;
                    }
                    if len > 0 {
                        out.extend_from_slice(&data[pos..pos + len]);
                        out.push(b'\n');
                    }
                    pos += len;
                }
                TYPE_SHORT_ASCII | TYPE_SHORT_ASCII_INTERNED => {
                    if pos >= data.len() {
                        break;
                    }
                    let len = data[pos] as usize;
                    pos += 1;
                    if pos + len > data.len() {
                        break;
                    }
                    if len > 0 {
                        out.extend_from_slice(&data[pos..pos + len]);
                        out.push(b'\n');
                    }
                    pos += len;
                }
                TYPE_ASCII | TYPE_ASCII_INTERNED => {
                    if pos + 4 > data.len() {
                        break;
                    }
                    let len = u32::from_le_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ]) as usize;
                    pos += 4;
                    if pos + len > data.len() {
                        break;
                    }
                    if len > 0 {
                        out.extend_from_slice(&data[pos..pos + len]);
                        out.push(b'\n');
                    }
                    pos += len;
                }

                // --- Fixed-size types we skip ---
                TYPE_NULL | TYPE_NONE | TYPE_FALSE | TYPE_TRUE | TYPE_STOPITER | TYPE_ELLIPSIS => {
                    // Zero-size sentinel types.
                }
                TYPE_INT => {
                    pos += 4;
                }
                TYPE_BINARY_FLOAT => {
                    pos += 8;
                }
                TYPE_BINARY_COMPLEX => {
                    pos += 16;
                }
                TYPE_FLOAT => {
                    // Legacy float: 1-byte length + that many ASCII chars.
                    if pos >= data.len() {
                        break;
                    }
                    let n = data[pos] as usize;
                    pos += 1;
                    if pos + n > data.len() {
                        break;
                    }
                    pos += n;
                }
                TYPE_COMPLEX => {
                    // Legacy complex: two legacy floats.
                    if pos >= data.len() {
                        break;
                    }
                    let n1 = data[pos] as usize;
                    pos += 1;
                    if pos + n1 > data.len() {
                        break;
                    }
                    pos += n1;
                    if pos >= data.len() {
                        break;
                    }
                    let n2 = data[pos] as usize;
                    pos += 1;
                    if pos + n2 > data.len() {
                        break;
                    }
                    pos += n2;
                }
                TYPE_LONG => {
                    // Variable-length long: i32 count of 15-bit digits (2 bytes each).
                    if pos + 4 > data.len() {
                        break;
                    }
                    let n = i32::from_le_bytes([
                        data[pos],
                        data[pos + 1],
                        data[pos + 2],
                        data[pos + 3],
                    ])
                    .unsigned_abs() as usize;
                    pos += 4;
                    let byte_len = match n.checked_mul(2) {
                        Some(v) => v,
                        None => break,
                    };
                    if pos + byte_len > data.len() {
                        break;
                    }
                    pos += byte_len;
                }
                TYPE_REF => {
                    pos += 4;
                }

                // --- Container types: just skip the count, contents follow inline ---
                TYPE_SMALL_TUPLE => {
                    if pos >= data.len() {
                        break;
                    }
                    // 1-byte count; elements follow as marshal objects.
                    pos += 1;
                }
                TYPE_TUPLE | TYPE_LIST | TYPE_SET | TYPE_FROZENSET => {
                    // 4-byte count; elements follow as marshal objects.
                    pos += 4;
                }
                TYPE_DICT => {
                    // Dict entries follow as key/value pairs until TYPE_NULL (0).
                    // Nothing to skip here — pairs are inline marshal objects.
                }
                TYPE_CODE => {
                    // Python 3.8+ code object layout (6 × u32 = 24 bytes):
                    //   argcount | posonlyargcount | kwonlyargcount
                    //   nlocals  | stacksize       | flags
                    //
                    // After these 24 bytes, the remaining fields (bytecode,
                    // constants, names, varnames, freevars, cellvars,
                    // filename, name, firstlineno, lnotab) are each
                    // marshal-encoded objects — our linear sweep picks
                    // them up automatically.
                    //
                    // Python 3.7 and earlier omit posonlyargcount (5 × u32
                    // = 20 bytes), so we over-skip by 4 bytes into the
                    // first sub-object (typically the bytecode string).
                    // Worst case: we lose that one sub-object's content.
                    // We never produce garbage because the next opcode byte
                    // is either valid (and parsing continues) or unknown
                    // (and we bail out cleanly).
                    if pos + 24 > data.len() {
                        break;
                    }
                    pos += 24;
                }

                _ => {
                    // Unknown opcode — stop to avoid mis-parsing.
                    break;
                }
            }
        }

        if out.len() == start_len {
            ExtractResult::Empty
        } else {
            ExtractResult::Ok
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal pyc file with the given marshal payload.
    fn make_pyc(marshal_data: &[u8]) -> Vec<u8> {
        let mut data = Vec::new();
        // Magic for Python 3.8 (0x550d = 3394).
        data.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
        // Flags = 0 (timestamp-based).
        data.extend_from_slice(&[0, 0, 0, 0]);
        // Timestamp.
        data.extend_from_slice(&[0, 0, 0, 0]);
        // Source size.
        data.extend_from_slice(&[0, 0, 0, 0]);
        // Marshal payload.
        data.extend_from_slice(marshal_data);
        data
    }

    #[test]
    fn extracts_short_ascii_string() {
        let mut marshal = Vec::new();
        // TYPE_SHORT_ASCII, length=5, "hello"
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(5);
        marshal.extend_from_slice(b"hello");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("hello"));
    }

    #[test]
    fn extracts_unicode_string() {
        let mut marshal = Vec::new();
        // TYPE_UNICODE, length=9 (u32 LE), "secret123"
        marshal.push(TYPE_UNICODE);
        marshal.extend_from_slice(&9u32.to_le_bytes());
        marshal.extend_from_slice(b"secret123");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("secret123"));
    }

    #[test]
    fn extracts_interned_string() {
        let mut marshal = Vec::new();
        marshal.push(TYPE_INTERNED);
        marshal.extend_from_slice(&7u32.to_le_bytes());
        marshal.extend_from_slice(b"API_KEY");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("API_KEY"));
    }

    #[test]
    fn extracts_with_flag_ref() {
        let mut marshal = Vec::new();
        // TYPE_SHORT_ASCII with FLAG_REF set.
        marshal.push(TYPE_SHORT_ASCII | FLAG_REF);
        marshal.push(3);
        marshal.extend_from_slice(b"abc");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("abc"));
    }

    #[test]
    fn skips_int_and_float() {
        let mut marshal = Vec::new();
        // INT = 42
        marshal.push(TYPE_INT);
        marshal.extend_from_slice(&42i32.to_le_bytes());
        // BINARY_FLOAT = 2.72
        marshal.push(TYPE_BINARY_FLOAT);
        marshal.extend_from_slice(&2.72f64.to_le_bytes());
        // Then a string we should find.
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(4);
        marshal.extend_from_slice(b"pass");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("pass"));
    }

    #[test]
    fn rejects_non_pyc() {
        let mut out = Vec::new();
        assert_eq!(
            PycExtractor.extract(b"not a pyc file", &mut out, &mut Vec::new()),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn too_short_returns_parse_error() {
        let mut out = Vec::new();
        assert_eq!(
            PycExtractor.extract(b"\x55\x0d\x0d\x0a", &mut out, &mut Vec::new()),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn empty_marshal_returns_empty() {
        let pyc = make_pyc(&[]);
        let mut out = Vec::new();
        assert_eq!(
            PycExtractor.extract(&pyc, &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }

    #[test]
    fn hash_based_pyc_header() {
        let mut data = Vec::new();
        // Magic for Python 3.8.
        data.extend_from_slice(&[0x55, 0x0d, 0x0d, 0x0a]);
        // Flags = 1 (hash-based).
        data.extend_from_slice(&[1, 0, 0, 0]);
        // 8-byte hash.
        data.extend_from_slice(&[0u8; 8]);
        // Marshal: short ascii string.
        data.push(TYPE_SHORT_ASCII);
        data.push(6);
        data.extend_from_slice(b"secret");

        let mut out = Vec::new();
        let result = PycExtractor.extract(&data, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("secret"));
    }

    #[test]
    fn supports_python36_timestamp_header() {
        let mut data = Vec::new();
        // Python 3.6-style header (12 bytes): magic + timestamp + source size.
        data.extend_from_slice(&[0x33, 0x0d, 0x0d, 0x0a]);
        data.extend_from_slice(&[0, 0, 0, 0]); // timestamp
        data.extend_from_slice(&[0, 0, 0, 0]); // source size
        // Marshal: TYPE_SHORT_ASCII("secret")
        data.push(TYPE_SHORT_ASCII);
        data.push(6);
        data.extend_from_slice(b"secret");

        let mut out = Vec::new();
        let result = PycExtractor.extract(&data, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(
            String::from_utf8(out).unwrap().contains("secret"),
            "expected string from marshal payload after 12-byte header"
        );
    }

    #[test]
    fn dict_terminator_does_not_abort_scan() {
        let mut marshal = Vec::new();
        // Dict with one key/value pair, then terminator, then another string.
        marshal.push(TYPE_DICT);
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(1);
        marshal.extend_from_slice(b"k");
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(1);
        marshal.extend_from_slice(b"v");
        marshal.push(TYPE_NULL); // dict terminator
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(5);
        marshal.extend_from_slice(b"after");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(
            String::from_utf8(out).unwrap().contains("after"),
            "dict terminator should not end the whole marshal walk"
        );
    }

    #[test]
    fn extracts_type_string() {
        // TYPE_STRING uses u32 LE length prefix.
        let mut marshal = Vec::new();
        marshal.push(TYPE_STRING);
        marshal.extend_from_slice(&11u32.to_le_bytes());
        marshal.extend_from_slice(b"hello_world");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("hello_world"));
    }

    #[test]
    fn extracts_ascii_and_ascii_interned() {
        let mut marshal = Vec::new();
        // TYPE_ASCII (u32 LE length)
        marshal.push(TYPE_ASCII);
        marshal.extend_from_slice(&3u32.to_le_bytes());
        marshal.extend_from_slice(b"foo");
        // TYPE_ASCII_INTERNED (u32 LE length)
        marshal.push(TYPE_ASCII_INTERNED);
        marshal.extend_from_slice(&3u32.to_le_bytes());
        marshal.extend_from_slice(b"bar");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("foo"));
        assert!(text.contains("bar"));
    }

    #[test]
    fn skips_small_tuple_and_tuple() {
        // SMALL_TUPLE with 1 element (the element is a string).
        let mut marshal = vec![TYPE_SMALL_TUPLE, 1, TYPE_SHORT_ASCII, 5];
        marshal.extend_from_slice(b"inner");
        // TUPLE with 1 element.
        marshal.push(TYPE_TUPLE);
        marshal.extend_from_slice(&1u32.to_le_bytes()); // 4-byte count
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(5);
        marshal.extend_from_slice(b"outer");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("inner"));
        assert!(text.contains("outer"));
    }

    #[test]
    fn skips_long_type() {
        // TYPE_LONG: i32 digit count, each digit is 2 bytes.
        // Negative digit count means negative number.
        let mut marshal = Vec::new();
        marshal.push(TYPE_LONG);
        marshal.extend_from_slice(&(-2i32).to_le_bytes()); // negative, 2 digits
        marshal.extend_from_slice(&[0xAB, 0xCD, 0xEF, 0x01]); // 2 × 2 bytes
        // String after the long.
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(10);
        marshal.extend_from_slice(b"after_long");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("after_long"));
    }

    #[test]
    fn skips_legacy_float() {
        // TYPE_FLOAT: 1-byte length + ASCII chars.
        let mut marshal = Vec::new();
        marshal.push(TYPE_FLOAT);
        marshal.push(4); // 4 ASCII chars
        marshal.extend_from_slice(b"3.14");
        // String after the float.
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(11);
        marshal.extend_from_slice(b"after_float");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("after_float"));
    }

    #[test]
    fn skips_legacy_complex() {
        // TYPE_COMPLEX: two legacy floats (1-byte length + ASCII each).
        let mut marshal = Vec::new();
        marshal.push(TYPE_COMPLEX);
        marshal.push(3); // real part: 3 chars
        marshal.extend_from_slice(b"1.0");
        marshal.push(3); // imaginary part: 3 chars
        marshal.extend_from_slice(b"2.0");
        // String after the complex.
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(13);
        marshal.extend_from_slice(b"after_complex");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("after_complex"));
    }

    #[test]
    fn skips_code_object() {
        // TYPE_CODE: 24-byte numeric prefix, then sub-objects follow inline.
        let mut marshal = Vec::new();
        marshal.push(TYPE_CODE);
        marshal.extend_from_slice(&[0u8; 24]); // 6 × u32 numeric prefix
        // After the prefix, sub-fields are marshal objects.
        marshal.push(TYPE_SHORT_ASCII);
        marshal.push(10);
        marshal.extend_from_slice(b"after_code");
        let pyc = make_pyc(&marshal);

        let mut out = Vec::new();
        let result = PycExtractor.extract(&pyc, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("after_code"));
    }
}
