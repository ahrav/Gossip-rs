//! Java `.class` file text extractor.
//!
//! Parses the constant pool to extract `CONSTANT_Utf8` entries, which contain
//! string literals, class names, method signatures, and other text that may
//! hold secrets.
//!
//! # Format
//!
//! A `.class` file starts with:
//! - `0xCAFEBABE` magic
//! - Minor/major version (4 bytes)
//! - Constant pool count (u16)
//! - Constant pool entries
//!
//! # Extraction strategy
//!
//! Only `CONSTANT_Utf8` entries (tag 1) are extracted — each is emitted as
//! a newline-terminated string. All other constant types are skipped by
//! their known fixed sizes (see JVM spec §4.4). We stop parsing at the end
//! of the constant pool and do not descend into fields, methods, or
//! attributes, because the constant pool already contains every string
//! literal referenced anywhere in the class.
//!
//! # Robustness
//!
//! - Truncated data causes an early exit (returns whatever was extracted
//!   so far, or `Empty` if nothing was).
//! - Unknown constant tags cause an immediate bail-out because we cannot
//!   determine their size to skip safely.
//! - `CONSTANT_Long` and `CONSTANT_Double` consume two constant pool
//!   slots per JVM spec §4.4.5.

use super::extract::{ExtractResult, Extractor};

/// Extracts `CONSTANT_Utf8` strings from a Java `.class` file's constant pool.
pub struct JavaClassExtractor;

const MAGIC: [u8; 4] = [0xCA, 0xFE, 0xBA, 0xBE];

// Constant pool tags.
const CONSTANT_UTF8: u8 = 1;
const CONSTANT_INTEGER: u8 = 3;
const CONSTANT_FLOAT: u8 = 4;
const CONSTANT_LONG: u8 = 5;
const CONSTANT_DOUBLE: u8 = 6;
const CONSTANT_CLASS: u8 = 7;
const CONSTANT_STRING: u8 = 8;
const CONSTANT_FIELDREF: u8 = 9;
const CONSTANT_METHODREF: u8 = 10;
const CONSTANT_INTERFACE_METHODREF: u8 = 11;
const CONSTANT_NAME_AND_TYPE: u8 = 12;
const CONSTANT_METHOD_HANDLE: u8 = 15;
const CONSTANT_METHOD_TYPE: u8 = 16;
const CONSTANT_DYNAMIC: u8 = 17;
const CONSTANT_INVOKE_DYNAMIC: u8 = 18;
const CONSTANT_MODULE: u8 = 19;
const CONSTANT_PACKAGE: u8 = 20;

impl Extractor for JavaClassExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, _scratch: &mut Vec<u8>) -> ExtractResult {
        if data.len() < 10 || data[..4] != MAGIC {
            return ExtractResult::ParseError;
        }

        // Skip magic (4) + minor (2) + major (2) = 8 bytes.
        let cp_count = u16::from_be_bytes([data[8], data[9]]) as usize;
        if cp_count < 1 {
            return ExtractResult::Empty;
        }

        let start_len = out.len();
        let mut pos = 10;
        // Constant pool indices are 1..cp_count (not 0-based).
        let mut i = 1;
        while i < cp_count {
            if pos >= data.len() {
                break;
            }
            let tag = data[pos];
            pos += 1;

            // Tags are grouped by their payload byte-size so each arm
            // advances `pos` by the correct amount (JVM spec §4.4).
            match tag {
                CONSTANT_UTF8 => {
                    if pos + 2 > data.len() {
                        break;
                    }
                    let len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
                    pos += 2;
                    if pos + len > data.len() {
                        break;
                    }
                    out.extend_from_slice(&data[pos..pos + len]);
                    out.push(b'\n');
                    pos += len;
                }
                CONSTANT_INTEGER | CONSTANT_FLOAT => {
                    pos += 4;
                }
                CONSTANT_LONG | CONSTANT_DOUBLE => {
                    pos += 8;
                    // Long and double take two constant pool entries.
                    i += 1;
                }
                CONSTANT_CLASS | CONSTANT_STRING | CONSTANT_METHOD_TYPE | CONSTANT_MODULE
                | CONSTANT_PACKAGE => {
                    pos += 2;
                }
                CONSTANT_FIELDREF
                | CONSTANT_METHODREF
                | CONSTANT_INTERFACE_METHODREF
                | CONSTANT_NAME_AND_TYPE
                | CONSTANT_DYNAMIC
                | CONSTANT_INVOKE_DYNAMIC => {
                    pos += 4;
                }
                CONSTANT_METHOD_HANDLE => {
                    pos += 3;
                }
                _ => {
                    // Unknown tag — cannot safely skip.
                    break;
                }
            }
            i += 1;
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

    fn make_class(utf8_strings: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0]); // minor
        data.extend_from_slice(&[0, 52]); // major (Java 8)
        let cp_count = (utf8_strings.len() + 1) as u16;
        data.extend_from_slice(&cp_count.to_be_bytes());
        for s in utf8_strings {
            data.push(CONSTANT_UTF8);
            let len = s.len() as u16;
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(s);
        }
        data
    }

    #[test]
    fn extracts_utf8_strings() {
        let class = make_class(&[b"com/example/App", b"SECRET_KEY"]);
        let mut out = Vec::new();
        let result = JavaClassExtractor.extract(&class, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("com/example/App"));
        assert!(text.contains("SECRET_KEY"));
    }

    #[test]
    fn rejects_non_class() {
        let mut out = Vec::new();
        assert_eq!(
            JavaClassExtractor.extract(b"not a class", &mut out, &mut Vec::new()),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn empty_constant_pool() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&1u16.to_be_bytes()); // cp_count=1 means no entries
        let mut out = Vec::new();
        assert_eq!(
            JavaClassExtractor.extract(&data, &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }

    #[test]
    fn skips_long_and_double_entries() {
        // Long and Double consume two constant pool slots.
        // Layout: LONG(8 bytes, 2 slots) + UTF8("found")
        // cp_count = 4 (index 1=long, 2=phantom, 3=utf8)
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&4u16.to_be_bytes()); // cp_count=4
        // Entry 1: CONSTANT_Long (takes slots 1 and 2)
        data.push(CONSTANT_LONG);
        data.extend_from_slice(&[0u8; 8]);
        // Entry 3: CONSTANT_Utf8
        data.push(CONSTANT_UTF8);
        data.extend_from_slice(&5u16.to_be_bytes());
        data.extend_from_slice(b"found");

        let mut out = Vec::new();
        let result = JavaClassExtractor.extract(&data, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("found"));
    }

    #[test]
    fn skips_method_handle() {
        // CONSTANT_MethodHandle is 3 bytes (unique size).
        // Layout: MethodHandle(3 bytes) + UTF8("after_handle")
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&3u16.to_be_bytes());
        // Entry 1: CONSTANT_MethodHandle (1 byte ref_kind + 2 byte ref_index)
        data.push(CONSTANT_METHOD_HANDLE);
        data.extend_from_slice(&[5, 0, 1]); // ref_kind=5, ref_index=1
        // Entry 2: CONSTANT_Utf8
        data.push(CONSTANT_UTF8);
        data.extend_from_slice(&12u16.to_be_bytes());
        data.extend_from_slice(b"after_handle");

        let mut out = Vec::new();
        let result = JavaClassExtractor.extract(&data, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("after_handle"));
    }

    #[test]
    fn truncated_utf8_entry_bails() {
        // Data ends in the middle of a UTF8 string's content.
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&2u16.to_be_bytes());
        data.push(CONSTANT_UTF8);
        data.extend_from_slice(&10u16.to_be_bytes()); // claims 10 bytes
        data.extend_from_slice(b"short"); // only 5 bytes

        let mut out = Vec::new();
        let result = JavaClassExtractor.extract(&data, &mut out, &mut Vec::new());
        // Should bail without extracting the truncated string.
        assert_eq!(result, ExtractResult::Empty);
    }

    #[test]
    fn unknown_tag_bails_gracefully() {
        // An unknown tag (e.g. 99) should stop parsing without panic.
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&3u16.to_be_bytes());
        // Entry 1: UTF8 (extracted)
        data.push(CONSTANT_UTF8);
        data.extend_from_slice(&5u16.to_be_bytes());
        data.extend_from_slice(b"hello");
        // Entry 2: unknown tag
        data.push(99);
        data.extend_from_slice(&[0; 10]); // trailing garbage

        let mut out = Vec::new();
        let result = JavaClassExtractor.extract(&data, &mut out, &mut Vec::new());
        // Should have extracted the first string before bailing.
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("hello"));
    }

    #[test]
    fn cp_count_zero_returns_empty() {
        let mut data = Vec::new();
        data.extend_from_slice(&MAGIC);
        data.extend_from_slice(&[0, 0, 0, 52]);
        data.extend_from_slice(&0u16.to_be_bytes()); // cp_count=0
        let mut out = Vec::new();
        assert_eq!(
            JavaClassExtractor.extract(&data, &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }
}
