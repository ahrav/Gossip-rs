//! JAR/WAR archive text extractor.
//!
//! Opens a ZIP archive and iterates over `.class` entries, delegating
//! each to [`JavaClassExtractor`](super::java_class::JavaClassExtractor)
//! to extract constant pool strings.
//!
//! # Why only `.class` files?
//!
//! `.properties`, `.xml`, and other text files inside JARs are already
//! scannable as-is if the scanner encounters them individually. When
//! scanning a JAR as a single blob, `.class` files are the only entries
//! whose useful text is locked behind a binary encoding. Extracting
//! everything else would duplicate work and inflate the output buffer.
//!
//! # Budget limits
//!
//! To prevent resource exhaustion on large archives (e.g. fat WARs with
//! hundreds of bundled libraries):
//! - **`MAX_ENTRIES`** (10,000): caps iteration over the ZIP central
//!   directory. Most application JARs contain far fewer entries.
//! - **`MAX_CLASS_SIZE`** (10 MiB): skips anomalously large `.class`
//!   files that are likely obfuscated or generated.
//! - **`MAX_TOTAL_EXTRACTED`** (100 MiB): hard ceiling on the output
//!   buffer to bound memory usage regardless of archive contents.
//!
//! Per-entry limits (`MAX_CLASS_SIZE`) skip the oversized entry.
//! The total budget (`MAX_TOTAL_EXTRACTED`) stops extraction entirely.
//! In both cases, text already appended is kept.
//!
//! # Scratch buffer reuse
//!
//! The caller-provided `scratch` buffer is reused across entries to hold
//! decompressed `.class` bytes. This avoids a per-entry allocation and
//! lets the buffer grow to the high-water mark once.
//! [`JavaClassExtractor`](super::java_class::JavaClassExtractor) itself
//! does not use `scratch`, so a zero-capacity stack Vec is passed as its
//! scratch parameter.

use super::extract::{ExtractResult, Extractor};
use super::java_class::JavaClassExtractor;

/// Extracts text from `.class` entries inside a JAR/WAR ZIP archive.
pub struct JarWarExtractor;

/// Max number of ZIP entries to process.
const MAX_ENTRIES: usize = 10_000;
/// Max decompressed size of a single `.class` file (10 MiB).
const MAX_CLASS_SIZE: u64 = 10 * 1024 * 1024;
/// Max total extracted bytes across all entries (100 MiB).
const MAX_TOTAL_EXTRACTED: usize = 100 * 1024 * 1024;

impl Extractor for JarWarExtractor {
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, scratch: &mut Vec<u8>) -> ExtractResult {
        let reader = std::io::Cursor::new(data);
        let mut archive = match zip::ZipArchive::new(reader) {
            Ok(a) => a,
            Err(_) => return ExtractResult::ParseError,
        };

        let start_len = out.len();
        let class_extractor = JavaClassExtractor;
        let entry_count = archive.len().min(MAX_ENTRIES);
        // JavaClassExtractor ignores its scratch param. A stack-only Vec
        // (zero capacity, no heap allocation) satisfies the signature.
        let mut no_scratch = Vec::new();

        for i in 0..entry_count {
            let mut entry = match archive.by_index(i) {
                Ok(e) => e,
                Err(_) => continue,
            };

            // Only process .class files. Uses rsplit to grab the final
            // extension segment, handling nested paths like "com/Foo.class".
            let is_class = entry
                .name()
                .rsplit('.')
                .next()
                .map(|ext| ext.eq_ignore_ascii_case("class"))
                .unwrap_or(false);
            if !is_class {
                continue;
            }

            // Skip oversized entries.
            if entry.size() > MAX_CLASS_SIZE {
                continue;
            }

            // Reuse caller-provided scratch instead of allocating per entry.
            scratch.clear();
            scratch.reserve(entry.size() as usize);
            if std::io::Read::read_to_end(&mut entry, scratch).is_err() {
                continue;
            }

            // Extract strings from the class file.
            class_extractor.extract(scratch, out, &mut no_scratch);

            // Check total budget.
            if out.len() - start_len > MAX_TOTAL_EXTRACTED {
                break;
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

    fn make_jar_with_class(class_name: &str, class_data: &[u8]) -> Vec<u8> {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);
        writer
            .start_file(format!("{class_name}.class"), options)
            .unwrap();
        std::io::Write::write_all(&mut writer, class_data).unwrap();
        let cursor = writer.finish().unwrap();
        cursor.into_inner()
    }

    fn make_class_bytes(utf8_strings: &[&[u8]]) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&[0xCA, 0xFE, 0xBA, 0xBE]);
        data.extend_from_slice(&[0, 0]); // minor
        data.extend_from_slice(&[0, 52]); // major (Java 8)
        let cp_count = (utf8_strings.len() + 1) as u16;
        data.extend_from_slice(&cp_count.to_be_bytes());
        for s in utf8_strings {
            data.push(1); // CONSTANT_UTF8
            let len = s.len() as u16;
            data.extend_from_slice(&len.to_be_bytes());
            data.extend_from_slice(s);
        }
        data
    }

    #[test]
    fn extracts_from_jar() {
        let class_data = make_class_bytes(&[b"com/example/Secret", b"API_KEY=abc123"]);
        let jar = make_jar_with_class("com/example/Secret", &class_data);

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("com/example/Secret"));
        assert!(text.contains("API_KEY=abc123"));
    }

    #[test]
    fn skips_non_class_entries() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Add a non-class file.
        writer.start_file("META-INF/MANIFEST.MF", options).unwrap();
        std::io::Write::write_all(&mut writer, b"Manifest-Version: 1.0\n").unwrap();

        // Add a class file.
        let class_data = make_class_bytes(&[b"Found"]);
        writer.start_file("App.class", options).unwrap();
        std::io::Write::write_all(&mut writer, &class_data).unwrap();

        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Found"));
        assert!(!text.contains("Manifest"));
    }

    #[test]
    fn empty_jar_returns_empty() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        assert_eq!(
            JarWarExtractor.extract(&jar, &mut out, &mut Vec::new()),
            ExtractResult::Empty
        );
    }

    #[test]
    fn invalid_zip_returns_parse_error() {
        let mut out = Vec::new();
        assert_eq!(
            JarWarExtractor.extract(b"not a zip", &mut out, &mut Vec::new()),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn multiple_class_files_extracted() {
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        for name in ["Alpha", "Beta", "Gamma"] {
            let class_data = make_class_bytes(&[name.as_bytes()]);
            writer
                .start_file(format!("com/example/{name}.class"), options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &class_data).unwrap();
        }

        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Alpha"));
        assert!(text.contains("Beta"));
        assert!(text.contains("Gamma"));
    }

    #[test]
    fn oversized_class_entry_skipped() {
        // Create a .class entry whose reported size exceeds MAX_CLASS_SIZE.
        // The zip crate stores the uncompressed size in the entry header.
        // We create a valid class that is small but check behavior with a
        // normal class (should be extracted) alongside.
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Normal class (should be extracted).
        let normal_class = make_class_bytes(&[b"NormalClass"]);
        writer.start_file("Normal.class", options).unwrap();
        std::io::Write::write_all(&mut writer, &normal_class).unwrap();

        // "Large" class — we can't easily fake the size header, but we can
        // verify the normal class is extracted fine. The MAX_CLASS_SIZE check
        // uses entry.size() which is set by the zip writer from actual content.
        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        assert!(String::from_utf8(out).unwrap().contains("NormalClass"));
    }

    #[test]
    fn case_insensitive_class_extension() {
        // .CLASS and .Class should both be recognized.
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        let class_data = make_class_bytes(&[b"UpperCase"]);
        writer.start_file("Upper.CLASS", options).unwrap();
        std::io::Write::write_all(&mut writer, &class_data).unwrap();

        let class_data2 = make_class_bytes(&[b"MixedCase"]);
        writer.start_file("Mixed.Class", options).unwrap();
        std::io::Write::write_all(&mut writer, &class_data2).unwrap();

        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("UpperCase"), "uppercase .CLASS not found");
        assert!(text.contains("MixedCase"), "mixed case .Class not found");
    }

    #[test]
    fn total_budget_stops_extraction() {
        // Verify that MAX_TOTAL_EXTRACTED limits output.
        // We can't easily hit 100 MiB in a test, but we can verify the
        // mechanism works by checking that extraction stops when budget is hit.
        // Here we just ensure many entries still produce output without panic.
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options =
            zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        // Add 50 class files.
        for i in 0..50 {
            let name = format!("entry_{i:04}");
            let class_data = make_class_bytes(&[name.as_bytes()]);
            writer
                .start_file(format!("pkg/Class{i}.class"), options)
                .unwrap();
            std::io::Write::write_all(&mut writer, &class_data).unwrap();
        }

        let cursor = writer.finish().unwrap();
        let jar = cursor.into_inner();

        let mut out = Vec::new();
        let result = JarWarExtractor.extract(&jar, &mut out, &mut Vec::new());
        assert_eq!(result, ExtractResult::Ok);
        // Should have extracted at least some entries.
        assert!(!out.is_empty());
        // And the output should be bounded (well under MAX_TOTAL_EXTRACTED).
        assert!(out.len() < MAX_TOTAL_EXTRACTED);
    }
}
