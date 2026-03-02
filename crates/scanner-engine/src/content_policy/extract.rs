//! Content extraction framework.
//!
//! Defines the [`Extractor`] trait and a format-aware dispatcher that routes
//! [`ExtractableFormat`] variants to the appropriate extractor implementation.
//!
//! # Architecture
//!
//! Each supported format has a dedicated [`Extractor`] implementation
//! that knows how to parse the format and emit any embedded text (string
//! literals, code cells, constant pool entries, etc.) that a secret-scanning
//! engine can then match against.
//!
//! Callers interact with [`extract_content`] only — it clears the output
//! buffer and dispatches to the correct extractor, keeping the caller
//! decoupled from individual format parsers.

use super::ExtractableFormat;

/// Result of a text extraction attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractResult {
    /// Extraction succeeded; `out` contains scannable text.
    Ok,
    /// Extraction succeeded but the file contained no scannable content.
    Empty,
    /// The input could not be parsed (corrupt or unsupported version).
    ParseError,
}

/// Pre-allocation hint for extraction input buffers.
pub const EXTRACT_INPUT_CAP: usize = 64 * 1024;
/// Pre-allocation hint for extraction output buffers.
pub const EXTRACT_OUTPUT_CAP: usize = 32 * 1024;
/// Pre-allocation hint for JAR entry scratch buffers.
pub const JAR_ENTRY_CAP: usize = 32 * 1024;

/// Trait for extracting scannable text from a known format.
///
/// Implementors parse a single format (e.g. `.class`, `.pyc`, `.env`) and append
/// any human-readable strings to the output buffer. The extracted text
/// need not be valid UTF-8 — the scan engine treats it as raw bytes.
///
/// # Contract
///
/// - Implementations **append** to `out`; they must not clear it.
///   (`extract_content` handles clearing before dispatch.)
/// - On [`ExtractResult::ParseError`] or [`ExtractResult::Empty`], `out`
///   must be left unchanged from its state at entry.
/// - Implementations must not panic on arbitrary input. Malformed data
///   must not crash. Extractors may return [`ExtractResult::ParseError`] when
///   they can confidently reject a format, or [`ExtractResult::Empty`] for
///   best-effort early bails on truncated/unknown content.
/// - `scratch` is a caller-provided temporary workspace that extractors
///   may use for intermediate allocations (e.g. decompressing JAR entries).
///   Callers should pass a pre-allocated buffer; extractors that don't
///   need it simply ignore it.
pub trait Extractor {
    /// Append scannable text extracted from `data` to `out`.
    ///
    /// Returns [`ExtractResult::Ok`] when at least one byte was appended,
    /// [`ExtractResult::Empty`] when no bytes were appended (including valid
    /// no-text inputs and best-effort parse bail-outs), or
    /// [`ExtractResult::ParseError`] when `data` is definitively rejected for
    /// this format.
    fn extract(&self, data: &[u8], out: &mut Vec<u8>, scratch: &mut Vec<u8>) -> ExtractResult;
}

/// Dispatch extraction to the appropriate format handler.
///
/// Clears `out` before dispatching so callers always receive a clean
/// buffer. Individual extractor types are public (for testing and
/// benchmarking) but production code should use this function — it
/// owns the clear-before-dispatch invariant that [`Extractor::extract`]
/// relies on.
pub fn extract_content(
    format: ExtractableFormat,
    data: &[u8],
    out: &mut Vec<u8>,
    scratch: &mut Vec<u8>,
) -> ExtractResult {
    out.clear();
    match format {
        ExtractableFormat::DotEnv => super::dotenv::DotEnvExtractor.extract(data, out, scratch),
        ExtractableFormat::Ipynb => super::ipynb::IpynbExtractor.extract(data, out, scratch),
        ExtractableFormat::JavaClass => {
            super::java_class::JavaClassExtractor.extract(data, out, scratch)
        }
        ExtractableFormat::JarWar => super::jar_war::JarWarExtractor.extract(data, out, scratch),
        ExtractableFormat::Pyc => super::pyc::PycExtractor.extract(data, out, scratch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn java_class_dispatches_correctly() {
        // Truncated / invalid class data should return ParseError.
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            extract_content(
                ExtractableFormat::JavaClass,
                b"\xCA\xFE",
                &mut out,
                &mut scratch
            ),
            ExtractResult::ParseError
        );
        assert!(out.is_empty());
    }

    #[test]
    fn pyc_dispatches_correctly() {
        // Too-short data should return ParseError.
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            extract_content(ExtractableFormat::Pyc, b"\x55\x0d", &mut out, &mut scratch),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn jar_dispatches_correctly() {
        // Invalid zip should return ParseError.
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            extract_content(
                ExtractableFormat::JarWar,
                b"not a zip",
                &mut out,
                &mut scratch
            ),
            ExtractResult::ParseError
        );
    }

    #[test]
    fn dotenv_dispatches_correctly() {
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        assert_eq!(
            extract_content(
                ExtractableFormat::DotEnv,
                b"export API_KEY=\"abc\\n123\"\n",
                &mut out,
                &mut scratch
            ),
            ExtractResult::Ok
        );
        assert_eq!(out, b"API_KEY=abc\n123\n");
    }
}
