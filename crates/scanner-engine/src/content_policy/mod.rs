//! Content classification for binary-aware scanning.
//!
//! Provides a unified policy for deciding whether file content should be
//! scanned as text, skipped as binary, or have text extracted from a known
//! extractable format (`.ipynb`, `.class`, `.jar`/`.war`, `.pyc`, `.env`).
//!
//! The primary entry point is [`classify_content`], which combines a NUL-byte
//! heuristic with extension matching to produce a [`ContentVerdict`].
//!
//! # Design
//!
//! - No heap allocation.
//! - Extension matching is case-insensitive on ASCII bytes.
//! - The NUL-byte heuristic is inspired by Git's `buffer_is_binary` (same
//!   technique, different check length: 8192 vs Git's 8000) and uses
//!   `memchr` for SIMD-accelerated scanning.

pub mod dotenv;
pub mod extract;
pub mod ipynb;
pub mod jar_war;
pub mod java_class;
pub mod pyc;

/// Number of leading bytes to inspect for the NUL-byte heuristic.
pub const CHECK_LEN: usize = 8192;

/// Classification verdict for file content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentVerdict {
    /// Content appears to be text — scan normally.
    Text,
    /// Content appears to be binary — skip unless `--scan-binary` is set.
    Binary,
    /// Content is a known format from which text can be extracted.
    BinaryExtractable(ExtractableFormat),
}

/// Formats that have a known text-extraction strategy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtractableFormat {
    /// Dotenv environment files (`.env`, `.env.*`).
    DotEnv,
    /// Jupyter Notebook (JSON with code cells).
    Ipynb,
    /// Compiled Java class file.
    JavaClass,
    /// Java archive (JAR/WAR) containing `.class` files.
    JarWar,
    /// Python compiled bytecode.
    Pyc,
}

impl ExtractableFormat {
    /// Returns `true` for formats extracted from text content (no NUL bytes
    /// required). Binary-only formats (`.class`, `.jar`, `.pyc`) return
    /// `false` — a NUL-free file with those extensions is likely a misnamed
    /// text file that should be scanned as-is rather than extracted.
    pub const fn extracts_from_text(&self) -> bool {
        matches!(self, Self::DotEnv | Self::Ipynb)
    }
}

/// Returns `true` if the first `check_len` bytes of `data` contain a NUL byte,
/// indicating the content is likely binary (images, compiled objects, etc.).
///
/// Uses `memchr` for SIMD-accelerated scanning, inspired by Git's
/// `buffer_is_binary` heuristic (same technique, different check length).
/// Empty data is not considered binary.
#[inline]
pub fn is_likely_binary(data: &[u8], check_len: usize) -> bool {
    if data.is_empty() {
        return false;
    }
    let end = data.len().min(check_len);
    memchr::memchr(0, &data[..end]).is_some()
}

/// Classify content by inspecting bytes and the file path extension.
///
/// 1. Check for NUL bytes in the first `check_len` bytes.
/// 2. If no NUL bytes:
///    - `.ipynb` is [`ContentVerdict::BinaryExtractable`] so code/markdown
///      cells can be extracted.
///    - `.env` / `.env.*` are [`ContentVerdict::BinaryExtractable`] so
///      structured `KEY=VALUE` lines can be extracted.
///    - otherwise classify as [`ContentVerdict::Text`].
/// 3. If NUL bytes are present: check extension for extractable formats →
///    [`ContentVerdict::BinaryExtractable`]; otherwise → [`ContentVerdict::Binary`].
///
/// Empty data returns [`ContentVerdict::Text`] unless the path is `.ipynb`,
/// `.env`, or `.env.*`.
#[inline]
pub fn classify_content(data: &[u8], path: &[u8], check_len: usize) -> ContentVerdict {
    if !is_likely_binary(data, check_len) {
        // .ipynb files are JSON (text) but we still want to classify them as
        // extractable so the extractor can pull code cells only (ignoring
        // output blobs). .env files are also text but benefit from structured
        // extraction (comment stripping + quote handling). Other extractable
        // extensions (.class, .jar, .war, .pyc) should only trigger
        // extraction when the data actually contains NUL bytes — otherwise a
        // misnamed text file would be silently skipped instead of scanned.
        if let Some(fmt) = match_extractable_format(path) {
            if fmt.extracts_from_text() {
                return ContentVerdict::BinaryExtractable(fmt);
            }
        }
        return ContentVerdict::Text;
    }

    // Binary content — check if we know how to extract text from it.
    match match_extractable_format(path) {
        Some(fmt) => ContentVerdict::BinaryExtractable(fmt),
        None => ContentVerdict::Binary,
    }
}

/// Match a file path against known extractable formats.
///
/// Dotenv is matched by basename first (`.env`, `.env.*`), then other formats
/// are matched by extension.
fn match_extractable_format(path: &[u8]) -> Option<ExtractableFormat> {
    if is_dotenv_basename(path) {
        return Some(ExtractableFormat::DotEnv);
    }
    let ext = file_extension(path)?;
    if eq_ignore_ascii_case(ext, b"ipynb") {
        return Some(ExtractableFormat::Ipynb);
    }
    if eq_ignore_ascii_case(ext, b"class") {
        return Some(ExtractableFormat::JavaClass);
    }
    if eq_ignore_ascii_case(ext, b"jar") || eq_ignore_ascii_case(ext, b"war") {
        return Some(ExtractableFormat::JarWar);
    }
    if eq_ignore_ascii_case(ext, b"pyc") {
        return Some(ExtractableFormat::Pyc);
    }
    None
}

/// Extract the filename component from a byte path.
///
/// Splits on both `/` (POSIX) and `\` (Windows) separators so that
/// extension and basename matching works regardless of path origin
/// (git tree objects use `/`; Windows filesystem paths use `\`).
#[inline]
fn file_name(path: &[u8]) -> &[u8] {
    let name_start = memchr::memrchr2(b'/', b'\\', path)
        .map(|idx| idx + 1)
        .unwrap_or(0);
    &path[name_start..]
}

/// Returns `true` for dotenv basenames (`.env` and `.env.*`).
///
/// Matching is case-insensitive on ASCII bytes (e.g. `.ENV`, `.Env.Local`
/// also match). Similar names like `.envrc` intentionally do not match.
fn is_dotenv_basename(path: &[u8]) -> bool {
    let name = file_name(path);
    if name.len() < 4 || !eq_ignore_ascii_case(&name[..4], b".env") {
        return false;
    }
    name.len() == 4 || name[4] == b'.'
}

/// Extract the file extension from a byte path (after the last `.` in the filename).
///
/// Returns `None` for dotfiles, paths ending in `.`, or paths with no extension.
fn file_extension(path: &[u8]) -> Option<&[u8]> {
    let name = file_name(path);
    let dot = memchr::memrchr(b'.', name)?;
    if dot == 0 {
        return None;
    }
    let ext = &name[dot + 1..];
    if ext.is_empty() { None } else { Some(ext) }
}

/// Case-insensitive ASCII byte comparison.
///
/// `b` must be all-lowercase for correct results.
fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).all(|(&x, &y)| x.to_ascii_lowercase() == y)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- is_likely_binary ----

    #[test]
    fn empty_data_is_not_binary() {
        assert!(!is_likely_binary(b"", CHECK_LEN));
    }

    #[test]
    fn pure_text_is_not_binary() {
        assert!(!is_likely_binary(b"hello world\n", CHECK_LEN));
    }

    #[test]
    fn nul_at_start_is_binary() {
        assert!(is_likely_binary(b"\0hello", CHECK_LEN));
    }

    #[test]
    fn nul_beyond_check_len_not_detected() {
        let mut data = vec![b'a'; 100];
        data.push(0);
        assert!(!is_likely_binary(&data, 100));
    }

    #[test]
    fn nul_at_exact_boundary_detected() {
        let mut data = vec![b'a'; 99];
        data.push(0);
        assert!(is_likely_binary(&data, 100));
    }

    // ---- classify_content ----

    #[test]
    fn text_file_classified_as_text() {
        let data = b"fn main() { println!(\"hello\"); }";
        assert_eq!(
            classify_content(data, b"src/main.rs", CHECK_LEN),
            ContentVerdict::Text
        );
    }

    #[test]
    fn binary_file_classified_as_binary() {
        let mut data = vec![b'a'; 100];
        data[50] = 0;
        assert_eq!(
            classify_content(&data, b"image.png", CHECK_LEN),
            ContentVerdict::Binary
        );
    }

    #[test]
    fn nul_free_extractable_binary_extensions_classify_as_text() {
        let data = b"SECRET in plain text";
        for path in [
            b"Foo.class".as_slice(),
            b"app.jar".as_slice(),
            b"app.war".as_slice(),
            b"module.pyc".as_slice(),
        ] {
            assert_eq!(
                classify_content(data, path, CHECK_LEN),
                ContentVerdict::Text,
                "expected text classification for path {:?}",
                String::from_utf8_lossy(path)
            );
        }
    }

    #[test]
    fn ipynb_text_content_classified_as_extractable() {
        let data = b"{\"cells\": []}";
        assert_eq!(
            classify_content(data, b"notebook.ipynb", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::Ipynb)
        );
    }

    #[test]
    fn ipynb_binary_content_classified_as_extractable() {
        let mut data = vec![b'{'; 100];
        data[50] = 0;
        assert_eq!(
            classify_content(&data, b"notebook.ipynb", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::Ipynb)
        );
    }

    #[test]
    fn dotenv_text_content_classified_as_extractable() {
        let data = b"API_KEY=abc123";
        assert_eq!(
            classify_content(data, b".env", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::DotEnv)
        );
    }

    #[test]
    fn dotenv_suffix_content_classified_as_extractable() {
        let data = b"DB_PASSWORD=supersecret";
        assert_eq!(
            classify_content(data, b"config/.env.local", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::DotEnv)
        );
    }

    #[test]
    fn non_dotenv_dotfile_is_not_extractable() {
        let data = b"SECRET in plain text";
        assert_eq!(
            classify_content(data, b".envrc", CHECK_LEN),
            ContentVerdict::Text
        );
    }

    // ---- file_name helper ----

    #[test]
    fn file_name_posix_path() {
        assert_eq!(file_name(b"src/content_policy/mod.rs"), b"mod.rs");
    }

    #[test]
    fn file_name_windows_path() {
        assert_eq!(file_name(b"src\\content_policy\\mod.rs"), b"mod.rs");
    }

    #[test]
    fn file_name_mixed_separators() {
        assert_eq!(file_name(b"C:\\Users\\dev/projects\\.env"), b".env");
    }

    #[test]
    fn file_name_no_separator() {
        assert_eq!(file_name(b".env"), b".env");
    }

    #[test]
    fn file_name_trailing_separator() {
        // Trailing separator yields an empty filename (caller never produces
        // this, but the function handles it gracefully).
        assert_eq!(file_name(b"dir/"), b"");
        assert_eq!(file_name(b"dir\\"), b"");
    }

    // ---- file_extension helper ----

    #[test]
    fn extension_from_simple_path() {
        assert_eq!(file_extension(b"foo.txt"), Some(b"txt".as_slice()));
    }

    #[test]
    fn extension_from_nested_path() {
        assert_eq!(
            file_extension(b"src/main/Foo.java"),
            Some(b"java".as_slice())
        );
    }

    #[test]
    fn extension_from_windows_path() {
        assert_eq!(
            file_extension(b"src\\main\\Foo.java"),
            Some(b"java".as_slice())
        );
    }

    #[test]
    fn no_extension() {
        assert_eq!(file_extension(b"Makefile"), None);
    }

    #[test]
    fn dotfile_no_extension() {
        assert_eq!(file_extension(b".gitignore"), None);
    }

    #[test]
    fn trailing_dot_no_extension() {
        assert_eq!(file_extension(b"foo."), None);
    }

    #[test]
    fn double_extension_takes_last() {
        assert_eq!(file_extension(b"archive.tar.gz"), Some(b"gz".as_slice()));
    }

    // ---- case-insensitive extension matching ----

    #[test]
    fn mixed_case_extensions_classify_correctly() {
        // Binary data (contains NUL) with various case extensions.
        let bin = b"\xCA\xFE\xBA\xBE\x00";
        for (path, expected_fmt) in [
            (&b"app.JAR"[..], ExtractableFormat::JarWar),
            (b"Foo.ClAsS", ExtractableFormat::JavaClass),
            (b"app.WAR", ExtractableFormat::JarWar),
            (b"mod.PYC", ExtractableFormat::Pyc),
            (b"nb.IPYNB", ExtractableFormat::Ipynb),
            (b".ENV", ExtractableFormat::DotEnv),
        ] {
            assert_eq!(
                classify_content(bin, path, CHECK_LEN),
                ContentVerdict::BinaryExtractable(expected_fmt),
                "case-insensitive match failed for {:?}",
                String::from_utf8_lossy(path),
            );
        }
    }

    // ---- empty / edge cases ----

    #[test]
    fn empty_path_with_binary_data() {
        let data = b"\x00\x01\x02";
        assert_eq!(
            classify_content(data, b"", CHECK_LEN),
            ContentVerdict::Binary
        );
    }

    // ---- Windows-style paths through classify_content ----

    #[test]
    fn dotenv_detected_with_windows_backslash_path() {
        let data = b"SECRET_KEY=abc";
        assert_eq!(
            classify_content(data, b"C:\\Users\\dev\\config\\.env", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::DotEnv)
        );
    }

    #[test]
    fn dotenv_suffix_detected_with_windows_path() {
        let data = b"DB_PASS=secret";
        assert_eq!(
            classify_content(data, b"projects\\myapp\\.env.production", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::DotEnv)
        );
    }

    #[test]
    fn extractable_binary_detected_with_windows_path() {
        let bin = b"\xCA\xFE\xBA\xBE\x00";
        assert_eq!(
            classify_content(bin, b"lib\\deps\\Foo.class", CHECK_LEN),
            ContentVerdict::BinaryExtractable(ExtractableFormat::JavaClass)
        );
    }

    #[test]
    fn non_dotenv_not_matched_with_windows_path() {
        let data = b"some text";
        assert_eq!(
            classify_content(data, b"config\\.envrc", CHECK_LEN),
            ContentVerdict::Text
        );
    }
}
