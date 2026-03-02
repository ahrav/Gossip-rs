//! Archive kind detection.
//!
//! Maps filenames and magic-byte headers to [`ArchiveKind`] so the scanner can
//! choose the right streaming decoder without I/O or allocation.
//!
//! # Invariants
//! - Detection is case-insensitive and suffix-based.
//! - `.tar.gz` / `.tgz` are treated as [`ArchiveKind::TarGz`].
//! - `.tar.bz2` / `.tbz2` are treated as [`ArchiveKind::TarBz2`].
//! - Extension-based detection has strict precedence over magic-byte sniffing;
//!   this is the only way to distinguish `.tar.gz` from plain `.gz` and
//!   `.tar.bz2` from plain `.bz2`.
//!
//! # Algorithm
//! 1. Try extension-based detection ([`detect_kind_from_path`] / [`detect_kind_from_name_bytes`]).
//!    This is a pure byte-suffix match — no I/O, no allocation.
//! 2. If the extension is unrecognized, optionally sniff magic bytes via
//!    [`sniff_kind_from_header`].
//!
//! # Design Notes
//! - Magic sniffing cannot distinguish `.tar.gz` from `.gz` without decompressing,
//!   so extensions always win for `TarGz`.
//! - The byte-level suffix matcher uses `| 0x20` for ASCII case-folding. This is
//!   correct for the extension alphabet (`[a-zA-Z.]`) but is *not* a general
//!   Unicode lowercase operation — which is fine because archive extensions are
//!   ASCII by definition.

use std::path::Path;

use super::formats::{is_bzip2_magic, is_gzip_magic, is_ustar_header, is_zip_magic};

/// Archive container kind.
///
/// Determines which streaming decoder the scanner instantiates. The key
/// distinction is between *containers* (multiple entries to iterate) and
/// *single-stream* formats:
///
/// | Kind   | Entries     | Access pattern           |
/// |--------|-------------|--------------------------|
/// | `Tar`  | many        | sequential (512-B blocks)|
/// | `Zip`  | many        | random-access via EOCD   |
/// | `TarGz`| many (chain)| sequential gzip → tar    |
/// | `TarBz2`| many (chain)| sequential bzip2 → tar  |
/// | `Gzip` | one         | sequential decompression |
/// | `Bzip2`| one         | sequential decompression |
///
/// `TarGz` represents a gzip-compressed tar stream (container semantics),
/// while `Gzip` represents a standalone gzip stream. Both start with the
/// same `1f 8b` magic bytes — only the filename extension distinguishes them.
/// `TarBz2` and `Bzip2` follow the same distinction for `BZh` streams.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ArchiveKind {
    /// Standalone gzip stream — single decompressed blob, no entry iteration.
    Gzip = 0,
    /// Uncompressed tar archive — sequential 512-byte header blocks.
    Tar = 1,
    /// Zip archive — random-access via end-of-central-directory record.
    Zip = 2,
    /// Gzip-compressed tar (`.tar.gz` / `.tgz`) — decompress then iterate.
    TarGz = 3,
    /// Standalone bzip2 stream — single decompressed blob, no entry iteration.
    Bzip2 = 4,
    /// Bzip2-compressed tar (`.tar.bz2` / `.tbz2`) — decompress then iterate.
    TarBz2 = 5,
}

impl ArchiveKind {
    /// Returns `true` for kinds that contain multiple named entries
    /// (`Tar`, `Zip`, `TarGz`, `TarBz2`), `false` for single-stream
    /// `Gzip`/`Bzip2`.
    ///
    /// Callers use this to decide whether to iterate entries or treat the
    /// decompressed output as one anonymous blob.
    #[inline(always)]
    pub const fn is_container(self) -> bool {
        matches!(
            self,
            ArchiveKind::Tar | ArchiveKind::Zip | ArchiveKind::TarGz | ArchiveKind::TarBz2
        )
    }
}

/// Detect from a filesystem path by inspecting the filename suffix.
///
/// Extracts the final path component via [`Path::file_name`] and delegates to
/// [`detect_kind_from_name_bytes`]. No allocation occurs on Unix (direct
/// `OsStr` → byte-slice). On non-Unix platforms, non-UTF-8 filenames
/// silently return `None` rather than allocating a lossy conversion.
pub fn detect_kind_from_path(path: &Path) -> Option<ArchiveKind> {
    let name = path.file_name()?;
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        detect_kind_from_name_bytes(name.as_bytes())
    }

    #[cfg(not(unix))]
    {
        // Non-UTF-8 filenames return None to avoid allocations on platforms
        // without byte-level path access.
        let s = name.to_str()?;
        detect_kind_from_name(s)
    }
}

/// Detect from a UTF-8 filename string.
///
/// Thin wrapper over [`detect_kind_from_name_bytes`]; prefer the byte variant
/// when the input is already `&[u8]` (e.g., tar entry names) to skip the
/// `&[u8]` → `&str` UTF-8 validation the caller would otherwise need.
#[inline]
pub fn detect_kind_from_name(name: &str) -> Option<ArchiveKind> {
    detect_kind_from_name_bytes(name.as_bytes())
}

/// Sniff archive kind from magic bytes in a header buffer.
///
/// Minimum buffer sizes for each format:
/// - **gzip**: 2 bytes (`1f 8b`)
/// - **zip**: 4 bytes (`PK` prefix + one of four signature pairs; see [`is_zip_magic`])
/// - **bzip2**: 4 bytes (`BZh` + block-size digit `'1'`–`'9'`)
/// - **tar (ustar)**: 512 bytes (magic at offset 257)
///
/// Returns `Gzip` for any gzip stream — callers must rely on the filename
/// extension (via [`detect_kind`]) to distinguish `.tar.gz` from plain `.gz`.
///
/// Probe order is gzip → zip → bzip2 → tar; first match wins.
pub fn sniff_kind_from_header(header: &[u8]) -> Option<ArchiveKind> {
    if is_gzip_magic(header) {
        return Some(ArchiveKind::Gzip);
    }
    if is_zip_magic(header) {
        return Some(ArchiveKind::Zip);
    }
    if is_bzip2_magic(header) {
        return Some(ArchiveKind::Bzip2);
    }
    if is_ustar_header(header) {
        return Some(ArchiveKind::Tar);
    }
    None
}

/// Combined detection: extension first, magic-byte fallback second.
///
/// Extension-based detection always takes precedence. This is critical for
/// `.tar.gz` files whose magic bytes are indistinguishable from plain `.gz`.
/// If the extension is unrecognized and `header_opt` is `Some`, falls back to
/// [`sniff_kind_from_header`].
pub fn detect_kind(path: &Path, header_opt: Option<&[u8]>) -> Option<ArchiveKind> {
    if let Some(k) = detect_kind_from_path(path) {
        return Some(k);
    }
    header_opt.and_then(sniff_kind_from_header)
}

/// Detect archive kind from an *archive entry name* (raw bytes).
///
/// Primary entry point for nested expansion inside streaming containers
/// (tar/gz). Does not allocate and does not require valid UTF-8, so it
/// can operate directly on tar header name fields and gzip FNAME bytes.
///
/// Trailing path separators (`/`, `\`) are stripped first, because tar
/// appends `/` to directory entry names and some producers include
/// trailing backslashes on Windows.
///
/// # Algorithm
///
/// Single-byte dispatch on the last (non-slash) byte, lowercased via `| 0x20`
/// (valid for the ASCII extension alphabet `[a-zA-Z.]`):
///
/// | Last byte | Candidates               | Checks          |
/// |-----------|--------------------------|-----------------|
/// | `'z'`     | `.tar.gz`, `.tgz`, `.gz` | penultimate `g` |
/// | `'2'`     | `.tar.bz2`, `.tbz2`, `.bz2` | penultimate `z` |
/// | `'r'`     | `.tar`                   | 4-byte check    |
/// | `'p'`     | `.zip`                   | 4-byte check    |
/// | anything  | —                        | return `None`   |
///
/// The common case (no match) exits after **one byte comparison**. Inputs
/// shorter than 3 bytes (after stripping) are rejected immediately — the
/// shortest valid extension is `.gz`.
#[inline]
pub fn detect_kind_from_name_bytes(name: &[u8]) -> Option<ArchiveKind> {
    let name = strip_trailing_slashes(name);
    let len = name.len();
    if len < 3 {
        return None;
    }

    // Dispatch on last byte, case-folded.
    match name[len - 1] | 0x20 {
        b'z' => detect_z_suffix(name, len),
        b'2' => detect_2_suffix(name, len),
        b'r' => detect_r_suffix(name, len),
        b'p' => detect_p_suffix(name, len),
        _ => None,
    }
}

/// Last byte is `z`/`Z` — check for `.tar.gz`, `.tgz`, `.gz` (longest match first).
#[inline]
fn detect_z_suffix(name: &[u8], len: usize) -> Option<ArchiveKind> {
    // Need at least `.gz` (3 chars), and penultimate must be 'g'/'G'.
    if len < 3 || name[len - 2] | 0x20 != b'g' {
        return None;
    }

    // Check `.tar.gz` (7 chars): ...'.''t''a''r''.''g''z'
    if len >= 7
        && name[len - 3] == b'.'
        && name[len - 4] | 0x20 == b'r'
        && name[len - 5] | 0x20 == b'a'
        && name[len - 6] | 0x20 == b't'
        && name[len - 7] == b'.'
    {
        return Some(ArchiveKind::TarGz);
    }

    // Check `.tgz` (4 chars): ...'.''t''g''z'
    if len >= 4 && name[len - 3] | 0x20 == b't' && name[len - 4] == b'.' {
        return Some(ArchiveKind::TarGz);
    }

    // Check `.gz` (3 chars): ...'.''g''z'
    if name[len - 3] == b'.' {
        return Some(ArchiveKind::Gzip);
    }

    None
}

/// Last byte is `2` — check for `.tar.bz2`, `.tbz2`, `.bz2` (longest match first).
#[inline]
fn detect_2_suffix(name: &[u8], len: usize) -> Option<ArchiveKind> {
    // Need at least `.bz2` (4 chars), and penultimate must be 'z'/'Z'.
    if len < 4 || name[len - 2] | 0x20 != b'z' {
        return None;
    }
    // Next must be 'b'/'B' for bzip2-derived suffixes.
    if name[len - 3] | 0x20 != b'b' {
        return None;
    }

    // Check `.tar.bz2` (8 chars): ...'.''t''a''r''.''b''z''2'
    if len >= 8
        && name[len - 4] == b'.'
        && name[len - 5] | 0x20 == b'r'
        && name[len - 6] | 0x20 == b'a'
        && name[len - 7] | 0x20 == b't'
        && name[len - 8] == b'.'
    {
        return Some(ArchiveKind::TarBz2);
    }

    // Check `.tbz2` (5 chars): ...'.''t''b''z''2'
    if len >= 5 && name[len - 4] | 0x20 == b't' && name[len - 5] == b'.' {
        return Some(ArchiveKind::TarBz2);
    }

    // Check `.bz2` (4 chars): ...'.''b''z''2'
    if name[len - 4] == b'.' {
        return Some(ArchiveKind::Bzip2);
    }

    None
}

/// Last byte is 'r'/'R': check for `.tar` (4 chars).
#[inline]
fn detect_r_suffix(name: &[u8], len: usize) -> Option<ArchiveKind> {
    if len >= 4
        && name[len - 2] | 0x20 == b'a'
        && name[len - 3] | 0x20 == b't'
        && name[len - 4] == b'.'
    {
        Some(ArchiveKind::Tar)
    } else {
        None
    }
}

/// Last byte is 'p'/'P': check for `.zip` (4 chars).
#[inline]
fn detect_p_suffix(name: &[u8], len: usize) -> Option<ArchiveKind> {
    if len >= 4
        && name[len - 2] | 0x20 == b'i'
        && name[len - 3] | 0x20 == b'z'
        && name[len - 4] == b'.'
    {
        Some(ArchiveKind::Zip)
    } else {
        None
    }
}

/// Strip trailing `/` and `\` separators.
///
/// Tar appends `/` to directory entry names; some Windows-origin archives
/// use `\`. Stripping lets the suffix matcher see the real extension.
#[inline]
fn strip_trailing_slashes(mut s: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = s.split_last() {
        if last == b'/' || last == b'\\' {
            s = rest;
        } else {
            break;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_by_extension() {
        assert_eq!(detect_kind_from_name("a.tar.gz"), Some(ArchiveKind::TarGz));
        assert_eq!(detect_kind_from_name("a.TGZ"), Some(ArchiveKind::TarGz));
        assert_eq!(detect_kind_from_name("a.gz"), Some(ArchiveKind::Gzip));
        assert_eq!(
            detect_kind_from_name("a.tar.bz2"),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(detect_kind_from_name("a.TBZ2"), Some(ArchiveKind::TarBz2));
        assert_eq!(detect_kind_from_name("a.bz2"), Some(ArchiveKind::Bzip2));
        assert_eq!(detect_kind_from_name("a.tar"), Some(ArchiveKind::Tar));
        assert_eq!(detect_kind_from_name("a.zip"), Some(ArchiveKind::Zip));
        assert_eq!(detect_kind_from_name("a.bin"), None);
    }

    #[test]
    fn sniff_magic_gzip_zip() {
        assert_eq!(
            sniff_kind_from_header(&[0x1f, 0x8b, 0x08, 0x00]),
            Some(ArchiveKind::Gzip)
        );
        assert_eq!(
            sniff_kind_from_header(&[0x42, 0x5A, 0x68, 0x39]),
            Some(ArchiveKind::Bzip2)
        );
        assert_eq!(
            sniff_kind_from_header(b"PK\x03\x04xxxx"),
            Some(ArchiveKind::Zip)
        );
        assert_eq!(sniff_kind_from_header(&[0, 1, 2, 3]), None);
    }

    #[test]
    fn sniff_magic_ustar() {
        // Valid ustar header: "ustar" at offset 257 in a 512-byte block.
        let mut header = [0u8; 512];
        header[257..262].copy_from_slice(b"ustar");
        assert_eq!(sniff_kind_from_header(&header), Some(ArchiveKind::Tar));

        // Too short to contain ustar magic (< 512 bytes).
        assert_eq!(sniff_kind_from_header(&header[..256]), None);

        // 512 bytes but wrong magic at offset 257.
        let mut bad = [0u8; 512];
        bad[257..262].copy_from_slice(b"nstar");
        assert_eq!(sniff_kind_from_header(&bad), None);
    }

    #[test]
    fn is_container_classification() {
        assert!(!ArchiveKind::Gzip.is_container());
        assert!(!ArchiveKind::Bzip2.is_container());
        assert!(ArchiveKind::Tar.is_container());
        assert!(ArchiveKind::Zip.is_container());
        assert!(ArchiveKind::TarGz.is_container());
        assert!(ArchiveKind::TarBz2.is_container());
    }

    #[test]
    fn double_dot_edge_cases() {
        // `file..gz` ends with `.gz` — the extra dot is part of the basename.
        assert_eq!(
            detect_kind_from_name_bytes(b"file..gz"),
            Some(ArchiveKind::Gzip)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"file..tar.gz"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"file..tar"),
            Some(ArchiveKind::Tar)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"file..zip"),
            Some(ArchiveKind::Zip)
        );
        // Double dot not adjacent to a recognized extension.
        assert_eq!(detect_kind_from_name_bytes(b"file..rs"), None);
    }

    #[test]
    fn extension_wins_over_sniff_for_targz() {
        use std::path::PathBuf;
        let p = PathBuf::from("x.tar.gz");
        // header indicates gzip; combined detection should still return TarGz.
        assert_eq!(
            detect_kind(&p, Some(&[0x1f, 0x8b, 0x08, 0x00])),
            Some(ArchiveKind::TarGz)
        );
    }

    #[test]
    fn extension_wins_over_sniff_for_tarbz2() {
        use std::path::PathBuf;
        let p = PathBuf::from("x.tar.bz2");
        // header indicates bzip2; combined detection should still return TarBz2.
        assert_eq!(
            detect_kind(&p, Some(&[0x42, 0x5A, 0x68, 0x39])),
            Some(ArchiveKind::TarBz2)
        );
    }

    #[test]
    fn detect_from_name_bytes_handles_case_and_trailing_slash() {
        assert_eq!(
            detect_kind_from_name_bytes(b"foo.TAR.GZ"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"foo.TAR.BZ2"),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"bar.tgz/"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"bar.tbz2/"),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"/path/inner.TAR"),
            Some(ArchiveKind::Tar)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"data.GZ"),
            Some(ArchiveKind::Gzip)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"data.BZ2"),
            Some(ArchiveKind::Bzip2)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"bundle.zip"),
            Some(ArchiveKind::Zip)
        );
        assert_eq!(detect_kind_from_name_bytes(b"nope.bin"), None);
    }

    #[test]
    fn empty_and_short_inputs() {
        assert_eq!(detect_kind_from_name_bytes(b""), None);
        assert_eq!(detect_kind_from_name_bytes(b"a"), None);
        assert_eq!(detect_kind_from_name_bytes(b"gz"), None);
        assert_eq!(detect_kind_from_name_bytes(b".gz"), Some(ArchiveKind::Gzip));
        assert_eq!(detect_kind_from_name_bytes(b"tgz"), None);
        assert_eq!(
            detect_kind_from_name_bytes(b".tgz"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(detect_kind_from_name_bytes(b"tar"), None);
        assert_eq!(detect_kind_from_name_bytes(b".tar"), Some(ArchiveKind::Tar));
        assert_eq!(detect_kind_from_name_bytes(b"zip"), None);
        assert_eq!(detect_kind_from_name_bytes(b".zip"), Some(ArchiveKind::Zip));
        assert_eq!(detect_kind_from_name_bytes(b"bz2"), None);
        assert_eq!(
            detect_kind_from_name_bytes(b".bz2"),
            Some(ArchiveKind::Bzip2)
        );
        assert_eq!(detect_kind_from_name_bytes(b"tbz2"), None);
        assert_eq!(
            detect_kind_from_name_bytes(b".tbz2"),
            Some(ArchiveKind::TarBz2)
        );
    }

    #[test]
    fn bare_extensions_no_basename() {
        assert_eq!(
            detect_kind_from_name_bytes(b".tar.gz"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b".tar.bz2"),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b".tgz"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b".tbz2"),
            Some(ArchiveKind::TarBz2)
        );
        assert_eq!(detect_kind_from_name_bytes(b".tar"), Some(ArchiveKind::Tar));
        assert_eq!(detect_kind_from_name_bytes(b".gz"), Some(ArchiveKind::Gzip));
        assert_eq!(
            detect_kind_from_name_bytes(b".bz2"),
            Some(ArchiveKind::Bzip2)
        );
        assert_eq!(detect_kind_from_name_bytes(b".zip"), Some(ArchiveKind::Zip));
    }

    #[test]
    fn exhaustive_case_variations() {
        // .tar.gz mixed case
        for &input in &[
            &b".Tar.Gz"[..],
            &b".TAR.gz"[..],
            &b".tar.GZ"[..],
            &b".tAr.gZ"[..],
            &b".TAR.GZ"[..],
        ] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::TarGz),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .tgz mixed case
        for &input in &[&b".Tgz"[..], &b".tGz"[..], &b".tgZ"[..], &b".TGZ"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::TarGz),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .tar mixed case
        for &input in &[&b".Tar"[..], &b".tAr"[..], &b".taR"[..], &b".TAR"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::Tar),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .gz mixed case
        for &input in &[&b".Gz"[..], &b".gZ"[..], &b".GZ"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::Gzip),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .zip mixed case
        for &input in &[&b".Zip"[..], &b".zIp"[..], &b".ziP"[..], &b".ZIP"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::Zip),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .tar.bz2 mixed case
        for &input in &[
            &b".Tar.Bz2"[..],
            &b".TAR.bz2"[..],
            &b".tar.BZ2"[..],
            &b".TAR.BZ2"[..],
        ] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::TarBz2),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .tbz2 mixed case
        for &input in &[&b".Tbz2"[..], &b".tBz2"[..], &b".tbZ2"[..], &b".TBZ2"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::TarBz2),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
        // .bz2 mixed case
        for &input in &[&b".Bz2"[..], &b".bZ2"[..], &b".BZ2"[..]] {
            assert_eq!(
                detect_kind_from_name_bytes(input),
                Some(ArchiveKind::Bzip2),
                "failed for {:?}",
                std::str::from_utf8(input)
            );
        }
    }

    #[test]
    fn non_matching_with_shared_terminal_chars() {
        // Ends in 'z' but not a recognized extension.
        assert_eq!(detect_kind_from_name_bytes(b"file.bz"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.xz"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.7z"), None);
        // Ends in '2' but not a recognized bzip2 extension.
        assert_eq!(detect_kind_from_name_bytes(b"file.z2"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.abz2"), None);
        // Ends in 'r' but not .tar
        assert_eq!(detect_kind_from_name_bytes(b"file.jar"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.bar"), None);
        // Ends in 'p' but not .zip
        assert_eq!(detect_kind_from_name_bytes(b"file.bmp"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.tmp"), None);
        // Ends in other chars entirely
        assert_eq!(detect_kind_from_name_bytes(b"file.rs"), None);
        assert_eq!(detect_kind_from_name_bytes(b"file.json"), None);
        assert_eq!(detect_kind_from_name_bytes(b"Makefile"), None);
    }

    #[test]
    fn multiple_trailing_slashes() {
        assert_eq!(
            detect_kind_from_name_bytes(b"a.tar.gz//"),
            Some(ArchiveKind::TarGz)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"a.zip\\\\"),
            Some(ArchiveKind::Zip)
        );
        assert_eq!(
            detect_kind_from_name_bytes(b"a.tar/\\//\\"),
            Some(ArchiveKind::Tar)
        );
        // All slashes → empty → None.
        assert_eq!(detect_kind_from_name_bytes(b"///"), None);
    }

    #[test]
    fn long_paths() {
        let mut long = b"some/very/deep/nested/directory/path/to/archive.tar.gz".to_vec();
        assert_eq!(detect_kind_from_name_bytes(&long), Some(ArchiveKind::TarGz));
        long.extend_from_slice(b"/");
        assert_eq!(detect_kind_from_name_bytes(&long), Some(ArchiveKind::TarGz));

        let long_no_match = b"a/really/long/path/to/some/file/named/important_data.csv";
        assert_eq!(detect_kind_from_name_bytes(long_no_match), None);
    }

    #[test]
    fn detect_kind_from_name_delegates_to_bytes() {
        let cases: &[&str] = &[
            "a.tar.gz",
            "a.TGZ",
            "a.gz",
            "a.tar",
            "a.zip",
            "a.bin",
            "",
            "a",
            ".gz",
            ".bz2",
            ".tbz2",
            ".tar.bz2",
            "file.bz",
            "file.jar",
            "file.bmp",
            ".tar.gz",
            ".Tar.Gz",
            ".Tar.Bz2",
            "archive.TAR.GZ/",
            "archive.TAR.BZ2/",
        ];
        for &s in cases {
            assert_eq!(
                detect_kind_from_name(s),
                detect_kind_from_name_bytes(s.as_bytes()),
                "mismatch for {:?}",
                s
            );
        }
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "detect_tests.rs"]
mod detect_tests;

#[cfg(kani)]
mod kani_proofs {
    use super::*;

    /// Prove `detect_kind_from_name_bytes` never panics for any `&[u8]` up to 32 bytes.
    ///
    /// The suffix functions do raw indexing (`name[len - N]`) guarded by `len >= N`
    /// checks. This proof exhaustively verifies those guards hold.
    #[kani::proof]
    #[kani::unwind(34)]
    fn verify_detect_kind_from_name_bytes_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 32);

        let name: [u8; 32] = kani::any();
        let slice = &name[..len];

        // Must not panic — result is unchecked.
        let _ = detect_kind_from_name_bytes(slice);
    }

    /// Prove `detect_z_suffix` never panics for any `(name, len)` pair
    /// where `len == name.len()` and `len <= 32`.
    ///
    /// Intentionally unconstrained — in production, `detect_kind_from_name_bytes`
    /// only calls this after `len >= 3`, but we prove safety without that precondition.
    #[kani::proof]
    #[kani::unwind(34)]
    fn verify_detect_z_suffix_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 32);

        let name: [u8; 32] = kani::any();
        let slice = &name[..len];

        let _ = detect_z_suffix(slice, len);
    }

    /// Prove `detect_r_suffix` never panics for any `(name, len)` pair.
    ///
    /// Intentionally unconstrained — see `verify_detect_z_suffix_no_panic`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn verify_detect_r_suffix_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 32);

        let name: [u8; 32] = kani::any();
        let slice = &name[..len];

        let _ = detect_r_suffix(slice, len);
    }

    /// Prove `detect_p_suffix` never panics for any `(name, len)` pair.
    ///
    /// Intentionally unconstrained — see `verify_detect_z_suffix_no_panic`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn verify_detect_p_suffix_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 32);

        let name: [u8; 32] = kani::any();
        let slice = &name[..len];

        let _ = detect_p_suffix(slice, len);
    }

    /// Prove `detect_2_suffix` never panics for any `(name, len)` pair.
    ///
    /// Intentionally unconstrained — see `verify_detect_z_suffix_no_panic`.
    #[kani::proof]
    #[kani::unwind(34)]
    fn verify_detect_2_suffix_no_panic() {
        let len: usize = kani::any();
        kani::assume(len <= 32);

        let name: [u8; 32] = kani::any();
        let slice = &name[..len];

        let _ = detect_2_suffix(slice, len);
    }
}
