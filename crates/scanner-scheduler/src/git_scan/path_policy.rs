//! Path policy classifier for tree diff candidates.
//!
//! Emits a compact bitfield that marks paths as source/test/vendor/generated/
//! binary-ish/lock-file/unknown using segment, extension, and filename tables.
//! The classifier is intentionally shallow: it does not inspect file contents
//! and does not allocate. Multiple bits may be set for the same path (for
//! example a test file is both `TEST` and `SOURCE`).
//!
//! Binary and source extensions are stored in sorted packed-u64 tables for
//! O(log n) lookup via binary search. Each extension (1–8 lowercase ASCII
//! bytes) is packed big-endian into a `u64`, giving lexicographic numeric
//! ordering. The tables are `const`-constructable and L1-resident.
//!
//! Lock files are matched by exact filename (after the last `/` separator)
//! using a sorted `&[&[u8]]` table with case-insensitive binary search.
//!
//! `classify_path` fuses the segment scan into a single pass over `/`-
//! delimited segments and shares the filename extraction across extension
//! and lock-file checks.

use core::cmp::Ordering;
use core::ops::{BitOr, BitOrAssign};

use memchr::memrchr;

/// Bitfield classification for candidate paths.
///
/// This is a bitset, not a single-choice enum. The classifier will set
/// multiple bits if a path matches more than one heuristic.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathClass(u8);

impl PathClass {
    /// Marks paths that look like source files by extension.
    pub const SOURCE: Self = Self(1 << 0);
    /// Marks paths under test-related directories.
    pub const TEST: Self = Self(1 << 1);
    /// Marks paths under vendor or third-party directories.
    pub const VENDOR: Self = Self(1 << 2);
    /// Marks paths under generated/build output directories.
    pub const GENERATED: Self = Self(1 << 3);
    /// Marks paths that look like binary assets by extension.
    pub const BINARY: Self = Self(1 << 4);
    /// Marks paths that did not match any heuristic.
    pub const UNKNOWN: Self = Self(1 << 5);
    /// Marks paths whose filename is a known lock/pinfile.
    pub const LOCK_FILE: Self = Self(1 << 6);

    /// Returns an empty classification (no bits set).
    #[inline]
    #[must_use]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Returns the bitset value widened to `u16`.
    #[inline]
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0 as u16
    }

    /// Returns true if no classification bits are set.
    #[inline]
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// Returns true if all bits in `other` are set in `self`.
    #[inline]
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    /// Returns true if this path is classified as non-scannable content.
    ///
    /// A path is non-scannable if it is a known binary format OR a known
    /// lock/pin file. Path-based skipping is always on — there is no version
    /// gating.
    #[inline]
    #[must_use]
    pub const fn is_nonscannable(self) -> bool {
        (self.0 & (Self::BINARY.0 | Self::LOCK_FILE.0)) != 0
    }
}

impl BitOr for PathClass {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        PathClass(self.0 | rhs.0)
    }
}

impl BitOrAssign for PathClass {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

// ---------------------------------------------------------------------------
// Packed-u64 extension table
// ---------------------------------------------------------------------------

/// Packs a lowercase ASCII extension (1–8 bytes) into a big-endian `u64`.
///
/// MSB-first alignment ensures numeric ordering matches lexicographic byte
/// ordering. The input MUST already be lowercase — this function does NOT
/// normalize case. Empty extensions and extensions longer than 8 bytes
/// return 0 (the latter are handled by the long-extension overflow table).
///
/// ```text
/// "png" → [0x70][0x6e][0x67][0x00][0x00][0x00][0x00][0x00] = 0x706e670000000000
/// "a"   → [0x61][0x00][0x00][0x00][0x00][0x00][0x00][0x00] = 0x6100000000000000
/// ```
#[inline]
pub const fn pack_ext(ext: &[u8]) -> u64 {
    if ext.is_empty() || ext.len() > 8 {
        return 0;
    }
    let mut val: u64 = 0;
    let mut i = 0;
    while i < ext.len() {
        val |= (ext[i] as u64) << (56 - (i * 8));
        i += 1;
    }
    val
}

/// Compile-time assertion that a `u64` slice is strictly sorted.
const fn assert_sorted(table: &[u64]) {
    let mut i = 1;
    while i < table.len() {
        assert!(table[i - 1] < table[i], "SKIP_EXTS table is not sorted");
        i += 1;
    }
}

/// Compile-time assertion that a `&[&[u8]]` slice is strictly sorted
/// (bytewise lexicographic, lowercase).
const fn assert_sorted_bytes(table: &[&[u8]]) {
    let mut i = 1;
    while i < table.len() {
        let a = table[i - 1];
        let b = table[i];
        let min_len = if a.len() < b.len() { a.len() } else { b.len() };
        let mut j = 0;
        let mut cmp = 0i8; // -1 = less, 0 = equal, 1 = greater
        while j < min_len {
            if a[j] < b[j] {
                cmp = -1;
                break;
            }
            if a[j] > b[j] {
                cmp = 1;
                break;
            }
            j += 1;
        }
        if cmp == 0 {
            // All compared bytes equal — shorter must come first.
            assert!(
                a.len() < b.len(),
                "LOCK_FILES / SKIP_EXTS_LONG table is not sorted"
            );
        } else {
            assert!(cmp < 0, "LOCK_FILES / SKIP_EXTS_LONG table is not sorted");
        }
        i += 1;
    }
}

/// Maximum number of long (>8 byte) extensions allowed.
const MAX_LONG_EXTS: usize = 16;

/// Sorted packed-u64 table of binary extensions that are safe to skip.
///
/// **Not included** (BinaryExtractable — must reach content classifier):
/// `.class`, `.ear`, `.ipynb`, `.jar`, `.pyc`, `.pyo`, `.war`
///
/// **Not included** (ambiguous/text-based):
/// `.db`, `.sqlite`, `.sqlitedb`, `.accdb`, `.mdb`, `.pb`, `.rtf`, `.svg`,
/// `.svgz`, `.ts` (TypeScript)
///
/// Extensions are grouped by category in comments but the table MUST remain
/// in strict ascending `u64` order. Run `cargo check` to verify — a
/// compile-time assertion will fire on misordering.
static SKIP_EXTS: &[u64] = {
    const TABLE: &[u64] = &[
        // ---- Digit-prefixed (ASCII digits < letters) ----
        pack_ext(b"3g2"), // 3GPP2
        pack_ext(b"3gp"), // 3GPP
        pack_ext(b"7z"),
        // ---- Native binaries / objects ----
        pack_ext(b"a"), // static library
        // ---- Audio ----
        pack_ext(b"aac"),
        pack_ext(b"ai"), // Adobe Illustrator
        pack_ext(b"aif"),
        pack_ext(b"aiff"),
        pack_ext(b"ape"),  // Monkey's Audio
        pack_ext(b"apk"),  // Android package
        pack_ext(b"apng"), // animated PNG
        pack_ext(b"ar"),   // Unix archive
        pack_ext(b"asf"),  // Advanced Systems Format
        pack_ext(b"au"),   // Sun audio
        pack_ext(b"avi"),
        pack_ext(b"avif"),
        // ---- Archives ----
        pack_ext(b"bin"),
        pack_ext(b"blend"), // Blender
        pack_ext(b"bmp"),
        pack_ext(b"br"), // Brotli
        // ---- Archives / other ----
        pack_ext(b"cab"), // Windows cabinet
        pack_ext(b"caf"), // Core Audio Format
        pack_ext(b"com"), // DOS executable
        pack_ext(b"cpio"),
        pack_ext(b"cr2"), // Canon RAW
        pack_ext(b"cur"), // Windows cursor
        // ---- Documents ----
        pack_ext(b"dat"),
        pack_ext(b"dds"), // DirectDraw Surface
        pack_ext(b"deb"), // Debian package
        pack_ext(b"dll"),
        pack_ext(b"dmg"), // macOS disk image
        pack_ext(b"dng"), // Digital Negative
        pack_ext(b"doc"),
        pack_ext(b"docm"),
        pack_ext(b"docx"),
        pack_ext(b"dts"), // DTS audio
        pack_ext(b"dylib"),
        // ---- Fonts / Executables ----
        pack_ext(b"elf"),
        pack_ext(b"eot"), // Embedded OpenType font
        pack_ext(b"epub"),
        pack_ext(b"exe"),
        pack_ext(b"exr"), // OpenEXR
        // ---- Video ----
        pack_ext(b"f4v"), // Flash video
        pack_ext(b"fev"), // FMOD event
        pack_ext(b"fig"), // Figma
        pack_ext(b"flac"),
        pack_ext(b"flv"), // Flash video
        pack_ext(b"fnt"), // bitmap font
        pack_ext(b"fon"), // Windows font
        pack_ext(b"fsb"), // FMOD sample bank
        // ---- ML models ----
        pack_ext(b"ggml"),
        pack_ext(b"gguf"),
        pack_ext(b"gif"),
        pack_ext(b"gz"),
        // ---- Images / Video (H) ----
        pack_ext(b"h264"),
        pack_ext(b"h5"), // HDF5
        pack_ext(b"hdf5"),
        pack_ext(b"hdr"), // Radiance HDR
        pack_ext(b"hdv"), // HDV video
        pack_ext(b"heic"),
        pack_ext(b"heif"),
        pack_ext(b"hprof"), // Java heap dump
        pack_ext(b"ico"),
        pack_ext(b"img"), // disk image
        pack_ext(b"ipa"), // iOS app archive
        pack_ext(b"iso"), // ISO disc image
        // ---- Images (J) ----
        pack_ext(b"jfif"),
        pack_ext(b"jpeg"),
        pack_ext(b"jpg"),
        pack_ext(b"jxl"), // JPEG XL
        pack_ext(b"jxr"), // JPEG XR
        // ---- Native ----
        pack_ext(b"ko"), // kernel object
        // ---- Native / Archives ----
        pack_ext(b"lib"), // Windows static library
        pack_ext(b"lz4"),
        pack_ext(b"lzma"),
        // ---- Video (M) ----
        pack_ext(b"m2ts"), // Blu-ray MPEG-2 TS
        pack_ext(b"m4a"),  // MPEG-4 audio
        pack_ext(b"m4p"),  // protected AAC
        pack_ext(b"m4v"),  // MPEG-4 video
        pack_ext(b"mid"),
        pack_ext(b"midi"),
        pack_ext(b"mka"), // Matroska audio
        pack_ext(b"mkv"),
        pack_ext(b"mobi"), // Mobipocket ebook
        pack_ext(b"mov"),
        pack_ext(b"mp2"),
        pack_ext(b"mp3"),
        pack_ext(b"mp4"),
        pack_ext(b"mpeg"),
        pack_ext(b"mpg"),
        pack_ext(b"msi"), // Windows installer
        pack_ext(b"mts"), // AVCHD
        // ---- Images (N) ----
        pack_ext(b"nef"),   // Nikon RAW
        pack_ext(b"nupkg"), // NuGet package
        // ---- Native (O) ----
        pack_ext(b"o"), // object file
        pack_ext(b"obj"),
        pack_ext(b"odp"), // OpenDocument presentation
        pack_ext(b"ods"), // OpenDocument spreadsheet
        pack_ext(b"odt"), // OpenDocument text
        pack_ext(b"ogg"),
        pack_ext(b"ogv"),  // Ogg Video
        pack_ext(b"onnx"), // ONNX model
        pack_ext(b"opus"),
        pack_ext(b"otf"),
        pack_ext(b"out"), // compiled output
        // ---- Images / Documents (P) ----
        pack_ext(b"pbm"), // Portable Bitmap
        pack_ext(b"pcx"), // PC Paintbrush
        pack_ext(b"pdb"), // program database
        pack_ext(b"pdf"),
        pack_ext(b"pgm"), // Portable Graymap
        pack_ext(b"pic"), // generic picture
        pack_ext(b"png"),
        pack_ext(b"pnm"), // Portable Anymap
        pack_ext(b"ppm"), // Portable Pixmap
        pack_ext(b"ppt"),
        pack_ext(b"pptm"),
        pack_ext(b"pptx"),
        pack_ext(b"psd"), // Photoshop
        // ---- Disk images (Q) ----
        pack_ext(b"qcow2"), // QEMU copy-on-write
        pack_ext(b"qt"),    // QuickTime
        // ---- Archives (R) ----
        pack_ext(b"rar"),
        pack_ext(b"raw"),  // raw image
        pack_ext(b"rgb"),  // SGI RGB
        pack_ext(b"rlib"), // Rust library
        pack_ext(b"rpm"),  // Red Hat package
        // ---- Design / 3D ----
        pack_ext(b"sgi"),    // SGI image
        pack_ext(b"sketch"), // Sketch design
        pack_ext(b"so"),     // shared object
        pack_ext(b"stl"),    // 3D model
        pack_ext(b"swf"),    // Flash
        pack_ext(b"sym"),    // symbol file
        pack_ext(b"sys"),    // Windows system
        // ---- Archives (T) ----
        pack_ext(b"tar"),
        pack_ext(b"tga"), // Truevision TGA
        pack_ext(b"tgz"),
        pack_ext(b"tif"),
        pack_ext(b"tiff"),
        pack_ext(b"tlz"), // tar.lz
        pack_ext(b"ttc"), // TrueType collection
        pack_ext(b"ttf"),
        pack_ext(b"txz"), // tar.xz
        // ---- Disk images (V) ----
        pack_ext(b"vdi"),  // VirtualBox disk image
        pack_ext(b"vhd"),  // Virtual Hard Disk
        pack_ext(b"vhdx"), // Hyper-V Virtual Hard Disk
        pack_ext(b"vmdk"), // VMware disk
        pack_ext(b"vob"),  // DVD Video Object
        pack_ext(b"vxd"),  // Windows virtual device
        // ---- Audio/Video/WASM (W) ----
        pack_ext(b"wasm"),
        pack_ext(b"wav"),
        pack_ext(b"wbmp"), // Wireless Bitmap
        pack_ext(b"wdp"),  // Windows Media Photo
        pack_ext(b"webm"),
        pack_ext(b"webp"),
        pack_ext(b"wma"), // Windows Media Audio
        pack_ext(b"wmv"), // Windows Media Video
        pack_ext(b"woff"),
        pack_ext(b"woff2"),
        // ---- Images (X) ----
        pack_ext(b"xbm"), // X BitMap
        pack_ext(b"xd"),  // Adobe XD
        pack_ext(b"xls"),
        pack_ext(b"xlsm"),
        pack_ext(b"xlsx"),
        pack_ext(b"xpi"), // Firefox extension
        pack_ext(b"xpm"), // X PixMap
        pack_ext(b"xwd"), // X Window Dump
        pack_ext(b"xz"),
        // ---- Misc (Z) ----
        pack_ext(b"z"), // compress
        pack_ext(b"zip"),
        pack_ext(b"zipx"), // extended zip
        pack_ext(b"zst"),  // Zstandard
    ];
    assert_sorted(TABLE);
    TABLE
};

/// Overflow table for extensions longer than 8 bytes.
/// Sorted bytewise (lowercase). Looked up via linear scan (tiny).
static SKIP_EXTS_LONG: &[&[u8]] = {
    const TABLE: &[&[u8]] = &[b"safetensors"];
    assert_sorted_bytes(TABLE);
    // Compile-time bound.
    assert!(TABLE.len() <= MAX_LONG_EXTS, "too many long extensions");
    TABLE
};

/// Returns true if the given extension (raw bytes, any case) matches the
/// binary skip set.
///
/// Extensions ≤ 8 bytes are lowercased, packed into a `u64`, and looked up
/// via binary search in [`SKIP_EXTS`]. Extensions > 8 bytes fall through to
/// a linear scan of [`SKIP_EXTS_LONG`].
#[inline]
pub fn ext_in_skip_set(ext: &[u8]) -> bool {
    if ext.is_empty() {
        return false;
    }
    if ext.len() <= 8 {
        // Lowercase into a stack buffer, then pack.
        let mut buf = [0u8; 8];
        for (dst, &src) in buf.iter_mut().zip(ext.iter()) {
            *dst = src.to_ascii_lowercase();
        }
        let key = pack_ext(&buf[..ext.len()]);
        SKIP_EXTS.binary_search(&key).is_ok()
    } else {
        // Long extension — linear scan (≤ MAX_LONG_EXTS entries).
        SKIP_EXTS_LONG.iter().any(|&candidate| {
            candidate.len() == ext.len()
                && candidate
                    .iter()
                    .zip(ext.iter())
                    .all(|(&a, &b)| a == b.to_ascii_lowercase())
        })
    }
}

// ---------------------------------------------------------------------------
// Lock-file table
// ---------------------------------------------------------------------------

/// Credential-safe lock/pin files — purely version-pinning data, no URLs or
/// auth tokens.
///
/// **Excluded** (can contain credentials): `composer.lock`, `package-lock.json`,
/// `npm-shrinkwrap.json`, `packages.lock.json`, `pipfile.lock`, `yarn.lock`.
///
/// Must be sorted bytewise (lowercase). Compile-time assertion enforces this.
static LOCK_FILES: &[&[u8]] = {
    const TABLE: &[&[u8]] = &[
        b"berksfile.lock",
        b"bun.lockb",
        b"cargo.lock",
        b"cartfile.resolved",
        b"deno.lock",
        b"flake.lock",
        b"gemfile.lock",
        b"go.sum",
        b"gradle.lockfile",
        b"mix.lock",
        b"package.resolved",
        b"pdm.lock",
        b"pnpm-lock.yaml",
        b"podfile.lock",
        b"poetry.lock",
        b"pubspec.lock",
        b"uv.lock",
    ];
    assert_sorted_bytes(TABLE);
    TABLE
};

/// Extracts the filename portion of a `/`-separated git tree path.
///
/// Returns the slice after the last `/`, or the entire input if no `/`
/// is present. Only handles `/` separators (git tree paths are always
/// `/`-normalized).
#[inline]
fn git_filename(path: &[u8]) -> &[u8] {
    match memrchr(b'/', path) {
        Some(idx) => &path[idx + 1..],
        None => path,
    }
}

/// Case-insensitive comparison: `reference` (lowercase) vs `input` (any case).
///
/// Returns `Ordering` suitable for use as a `binary_search_by` comparator
/// where `reference` is the table entry and `input` is the search key.
#[inline]
fn cmp_lower_vs_input(reference: &[u8], input: &[u8]) -> Ordering {
    let min_len = reference.len().min(input.len());
    for i in 0..min_len {
        let cmp = reference[i].cmp(&input[i].to_ascii_lowercase());
        if cmp != Ordering::Equal {
            return cmp;
        }
    }
    reference.len().cmp(&input.len())
}

/// Returns true if the filename portion of `path` matches a known lock file.
///
/// Handles both `/` (POSIX/git) and `\` (Windows) separators so this works
/// for OS paths passed from the local-filesystem scanner as well as git paths.
#[inline]
pub fn is_lock_filename(path: &[u8]) -> bool {
    // Find the last separator of either kind.
    let after_sep = match memchr::memrchr2(b'/', b'\\', path) {
        Some(idx) => &path[idx + 1..],
        None => path,
    };
    is_lock_name(after_sep)
}

// ---------------------------------------------------------------------------
// Segment / extension tables
// ---------------------------------------------------------------------------

const TEST_DIRS: &[&[u8]] = &[
    b"test",
    b"tests",
    b"__tests__",
    b"spec",
    b"specs",
    b"fixture",
    b"fixtures",
    b"__fixtures__",
];

const VENDOR_DIRS: &[&[u8]] = &[
    b"vendor",
    b"third_party",
    b"third-party",
    b"thirdparty",
    b"deps",
    b"external",
    b"extern",
    b"node_modules",
];

const GENERATED_DIRS: &[&[u8]] = &[
    b"generated",
    b"gen",
    b"autogen",
    b"auto",
    b"build",
    b"dist",
    b"out",
    b"target",
    b"bazel-bin",
    b"bazel-out",
    b"buck-out",
];

/// Sorted packed-u64 table of source-code extensions.
///
/// Uses the same `pack_ext` + binary search pattern as [`SKIP_EXTS`].
/// All source extensions are ≤ 8 bytes so no overflow table is needed.
static SOURCE_EXTS_PACKED: &[u64] = {
    const TABLE: &[u64] = &[
        pack_ext(b"bash"),
        pack_ext(b"c"),
        pack_ext(b"cc"),
        pack_ext(b"cfg"),
        pack_ext(b"clj"),
        pack_ext(b"conf"),
        pack_ext(b"cpp"),
        pack_ext(b"cs"),
        pack_ext(b"css"),
        pack_ext(b"dart"),
        pack_ext(b"fs"),
        pack_ext(b"go"),
        pack_ext(b"gradle"),
        pack_ext(b"groovy"),
        pack_ext(b"h"),
        pack_ext(b"hpp"),
        pack_ext(b"htm"),
        pack_ext(b"html"),
        pack_ext(b"ini"),
        pack_ext(b"java"),
        pack_ext(b"js"),
        pack_ext(b"json"),
        pack_ext(b"jsx"),
        pack_ext(b"kt"),
        pack_ext(b"less"),
        pack_ext(b"lua"),
        pack_ext(b"m"),
        pack_ext(b"md"),
        pack_ext(b"mm"),
        pack_ext(b"php"),
        pack_ext(b"proto"),
        pack_ext(b"ps1"),
        pack_ext(b"py"),
        pack_ext(b"rb"),
        pack_ext(b"rs"),
        pack_ext(b"scala"),
        pack_ext(b"scss"),
        pack_ext(b"sh"),
        pack_ext(b"sql"),
        pack_ext(b"swift"),
        pack_ext(b"toml"),
        pack_ext(b"ts"),
        pack_ext(b"tsx"),
        pack_ext(b"txt"),
        pack_ext(b"xml"),
        pack_ext(b"yaml"),
        pack_ext(b"yml"),
        pack_ext(b"zsh"),
    ];
    assert_sorted(TABLE);
    TABLE
};

// ---------------------------------------------------------------------------
// Classifier
// ---------------------------------------------------------------------------

/// Returns true if the given extension (raw bytes, any case) matches the
/// source extension set.
///
/// Uses the same packed-u64 binary search as [`ext_in_skip_set`].
#[inline]
fn ext_in_source_set(ext: &[u8]) -> bool {
    if ext.is_empty() || ext.len() > 8 {
        return false;
    }
    let mut buf = [0u8; 8];
    for (dst, &src) in buf.iter_mut().zip(ext.iter()) {
        *dst = src.to_ascii_lowercase();
    }
    let key = pack_ext(&buf[..ext.len()]);
    SOURCE_EXTS_PACKED.binary_search(&key).is_ok()
}

/// Classifies a path into `PathClass` bitflags.
///
/// The classifier is case-insensitive and treats only `/` as a separator
/// (Git tree paths are normalized to `/`, even on Windows).
///
/// This function performs no heap allocation and operates on raw bytes.
///
/// Internally the path is traversed once: segments are split on `/` and
/// checked against test/vendor/generated directory tables in a single
/// fused loop, the filename is extracted from the last segment, and the
/// extension is derived from that filename (avoiding redundant `memrchr`
/// calls).
#[must_use]
pub fn classify_path(path: &[u8]) -> PathClass {
    let mut class = PathClass::empty();

    // --- Fused single-pass segment scan ---
    // Split on `/` once, checking all three directory tables per segment.
    // The `!class.contains(X)` guard skips table checks once a category
    // is already matched.
    let mut start = 0usize;
    while start <= path.len() {
        let end = match memchr::memchr(b'/', &path[start..]) {
            Some(idx) => start + idx,
            None => path.len(),
        };
        let seg = &path[start..end];
        if !seg.is_empty() {
            if !class.contains(PathClass::TEST) && seg_in_table(seg, TEST_DIRS) {
                class |= PathClass::TEST;
            }
            if !class.contains(PathClass::VENDOR) && seg_in_table(seg, VENDOR_DIRS) {
                class |= PathClass::VENDOR;
            }
            if !class.contains(PathClass::GENERATED) && seg_in_table(seg, GENERATED_DIRS) {
                class |= PathClass::GENERATED;
            }
        }
        if end == path.len() {
            break;
        }
        start = end + 1;
    }

    // --- Shared filename extraction ---
    // Extract filename once, derive extension from it.
    let filename = git_filename(path);
    let ext = filename_extension(filename);

    if let Some(e) = ext {
        if ext_in_skip_set(e) {
            class |= PathClass::BINARY;
        }
        if ext_in_source_set(e) {
            class |= PathClass::SOURCE;
        }
    }

    if is_lock_name(filename) {
        class |= PathClass::LOCK_FILE;
        // Lock files are not source code even if they have a source-like
        // extension (e.g. pnpm-lock.yaml → .yaml is in SOURCE_EXTS).
        class.0 &= !PathClass::SOURCE.0;
    }

    if class.is_empty() {
        PathClass::UNKNOWN
    } else {
        class
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Returns true if `seg` matches any entry in `table` (case-insensitive).
/// Table entries must be lowercase.
#[inline]
fn seg_in_table(seg: &[u8], table: &[&[u8]]) -> bool {
    for &name in table {
        if seg.len() == name.len()
            && seg
                .iter()
                .zip(name)
                .all(|(&x, &y)| x.to_ascii_lowercase() == y)
        {
            return true;
        }
    }
    false
}

/// Extracts the extension from a filename slice (no `/` scan needed).
///
/// Returns `None` for dotfiles (`.gitignore`), missing dots, or trailing
/// dots.
#[inline]
fn filename_extension(filename: &[u8]) -> Option<&[u8]> {
    let dot = memrchr(b'.', filename)?;
    if dot == 0 {
        return None;
    }
    let ext = &filename[dot + 1..];
    if ext.is_empty() {
        None
    } else {
        Some(ext)
    }
}

/// Returns true if `filename` matches a known lock file (case-insensitive
/// binary search).
#[inline]
fn is_lock_name(filename: &[u8]) -> bool {
    if filename.is_empty() {
        return false;
    }
    LOCK_FILES
        .binary_search_by(|entry| cmp_lower_vs_input(entry, filename))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------
    // Common binary extensions must be in the skip set
    // ------------------------------------------------------------------
    const BINARY_EXTS_SAMPLE: &[&[u8]] = &[
        b"png", b"jpg", b"jpeg", b"gif", b"bmp", b"ico", b"tiff", b"webp", b"zip", b"gz", b"tgz",
        b"xz", b"7z", b"rar", b"tar", b"zst", b"pdf", b"doc", b"docx", b"ppt", b"pptx", b"xls",
        b"xlsx", b"mp3", b"wav", b"flac", b"ogg", b"mp4", b"mov", b"avi", b"mkv", b"woff",
        b"woff2", b"ttf", b"otf", b"exe", b"dll", b"so", b"dylib", b"bin", b"dat", b"wasm",
    ];

    #[test]
    fn common_binary_exts_in_skip_set() {
        for ext in BINARY_EXTS_SAMPLE {
            assert!(
                ext_in_skip_set(ext),
                "binary ext {:?} not in skip set",
                core::str::from_utf8(ext).unwrap_or("??"),
            );
        }
    }

    // ------------------------------------------------------------------
    // BinaryExtractable formats must NOT be in the skip set
    // ------------------------------------------------------------------
    #[test]
    fn extractable_formats_not_in_skip_set() {
        for ext in &[
            b"class" as &[u8],
            b"jar",
            b"war",
            b"ear",
            b"bz2",
            b"tbz2",
            b"pyc",
            b"pyo",
            b"ipynb",
        ] {
            assert!(
                !ext_in_skip_set(ext),
                "BinaryExtractable ext {:?} must NOT be in skip set",
                core::str::from_utf8(ext).unwrap_or("??"),
            );
        }
    }

    // ------------------------------------------------------------------
    // Database files must NOT be in the skip set
    // ------------------------------------------------------------------
    #[test]
    fn database_files_not_in_skip_set() {
        for ext in &[b"db" as &[u8], b"sqlite", b"sqlitedb", b"accdb", b"mdb"] {
            assert!(
                !ext_in_skip_set(ext),
                "database ext {:?} must NOT be in skip set",
                core::str::from_utf8(ext).unwrap_or("??"),
            );
        }
    }

    // ------------------------------------------------------------------
    // ext_in_skip_set edge cases
    // ------------------------------------------------------------------
    #[test]
    fn ext_in_skip_set_empty() {
        assert!(!ext_in_skip_set(b""));
    }

    #[test]
    fn ext_in_skip_set_exactly_8_bytes() {
        // "safetensors" is >8 bytes (11), test overflow path
        assert!(ext_in_skip_set(b"safetensors"));
        assert!(ext_in_skip_set(b"SAFETENSORS"));
    }

    #[test]
    fn ext_in_skip_set_case_insensitive() {
        assert!(ext_in_skip_set(b"PNG"));
        assert!(ext_in_skip_set(b"Png"));
        assert!(ext_in_skip_set(b"JPEG"));
        assert!(ext_in_skip_set(b"Woff2"));
    }

    #[test]
    fn ext_in_skip_set_no_false_positive() {
        assert!(!ext_in_skip_set(b"rs"));
        assert!(!ext_in_skip_set(b"py"));
        assert!(!ext_in_skip_set(b"ts"));
        assert!(!ext_in_skip_set(b"json"));
        assert!(!ext_in_skip_set(b"zzzzz"));
    }

    // ------------------------------------------------------------------
    // git_filename edge cases
    // ------------------------------------------------------------------
    #[test]
    fn git_filename_no_slash() {
        assert_eq!(git_filename(b"Cargo.lock"), b"Cargo.lock");
    }

    #[test]
    fn git_filename_with_slash() {
        assert_eq!(git_filename(b"foo/bar/Cargo.lock"), b"Cargo.lock");
    }

    #[test]
    fn git_filename_trailing_slash() {
        assert_eq!(git_filename(b"foo/bar/"), b"");
    }

    #[test]
    fn git_filename_empty() {
        assert_eq!(git_filename(b""), b"");
    }

    // ------------------------------------------------------------------
    // is_lock_filename
    // ------------------------------------------------------------------
    #[test]
    fn lock_file_matches() {
        assert!(is_lock_filename(b"Cargo.lock"));
        assert!(is_lock_filename(b"src/Cargo.lock"));
        assert!(is_lock_filename(b"CARGO.LOCK"));
        assert!(is_lock_filename(b"go.sum"));
        assert!(is_lock_filename(b"foo/go.sum"));
        assert!(is_lock_filename(b"Gemfile.lock"));
        assert!(is_lock_filename(b"pnpm-lock.yaml"));
        assert!(is_lock_filename(b"uv.lock"));
    }

    #[test]
    fn lock_file_rejects_credential_bearing() {
        // These are intentionally excluded from LOCK_FILES.
        assert!(!is_lock_filename(b"package-lock.json"));
        assert!(!is_lock_filename(b"yarn.lock"));
        assert!(!is_lock_filename(b"composer.lock"));
        assert!(!is_lock_filename(b"Pipfile.lock"));
    }

    #[test]
    fn lock_file_rejects_non_lock() {
        assert!(!is_lock_filename(b"main.rs"));
        assert!(!is_lock_filename(b""));
        assert!(!is_lock_filename(b"foo/"));
    }

    #[test]
    fn lock_file_matches_backslash_paths() {
        // Windows OS paths use backslash separators. is_lock_filename must
        // extract the filename correctly even when the path uses `\`.
        assert!(is_lock_filename(b"C:\\project\\Cargo.lock"));
        assert!(is_lock_filename(b"src\\go.sum"));
        assert!(is_lock_filename(b"deep\\nested\\dir\\Gemfile.lock"));
    }

    // ------------------------------------------------------------------
    // classify_path: existing behavior preserved
    // ------------------------------------------------------------------
    #[test]
    fn classifies_vendor_source() {
        let class = classify_path(b"vendor/lib/foo.rs");
        assert!(class.contains(PathClass::VENDOR));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_test_source() {
        let class = classify_path(b"tests/foo_test.py");
        assert!(class.contains(PathClass::TEST));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_generated_source() {
        let class = classify_path(b"generated/foo.go");
        assert!(class.contains(PathClass::GENERATED));
        assert!(class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_binary() {
        let class = classify_path(b"assets/logo.png");
        assert!(class.contains(PathClass::BINARY));
        assert!(!class.contains(PathClass::SOURCE));
    }

    #[test]
    fn classifies_unknown() {
        let class = classify_path(b"data/blob.xyz");
        assert!(class.contains(PathClass::UNKNOWN));
    }

    #[test]
    fn classifies_lock_file() {
        let class = classify_path(b"Cargo.lock");
        assert!(class.contains(PathClass::LOCK_FILE));
        assert!(!class.contains(PathClass::BINARY));
    }

    #[test]
    fn classifies_lock_file_in_subdir() {
        let class = classify_path(b"vendor/Gemfile.lock");
        assert!(class.contains(PathClass::LOCK_FILE));
        assert!(class.contains(PathClass::VENDOR));
    }

    #[test]
    fn pnpm_lock_yaml_not_source() {
        // pnpm-lock.yaml has .yaml extension (in SOURCE_EXTS) and its
        // filename is in LOCK_FILES. LOCK_FILE must suppress SOURCE —
        // lock files are not source code.
        let class = classify_path(b"pnpm-lock.yaml");
        assert!(class.contains(PathClass::LOCK_FILE));
        assert!(
            !class.contains(PathClass::SOURCE),
            "LOCK_FILE and SOURCE both set for pnpm-lock.yaml: {:#04x}",
            class.bits()
        );
    }

    #[test]
    fn pnpm_lock_yaml_in_subdir_not_source() {
        let class = classify_path(b"frontend/pnpm-lock.yaml");
        assert!(class.contains(PathClass::LOCK_FILE));
        assert!(!class.contains(PathClass::SOURCE));
    }

    // ------------------------------------------------------------------
    // is_nonscannable
    // ------------------------------------------------------------------
    #[test]
    fn is_nonscannable_binary() {
        let class = classify_path(b"logo.png");
        assert!(class.is_nonscannable());
    }

    #[test]
    fn is_nonscannable_lock() {
        let class = classify_path(b"Cargo.lock");
        assert!(class.is_nonscannable());
    }

    #[test]
    fn is_nonscannable_source() {
        let class = classify_path(b"main.rs");
        assert!(!class.is_nonscannable());
    }

    // ------------------------------------------------------------------
    // pack_ext
    // ------------------------------------------------------------------
    #[test]
    fn pack_ext_empty_and_too_long() {
        assert_eq!(pack_ext(b""), 0);
        assert_eq!(pack_ext(b"123456789"), 0); // 9 bytes
    }

    #[test]
    fn pack_ext_known_values() {
        // "png" -> [p=0x70][n=0x6e][g=0x67][0][0][0][0][0]
        assert_eq!(pack_ext(b"png"), 0x706e_6700_0000_0000);
        // "a" -> [a=0x61][0][0][0][0][0][0][0]
        assert_eq!(pack_ext(b"a"), 0x6100_0000_0000_0000);
    }

    // ------------------------------------------------------------------
    // Dotfiles
    // ------------------------------------------------------------------
    #[test]
    fn dotfile_no_extension() {
        let class = classify_path(b".gitignore");
        assert!(!class.contains(PathClass::BINARY));
        assert!(!class.contains(PathClass::LOCK_FILE));
    }
}

#[cfg(all(test, feature = "stdx-proptest"))]
#[path = "path_policy_tests.rs"]
mod path_policy_tests;
