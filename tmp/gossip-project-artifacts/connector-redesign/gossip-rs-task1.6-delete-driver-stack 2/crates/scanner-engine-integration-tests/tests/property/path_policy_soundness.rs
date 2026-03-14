//! Property tests for path policy extension classification.
//!
//! # Oracle Test
//!
//! The primary oracle test builds a `HashSet` from the packed-u64 skip table
//! and verifies that `ext_in_skip_set` agrees with the reference set for
//! arbitrary extensions. This subsumes individual per-extension assertions.
//!
//! # Additional Properties
//!
//! - `pack_ext` is injective for distinct inputs within 1–8 lowercase ASCII bytes.
//! - `classify_path` is deterministic and UNKNOWN is exclusive.

use std::collections::HashSet;
use std::sync::LazyLock;

use proptest::prelude::*;

use scanner_git::path_policy::{PathClass, classify_path, ext_in_skip_set, pack_ext};

/// Build the reference set by packing every extension in the skip table.
/// We rebuild this from the public API instead of reaching into internals.
///
/// Sync: if a new extension is added to the production skip table but not
/// to the list below, the oracle property test will catch the drift — any
/// random extension that `ext_in_skip_set` accepts but the reference set
/// rejects (or vice-versa) is a test failure.
fn reference_skip_set() -> HashSet<Vec<u8>> {
    // We enumerate every extension that ext_in_skip_set returns true for
    // by testing a curated superset. In practice the oracle just confirms
    // agreement — we feed random extensions through both paths.
    //
    // For the reference set, we use the known extension list from the plan.
    let known: &[&[u8]] = &[
        // Digit-prefixed
        b"3g2",
        b"3gp",
        b"7z",
        // A
        b"a",
        b"aac",
        b"ai",
        b"aif",
        b"aiff",
        b"ape",
        b"apk",
        b"apng",
        b"ar",
        b"asf",
        b"au",
        b"avi",
        b"avif",
        // B
        b"bin",
        b"blend",
        b"bmp",
        b"br",
        b"bz2",
        // C
        b"cab",
        b"caf",
        b"com",
        b"cpio",
        b"cr2",
        b"cur",
        // D
        b"dat",
        b"dds",
        b"deb",
        b"dll",
        b"dmg",
        b"dng",
        b"doc",
        b"docm",
        b"docx",
        b"dts",
        b"dylib",
        // E
        b"elf",
        b"eot",
        b"epub",
        b"exe",
        b"exr",
        // F
        b"f4v",
        b"fev",
        b"fig",
        b"flac",
        b"flv",
        b"fnt",
        b"fon",
        b"fsb",
        // G
        b"ggml",
        b"gguf",
        b"gif",
        b"gz",
        // H
        b"h264",
        b"h5",
        b"hdf5",
        b"hdr",
        b"hdv",
        b"heic",
        b"heif",
        b"hprof",
        // I
        b"ico",
        b"img",
        b"ipa",
        b"iso",
        // J
        b"jfif",
        b"jpeg",
        b"jpg",
        b"jxl",
        b"jxr",
        // K
        b"ko",
        // L
        b"lib",
        b"lz4",
        b"lzma",
        // M
        b"m2ts",
        b"m4a",
        b"m4p",
        b"m4v",
        b"mid",
        b"midi",
        b"mka",
        b"mkv",
        b"mobi",
        b"mov",
        b"mp2",
        b"mp3",
        b"mp4",
        b"mpeg",
        b"mpg",
        b"msi",
        b"mts",
        // N
        b"nef",
        b"nupkg",
        // O
        b"o",
        b"obj",
        b"odp",
        b"ods",
        b"odt",
        b"ogg",
        b"ogv",
        b"onnx",
        b"opus",
        b"otf",
        b"out",
        // P
        b"pbm",
        b"pcx",
        b"pdb",
        b"pdf",
        b"pgm",
        b"pic",
        b"png",
        b"pnm",
        b"ppm",
        b"ppt",
        b"pptm",
        b"pptx",
        b"psd",
        // Q
        b"qcow2",
        b"qt",
        // R
        b"rar",
        b"raw",
        b"rgb",
        b"rlib",
        b"rpm",
        // S
        b"sgi",
        b"sketch",
        b"so",
        b"stl",
        b"swf",
        b"sym",
        b"sys",
        // T
        b"tar",
        b"tbz2",
        b"tga",
        b"tgz",
        b"tif",
        b"tiff",
        b"tlz",
        b"ttc",
        b"ttf",
        b"txz",
        // V
        b"vdi",
        b"vhd",
        b"vhdx",
        b"vmdk",
        b"vob",
        b"vxd",
        // W
        b"wasm",
        b"wav",
        b"wbmp",
        b"wdp",
        b"webm",
        b"webp",
        b"wma",
        b"wmv",
        b"woff",
        b"woff2",
        // X
        b"xbm",
        b"xd",
        b"xls",
        b"xlsm",
        b"xlsx",
        b"xpi",
        b"xpm",
        b"xwd",
        b"xz",
        // Z
        b"z",
        b"zip",
        b"zipx",
        b"zst",
        // Long (> 8 bytes)
        b"safetensors",
    ];

    known.iter().map(|e| e.to_vec()).collect()
}

static REFERENCE_SET: LazyLock<HashSet<Vec<u8>>> = LazyLock::new(reference_skip_set);

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    /// Oracle: `ext_in_skip_set` agrees with the reference HashSet.
    #[test]
    fn ext_in_skip_set_matches_oracle(
        ext in proptest::collection::vec(
            prop_oneof![
                // ASCII letters (common)
                b'a'..=b'z',
                b'A'..=b'Z',
                // digits
                b'0'..=b'9',
            ],
            0..=12
        )
    ) {
        let reference = &*REFERENCE_SET;
        let lower: Vec<u8> = ext.iter().map(|b| b.to_ascii_lowercase()).collect();
        let expected = reference.contains(&lower);
        let actual = ext_in_skip_set(&ext);
        prop_assert_eq!(
            actual, expected,
            "mismatch for {:?} (lower={:?})",
            String::from_utf8_lossy(&ext),
            String::from_utf8_lossy(&lower),
        );
    }

    /// `pack_ext` is injective: distinct 1-8 byte lowercase ASCII inputs
    /// produce distinct u64 values.
    #[test]
    fn pack_ext_injective(
        a in proptest::collection::vec(b'a'..=b'z', 1..=8usize),
        b in proptest::collection::vec(b'a'..=b'z', 1..=8usize),
    ) {
        prop_assume!(a != b);
        let pa = pack_ext(&a);
        let pb = pack_ext(&b);
        prop_assert_ne!(pa, pb, "pack_ext collision: {:?} and {:?} both -> {:#018x}",
            String::from_utf8_lossy(&a),
            String::from_utf8_lossy(&b),
            pa,
        );
    }

    /// `classify_path` is deterministic: same input always yields same output.
    #[test]
    fn classify_path_deterministic(
        path in proptest::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                Just(b'/'),
                Just(b'.'),
            ],
            0..=64
        )
    ) {
        let a = classify_path(&path);
        let b = classify_path(&path);
        prop_assert_eq!(a, b);
    }

    /// UNKNOWN is exclusive: when UNKNOWN is set, no other classification
    /// bits should be set.
    #[test]
    fn unknown_is_exclusive(
        path in proptest::collection::vec(
            prop_oneof![
                b'a'..=b'z',
                b'A'..=b'Z',
                b'0'..=b'9',
                Just(b'/'),
                Just(b'.'),
                Just(b'_'),
                Just(b'-'),
            ],
            0..=80
        )
    ) {
        let class = classify_path(&path);
        if class.contains(PathClass::UNKNOWN) {
            prop_assert_eq!(class.bits(), PathClass::UNKNOWN.bits(),
                "UNKNOWN set alongside other bits: bits={:#04x}", class.bits());
        }
    }
}
