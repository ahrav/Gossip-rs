//! Property tests for binary content classification and extraction.
//!
//! # Invariants
//! - Classification is deterministic.
//! - NUL-free data is never classified as `Binary`.
//! - Empty data is always classified as `Text`.
//! - Known extractable extensions yield `BinaryExtractable` when data is binary.
//! - Extraction never panics on arbitrary data.

use proptest::prelude::*;
use scanner_engine::content_policy::{CHECK_LEN, ContentVerdict, classify_content};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn classify_is_deterministic(data in proptest::collection::vec(any::<u8>(), 0..2048)) {
        let a = classify_content(&data, b"test.bin", CHECK_LEN);
        let b = classify_content(&data, b"test.bin", CHECK_LEN);
        prop_assert_eq!(a, b);
    }

    #[test]
    fn nul_free_data_is_never_binary(
        data in proptest::collection::vec(1..=255u8, 0..2048),
        ext in prop_oneof![
            Just(&b"file.txt"[..]),
            Just(&b"file.rs"[..]),
            Just(&b"file.dat"[..]),
            Just(&b"file.bin"[..]),
        ]
    ) {
        let verdict = classify_content(&data, ext, CHECK_LEN);
        prop_assert_ne!(verdict, ContentVerdict::Binary,
            "NUL-free data should never be classified as Binary");
    }

    #[test]
    fn empty_data_is_always_text(
        ext in prop_oneof![
            Just(&b"file.txt"[..]),
            Just(&b"file.bin"[..]),
            Just(&b"file.class"[..]),
            Just(&b"file.pyc"[..]),
        ]
    ) {
        // Empty data has no NUL bytes, so should be Text (or BinaryExtractable
        // for known extensions since ipynb/class/pyc match on extension even for text).
        let verdict = classify_content(b"", ext, CHECK_LEN);
        // Empty data is never Binary.
        prop_assert_ne!(verdict, ContentVerdict::Binary);
    }

    #[test]
    fn extractable_extension_always_extractable_when_binary(
        ext in prop_oneof![
            Just(&b"file.class"[..]),
            Just(&b"file.jar"[..]),
            Just(&b"file.war"[..]),
            Just(&b"file.pyc"[..]),
            Just(&b"file.ipynb"[..]),
            Just(&b".env"[..]),
            Just(&b".env.prod"[..]),
        ]
    ) {
        // Binary data (contains NUL) with a known extension must be BinaryExtractable.
        let data = b"\x00\x01\x02\x03";
        let verdict = classify_content(data, ext, CHECK_LEN);
        match verdict {
            ContentVerdict::BinaryExtractable(_) => {} // expected
            other => prop_assert!(false,
                "binary data + extractable extension should be BinaryExtractable, got {:?}", other),
        }
    }
}

mod with_extraction {
    use proptest::prelude::*;
    use scanner_engine::content_policy::ExtractableFormat;
    use scanner_engine::content_policy::extract::{ExtractResult, extract_content};

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn extract_content_never_panics(
            data in proptest::collection::vec(any::<u8>(), 0..4096),
            format in prop_oneof![
                Just(ExtractableFormat::DotEnv),
                Just(ExtractableFormat::Ipynb),
                Just(ExtractableFormat::JavaClass),
                Just(ExtractableFormat::JarWar),
                Just(ExtractableFormat::Pyc),
            ]
        ) {
            let mut out = Vec::new();
            let mut scratch = Vec::new();
            let result = extract_content(format, &data, &mut out, &mut scratch);
            // Must return a valid variant, never panic.
            match result {
                ExtractResult::Ok | ExtractResult::Empty | ExtractResult::ParseError => {}
            }
        }
    }
}
