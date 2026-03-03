//! Fuzz target for anchor soundness testing.
//!
//! This fuzzer checks the soundness invariant:
//!   if regex.is_match(haystack) && anchors_derived => some anchor in haystack
//!
//! # Input Format
//!
//! The fuzzer input is split at the first null byte:
//!   [pattern_utf8] 0x00 [haystack_bytes]
//!
//! If no null byte is present, the entire input is treated as pattern with empty haystack.
//!
//! # Running
//!
//! ```bash
//! cargo +nightly fuzz run fuzz_anchor_soundness
//! ```

#![no_main]

use libfuzzer_sys::fuzz_target;
use memchr::memmem;
use scanner_engine::regex2anchor::{derive_anchors_from_pattern, AnchorDeriveConfig};

/// Maximum pattern length to prevent pathological regex compilation.
const MAX_PATTERN_LEN: usize = 256;

/// Maximum haystack length to keep fuzzer iterations fast.
const MAX_HAYSTACK_LEN: usize = 512;

/// Check if haystack contains the needle.
#[inline]
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    memmem::find(haystack, needle).is_some()
}

/// Check if any anchor is present in the haystack.
#[inline]
fn anchors_cover(haystack: &[u8], anchors: &[Vec<u8>]) -> bool {
    anchors
        .iter()
        .any(|anchor| contains_subslice(haystack, anchor))
}

/// Compile a regex with safety limits.
fn compile_regex(pattern: &str) -> Option<regex::bytes::Regex> {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(1 << 18) // 256KB compiled size
        .dfa_size_limit(1 << 18) // 256KB DFA size
        .nest_limit(64) // Nesting depth
        .build()
        .ok()
}

fuzz_target!(|data: &[u8]| {
    // Split input at first null byte
    let (pattern_bytes, haystack) = match memchr::memchr(0, data) {
        Some(pos) => (&data[..pos], &data[pos + 1..]),
        None => (data, &[][..]),
    };

    // Apply size limits
    if pattern_bytes.len() > MAX_PATTERN_LEN || haystack.len() > MAX_HAYSTACK_LEN {
        return;
    }

    // Pattern must be valid UTF-8
    let pattern = match std::str::from_utf8(pattern_bytes) {
        Ok(s) => s,
        Err(_) => return,
    };

    // Skip empty patterns (they match empty which is unanchorable)
    if pattern.is_empty() {
        return;
    }

    // Try to compile the regex
    let regex = match compile_regex(pattern) {
        Some(re) => re,
        None => return, // Invalid or too complex pattern
    };

    // Configuration for anchor derivation
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1, // Use low threshold to find more bugs
        max_exact_set: 64,
        max_exact_string_len: 128,
        max_class_expansion: 16,
        utf8: false,
        kgram_k: 4,
        max_kgram_set: 4096,
        max_kgram_alphabet: 32,
    };

    // Try to derive anchors
    let anchors = match derive_anchors_from_pattern(pattern, &cfg) {
        Ok(a) => a,
        Err(_) => return, // Derivation failed (conservative, safe)
    };

    // THE SOUNDNESS CHECK
    // If the regex matches the haystack, at least one anchor must be present
    if regex.is_match(haystack) {
        assert!(
            anchors_cover(haystack, &anchors),
            "SOUNDNESS BUG FOUND!\n\
             Pattern: {:?}\n\
             Haystack: {:?}\n\
             Haystack (bytes): {:?}\n\
             Anchors: {:?}\n\
             Regex matches: true\n\
             Anchor found: false",
            pattern,
            String::from_utf8_lossy(haystack),
            haystack,
            anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );
    }
});
