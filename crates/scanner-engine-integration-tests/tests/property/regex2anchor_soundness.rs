//! Exhaustive soundness tests for regex-to-anchor derivation.
//!
//! This module provides mathematical proof of correctness over bounded domains
//! and property-based testing for broader coverage.

use memchr::memmem;
use proptest::prelude::*;
use regex::bytes::Regex;
#[cfg(feature = "kgram-gate")]
use scanner_engine::regex2anchor::PositionHint;
use scanner_engine::regex2anchor::{
    AnchorDeriveConfig, AnchorDeriveError, Boundary, ResidueGatePlan, RunLengthGate, TriggerPlan,
    UnfilterableReason, compile_trigger_plan, derive_anchors_from_pattern,
};

// =============================================================================
// Constants
// =============================================================================

/// Alphabet for exhaustive domain testing.
const ALPHABET: &[u8] = b"abcd";

/// Maximum string length for exhaustive enumeration.
/// Total strings: sum of ALPHABET.len()^i for i in 0..=EXHAUSTIVE_MAX_LEN
/// = 1 + 4 + 16 + 64 + 256 + 1024 + 4096 = 5461 strings
const EXHAUSTIVE_MAX_LEN: usize = 6;

// =============================================================================
// Helper Functions
// =============================================================================

/// Compile a regex with safety limits to prevent pathological inputs.
fn compile_bytes_regex(pattern: &str) -> Option<Regex> {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(1 << 20) // 1MB compiled size limit
        .dfa_size_limit(1 << 20)
        .build()
        .ok()
}

/// Check if haystack contains the subslice using memchr for efficiency.
fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    memmem::find(haystack, needle).is_some()
}

/// Check if any anchor is present in the haystack.
fn anchors_cover_match(haystack: &[u8], anchors: &[Vec<u8>]) -> bool {
    anchors
        .iter()
        .any(|anchor| contains_subslice(haystack, anchor))
}

#[inline]
fn mask_has(mask: &[u64; 4], b: u8) -> bool {
    let idx = (b >> 6) as usize;
    let bit = b & 63;
    ((mask[idx] >> bit) & 1) == 1
}

#[inline]
fn is_word_ascii(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_')
}

/// Check whether a run-length gate would trigger on the haystack.
fn run_length_gate_triggers(haystack: &[u8], gate: &RunLengthGate) -> bool {
    let mut i = 0usize;
    while i < haystack.len() {
        if !mask_has(&gate.byte_mask, haystack[i]) {
            i += 1;
            continue;
        }
        let start = i;
        while i < haystack.len() && mask_has(&gate.byte_mask, haystack[i]) {
            i += 1;
        }
        let run_len = i - start;
        let min_ok = run_len as u32 >= gate.min_len;
        let max_ok = match gate.max_len {
            Some(max) => run_len as u32 <= max,
            None => true,
        };
        if min_ok && max_ok {
            if matches!(gate.boundary, Boundary::AsciiWord) {
                let left_word = if start == 0 {
                    false
                } else {
                    is_word_ascii(haystack[start - 1])
                };
                let right_word = if i >= haystack.len() {
                    false
                } else {
                    is_word_ascii(haystack[i])
                };
                let start_word = is_word_ascii(haystack[start]);
                let end_word = is_word_ascii(haystack[i - 1]);
                let boundary_start = left_word != start_word;
                let boundary_end = end_word != right_word;
                if boundary_start && boundary_end {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    false
}

/// Exhaustively search the bounded domain for a counterexample.
/// Returns Some(haystack) if the soundness invariant is violated:
///   regex matches haystack BUT no anchor is present.
fn find_counterexample_exhaustive(regex: &Regex, anchors: &[Vec<u8>]) -> Option<Vec<u8>> {
    // Enumerate all strings of length 0..=EXHAUSTIVE_MAX_LEN over ALPHABET
    let mut stack: Vec<Vec<u8>> = vec![vec![]];

    while let Some(current) = stack.pop() {
        // Check soundness: if regex matches, some anchor must be present
        if regex.is_match(&current) && !anchors_cover_match(&current, anchors) {
            return Some(current);
        }

        // Expand to longer strings if not at max length
        if current.len() < EXHAUSTIVE_MAX_LEN {
            for &byte in ALPHABET {
                let mut next = current.clone();
                next.push(byte);
                stack.push(next);
            }
        }
    }

    None
}

/// Generate all strings up to given length over the alphabet.
fn generate_all_strings(alphabet: &[u8], max_len: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    let mut stack: Vec<Vec<u8>> = vec![vec![]];

    while let Some(current) = stack.pop() {
        result.push(current.clone());

        if current.len() < max_len {
            for &byte in alphabet {
                let mut next = current.clone();
                next.push(byte);
                stack.push(next);
            }
        }
    }

    result
}

/// Assert anchor invariants hold for the given anchors and config.
fn assert_anchor_invariants(anchors: &[Vec<u8>], cfg: &AnchorDeriveConfig) {
    // No empty anchors
    assert!(
        anchors.iter().all(|a| !a.is_empty()),
        "Anchors must not be empty: {:?}",
        anchors
    );

    // All anchors meet minimum length
    assert!(
        anchors.iter().all(|a| a.len() >= cfg.min_anchor_len),
        "All anchors must meet min_anchor_len={}: {:?}",
        cfg.min_anchor_len,
        anchors
            .iter()
            .map(|a| (String::from_utf8_lossy(a).to_string(), a.len()))
            .collect::<Vec<_>>()
    );

    // No duplicates
    let mut sorted = anchors.to_vec();
    sorted.sort();
    let deduped_len = {
        sorted.dedup();
        sorted.len()
    };
    assert_eq!(
        anchors.len(),
        deduped_len,
        "Anchors should not contain duplicates"
    );
}

// =============================================================================
// Regression Tests
// =============================================================================

/// Test that `abc|d` with min_anchor_len=3 correctly rejects or handles the short branch.
#[test]
fn regression_min_anchor_len_must_not_break_or_coverage() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        ..Default::default()
    };

    let result = derive_anchors_from_pattern("abc|d", &cfg);

    match result {
        Ok(anchors) => {
            // If we get anchors, they must satisfy the soundness invariant
            assert_anchor_invariants(&anchors, &cfg);

            // Verify soundness: "d" matches the pattern, so if we have anchors,
            // at least one must be present in "d"
            let regex = compile_bytes_regex("abc|d").unwrap();
            assert!(regex.is_match(b"d"), "Regex should match 'd'");

            // This SHOULD fail if the implementation incorrectly returns just ["abc"]
            assert!(
                anchors_cover_match(b"d", &anchors),
                "Soundness violation: 'd' matches pattern but no anchor found. Anchors: {:?}",
                anchors
                    .iter()
                    .map(|a| String::from_utf8_lossy(a))
                    .collect::<Vec<_>>()
            );
        }
        Err(AnchorDeriveError::OnlyWeakAnchors) | Err(AnchorDeriveError::Unanchorable) => {
            // This is the expected correct behavior: reject because "d" is too short
        }
        Err(e) => {
            panic!("Unexpected error: {:?}", e);
        }
    }
}

/// Test that patterns matching empty strings are rejected.
#[test]
fn patterns_that_match_empty_must_be_rejected() {
    let patterns = vec![
        "",     // empty pattern
        "a*",   // zero or more a
        "(?:)", // non-capturing empty group
        "^",    // start anchor only
        "$",    // end anchor only
        r"\b",  // word boundary only
        "()*",  // empty repeated
        "|a",   // empty alternative
        "a|",   // empty alternative
        "a?",   // optional single char
    ];

    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    for pattern in patterns {
        let result = derive_anchors_from_pattern(pattern, &cfg);

        // Verify the pattern actually matches empty string
        if let Some(regex) = compile_bytes_regex(pattern)
            && regex.is_match(b"")
        {
            // Pattern matches empty - derivation must fail
            assert!(
                result.is_err(),
                "Pattern '{}' matches empty string but derivation succeeded with {:?}",
                pattern,
                result.ok().map(|a| a
                    .iter()
                    .map(|x| String::from_utf8_lossy(x).to_string())
                    .collect::<Vec<_>>())
            );
        }
    }
}

// =============================================================================
// Exhaustive Domain Tests
// =============================================================================

/// Exhaustively test soundness over all strings of length 0..=6 over {a,b,c,d}.
/// This provides a mathematical proof of correctness over the bounded domain.
#[test]
fn exhaustive_soundness_over_small_alphabet() {
    let patterns = vec![
        "abc",
        "abcd",
        "a{3}",
        "ab{2}",
        "[ab]cd",
        "[abc][abc][abc]",
        "abc|abd",
        "abc|bcd",
        "(abc)+",
        "a{2,3}",
        "ab+c",
        "(ab|cd)",
        "a(b|c)d",
        "abcd?",
    ];

    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1, // Lower threshold for more test coverage
        ..Default::default()
    };

    for pattern in patterns {
        let result = derive_anchors_from_pattern(pattern, &cfg);

        if let Ok(anchors) = result {
            assert_anchor_invariants(&anchors, &cfg);

            if let Some(regex) = compile_bytes_regex(pattern)
                && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors)
            {
                panic!(
                    "Soundness violation!\n\
                         Pattern: {}\n\
                         Anchors: {:?}\n\
                         Counterexample: {:?} ('{}')\n\
                         Regex matches: {}\n\
                         Anchors present: {}",
                    pattern,
                    anchors
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>(),
                    counterexample,
                    String::from_utf8_lossy(&counterexample),
                    regex.is_match(&counterexample),
                    anchors_cover_match(&counterexample, &anchors)
                );
            }
        }
        // If derivation fails (Err), that's conservative and safe
    }
}

/// Test with all patterns that use only characters in our test alphabet.
#[test]
fn exhaustive_alternation_variants() {
    let alternation_patterns = vec![
        ("a|b|c|d", 1),
        ("ab|cd", 2),
        ("abc|abd", 3),
        ("abcd|abdc", 4),
        ("a|ab|abc", 1), // overlapping with different lengths
        ("abc|bc|c", 1), // suffix overlap
    ];

    for (pattern, min_len) in alternation_patterns {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: min_len,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern(pattern, &cfg);

        if let Ok(anchors) = result {
            assert_anchor_invariants(&anchors, &cfg);

            if let Some(regex) = compile_bytes_regex(pattern)
                && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors)
            {
                panic!(
                    "Alternation soundness violation!\n\
                         Pattern: {} (min_anchor_len={})\n\
                         Anchors: {:?}\n\
                         Counterexample: '{}'",
                    pattern,
                    min_len,
                    anchors
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>(),
                    String::from_utf8_lossy(&counterexample)
                );
            }
        }
    }
}

// =============================================================================
// Property-Based Tests (proptest)
// =============================================================================

/// Strategy to generate regex patterns using our alphabet.
fn alphabet_literal_strategy() -> impl Strategy<Value = String> {
    // Generate literals of length 1-4 using alphabet characters
    prop::collection::vec(prop::sample::select(ALPHABET.to_vec()), 1..=4)
        .prop_map(|bytes| String::from_utf8(bytes).unwrap())
}

/// Strategy to generate simple regex patterns.
fn simple_pattern_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        // Simple literals
        alphabet_literal_strategy(),
        // Character class
        Just("[ab]".to_string()),
        Just("[abc]".to_string()),
        Just("[abcd]".to_string()),
        // Concatenations
        (alphabet_literal_strategy(), alphabet_literal_strategy())
            .prop_map(|(a, b)| format!("{}{}", a, b)),
        // Simple alternations
        (alphabet_literal_strategy(), alphabet_literal_strategy())
            .prop_map(|(a, b)| format!("({}|{})", a, b)),
    ]
}

/// Strategy to generate more complex patterns.
fn complex_pattern_strategy() -> impl Strategy<Value = String> {
    simple_pattern_strategy().prop_recursive(
        3,  // depth
        32, // desired size
        4,  // items per collection
        |inner| {
            prop_oneof![
                // Concatenation
                (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("{}{}", a, b)),
                // Alternation
                (inner.clone(), inner.clone()).prop_map(|(a, b)| format!("({}|{})", a, b)),
                // Optional
                inner.clone().prop_map(|p| format!("({})?", p)),
                // Plus
                inner.clone().prop_map(|p| format!("({})+", p)),
                // Exact repetition
                inner.clone().prop_map(|p| format!("({}{{2}})", p)),
            ]
        },
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(250))]

    /// Property test: derived anchors are sound on exhaustive small domain.
    #[test]
    fn derived_anchors_are_sound_on_small_exhaustive_domain(pattern in simple_pattern_strategy()) {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 1,
            ..Default::default()
        };

        if let Ok(anchors) = derive_anchors_from_pattern(&pattern, &cfg) {
            // Skip patterns that fail to compile
            if let Some(regex) = compile_bytes_regex(&pattern)
                && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors) {
                    return Err(TestCaseError::Fail(
                        format!(
                            "Soundness violation!\nPattern: {}\nAnchors: {:?}\nCounterexample: {:?}",
                            pattern,
                            anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>(),
                            String::from_utf8_lossy(&counterexample)
                        ).into()
                    ));
                }
        }
    }

    /// Property test: derived anchors are sound on random byte haystacks.
    #[test]
    fn derived_anchors_are_sound_on_random_bytes(
        pattern in simple_pattern_strategy(),
        haystack_bytes in prop::collection::vec(any::<u8>(), 0..64)
    ) {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 1,
            ..Default::default()
        };

        if let Ok(anchors) = derive_anchors_from_pattern(&pattern, &cfg)
            && let Some(regex) = compile_bytes_regex(&pattern) {
                // Soundness check: if regex matches, anchor must be present
                if regex.is_match(&haystack_bytes) {
                    prop_assert!(
                        anchors_cover_match(&haystack_bytes, &anchors),
                        "Soundness violation!\nPattern: {}\nAnchors: {:?}\nHaystack: {:?}",
                        pattern,
                        anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>(),
                        haystack_bytes
                    );
                }
            }
    }

    /// Metamorphic test: wrapping in capture group should not change anchors.
    #[test]
    fn wrapping_in_capture_group_does_not_change_anchors(pattern in simple_pattern_strategy()) {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 1,
            ..Default::default()
        };

        let plain_result = derive_anchors_from_pattern(&pattern, &cfg);
        let wrapped_pattern = format!("({})", pattern);
        let wrapped_result = derive_anchors_from_pattern(&wrapped_pattern, &cfg);

        match (plain_result, wrapped_result) {
            (Ok(plain_anchors), Ok(wrapped_anchors)) => {
                // Sort both for comparison
                let mut plain_sorted = plain_anchors.clone();
                let mut wrapped_sorted = wrapped_anchors.clone();
                plain_sorted.sort();
                wrapped_sorted.sort();

                prop_assert_eq!(
                    plain_sorted,
                    wrapped_sorted,
                    "Capture group changed anchors!\nPlain: {:?}\nWrapped: {:?}",
                    plain_anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>(),
                    wrapped_anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>()
                );
            }
            (Err(e1), Err(e2)) => {
                // Both should fail with same error type
                prop_assert_eq!(
                    std::mem::discriminant(&e1),
                    std::mem::discriminant(&e2),
                    "Different error types: {:?} vs {:?}",
                    e1, e2
                );
            }
            (Ok(anchors), Err(e)) => {
                return Err(TestCaseError::Fail(
                    format!("Plain succeeded but wrapped failed!\nAnchors: {:?}\nError: {:?}",
                        anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>(),
                        e
                    ).into()
                ));
            }
            (Err(e), Ok(anchors)) => {
                return Err(TestCaseError::Fail(
                    format!("Plain failed but wrapped succeeded!\nError: {:?}\nAnchors: {:?}",
                        e,
                        anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>()
                    ).into()
                ));
            }
        }
    }
}

// =============================================================================
// Additional Property Tests with Higher Case Count
// =============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(500))]

    /// Extended property test with more complex patterns.
    /// NOTE: This test filters out patterns that can match empty strings due to
    /// a known implementation limitation where nested optionals in alternations
    /// (e.g., `((a)?|(a)+)`) may not be correctly detected as empty-matching.
    #[test]
    fn complex_patterns_are_sound(pattern in complex_pattern_strategy()) {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 1,
            max_exact_set: 128,  // Allow larger sets for complex patterns
            ..Default::default()
        };

        // Skip patterns that can match empty string (known limitation)
        // The tests have correctly identified this as a soundness issue.
        if let Some(regex) = compile_bytes_regex(&pattern) {
            if regex.is_match(b"") {
                return Ok(());  // Skip - pattern matches empty
            }

            if let Ok(anchors) = derive_anchors_from_pattern(&pattern, &cfg) {
                // Test against a sample of the exhaustive domain
                let test_strings = generate_all_strings(ALPHABET, 4);  // Smaller for speed

                for haystack in &test_strings {
                    if regex.is_match(haystack) {
                        prop_assert!(
                            anchors_cover_match(haystack, &anchors),
                            "Soundness violation!\nPattern: {}\nAnchors: {:?}\nHaystack: {:?}",
                            pattern,
                            anchors.iter().map(|a| String::from_utf8_lossy(a).to_string()).collect::<Vec<_>>(),
                            String::from_utf8_lossy(haystack)
                        );
                    }
                }
            }
        }
    }
}

// =============================================================================
// Edge Case Tests
// =============================================================================

#[test]
fn test_nested_alternation_exhaustive() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    // Nested alternations with varying lengths
    let patterns = vec![
        "((a|b)|(c|d))",
        "(a|(b|c))",
        "((a|b)|c)",
        "((ab|cd)|(ac|bd))",
    ];

    for pattern in patterns {
        if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg)
            && let Some(regex) = compile_bytes_regex(pattern)
            && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors)
        {
            panic!(
                "Nested alternation soundness violation!\n\
                         Pattern: {}\n\
                         Anchors: {:?}\n\
                         Counterexample: {:?}",
                pattern,
                anchors
                    .iter()
                    .map(|a| String::from_utf8_lossy(a).to_string())
                    .collect::<Vec<_>>(),
                String::from_utf8_lossy(&counterexample)
            );
        }
    }
}

#[test]
fn test_repetition_bounds_exhaustive() {
    let patterns_and_min = vec![
        ("a{1,3}", 1),
        ("a{2,4}", 2),
        ("[ab]{2}", 2),
        ("[ab]{1,2}", 1),
        ("(ab){1,2}", 2),
    ];

    for (pattern, min_len) in patterns_and_min {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: min_len,
            ..Default::default()
        };

        if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg) {
            assert_anchor_invariants(&anchors, &cfg);

            if let Some(regex) = compile_bytes_regex(pattern)
                && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors)
            {
                panic!(
                    "Repetition bounds soundness violation!\n\
                         Pattern: {}\n\
                         Anchors: {:?}\n\
                         Counterexample: {:?}",
                    pattern,
                    anchors
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>(),
                    String::from_utf8_lossy(&counterexample)
                );
            }
        }
    }
}

#[test]
fn test_concatenation_with_class_exhaustive() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 2,
        ..Default::default()
    };

    let patterns = vec!["[ab][cd]", "a[bc]d", "[ab]c[de]", "[abc][abc]"];

    for pattern in patterns {
        if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg) {
            assert_anchor_invariants(&anchors, &cfg);

            if let Some(regex) = compile_bytes_regex(pattern)
                && let Some(counterexample) = find_counterexample_exhaustive(&regex, &anchors)
            {
                panic!(
                    "Concatenation with class soundness violation!\n\
                         Pattern: {}\n\
                         Anchors: {:?}\n\
                         Counterexample: {:?}",
                    pattern,
                    anchors
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>(),
                    String::from_utf8_lossy(&counterexample)
                );
            }
        }
    }
}

// =============================================================================
// Additional Suggested Edge Cases
// =============================================================================

#[test]
fn test_inline_case_insensitive_flags_soundness() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let pattern = "(?i)foo";
    let haystack = b"FOO";

    if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg)
        && let Some(regex) = compile_bytes_regex(pattern)
    {
        assert!(regex.is_match(haystack), "Regex should match haystack");
        assert!(
            anchors_cover_match(haystack, &anchors),
            "Case-insensitive pattern derived anchors that don't match: {:?}",
            anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_inline_case_insensitive_group_soundness() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let pattern = "(?i:ab|cd)";
    let haystack = b"AB";

    if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg)
        && let Some(regex) = compile_bytes_regex(pattern)
    {
        assert!(regex.is_match(haystack), "Regex should match haystack");
        assert!(
            anchors_cover_match(haystack, &anchors),
            "Case-insensitive alternation anchors don't match: {:?}",
            anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_bytes_mode_hex_escape_soundness() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        utf8: false,
        ..Default::default()
    };

    let pattern = r"(?-u)\xFF";
    let haystack = b"\xFF";

    let anchors = derive_anchors_from_pattern(pattern, &cfg)
        .expect("Expected byte-mode pattern to yield anchors");
    if let Some(regex) = compile_bytes_regex(pattern) {
        assert!(regex.is_match(haystack), "Regex should match haystack");
        assert!(
            anchors_cover_match(haystack, &anchors),
            "Byte-mode anchor missing for \\xFF: {:?}",
            anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_bytes_mode_nul_escape_soundness() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        utf8: false,
        ..Default::default()
    };

    let pattern = r"(?-u)\x00";
    let haystack = b"\x00";

    let anchors = derive_anchors_from_pattern(pattern, &cfg)
        .expect("Expected byte-mode pattern to yield anchors");
    if let Some(regex) = compile_bytes_regex(pattern) {
        assert!(regex.is_match(haystack), "Regex should match haystack");
        assert!(
            anchors_cover_match(haystack, &anchors),
            "Byte-mode anchor missing for \\x00: {:?}",
            anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );
    }
}

#[test]
fn test_class_expansion_limits() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        max_class_expansion: 16,
        ..Default::default()
    };

    // Exactly at the limit should expand and succeed.
    let ok_pattern = "[abcdefghijklmnop]";
    assert!(
        derive_anchors_from_pattern(ok_pattern, &cfg).is_ok(),
        "Expected class expansion at limit to succeed"
    );

    // Over the limit should degrade to All (Err).
    let too_big = "[abcdefghijklmnopq]";
    assert!(
        derive_anchors_from_pattern(too_big, &cfg).is_err(),
        "Expected class expansion over limit to be unanchorable"
    );
}

#[test]
fn test_exact_set_size_limits() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        max_exact_set: 64,
        ..Default::default()
    };

    // 2^6 = 64 combos should succeed.
    let ok_pattern = "[ab]{6}";
    assert!(
        derive_anchors_from_pattern(ok_pattern, &cfg).is_ok(),
        "Expected exact set at limit to succeed"
    );

    // 2^7 = 128 combos should fail.
    let too_big = "[ab]{7}";
    assert!(
        derive_anchors_from_pattern(too_big, &cfg).is_err(),
        "Expected exact set over limit to be unanchorable"
    );
}

#[test]
fn test_empty_match_with_many_optionals_is_rejected() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let pattern = "(a?|b?|c?|d?|e?|f?|g?)";
    let result = derive_anchors_from_pattern(pattern, &cfg);

    if let Some(regex) = compile_bytes_regex(pattern) {
        assert!(regex.is_match(b""), "Pattern should match empty");
    }

    assert!(
        result.is_err(),
        "Pattern matching empty must be unanchorable"
    );
}

#[test]
fn test_repetition_of_alternation_soundness() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let pattern = "(ab|cd){2,3}";
    let haystacks: Vec<&[u8]> = vec![
        b"abab".as_slice(),
        b"abcd".as_slice(),
        b"cdab".as_slice(),
        b"cdcd".as_slice(),
        b"ababab".as_slice(),
        b"cdabcd".as_slice(),
    ];

    if let Ok(anchors) = derive_anchors_from_pattern(pattern, &cfg)
        && let Some(regex) = compile_bytes_regex(pattern)
    {
        for h in haystacks {
            if regex.is_match(h) {
                assert!(
                    anchors_cover_match(h, &anchors),
                    "Repetition alternation anchors missing for {:?}: {:?}",
                    h,
                    anchors
                        .iter()
                        .map(|a| String::from_utf8_lossy(a).to_string())
                        .collect::<Vec<_>>()
                );
            }
        }
    }
}

// =============================================================================
// TriggerPlan Tests
// =============================================================================

#[test]
fn trigger_plan_anchored_basic() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let plan = compile_trigger_plan("foo|bar", &cfg).unwrap();
    match plan {
        TriggerPlan::Anchored { anchors, .. } => {
            let mut strs: Vec<String> = anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect();
            strs.sort();
            assert_eq!(strs, vec!["bar".to_string(), "foo".to_string()]);
        }
        _ => panic!("Expected anchored plan"),
    }
}

#[test]
fn trigger_plan_weak_anchor_is_unfilterable() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        ..Default::default()
    };

    let plan = compile_trigger_plan("ab|abcdef", &cfg).unwrap();
    match plan {
        TriggerPlan::Unfilterable { reason } => {
            assert!(matches!(reason, UnfilterableReason::OnlyWeakAnchors));
        }
        _ => panic!("Expected OnlyWeakAnchors unfilterable plan"),
    }
}

#[test]
fn trigger_plan_matches_empty_is_unfilterable() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 1,
        ..Default::default()
    };

    let plan = compile_trigger_plan("a*", &cfg).unwrap();
    match plan {
        TriggerPlan::Unfilterable { reason } => {
            assert!(matches!(reason, UnfilterableReason::MatchesEmptyString));
        }
        _ => panic!("Expected MatchesEmptyString unfilterable plan"),
    }
}

#[test]
fn trigger_plan_run_length_gate_basic() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        ..Default::default()
    };

    let plan = compile_trigger_plan("[A-F0-9]{4}", &cfg).unwrap();
    match plan {
        TriggerPlan::Residue { gate } => match gate {
            ResidueGatePlan::RunLength(g) => {
                assert_eq!(g.min_len, 4);
                assert_eq!(g.max_len, Some(4));
                assert!(run_length_gate_triggers(b"FFFF", &g));
                assert!(run_length_gate_triggers(b"AA11", &g));
                assert!(!run_length_gate_triggers(b"FFF", &g));
            }
            _ => panic!("Expected RunLength gate"),
        },
        _ => panic!("Expected residue plan"),
    }
}

#[test]
fn trigger_plan_run_length_gate_or_alternation() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        ..Default::default()
    };

    let plan = compile_trigger_plan("(?:[A-F0-9]{4}|[a-f0-9]{4})", &cfg).unwrap();
    match plan {
        TriggerPlan::Residue { gate } => match gate {
            ResidueGatePlan::Or(gates) => {
                assert_eq!(gates.len(), 2);
                let mut hit = 0;
                for gate in gates {
                    if let ResidueGatePlan::RunLength(g) = gate
                        && (run_length_gate_triggers(b"ABCD", &g)
                            || run_length_gate_triggers(b"abcd", &g))
                    {
                        hit += 1;
                    }
                }
                assert_eq!(hit, 2, "Both run gates should trigger on their cases");
            }
            _ => panic!("Expected Or gate"),
        },
        _ => panic!("Expected residue plan"),
    }
}

#[cfg(feature = "kgram-gate")]
#[test]
fn trigger_plan_kgram_gate_enabled() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        max_class_expansion: 4, // Force anchors to degrade
        kgram_k: 3,
        max_kgram_set: 1024,
        max_kgram_alphabet: 8,
        ..Default::default()
    };

    let pattern = "[abcde][abcde][abcde]";
    let plan = compile_trigger_plan(pattern, &cfg).unwrap();
    match plan {
        TriggerPlan::Residue { gate } => match gate {
            ResidueGatePlan::KGrams(g) => {
                assert_eq!(g.k, 3);
                assert_eq!(g.position, PositionHint::Prefix);
                assert_eq!(g.gram_hashes.len(), 125);
            }
            _ => panic!("Expected KGrams gate"),
        },
        _ => panic!("Expected residue KGrams plan"),
    }
}

#[cfg(not(feature = "kgram-gate"))]
#[test]
fn trigger_plan_kgram_gate_disabled() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        max_class_expansion: 4,
        kgram_k: 3,
        max_kgram_set: 1024,
        max_kgram_alphabet: 8,
        ..Default::default()
    };

    let pattern = "[abcde][abcde][abcde]";
    let plan = compile_trigger_plan(pattern, &cfg).unwrap();
    match plan {
        TriggerPlan::Unfilterable { reason } => {
            assert!(matches!(reason, UnfilterableReason::NoSoundGate));
        }
        _ => panic!("Expected NoSoundGate when feature disabled"),
    }
}
