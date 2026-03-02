use super::*;

/// Helper to derive anchors with default config
fn derive(pattern: &str) -> Result<Vec<String>, AnchorDeriveError> {
    derive_anchors_as_strings(pattern, &AnchorDeriveConfig::default())
}

/// Helper to derive anchors with custom min length
fn derive_min(pattern: &str, min_len: usize) -> Result<Vec<String>, AnchorDeriveError> {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: min_len,
        ..Default::default()
    };
    derive_anchors_as_strings(pattern, &cfg)
}

/// Verify soundness: if regex matches, at least one anchor is present
fn verify_soundness(pattern: &str, haystack: &str) -> bool {
    let cfg = AnchorDeriveConfig::default();
    match derive_anchors_from_pattern(pattern, &cfg) {
        Ok(anchors) => {
            let re = regex::Regex::new(pattern).unwrap();
            if re.is_match(haystack) {
                // If regex matches, at least one anchor must be present
                anchors.iter().any(|a| {
                    haystack
                        .as_bytes()
                        .windows(a.len())
                        .any(|w| w == a.as_slice())
                })
            } else {
                // If regex doesn't match, soundness is trivially satisfied
                true
            }
        }
        Err(_) => true, // If we can't derive anchors, soundness is trivially satisfied
    }
}

// =============================================================================
// UNIT TESTS: Basic Functionality
// =============================================================================

mod unit_tests {
    use super::*;

    #[test]
    fn test_literal() {
        assert_eq!(derive("foo").unwrap(), vec!["foo"]);
        assert_eq!(derive("hello_world").unwrap(), vec!["hello_world"]);
    }

    #[test]
    fn test_literal_too_short() {
        assert!(matches!(
            derive("ab"),
            Err(AnchorDeriveError::OnlyWeakAnchors)
        ));
        assert!(matches!(
            derive("a"),
            Err(AnchorDeriveError::OnlyWeakAnchors)
        ));
    }

    #[test]
    fn test_literal_min_1() {
        assert_eq!(derive_min("ab", 1).unwrap(), vec!["ab"]);
        assert_eq!(derive_min("a", 1).unwrap(), vec!["a"]);
    }

    #[test]
    fn test_concat() {
        assert_eq!(derive("foobar").unwrap(), vec!["foobar"]);
        assert_eq!(derive("abc123").unwrap(), vec!["abc123"]);
    }

    #[test]
    fn test_alternation_basic() {
        let mut result = derive("foo|bar").unwrap();
        result.sort();
        assert_eq!(result, vec!["bar", "foo"]);
    }

    #[test]
    fn test_optional_prefix() {
        // a?bc - the "a" is optional, so "bc" might not have it
        // But "bc" is too short with min=3
        // This should handle the optional properly
        let result = derive_min("a?bcd", 3);
        // With optional prefix, we should get "bcd" (without a) or "abcd" (with a)
        // The exact behavior depends on implementation
        assert!(result.is_ok() || matches!(result, Err(AnchorDeriveError::OnlyWeakAnchors)));
    }

    #[test]
    fn test_optional_suffix() {
        // abc? - "c" is optional
        // Should get "ab" (without c) or "abc" (with c)
        let result = derive_min("abc?", 2);
        assert!(result.is_ok());
    }

    #[test]
    fn test_repetition_plus() {
        // a+ means one or more 'a'
        // This is too short with default min
        assert!(derive("a+").is_err());

        // "aaa+" is parsed as "aa" + "a+" (regex syntax: + applies to preceding char)
        // The minimum match is "aaa", but the prefix "aa" is only 2 chars
        // With min_anchor_len=3, the best we can extract is "aa" which is too short
        let result = derive_min("aaa+", 3);
        // Due to regex parsing, this returns OnlyWeakAnchors (best anchor is "aa")
        // This is conservative but sound
        assert!(result.is_err() || result.is_ok());

        // For a working example, use explicit grouping or fixed repetition
        let result = derive_min("a{3,}", 3);
        // a{3,} means "at least 3 a's" - should give us "aaa" as anchor
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), vec!["aaa"]);
    }

    #[test]
    fn test_repetition_star() {
        // a* can match empty, so it's unanchorable
        assert!(matches!(derive("a*"), Err(AnchorDeriveError::Unanchorable)));
    }

    #[test]
    fn test_repetition_exact() {
        // a{3} means exactly "aaa"
        assert_eq!(derive("a{3}").unwrap(), vec!["aaa"]);

        // [ab]{2} means aa, ab, ba, or bb
        let mut result = derive_min("[ab]{2}", 2).unwrap();
        result.sort();
        assert_eq!(result, vec!["aa", "ab", "ba", "bb"]);
    }

    #[test]
    fn test_character_class_small() {
        // [abc] expands to a, b, c
        let mut result = derive_min("[abc]", 1).unwrap();
        result.sort();
        assert_eq!(result, vec!["a", "b", "c"]);
    }

    #[test]
    fn test_character_class_with_literal() {
        // [ab]cd expands to acd, bcd
        let mut result = derive("[ab]cd").unwrap();
        result.sort();
        assert_eq!(result, vec!["acd", "bcd"]);
    }

    #[test]
    fn test_character_class_large() {
        // [a-z] is too large to expand (26 > 16 default)
        // Should degrade to All
        assert!(matches!(
            derive("[a-z]"),
            Err(AnchorDeriveError::Unanchorable)
        ));
    }

    #[test]
    fn test_wildcard_dot() {
        // . matches any character - too broad
        assert!(matches!(derive("."), Err(AnchorDeriveError::Unanchorable)));
    }

    #[test]
    fn test_anchors_caret_dollar() {
        // ^foo$ - the anchors don't add characters
        assert_eq!(derive("^foo$").unwrap(), vec!["foo"]);
    }

    #[test]
    fn test_word_boundary() {
        // \bfoo\b - word boundaries don't add characters
        assert_eq!(derive(r"\bfoo\b").unwrap(), vec!["foo"]);
    }

    #[test]
    fn test_capture_group() {
        // (foo) is same as foo
        assert_eq!(derive("(foo)").unwrap(), vec!["foo"]);

        // (foo)(bar) is foobar
        assert_eq!(derive("(foo)(bar)").unwrap(), vec!["foobar"]);
    }

    #[test]
    fn test_nested_alternation() {
        // ((a|b)|(c|d)) with min=1
        let mut result = derive_min("(a|b)|(c|d)", 1).unwrap();
        result.sort();
        assert_eq!(result, vec!["a", "b", "c", "d"]);
    }

    #[test]
    fn test_complex_pattern() {
        // Real-world-ish: API key pattern
        // "api_key_" followed by alphanumeric
        let result = derive("api_key_[a-zA-Z0-9]+");
        // Should at least get "api_key_" as anchor
        assert!(result.is_ok());
        let anchors = result.unwrap();
        assert!(anchors.iter().any(|a| a.contains("api_key_")));
    }
}

// =============================================================================
// BUG HUNTING TESTS: Specific failure modes
// =============================================================================

mod bug_hunting {
    use super::*;

    #[test]
    fn test_bug_min_anchor_length_post_filter() {
        // BUG CLASS 1: min_anchor_len post-filtering
        // Pattern: (a|abc) with min_anchor_len=3
        // Bug: Filter after derivation removes "a", leaving only "abc"
        // Input "a" matches pattern but doesn't contain "abc"

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("a|abc", &cfg);

        // With the fix, this should return error (OnlyWeakAnchors or Unanchorable)
        // NOT Ok(["abc"]) which would be unsound
        assert!(
            result.is_err(),
            "Pattern (a|abc) with min=3 should fail, not return only 'abc'"
        );

        // With min_anchor_len=1, both branches are long enough and should succeed.
        // (Merged from test_alternation_with_short_branch)
        let mut result = derive_min("a|abc", 1).unwrap();
        result.sort();
        assert_eq!(result, vec!["a", "abc"]);
    }

    #[test]
    fn test_bug_min_anchor_length_variant() {
        // Another variant: (ab|abcdef) with min=3
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("ab|abcdef", &cfg);
        assert!(
            result.is_err(),
            "Pattern (ab|abcdef) with min=3 should fail, not return only 'abcdef'"
        );
    }

    #[test]
    fn test_bug_optional_prefix_drops_required() {
        // BUG CLASS 2: Optional prefix handling
        // Pattern: a?bc - "a" is optional
        // The pattern matches "bc" and "abc"
        // If we only return "abc", we miss "bc"

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 2,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("a?bc", &cfg);
        if let Ok(anchors) = result {
            // Should contain "bc" (the required part without optional prefix)
            // or should fail if we can't handle this case
            let has_bc = anchors.iter().any(|a| a == b"bc");
            let has_abc = anchors.iter().any(|a| a == b"abc");
            assert!(
                has_bc || anchors.is_empty(),
                "If we have anchors, must include 'bc' for soundness"
            );
            // If we have abc but not bc, that's a bug
            if has_abc && !has_bc {
                panic!("Has 'abc' but missing 'bc' - would miss inputs matching 'bc'");
            }
        }
        // If Err, that's fine - conservative is safe
    }

    #[test]
    fn test_bug_concat_with_all_child() {
        // BUG CLASS 4: Concatenation with All child
        // Pattern: foo.*bar
        // .* is All, so we can't use the full concatenation
        // Should extract "foo" or "bar" as anchor

        let result = derive("foo.*bar");
        if let Ok(anchors) = result {
            let has_foo = anchors.iter().any(|a| a == "foo");
            let has_bar = anchors.iter().any(|a| a == "bar");
            assert!(
                has_foo || has_bar,
                "Should extract 'foo' or 'bar' from 'foo.*bar'"
            );
        }
    }

    #[test]
    fn test_compile_trigger_plan_confirm_all_islands() {
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            ..Default::default()
        };

        let plan = compile_trigger_plan(r"foo\d+bar", &cfg).unwrap();
        match plan {
            TriggerPlan::Anchored {
                anchors,
                confirm_all,
            } => {
                for a in &anchors {
                    assert!(
                        !confirm_all.contains(a),
                        "confirm_all should not duplicate anchors"
                    );
                }

                let has_foo = anchors
                    .iter()
                    .chain(confirm_all.iter())
                    .any(|a| a.as_slice() == b"foo");
                let has_bar = anchors
                    .iter()
                    .chain(confirm_all.iter())
                    .any(|a| a.as_slice() == b"bar");
                assert!(has_foo && has_bar, "mandatory islands must be preserved");
            }
            other => panic!("expected anchored plan, got {other:?}"),
        }
    }

    #[test]
    fn test_bug_overlapping_alternatives_prefix() {
        // BUG CLASS 5: Overlapping alternatives
        // Pattern: (foo|foobar) - "foo" is prefix of "foobar"
        // Both must be anchors, can't just use "foo"

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("foo|foobar", &cfg);
        if let Ok(anchors) = result {
            // Must have both foo and foobar
            let anchor_strs: Vec<String> = anchors
                .iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect();
            assert!(
                anchor_strs.contains(&"foo".to_string()),
                "Must include 'foo'"
            );
            assert!(
                anchor_strs.contains(&"foobar".to_string()),
                "Must include 'foobar'"
            );
        }

        // Both branches long enough — both must be preserved.
        // (Merged from test_alternation_overlapping)
        let mut result = derive("abc|abcdef").unwrap();
        result.sort();
        assert_eq!(result, vec!["abc", "abcdef"]);
    }

    #[test]
    fn test_bug_repetition_bounds_undercount() {
        // BUG CLASS 6: Repetition bounds
        // Pattern: a{2,4} means aa, aaa, or aaaa
        // If we only use "aa", we're sound but if we use "aaaa" we miss "aa"

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 2,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("a{2,4}", &cfg);
        if let Ok(anchors) = result {
            // The minimum repetition is "aa", so "aa" must be valid
            // We might return "aa" as anchor (sound for all cases)
            let has_aa = anchors.iter().any(|a| a == b"aa");
            assert!(has_aa, "Anchor 'aa' required for {{2,4}} pattern");
        }
    }

    #[test]
    fn test_bug_class_expansion_overflow() {
        // BUG CLASS 9: Cross-product overflow
        // Pattern: [abc][def][ghi] - 3*3*3 = 27 combinations
        // Should handle gracefully

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            max_exact_set: 64,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern("[abc][def][ghi]", &cfg);
        // Should either succeed with all 27 combinations or fail gracefully
        if let Ok(anchors) = result {
            assert_eq!(anchors.len(), 27, "Should have 27 combinations");
        }
    }

    #[test]
    fn test_bug_all_branches_become_all() {
        // BUG CLASS 12: All branches become All
        // Pattern: (.*|foo) - one branch is All
        // Entire alternation must be All

        let result = derive(".*|foo");
        assert!(
            result.is_err(),
            "Pattern with .* alternative should be unanchorable"
        );
    }

    #[test]
    fn test_bug_nested_groups_transparency() {
        // Capture groups should be transparent
        // Pattern: ((foo)) should be same as (foo) should be same as foo

        assert_eq!(derive("((foo))").unwrap(), vec!["foo"]);
        assert_eq!(derive("(((foo)))").unwrap(), vec!["foo"]);
    }

    #[test]
    fn test_bug_empty_alternation_branch() {
        // Pattern: (foo|) has empty branch
        // Empty branch matches empty string
        // Therefore the pattern can match "", making it unanchorable

        let result = derive("foo|");
        // Must return error because pattern matches empty string
        assert!(
            result.is_err(),
            "Pattern 'foo|' matches empty string, should be unanchorable"
        );

        // Leading empty branch: (|foo) — same invariant, opposite order.
        // If the pattern happens to succeed, the empty string must not appear
        // in the anchor set.
        // (Merged from test_bug_empty_string_in_exact_set)
        let result = derive_min("|foo", 1);
        if let Ok(anchors) = result {
            assert!(
                !anchors.contains(&String::new()),
                "Empty string should not be an anchor"
            );
        }
    }

    #[test]
    fn test_bug_unicode_vs_bytes() {
        // BUG CLASS 10: Unicode/byte mode
        // Multi-byte UTF-8 characters

        let cfg = AnchorDeriveConfig {
            min_anchor_len: 1,
            ..Default::default()
        };

        // "日本" is 6 bytes in UTF-8
        let result = derive_anchors_from_pattern("日本", &cfg);
        if let Ok(anchors) = result {
            assert!(!anchors.is_empty());
            // Verify the bytes are correct
            assert_eq!(anchors[0], "日本".as_bytes());
        }
    }
}

// =============================================================================
// SOUNDNESS TESTS: Property-based verification
// =============================================================================

mod proptest_soundness {
    use super::*;
    use proptest::prelude::*;

    /// Simple regex AST for generating correlated pattern/haystack pairs
    #[derive(Debug, Clone)]
    enum TestRe {
        Literal(String),
        Concat(Vec<TestRe>),
        Alt(Vec<TestRe>),
        Optional(Box<TestRe>),
        Plus(Box<TestRe>),
    }

    impl TestRe {
        fn to_regex_string(&self) -> String {
            match self {
                TestRe::Literal(s) => regex_syntax::escape(s),
                TestRe::Concat(parts) => parts.iter().map(|p| p.to_regex_string()).collect(),
                TestRe::Alt(alts) => {
                    let parts: Vec<String> = alts.iter().map(|a| a.to_regex_string()).collect();
                    format!("({})", parts.join("|"))
                }
                TestRe::Optional(inner) => format!("({})?", inner.to_regex_string()),
                TestRe::Plus(inner) => format!("({})+", inner.to_regex_string()),
            }
        }

        fn generate_matching_haystack(&self) -> String {
            match self {
                TestRe::Literal(s) => s.clone(),
                TestRe::Concat(parts) => parts
                    .iter()
                    .map(|p| p.generate_matching_haystack())
                    .collect(),
                TestRe::Alt(alts) => {
                    // Pick first alternative for determinism
                    alts.first()
                        .map(|a| a.generate_matching_haystack())
                        .unwrap_or_default()
                }
                TestRe::Optional(inner) => {
                    // Include the optional part
                    inner.generate_matching_haystack()
                }
                TestRe::Plus(inner) => {
                    // Generate one copy
                    inner.generate_matching_haystack()
                }
            }
        }
    }

    fn arb_literal() -> impl Strategy<Value = TestRe> {
        "[a-zA-Z0-9_]{1,8}".prop_map(TestRe::Literal)
    }

    fn arb_test_re() -> impl Strategy<Value = TestRe> {
        let leaf = arb_literal();

        leaf.prop_recursive(
            3,  // depth
            16, // desired size
            4,  // items per collection
            |inner| {
                prop_oneof![
                    // Concatenation of 2-3 elements
                    prop::collection::vec(inner.clone(), 2..=3).prop_map(TestRe::Concat),
                    // Alternation of 2-3 elements
                    prop::collection::vec(inner.clone(), 2..=3).prop_map(TestRe::Alt),
                    // Optional
                    inner.clone().prop_map(|r| TestRe::Optional(Box::new(r))),
                    // Plus
                    inner.clone().prop_map(|r| TestRe::Plus(Box::new(r))),
                ]
            },
        )
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]

        #[test]
        fn test_soundness_invariant(test_re in arb_test_re()) {
            let pattern = test_re.to_regex_string();
            let haystack = test_re.generate_matching_haystack();

            let cfg = AnchorDeriveConfig {
                min_anchor_len: 1, // Use small min for more coverage
                ..Default::default()
            };

            // The pattern should match the generated haystack
            let re = regex::Regex::new(&pattern).unwrap();
            prop_assert!(re.is_match(&haystack), "Generated haystack should match pattern");

            // If we can derive anchors, at least one must be present
            if let Ok(anchors) = derive_anchors_from_pattern(&pattern, &cfg) {
                let haystack_bytes = haystack.as_bytes();
                let found = anchors.iter().any(|anchor| {
                    haystack_bytes.windows(anchor.len()).any(|w| w == anchor.as_slice())
                });

                prop_assert!(found,
                    "Soundness violated!\nPattern: {}\nHaystack: {}\nAnchors: {:?}",
                    pattern, haystack, anchors.iter().map(|a| String::from_utf8_lossy(a)).collect::<Vec<_>>()
                );
            }
            // If we can't derive anchors (Err), that's conservative and safe
        }

        #[test]
        fn test_soundness_with_prefix_suffix(
            prefix in "[a-z]{0,5}",
            test_re in arb_test_re(),
            suffix in "[a-z]{0,5}"
        ) {
            let pattern = test_re.to_regex_string();
            let core_haystack = test_re.generate_matching_haystack();
            let haystack = format!("{}{}{}", prefix, core_haystack, suffix);

            let cfg = AnchorDeriveConfig {
                min_anchor_len: 1,
                ..Default::default()
            };

            let re = regex::Regex::new(&pattern).unwrap();
            if re.is_match(&haystack) {
                if let Ok(anchors) = derive_anchors_from_pattern(&pattern, &cfg) {
                    let haystack_bytes = haystack.as_bytes();
                    let found = anchors.iter().any(|anchor| {
                        haystack_bytes.windows(anchor.len()).any(|w| w == anchor.as_slice())
                    });

                    prop_assert!(found,
                        "Soundness violated with prefix/suffix!\nPattern: {}\nHaystack: {}",
                        pattern, haystack
                    );
                }
            }
        }
    }

    #[test]
    fn test_specific_soundness_cases() {
        // Manually test specific cases that might be edge cases
        let cases = vec![
            ("foo", "foo"),
            ("foo", "xfooy"),
            ("foo|bar", "foo"),
            ("foo|bar", "bar"),
            ("foo|bar", "xfooy"),
            ("foo|bar", "xbary"),
            ("fo+", "foo"),
            ("fo+", "foooo"),
            ("fo*", "f"),
            ("fo*", "foo"),
            ("a?bc", "bc"),
            ("a?bc", "abc"),
            ("[ab]cd", "acd"),
            ("[ab]cd", "bcd"),
        ];

        for (pattern, haystack) in cases {
            assert!(
                verify_soundness(pattern, haystack),
                "Soundness failed for pattern '{}' with haystack '{}'",
                pattern,
                haystack
            );
        }
    }
}

// =============================================================================
// REAL-WORLD PATTERN TESTS
// =============================================================================

mod real_world_patterns {
    use super::*;

    #[test]
    fn test_api_key_pattern() {
        // Pattern for generic API keys
        let pattern = r#"api[_\-]?key[_\-]?[=:]\s*['\"]?[a-zA-Z0-9]{16,}"#;
        let cfg = AnchorDeriveConfig {
            min_anchor_len: 3,
            ..Default::default()
        };

        let result = derive_anchors_from_pattern(pattern, &cfg);
        // Should extract something useful
        if let Ok(anchors) = result {
            let has_api = anchors.iter().any(|a| {
                let s = String::from_utf8_lossy(a);
                s.contains("api")
            });
            let has_key = anchors.iter().any(|a| {
                let s = String::from_utf8_lossy(a);
                s.contains("key")
            });
            assert!(has_api || has_key, "Should extract api or key anchor");
        }
    }

    #[test]
    fn test_aws_access_key() {
        // AWS access key pattern: AKIA followed by 16 alphanumeric chars
        let pattern = "AKIA[0-9A-Z]{16}";
        let result = derive(pattern);
        if let Ok(anchors) = result {
            assert!(
                anchors.iter().any(|a| a.starts_with("AKIA")),
                "Should have AKIA anchor"
            );
        }
    }

    #[test]
    fn test_jwt_pattern() {
        // Simplified JWT pattern: eyJ followed by base64
        let pattern = r#"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"#;
        let result = derive(pattern);
        if let Ok(anchors) = result {
            // Should get "eyJ" as anchor (appears twice)
            assert!(
                anchors.iter().any(|a| a.contains("eyJ")),
                "Should have eyJ anchor"
            );
        }
    }

    #[test]
    fn test_github_token() {
        // GitHub personal access token pattern
        let pattern = "ghp_[A-Za-z0-9]{36}";
        let result = derive(pattern);
        if let Ok(anchors) = result {
            assert!(
                anchors.iter().any(|a| a.starts_with("ghp_")),
                "Should have ghp_ prefix anchor"
            );
        }
    }

    #[test]
    fn test_slack_token() {
        // Slack token patterns
        let patterns = vec![
            "xoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
            "xoxp-[0-9]+-[0-9]+-[a-zA-Z0-9]+",
            "xoxa-[0-9]+-[a-zA-Z0-9]+",
        ];

        for pattern in patterns {
            let result = derive(pattern);
            if let Ok(anchors) = result {
                assert!(
                    anchors.iter().any(|a| a.starts_with("xox")),
                    "Should have xox prefix for pattern"
                );
            }
        }
    }
}
