//! Property-based tests for YAML parsing and interning invariants.

use super::*;
use proptest::prelude::*;

const PROPTEST_CASES: u32 = 64;

// Keep the generated vocabulary finite to avoid unbounded global interner growth
// across proptest cases; `parse_yaml_rules` intentionally leaks interned atoms.
const TOKEN_POOL: &[&str] = &[
    "alpha", "beta", "gamma", "delta", "epsilon", "zeta", "example", "dummy", "token", "key",
    "secret", "prod", "dev", "test",
];

const REGEX_POOL: &[&str] = &[
    "TOK_([A-Za-z0-9]{8,24})",
    "key=([A-Za-z0-9]{6,12})",
    "([A-F0-9]{16})",
];

type LocalContextCase = (usize, usize, bool, bool, Option<Vec<String>>);

#[derive(Debug, Clone)]
struct RuleCase {
    name: String,
    regex: String,
    anchors: Vec<String>,
    radius: usize,
    must_contain: Option<String>,
    keywords_any: Option<Vec<String>>,
    value_suppressors_any: Option<Vec<String>>,
    entropy: Option<(u16, usize, usize, bool)>,
    char_class: Option<(u8, u16)>,
    two_phase: Option<(usize, usize, Vec<String>)>,
    local_context: Option<LocalContextCase>,
    secret_group: Option<u16>,
    min_confidence: Option<i8>,
}

impl RuleCase {
    fn to_yaml_rule(&self) -> YamlRule {
        YamlRule {
            name: self.name.clone(),
            regex: self.regex.clone(),
            anchors: self.anchors.clone(),
            radius: self.radius,
            must_contain: self.must_contain.clone(),
            keywords_any: self.keywords_any.clone(),
            value_suppressors_any: self.value_suppressors_any.clone(),
            char_class: self
                .char_class
                .map(|(max_lower_pct, min_window_len)| YamlCharClass {
                    max_lower_pct,
                    min_window_len,
                }),
            entropy: self
                .entropy
                .as_ref()
                .map(|(bits_x10, min_len, max_len, digit_penalty)| YamlEntropy {
                    min_bits_per_byte: *bits_x10 as f32 / 10.0,
                    min_len: *min_len,
                    max_len: *max_len,
                    min_entropy_bits_per_byte: None,
                    digit_penalty: *digit_penalty,
                }),
            two_phase: self
                .two_phase
                .as_ref()
                .map(|(seed_radius, full_radius, confirm_any)| YamlTwoPhase {
                    seed_radius: *seed_radius,
                    full_radius: *full_radius,
                    confirm_any: confirm_any.clone(),
                }),
            local_context: self.local_context.as_ref().map(
                |(
                    lookbehind,
                    lookahead,
                    require_same_line_assignment,
                    require_quoted,
                    key_names_any,
                )| YamlLocalContext {
                    lookbehind: *lookbehind,
                    lookahead: *lookahead,
                    require_same_line_assignment: *require_same_line_assignment,
                    require_quoted: *require_quoted,
                    key_names_any: key_names_any.clone(),
                },
            ),
            secret_group: self.secret_group,
            offline_validation: None,
            uuid_format_secret: false,
            min_confidence: self.min_confidence,
        }
    }
}

fn pick_tokens(indices: &[usize]) -> Vec<String> {
    indices
        .iter()
        .map(|idx| TOKEN_POOL[*idx].to_string())
        .collect()
}

fn arb_opt_token_vec(max_len: usize) -> impl Strategy<Value = Option<Vec<String>>> {
    prop_oneof![
        Just(None),
        prop::collection::vec(0usize..TOKEN_POOL.len(), 0..=max_len)
            .prop_map(|indices| Some(pick_tokens(&indices))),
    ]
}

fn arb_entropy() -> impl Strategy<Value = Option<(u16, usize, usize, bool)>> {
    prop_oneof![
        Just(None),
        (0u16..=80, 0usize..=96, 0usize..=96, any::<bool>()).prop_map(
            |(bits_x10, a, b, digit_penalty)| {
                let (min_len, max_len) = if a <= b { (a, b) } else { (b, a) };
                Some((bits_x10, min_len, max_len, digit_penalty))
            }
        ),
    ]
}

fn arb_two_phase() -> impl Strategy<Value = Option<(usize, usize, Vec<String>)>> {
    prop_oneof![
        Just(None),
        (
            0usize..=64,
            0usize..=128,
            prop::collection::vec(0usize..TOKEN_POOL.len(), 1..=4),
        )
            .prop_map(|(a, b, confirm_indices)| {
                let (seed_radius, full_radius) = if a <= b { (a, b) } else { (b, a) };
                Some((seed_radius, full_radius, pick_tokens(&confirm_indices)))
            }),
    ]
}

fn arb_local_context() -> impl Strategy<Value = Option<LocalContextCase>> {
    prop_oneof![
        Just(None),
        (
            0usize..=128,
            0usize..=128,
            any::<bool>(),
            any::<bool>(),
            arb_opt_token_vec(4),
        )
            .prop_map(
                |(
                    lookbehind,
                    lookahead,
                    require_same_line_assignment,
                    require_quoted,
                    key_names_any,
                )| {
                    Some((
                        lookbehind,
                        lookahead,
                        require_same_line_assignment,
                        require_quoted,
                        key_names_any,
                    ))
                },
            ),
    ]
}

fn arb_rule_case() -> impl Strategy<Value = RuleCase> {
    (
        0usize..64,
        0usize..REGEX_POOL.len(),
        prop::collection::vec(0usize..TOKEN_POOL.len(), 1..=4),
        0usize..=256,
        prop_oneof![
            Just(None),
            (0usize..TOKEN_POOL.len()).prop_map(|idx| Some(TOKEN_POOL[idx].to_string())),
        ],
        arb_opt_token_vec(4),
        arb_opt_token_vec(4),
        arb_entropy(),
        arb_two_phase(),
        arb_local_context(),
        prop_oneof![Just(None), (0u16..=64).prop_map(Some)],
        prop_oneof![Just(None), (0i8..=10).prop_map(Some)],
    )
        .prop_map(
            |(
                name_idx,
                regex_idx,
                anchor_indices,
                radius,
                must_contain,
                keywords_any,
                value_suppressors_any,
                entropy,
                two_phase,
                local_context,
                secret_group,
                min_confidence,
            )| RuleCase {
                name: format!("prop-rule-{name_idx}"),
                regex: REGEX_POOL[regex_idx].to_string(),
                anchors: pick_tokens(&anchor_indices),
                radius,
                must_contain,
                keywords_any,
                value_suppressors_any,
                entropy,
                // char_class defaults to None for proptest; auto-enable
                // is tested separately in unit tests.
                char_class: None,
                two_phase,
                local_context,
                secret_group,
                min_confidence,
            },
        )
}

fn bytes_to_string(bytes: &[u8]) -> String {
    std::str::from_utf8(bytes)
        .expect("test tokens are valid UTF-8")
        .to_string()
}

fn bytes_slice_to_strings(values: &[&[u8]]) -> Vec<String> {
    values.iter().map(|bytes| bytes_to_string(bytes)).collect()
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(
        crate::test_utils::proptest_cases(PROPTEST_CASES)
    ))]

    #[test]
    // Semantic invariant: serde round-trip through `parse_yaml_rules` preserves
    // all schema-visible fields (including optional nested structures).
    fn parse_yaml_preserves_semantic_fields(case in arb_rule_case()) {
        let yaml = serde_norway::to_string(&YamlRulesFile {
            rules: vec![case.to_yaml_rule()],
        })
        .expect("serialize generated YAML");

        let parsed = parse_yaml_rules(&yaml).expect("parse generated YAML");
        prop_assert_eq!(parsed.len(), 1);
        let rule = &parsed[0];

        prop_assert_eq!(rule.name, case.name.as_str());
        prop_assert_eq!(rule.re.as_str(), case.regex.as_str());
        prop_assert_eq!(rule.radius, case.radius);
        prop_assert_eq!(rule.validator, ValidatorKind::None);
        prop_assert_eq!(rule.secret_group, case.secret_group);
        prop_assert_eq!(rule.min_confidence, case.min_confidence);

        let parsed_anchors = bytes_slice_to_strings(rule.anchors);
        prop_assert_eq!(parsed_anchors, case.anchors.clone());

        match (&case.must_contain, rule.must_contain) {
            (Some(expected), Some(actual)) => {
                prop_assert_eq!(bytes_to_string(actual), expected.as_str());
            }
            (None, None) => {}
            _ => panic!("must_contain presence mismatch"),
        }

        let parsed_keywords = rule.keywords_any.map(bytes_slice_to_strings);
        prop_assert_eq!(parsed_keywords, case.keywords_any.clone());

        let parsed_suppressors = rule.value_suppressors_any.map(bytes_slice_to_strings);
        prop_assert_eq!(parsed_suppressors, case.value_suppressors_any.clone());

        match (&case.entropy, &rule.entropy) {
            (Some((bits_x10, min_len, max_len, digit_penalty)), Some(entropy)) => {
                prop_assert!((entropy.min_bits_per_byte - (*bits_x10 as f32 / 10.0)).abs() <= 1e-6);
                prop_assert_eq!(entropy.min_len, *min_len);
                prop_assert_eq!(entropy.max_len, *max_len);
                prop_assert_eq!(
                    entropy.digit_penalty, *digit_penalty,
                    "digit_penalty should round-trip through YAML"
                );
            }
            (None, None) => {}
            _ => panic!("entropy presence mismatch"),
        }

        // char_class: either explicit from the case, or auto-enabled when
        // entropy >= 3.0 bits/byte.
        let expect_auto_enable = case.char_class.is_none()
            && case
                .entropy
                .is_some_and(|(bits_x10, _, _, _)| bits_x10 as f32 / 10.0 >= AUTO_CHAR_CLASS_ENTROPY_THRESHOLD);
        match (&case.char_class, &rule.char_class) {
            (Some((max_lower_pct, min_window_len)), Some(cc)) => {
                prop_assert_eq!(cc.max_lower_pct, *max_lower_pct);
                prop_assert_eq!(cc.min_window_len, *min_window_len);
            }
            (None, Some(cc)) if expect_auto_enable => {
                prop_assert_eq!(cc.max_lower_pct, AUTO_CHAR_CLASS_MAX_LOWER_PCT);
                prop_assert_eq!(cc.min_window_len, AUTO_CHAR_CLASS_MIN_WINDOW_LEN);
            }
            (None, None) if !expect_auto_enable => {}
            _ => panic!("char_class presence mismatch"),
        }

        match (&case.two_phase, &rule.two_phase) {
            (Some((seed_radius, full_radius, confirm_any)), Some(two_phase)) => {
                prop_assert_eq!(two_phase.seed_radius, *seed_radius);
                prop_assert_eq!(two_phase.full_radius, *full_radius);
                let parsed_confirm_any = bytes_slice_to_strings(two_phase.confirm_any);
                prop_assert_eq!(parsed_confirm_any, confirm_any.clone());
            }
            (None, None) => {}
            _ => panic!("two_phase presence mismatch"),
        }

        match (&case.local_context, &rule.local_context) {
            (
                Some((
                    lookbehind,
                    lookahead,
                    require_same_line_assignment,
                    require_quoted,
                    key_names_any,
                )),
                Some(local_context),
            ) => {
                prop_assert_eq!(local_context.lookbehind, *lookbehind);
                prop_assert_eq!(local_context.lookahead, *lookahead);
                prop_assert_eq!(
                    local_context.require_same_line_assignment,
                    *require_same_line_assignment
                );
                prop_assert_eq!(local_context.require_quoted, *require_quoted);
                let parsed_key_names = local_context.key_names_any.map(bytes_slice_to_strings);
                prop_assert_eq!(parsed_key_names, key_names_any.clone());
            }
            (None, None) => {}
            _ => panic!("local_context presence mismatch"),
        }
    }

    #[test]
    // Interning invariant: repeated parse of identical YAML must reuse pointers
    // for all interned atoms and interned atom slices.
    fn repeated_parse_reuses_interned_atoms(case in arb_rule_case()) {
        let yaml = serde_norway::to_string(&YamlRulesFile {
            rules: vec![case.to_yaml_rule()],
        })
        .expect("serialize generated YAML");

        let first = parse_yaml_rules(&yaml).expect("first parse");
        let second = parse_yaml_rules(&yaml).expect("second parse");
        let a = &first[0];
        let b = &second[0];

        prop_assert!(std::ptr::eq(a.name, b.name));
        prop_assert!(std::ptr::eq(a.anchors, b.anchors));
        for (left, right) in a.anchors.iter().zip(b.anchors.iter()) {
            prop_assert!(std::ptr::eq(*left, *right));
        }

        match (a.must_contain, b.must_contain) {
            (Some(left), Some(right)) => prop_assert!(std::ptr::eq(left, right)),
            (None, None) => {}
            _ => panic!("must_contain presence mismatch"),
        }

        match (a.keywords_any, b.keywords_any) {
            (Some(left), Some(right)) => {
                prop_assert!(std::ptr::eq(left, right));
                for (l, r) in left.iter().zip(right.iter()) {
                    prop_assert!(std::ptr::eq(*l, *r));
                }
            }
            (None, None) => {}
            _ => panic!("keywords_any presence mismatch"),
        }

        match (a.value_suppressors_any, b.value_suppressors_any) {
            (Some(left), Some(right)) => {
                prop_assert!(std::ptr::eq(left, right));
                for (l, r) in left.iter().zip(right.iter()) {
                    prop_assert!(std::ptr::eq(*l, *r));
                }
            }
            (None, None) => {}
            _ => panic!("value_suppressors_any presence mismatch"),
        }

        match (&a.two_phase, &b.two_phase) {
            (Some(left), Some(right)) => {
                prop_assert!(std::ptr::eq(left.confirm_any, right.confirm_any));
                for (l, r) in left.confirm_any.iter().zip(right.confirm_any.iter()) {
                    prop_assert!(std::ptr::eq(*l, *r));
                }
            }
            (None, None) => {}
            _ => panic!("two_phase presence mismatch"),
        }

        match (&a.local_context, &b.local_context) {
            (Some(left), Some(right)) => match (left.key_names_any, right.key_names_any) {
                (Some(left_keys), Some(right_keys)) => {
                    prop_assert!(std::ptr::eq(left_keys, right_keys));
                    for (l, r) in left_keys.iter().zip(right_keys.iter()) {
                        prop_assert!(std::ptr::eq(*l, *r));
                    }
                }
                (None, None) => {}
                _ => panic!("local_context.key_names_any presence mismatch"),
            },
            (None, None) => {}
            _ => panic!("local_context presence mismatch"),
        }
    }
}
