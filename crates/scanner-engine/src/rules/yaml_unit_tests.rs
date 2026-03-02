use super::*;
use crate::api::{OfflineVerdict, ValidatorKind};
use crate::rules::builtin_rules;
use crate::{AnchorPolicy, Engine, Finding, demo_tuning};
use std::path::Path;

/// Parse YAML → `RuleSpec` → `rulespec_to_yaml` → serialize → re-parse →
/// assert `offline_validation` equality on each rule.
fn assert_offline_validation_roundtrip(yaml: &str) {
    let original = parse_yaml_rules(yaml).expect("parse");
    let yaml_rules: Vec<YamlRule> = original.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_norway::to_string(&file).expect("serialize");
    let parsed = parse_yaml_rules(&yaml_str).expect("re-parse");
    for (orig, reparsed) in original.iter().zip(parsed.iter()) {
        assert_eq!(
            orig.offline_validation, reparsed.offline_validation,
            "round-trip mismatch for {}",
            orig.name
        );
    }
}

/// Convert `RuleSpec` back to YAML intermediate type for round-trip testing.
fn rulespec_to_yaml(rule: &RuleSpec) -> YamlRule {
    let anchors: Vec<String> = rule
        .anchors
        .iter()
        .map(|a| String::from_utf8(a.to_vec()).expect("anchors should be ASCII"))
        .collect();

    let keywords_any = rule.keywords_any.map(|kws| {
        kws.iter()
            .map(|k| String::from_utf8(k.to_vec()).expect("keywords should be ASCII"))
            .collect()
    });
    let value_suppressors_any = rule.value_suppressors_any.map(|sups| {
        sups.iter()
            .map(|s| {
                // Suppressors originate from YAML string scalars, so they are
                // guaranteed to be valid UTF-8 on the round-trip path.
                std::str::from_utf8(s)
                    .expect("value suppressors should be valid UTF-8")
                    .to_owned()
            })
            .collect()
    });

    let must_contain = rule
        .must_contain
        .map(|mc| String::from_utf8(mc.to_vec()).expect("must_contain should be ASCII"));

    let entropy = rule.entropy.as_ref().map(|e| YamlEntropy {
        min_bits_per_byte: e.min_bits_per_byte,
        min_len: e.min_len,
        max_len: e.max_len,
        min_entropy_bits_per_byte: e.min_entropy_bits_per_byte,
        digit_penalty: e.digit_penalty,
    });

    let two_phase = rule.two_phase.as_ref().map(|tp| YamlTwoPhase {
        seed_radius: tp.seed_radius,
        full_radius: tp.full_radius,
        confirm_any: tp
            .confirm_any
            .iter()
            .map(|c| String::from_utf8(c.to_vec()).expect("confirm_any should be ASCII"))
            .collect(),
    });

    let local_context = rule.local_context.as_ref().map(|lc| YamlLocalContext {
        lookbehind: lc.lookbehind,
        lookahead: lc.lookahead,
        require_same_line_assignment: lc.require_same_line_assignment,
        require_quoted: lc.require_quoted,
        key_names_any: lc.key_names_any.map(|kns| {
            kns.iter()
                .map(|k| String::from_utf8(k.to_vec()).expect("key_names should be ASCII"))
                .collect()
        }),
    });

    let char_class = rule.char_class.map(|cc| YamlCharClass {
        max_lower_pct: cc.max_lower_pct,
        min_window_len: cc.min_window_len,
    });

    let offline_validation = rule.offline_validation.map(|ov| match ov {
        OfflineValidationSpec::Crc32Base62 {
            prefix_skip,
            payload_len,
            checksum_len,
        } => YamlOfflineValidation {
            kind: "crc32_base62".into(),
            prefix_skip: Some(prefix_skip),
            payload_len: Some(payload_len),
            checksum_len: Some(checksum_len),
        },
        OfflineValidationSpec::GithubFinegrainedPat => YamlOfflineValidation {
            kind: "github_fine_grained_pat".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::GrafanaServiceAccount => YamlOfflineValidation {
            kind: "grafana_service_account".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::AwsAccessKey => YamlOfflineValidation {
            kind: "aws_access_key".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::SentryOrgToken => YamlOfflineValidation {
            kind: "sentry_org_token".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::PyPiToken => YamlOfflineValidation {
            kind: "pypi_token".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
        OfflineValidationSpec::SlackToken => YamlOfflineValidation {
            kind: "slack_token".into(),
            prefix_skip: None,
            payload_len: None,
            checksum_len: None,
        },
    });

    YamlRule {
        name: rule.name.to_string(),
        regex: rule.re.as_str().to_string(),
        anchors,
        radius: rule.radius,
        must_contain,
        keywords_any,
        value_suppressors_any,
        entropy,
        char_class,
        two_phase,
        local_context,
        offline_validation,
        secret_group: rule.secret_group,
        uuid_format_secret: rule.uuid_format_secret,
        min_confidence: rule.min_confidence,
    }
}

/// Assert that a YAML mapping section contains only known field names.
fn assert_no_unknown_nested_fields(
    map: &serde_norway::Mapping,
    section: &str,
    allowed: &[&str],
    rule_idx: usize,
    rule_name: &str,
) {
    if let Some(val) = map.get(serde_norway::Value::String(section.into())) {
        if let Some(sm) = val.as_mapping() {
            for key in sm.keys() {
                let k = key.as_str().unwrap_or("");
                assert!(
                    allowed.contains(&k),
                    "rule {rule_idx} ({rule_name}) {section} has unknown field '{k}'"
                );
            }
        }
    }
}

/// Assert two `Option<&[&[u8]]>` values are element-wise equal.
fn assert_opt_slices_eq(
    orig: Option<&[&[u8]]>,
    parsed: Option<&[&[u8]]>,
    field: &str,
    rule_name: &str,
) {
    match (orig, parsed) {
        (Some(o), Some(p)) => {
            assert_eq!(o.len(), p.len(), "{field} count mismatch for {rule_name}");
            for (a, b) in o.iter().zip(p.iter()) {
                assert_eq!(*a, *b, "{field} mismatch for {rule_name}");
            }
        }
        (None, None) => {}
        _ => panic!("{field} presence mismatch for {rule_name}"),
    }
}

fn assert_rules_equal(original_rules: &[RuleSpec], parsed_rules: &[RuleSpec]) {
    assert_eq!(
        original_rules.len(),
        parsed_rules.len(),
        "rule count mismatch"
    );

    for (orig, parsed) in original_rules.iter().zip(parsed_rules.iter()) {
        assert_eq!(orig.name, parsed.name, "name mismatch");
        assert_eq!(
            orig.radius, parsed.radius,
            "radius mismatch for {}",
            orig.name
        );
        assert_eq!(
            orig.re.as_str(),
            parsed.re.as_str(),
            "regex mismatch for {}",
            orig.name
        );

        // Anchors.
        assert_opt_slices_eq(
            Some(orig.anchors),
            Some(parsed.anchors),
            "anchors",
            orig.name,
        );

        // Keywords.
        assert_opt_slices_eq(
            orig.keywords_any,
            parsed.keywords_any,
            "keywords_any",
            orig.name,
        );

        // Value suppressors.
        assert_opt_slices_eq(
            orig.value_suppressors_any,
            parsed.value_suppressors_any,
            "value_suppressors_any",
            orig.name,
        );

        // Entropy.
        match (&orig.entropy, &parsed.entropy) {
            (Some(oe), Some(pe)) => {
                assert_eq!(
                    oe.min_bits_per_byte, pe.min_bits_per_byte,
                    "entropy min_bits_per_byte mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    oe.min_len, pe.min_len,
                    "entropy min_len mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    oe.max_len, pe.max_len,
                    "entropy max_len mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    oe.digit_penalty, pe.digit_penalty,
                    "entropy digit_penalty mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    oe.min_entropy_bits_per_byte, pe.min_entropy_bits_per_byte,
                    "entropy min_entropy_bits_per_byte mismatch for {}",
                    orig.name
                );
            }
            (None, None) => {}
            _ => panic!("entropy presence mismatch for {}", orig.name),
        }

        // Two-phase.
        match (&orig.two_phase, &parsed.two_phase) {
            (Some(otp), Some(ptp)) => {
                assert_eq!(
                    otp.seed_radius, ptp.seed_radius,
                    "two_phase seed_radius mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    otp.full_radius, ptp.full_radius,
                    "two_phase full_radius mismatch for {}",
                    orig.name
                );
                assert_opt_slices_eq(
                    Some(otp.confirm_any),
                    Some(ptp.confirm_any),
                    "two_phase confirm_any",
                    orig.name,
                );
            }
            (None, None) => {}
            _ => panic!("two_phase presence mismatch for {}", orig.name),
        }

        // Local context.
        match (&orig.local_context, &parsed.local_context) {
            (Some(olc), Some(plc)) => {
                assert_eq!(
                    olc.lookbehind, plc.lookbehind,
                    "local_context lookbehind mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    olc.lookahead, plc.lookahead,
                    "local_context lookahead mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    olc.require_same_line_assignment, plc.require_same_line_assignment,
                    "local_context require_same_line_assignment mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    olc.require_quoted, plc.require_quoted,
                    "local_context require_quoted mismatch for {}",
                    orig.name
                );
                assert_opt_slices_eq(
                    olc.key_names_any,
                    plc.key_names_any,
                    "local_context key_names_any",
                    orig.name,
                );
            }
            (None, None) => {}
            _ => panic!("local_context presence mismatch for {}", orig.name),
        }

        // Char class.
        match (orig.char_class, parsed.char_class) {
            (Some(occ), Some(pcc)) => {
                assert_eq!(
                    occ.max_lower_pct, pcc.max_lower_pct,
                    "char_class max_lower_pct mismatch for {}",
                    orig.name
                );
                assert_eq!(
                    occ.min_window_len, pcc.min_window_len,
                    "char_class min_window_len mismatch for {}",
                    orig.name
                );
            }
            (None, None) => {}
            _ => panic!("char_class presence mismatch for {}", orig.name),
        }

        // Offline validation.
        assert_eq!(
            orig.offline_validation, parsed.offline_validation,
            "offline_validation mismatch for {}",
            orig.name
        );

        // Secret group.
        assert_eq!(
            orig.secret_group, parsed.secret_group,
            "secret_group mismatch for {}",
            orig.name
        );

        // Min confidence threshold.
        assert_eq!(
            orig.min_confidence, parsed.min_confidence,
            "min_confidence mismatch for {}",
            orig.name
        );

        // Validator (always None for builtin rules).
        assert_eq!(
            orig.validator, parsed.validator,
            "validator mismatch for {}",
            orig.name
        );
    }
}

fn scan_yaml_rules(yaml: &str, hay: &[u8]) -> Vec<Finding> {
    let rules = parse_yaml_rules(yaml).expect("parse YAML rules");
    let engine =
        Engine::new_with_anchor_policy(rules, Vec::new(), demo_tuning(), AnchorPolicy::ManualOnly);
    let mut scratch = engine.new_scratch();
    let mut findings = Vec::with_capacity(1024);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
    findings
}

fn builtin_rule_by_name(rule_name: &str) -> RuleSpec {
    builtin_rules()
        .into_iter()
        .find(|rule| rule.name == rule_name)
        .unwrap_or_else(|| panic!("missing builtin rule: {rule_name}"))
}

fn scan_single_builtin_rule(rule_name: &str, hay: &[u8]) -> Vec<Finding> {
    let rule = builtin_rule_by_name(rule_name);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    let mut scratch = engine.new_scratch();
    let mut findings = Vec::with_capacity(16);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
    findings
}

/// Build an engine for a single rule, returning a closure that scans a
/// haystack without rebuilding the Vectorscan database each time.
///
/// NOTE: Scratch is allocated per-call intentionally. `ScanScratch`
/// carries inter-chunk state (dedup sets, stream counters) that causes
/// incorrect results when reused across independent inputs. Production
/// code reuses scratch across *chunks of the same file*, not across
/// unrelated scans.
fn make_rule_scanner(rule_name: &str) -> impl FnMut(&[u8]) -> Vec<Finding> {
    let rule = builtin_rule_by_name(rule_name);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );
    move |hay: &[u8]| {
        let mut scratch = engine.new_scratch();
        let mut findings = Vec::with_capacity(16);
        engine.scan_chunk_materialized(hay, &mut scratch, &mut findings);
        findings
    }
}

fn has_rule_hit(hits: &[Finding], rule_name: &str) -> bool {
    hits.iter().any(|hit| hit.rule == rule_name)
}

fn lcg_next(state: &mut u64) -> u64 {
    // Knuth's MMIX LCG (TAOCP Vol 2): a = 6364136223846793005, c = 1442695040888963407.
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn deterministic_secret(state: &mut u64, len: usize) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut out = String::with_capacity(len);
    for _ in 0..len {
        let next = lcg_next(state);
        let idx = (next % ALPHABET.len() as u64) as usize;
        out.push(ALPHABET[idx] as char);
    }
    out
}

/// Shared loop logic for random-high-entropy suppressor tests.
fn assert_random_high_entropy_not_suppressed(
    rule_name: &str,
    seed: u64,
    distinct_min: usize,
    secret_gen: &dyn Fn(&mut u64) -> String,
    haystack_fmt: &dyn Fn(&str) -> String,
) {
    let rule = builtin_rule_by_name(rule_name);
    let suppressors = rule
        .value_suppressors_any
        .unwrap_or_else(|| panic!("{rule_name} should have value suppressors"));
    let suppressors: Vec<&str> = suppressors
        .iter()
        .map(|s| std::str::from_utf8(s).expect("suppressor should be valid UTF-8"))
        .collect();

    let mut scan = make_rule_scanner(rule_name);
    let mut state = seed;
    let mut checked = 0usize;
    for _ in 0..192 {
        let secret = secret_gen(&mut state);
        if suppressors.iter().any(|sup| {
            secret
                .to_ascii_lowercase()
                .contains(&sup.to_ascii_lowercase())
        }) {
            continue;
        }

        let distinct = secret
            .as_bytes()
            .iter()
            .copied()
            .collect::<std::collections::BTreeSet<u8>>()
            .len();
        if distinct < distinct_min {
            continue;
        }

        let hay = haystack_fmt(&secret);
        let hits = scan(hay.as_bytes());
        assert!(
            has_rule_hit(&hits, rule_name),
            "expected randomized secret '{secret}' to be reported for {rule_name}"
        );
        checked += 1;
    }

    assert!(
        checked >= 96,
        "expected >=96 validated secrets for {rule_name}, got {checked}"
    );
}

#[test]
fn default_rules_yaml_matches_builtin_rules() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("default_rules.yaml");
    let yaml_str = std::fs::read_to_string(&path).expect("read default_rules.yaml");
    let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse default_rules.yaml");
    let expected_rules = builtin_rules();
    assert_rules_equal(&expected_rules, &parsed_rules);
}

#[test]
fn roundtrip_builtin_rules() {
    let original_rules = builtin_rules();

    // Convert to YAML and back.
    let yaml_rules: Vec<YamlRule> = original_rules.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_norway::to_string(&file).expect("serialize to YAML");
    let parsed_rules = parse_yaml_rules(&yaml_str).expect("parse YAML rules");
    assert_rules_equal(&original_rules, &parsed_rules);
}

#[test]
fn rulespec_to_yaml_emits_value_suppressors_any_when_present() {
    let yaml = r#"
rules:
  - name: "emit-value-suppressors"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
    secret_group: 1
"#;
    let parsed = parse_yaml_rules(yaml).expect("parse YAML into rulespec");
    let yaml_rule = rulespec_to_yaml(&parsed[0]);

    assert_eq!(
        yaml_rule.value_suppressors_any,
        Some(vec!["EXAMPLE".to_string(), "DUMMY_TOKEN".to_string()])
    );
}

#[test]
fn rulespec_to_yaml_omits_value_suppressors_any_when_absent() {
    let yaml = r#"
rules:
  - name: "omit-value-suppressors"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    secret_group: 1
"#;
    let parsed = parse_yaml_rules(yaml).expect("parse YAML into rulespec");
    let yaml_rule = rulespec_to_yaml(&parsed[0]);

    assert!(yaml_rule.value_suppressors_any.is_none());
}

#[test]
fn yaml_to_engine_suppresses_matching_secret_value() {
    let yaml = r#"
rules:
  - name: "yaml-suppressor-e2e"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    value_suppressors_any: ["EXAMPLE"]
    secret_group: 1
"#;

    let hay = b"prefix TOK_AEXAMPLE1234 suffix";
    let hits = scan_yaml_rules(yaml, hay);
    assert!(
        !hits.iter().any(|h| h.rule == "yaml-suppressor-e2e"),
        "expected suppressor match to prevent finding emission"
    );
}

#[test]
fn yaml_to_engine_emits_when_value_suppressor_absent() {
    let yaml = r#"
rules:
  - name: "yaml-suppressor-e2e"
    regex: 'TOK_([A-Z0-9]{12})'
    anchors: ["TOK_"]
    radius: 32
    secret_group: 1
"#;

    let hay = b"prefix TOK_AEXAMPLE1234 suffix";
    let hits = scan_yaml_rules(yaml, hay);
    assert!(
        hits.iter().any(|h| h.rule == "yaml-suppressor-e2e"),
        "expected finding when suppressors are not configured"
    );
}

#[test]
fn builtin_rules_use_no_fast_validators() {
    let rules = builtin_rules();
    assert!(!rules.is_empty(), "builtin rule set should not be empty");
    for rule in rules {
        assert_eq!(
            rule.validator,
            ValidatorKind::None,
            "rule '{}' unexpectedly enables fast validator",
            rule.name
        );
    }
}

#[test]
fn builtin_rules_count() {
    let rules = builtin_rules();
    assert_eq!(rules.len(), 223, "expected 223 builtin rules");
}

#[test]
fn top_fp_rules_have_value_suppressors_configured() {
    let target_rules = [
        "generic-api-key",
        "hashicorp-tf-password",
        "curl-auth-header",
        "curl-auth-user",
        "atlassian-api-token",
        "adafruit-api-key",
        "adobe-client-id",
        "algolia-api-key",
        "confluent-access-token",
        "confluent-secret-key",
        "discord-api-token",
        "discord-client-secret",
        "heroku-api-key",
        "linear-client-secret",
        "zendesk-secret-key",
    ];

    for rule_name in target_rules {
        let rule = builtin_rule_by_name(rule_name);
        let suppressors = rule
            .value_suppressors_any
            .unwrap_or_else(|| panic!("expected value_suppressors_any for {rule_name}"));
        assert!(
            !suppressors.is_empty(),
            "expected non-empty value_suppressors_any for {rule_name}"
        );
        assert!(
            suppressors.iter().any(|v| *v == b"example"),
            "expected shared suppressor 'example' for {rule_name}"
        );
    }
}

#[test]
/// Guardrail: strongly prefix-structured tokens intentionally stay off the
/// generic placeholder suppressor baseline to avoid format-specific false negatives.
fn structured_prefix_rules_keep_value_suppressors_unset() {
    let structured_prefix_rules = [
        "aws-access-token",
        "github-pat",
        "npm-access-token",
        "grafana-service-account-token",
        "sentry-org-token",
        // Explicitly commented in YAML as prefix-structured.
        "heroku-api-key-v2",
        "linear-api-key",
        // Shopify family (shpat_, shpca_, shppa_, shpss_).
        "shopify-access-token",
        "shopify-custom-access-token",
        "shopify-private-app-access-token",
        "shopify-shared-secret",
        // GitLab family (glpat-).
        "gitlab-pat",
    ];

    for rule_name in structured_prefix_rules {
        let rule = builtin_rule_by_name(rule_name);
        assert!(
            rule.value_suppressors_any.is_none(),
            "expected value_suppressors_any to remain unset for {rule_name}"
        );
    }
}

#[test]
fn generic_api_key_stage1_policy_requires_entropy_backed_confidence() {
    // Keep default_rules.yaml aligned with Stage 1 semantics verified in engine tests.
    let rule = builtin_rule_by_name("generic-api-key");
    assert_eq!(
        rule.min_confidence,
        Some(5),
        "generic-api-key should pin Stage 1 confidence floor to 5"
    );

    let entropy = rule
        .entropy
        .as_ref()
        .expect("generic-api-key should keep entropy gate enabled");
    assert_eq!(
        entropy.min_bits_per_byte, 3.5,
        "Stage 1 should keep existing Shannon entropy threshold"
    );
    assert_eq!(
        entropy.min_entropy_bits_per_byte, None,
        "Stage 1 should not enable min-entropy tightening yet"
    );
}

#[test]
fn suppressor_value_cases() {
    // Each entry: (rule_name, haystack, expect_hit, label).
    const CASES: &[(&str, &[u8], bool, &str)] = &[
        // Formerly: adafruit_api_key_suppresses_placeholder_value
        (
            "adafruit-api-key",
            b"adafruit_token=exampleexampleexampleexampleabcd",
            false,
            "placeholder adafruit API key should be suppressed",
        ),
        // Formerly: adafruit_api_key_allows_real_value
        (
            "adafruit-api-key",
            b"adafruit_token=a8f2k9x7m4p1q6w3b5n0j4c9d2e7h6m1",
            true,
            "real-looking adafruit API key should be reported",
        ),
        // Formerly: heroku_api_key_suppresses_placeholder_uuid
        (
            "heroku-api-key",
            b"heroku_key=00000000-0000-0000-0000-000000000000",
            false,
            "all-zeros placeholder UUID should be suppressed",
        ),
        // Formerly: heroku_api_key_allows_real_uuid
        (
            "heroku-api-key",
            b"heroku_key=7e2f19c4-83d1-4a56-b7e9-1f3c8d2a5b60",
            true,
            "real-looking Heroku UUID should be reported",
        ),
        // Formerly: discord_client_secret_suppresses_placeholder_value
        (
            "discord-client-secret",
            b"discord_app_key=exampleexampleexampleexampleabcd",
            false,
            "placeholder discord client secret should be suppressed",
        ),
        // Formerly: discord_client_secret_allows_real_value
        (
            "discord-client-secret",
            b"discord_app_key=\"a8f2c9d7e4b1063895fa2d7c4e0b1a39\"",
            true,
            "real-looking discord client secret should be reported",
        ),
        // Formerly: generic_api_key_suppresses_placeholder_value
        (
            "generic-api-key",
            b"API_KEY=YOUR_EXAMPLE_1",
            false,
            "placeholder API key should be suppressed",
        ),
        // Linux-style identifier assignment should not survive Stage 1.
        (
            "generic-api-key",
            b"api_key=driver_probe",
            false,
            "short identifier assignment should fail generic-api-key confidence floor",
        ),
        // Another identifier-like constant without entropy evidence.
        (
            "generic-api-key",
            b"token=KERNEL_STACK_ID",
            false,
            "identifier-like constant should fail generic-api-key confidence floor",
        ),
        // Formerly: generic_api_key_allows_real_value
        (
            "generic-api-key",
            b"API_KEY=a8f2k9x7m4p1q6w3",
            true,
            "real-looking API key should be reported",
        ),
        // Formerly: hashicorp_tf_password_suppresses_placeholder_value
        (
            "hashicorp-tf-password",
            b"password = \"changeme123\"",
            false,
            "placeholder terraform password should be suppressed",
        ),
        // Formerly: hashicorp_tf_password_allows_real_value
        (
            "hashicorp-tf-password",
            b"password = \"a8f2k9x7m4p1q6w3\"",
            true,
            "real-looking terraform password should be reported",
        ),
        // Formerly: hashicorp_tf_password_allows_real_value_with_password_substring
        (
            "hashicorp-tf-password",
            b"password = \"prodpassword19\"",
            true,
            "terraform password containing 'password' should be reported",
        ),
        // Formerly: curl_auth_header_suppresses_placeholder_bearer_token
        (
            "curl-auth-header",
            b"curl -H \"Authorization: Bearer YOUR_TOKEN_HERE\" https://api.example.com",
            false,
            "placeholder bearer token should be suppressed",
        ),
        // Formerly: curl_auth_header_allows_real_bearer_token
        (
            "curl-auth-header",
            b"curl -H \"Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9\" https://api.internal",
            true,
            "real-looking bearer token should be reported",
        ),
        // Formerly: curl_auth_header_suppresses_placeholder_api_key
        (
            "curl-auth-header",
            b"curl -H \"X-Api-Key: EXAMPLE_KEY_12345\" https://api.example.com",
            false,
            "placeholder X-Api-Key value should be suppressed",
        ),
        // Formerly: curl_auth_user_suppresses_placeholder_user_password
        (
            "curl-auth-user",
            b"curl -u admin:changeme https://api.example.com",
            false,
            "placeholder user:password should be suppressed",
        ),
        // Formerly: curl_auth_user_allows_real_user_password
        (
            "curl-auth-user",
            b"curl -u deploy_bot:a8f2k9x7m4p1q6w3 https://registry.internal",
            true,
            "real-looking curl -u credentials should be reported",
        ),
        // Formerly: curl_auth_user_allows_real_password_with_password_substring
        (
            "curl-auth-user",
            b"curl -u deploy_bot:password1234 https://registry.internal",
            true,
            "curl -u credentials containing 'password' should be reported",
        ),
        // Formerly: curl_auth_user_suppresses_literal_password_example
        (
            "curl-auth-user",
            b"curl -u 'user:password' https://api.example.com",
            false,
            "user:password literal example should be suppressed",
        ),
        // Formerly: atlassian_api_token_suppresses_placeholder_value
        (
            "atlassian-api-token",
            b"JIRA_TOKEN=yourexampletokenabcd1234",
            false,
            "placeholder atlassian token should be suppressed",
        ),
        // Formerly: atlassian_api_token_allows_real_value
        (
            "atlassian-api-token",
            b"JIRA_TOKEN=a8f2k9x7m4p1q6w3b5n0c1d2",
            true,
            "real-looking atlassian token should be reported",
        ),
        // Formerly: curl_auth_header_non_safelisted_url_does_not_suppress_real_token
        (
            "curl-auth-header",
            br#"curl https://api.internal -H "Authorization: Bearer a8f2k9x7m4p1q6w3b5n0j4c9""#,
            true,
            "non-safelisted URL must not suppress a real bearer token",
        ),
    ];

    for &(rule_name, hay, expect_hit, label) in CASES {
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert_eq!(
            has_rule_hit(&hits, rule_name),
            expect_hit,
            "{rule_name}: {label}"
        );
    }
}

#[test]
/// Validate that default_rules.yaml uses only known field names, catching
/// typos that serde would silently ignore.
fn default_rules_yaml_has_no_unknown_fields() {
    let yaml_str = include_str!("../../default_rules.yaml");
    let raw: serde_norway::Value =
        serde_norway::from_str(yaml_str).expect("parse default_rules.yaml");

    let rule_fields: &[&str] = &[
        "name",
        "regex",
        "anchors",
        "radius",
        "must_contain",
        "keywords_any",
        "value_suppressors_any",
        "entropy",
        "char_class",
        "two_phase",
        "local_context",
        "offline_validation",
        "secret_group",
        "uuid_format_secret",
        "min_confidence",
    ];
    let offline_validation_fields: &[&str] =
        &["type", "prefix_skip", "payload_len", "checksum_len"];
    let entropy_fields: &[&str] = &[
        "min_bits_per_byte",
        "min_len",
        "max_len",
        "min_entropy_bits_per_byte",
        "digit_penalty",
    ];
    let two_phase_fields: &[&str] = &["seed_radius", "full_radius", "confirm_any"];
    let local_ctx_fields: &[&str] = &[
        "lookbehind",
        "lookahead",
        "require_same_line_assignment",
        "require_quoted",
        "key_names_any",
    ];

    let rules = raw
        .get("rules")
        .and_then(|v| v.as_sequence())
        .expect("rules key");
    for (i, rule) in rules.iter().enumerate() {
        let map = rule.as_mapping().unwrap();
        let name = map
            .get(serde_norway::Value::String("name".into()))
            .and_then(|v| v.as_str())
            .unwrap_or("<unnamed>");
        for key in map.keys() {
            let k = key.as_str().unwrap_or("");
            assert!(
                rule_fields.contains(&k),
                "rule {i} ({name}) has unknown field '{k}'"
            );
        }
        // Check nested section fields.
        let char_class_fields: &[&str] = &["max_lower_pct", "min_window_len"];
        let nested_sections: &[(&str, &[&str])] = &[
            ("entropy", entropy_fields),
            ("char_class", char_class_fields),
            ("two_phase", two_phase_fields),
            ("local_context", local_ctx_fields),
            ("offline_validation", offline_validation_fields),
        ];
        for &(section, allowed) in nested_sections {
            assert_no_unknown_nested_fields(map, section, allowed, i, name);
        }
    }
}

#[test]
fn random_high_entropy_values_are_not_suppressed() {
    // Formerly: generic_api_key_random_high_entropy_values_are_not_suppressed,
    //           hashicorp_tf_password_random_high_entropy_values_are_not_suppressed,
    //           atlassian_api_token_random_high_entropy_values_are_not_suppressed,
    //           curl_auth_header_random_high_entropy_values_are_not_suppressed,
    //           curl_auth_user_random_high_entropy_values_are_not_suppressed.

    // generic-api-key: 24-char alphanumeric, distinct >= 8.
    assert_random_high_entropy_not_suppressed(
        "generic-api-key",
        0x9E3779B97F4A7C15,
        8,
        &|state| deterministic_secret(state, 24),
        &|secret| format!("API_KEY={secret}"),
    );

    // hashicorp-tf-password: 16-char alphanumeric, distinct >= 6.
    // The rule auto-derives min_confidence=3 (keyword + measured entropy), so
    // test secrets must be long enough for measured entropy (min_len=16).
    assert_random_high_entropy_not_suppressed(
        "hashicorp-tf-password",
        0xA5A5A5A5A5A5A5A5,
        6,
        &|state| deterministic_secret(state, 16),
        &|secret| format!("password = \"{secret}\""),
    );

    // atlassian-api-token: 20 [a-z0-9] + 4 [a-f0-9], distinct >= 6.
    let hex_alphabet: &[u8] = b"0123456789abcdef";
    let alnum_alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    assert_random_high_entropy_not_suppressed(
        "atlassian-api-token",
        0xCAFEBABEDEAD5678,
        6,
        &|state| {
            let mut secret = String::with_capacity(24);
            for _ in 0..20 {
                let next = lcg_next(state);
                secret.push(alnum_alphabet[(next % alnum_alphabet.len() as u64) as usize] as char);
            }
            for _ in 0..4 {
                let next = lcg_next(state);
                secret.push(hex_alphabet[(next % hex_alphabet.len() as u64) as usize] as char);
            }
            secret
        },
        &|secret| format!("JIRA_TOKEN={secret}"),
    );

    // curl-auth-header: 24-char alphanumeric, distinct >= 8.
    assert_random_high_entropy_not_suppressed(
        "curl-auth-header",
        0xDEADBEEFCAFEBABE,
        8,
        &|state| deterministic_secret(state, 24),
        &|secret| format!("curl -H \"Authorization: Bearer {secret}\" https://api.internal"),
    );

    // curl-auth-user: 20-char alphanumeric, distinct >= 8.
    assert_random_high_entropy_not_suppressed(
        "curl-auth-user",
        0xA5A5A5A5B4B4B4B4,
        8,
        &|state| deterministic_secret(state, 20),
        &|secret| format!("curl -u deploy_svc:{secret} https://registry.internal"),
    );
}

/// "password" must not appear in hashicorp-tf-password's value_suppressors_any,
/// as it would suppress real passwords containing that substring.
#[test]
fn hashicorp_tf_password_suppressors_do_not_include_password() {
    let rule = builtin_rule_by_name("hashicorp-tf-password");
    let suppressors = rule
        .value_suppressors_any
        .expect("hashicorp-tf-password should have value suppressors");
    assert!(
        !suppressors.iter().any(|s| s == b"password"),
        "literal 'password' must not be a value suppressor — it would cause false negatives"
    );
}

#[test]
fn parse_minimal_yaml() {
    let yaml = r#"
rules:
  - name: "test-rule"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
"#;
    let rules = parse_yaml_rules(yaml).expect("parse minimal YAML");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "test-rule");
    assert_eq!(rules[0].radius, 64);
    assert!(rules[0].keywords_any.is_none());
    assert!(rules[0].value_suppressors_any.is_none());
    assert!(rules[0].entropy.is_none());
    assert!(rules[0].two_phase.is_none());
    assert!(rules[0].local_context.is_none());
    assert!(rules[0].secret_group.is_none());
}

#[test]
fn parse_bad_regex_reports_rule_name() {
    let yaml = r#"
rules:
  - name: "bad-rule"
    regex: '[invalid'
    anchors: ["tok"]
    radius: 64
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::Regex { rule_name, .. }) => {
            assert_eq!(rule_name, "bad-rule");
        }
        other => panic!("expected Regex error, got: {:?}", other),
    }
}

#[test]
fn parse_empty_rules_list() {
    let yaml = "rules: []\n";
    // parse_yaml_rules itself returns Ok with empty vec;
    // load_rules catches the NoRules case.
    let rules = parse_yaml_rules(yaml).expect("parse empty rules");
    assert!(rules.is_empty());
}

#[test]
fn parse_invalid_yaml_returns_yaml_error() {
    let yaml = "{{{{not valid yaml";
    match parse_yaml_rules(yaml) {
        Err(RulesError::Yaml(_)) => {}
        other => panic!("expected Yaml error, got: {other:?}"),
    }
}

#[test]
fn parse_full_featured_yaml_rule() {
    let yaml = r#"
rules:
  - name: "full-rule"
    regex: '(secret_)[a-z0-9]{16}'
    anchors: ["secret_"]
    radius: 128
    must_contain: "secret_"
    keywords_any: ["secret", "key"]
    value_suppressors_any: ["EXAMPLE", "DUMMY_SECRET"]
    entropy:
      min_bits_per_byte: 3.5
      min_len: 8
      max_len: 64
    two_phase:
      seed_radius: 32
      full_radius: 128
      confirm_any: ["secret"]
    local_context:
      lookbehind: 64
      lookahead: 64
      require_same_line_assignment: true
      require_quoted: false
      key_names_any: ["api_key", "token"]
    secret_group: 1
"#;
    let rules = parse_yaml_rules(yaml).expect("parse full-featured YAML");
    assert_eq!(rules.len(), 1);
    let r = &rules[0];
    assert_eq!(r.name, "full-rule");
    assert_eq!(r.radius, 128);
    assert_eq!(r.anchors.len(), 1);
    assert_eq!(r.anchors[0], b"secret_");
    assert_eq!(r.must_contain, Some(b"secret_".as_slice()));
    assert_eq!(r.secret_group, Some(1));
    assert_eq!(r.validator, ValidatorKind::None);

    let kws = r.keywords_any.expect("keywords_any should be present");
    assert_eq!(kws.len(), 2);
    assert_eq!(kws[0], b"secret");
    assert_eq!(kws[1], b"key");

    let suppressors = r
        .value_suppressors_any
        .expect("value_suppressors_any should be present");
    assert_eq!(suppressors.len(), 2);
    assert_eq!(suppressors[0], b"EXAMPLE");
    assert_eq!(suppressors[1], b"DUMMY_SECRET");

    let ent = r.entropy.as_ref().expect("entropy should be present");
    assert_eq!(ent.min_bits_per_byte, 3.5);
    assert_eq!(ent.min_len, 8);
    assert_eq!(ent.max_len, 64);

    let tp = r.two_phase.as_ref().expect("two_phase should be present");
    assert_eq!(tp.seed_radius, 32);
    assert_eq!(tp.full_radius, 128);
    assert_eq!(tp.confirm_any.len(), 1);
    assert_eq!(tp.confirm_any[0], b"secret");

    let lc = r
        .local_context
        .as_ref()
        .expect("local_context should be present");
    assert_eq!(lc.lookbehind, 64);
    assert_eq!(lc.lookahead, 64);
    assert!(lc.require_same_line_assignment);
    assert!(!lc.require_quoted);
    let kns = lc.key_names_any.expect("key_names_any should be present");
    assert_eq!(kns.len(), 2);
    assert_eq!(kns[0], b"api_key");
    assert_eq!(kns[1], b"token");
}

#[test]
fn parse_reuses_interned_storage_across_calls() {
    let yaml = r#"
rules:
  - name: "interned-rule"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_", "TOK_"]
    radius: 64
    must_contain: "tok_"
    keywords_any: ["api", "token"]
    value_suppressors_any: ["EXAMPLE", "DUMMY_TOKEN"]
    two_phase:
      seed_radius: 32
      full_radius: 128
      confirm_any: ["api", "token"]
"#;

    let first = parse_yaml_rules(yaml).expect("first parse");
    let second = parse_yaml_rules(yaml).expect("second parse");
    let a = &first[0];
    let b = &second[0];

    assert!(
        std::ptr::eq(a.name, b.name),
        "name should be interned and reused"
    );
    assert!(
        std::ptr::eq(a.anchors, b.anchors),
        "anchor list should be interned and reused"
    );
    assert!(
        std::ptr::eq(a.anchors[0], b.anchors[0]),
        "anchor bytes should be interned and reused"
    );

    let a_must = a.must_contain.expect("must_contain set");
    let b_must = b.must_contain.expect("must_contain set");
    assert!(
        std::ptr::eq(a_must, b_must),
        "must_contain should be interned and reused"
    );

    let a_keywords = a.keywords_any.expect("keywords_any set");
    let b_keywords = b.keywords_any.expect("keywords_any set");
    assert!(
        std::ptr::eq(a_keywords, b_keywords),
        "keywords list should be interned and reused"
    );
    assert!(
        std::ptr::eq(a_keywords[0], b_keywords[0]),
        "keyword bytes should be interned and reused"
    );

    let a_suppressors = a.value_suppressors_any.expect("value_suppressors_any set");
    let b_suppressors = b.value_suppressors_any.expect("value_suppressors_any set");
    assert!(
        std::ptr::eq(a_suppressors, b_suppressors),
        "value_suppressors_any list should be interned and reused"
    );
    assert!(
        std::ptr::eq(a_suppressors[0], b_suppressors[0]),
        "value_suppressors_any bytes should be interned and reused"
    );

    let a_tp = a.two_phase.as_ref().expect("two_phase set");
    let b_tp = b.two_phase.as_ref().expect("two_phase set");
    assert!(
        std::ptr::eq(a_tp.confirm_any, b_tp.confirm_any),
        "two_phase confirm list should be interned and reused"
    );
    assert!(
        std::ptr::eq(a_tp.confirm_any[0], b_tp.confirm_any[0]),
        "two_phase confirm bytes should be interned and reused"
    );
}

#[test]
fn parse_yaml_with_unknown_fields_succeeds() {
    // Unknown fields are silently ignored (no deny_unknown_fields).
    let yaml = r#"
rules:
  - name: "extra-fields"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
    description: "this field is not in the schema"
    extra_field: 42
"#;
    let rules = parse_yaml_rules(yaml).expect("unknown fields should be ignored");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].name, "extra-fields");
}

#[test]
fn parse_yaml_missing_required_field_returns_yaml_error() {
    let yaml = r#"
rules:
  - name: "no-regex"
    anchors: ["tok"]
    radius: 64
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::Yaml(_)) => {}
        other => panic!("expected Yaml error, got: {other:?}"),
    }
}

// ---- offline_validation YAML parsing tests ----

#[test]
fn parse_offline_validation_valid_types() {
    // Formerly: parse_offline_validation_crc32_base62,
    //           parse_offline_validation_github_fine_grained_pat,
    //           parse_offline_validation_grafana_service_account,
    //           parse_offline_validation_aws_access_key,
    //           parse_offline_validation_sentry_org_token,
    //           parse_offline_validation_pypi_token,
    //           parse_offline_validation_slack_token.
    let cases: &[(&str, OfflineValidationSpec)] = &[
        (
            "type: crc32_base62\n      prefix_skip: 4\n      payload_len: 30\n      checksum_len: 6",
            OfflineValidationSpec::Crc32Base62 {
                prefix_skip: 4,
                payload_len: 30,
                checksum_len: 6,
            },
        ),
        (
            "type: github_fine_grained_pat",
            OfflineValidationSpec::GithubFinegrainedPat,
        ),
        (
            "type: grafana_service_account",
            OfflineValidationSpec::GrafanaServiceAccount,
        ),
        ("type: aws_access_key", OfflineValidationSpec::AwsAccessKey),
        (
            "type: sentry_org_token",
            OfflineValidationSpec::SentryOrgToken,
        ),
        ("type: pypi_token", OfflineValidationSpec::PyPiToken),
        ("type: slack_token", OfflineValidationSpec::SlackToken),
    ];

    for (ov_body, expected) in cases {
        let yaml = format!(
            "rules:\n  - name: \"ov-test\"\n    regex: 'tok_[a-z0-9]{{40}}'\n    \
             anchors: [\"tok_\"]\n    radius: 64\n    offline_validation:\n      {ov_body}\n"
        );
        let rules = parse_yaml_rules(&yaml).unwrap_or_else(|e| {
            panic!("parse failed for {ov_body}: {e}");
        });
        assert_eq!(
            rules[0].offline_validation,
            Some(*expected),
            "mismatch for {ov_body}"
        );
    }
}

#[test]
fn parse_offline_validation_absent_yields_none() {
    let yaml = r#"
rules:
  - name: "no-ov"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
"#;
    let rules = parse_yaml_rules(yaml).expect("parse rule without offline_validation");
    assert!(rules[0].offline_validation.is_none());
}

#[test]
fn parse_offline_validation_unknown_type_fails() {
    let yaml = r#"
rules:
  - name: "ov-bad"
    regex: 'tok_[a-z0-9]{8}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: nonexistent_algo
"#;
    match parse_yaml_rules(yaml) {
        Err(RulesError::OfflineValidation { rule_name, message }) => {
            assert_eq!(rule_name, "ov-bad");
            assert!(
                message.contains("nonexistent_algo"),
                "error should mention the unknown type: {message}"
            );
        }
        other => panic!("expected OfflineValidation error, got: {other:?}"),
    }
}

#[test]
fn parse_offline_validation_crc32_missing_fields() {
    // Formerly: parse_offline_validation_crc32_missing_payload_len_fails,
    //           parse_offline_validation_crc32_missing_prefix_skip_fails,
    //           parse_offline_validation_crc32_missing_checksum_len_fails.
    let cases: &[(&str, &str, &str)] = &[
        // (rule_name, present_fields, expected_missing_field)
        (
            "ov-incomplete",
            "prefix_skip: 4\n      checksum_len: 6",
            "payload_len",
        ),
        (
            "ov-no-prefix",
            "payload_len: 30\n      checksum_len: 6",
            "prefix_skip",
        ),
        (
            "ov-no-crc",
            "prefix_skip: 4\n      payload_len: 30",
            "checksum_len",
        ),
    ];

    for &(rule_name, fields, expected_field) in cases {
        let yaml = format!(
            "rules:\n  - name: \"{rule_name}\"\n    regex: 'tok_[a-z0-9]{{40}}'\n    \
             anchors: [\"tok_\"]\n    radius: 64\n    offline_validation:\n      \
             type: crc32_base62\n      {fields}\n"
        );
        match parse_yaml_rules(&yaml) {
            Err(RulesError::OfflineValidation {
                rule_name: got_name,
                message,
            }) => {
                assert_eq!(got_name, rule_name);
                assert!(
                    message.contains(expected_field),
                    "error for {rule_name} should mention '{expected_field}': {message}"
                );
            }
            other => panic!("expected OfflineValidation error for {rule_name}, got: {other:?}"),
        }
    }
}

#[test]
fn roundtrip_offline_validation_all_types() {
    // Formerly: roundtrip_offline_validation_crc32_base62,
    //           roundtrip_offline_validation_unit_variants,
    //           roundtrip_offline_validation_pypi_and_slack.
    assert_offline_validation_roundtrip(
        r#"
rules:
  - name: "rt-crc32"
    regex: 'tok_[a-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    offline_validation:
      type: crc32_base62
      prefix_skip: 4
      payload_len: 30
      checksum_len: 6
  - name: "rt-ghpat"
    regex: 'github_pat_[A-Za-z0-9_]{82}'
    anchors: ["github_pat_"]
    radius: 128
    offline_validation:
      type: github_fine_grained_pat
  - name: "rt-grafana"
    regex: 'glsa_[A-Za-z0-9]{32}_[a-f0-9]{8}'
    anchors: ["glsa_"]
    radius: 64
    offline_validation:
      type: grafana_service_account
  - name: "rt-aws"
    regex: 'AKIA[0-9A-Z]{16}'
    anchors: ["AKIA"]
    radius: 32
    offline_validation:
      type: aws_access_key
  - name: "rt-sentry"
    regex: 'sntrys_[A-Za-z0-9+/=]{64,}'
    anchors: ["sntrys_"]
    radius: 128
    offline_validation:
      type: sentry_org_token
  - name: "rt-pypi"
    regex: 'pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}'
    anchors: ["pypi-ageichlwas5vcmc"]
    radius: 1064
    offline_validation:
      type: pypi_token
  - name: "rt-slack"
    regex: 'xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*'
    anchors: ["xoxb"]
    radius: 2048
    offline_validation:
      type: slack_token
"#,
    );
}

// ---- default_rules.yaml offline validation spec assertions ----

#[test]
fn default_rules_offline_validation_specs() {
    let rules = builtin_rules();
    let find = |name: &str| -> &RuleSpec {
        rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing rule: {name}"))
    };

    let crc32_spec = OfflineValidationSpec::Crc32Base62 {
        prefix_skip: 4,
        payload_len: 30,
        checksum_len: 6,
    };

    // CRC32/Base62 rules (5 rules sharing the same token format).
    for rule_name in [
        "github-pat",
        "github-oauth",
        "github-app-token",
        "github-refresh-token",
        "npm-access-token",
    ] {
        assert_eq!(
            find(rule_name).offline_validation,
            Some(crc32_spec),
            "{rule_name} should have crc32_base62 offline validation"
        );
    }

    // Unit-variant rules.
    assert_eq!(
        find("github-fine-grained-pat").offline_validation,
        Some(OfflineValidationSpec::GithubFinegrainedPat),
    );
    assert_eq!(
        find("grafana-service-account-token").offline_validation,
        Some(OfflineValidationSpec::GrafanaServiceAccount),
    );
    assert_eq!(
        find("aws-access-token").offline_validation,
        Some(OfflineValidationSpec::AwsAccessKey),
    );
    assert_eq!(
        find("sentry-org-token").offline_validation,
        Some(OfflineValidationSpec::SentryOrgToken),
    );

    // PyPI upload token.
    assert_eq!(
        find("pypi-upload-token").offline_validation,
        Some(OfflineValidationSpec::PyPiToken),
    );

    // Slack token rules (8 rules, excluding slack-webhook-url).
    for rule_name in [
        "slack-app-token",
        "slack-bot-token",
        "slack-config-access-token",
        "slack-config-refresh-token",
        "slack-legacy-bot-token",
        "slack-legacy-token",
        "slack-legacy-workspace-token",
        "slack-user-token",
    ] {
        assert_eq!(
            find(rule_name).offline_validation,
            Some(OfflineValidationSpec::SlackToken),
            "{rule_name} should have slack_token offline validation"
        );
    }

    // slack-webhook-url is a URL, not a token — no offline validation.
    assert_eq!(
        find("slack-webhook-url").offline_validation,
        None,
        "slack-webhook-url should NOT have offline validation"
    );

    // Unrelated rules should have no offline validation.
    assert_eq!(
        find("generic-api-key").offline_validation,
        None,
        "generic-api-key should not have offline validation"
    );
}

// ---- offline validation rejection with default_rules.yaml specs ----

#[test]
fn default_rules_offline_validators_reject_bad_tokens() {
    use crate::engine::offline_validate;

    let rules = builtin_rules();
    let find = |name: &str| -> &RuleSpec {
        rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing rule: {name}"))
    };

    // CRC32/Base62 rules: token matches regex format but checksum is wrong.
    // 4-char prefix + 30 alphanumeric payload + 6 wrong checksum = 40 chars.
    let bad_crc32_token = b"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcd000000";
    for rule_name in [
        "github-pat",
        "github-oauth",
        "github-app-token",
        "github-refresh-token",
        "npm-access-token",
    ] {
        let spec = find(rule_name)
            .offline_validation
            .expect("should have offline_validation");
        let verdict = offline_validate::validate(spec, bad_crc32_token);
        assert_eq!(
            verdict,
            OfflineVerdict::Invalid,
            "{rule_name}: bad CRC32 token should be rejected"
        );
    }

    // GitHub fine-grained PAT: valid prefix but wrong checksum.
    let mut bad_ghpat = Vec::with_capacity(93);
    bad_ghpat.extend_from_slice(b"github_pat_");
    bad_ghpat.extend_from_slice(&[b'A'; 76]);
    bad_ghpat.extend_from_slice(b"000000"); // wrong checksum
    assert_eq!(bad_ghpat.len(), 93);
    let spec = find("github-fine-grained-pat").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_ghpat),
        OfflineVerdict::Invalid,
    );

    // Grafana: valid prefix but wrong hex checksum.
    let mut bad_grafana = Vec::new();
    bad_grafana.extend_from_slice(b"glsa_");
    bad_grafana.extend_from_slice(&[b'a'; 32]);
    bad_grafana.push(b'_');
    bad_grafana.extend_from_slice(b"deadbeef"); // wrong CRC
    let spec = find("grafana-service-account-token")
        .offline_validation
        .unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_grafana),
        OfflineVerdict::Invalid,
    );

    // AWS: lowercase chars in suffix → invalid.
    let bad_aws = b"AKIAiosfodnn7example";
    let spec = find("aws-access-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, bad_aws),
        OfflineVerdict::Invalid,
    );

    // Sentry: payload decodes to non-JSON → invalid.
    let mut bad_sentry = Vec::new();
    bad_sentry.extend_from_slice(b"sntrys_");
    // Base64 of "not_json_at_all_here" = "bm90X2pzb25fYXRfYWxsX2hlcmU="
    bad_sentry.extend_from_slice(b"bm90X2pzb25fYXRfYWxsX2hlcmU=");
    bad_sentry.push(b'_');
    bad_sentry.extend_from_slice(&[b'A'; 43]);
    let spec = find("sentry-org-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_sentry),
        OfflineVerdict::Invalid,
    );

    // PyPI: valid base64url but decodes to wrong header.
    let mut bad_pypi = Vec::new();
    bad_pypi.extend_from_slice(b"pypi-AAAAAAAAAAAAAAAA"); // decodes to 12 zero bytes
    bad_pypi.extend_from_slice(&[b'B'; 50]);
    let spec = find("pypi-upload-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, &bad_pypi),
        OfflineVerdict::Invalid,
    );

    // Slack: xoxb with unrecognised segment structure — Indeterminate (not
    // Invalid) so unknown future token formats are not suppressed.
    let bad_slack = b"xoxb-123-abc";
    let spec = find("slack-bot-token").offline_validation.unwrap();
    assert_eq!(
        offline_validate::validate(spec, bad_slack),
        OfflineVerdict::Indeterminate,
    );
}

#[test]
fn entropy_boundary_cases() {
    // Formerly: dropbox_api_token_entropy_gate_rejects_low_entropy,
    //           linkedin_client_id_entropy_gate_rejects_low_entropy,
    //           sumologic_access_id_entropy_gate_rejects_low_entropy,
    //           sendgrid_api_token_entropy_{rejects_below,accepts_above}_threshold,
    //           adobe_client_secret_entropy_{rejects_below,accepts_above}_threshold,
    //           alibaba_access_key_id_entropy_{rejects_below,accepts_above}_threshold,
    //           asana_client_id_entropy_{rejects_degenerate,rejects_low,accepts_high}_entropy,
    //           discord_client_id_entropy_{rejects_degenerate,rejects_low,accepts_high}_entropy.

    // (rule_name, haystack, expect_hit, label)
    let sendgrid_low = format!("secret = SG.{}\n", "abcd".repeat(16) + "ab");
    let sendgrid_high_base = "abcdefghijklmnopqrstuvwxyz012345";
    let sendgrid_high = format!(
        "secret = SG.{}\n",
        sendgrid_high_base.repeat(2).to_string() + &sendgrid_high_base[..2]
    );
    let adobe_low = format!("secret = p8e-{}\n", "abcd".repeat(8));
    let adobe_high = format!("secret = p8e-{}\n", "abcdefghijklmnopqrstuvwxyz012345");
    let alibaba_low = format!("secret = LTAI{}\n", "abcd".repeat(5));
    let alibaba_high = format!("secret = LTAI{}\n", "abcdefghijklmnopqrst");

    let cases: &[(&str, &[u8], bool, &str)] = &[
        // Zero-entropy rejection (degenerate inputs).
        (
            "dropbox-api-token",
            b"dropbox_key = aaaaaaaaaaaaaaa\n",
            false,
            "zero-entropy dropbox token should be rejected",
        ),
        (
            "linkedin-client-id",
            b"linkedin_key = aaaaaaaaaaaaaa\n",
            false,
            "zero-entropy linkedin client id should be rejected",
        ),
        (
            "sumologic-access-id",
            b"sumo_key = suaaaaaaaaaaaa\n",
            false,
            "near-zero entropy sumologic access id should be rejected",
        ),
        // Threshold 3.0: below/above pairs.
        (
            "sendgrid-api-token",
            sendgrid_low.as_bytes(),
            false,
            "~2.24 bits/byte should be rejected by 3.0 threshold",
        ),
        (
            "sendgrid-api-token",
            sendgrid_high.as_bytes(),
            true,
            "~5.1 bits/byte should pass the 3.0 threshold",
        ),
        (
            "adobe-client-secret",
            adobe_low.as_bytes(),
            false,
            "~2.50 bits/byte should be rejected by 3.0 threshold",
        ),
        (
            "adobe-client-secret",
            adobe_high.as_bytes(),
            true,
            "~5.1 bits/byte should pass the 3.0 threshold",
        ),
        (
            "alibaba-access-key-id",
            alibaba_low.as_bytes(),
            false,
            "~2.65 bits/byte should be rejected by 3.0 threshold",
        ),
        (
            "alibaba-access-key-id",
            alibaba_high.as_bytes(),
            true,
            "~4.58 bits/byte should pass the 3.0 threshold",
        ),
        // Threshold 2.5: digit-only rules.
        (
            "asana-client-id",
            b"asana_key = 1111111111111111\n",
            false,
            "0.0 bits/byte should be rejected by 2.5 threshold",
        ),
        (
            "asana-client-id",
            b"asana_key = 1234123412341234\n",
            false,
            "2.0 bits/byte should be rejected by 2.5 threshold",
        ),
        (
            "asana-client-id",
            b"asana_key = 1122334455667788\n",
            true,
            "3.0 bits/byte should pass the 2.5 threshold",
        ),
        (
            "discord-client-id",
            b"discord_id = 111111111111111111\n",
            false,
            "0.0 bits/byte should be rejected by 2.5 threshold",
        ),
        (
            "discord-client-id",
            b"discord_id = 123412341234123412\n",
            false,
            "~2.0 bits/byte should be rejected by 2.5 threshold",
        ),
        (
            "discord-client-id",
            b"discord_id = 112233445566778899\n",
            true,
            "3.17 bits/byte should pass the 2.5 threshold",
        ),
    ];

    for &(rule_name, hay, expect_hit, label) in cases {
        let hits = scan_single_builtin_rule(rule_name, hay);
        assert_eq!(
            has_rule_hit(&hits, rule_name),
            expect_hit,
            "{rule_name}: {label}"
        );
    }
}

/// CI guard: for every builtin rule with an entropy gate, the capture group's
/// maximum possible length must be >= `entropy.min_len`. When the longest
/// possible capture is shorter than `min_len`, the gate is silently bypassed
/// for ALL matches — the same bug class as dropbox-api-token (commit 9f7a293),
/// linkedin-client-id, and sumologic-access-id.
///
/// Variable-length captures (e.g., `{8,}`) where the minimum is below `min_len`
/// but longer matches can reach it are fine — the gate fires on those longer
/// matches by design.
#[test]
fn entropy_min_len_does_not_exceed_capture_maximum() {
    use regex_syntax::hir::HirKind;

    /// Recursively find capture group `target` and return its `maximum_len()`.
    /// Returns `None` if the group is not found; returns `Some(None)` if the
    /// group exists but has no upper bound.
    fn capture_max_len(hir: &regex_syntax::hir::Hir, target: u32) -> Option<Option<usize>> {
        match hir.kind() {
            HirKind::Capture(cap) => {
                if cap.index == target {
                    return Some(cap.sub.properties().maximum_len());
                }
                capture_max_len(&cap.sub, target)
            }
            HirKind::Concat(subs) | HirKind::Alternation(subs) => {
                for sub in subs {
                    if let Some(len) = capture_max_len(sub, target) {
                        return Some(len);
                    }
                }
                None
            }
            HirKind::Repetition(rep) => capture_max_len(&rep.sub, target),
            _ => None,
        }
    }

    // jwt-base64 uses only named capture groups in an alternation — group 1
    // is the `alg` field which is short (10 bytes), but the engine falls back
    // to group 0 (full match, 40+ bytes) when group 1 doesn't participate.
    // The entropy gate effectively fires on the fallback span.
    let skip: &[&str] = &["jwt-base64"];

    let rules = builtin_rules();
    let mut failures = Vec::new();

    for rule in &rules {
        if skip.contains(&rule.name) {
            continue;
        }

        let entropy = match &rule.entropy {
            Some(e) => e,
            None => continue,
        };

        let group_index = rule.secret_group.map_or(1u32, |g| g as u32);

        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .build()
            .parse(rule.re.as_str())
            .unwrap_or_else(|e| panic!("failed to parse regex for {}: {e}", rule.name));

        // Get the maximum capture length. `None` (unbounded) means the gate
        // will fire on sufficiently long matches, which is fine.
        let max_capture = match capture_max_len(&hir, group_index) {
            Some(Some(max)) => max,
            Some(None) => continue, // unbounded — gate can fire
            None => {
                // No explicit capture group; fall back to full pattern maximum.
                match hir.properties().maximum_len() {
                    Some(max) => max,
                    None => continue,
                }
            }
        };

        if entropy.min_len > max_capture {
            failures.push(format!(
                "{}: entropy.min_len ({}) > capture group {} maximum length ({})",
                rule.name, entropy.min_len, group_index, max_capture,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "entropy min_len exceeds capture maximum for {} rule(s):\n  {}",
        failures.len(),
        failures.join("\n  "),
    );
}

// ---------------------------------------------------------------------------
// CI guardrail: entropy threshold sanity bounds
// ---------------------------------------------------------------------------

/// CI guard: for every builtin rule with an entropy gate, the
/// `min_bits_per_byte` threshold must be within sane bounds.
///
/// 1. General: 1.0 ≤ threshold ≤ 5.0 for all entropy-gated rules.
/// 2. Digit-only ceiling: rules whose capture group matches only `[0-9]`
///    must not exceed `log2(10) ≈ 3.322` (the theoretical maximum entropy
///    for decimal digits).
#[test]
fn entropy_min_bits_per_byte_within_sane_bounds() {
    use regex_syntax::hir::{Class, HirKind};

    /// Recursively check if a HIR subtree can only match ASCII digits.
    fn is_digit_only(hir: &regex_syntax::hir::Hir) -> bool {
        match hir.kind() {
            HirKind::Literal(lit) => lit.0.iter().all(|&b| b.is_ascii_digit()),
            HirKind::Class(class) => match class {
                Class::Unicode(uc) => uc
                    .ranges()
                    .iter()
                    .all(|r| r.start() >= '0' && r.end() <= '9'),
                Class::Bytes(bc) => bc
                    .ranges()
                    .iter()
                    .all(|r| r.start() >= b'0' && r.end() <= b'9'),
            },
            HirKind::Concat(subs) | HirKind::Alternation(subs) => subs.iter().all(is_digit_only),
            HirKind::Repetition(rep) => is_digit_only(&rep.sub),
            HirKind::Capture(cap) => is_digit_only(&cap.sub),
            HirKind::Empty => true,
            _ => false,
        }
    }

    /// Find the capture group by index and check if its content is digit-only.
    fn capture_is_digit_only(hir: &regex_syntax::hir::Hir, target: u32) -> Option<bool> {
        match hir.kind() {
            HirKind::Capture(cap) => {
                if cap.index == target {
                    return Some(is_digit_only(&cap.sub));
                }
                capture_is_digit_only(&cap.sub, target)
            }
            HirKind::Concat(subs) | HirKind::Alternation(subs) => {
                for sub in subs {
                    if let Some(result) = capture_is_digit_only(sub, target) {
                        return Some(result);
                    }
                }
                None
            }
            HirKind::Repetition(rep) => capture_is_digit_only(&rep.sub, target),
            _ => None,
        }
    }

    // Maximum entropy possible with only decimal digits: log2(10).
    const LOG2_10: f64 = std::f64::consts::LOG2_10;

    let rules = builtin_rules();
    let mut failures = Vec::new();

    for rule in &rules {
        let entropy = match &rule.entropy {
            Some(e) => e,
            None => continue,
        };

        let threshold = f64::from(entropy.min_bits_per_byte);

        // Check 1: general bounds.
        if !(1.0..=5.0).contains(&threshold) {
            failures.push(format!(
                "{}: min_bits_per_byte ({}) outside sane range [1.0, 5.0]",
                rule.name, entropy.min_bits_per_byte,
            ));
            continue;
        }

        // Check 2: digit-only ceiling.
        let group_index = rule.secret_group.map_or(1u32, |g| g as u32);

        let hir = regex_syntax::ParserBuilder::new()
            .utf8(false)
            .build()
            .parse(rule.re.as_str())
            .unwrap_or_else(|e| panic!("failed to parse regex for {}: {e}", rule.name));

        let digit_only = capture_is_digit_only(&hir, group_index).unwrap_or(false);
        if digit_only && threshold > LOG2_10 {
            failures.push(format!(
                "{}: min_bits_per_byte ({}) exceeds log2(10) = {LOG2_10:.3} \
                 for digit-only capture group {group_index}",
                rule.name, entropy.min_bits_per_byte,
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "entropy min_bits_per_byte invariant violated for {} rule(s):\n  {}",
        failures.len(),
        failures.join("\n  "),
    );
}

#[test]
fn roundtrip_min_entropy_bits_per_byte() {
    let yaml = r#"
rules:
  - name: "rt-min-entropy"
    regex: '[A-Za-z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    entropy:
      min_bits_per_byte: 3.5
      min_len: 20
      max_len: 128
      min_entropy_bits_per_byte: 2.0
"#;
    let original = parse_yaml_rules(yaml).expect("parse");
    let ent = original[0].entropy.as_ref().expect("entropy present");
    assert_eq!(
        ent.min_entropy_bits_per_byte,
        Some(2.0),
        "parsed min_entropy_bits_per_byte should be Some(2.0)"
    );
    assert!(
        !ent.digit_penalty,
        "digit_penalty should default to false when omitted"
    );

    // Round-trip through YAML serialization.
    let yaml_rules: Vec<YamlRule> = original.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_norway::to_string(&file).expect("serialize");
    let parsed = parse_yaml_rules(&yaml_str).expect("re-parse");
    let reparsed_ent = parsed[0]
        .entropy
        .as_ref()
        .expect("entropy present after roundtrip");
    assert_eq!(
        reparsed_ent.min_entropy_bits_per_byte,
        Some(2.0),
        "round-tripped min_entropy_bits_per_byte should be Some(2.0)"
    );
    assert!(
        !reparsed_ent.digit_penalty,
        "round-tripped digit_penalty should stay false when omitted"
    );
}

#[test]
fn roundtrip_digit_penalty_true() {
    let yaml = r#"
rules:
  - name: "rt-digit-penalty"
    regex: '[a-f0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    entropy:
      min_bits_per_byte: 3.0
      min_len: 20
      max_len: 128
      digit_penalty: true
"#;
    let original = parse_yaml_rules(yaml).expect("parse");
    let ent = original[0].entropy.as_ref().expect("entropy present");
    assert!(ent.digit_penalty, "parsed digit_penalty should be true");

    let yaml_rules: Vec<YamlRule> = original.iter().map(rulespec_to_yaml).collect();
    let file = YamlRulesFile { rules: yaml_rules };
    let yaml_str = serde_norway::to_string(&file).expect("serialize");
    let parsed = parse_yaml_rules(&yaml_str).expect("re-parse");
    let reparsed_ent = parsed[0]
        .entropy
        .as_ref()
        .expect("entropy present after roundtrip");
    assert!(
        reparsed_ent.digit_penalty,
        "round-tripped digit_penalty should stay true"
    );
}

#[test]
fn char_class_auto_enable_cases() {
    // Formerly: char_class_auto_enabled_for_high_entropy_rule_without_explicit_field,
    //           char_class_not_auto_enabled_for_low_entropy_rule,
    //           explicit_char_class_not_overridden_by_auto_enable.

    // (yaml, expected char_class as Option<(max_lower_pct, min_window_len)>, label)
    #[allow(clippy::type_complexity)]
    const CASES: &[(&str, Option<(u8, u16)>, &str)] = &[
        (
            "rules:\n  - name: high-entropy-no-cc\n    regex: 'tok_[a-zA-Z0-9]{40}'\n    anchors: [\"tok_\"]\n    radius: 64\n    entropy:\n      min_bits_per_byte: 3.5\n      min_len: 8\n      max_len: 64\n",
            Some((95, 32)),
            "high entropy without explicit char_class → auto-enabled with defaults",
        ),
        (
            "rules:\n  - name: low-entropy-no-cc\n    regex: 'password=[a-z]{8}'\n    anchors: [\"password=\"]\n    radius: 64\n    entropy:\n      min_bits_per_byte: 1.0\n      min_len: 4\n      max_len: 32\n",
            None,
            "low entropy without explicit char_class → not auto-enabled",
        ),
        (
            "rules:\n  - name: explicit-cc\n    regex: 'tok_[a-zA-Z0-9]{40}'\n    anchors: [\"tok_\"]\n    radius: 64\n    entropy:\n      min_bits_per_byte: 4.0\n      min_len: 8\n      max_len: 64\n    char_class:\n      max_lower_pct: 80\n      min_window_len: 16\n",
            Some((80, 16)),
            "high entropy with explicit char_class → explicit values preserved",
        ),
    ];

    for &(yaml, expected, label) in CASES {
        let rules = parse_yaml_rules(yaml).unwrap_or_else(|e| panic!("[{label}] parse: {e}"));
        let cc = rules[0]
            .char_class
            .as_ref()
            .map(|c| (c.max_lower_pct, c.min_window_len));
        assert_eq!(cc, expected, "[{label}]");
    }
}

#[test]
fn char_class_null_in_yaml_is_equivalent_to_absent() {
    // Verify that `char_class: null` and absent `char_class` both trigger
    // auto-enable for high-entropy rules. In serde YAML, `null` and absent
    // both deserialize to `None` for `Option<T>` with `#[serde(default)]`.
    // This is standard YAML/serde semantics, not a bug.
    let yaml_with_null = r#"
rules:
  - name: "cc-null"
    regex: 'tok_[a-zA-Z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    char_class: null
    entropy:
      min_bits_per_byte: 3.5
      min_len: 8
      max_len: 64
"#;
    let yaml_absent = r#"
rules:
  - name: "cc-absent"
    regex: 'tok_[a-zA-Z0-9]{40}'
    anchors: ["tok_"]
    radius: 64
    entropy:
      min_bits_per_byte: 3.5
      min_len: 8
      max_len: 64
"#;
    let with_null = parse_yaml_rules(yaml_with_null).expect("parse null");
    let absent = parse_yaml_rules(yaml_absent).expect("parse absent");

    // Both should have auto-enabled char_class with identical defaults.
    let cc_null = with_null[0]
        .char_class
        .as_ref()
        .expect("null should auto-enable");
    let cc_absent = absent[0]
        .char_class
        .as_ref()
        .expect("absent should auto-enable");
    assert_eq!(cc_null.max_lower_pct, cc_absent.max_lower_pct);
    assert_eq!(cc_null.min_window_len, cc_absent.min_window_len);
}

#[test]
fn parse_min_confidence_explicit_integer() {
    let yaml = r#"
rules:
  - name: "mc-explicit"
    regex: 'tok_[A-Za-z0-9]{12}'
    anchors: ["tok_"]
    radius: 64
    min_confidence: 7
"#;
    let rules = parse_yaml_rules(yaml).expect("parse YAML with min_confidence");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].min_confidence, Some(7));
}

#[test]
fn parse_min_confidence_absent_is_none() {
    let yaml = r#"
rules:
  - name: "mc-absent"
    regex: 'tok_[A-Za-z0-9]{12}'
    anchors: ["tok_"]
    radius: 64
"#;
    let rules = parse_yaml_rules(yaml).expect("parse YAML without min_confidence");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].min_confidence, None);
}

#[test]
fn parse_min_confidence_null_is_none() {
    let yaml = r#"
rules:
  - name: "mc-null"
    regex: 'tok_[A-Za-z0-9]{12}'
    anchors: ["tok_"]
    radius: 64
    min_confidence: null
"#;
    let rules = parse_yaml_rules(yaml).expect("parse YAML with null min_confidence");
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0].min_confidence, None);
}

/// Verify that rules whose regex captures UUID-format secrets have the
/// `uuid_format_secret` flag set, and rules whose regex captures non-UUID
/// formats do NOT have the flag.
#[test]
fn uuid_format_secret_flag_matches_regex_structure() {
    let rules = builtin_rules();
    let find = |name: &str| -> &RuleSpec {
        rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("missing rule: {name}"))
    };

    // Rules whose capture group is exactly UUID format (8-4-4-4-12 hex)
    // MUST have uuid_format_secret=true to avoid false-negative suppression.
    let uuid_format_rules = [
        "heroku-api-key",
        "hubspot-api-key",
        "kucoin-secret-key",
        "messagebird-client-id",
        "sendbird-access-id",
        "snyk-api-token",
        "squarespace-access-token",
    ];
    for name in uuid_format_rules {
        assert!(
            find(name).uuid_format_secret,
            "{name}: regex captures UUID format but uuid_format_secret is false"
        );
    }

    // Rules whose capture group is NOT UUID format must NOT have the flag.
    let non_uuid_rules = [
        "heroku-api-key-v2",         // HRKU-AA prefix + 58 chars
        "huggingface-access-token",  // hf_ prefix + 34 alpha
        "launchdarkly-access-token", // 40-char alphanumeric
        "microsoft-teams-webhook",   // full webhook URL
        "sendbird-access-token",     // 40-char hex
        "sonar-api-token",           // squ_/sqp_/sqa_ prefix + 40 chars
        "stripe-access-token",       // sk_/rk_ prefix + 10-99 alphanum
    ];
    for name in non_uuid_rules {
        assert!(
            !find(name).uuid_format_secret,
            "{name}: regex does NOT capture UUID format but uuid_format_secret is true"
        );
    }
}
