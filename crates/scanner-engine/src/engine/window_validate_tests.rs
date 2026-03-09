use super::*;
use crate::api::{AnchorPolicy, FileId, RuleSpec, ValidatorKind, confidence};
use crate::demo::demo_tuning;
use crate::engine::rule_repr::NO_GATE;
use regex::bytes::Regex;

#[test]
fn has_assignment_value_shape_cases() {
    let cases: &[(&str, &[u8], bool)] = &[
        // ---- separators ----
        ("equals basic", b"api_key=AKIAIOSFODNN7EXAMPLE", true),
        ("equals with space", b"token = abcdefghij1234567890", true),
        (
            "equals with quoted value",
            b"secret=\"longtoken1234\"",
            true,
        ),
        (
            "colon JSON-style",
            b"\"api_key\": \"AKIAIOSFODNN7EXAMPLE\"",
            true,
        ),
        ("colon bare", b"token: abcdefghij1234567890", true),
        ("arrow =>", b"key => longtoken1234567890", true),
        ("arrow => short-ish", b"secret => AKIAIOSFODNN7EX", true),
        // ---- special chars in token ----
        ("underscore/hyphen/dot", b"key=abc_def-ghi.jkl", true),
        ("hyphen token", b"token: some-long-token-value", true),
        ("dotted token", b"id = user.name.domain", true),
        // ---- boundary: exactly 10 chars ----
        ("10-char token passes", b"key=0123456789", true),
        // ---- skip whitespace and quotes ----
        ("spaces after sep", b"key=  longtokenvalue", true),
        ("double-quoted value", b"key=\"longtokenvalue\"", true),
        ("single-quoted value", b"key='longtokenvalue'", true),
        ("backtick-quoted value", b"key=`longtokenvalue`", true),
        // ---- false: short token (<10 chars) ----
        ("short token 'short'", b"key=short", false),
        ("short colon token", b"x: abc", false),
        ("9-char token fails", b"token = 123456789", false),
        ("9-char boundary", b"key=012345678", false),
        // ---- false: no separator ----
        (
            "prose without separator",
            b"some random text without assignment",
            false,
        ),
        (
            "space instead of sep",
            b"api_key AKIAIOSFODNN7EXAMPLE",
            false,
        ),
        // ---- false: no token after separator ----
        ("empty after equals", b"key=", false),
        ("whitespace after colon", b"token:   ", false),
        ("empty quotes after sep", b"secret = \"\"", false),
    ];

    for (label, input, expected) in cases {
        assert_eq!(
            has_assignment_value_shape(input),
            *expected,
            "case: {label}"
        );
    }
}

#[test]
fn test_local_context_same_line_assignment_passes() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix\nkey = SECRET\nsuffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));
}

#[test]
fn test_local_context_same_line_assignment_fails_when_missing() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix\nnope SECRET\nsuffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(!local_context_passes(
        window,
        secret_start,
        secret_end,
        spec
    ));
}

#[test]
fn test_local_context_same_line_assignment_fail_open_without_bounds() {
    let spec = LocalContextSpec {
        lookbehind: 4,
        lookahead: 4,
        require_same_line_assignment: true,
        require_quoted: false,
        key_names_any: None,
    };
    let window = b"prefix SECRET suffix";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));
}

#[test]
fn test_local_context_requires_quotes() {
    let spec = LocalContextSpec {
        lookbehind: 64,
        lookahead: 64,
        require_same_line_assignment: false,
        require_quoted: true,
        key_names_any: None,
    };
    let window = b"key='SECRET' ";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(local_context_passes(window, secret_start, secret_end, spec));

    let window = b"key=SECRET ";
    let secret_start = window.iter().position(|&b| b == b'S').unwrap();
    let secret_end = secret_start + "SECRET".len();
    assert!(!local_context_passes(
        window,
        secret_start,
        secret_end,
        spec
    ));
}

// ---- char_class_gate_passes tests ----

#[test]
fn char_class_gate_cases() {
    let cases: Vec<(&str, CharClassCompiled, Vec<u8>, bool)> = vec![
        (
            "short window fails open",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            vec![b'a'; 31],
            true,
        ),
        (
            "all-lowercase rejected",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            vec![b'a'; 40],
            false,
        ),
        (
            "mixed case passes",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 32,
            },
            {
                let mut w = vec![b'a'; 19];
                w.extend_from_slice(&[b'A'; 19]);
                w.extend_from_slice(&[b'0'; 2]);
                w
            },
            true,
        ),
        (
            "exact boundary (95%) passes",
            CharClassCompiled {
                max_lower_pct: 95,
                min_window_len: 20,
            },
            {
                let mut w = vec![b'a'; 19];
                w.push(b'A');
                w
            },
            true,
        ),
        (
            "zero tolerance rejects lowercase",
            CharClassCompiled {
                max_lower_pct: 0,
                min_window_len: 1,
            },
            b"a".to_vec(),
            false,
        ),
        (
            "zero tolerance allows uppercase",
            CharClassCompiled {
                max_lower_pct: 0,
                min_window_len: 1,
            },
            b"ABCDEF".to_vec(),
            true,
        ),
    ];

    for (label, spec, window, expected) in &cases {
        assert_eq!(
            char_class_gate_passes(window, *spec),
            *expected,
            "case: {label}"
        );
    }
}

// ---- compute_confidence_score tests ----

fn stub_rule(needs_assignment_shape: bool) -> RuleCompiled {
    RuleCompiled {
        re: Regex::new("x").unwrap(),
        must_contain: None,
        rule_meta: if needs_assignment_shape { 1 << 16 } else { 0 },
        confirm_all: NO_GATE,
        keywords: NO_GATE,
        value_suppressors: NO_GATE,
        entropy: NO_GATE,
        char_class: NO_GATE,
        local_context: NO_GATE,
        two_phase: NO_GATE,
        offline_validation: NO_GATE,
    }
}

fn stub_outcome(offline_verdict_valid: bool) -> EmitPolicyOutcome {
    EmitPolicyOutcome {
        drop_hint_end: 0,
        dedupe_with_span: false,
        norm_hash: [0; 32],
        offline_verdict_valid,
    }
}

fn stub_evidence(
    entropy_outcome: Option<EntropyGateOutcome>,
    keyword_local_hit: bool,
) -> GateEvidence {
    GateEvidence {
        entropy_outcome,
        keyword_local_hit,
    }
}

#[test]
fn compute_confidence_score_cases() {
    let cases: Vec<(&str, GateEvidence, bool, bool, i8)> = vec![
        ("no evidence", stub_evidence(None, false), false, false, 0),
        (
            "measured entropy only",
            stub_evidence(Some(EntropyGateOutcome::PassedMeasured), false),
            false,
            false,
            confidence::ENTROPY_PASS,
        ),
        (
            "keyword local only",
            stub_evidence(None, true),
            false,
            false,
            confidence::KEYWORD_PRESENT,
        ),
        (
            "short-len bypass entropy contributes zero",
            stub_evidence(Some(EntropyGateOutcome::BypassedShortLen), false),
            false,
            false,
            0,
        ),
        (
            "assignment shape only",
            stub_evidence(None, false),
            true,
            false,
            confidence::ASSIGNMENT_SHAPE,
        ),
        (
            "offline valid only",
            stub_evidence(None, false),
            false,
            true,
            confidence::OFFLINE_VALID,
        ),
        (
            "all signals",
            stub_evidence(Some(EntropyGateOutcome::PassedMeasured), true),
            true,
            true,
            10, // 1 + 2 + 2 + 5
        ),
    ];

    for (label, evidence, assignment_shape, offline_valid, expected) in &cases {
        let rule = stub_rule(*assignment_shape);
        let outcome = stub_outcome(*offline_valid);

        let score = compute_confidence_score(evidence, &rule, &outcome);
        assert_eq!(score, *expected, "case: {label}");
    }
}

fn min_conf_rule(
    name: &'static str,
    keywords_any: Option<&'static [&'static [u8]]>,
    min_confidence: i8,
) -> RuleSpec {
    RuleSpec {
        name,
        anchors: &[b"TOK_"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: Some(1),
        min_confidence: Some(min_confidence),
        offline_validation: None,
        uuid_format_secret: false,
        re: Regex::new(r"TOK_([A-Za-z0-9]{8})").unwrap(),
    }
}

#[test]
fn min_confidence_threshold_suppresses_low_score_finding() {
    let rule = min_conf_rule("min-conf-drop", None, 1);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(b"prefix TOK_ABCDEFGH suffix", FileId(0), 0, &mut scratch);

    assert!(
        scratch.findings().is_empty(),
        "score-0 finding should be suppressed by min_confidence=1"
    );
}

#[test]
fn min_confidence_threshold_allows_finding_at_threshold() {
    let rule = min_conf_rule(
        "min-conf-keep",
        Some(&[b"password"]),
        confidence::KEYWORD_PRESENT,
    );
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();
    engine.scan_chunk_into(b"password TOK_ABCDEFGH suffix", FileId(0), 0, &mut scratch);

    let findings = scratch.findings();
    assert_eq!(
        findings.len(),
        1,
        "threshold-equal finding should be emitted"
    );
    assert_eq!(
        findings[0].confidence_score,
        confidence::KEYWORD_PRESENT,
        "keyword gate should contribute KEYWORD_PRESENT and satisfy threshold"
    );
}

#[cfg(all(feature = "perf-stats", debug_assertions))]
#[test]
fn confidence_suppressed_counter_increments_and_resets() {
    // A rule with min_confidence=1 and no keyword/entropy gates: all findings
    // score 0 and get suppressed, incrementing the counter.
    let rule = min_conf_rule("counter-test", None, 1);
    let engine = Engine::new_with_anchor_policy(
        vec![rule],
        Vec::new(),
        demo_tuning(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch = engine.new_scratch();

    // First scan: one finding suppressed by confidence threshold.
    engine.scan_chunk_into(b"prefix TOK_ABCDEFGH suffix", FileId(0), 0, &mut scratch);
    assert_eq!(
        scratch.confidence_suppressed(),
        1,
        "confidence_suppressed counter should increment on suppression"
    );

    // Second scan (new file): another suppressed finding. Verify the counter
    // was reset (reads 1 again, not accumulated to 2).
    engine.scan_chunk_into(b"prefix TOK_XYZWVUTS suffix", FileId(1), 0, &mut scratch);
    assert_eq!(
        scratch.confidence_suppressed(),
        1,
        "confidence_suppressed counter should reset between scans (reads 1, not 2)"
    );
}
