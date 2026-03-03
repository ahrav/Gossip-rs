//! Rule Isolation Benchmark
//!
//! Identifies which individual rules cause the most throughput damage by A/B
//! testing engines with and without specific rules.
//!
//! # Problem Statement
//!
//! Not all rules are equal in cost. A single "broad" rule—one with many common
//! anchors (e.g., "api", "key", "token")—can dominate scan time because every
//! anchor hit triggers a radius extraction and regex evaluation. This benchmark
//! quantifies per-rule cost so we can decide whether to tighten, restructure,
//! or accept a given rule's overhead.
//!
//! # Methodology
//!
//! Each benchmark group builds multiple `Engine` instances that differ by
//! exactly one rule (or one dimension of a rule), then measures throughput on
//! the same input. The difference in throughput isolates that rule's cost.
//!
//! Two data classes are used:
//! - **Clean ASCII**: Random lowercase letters with no anchor matches.
//!   Measures Vectorscan's raw scan speed with zero post-match work.
//! - **Realistic code**: Repeating code snippets rich in common keywords
//!   (api, key, token, secret, password). Produces many anchor hits to stress
//!   the full scan pipeline: anchor match → radius extraction → regex → gates.
//!
//! # Benchmark Groups
//!
//! - **generic_api_key_impact**: Four engine configurations (baseline impossible
//!   rules, well-anchored rules only, generic-api-key only, mixed) × two data
//!   types = eight measurements. Isolates the generic-api-key rule's overhead.
//!
//! - **full_gitleaks_engine**: The production rule set from `demo_engine` on
//!   both data types. Provides an absolute reference point.
//!
//! - **anchor_density**: A single generic-api-key-style rule with 2, 4, 8, or
//!   14 common anchors. Shows how throughput degrades as anchor hit rate rises.
//!
//! # Interpreting Results
//!
//! - Compare "good_rules_only" vs "good_plus_generic" to see the marginal cost
//!   of adding generic-api-key to an otherwise efficient rule set.
//! - Compare "generic_api_key_only_clean" vs "_realistic" to see the
//!   amplification effect of anchor density on a broad rule.
//! - Use anchor_density results to set upper bounds on how many common anchors
//!   a single rule should carry.
//!
//! # Running
//!
//! ```bash
//! cargo bench --bench rule_isolation
//! cargo bench --bench rule_isolation -- generic_api_key_impact   # one group
//! cargo bench --bench rule_isolation -- anchor_density            # one group
//! ```
//!
//! # Relationship to `rule_scaling`
//!
//! `rule_scaling` measures how throughput changes as the *number* of rules
//! grows. This benchmark varies *which* rules are active (and sometimes isolates
//! a single rule), focusing on per-rule quality rather than quantity.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use regex::bytes::Regex;
use scanner_engine::{
    AnchorMode, AnchorPolicy, Engine, EntropySpec, RuleSpec, Tuning, ValidatorKind,
};

/// Buffer size for all isolation benchmarks.
///
/// 4 MiB is large enough to amortize per-scan overhead and measure steady-state
/// throughput, but small enough that even slow configurations complete quickly.
const BUFFER_SIZE: usize = 4 * 1024 * 1024;

/// Generate realistic code-like content saturated with common anchor keywords.
///
/// Returns a buffer of repeating code snippets that mimic real source files:
/// JavaScript, Python, env files, and YAML configs. Each snippet contains one
/// or more of the broad anchors used by generic-api-key ("api", "key", "token",
/// "secret", "password", "access", "auth", "credential").
///
/// # Why this matters
///
/// On clean data, broad anchors never fire and the rule is nearly free. On real
/// code, these keywords appear every few lines. This generator produces the
/// high-density case that stresses the full scan pipeline, making it the
/// complement to `gen_clean_ascii`.
///
/// The snippets are cycled round-robin to fill `size` bytes, then truncated.
fn gen_realistic_code(size: usize) -> Vec<u8> {
    let code_snippets = [
        b"const apiKey = process.env.API_KEY;\n".as_slice(),
        b"let token = getAccessToken();\n".as_slice(),
        b"const secret = config.secret;\n".as_slice(),
        b"password: ${PASSWORD}\n".as_slice(),
        b"authorization: Bearer token123\n".as_slice(),
        b"import { api } from './api';\n".as_slice(),
        b"function authenticate(credentials) {\n".as_slice(),
        b"const KEY = 'some-key-value';\n".as_slice(),
        b"export const ACCESS_TOKEN = '';\n".as_slice(),
        b"// This is a comment with key mention\n".as_slice(),
        b"def get_api_response(api_url):\n".as_slice(),
        b"    return requests.get(api_url)\n".as_slice(),
        b"class TokenManager:\n".as_slice(),
        b"    def refresh_token(self):\n".as_slice(),
        b"        pass\n".as_slice(),
        b"DISCORD_TOKEN=your_token_here\n".as_slice(),
        b"SLACK_API_KEY=xoxb-placeholder\n".as_slice(),
        b"aws_secret_access_key = placeholder\n".as_slice(),
        b"github_token: ghp_placeholder\n".as_slice(),
        b"stripe_secret_key: sk_test_placeholder\n".as_slice(),
    ];

    let mut data = Vec::with_capacity(size);
    let mut idx = 0;
    while data.len() < size {
        data.extend_from_slice(code_snippets[idx % code_snippets.len()]);
        idx += 1;
    }
    data.truncate(size);
    data
}

/// Generate pseudo-random lowercase ASCII text with 80-character lines.
///
/// Produces "clean" data with no secret-like keywords—anchors will not fire.
/// This isolates Vectorscan's raw multi-pattern scan cost from post-match
/// validation overhead. The xorshift PRNG ensures deterministic output
/// for reproducible benchmarks.
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        // xorshift64: fast, deterministic, good enough for test data
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    // Insert newlines every 80 chars for realistic line structure
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

/// Compile a byte-mode regex with a 32 MiB DFA size limit.
///
/// The elevated limit (default is 10 MiB) accommodates the generic-api-key
/// pattern which produces a large alternation automaton. Panics on invalid
/// patterns since benchmark rule definitions are compile-time constants.
fn build_regex(pattern: &str) -> Regex {
    regex::bytes::RegexBuilder::new(pattern)
        .size_limit(32 * 1024 * 1024)
        .build()
        .expect("invalid regex")
}

/// Construct the generic-api-key rule—the primary subject of this benchmark.
///
/// This rule is expensive because of three compounding factors:
///
/// 1. **Broad anchors**: 20 common keywords (api, key, token, secret, ...) that
///    appear frequently in real code. Each hit triggers radius extraction.
/// 2. **Large radius** (256 bytes): Every anchor hit extracts a 512-byte window
///    for regex evaluation, increasing memory traffic.
/// 3. **Complex regex**: Case-insensitive alternation with many branches and
///    flexible whitespace/delimiter matching, making regex evaluation slow per
///    candidate.
///
/// Together these mean: many anchor hits × large extraction × slow regex = the
/// rule that typically dominates scan time in production.
fn generic_api_key_rule() -> RuleSpec {
    RuleSpec {
        name: "generic-api-key",
        anchors: &[
            b"access",
            b"ACCESS",
            b"api",
            b"API",
            b"auth",
            b"AUTH",
            b"key",
            b"KEY",
            b"credential",
            b"CREDENTIAL",
            b"creds",
            b"CREDS",
            b"passwd",
            b"PASSWD",
            b"password",
            b"PASSWORD",
            b"secret",
            b"SECRET",
            b"token",
            b"TOKEN",
        ],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[
            b"access",
            b"ACCESS",
            b"api",
            b"API",
            b"auth",
            b"AUTH",
            b"key",
            b"KEY",
            b"credential",
            b"CREDENTIAL",
            b"creds",
            b"CREDS",
            b"passwd",
            b"PASSWD",
            b"password",
            b"PASSWORD",
            b"secret",
            b"SECRET",
            b"token",
            b"TOKEN",
        ]),
        value_suppressors_any: None,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.5,
            min_len: 16,
            max_len: 256,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: build_regex(
            r#"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"#,
        ),
    }
}

/// Create a rule whose anchor never appears in ASCII data (measurement baseline).
///
/// Uses a 4-byte high-ASCII anchor (`\xFF\xFE\xFD\xFC`) that cannot occur in
/// any of the benchmark's test buffers. This lets us measure the cost of having
/// rules *registered* in the Vectorscan automaton without any post-match work,
/// isolating automaton overhead from rule evaluation overhead.
fn impossible_rule(name: &'static str) -> RuleSpec {
    RuleSpec {
        name,
        anchors: &[b"\xFF\xFE\xFD\xFC"],
        radius: 64,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: None,
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: build_regex(r"\xFF\xFE\xFD\xFC[a-z]{10}"),
    }
}

/// A well-anchored rule representing the ideal case: GitHub Personal Access Token.
///
/// "Well-anchored" means the anchor (`ghp_`) is specific enough that it rarely
/// appears outside actual secrets. In realistic code the hit rate is near zero,
/// so this rule adds almost no post-match cost. Used as a control alongside
/// `generic_api_key_rule` to measure the gap between good and bad anchor design.
fn github_pat_rule() -> RuleSpec {
    RuleSpec {
        name: "github-pat",
        anchors: &[b"ghp_"],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"ghp_"]),
        value_suppressors_any: None,
        entropy: Some(EntropySpec {
            min_bits_per_byte: 3.0,
            min_len: 16,
            max_len: 256,
            min_entropy_bits_per_byte: None,
            digit_penalty: false,
        }),
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: build_regex(r"ghp_[0-9a-zA-Z]{36}"),
    }
}

/// Another well-anchored rule: AWS access key IDs.
///
/// AWS keys always start with a 4-character service prefix (AKIA, AGPA, etc.)
/// that is rare in non-secret text. Multiple anchors are used here (one per
/// service type), but all are highly specific—demonstrating that anchor *count*
/// alone does not make a rule expensive; anchor *frequency in real data* does.
fn aws_rule() -> RuleSpec {
    RuleSpec {
        name: "aws-access-key",
        anchors: &[b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA"],
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(&[b"AKIA", b"AGPA", b"AIDA", b"AROA", b"AIPA"]),
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: build_regex(r"(?:AKIA|AGPA|AIDA|AROA|AIPA)[A-Z0-9]{16}"),
    }
}

/// Measure the throughput impact of adding generic-api-key to an engine.
///
/// # Experimental design
///
/// Four engine configurations (three padded to 10 rules, one isolated):
///
/// | Config               | Rule composition                        |
/// |----------------------|-----------------------------------------|
/// | `baseline`           | 10 impossible rules (no anchor hits)    |
/// | `good_rules_only`    | 2 well-anchored + 8 impossible          |
/// | `generic_only`       | 1 generic-api-key (the subject rule)    |
/// | `good_plus_generic`  | 2 well-anchored + generic + 7 impossible|
///
/// Each is run on both clean and realistic data (8 total measurements).
///
/// # What to look for
///
/// - `baseline` vs `good_rules_only` on clean data: should be nearly identical
///   (specific anchors don't fire). On realistic data, may differ if GitHub/AWS
///   anchors appear in the snippets.
/// - `good_rules_only` vs `good_plus_generic`: the marginal cost of the broad
///   rule. A large gap means generic-api-key dominates overall scan time.
/// - `generic_only` on clean vs realistic: shows the amplification factor of
///   anchor density on a single rule's cost.
fn bench_generic_api_key_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("generic_api_key_impact");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    let tuning = Tuning {
        max_transform_depth: 0,
        ..scanner_engine::demo_tuning()
    };

    // Baseline: 10 rules registered in the automaton but never matching.
    // Measures the floor cost of having rules compiled into Vectorscan.
    let baseline_rules: Vec<RuleSpec> = (0..10)
        .map(|i| {
            let name: &'static str = Box::leak(format!("impossible_{}", i).into_boxed_str());
            impossible_rule(name)
        })
        .collect();
    let baseline_engine = Engine::new_with_anchor_policy(
        baseline_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut baseline_scratch = baseline_engine.new_scratch();

    // Well-anchored rules: specific prefixes that rarely fire in test data.
    // Pads to 10 rules with impossible fillers to keep rule count constant.
    let good_rules = vec![
        github_pat_rule(),
        aws_rule(),
        impossible_rule("placeholder_1"),
        impossible_rule("placeholder_2"),
        impossible_rule("placeholder_3"),
        impossible_rule("placeholder_4"),
        impossible_rule("placeholder_5"),
        impossible_rule("placeholder_6"),
        impossible_rule("placeholder_7"),
        impossible_rule("placeholder_8"),
    ];
    let good_engine = Engine::new_with_anchor_policy(
        good_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut good_scratch = good_engine.new_scratch();

    // Single broad rule in isolation—shows its standalone cost.
    let generic_only = vec![generic_api_key_rule()];
    let generic_engine = Engine::new_with_anchor_policy(
        generic_only,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut generic_scratch = generic_engine.new_scratch();

    // Mixed: well-anchored rules plus the broad rule. The throughput delta
    // between this and good_rules_only is the marginal cost of generic-api-key.
    let mixed_rules = vec![
        github_pat_rule(),
        aws_rule(),
        generic_api_key_rule(),
        impossible_rule("placeholder_1"),
        impossible_rule("placeholder_2"),
        impossible_rule("placeholder_3"),
        impossible_rule("placeholder_4"),
        impossible_rule("placeholder_5"),
        impossible_rule("placeholder_6"),
        impossible_rule("placeholder_7"),
    ];
    let mixed_engine = Engine::new_with_anchor_policy(
        mixed_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut mixed_scratch = mixed_engine.new_scratch();

    // -- Clean data: zero anchor hits expected, measures automaton overhead --
    group.bench_function("baseline_10_impossible_clean", |b| {
        b.iter(|| {
            let hits = baseline_engine.scan_chunk(black_box(&clean_data), &mut baseline_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_rules_only_clean", |b| {
        b.iter(|| {
            let hits = good_engine.scan_chunk(black_box(&clean_data), &mut good_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("generic_api_key_only_clean", |b| {
        b.iter(|| {
            let hits = generic_engine.scan_chunk(black_box(&clean_data), &mut generic_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_plus_generic_clean", |b| {
        b.iter(|| {
            let hits = mixed_engine.scan_chunk(black_box(&clean_data), &mut mixed_scratch);
            black_box(hits.len())
        })
    });

    // -- Realistic data: high anchor density, stresses the full scan pipeline --
    group.bench_function("baseline_10_impossible_realistic", |b| {
        b.iter(|| {
            let hits =
                baseline_engine.scan_chunk(black_box(&realistic_data), &mut baseline_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_rules_only_realistic", |b| {
        b.iter(|| {
            let hits = good_engine.scan_chunk(black_box(&realistic_data), &mut good_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("generic_api_key_only_realistic", |b| {
        b.iter(|| {
            let hits = generic_engine.scan_chunk(black_box(&realistic_data), &mut generic_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("good_plus_generic_realistic", |b| {
        b.iter(|| {
            let hits = mixed_engine.scan_chunk(black_box(&realistic_data), &mut mixed_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Measure throughput of the full production rule set as an absolute reference.
///
/// Uses `demo_engine_with_anchor_mode(Manual)` which loads all ~220 gitleaks
/// rules with their hand-specified anchors. This provides the "real world"
/// throughput number that the isolation benchmarks above help explain: if the
/// full engine is slow, the per-rule benchmarks show which rule(s) are to blame.
fn bench_full_gitleaks_engine(c: &mut Criterion) {
    let mut group = c.benchmark_group("full_gitleaks_engine");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let clean_data = gen_clean_ascii(BUFFER_SIZE, 0x1234);
    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    let full_engine = scanner_engine::demo_engine_with_anchor_mode(AnchorMode::Manual);
    let mut full_scratch = full_engine.new_scratch();

    group.bench_function("full_gitleaks_clean", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&clean_data), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.bench_function("full_gitleaks_realistic", |b| {
        b.iter(|| {
            let hits = full_engine.scan_chunk(black_box(&realistic_data), &mut full_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Measure how throughput degrades as a single rule gains more broad anchors.
///
/// Holds everything constant (one rule, same regex, same data) and varies only
/// the number of common anchors from 2 to 14. This answers the question: "If I
/// add `AUTH` as an anchor to my rule, how much throughput do I lose?"
///
/// # Design
///
/// The 14 anchors are drawn from the generic-api-key rule's actual anchor list,
/// ordered roughly by frequency in real code. Each test point uses the first N
/// anchors, so the 8-anchor case is a strict subset of the 14-anchor case.
///
/// Only realistic data is tested because clean data produces zero anchor hits
/// regardless of anchor count, making the measurements identical.
///
/// # Expected shape
///
/// Throughput should decrease monotonically with anchor count, but the curve
/// shape reveals whether the cost is:
/// - **Linear**: Each anchor adds a fixed cost (ideal for budgeting)
/// - **Super-linear**: Anchors interact (e.g., overlapping radii cause
///   redundant regex evaluations)
/// - **Sub-linear**: Diminishing marginal cost (anchor hit regions overlap)
fn bench_anchor_density(c: &mut Criterion) {
    let mut group = c.benchmark_group("anchor_density");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));

    let realistic_data = gen_realistic_code(BUFFER_SIZE);

    // The common keywords from generic-api-key, in both cases.
    // Ordered roughly by expected frequency in real code.
    let common_anchors = [
        "api", "API", "key", "KEY", "token", "TOKEN", "secret", "SECRET", "password", "PASSWORD",
        "access", "ACCESS", "auth", "AUTH",
    ];

    let tuning = Tuning {
        max_transform_depth: 0,
        ..scanner_engine::demo_tuning()
    };

    // Progressively add anchors to observe marginal cost per anchor
    for anchor_count in [2, 4, 8, 14] {
        let anchors: Vec<&'static [u8]> = common_anchors[..anchor_count]
            .iter()
            .map(|s| s.as_bytes() as &'static [u8])
            .collect();
        let anchors_static: &'static [&'static [u8]] = Box::leak(anchors.into_boxed_slice());

        let rule = RuleSpec {
            name: Box::leak(format!("test_{}_anchors", anchor_count).into_boxed_str()),
            anchors: anchors_static,
            radius: 256,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: Some(anchors_static),
            value_suppressors_any: None,
            entropy: Some(EntropySpec {
                min_bits_per_byte: 3.5,
                min_len: 16,
                max_len: 256,
                min_entropy_bits_per_byte: None,
                digit_penalty: false,
            }),
            char_class: None,
            local_context: None,
            secret_group: None,
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: build_regex(
                r#"(?i)[\w.-]{0,50}?(?:access|auth|api|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150})(?:[\x60'"\s;]|\\[nr]|$)"#,
            ),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            vec![],
            tuning.clone(),
            AnchorPolicy::ManualOnly,
        );
        let mut scratch = engine.new_scratch();

        group.bench_function(format!("{}_common_anchors", anchor_count), |b| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(&realistic_data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

criterion_group!(
    rule_isolation,
    bench_generic_api_key_impact,
    bench_full_gitleaks_engine,
    bench_anchor_density,
);

criterion_main!(rule_isolation);
