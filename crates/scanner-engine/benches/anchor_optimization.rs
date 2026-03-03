//! Anchor Optimization Benchmarks
//!
//! Measures the impact of anchor design choices on scanning throughput. Anchors
//! are the literal byte sequences Vectorscan uses to locate potential matches
//! before running expensive regex validation. Better anchors = fewer false
//! candidates = higher throughput.
//!
//! # Problem Statement
//!
//! Every anchor match triggers a regex scan in a ±radius window. If an anchor
//! is too short (e.g., "ey"), it matches frequently in base64 data, causing
//! thousands of wasted regex evaluations. If too long, we might miss valid
//! secrets with slight variations.
//!
//! This benchmark quantifies these trade-offs with real-world anchor patterns.
//!
//! # Key Questions
//!
//! 1. **Anchor length impact**: How much does extending `ey` → `eyJ` → `eyJhbGci`
//!    improve throughput on base64-heavy data? (JWT detection)
//!
//! 2. **Consolidation benefits**: If 5 Twitter rules share the "twitter" anchor,
//!    can we merge them into 1 rule with a combined regex? Does this help?
//!
//! 3. **False candidate rate**: On data with high anchor density, how do
//!    different anchor lengths affect the candidate-to-match ratio?
//!
//! # Benchmark Groups
//!
//! - **anchor_length/jwt**: Compares `ey` (2-char), `eyJ` (3-char), and
//!   `eyJhbGci` (8-char) anchors on JWT-heavy, clean, and random data.
//!
//! - **anchor_length/sk**: Compares `sk` (2-char), `sk_live_` (8-char), and
//!   `sk_live_test` (12-char) for Stripe-like keys.
//!
//! - **consolidation/twitter**: 5 separate Twitter rules vs. 1 consolidated rule.
//!
//! - **consolidation/multi_provider**: 14 rules (5 Twitter, 3 Discord, 3 Dropbox,
//!   3 Mailgun) vs. 4 consolidated rules.
//!
//! - **diversity**: 50 rules with shared prefix vs. 50 rules with diverse prefixes.
//!
//! # Running
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench --bench anchor_optimization
//!
//! # Run specific groups
//! cargo bench --bench anchor_optimization -- anchor_length
//! cargo bench --bench anchor_optimization -- consolidation
//! cargo bench --bench anchor_optimization -- diversity
//! ```
//!
//! # Interpreting Results
//!
//! - **JWT benchmarks**: If `eyJhbGci` is 10x faster than `ey` on base64 data but
//!   only 2x faster on clean data, the benefit is data-dependent.
//!
//! - **Consolidation**: If 1 rule is only 5-10% faster than 5 rules, consolidation
//!   may not be worth the regex complexity. If 50%+ faster, consolidate.
//!
//! - **Diversity**: If diverse prefixes are significantly slower, consider
//!   organizing rules by prefix families to improve automaton efficiency.

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::{AnchorPolicy, Engine, RuleSpec, Tuning, ValidatorKind, demo_tuning};

// ============================================================================
// Configuration
// ============================================================================

/// Buffer size for all anchor benchmarks.
///
/// 4 MiB is large enough to amortize per-scan overhead and observe steady-state
/// behavior across different anchor densities.
const BUFFER_SIZE: usize = 4 * 1024 * 1024;

// ============================================================================
// Data Generation
// ============================================================================

/// Generate base64-like data with controlled "ey" prefix density.
///
/// JWTs start with `eyJ` (base64 prefix for `{"...` JSON objects) which means "ey" appears at the
/// start of every JWT header. However, "ey" also appears naturally in base64
/// data at ~1/4096 frequency (1/64 * 1/64). This function creates worst-case
/// data for JWT detection by:
///
/// 1. Filling with base64 alphabet (high natural "ey" density)
/// 2. Adding extra "ey" patterns at specified density
///
/// # Parameters
///
/// - `jwt_density`: Percentage of buffer positions that contain "ey" (0.5 = 0.5%)
///
/// # Use case
///
/// Tests how short anchors like "ey" perform when the input has many false
/// candidates that pass Vectorscan but fail regex validation.
fn gen_jwt_heavy_data(size: usize, jwt_density: f64) -> Vec<u8> {
    let mut buf = vec![0u8; size];
    let mut state = 0x12345678u64;

    // Fill with base64-like characters (which frequently contain "ey")
    let b64_chars = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b64_chars[(state as usize) % b64_chars.len()];
    }

    // Sprinkle "ey" patterns at specified density
    let ey_count = ((size as f64) * jwt_density / 100.0) as usize;
    for i in 0..ey_count {
        let pos = (i * size / ey_count.max(1)) % (size - 2);
        buf[pos] = b'e';
        buf[pos + 1] = b'y';
    }

    // Add line breaks for realistic-ish structure
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }

    buf
}

/// Generate ASCII data with controlled "sk" prefix density.
///
/// Stripe keys start with `sk_live_` or `sk_test_`, but many secrets and
/// identifiers contain "sk" (e.g., "task", "flask", "desk"). This creates
/// data to test whether longer anchors like `sk_live_` filter better than
/// the minimal "sk" prefix.
///
/// # Parameters
///
/// - `density`: Percentage of buffer positions that contain "sk" (0.5 = 0.5%)
fn gen_sk_heavy_data(size: usize, density: f64) -> Vec<u8> {
    let mut buf = gen_clean_ascii(size, 0x5678);

    // Sprinkle "sk" patterns
    let count = ((size as f64) * density / 100.0) as usize;
    for i in 0..count {
        let pos = (i * size / count.max(1)) % (size - 2);
        buf[pos] = b's';
        buf[pos + 1] = b'k';
    }

    buf
}

/// Generate data with high density of provider keyword anchors.
///
/// Many secret detection rules use provider names as anchors (e.g., "twitter",
/// "discord"). This tests the scenario where documentation or code frequently
/// mentions these providers without containing actual secrets.
///
/// # Keyword distribution
///
/// - 1000 total keyword occurrences across 8 variations
/// - Both lowercase and uppercase (twitter/TWITTER)
/// - Evenly distributed throughout the buffer
///
/// # Use case
///
/// Tests consolidation strategies: does merging 5 Twitter rules into 1 help
/// when "twitter" appears frequently in the input?
fn gen_keyword_heavy_data(size: usize) -> Vec<u8> {
    let mut buf = gen_clean_ascii(size, 0x9abc);

    // Provider keywords commonly used as rule anchors
    let keywords = [
        b"twitter".as_slice(),
        b"TWITTER".as_slice(),
        b"discord".as_slice(),
        b"DISCORD".as_slice(),
        b"dropbox".as_slice(),
        b"DROPBOX".as_slice(),
        b"mailgun".as_slice(),
        b"MAILGUN".as_slice(),
    ];

    // Add ~1000 keyword occurrences (evenly spaced)
    for i in 0..1000 {
        let keyword = keywords[i % keywords.len()];
        let pos = (i * (size / 1000)) % (size - keyword.len());
        buf[pos..pos + keyword.len()].copy_from_slice(keyword);
    }

    buf
}

/// Generate pseudo-random lowercase ASCII text with 80-character lines.
///
/// Represents "clean" data with minimal false candidates. Lowercase-only
/// ensures no matches against uppercase anchors (AKIA, TWITTER, etc.).
fn gen_clean_ascii(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = b'a' + ((state & 0xFF) % 26) as u8;
    }
    for i in (80..buf.len()).step_by(80) {
        buf[i] = b'\n';
    }
    buf
}

/// Generate uniform random bytes (0x00-0xFF).
///
/// Represents binary data like images or compressed files. Any 2-character
/// anchor has ~1/65536 chance per position, so a 4 MiB buffer will have
/// ~64 random occurrences of any 2-byte sequence. This tests the baseline
/// false candidate rate for short anchors on binary input.
fn gen_random_bytes(size: usize, seed: u64) -> Vec<u8> {
    let mut state = seed;
    let mut buf = vec![0u8; size];
    for b in buf.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *b = (state & 0xFF) as u8;
    }
    buf
}

// ============================================================================
// Rule Generators
// ============================================================================

/// Create a single-anchor rule with keyword filtering enabled.
///
/// The `keywords_any` field is set to match the anchor, enabling the fast-path
/// keyword check before regex evaluation. This matches production rule config.
fn make_rule(name: &'static str, anchor: &'static [u8], pattern: &str) -> RuleSpec {
    let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

    RuleSpec {
        name,
        anchors,
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(anchors),
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: regex::bytes::Regex::new(pattern).unwrap(),
    }
}

/// Create a rule with multiple anchor variants (e.g., lowercase + uppercase).
///
/// Used for case-insensitive keyword detection where we want Vectorscan to
/// match either "twitter" or "TWITTER" and trigger the same rule.
fn make_rule_multi(
    name: &'static str,
    anchors: &'static [&'static [u8]],
    pattern: &str,
) -> RuleSpec {
    RuleSpec {
        name,
        anchors,
        radius: 256,
        validator: ValidatorKind::None,
        two_phase: None,
        must_contain: None,
        keywords_any: Some(anchors),
        value_suppressors_any: None,
        entropy: None,
        char_class: None,
        local_context: None,
        secret_group: None,
        min_confidence: None,
        offline_validation: None,
        uuid_format_secret: false,
        re: regex::bytes::Regex::new(pattern).unwrap(),
    }
}

// ============================================================================
// Short Anchor Benchmarks
// ============================================================================

/// Measure the throughput impact of anchor length for JWT detection.
///
/// # Background
///
/// JWTs are base64-encoded JSON with structure: `header.payload.signature`.
/// The header always starts with `{"alg"` (or similar JSON key), which
/// base64-encodes to a string starting with `eyJ`. Many
/// rules use `ey` (2 chars) as the anchor, but this matches frequently in
/// any base64 data.
///
/// # Anchor variants tested
///
/// - `ey` (2 chars): Matches any base64 starting with 'e','y'. High false rate.
/// - `eyJ` (3 chars): Matches JSON-like base64 headers. Better filtering.
/// - `eyJhbGci` (8 chars): Matches `{"alg"` prefix. Very specific but may
///   miss JWTs with different first keys.
///
/// # Data scenarios
///
/// - **jwt_heavy**: Base64 alphabet with 0.5% "ey" density (worst case)
/// - **clean**: Lowercase ASCII (best case, no matches)
/// - **random**: Uniform bytes (realistic binary file)
///
/// # Trade-off insight
///
/// Longer anchors reduce false candidates but may miss edge cases. Use this
/// data to find the sweet spot for JWT detection in your workload.
fn bench_jwt_anchor_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("anchor_length/jwt");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    // Three data types with different "ey" densities
    let jwt_heavy = gen_jwt_heavy_data(BUFFER_SIZE, 0.5); // Worst case: 0.5% "ey"
    let clean_ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234); // Best case: ~0% "ey"
    let random = gen_random_bytes(BUFFER_SIZE, 0x5678); // Baseline: ~0.0015% "ey"

    // Short anchor: matches "eye", "eyes", "eyebrow", etc.
    let rule_short = make_rule(
        "jwt-short",
        b"ey",
        r"\bey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    );

    // Medium anchor: matches `{"` base64 prefix (most JWTs)
    let rule_long = make_rule(
        "jwt-long",
        b"eyJ",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    );

    // Long anchor: matches `{"alg":` (standard JWT header start)
    let rule_very_long = make_rule(
        "jwt-very-long",
        b"eyJhbGci",
        r"\beyJhbGci[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
    );

    let engine_short = Engine::new_with_anchor_policy(
        vec![rule_short],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_long = Engine::new_with_anchor_policy(
        vec![rule_long],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_very_long = Engine::new_with_anchor_policy(
        vec![rule_very_long],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch_short = engine_short.new_scratch();
    let mut scratch_long = engine_long.new_scratch();
    let mut scratch_very_long = engine_very_long.new_scratch();

    // Test on JWT-heavy data
    group.bench_function("ey_jwt_heavy", |b| {
        b.iter(|| {
            let hits = engine_short.scan_chunk(black_box(&jwt_heavy), &mut scratch_short);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJ_jwt_heavy", |b| {
        b.iter(|| {
            let hits = engine_long.scan_chunk(black_box(&jwt_heavy), &mut scratch_long);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJhbGci_jwt_heavy", |b| {
        b.iter(|| {
            let hits = engine_very_long.scan_chunk(black_box(&jwt_heavy), &mut scratch_very_long);
            black_box(hits.len())
        })
    });

    // Test on clean ASCII
    group.bench_function("ey_clean", |b| {
        b.iter(|| {
            let hits = engine_short.scan_chunk(black_box(&clean_ascii), &mut scratch_short);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJ_clean", |b| {
        b.iter(|| {
            let hits = engine_long.scan_chunk(black_box(&clean_ascii), &mut scratch_long);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJhbGci_clean", |b| {
        b.iter(|| {
            let hits = engine_very_long.scan_chunk(black_box(&clean_ascii), &mut scratch_very_long);
            black_box(hits.len())
        })
    });

    // Test on random bytes
    group.bench_function("ey_random", |b| {
        b.iter(|| {
            let hits = engine_short.scan_chunk(black_box(&random), &mut scratch_short);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJ_random", |b| {
        b.iter(|| {
            let hits = engine_long.scan_chunk(black_box(&random), &mut scratch_long);
            black_box(hits.len())
        })
    });

    group.bench_function("eyJhbGci_random", |b| {
        b.iter(|| {
            let hits = engine_very_long.scan_chunk(black_box(&random), &mut scratch_very_long);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Measure the throughput impact of anchor length for Stripe-like API keys.
///
/// # Background
///
/// Stripe uses prefixed keys: `sk_live_*`, `sk_test_*`, `pk_live_*`. Some
/// rules use just `sk` (2 chars) as the anchor, catching more key types but
/// also matching words like "task", "flask", "desk".
///
/// # Anchor variants tested
///
/// - `sk` (2 chars): Generic, catches Twilio (`SK*`), matches English words
/// - `sk_live_` (8 chars): Stripe-specific, very low false positive rate
/// - `sk_live_test` (12 chars): Hypothetical long prefix, near-zero false rate
///
/// # Trade-off insight
///
/// Unlike JWT where `eyJ` is nearly as good as `eyJhbGci`, the gap between
/// `sk` and `sk_live_` is larger because "sk" is a common bigram in English.
fn bench_sk_anchor_length(c: &mut Criterion) {
    let mut group = c.benchmark_group("anchor_length/sk");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let sk_heavy = gen_sk_heavy_data(BUFFER_SIZE, 0.5); // 0.5% "sk" density
    let clean_ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // 2-char anchor: matches "sk" in "task", "flask", "desk", etc.
    let rule_short = make_rule("sk-short", b"sk", r"\bsk[A-Za-z0-9]{30,}\b");

    // 8-char anchor: Stripe live key prefix (very specific)
    let rule_medium = make_rule("sk-medium", b"sk_live_", r"\bsk_live_[A-Za-z0-9]{24,}\b");

    // 12-char anchor: hypothetical even longer prefix
    let rule_long = make_rule(
        "sk-long",
        b"sk_live_test",
        r"\bsk_live_test[A-Za-z0-9]{20,}\b",
    );

    let engine_short = Engine::new_with_anchor_policy(
        vec![rule_short],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_medium = Engine::new_with_anchor_policy(
        vec![rule_medium],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_long = Engine::new_with_anchor_policy(
        vec![rule_long],
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch_short = engine_short.new_scratch();
    let mut scratch_medium = engine_medium.new_scratch();
    let mut scratch_long = engine_long.new_scratch();

    // Test on sk-heavy data
    group.bench_function("sk_heavy", |b| {
        b.iter(|| {
            let hits = engine_short.scan_chunk(black_box(&sk_heavy), &mut scratch_short);
            black_box(hits.len())
        })
    });

    group.bench_function("sk_live_heavy", |b| {
        b.iter(|| {
            let hits = engine_medium.scan_chunk(black_box(&sk_heavy), &mut scratch_medium);
            black_box(hits.len())
        })
    });

    group.bench_function("sk_live_test_heavy", |b| {
        b.iter(|| {
            let hits = engine_long.scan_chunk(black_box(&sk_heavy), &mut scratch_long);
            black_box(hits.len())
        })
    });

    // Test on clean ASCII (shows false candidate rate)
    group.bench_function("sk_clean", |b| {
        b.iter(|| {
            let hits = engine_short.scan_chunk(black_box(&clean_ascii), &mut scratch_short);
            black_box(hits.len())
        })
    });

    group.bench_function("sk_live_clean", |b| {
        b.iter(|| {
            let hits = engine_medium.scan_chunk(black_box(&clean_ascii), &mut scratch_medium);
            black_box(hits.len())
        })
    });

    group.bench_function("sk_live_test_clean", |b| {
        b.iter(|| {
            let hits = engine_long.scan_chunk(black_box(&clean_ascii), &mut scratch_long);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Keyword Anchor Consolidation Benchmarks
// ============================================================================

/// Compare scanning cost of 5 separate Twitter rules vs. 1 consolidated rule.
///
/// # Background
///
/// Gitleaks has multiple Twitter secret rules:
/// - twitter-access-secret
/// - twitter-access-token
/// - twitter-api-key
/// - twitter-api-secret
/// - twitter-bearer-token
///
/// All share the "twitter"/"TWITTER" anchor. When Vectorscan matches "twitter",
/// it triggers validation for all 5 rules. We can consolidate into 1 rule with
/// a combined regex that captures all variants.
///
/// # Hypothesis
///
/// - **Vectorscan cost**: Same (one anchor match triggers callback once per rule)
/// - **Regex cost**: Consolidated regex is more complex but runs once, not 5x
/// - **Net effect**: Depends on regex complexity vs. callback overhead
///
/// # Decision guidance
///
/// If consolidation shows >20% improvement, consider merging rules by provider.
/// If <10%, keep rules separate for easier maintenance and debugging.
fn bench_keyword_consolidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("consolidation/twitter");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let keyword_heavy = gen_keyword_heavy_data(BUFFER_SIZE);
    let clean_ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // Original: 5 separate rules, each with twitter/TWITTER anchor
    let rules_separate = vec![
        make_rule_multi(
            "twitter-access-secret",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}access.{0,20}secret.{0,20}['\"][a-zA-Z0-9]{35,44}['\"]"#,
        ),
        make_rule_multi(
            "twitter-access-token",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}access.{0,20}token.{0,20}['\"][0-9]+-[a-zA-Z0-9]{35,44}['\"]"#,
        ),
        make_rule_multi(
            "twitter-api-key",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}api.{0,20}key.{0,20}['\"][a-zA-Z0-9]{25}['\"]"#,
        ),
        make_rule_multi(
            "twitter-api-secret",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}api.{0,20}secret.{0,20}['\"][a-zA-Z0-9]{50}['\"]"#,
        ),
        make_rule_multi(
            "twitter-bearer-token",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}bearer.{0,20}token.{0,20}['\"]AAAA[a-zA-Z0-9%]{100,}['\"]"#,
        ),
    ];

    // Consolidated: 1 rule with combined pattern
    let rules_consolidated = vec![make_rule_multi(
        "twitter-any",
        &[b"twitter", b"TWITTER"],
        r#"(?i)twitter.{0,50}(?:access.{0,20}(?:secret|token)|api.{0,20}(?:key|secret)|bearer.{0,20}token).{0,20}['\"][a-zA-Z0-9%_-]{25,}['\"]"#,
    )];

    let engine_separate = Engine::new_with_anchor_policy(
        rules_separate,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_consolidated = Engine::new_with_anchor_policy(
        rules_consolidated,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch_separate = engine_separate.new_scratch();
    let mut scratch_consolidated = engine_consolidated.new_scratch();

    // Test on keyword-heavy data
    group.bench_function("5_rules_keyword_heavy", |b| {
        b.iter(|| {
            let hits = engine_separate.scan_chunk(black_box(&keyword_heavy), &mut scratch_separate);
            black_box(hits.len())
        })
    });

    group.bench_function("1_rule_keyword_heavy", |b| {
        b.iter(|| {
            let hits = engine_consolidated
                .scan_chunk(black_box(&keyword_heavy), &mut scratch_consolidated);
            black_box(hits.len())
        })
    });

    // Test on clean ASCII
    group.bench_function("5_rules_clean", |b| {
        b.iter(|| {
            let hits = engine_separate.scan_chunk(black_box(&clean_ascii), &mut scratch_separate);
            black_box(hits.len())
        })
    });

    group.bench_function("1_rule_clean", |b| {
        b.iter(|| {
            let hits =
                engine_consolidated.scan_chunk(black_box(&clean_ascii), &mut scratch_consolidated);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Compare 14 provider-specific rules vs. 4 consolidated rules.
///
/// Extends the Twitter consolidation test to multiple providers:
/// - Twitter: 5 rules → 1 rule
/// - Discord: 3 rules → 1 rule
/// - Dropbox: 3 rules → 1 rule
/// - Mailgun: 3 rules → 1 rule
///
/// This tests whether consolidation benefits scale linearly with rule count
/// or have diminishing returns.
fn bench_multi_provider_consolidation(c: &mut Criterion) {
    let mut group = c.benchmark_group("consolidation/multi_provider");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let keyword_heavy = gen_keyword_heavy_data(BUFFER_SIZE);
    let clean_ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // Original: Each provider has its own rules with keyword anchors
    // (Simulating: 5 twitter + 3 discord + 3 dropbox + 3 mailgun = 14 rules)
    let rules_separate: Vec<RuleSpec> = vec![
        // Twitter (5 rules)
        make_rule_multi(
            "twitter-1",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "twitter-2",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}token.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "twitter-3",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}secret.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "twitter-4",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}api.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "twitter-5",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}bearer.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        // Discord (3 rules)
        make_rule_multi(
            "discord-1",
            &[b"discord", b"DISCORD"],
            r#"(?i)discord.{0,50}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "discord-2",
            &[b"discord", b"DISCORD"],
            r#"(?i)discord.{0,50}token.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "discord-3",
            &[b"discord", b"DISCORD"],
            r#"(?i)discord.{0,50}webhook.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        // Dropbox (3 rules)
        make_rule_multi(
            "dropbox-1",
            &[b"dropbox", b"DROPBOX"],
            r#"(?i)dropbox.{0,50}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "dropbox-2",
            &[b"dropbox", b"DROPBOX"],
            r#"(?i)dropbox.{0,50}token.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "dropbox-3",
            &[b"dropbox", b"DROPBOX"],
            r#"(?i)dropbox.{0,50}api.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        // Mailgun (3 rules)
        make_rule_multi(
            "mailgun-1",
            &[b"mailgun", b"MAILGUN"],
            r#"(?i)mailgun.{0,50}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "mailgun-2",
            &[b"mailgun", b"MAILGUN"],
            r#"(?i)mailgun.{0,50}key.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "mailgun-3",
            &[b"mailgun", b"MAILGUN"],
            r#"(?i)mailgun.{0,50}api.{0,20}['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
    ];

    // Consolidated: One rule per provider
    let rules_consolidated: Vec<RuleSpec> = vec![
        make_rule_multi(
            "twitter-all",
            &[b"twitter", b"TWITTER"],
            r#"(?i)twitter.{0,50}(?:token|secret|api|bearer)?['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "discord-all",
            &[b"discord", b"DISCORD"],
            r#"(?i)discord.{0,50}(?:token|webhook)?['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "dropbox-all",
            &[b"dropbox", b"DROPBOX"],
            r#"(?i)dropbox.{0,50}(?:token|api)?['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
        make_rule_multi(
            "mailgun-all",
            &[b"mailgun", b"MAILGUN"],
            r#"(?i)mailgun.{0,50}(?:key|api)?['\"][a-zA-Z0-9]{25,}['\"]"#,
        ),
    ];

    let engine_separate = Engine::new_with_anchor_policy(
        rules_separate,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_consolidated = Engine::new_with_anchor_policy(
        rules_consolidated,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch_separate = engine_separate.new_scratch();
    let mut scratch_consolidated = engine_consolidated.new_scratch();

    // Test on keyword-heavy data
    group.bench_function("14_rules_keyword_heavy", |b| {
        b.iter(|| {
            let hits = engine_separate.scan_chunk(black_box(&keyword_heavy), &mut scratch_separate);
            black_box(hits.len())
        })
    });

    group.bench_function("4_rules_keyword_heavy", |b| {
        b.iter(|| {
            let hits = engine_consolidated
                .scan_chunk(black_box(&keyword_heavy), &mut scratch_consolidated);
            black_box(hits.len())
        })
    });

    // Test on clean ASCII
    group.bench_function("14_rules_clean", |b| {
        b.iter(|| {
            let hits = engine_separate.scan_chunk(black_box(&clean_ascii), &mut scratch_separate);
            black_box(hits.len())
        })
    });

    group.bench_function("4_rules_clean", |b| {
        b.iter(|| {
            let hits =
                engine_consolidated.scan_chunk(black_box(&clean_ascii), &mut scratch_consolidated);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Anchor Diversity Impact
// ============================================================================

/// Measure how anchor prefix diversity affects Vectorscan automaton efficiency.
///
/// # Background
///
/// Vectorscan builds an Aho-Corasick automaton from all anchor patterns. When
/// patterns share prefixes, the automaton can reuse states. When patterns are
/// diverse (AKIA, ghp_, xoxb, sk_live_), more states are needed.
///
/// # Test setup
///
/// - **same_prefix**: 50 rules, all starting with "prefix_" (e.g., prefix_00,
///   prefix_01, ..., prefix_49). Maximum state sharing.
///
/// - **diverse_prefix**: 50 rules using 10 different real-world prefixes
///   (AKIA, ghp_, glpat, xoxb, sk_live, Bearer, api_key, secret, token, npm_).
///   Minimal state sharing.
///
/// # Hypothesis
///
/// Same-prefix rules should scan faster because:
/// 1. Smaller automaton fits better in cache
/// 2. Fewer state transitions per byte
/// 3. Better branch prediction for common prefix path
///
/// # Implications
///
/// If diverse is significantly slower (>20%), consider:
/// - Grouping rules by prefix family in separate engines
/// - Prioritizing longer, more specific anchors to reduce total patterns
fn bench_anchor_diversity(c: &mut Criterion) {
    let mut group = c.benchmark_group("diversity");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(30);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let clean_ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // Best case: all 50 rules share 7-char prefix "prefix_"
    let rules_same_prefix: Vec<RuleSpec> = (0..50)
        .map(|i| {
            let suffix = format!("{i:02}");
            let anchor_str = format!("prefix_{suffix}");
            let anchor: &'static [u8] =
                Box::leak(anchor_str.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            RuleSpec {
                name: Box::leak(format!("same_prefix_{i}").into_boxed_str()),
                anchors,
                radius: 64,
                validator: ValidatorKind::None,
                two_phase: None,
                must_contain: None,
                keywords_any: Some(anchors),
                value_suppressors_any: None,
                entropy: None,
                char_class: None,
                local_context: None,
                secret_group: None,
                min_confidence: None,
                offline_validation: None,
                uuid_format_secret: false,
                re: regex::bytes::Regex::new(&format!(r"{anchor_str}[A-Za-z0-9]{{20}}")).unwrap(),
            }
        })
        .collect();

    // Worst case: 10 different real-world prefixes with no common chars
    let prefixes = [
        "AKIA", "ghp_", "glpat", "xoxb", "sk_live", "Bearer", "api_key", "secret", "token", "npm_",
    ];
    let rules_diverse: Vec<RuleSpec> = (0..50)
        .map(|i| {
            let base = prefixes[i % prefixes.len()];
            let anchor_str = format!("{base}{:02}", i / prefixes.len());
            let anchor: &'static [u8] =
                Box::leak(anchor_str.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            RuleSpec {
                name: Box::leak(format!("diverse_{i}").into_boxed_str()),
                anchors,
                radius: 64,
                validator: ValidatorKind::None,
                two_phase: None,
                must_contain: None,
                keywords_any: Some(anchors),
                value_suppressors_any: None,
                entropy: None,
                char_class: None,
                local_context: None,
                secret_group: None,
                min_confidence: None,
                offline_validation: None,
                uuid_format_secret: false,
                re: regex::bytes::Regex::new(&format!(r"{anchor_str}[A-Za-z0-9]{{20}}")).unwrap(),
            }
        })
        .collect();

    let engine_same = Engine::new_with_anchor_policy(
        rules_same_prefix,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let engine_diverse = Engine::new_with_anchor_policy(
        rules_diverse,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );

    let mut scratch_same = engine_same.new_scratch();
    let mut scratch_diverse = engine_diverse.new_scratch();

    group.bench_function("50_rules_same_prefix", |b| {
        b.iter(|| {
            let hits = engine_same.scan_chunk(black_box(&clean_ascii), &mut scratch_same);
            black_box(hits.len())
        })
    });

    group.bench_function("50_rules_diverse_prefix", |b| {
        b.iter(|| {
            let hits = engine_diverse.scan_chunk(black_box(&clean_ascii), &mut scratch_diverse);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Main
// ============================================================================

criterion_group!(
    benches,
    bench_jwt_anchor_length,
    bench_sk_anchor_length,
    bench_keyword_consolidation,
    bench_multi_provider_consolidation,
    bench_anchor_diversity,
);

criterion_main!(benches);
