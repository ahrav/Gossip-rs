//! Rule Scaling Analysis
//!
//! Measures how scanner throughput degrades as rule count grows, and identifies
//! optimization opportunities in rule design.
//!
//! # Problem Statement
//!
//! Secret scanners must balance detection coverage (more rules) against throughput.
//! Vectorscan (the underlying multi-pattern matcher) has sub-linear scaling—adding
//! rules doesn't linearly increase scan time—but there are inflection points where
//! performance cliffs occur. This benchmark quantifies those trade-offs.
//!
//! # Questions Answered
//!
//! 1. **Cost per rule**: How much throughput do we lose per additional rule?
//!    Helps decide whether to add new detection rules or optimize existing ones.
//!
//! 2. **UTF-16 impact**: UTF-16 variants add LE and BE copies of every anchor
//!    (tripling the prefilter pattern count). When is this cost justified
//!    vs. scanning only UTF-8?
//!
//! 3. **Inflection points**: At what rule counts does Vectorscan's automaton
//!    become less efficient (state explosion, cache pressure)?
//!
//! 4. **Grouping benefits**: Can rules with shared prefixes (e.g., all GitHub
//!    patterns share `gh*`) be grouped to reduce automaton complexity?
//!
//! # Benchmark Groups
//!
//! - **diagnostics**: Prints engine statistics without heavy benchmarking. Use to
//!   inspect automaton composition (manual vs. derived anchors, UTF-16 DB size).
//!
//! - **scaling/unique_rules**: Measures throughput from 1 to 250 rules, each with
//!   a unique 4-character anchor. Shows raw scaling behavior.
//!
//! - **scaling/grouped_vs_unique**: Compares rules with shared prefixes (grouped)
//!   vs. completely distinct prefixes (unique). Tests whether Vectorscan's
//!   Aho-Corasick automaton shares states for common prefixes.
//!
//! - **scaling/utf16_impact**: Measures overhead of enabling UTF-16 variant
//!   scanning on ASCII data (where UTF-16 patterns won't match).
//!
//! # Running
//!
//! ```bash
//! # Run all benchmarks
//! cargo bench --bench rule_scaling
//!
//! # Print diagnostics only (fast, no benchmarking)
//! cargo bench --bench rule_scaling -- diagnostics
//!
//! # Run scaling benchmarks only
//! cargo bench --bench rule_scaling -- scaling
//! ```
//!
//! # Interpreting Results
//!
//! - **GB/s throughput**: Higher is better. Compare against memory bandwidth
//!   ceiling from `memory_bandwidth` benchmark.
//!
//! - **Cost per rule**: Compute `(1/throughput_N - 1/throughput_1) / (N-1)` to
//!   estimate marginal cost of each additional rule.
//!
//! - **UTF-16 overhead**: If UTF-16 ON is >2x slower than OFF on ASCII data,
//!   the extra patterns are hurting cache efficiency even when not matching.

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use scanner_engine::{
    AnchorPolicy, Engine, EntropySpec, RuleSpec, Tuning, ValidatorKind, demo_tuning,
};

// ============================================================================
// Configuration
// ============================================================================

/// Buffer size for all scaling benchmarks.
///
/// 4 MiB is large enough to amortize per-scan overhead and measure steady-state
/// throughput, but small enough that even slow configurations complete quickly.
/// All benchmark functions share this constant so that throughput numbers are
/// directly comparable across groups.
const BUFFER_SIZE: usize = 4 * 1024 * 1024;

// ============================================================================
// Data Generation
// ============================================================================

/// Generate pseudo-random lowercase ASCII text with 80-character lines.
///
/// This represents "clean" data with no secrets—the best case for Vectorscan
/// because zero anchor callbacks fire. This isolates Vectorscan's raw
/// scanning speed from post-match validation overhead. The xorshift PRNG
/// ensures deterministic output for reproducible benchmarks.
///
/// # Why lowercase only?
///
/// Anchors in `generate_unique_rules` use uppercase (AAAA-ZZZZ), so lowercase
/// data guarantees zero false candidates. This isolates Vectorscan's raw
/// scanning speed from post-match validation overhead.
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

// ============================================================================
// Rule Generators
// ============================================================================
//
// All generators use `Box::leak` to convert owned Strings into `&'static` references.
// This is intentional: `RuleSpec` requires `'static` lifetimes for its anchor and
// name slices (the production path uses compile-time constants), and benchmarks
// run once then exit, so the leaked memory is reclaimed by the OS at process exit.
// Do not use this pattern in library code.

/// Generate N rules with unique, non-overlapping 4-character anchors (AAAA-ZZZZ).
///
/// Each rule has a distinct uppercase prefix that won't match other rules or
/// the lowercase test data. This provides the purest scaling measurement:
/// Vectorscan must maintain N separate automaton paths with no prefix sharing.
///
/// # Anchor encoding
///
/// Uses base-26 encoding: rule 0 = "AAAA", rule 1 = "AAAB", ..., rule 456975 = "ZZZZ".
/// This supports up to 26^4 = 456,976 unique rules without collision.
///
/// # Why 4 characters?
///
/// - 2-3 chars: Too short, causes false candidates in real data
/// - 4 chars: Good balance—specific enough to filter well, short enough to
///   stress Vectorscan's state machine with many patterns
/// - 8+ chars: Unrealistic; most real anchors (AKIA, ghp_, etc.) are 3-8 chars
///
/// # Wrapping behavior
///
/// If `count` exceeds 456,976 (26^4), anchors wrap around and collide.
/// This is acceptable for benchmark purposes since the tested range
/// (up to 250 rules) is well within the unique address space.
fn generate_unique_rules(count: usize) -> Vec<RuleSpec> {
    (0..count)
        .map(|i| {
            // Base-26 encode `i` into a 4-character uppercase string.
            let prefix = format!(
                "{}{}{}{}",
                (b'A' + ((i / (26 * 26 * 26)) % 26) as u8) as char,
                (b'A' + ((i / (26 * 26)) % 26) as u8) as char,
                (b'A' + ((i / 26) % 26) as u8) as char,
                (b'A' + (i % 26) as u8) as char,
            );
            let anchor: &'static [u8] = Box::leak(prefix.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            RuleSpec {
                name: Box::leak(format!("rule_{i:04}").into_boxed_str()),
                anchors,
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
                re: regex::bytes::Regex::new(&format!(r"{prefix}[A-Z0-9]{{16}}")).unwrap(),
            }
        })
        .collect()
}

/// Generate N rules organized into groups that share a common 2-character prefix.
///
/// Simulates real-world scenarios where related secrets share prefixes:
/// - GitHub: `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` (5 rules, shared "gh" prefix)
/// - Stripe: `sk_live_`, `sk_test_`, `pk_live_`, `rk_live_` (4 rules, shared "sk"/"pk"/"rk")
///
/// # Hypothesis
///
/// Vectorscan's Aho-Corasick automaton can share prefix states, so 100 rules
/// in 10 groups should be faster than 100 rules with unique prefixes. This
/// benchmark tests that hypothesis.
///
/// # Parameters
///
/// - `count`: Total number of rules to generate
/// - `group_size`: Rules per group (e.g., 10 = 10 groups of 10 for count=100)
///
/// # Anchor structure
///
/// - Group prefix: 2 chars based on group number (AA, AB, AC, ...)
/// - Rule suffix: 2 chars based on global rule index (not per-group index)
/// - Full anchor: 4 chars (e.g., "AAAB" = group 0, rule 1)
///
/// # Note
///
/// When `count` is not evenly divisible by `group_size`, the last group is smaller.
/// This is fine for benchmarking purposes since the automaton sees the same total
/// number of patterns regardless.
fn generate_grouped_rules(count: usize, group_size: usize) -> Vec<RuleSpec> {
    (0..count)
        .map(|i| {
            let group = i / group_size;
            // All rules in a group share the same 2-char prefix
            let group_prefix = format!(
                "{}{}",
                (b'A' + ((group / 26) % 26) as u8) as char,
                (b'A' + (group % 26) as u8) as char,
            );
            // But have unique suffixes
            let suffix = format!(
                "{}{}",
                (b'A' + ((i / 26) % 26) as u8) as char,
                (b'A' + (i % 26) as u8) as char,
            );
            let full = format!("{group_prefix}{suffix}");
            let anchor: &'static [u8] = Box::leak(full.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            RuleSpec {
                name: Box::leak(format!("grouped_{i:04}").into_boxed_str()),
                anchors,
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
                re: regex::bytes::Regex::new(&format!(r"{full}[A-Z0-9]{{16}}")).unwrap(),
            }
        })
        .collect()
}

/// Generate rules mimicking real gitleaks patterns with diverse, production-like anchors.
///
/// Uses actual secret prefixes from popular services (AWS, GitHub, Stripe, etc.)
/// to measure scaling behavior that matches real-world rule sets. Key differences
/// from synthetic rules:
///
/// - **Variable base prefix lengths**: 4-11 characters (AKIA=4, ssh-ed25519=11),
///   plus a 3-character unique suffix making actual anchors 7-14 characters
/// - **Character diversity**: Underscores, hyphens, mixed case (not just uppercase)
/// - **Entropy requirements**: 1/3 of rules require minimum entropy, adding
///   post-match validation overhead
/// - **Keywords enabled**: Rules use `keywords_any` for early filtering
///
/// # Why this matters
///
/// Synthetic rules with uniform 4-char anchors may not reflect real performance.
/// This generator produces the anchor distribution found in gitleaks ~200 rules,
/// revealing how Vectorscan handles heterogeneous pattern sets.
fn generate_realistic_rules(count: usize) -> Vec<RuleSpec> {
    // Common secret prefixes found in real rules—covers major cloud providers,
    // SaaS platforms, and generic credential patterns
    let prefixes = [
        "AKIA",        // AWS
        "ghp_",        // GitHub
        "gho_",        // GitHub OAuth
        "ghu_",        // GitHub User
        "ghs_",        // GitHub Server
        "ghr_",        // GitHub Refresh
        "glpat-",      // GitLab
        "xoxb-",       // Slack bot
        "xoxp-",       // Slack user
        "xoxa-",       // Slack app
        "sk_live_",    // Stripe
        "sk_test_",    // Stripe test
        "pk_live_",    // Stripe public
        "rk_live_",    // Stripe restricted
        "Bearer",      // Generic auth
        "Basic",       // Basic auth
        "api_key",     // Generic
        "apikey",      // Generic
        "secret",      // Generic
        "password",    // Generic
        "token",       // Generic
        "credential",  // Generic
        "private_key", // Generic
        "PRIVATE",     // PEM
        "BEGIN",       // PEM
        "ssh-rsa",     // SSH
        "ssh-ed25519", // SSH
        "AIza",        // Google
        "SG.",         // SendGrid
        "npm_",        // NPM
        "pypi-",       // PyPI
    ];

    (0..count)
        .map(|i| {
            let base_prefix = prefixes[i % prefixes.len()];
            // Add a unique suffix to each
            let unique_suffix = format!("{:03}", i / prefixes.len());
            let full_prefix = format!("{base_prefix}{unique_suffix}");

            let anchor: &'static [u8] =
                Box::leak(full_prefix.clone().into_bytes().into_boxed_slice());
            let anchors: &'static [&'static [u8]] = Box::leak(Box::new([anchor]));

            // Every third rule gets an entropy gate, simulating production rules
            // that require high-entropy secret values (e.g., AWS keys, API tokens).
            let entropy = if i % 3 == 0 {
                Some(EntropySpec {
                    min_bits_per_byte: 3.5,
                    min_len: 16,
                    max_len: 256,
                    min_entropy_bits_per_byte: None,
                    digit_penalty: false,
                })
            } else {
                None
            };

            RuleSpec {
                name: Box::leak(format!("realistic_{i:04}").into_boxed_str()),
                anchors,
                radius: 128,
                validator: ValidatorKind::None,
                two_phase: None,
                must_contain: None,
                keywords_any: Some(anchors),
                value_suppressors_any: None,
                entropy,
                char_class: None,
                local_context: None,
                secret_group: None,
                min_confidence: None,
                offline_validation: None,
                uuid_format_secret: false,
                re: regex::bytes::Regex::new(&format!(r"{full_prefix}[A-Za-z0-9_-]{{20,40}}"))
                    .unwrap(),
            }
        })
        .collect()
}

// ============================================================================
// Diagnostics
// ============================================================================

/// Print engine statistics to stderr for manual inspection.
///
/// Requires `--features stats` to see detailed metrics. Without the feature,
/// only rule count is printed.
///
/// # Metrics (with `stats` feature)
///
/// - **Manual anchors**: Rules with explicit anchor patterns in `RuleSpec.anchors`
/// - **Derived anchors**: Anchors extracted automatically from regex prefixes
/// - **Residue rules**: Rules that couldn't derive anchors (gated by weaker
///   heuristics like run-length or k-gram checks instead of Vectorscan patterns)
/// - **Unfilterable**: Rules where no filtering is possible (expensive!)
/// - **DB built**: Whether a Vectorscan database was compiled
/// - **UTF-16 DB built**: Whether a separate UTF-16 variant DB exists
#[allow(unused_variables)]
fn print_engine_diagnostics(name: &str, engine: &Engine, rule_count: usize) {
    #[cfg(feature = "stats")]
    {
        let stats = engine.anchor_plan_stats();
        let vs_stats = engine.vectorscan_stats();
        eprintln!("=== {name} ({rule_count} rules) ===");
        eprintln!("  Anchor plan:");
        eprintln!("    Manual anchors: {}", stats.manual_rules);
        eprintln!("    Derived anchors: {}", stats.derived_rules);
        eprintln!("    Residue rules: {}", stats.residue_rules);
        eprintln!("    Unfilterable: {}", stats.unfilterable_rules);
        eprintln!("  Vectorscan:");
        eprintln!("    DB built: {}", vs_stats.db_built);
        eprintln!("    UTF-16 DB built: {}", vs_stats.utf16_db_built);
    }
    #[cfg(not(feature = "stats"))]
    {
        eprintln!("=== {name} ({rule_count} rules) ===");
        eprintln!("  (Enable 'stats' feature for detailed diagnostics)");
    }
}

/// Print engine composition statistics without heavy benchmarking.
///
/// Use this to understand how rules are classified before running timing
/// benchmarks. Helps answer: "Why is my engine slow?"—often the answer is
/// too many residue/unfilterable rules or unexpected UTF-16 DB creation.
///
/// Compares three engine configurations:
/// 1. The full gitleaks rule set with derived anchors
/// 2. 100 realistic rules with UTF-16 scanning enabled
/// 3. 100 realistic rules with UTF-16 scanning disabled
///
/// Output goes to stderr so it does not interfere with criterion's JSON output.
fn bench_diagnostics(c: &mut Criterion) {
    let mut group = c.benchmark_group("diagnostics");
    // Minimal samples—this group exists for its diagnostic side effects (eprintln),
    // not for timing precision.
    group.sample_size(10);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: true,
        ..demo_tuning()
    };

    let tuning_no_utf16 = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    eprintln!("\n========== ENGINE DIAGNOSTICS ==========\n");

    // Full gitleaks engine
    let gitleaks =
        scanner_engine::demo_engine_with_anchor_mode(scanner_engine::AnchorMode::Derived);
    let gitleaks_rule_count = scanner_engine::demo_rules().len();
    print_engine_diagnostics("Gitleaks (derived)", &gitleaks, gitleaks_rule_count);

    // Compare UTF-16 enabled vs disabled
    let rules_100 = generate_realistic_rules(100);

    let engine_utf16 = Engine::new_with_anchor_policy(
        rules_100.clone(),
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    print_engine_diagnostics("100 realistic (UTF-16 ON)", &engine_utf16, 100);

    let engine_no_utf16 = Engine::new_with_anchor_policy(
        rules_100.clone(),
        vec![],
        tuning_no_utf16.clone(),
        AnchorPolicy::ManualOnly,
    );
    print_engine_diagnostics("100 realistic (UTF-16 OFF)", &engine_no_utf16, 100);

    eprintln!("\n=========================================\n");

    group.finish();
}

// ============================================================================
// Scaling Benchmarks
// ============================================================================

/// Measure throughput as rule count increases from 1 to 250.
///
/// Uses unique 4-character anchors to isolate pure scaling behavior—no prefix
/// sharing, no entropy checks, no transforms. This is the "worst case" for
/// automaton complexity: each rule adds independent states.
///
/// # Expected results
///
/// - 1-25 rules: Near memory bandwidth ceiling (7+ GB/s)
/// - 25-100 rules: Gradual decline as automaton grows
/// - 100-250 rules: Watch for inflection points where cache pressure spikes
///
/// # Trade-off insight
///
/// Use this data to set rule count budgets. If throughput at 200 rules is 50%
/// of 100 rules, consider consolidating patterns or splitting into rule tiers.
fn bench_rule_scaling(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/unique_rules");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(20);

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    // Disable UTF-16 and transforms to isolate Vectorscan automaton scaling
    // from orthogonal costs (transform decoding, secondary DB scan).
    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    // Progression from trivial (1 rule) to beyond-gitleaks scale (250 rules).
    // The gitleaks rule set has ~200 rules, so this range brackets production.
    let rule_counts = [1, 5, 10, 25, 50, 100, 150, 200, 250];

    for &count in &rule_counts {
        let rules = generate_unique_rules(count);
        let engine =
            Engine::new_with_anchor_policy(rules, vec![], tuning.clone(), AnchorPolicy::ManualOnly);
        let mut scratch = engine.new_scratch();

        group.bench_with_input(BenchmarkId::from_parameter(count), &ascii, |b, data| {
            b.iter(|| {
                let hits = engine.scan_chunk(black_box(data), &mut scratch);
                black_box(hits.len())
            })
        });
    }

    group.finish();
}

/// Compare automaton efficiency for grouped vs. unique anchor prefixes.
///
/// # Hypothesis
///
/// Aho-Corasick automatons share prefix states. Given 100 rules:
/// - **Unique**: 100 independent 4-char paths = more states
/// - **Grouped 10x10**: 10 groups share 2-char prefixes = fewer states
/// - **Grouped 5x20**: 5 groups share 2-char prefixes = even fewer states
///
/// If this hypothesis holds, grouped patterns should scan faster because:
/// 1. Smaller automaton fits better in L2/L3 cache
/// 2. Fewer state transitions per input byte
///
/// # Realistic comparison
///
/// Also includes `100_realistic` using production-like anchors to show how
/// natural prefix diversity (AKIA, ghp_, xoxb, etc.) performs vs. synthetic.
///
/// # Decision guidance
///
/// If grouped is significantly faster, consider reorganizing rules by provider
/// prefix families rather than by secret type.
fn bench_grouped_vs_unique(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/grouped_vs_unique");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(20);

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    let tuning = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };

    let count = 100;

    // Baseline: 100 rules with completely distinct prefixes.
    // No prefix sharing possible—worst case for automaton state count.
    let unique_rules = generate_unique_rules(count);
    let unique_engine = Engine::new_with_anchor_policy(
        unique_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut unique_scratch = unique_engine.new_scratch();

    group.bench_function("100_unique", |b| {
        b.iter(|| {
            let hits = unique_engine.scan_chunk(black_box(&ascii), &mut unique_scratch);
            black_box(hits.len())
        })
    });

    // 10 groups of 10: moderate prefix sharing (2-char shared prefix per group)
    let grouped_rules = generate_grouped_rules(count, 10);
    let grouped_engine = Engine::new_with_anchor_policy(
        grouped_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut grouped_scratch = grouped_engine.new_scratch();

    group.bench_function("100_grouped_10x10", |b| {
        b.iter(|| {
            let hits = grouped_engine.scan_chunk(black_box(&ascii), &mut grouped_scratch);
            black_box(hits.len())
        })
    });

    // 5 groups of 20: more aggressive prefix sharing (fewer unique prefixes)
    let grouped_rules_5x20 = generate_grouped_rules(count, 20);
    let grouped_engine_5x20 = Engine::new_with_anchor_policy(
        grouped_rules_5x20,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut grouped_scratch_5x20 = grouped_engine_5x20.new_scratch();

    group.bench_function("100_grouped_5x20", |b| {
        b.iter(|| {
            let hits = grouped_engine_5x20.scan_chunk(black_box(&ascii), &mut grouped_scratch_5x20);
            black_box(hits.len())
        })
    });

    // Production-like prefix diversity (AKIA, ghp_, xoxb, etc.) — the natural
    // grouping that emerges from real cloud-provider secret formats.
    let realistic_rules = generate_realistic_rules(count);
    let realistic_engine = Engine::new_with_anchor_policy(
        realistic_rules,
        vec![],
        tuning.clone(),
        AnchorPolicy::ManualOnly,
    );
    let mut realistic_scratch = realistic_engine.new_scratch();

    group.bench_function("100_realistic", |b| {
        b.iter(|| {
            let hits = realistic_engine.scan_chunk(black_box(&ascii), &mut realistic_scratch);
            black_box(hits.len())
        })
    });

    group.finish();
}

/// Measure the throughput cost of enabling UTF-16 variant scanning.
///
/// # Background
///
/// Some secrets appear in UTF-16 encoded files (e.g., Windows resources, certain
/// config formats). When `scan_utf16_variants` is enabled, the engine scans a
/// second Vectorscan database at runtime (UTF-16 LE/BE variants of all anchors).
/// The database is always compiled at construction time; the flag controls whether
/// it is used during scanning.
///
/// # Trade-off
///
/// - **Benefit**: Detect secrets in UTF-16 files without preprocessing
/// - **Cost**: ~3x total prefilter pattern count (raw + LE + BE), larger
///   automaton, more cache pressure
///
/// # Test methodology
///
/// Scans ASCII data (where UTF-16 patterns never match) to measure pure
/// overhead. Real-world impact is lower if UTF-16 files are rare, but this
/// shows the worst-case cost for UTF-8 content.
///
/// # Decision guidance
///
/// - If UTF-16 OFF is >2x faster: Consider UTF-16 as an optional mode
/// - If difference is <20%: Automaton is small enough that extra patterns
///   fit in cache; safe to enable by default
fn bench_utf16_impact(c: &mut Criterion) {
    let mut group = c.benchmark_group("scaling/utf16_impact");
    group.throughput(Throughput::Bytes(BUFFER_SIZE as u64));
    group.sample_size(20);

    let ascii = gen_clean_ascii(BUFFER_SIZE, 0x1234);

    let rules = generate_realistic_rules(100);

    // Baseline: `scan_utf16_variants = false` — the prefilter DB still contains
    // UTF-16 patterns, but the separate UTF-16 anchor DB scan is skipped at runtime.
    let tuning_no_utf16 = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: false,
        ..demo_tuning()
    };
    let engine_no_utf16 = Engine::new_with_anchor_policy(
        rules.clone(),
        vec![],
        tuning_no_utf16,
        AnchorPolicy::ManualOnly,
    );
    let mut scratch_no_utf16 = engine_no_utf16.new_scratch();

    group.bench_function("100_rules_utf16_off", |b| {
        b.iter(|| {
            let hits = engine_no_utf16.scan_chunk(black_box(&ascii), &mut scratch_no_utf16);
            black_box(hits.len())
        })
    });

    // UTF-16 enabled — the engine compiles a second Vectorscan database with
    // LE and BE variants of every anchor, then scans both databases per chunk.
    let tuning_utf16 = Tuning {
        max_transform_depth: 0,
        scan_utf16_variants: true,
        ..demo_tuning()
    };
    let engine_utf16 = Engine::new_with_anchor_policy(
        rules.clone(),
        vec![],
        tuning_utf16,
        AnchorPolicy::ManualOnly,
    );
    let mut scratch_utf16 = engine_utf16.new_scratch();

    group.bench_function("100_rules_utf16_on", |b| {
        b.iter(|| {
            let hits = engine_utf16.scan_chunk(black_box(&ascii), &mut scratch_utf16);
            black_box(hits.len())
        })
    });

    group.finish();
}

// ============================================================================
// Criterion Groups
// ============================================================================
//
// Two groups so that diagnostics (fast, side-effect–driven) can be run
// independently from timing benchmarks (slower, throughput-driven).
// Use `cargo bench --bench rule_scaling -- diagnostics` or `-- scaling`
// to select one group.

criterion_group!(diagnostic_benches, bench_diagnostics,);

criterion_group!(
    scaling_benches,
    bench_rule_scaling,
    bench_grouped_vs_unique,
    bench_utf16_impact,
);

criterion_main!(diagnostic_benches, scaling_benches,);
