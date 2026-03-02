//! Property-based soundness tests for the secret-bytes safelist.
//!
//! Verifies the critical invariant: no high-entropy random byte string
//! (>4.0 bits/byte, length 10–150) ever triggers the secret-bytes safelist
//! when used as a secret value. Real secrets must not be suppressed.
//!
//! Tests use the full engine pipeline to exercise the exact code path that
//! production scans take.

use proptest::prelude::*;
use regex::bytes::Regex;
use scanner_engine::{AnchorPolicy, Engine, Finding, RuleSpec, ValidatorKind, demo_tuning};

fn scan_findings(engine: &Engine, hay: &[u8]) -> Vec<Finding> {
    let mut scratch = engine.new_scratch();
    let mut out = Vec::with_capacity(16);
    engine.scan_chunk_materialized(hay, &mut scratch, &mut out);
    out
}

fn lcg(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

/// Shannon entropy in bits per byte.
fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    /// No high-entropy random string (>4.0 bits/byte, length 10–150) should
    /// be suppressed by the secret-bytes safelist when extracted as a secret
    /// value through the full engine pipeline.
    #[test]
    fn high_entropy_secret_never_suppressed(
        secret_len in 10usize..=80,
        seed in any::<u64>(),
    ) {
        // Generate random printable ASCII secret using LCG.
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let mut rng = seed;
        let secret: Vec<u8> = (0..secret_len)
            .map(|_| {
                let v = lcg(&mut rng);
                alphabet[(v >> 33) as usize % alphabet.len()]
            })
            .collect();

        let entropy = shannon_entropy(&secret);
        // Only test high-entropy strings — low-entropy might legitimately
        // contain placeholder patterns.
        prop_assume!(entropy > 4.0);

        let secret_str = std::str::from_utf8(&secret).unwrap();
        // Ensure the secret doesn't coincidentally contain safelist patterns.
        // The property test is about high-entropy secrets, and the probability
        // of a random high-entropy string containing "hunter2", "changeme",
        // "EXAMPLE", etc. is vanishingly small — but filter them out to avoid
        // flaky test failures.
        prop_assume!(!secret_str.contains("hunter2") && !secret_str.contains("HUNTER2"));
        prop_assume!(!secret_str.contains("changeme") && !secret_str.contains("CHANGEME"));
        prop_assume!(!secret_str.contains("EXAMPLE"));
        prop_assume!(!secret_str.contains("placeholder") && !secret_str.contains("PLACEHOLDER"));
        prop_assume!(!secret_str.contains("0123456789"));
        prop_assume!(!secret_str.to_ascii_lowercase().contains("abcdefghij"));

        // Build an engine with a rule that extracts the secret via capture group.
        let re_pattern = format!(r"SEC_([A-Za-z0-9]{{{secret_len}}})");
        let rule = RuleSpec {
            name: "proptest-secret-bytes",
            anchors: &[b"SEC_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(&re_pattern).unwrap(),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hay = format!("prefix SEC_{secret_str} suffix");
        let hits = scan_findings(&engine, hay.as_bytes());
        prop_assert!(
            hits.iter().any(|h| h.rule == "proptest-secret-bytes"),
            "high-entropy secret (entropy={:.2}, len={}) should NOT be suppressed \
             by secret-bytes safelist: {:?}",
            entropy,
            secret_len,
            &secret_str[..secret_str.len().min(40)]
        );
    }

    /// Composite secrets built from random alphanumeric segments joined by
    /// hyphens and dots must never be suppressed, even when individual
    /// segments happen to match placeholder words. The `^...$` anchoring
    /// on SECRET_BYTES_PATTERNS prevents this.
    #[test]
    fn composite_secret_with_separators_never_suppressed(
        segment_count in 2usize..=5,
        segment_len in 4usize..=10,
        seed in any::<u64>(),
    ) {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        let separators = b"-.";
        let mut rng = seed;

        // Build composite secret: seg1-seg2.seg3-seg4
        let mut secret = Vec::with_capacity(segment_count * (segment_len + 1));
        for i in 0..segment_count {
            if i > 0 {
                let sep = separators[(lcg(&mut rng) >> 33) as usize % separators.len()];
                secret.push(sep);
            }
            for _ in 0..segment_len {
                let v = lcg(&mut rng);
                secret.push(alphabet[(v >> 33) as usize % alphabet.len()]);
            }
        }

        let entropy = shannon_entropy(&secret);
        // Lower threshold than the main test because separators reduce entropy.
        prop_assume!(entropy > 3.5);

        let secret_str = std::str::from_utf8(&secret).unwrap();

        // Filter out secrets that match UUID format (8-4-4-4-12 hex with
        // hyphens at positions 8, 13, 18, 23). These are now suppressed by
        // the UUID quick-reject filter.
        prop_assume!(secret.len() != 36 || secret[8] != b'-' || secret[13] != b'-');

        // Filter out secrets that are exact placeholder matches (the only
        // cases the anchored patterns should catch). With segment_count >= 2
        // and separators, this is practically impossible for length 10+.
        let lower = secret_str.to_ascii_lowercase();
        prop_assume!(lower != "null" && lower != "changeme" && lower != "todo" && lower != "fixme");
        prop_assume!(lower != "hunter2");
        prop_assume!(lower != "0123456789" && lower != "abcdefghij");
        prop_assume!(!secret_str.contains("EXAMPLE"));

        // Regex matches the composite secret including hyphens and dots.
        let total_len = secret.len();
        let re_pattern = format!(r"SEC_([A-Za-z0-9.\-]{{{total_len}}})");
        let rule = RuleSpec {
            name: "proptest-composite-secret",
            anchors: &[b"SEC_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(&re_pattern).unwrap(),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hay = format!("prefix SEC_{secret_str} suffix");
        let hits = scan_findings(&engine, hay.as_bytes());
        prop_assert!(
            hits.iter().any(|h| h.rule == "proptest-composite-secret"),
            "composite secret (entropy={:.2}, len={}, segments={}) should NOT be \
             suppressed by secret-bytes safelist: {:?}",
            entropy,
            total_len,
            segment_count,
            &secret_str[..secret_str.len().min(40)]
        );
    }

    /// The `uuid_format_secret` flag prevents UUID-format values from being
    /// suppressed. Rules that intentionally capture UUID-format secrets
    /// (e.g., Heroku, Snyk API keys) set this flag.
    #[test]
    fn uuid_format_secret_flag_prevents_suppression(
        seed in any::<u64>(),
    ) {
        // Generate a random valid UUID (8-4-4-4-12 hex).
        let hex_chars = b"0123456789abcdef";
        let mut rng = seed;
        let mut uuid = Vec::with_capacity(36);
        for i in 0..36 {
            if i == 8 || i == 13 || i == 18 || i == 23 {
                uuid.push(b'-');
            } else {
                let v = lcg(&mut rng);
                uuid.push(hex_chars[(v >> 33) as usize % hex_chars.len()]);
            }
        }
        let uuid_str = std::str::from_utf8(&uuid).unwrap();

        // Rule WITHOUT the flag: UUID should be suppressed.
        let re_pattern = r"SEC_([0-9a-f\-]{36})";
        let rule_without = RuleSpec {
            name: "proptest-uuid-no-flag",
            anchors: &[b"SEC_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(re_pattern).unwrap(),
        };

        let engine_without = Engine::new_with_anchor_policy(
            vec![rule_without],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hay = format!("prefix SEC_{uuid_str} suffix");
        let hits_without = scan_findings(&engine_without, hay.as_bytes());
        prop_assert!(
            !hits_without.iter().any(|h| h.rule == "proptest-uuid-no-flag"),
            "UUID-format value should be suppressed when uuid_format_secret=false: {uuid_str}"
        );

        // Rule WITH the flag: UUID should NOT be suppressed.
        let rule_with = RuleSpec {
            name: "proptest-uuid-with-flag",
            anchors: &[b"SEC_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: None,
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: true,
            re: Regex::new(re_pattern).unwrap(),
        };

        let engine_with = Engine::new_with_anchor_policy(
            vec![rule_with],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hits_with = scan_findings(&engine_with, hay.as_bytes());
        prop_assert!(
            hits_with.iter().any(|h| h.rule == "proptest-uuid-with-flag"),
            "UUID-format value should NOT be suppressed when uuid_format_secret=true: {uuid_str}"
        );
    }
}
