//! Property-based soundness tests for the value suppressor gate.
//!
//! These tests verify two critical invariants:
//! 1. A suppressor NEVER filters a secret that doesn't contain any suppressor pattern.
//! 2. A suppressor ALWAYS filters a secret that contains a suppressor pattern.

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

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn suppressor_never_suppresses_non_matching_secret(
        suppressor_count in 1usize..=5,
        seed in any::<u64>(),
        secret_len in 10usize..=30,
    ) {
        // Generate random suppressor patterns (2-8 bytes, uppercase + digits).
        let sup_alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = seed;

        let mut suppressors: Vec<Vec<u8>> = Vec::new();
        for _ in 0..suppressor_count {
            let len = 2 + (lcg(&mut rng) % 7) as usize; // 2..8
            let pat: Vec<u8> = (0..len)
                .map(|_| sup_alphabet[(lcg(&mut rng) % sup_alphabet.len() as u64) as usize])
                .collect();
            suppressors.push(pat);
        }

        // Generate a random secret (lowercase + digits) that cannot contain uppercase suppressors.
        let secret_alphabet = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let secret: Vec<u8> = (0..secret_len)
            .map(|_| secret_alphabet[(lcg(&mut rng) % secret_alphabet.len() as u64) as usize])
            .collect();

        let secret_str = std::str::from_utf8(&secret).unwrap();
        // Suppressors are uppercase; secrets are lowercase. Only digit-only suppressors
        // could match, so filter those out.
        for sup in &suppressors {
            let sup_str = std::str::from_utf8(sup).unwrap();
            prop_assume!(!secret_str.contains(sup_str));
        }

        // Leak to get 'static lifetime for test purposes.
        let sup_static: &'static [&'static [u8]] = Box::leak(
            suppressors.iter().map(|s| {
                let leaked: &'static [u8] = Box::leak(s.clone().into_boxed_slice());
                leaked
            }).collect::<Vec<&'static [u8]>>().into_boxed_slice()
        );

        let rule = RuleSpec {
            name: "proptest-no-suppress",
            anchors: &[b"TOK_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: Some(sup_static),
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(r"TOK_([A-Za-z0-9]{10,30})").unwrap(),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hay = format!("prefix TOK_{secret_str} suffix");
        let hits = scan_findings(&engine, hay.as_bytes());
        prop_assert!(
            hits.iter().any(|h| h.rule == "proptest-no-suppress"),
            "secret '{}' should not be suppressed by {:?}",
            secret_str,
            suppressors.iter().map(|s| String::from_utf8_lossy(s).to_string()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn suppressor_always_suppresses_matching_secret(
        sup_len in 3usize..=8,
        prefix_len in 0usize..=10,
        suffix_len in 0usize..=10,
        seed in any::<u64>(),
    ) {
        let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut rng = seed;

        // Generate a random suppressor pattern.
        let suppressor: Vec<u8> = (0..sup_len)
            .map(|_| alphabet[(lcg(&mut rng) % alphabet.len() as u64) as usize])
            .collect();

        // Build secret = prefix + suppressor + suffix (guaranteed substring match).
        let prefix: Vec<u8> = (0..prefix_len)
            .map(|_| alphabet[(lcg(&mut rng) % alphabet.len() as u64) as usize])
            .collect();
        let suffix: Vec<u8> = (0..suffix_len)
            .map(|_| alphabet[(lcg(&mut rng) % alphabet.len() as u64) as usize])
            .collect();

        let mut secret = Vec::with_capacity(prefix_len + sup_len + suffix_len);
        secret.extend_from_slice(&prefix);
        secret.extend_from_slice(&suppressor);
        secret.extend_from_slice(&suffix);

        let total_len = secret.len();
        prop_assume!((10..=30).contains(&total_len));

        let secret_str = std::str::from_utf8(&secret).unwrap();

        // Leak to get 'static lifetime for test purposes.
        let sup_static: &'static [u8] = Box::leak(suppressor.clone().into_boxed_slice());
        let sup_slice: &'static [&'static [u8]] = Box::leak(vec![sup_static].into_boxed_slice());

        let rule = RuleSpec {
            name: "proptest-always-suppress",
            anchors: &[b"TOK_"],
            radius: 64,
            validator: ValidatorKind::None,
            two_phase: None,
            must_contain: None,
            keywords_any: None,
            value_suppressors_any: Some(sup_slice),
            entropy: None,
            char_class: None,
            local_context: None,
            secret_group: Some(1),
            min_confidence: None,
            offline_validation: None,
            uuid_format_secret: false,
            re: Regex::new(r"TOK_([A-Z0-9]{10,30})").unwrap(),
        };

        let engine = Engine::new_with_anchor_policy(
            vec![rule],
            Vec::new(),
            demo_tuning(),
            AnchorPolicy::ManualOnly,
        );

        let hay = format!("prefix TOK_{secret_str} suffix");
        let hits = scan_findings(&engine, hay.as_bytes());
        prop_assert!(
            !hits.iter().any(|h| h.rule == "proptest-always-suppress"),
            "secret '{}' contains suppressor '{}' and should be suppressed",
            secret_str,
            String::from_utf8_lossy(&suppressor)
        );
    }
}
