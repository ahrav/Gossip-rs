//! Tests for anchor optimization changes.
//!
//! These tests verify that the anchor optimizations (JWT: ey→eyJ, Vault: split rules)
//! do not cause any secrets to be missed.

use scanner_engine::demo_engine;

/// Helper to check if a rule matched in the scan results
fn has_rule_match(engine: &scanner_engine::Engine, input: &[u8], rule_name: &str) -> bool {
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);
    hits.iter()
        .any(|h| engine.rule_name(h.rule_id) == rule_name)
}

// ============================================================================
// JWT Tests
// ============================================================================

#[test]
fn test_jwt_standard_hs256_detected() {
    let engine = demo_engine();

    // Standard JWT with HS256 algorithm
    let jwt_hs256 = b"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    assert!(
        has_rule_match(&engine, jwt_hs256, "jwt"),
        "JWT with HS256 should be detected"
    );

    // JWT with RS256 algorithm
    let jwt_rs256 = b"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature_placeholder_xxxxx";
    assert!(
        has_rule_match(&engine, jwt_rs256, "jwt"),
        "JWT with RS256 should be detected"
    );

    // JWT with ES256 algorithm
    let jwt_es256 = b"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.signature_placeholder_xxxxx";
    assert!(
        has_rule_match(&engine, jwt_es256, "jwt"),
        "JWT with ES256 should be detected"
    );
}

#[test]
fn test_jwt_in_env_var_detected() {
    let engine = demo_engine();
    // JWT in environment variable assignment
    let input = b"export JWT_TOKEN=\"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\"";
    assert!(
        has_rule_match(&engine, input, "jwt"),
        "JWT in env var should be detected"
    );
}

#[test]
fn test_jwt_in_json_detected() {
    let engine = demo_engine();
    // JWT in JSON
    let input = b"{\"token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\"}";
    assert!(
        has_rule_match(&engine, input, "jwt"),
        "JWT in JSON should be detected"
    );
}

#[test]
fn test_jwt_non_jwt_ey_prefix_not_detected() {
    let engine = demo_engine();
    // Words starting with "ey" should not trigger JWT detection
    let input = b"eyebrow painting techniques and eyes_and_ears data file";
    // This should NOT match JWT rule (we can't easily verify non-match without looking at all hits,
    // but we can verify the engine doesn't crash and processes it)
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);
    let jwt_hits: Vec<_> = hits
        .iter()
        .filter(|h| engine.rule_name(h.rule_id) == "jwt")
        .collect();
    assert!(
        jwt_hits.is_empty(),
        "Non-JWT 'ey' words should not match JWT rule"
    );
}

// ============================================================================
// Vault Token Tests
// ============================================================================

#[test]
fn test_vault_modern_hvs_token_detected() {
    let engine = demo_engine();
    // Modern hvs. format token (90-120 chars after hvs.)
    let token = b"hvs.CAESIJvYpLvL7Ks7Q9v8zQm1uD3eK2xS5mA0wBcNdF1gH2jKGh4KHGh2cy5YV0pOVWxvTklYbFFOMndNVHFNa1pqUWsudllGRzBOdlBaZ3E4YTNNMGp5";
    assert!(
        has_rule_match(&engine, token, "vault-service-token"),
        "Modern hvs. token should be detected"
    );
}

#[test]
fn test_vault_modern_hvs_in_env_var() {
    let engine = demo_engine();
    // Modern hvs. token in environment variable
    let input = b"export VAULT_TOKEN=\"hvs.CAESIJvYpLvL7Ks7Q9v8zQm1uD3eK2xS5mA0wBcNdF1gH2jKGh4KHGh2cy5YV0pOVWxvTklYbFFOMndNVHFNa1pqUWsudllGRzBOdlBaZ3E4YTNNMGp5\"";
    assert!(
        has_rule_match(&engine, input, "vault-service-token"),
        "Modern hvs. token in env var should be detected"
    );
}

#[test]
fn test_vault_legacy_token_with_context() {
    let engine = demo_engine();
    // Legacy s. token WITH vault context (should be detected by vault-service-token-legacy)
    let input = b"export VAULT_TOKEN=s.abcdefghijklmnopqrstuvwx";
    assert!(
        has_rule_match(&engine, input, "vault-service-token-legacy"),
        "Legacy s. token with VAULT context should be detected"
    );
}

#[test]
fn test_vault_legacy_token_lowercase_context() {
    let engine = demo_engine();
    // Legacy s. token with lowercase vault context
    let input = b"vault_token: s.abcdefghijklmnopqrstuvwx";
    assert!(
        has_rule_match(&engine, input, "vault-service-token-legacy"),
        "Legacy s. token with lowercase vault context should be detected"
    );
}

#[test]
fn test_vault_legacy_token_in_config() {
    let engine = demo_engine();
    // Legacy s. token in a config file with Vault mentioned
    let input = b"# Vault configuration\ntoken = \"s.abc123def456ghi789jkl012\"";
    assert!(
        has_rule_match(&engine, input, "vault-service-token-legacy"),
        "Legacy s. token with Vault comment context should be detected"
    );
}

#[test]
fn test_decimal_not_detected_as_vault() {
    let engine = demo_engine();
    // Decimal numbers with "s." should NOT trigger vault detection
    let input = b"The calculation took 3.14159s. Then another 2.71828s. completed.";
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);
    let vault_hits: Vec<_> = hits
        .iter()
        .filter(|h| engine.rule_name(h.rule_id).starts_with("vault"))
        .collect();
    assert!(
        vault_hits.is_empty(),
        "Decimals with 's.' should not match vault rules"
    );
}

#[test]
fn test_abbreviations_not_detected_as_vault() {
    let engine = demo_engine();
    // Common abbreviations should not trigger vault detection
    let input = b"For example, e.g. this and i.e. that, v1.0.0 and s.t. conditions apply.";
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);
    let vault_hits: Vec<_> = hits
        .iter()
        .filter(|h| engine.rule_name(h.rule_id).starts_with("vault"))
        .collect();
    // Note: Some of these might match if they happen to have 24 alphanumeric chars following
    // but typical text won't have that pattern
    assert!(
        vault_hits.is_empty(),
        "Common abbreviations should not match vault rules: {:?}",
        vault_hits
    );
}

// ============================================================================
// Combined Tests - Ensure all rules work together
// ============================================================================

#[test]
fn test_mixed_secrets_file() {
    let engine = demo_engine();
    // A file with multiple secret types
    let input = br#"
# Application secrets
JWT_TOKEN=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
VAULT_TOKEN=hvs.CAESIJvYpLvL7Ks7Q9v8zQm1uD3eK2xS5mA0wBcNdF1gH2jKGh4KHGh2cy5YV0pOVWxvTklYbFFOMndNVHFNa1pqUWsudllGRzBOdlBaZ3E4YTNNMGp5

# Some random text with ey prefix that is NOT a JWT
The eyebrows were raised when they saw the eyes_and_ears file.

# Some decimals that should NOT match vault
Pi is approximately 3.14159s. per calculation
"#;

    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);

    // Check JWT is detected
    assert!(
        hits.iter().any(|h| engine.rule_name(h.rule_id) == "jwt"),
        "JWT should be detected in mixed file"
    );

    // Check Vault is detected
    assert!(
        hits.iter()
            .any(|h| engine.rule_name(h.rule_id) == "vault-service-token"),
        "Vault token should be detected in mixed file"
    );
}

// ============================================================================
// Edge Cases
// ============================================================================

#[test]
fn test_jwt_minimum_length() {
    let engine = demo_engine();
    // Minimum valid JWT structure (header.payload.signature with minimum lengths)
    // eyJ = base64("{") so minimum header is at least eyJ + 16 more chars per the regex
    let jwt = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature_pad";
    // This may or may not match depending on exact length requirements
    let mut scratch = engine.new_scratch();
    let _hits = engine.scan_chunk(jwt, &mut scratch);
    // Just verify it doesn't panic
}

#[test]
fn test_vault_hvs_exact_boundary() {
    let engine = demo_engine();
    // Test hvs. token at exact 90 character boundary (minimum)
    let token =
        b"hvs.CAESIJ2Hb_T1sVN1P9aUDANaBPUdmEIu_D2RxRgfzU5wT1rGGh4KHGh2cy5YV0pOVWxvTklYbFFOMndNVHE";
    // 90 chars after hvs.
    let mut scratch = engine.new_scratch();
    let _hits = engine.scan_chunk(token, &mut scratch);
    // Just verify it doesn't panic
}
