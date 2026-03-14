//! Analyze unfilterable rules to understand why they fail anchor derivation.
//!
//! Run with: cargo test --test analyze_unfilterable -- --nocapture

use scanner_engine::regex2anchor::{AnchorDeriveConfig, compile_trigger_plan};

#[test]
fn analyze_unfilterable_patterns() {
    let cfg = AnchorDeriveConfig {
        min_anchor_len: 3,
        utf8: false, // byte-oriented matching
        ..Default::default()
    };

    let patterns = vec![
        // azure-ad-client-secret: The regex has "Q~" which is only 2 chars
        (
            "azure-ad-client-secret",
            r#"(?:^|[\\'"\x60\s>=:(,)])([a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\'"\x60\s<),])"#,
            r"Problem: 'Q~' is only 2 chars. The pattern has {3}\dQ~ which could derive '0Q~', '1Q~', etc (3 chars each)",
        ),
        // facebook-access-token: Starts with digits, no literal anchor
        (
            "facebook-access-token",
            r#"(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$)"#,
            r"Problem: Starts with \d{15,16} - no literal substring. Only '|' or '%' separators are literals",
        ),
        // generic-api-key: Very broad pattern with many optional parts
        (
            "generic-api-key",
            r#"(?i)[\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: Alternation of keywords (access|auth|api|...) but with optional prefix/suffix making them not required",
        ),
        // grafana-service-account-token: glsa_ is 5 chars - should work!
        (
            "grafana-service-account-token",
            r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}",
            "Should work: 'glsa_' is 5 chars - meets min_anchor_len=3",
        ),
        // hashicorp-tf-password: keyword-based pattern
        (
            "hashicorp-tf-password",
            r#"(?i)[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{8,20})(?:[\x60'"\s;]|\\[nr]|$)"#,
            r"Problem: Optional prefix [\w.-]{0,50}? can be empty, so keywords aren't strictly required",
        ),
        // jfrog-api-key
        (
            "jfrog-api-key",
            r#"(?i)[\w.-]{0,50}?(?:jfrog|artifactory)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{73})(?:[\x60'"\s;]|\\[nr]|$)"#,
            r"Problem: Optional prefix [\w.-]{0,50}? makes keywords not strictly required",
        ),
        // jfrog-identity-token
        (
            "jfrog-identity-token",
            r#"(?i)[\w.-]{0,50}?(?:jfrog|artifactory)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: Same as jfrog-api-key",
        ),
        // kraken-access-token
        (
            "kraken-access-token",
            r#"(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-zA-Z0-9/+=]{80,90})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: Optional prefix makes 'kraken' not strictly required",
        ),
        // nytimes-access-token
        (
            "nytimes-access-token",
            r#"(?i)[\w.-]{0,50}?(?:nytimes|new-york-times)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9-]{32})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: Optional prefix makes keywords not strictly required",
        ),
        // snyk-api-token
        (
            "snyk-api-token",
            r#"(?i)[\w.-]{0,50}?(?:snyk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9-]{36})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: Optional prefix makes 'snyk' not strictly required",
        ),
        // sourcegraph-access-token
        (
            "sourcegraph-access-token",
            r"sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}",
            "Should work: 'sgp_' is 4 chars - meets min_anchor_len=3",
        ),
        // twilio-api-key
        (
            "twilio-api-key",
            r"SK[0-9a-fA-F]{32}",
            "Problem: 'SK' is only 2 chars",
        ),
        // vault-service-token-legacy
        (
            "vault-service-token-legacy",
            r#"\b(s\.[a-zA-Z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)"#,
            "Problem: 's.' is only 2 chars",
        ),
    ];

    eprintln!("\n=== UNFILTERABLE PATTERN ANALYSIS ===\n");

    for (name, pattern, analysis) in patterns {
        eprintln!("┌─ {} ─┐", name);
        eprintln!("│ Pattern: {}", pattern);
        eprintln!("│ Analysis: {}", analysis);

        match compile_trigger_plan(pattern, &cfg) {
            Ok(plan) => {
                eprintln!("│ Result: {:?}", plan);
            }
            Err(e) => {
                eprintln!("│ Error: {:?}", e);
            }
        }
        eprintln!("└────────────────────────────────────────┘\n");
    }
}
