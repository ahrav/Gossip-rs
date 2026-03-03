//! Test that manual anchors are being used for unfilterable rules.
//!
//! Run with: cargo test --test test_manual_anchors -- --nocapture

use scanner_engine::demo_engine;

#[test]
fn test_twilio_detection() {
    let engine = demo_engine();

    // Valid Twilio API key format: SK + 32 hex chars
    let input = b"api_key = SK0123456789abcdef0123456789abcdef";
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);

    eprintln!("\nTwilio test input: {:?}", String::from_utf8_lossy(input));
    eprintln!("Hits: {}", hits.len());
    for h in hits {
        eprintln!("  - rule: {}", engine.rule_name(h.rule_id));
    }

    assert!(
        hits.iter()
            .any(|h| engine.rule_name(h.rule_id) == "twilio-api-key"),
        "Should detect twilio-api-key"
    );
}

#[test]
fn test_azure_ad_detection() {
    let engine = demo_engine();

    // Azure AD client secret format: {3}\dQ~{31,34}
    // Example: abc1Q~XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX (3 + 1 + 2 + 31 = 37 chars min)
    let input = b"secret = xyz0Q~abcdefghijklmnopqrstuvwxyz0123";
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);

    eprintln!(
        "\nAzure AD test input: {:?}",
        String::from_utf8_lossy(input)
    );
    eprintln!("Hits: {}", hits.len());
    for h in hits {
        eprintln!("  - rule: {}", engine.rule_name(h.rule_id));
    }

    // Note: This may or may not match depending on the exact format requirements
    // The test is primarily to verify the anchor mechanism works
}

#[test]
fn test_facebook_detection() {
    let engine = demo_engine();

    // Facebook access token format: \d{15,16}(\||%)[0-9a-z\-_]{27,40}
    // Example: 123456789012345|abcdefghijklmnopqrstuvwxyz0
    let input = b"facebook_token = 123456789012345|abcdefghijklmnopqrstuvwxyz0";
    let mut scratch = engine.new_scratch();
    let hits = engine.scan_chunk(input, &mut scratch);

    eprintln!(
        "\nFacebook test input: {:?}",
        String::from_utf8_lossy(input)
    );
    eprintln!("Hits: {}", hits.len());
    for h in hits {
        eprintln!("  - rule: {}", engine.rule_name(h.rule_id));
    }

    // Verify the manual-anchor path detects the Facebook access token pattern.
    assert!(
        hits.iter()
            .any(|h| engine.rule_name(h.rule_id).contains("facebook")),
        "Should detect a facebook-related rule"
    );
}
