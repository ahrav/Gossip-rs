//! Print unfilterable rules from the gitleaks ruleset.
//!
//! Run with: cargo test --test print_unfilterable -- --nocapture

use scanner_engine::demo_engine;

#[test]
fn print_unfilterable_rules() {
    let engine = demo_engine();

    let unfilterable = engine.unfilterable_rules();

    eprintln!(
        "\n=== UNFILTERABLE RULES ({} total) ===\n",
        unfilterable.len()
    );

    for (rule_idx, reason) in unfilterable {
        let rule_name = engine.rule_name(*rule_idx as u32);
        eprintln!("  [{:3}] {:40} -> {:?}", rule_idx, rule_name, reason);
    }

    eprintln!("\n=== END UNFILTERABLE RULES ===\n");
}
