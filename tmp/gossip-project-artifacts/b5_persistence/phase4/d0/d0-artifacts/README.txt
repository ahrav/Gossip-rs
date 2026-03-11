D0 artifacts for gossip-findings-postgres

Included:
- workspace Cargo.toml update
- new crate crates/gossip-findings-postgres
- schema plan constants and row projections
- BIGINT conversion helpers for later D1/D2 work

Not included yet:
- SQL migrations (D1)
- FindingsSinkPg implementation (D2)
