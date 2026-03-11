D1 findings Postgres migrations artifact bundle

Includes:
- workspace Cargo.toml update
- new crate crates/gossip-findings-postgres
- D0 schema-plan code (row projections + constants)
- D1 forward-only migration runner
- 0001_findings_schema.sql
- patch file

Notes:
- This bundle includes the D0 crate scaffold because the uploaded project tree
  did not yet contain gossip-findings-postgres.
- The schema keeps policy_hash out of occurrences and stores policy-scoped state
  only in observations.
