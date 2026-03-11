D3 findings persistence integration tests artifact.

Included:
- existing D2 findings persistence backend (FindingsSinkPg)
- new live-Postgres integration test harness under:
  crates/gossip-findings-postgres/tests/common/mod.rs
- new integration tests under:
  crates/gossip-findings-postgres/tests/findings_pg_integration.rs

Tests covered:
- generic findings conformance harness smoke test
- same record inserted twice -> no duplicates
- same occurrence observed under different policies -> two observations, one finding, one occurrence
- no raw secret bytes or norm-hash bytes persisted in inserted columns

Run with a live Postgres instance:
  cargo test -p gossip-findings-postgres -- --ignored

Optional DSN override:
  GOSSIP_POSTGRES_TEST_URL='host=127.0.0.1 user=postgres password=postgres dbname=postgres'
