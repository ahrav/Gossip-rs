D2 findings persistence backend artifact.

Included:
- workspace update adding crates/gossip-findings-postgres
- Postgres findings backend implementation (FindingsSinkPg)
- idempotent upsert SQL for findings and occurrences
- monotonic merge/upsert SQL for observations
- migration + schema + BIGINT helpers
- FindingsConformanceProbe implementation for A5/D3 reuse
