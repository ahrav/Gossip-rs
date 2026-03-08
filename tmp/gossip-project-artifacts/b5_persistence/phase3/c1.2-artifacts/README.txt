C1.2 - DoneLedgerPg (Postgres MVP)

Included:
- workspace Cargo.toml update
- new crate: crates/gossip-done-ledger-postgres
- BIGINT-based schema/migration (no NUMERIC)
- synchronous DoneLedger implementation with ReadyCommitHandle
- monotonic UPSERT semantics: scanned dominates failed/skipped
- per-key batch_get with positional results
- ignored live-Postgres conformance test scaffold
- unified patch file: c1.2.patch

Notes:
- run_id and shard_id use u64<->i64 bit reinterpretation at the Rust boundary
- ordered counters/times use non-negative BIGINT with checked conversion
- batch_upsert is fully durable before returning a CommitHandle (no early ACK)
