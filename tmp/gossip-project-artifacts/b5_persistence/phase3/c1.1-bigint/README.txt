This tarball contains the corrected C1.1 implementation for the PostgreSQL
DoneLedger MVP backend, updated to use BIGINT instead of NUMERIC(20,0).

Included:
- workspace Cargo.toml changes adding gossip-done-ledger-postgres
- new crate crates/gossip-done-ledger-postgres
- embedded migration runner
- initial SQL migration using BIGINT-based storage
- Rust-side u64 <-> BIGINT conversion helpers

Notes:
- run_id and shard_id use raw BIGINT bit-pattern storage
- fence_epoch, started_at, finished_at, bytes_scanned use non-negative BIGINT
- tests are intentionally omitted in this drop
