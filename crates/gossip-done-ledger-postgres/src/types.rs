//! Rust ↔ PostgreSQL type-mapping for `u64` fields stored as `BIGINT`.
//!
//! PostgreSQL `BIGINT` is a signed 64-bit integer. The contracts layer uses
//! `u64` for both opaque identifiers and ordered counters, but these two use
//! cases have different SQL requirements:
//!
//! | Mode | Fields | Accepted range | SQL semantics preserved |
//! |------|--------|----------------|-------------------------|
//! | **Bit-pattern** | `run_id`, `shard_id` | Full `u64` (`0..=u64::MAX`) | `=`, `GROUP BY` only |
//! | **Ordered non-negative** | `fence_epoch`, `started_at`, `finished_at`, `bytes_scanned` | `0..=i64::MAX` | `<`, `>`, `ORDER BY`, `BETWEEN` |
//!
//! All types and conversion helpers are defined in [`gossip_pg_common::types`]
//! and re-exported here so that intra-crate `use crate::types::*` paths
//! continue to resolve without change.

pub use gossip_pg_common::types::{
    PgByteDecodeError, PgU64ConversionError, decode_fixed_32, pg_bigint_nonnegative_to_u64,
    pg_bigint_to_u64_bits, u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};
