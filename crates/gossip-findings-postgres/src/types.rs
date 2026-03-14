//! Rust ↔ PostgreSQL type-mapping helpers for `u64` fields stored as
//! `BIGINT`.
//!
//! PostgreSQL `BIGINT` is signed, but findings persistence needs two distinct
//! storage modes:
//!
//! | Mode | Fields | Accepted range | SQL semantics preserved |
//! |------|--------|----------------|-------------------------|
//! | **Bit-pattern** | `run_id`, `shard_id` | Full `u64` (`0..=u64::MAX`) | `=`, `GROUP BY` only |
//! | **Ordered non-negative** | `fence_epoch`, `seen_at`, `byte_offset`, `byte_length` | `0..=i64::MAX` | `<`, `>`, `ORDER BY`, `BETWEEN` |
//!
//! All types and conversion helpers are defined in [`gossip_pg_common::types`]
//! and re-exported here so that intra-crate `use crate::types::*` paths
//! continue to resolve without change.

pub use gossip_pg_common::types::{
    PgByteDecodeError, PgU64ConversionError, decode_fixed_32, pg_bigint_nonnegative_to_u64,
    pg_bigint_to_u64_bits, u64_to_pg_bigint_bits, u64_to_pg_bigint_checked,
};
