//! Public shard key primitives for shard algebra.
//!
//! This module is the stable re-export boundary for byte-level shard key
//! primitives from [`key_encoding`]. It exists so downstream code can import
//! from `crate::shard` without coupling to internal file layout.
//!
//! Re-export groups:
//! - Encoding contract + buffer: [`KeyEncoding`], [`KeyBuf`].
//! - Typed schemas: [`PathKey`], [`ManifestRowKey`], and
//!   [`decode_manifest_row_key`].
//! - Boundary arithmetic: [`prefix_successor`], [`key_successor`], and
//!   [`byte_midpoint`].
//! - Typed-to-`ShardSpec` bridge helpers: [`shard_spec_from_keys`],
//!   [`shard_spec_from_prefix`], and [`shard_spec_from_manifest_range`].
//! - Prefix construction failures: [`PrefixShardError`].
//!
//! This module adds no extra validation logic: key arithmetic and typed-key
//! semantics live in [`key_encoding`], while whole-partition invariants are
//! enforced in [`crate::coordination::shard_spec`].
//!
//! **Dependency direction:** May depend on `identity` and `coordination`.
//! Must not reference `connector` or `persistence`.

pub mod key_encoding;
#[cfg(test)]
mod key_encoding_tests;

pub use key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PathKey, PrefixShardError, byte_midpoint,
    decode_manifest_row_key, key_successor, prefix_successor, shard_spec_from_keys,
    shard_spec_from_manifest_range, shard_spec_from_prefix,
};
