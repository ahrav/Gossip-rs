//! Public shard primitives exposed as a stable import surface.
//!
//! This module intentionally re-exports two concerns:
//!
//! - [`key_encoding`]: byte-order-preserving key encoders, range arithmetic,
//!   and typed-to-`ShardSpec` helpers.
//! - [`hint`]: strict, versionless shard-hint metadata framing with
//!   borrowed decode and caller-scratch encode.
//!
//! Keeping these re-exports under `crate::shard` lets downstream code avoid
//! coupling to file layout while preserving a clear layering boundary:
//! this module is a facade, not a second validation layer.
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
//! - Metadata/hint no-allocation API: [`ShardMetadata`], [`ShardHint`], and
//!   reusable encode scratch [`MetadataBuf`].
//! - Metadata/hint failures: [`ShardHintDecodeError`],
//!   [`ShardMetadataDecodeError`], [`ShardHintEncodeError`], and
//!   [`MetadataEncodingError`].
//!
//! Validation ownership remains single-sourced:
//! - `key_encoding` enforces local key arithmetic contracts.
//! - `hint` enforces strict metadata/hint wire framing.
//! - [`crate::coordination::shard_spec`] enforces whole-shard invariants.
//!
//! **Dependency direction:** May depend on `identity` and `coordination`.
//! Must not reference `connector` or `persistence`.

pub mod hint;
pub mod key_encoding;

pub use hint::{
    MetadataBuf, MetadataEncodingError, ShardHint, ShardHintDecodeError, ShardHintEncodeError,
    ShardMetadata, ShardMetadataDecodeError,
};
pub use key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PathKey, PrefixShardError, byte_midpoint,
    decode_manifest_row_key, key_successor, prefix_successor, shard_spec_from_keys,
    shard_spec_from_manifest_range, shard_spec_from_prefix,
};

#[cfg(test)]
mod hint_tests;
