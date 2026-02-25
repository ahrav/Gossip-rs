//! Shard primitives: key encoding, range arithmetic, and hint metadata.
//!
//! This module is the bridge between connectors (which think in typed keys
//! like file paths or manifest rows) and the coordination layer (which
//! operates on opaque `&[u8]` range boundaries). It provides two
//! complementary submodules:
//!
//! - [`key_encoding`] -- byte-order-preserving key encoders
//!   ([`KeyEncoding`], [`PathKey`], [`ManifestRowKey`]), range arithmetic
//!   ([`prefix_successor`], [`key_successor`], [`byte_midpoint`]), and
//!   `ShardSpec` constructors from typed key inputs.
//!
//! - [`hint`] -- versionless shard-hint wire framing ([`ShardHint`],
//!   [`ShardMetadata`]), allocation-free typed shard-spec builders
//!   ([`range_shard_ref`], [`prefix_shard_ref`], [`manifest_shard_ref`]),
//!   decode helpers, and split-propagation logic
//!   ([`propagate_hint_on_split`]).
//!
//! # Zero-allocation design
//!
//! Both submodules follow the same caller-owned-buffer pattern: callers
//! provide a reusable scratch buffer ([`KeyBuf`], [`MetadataBuf`], or
//! [`ShardSpecScratch`]) and receive borrowed output slices. This
//! eliminates per-operation heap allocation on the coordination hot path
//! (acquire, checkpoint, split).
//!
//! # Dependency direction
//!
//! May depend on `identity` and `coordination::shard_spec`. Must not
//! reference `connector` or `persistence`.

pub mod builder;
pub mod hint;
pub mod key_encoding;

pub use hint::{
    HintPropagationError, MetadataBuf, ShardEncodeError, ShardHint, ShardHintDecodeError,
    ShardMetadata, ShardMetadataDecodeError, ShardSpecScratch, SplitBoundary,
    decode_connector_extra, decode_hint, decode_metadata, manifest_shard_into, manifest_shard_ref,
    prefix_shard_into, prefix_shard_ref, propagate_hint_on_split, range_shard_into,
    range_shard_ref,
};
pub use key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PathKey, PrefixShardError, ShardIntoError, byte_midpoint,
    decode_manifest_row_key, key_successor, prefix_successor, shard_spec_from_keys_into,
    shard_spec_from_keys_ref, shard_spec_from_manifest_range_into,
    shard_spec_from_manifest_range_ref, shard_spec_from_prefix_into, shard_spec_from_prefix_ref,
};
