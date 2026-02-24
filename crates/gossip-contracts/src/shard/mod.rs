//! Shard primitives: key encoding, range arithmetic, and hint metadata.
//!
//! Re-exports from [`key_encoding`] (byte-order-preserving key encoders,
//! range arithmetic, typed-to-`ShardSpec` helpers) and [`hint`] (versionless
//! shard-hint wire framing, typed shard-spec constructors/decoders, and
//! split-propagation helpers).
//!
//! **Dependency direction:** may depend on `identity` and `coordination`;
//! must not reference `connector` or `persistence`.

pub mod hint;
pub mod key_encoding;

pub use hint::{
    HintPropagationError, MetadataBuf, ShardEncodeError, ShardHint, ShardHintDecodeError,
    ShardMetadata, ShardMetadataDecodeError, SplitBoundary, decode_connector_extra, decode_hint,
    decode_metadata, manifest_shard, prefix_shard, propagate_hint_on_split, range_shard,
};
pub use key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PathKey, PrefixShardError, byte_midpoint,
    decode_manifest_row_key, key_successor, prefix_successor, shard_spec_from_keys,
    shard_spec_from_manifest_range, shard_spec_from_prefix,
};
