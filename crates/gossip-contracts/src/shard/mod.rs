//! Shard primitives: key encoding, range arithmetic, and hint metadata.
//!
//! Re-exports from [`key_encoding`] (byte-order-preserving key encoders and
//! range arithmetic) and [`hint`] (versionless shard-hint wire framing,
//! borrowed constructors (`*_shard_ref`), arena-backed constructors
//! (`*_shard_into`), typed decoders, and split-propagation helpers).
//!
//! Startup preallocation lives in [`builder`]: [`PreallocShardBuilder`] stages
//! borrowed/spec-handle inputs and produces validated borrowed
//! [`crate::coordination::InitialShardInput`] rows for run registration.
//!
//! **Dependency direction:** may depend on `identity` and `coordination`;
//! must not reference `connector` or `persistence`.

pub mod builder;
pub mod hint;
pub mod key_encoding;

pub use builder::{
    PreallocShardBuilder, PreallocShardBuilderConfigError, PreallocShardBuilderError,
};
pub use hint::{
    HintPropagationError, ManifestShardIntoError, MetadataBuf, PrefixShardIntoError,
    RangeShardIntoError, ShardEncodeError, ShardHint, ShardHintDecodeError, ShardMetadata,
    ShardMetadataDecodeError, ShardSpecScratch, SplitBoundary, decode_connector_extra, decode_hint,
    decode_metadata, manifest_shard_into, manifest_shard_ref, prefix_shard_into, prefix_shard_ref,
    propagate_hint_on_split, range_shard_into, range_shard_ref,
};
pub use key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PathKey, PrefixShardError, byte_midpoint,
    decode_manifest_row_key, key_successor, prefix_successor,
};
