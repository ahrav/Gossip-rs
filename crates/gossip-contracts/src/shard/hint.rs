//! Shard-hint wire framing shared between coordination and connectors.
//!
//! This module defines the structured prefix of shard metadata. The
//! coordinator decodes only the hint frame, then treats the trailing bytes as
//! connector-owned opaque data.
//!
//! # No-versioning policy
//!
//! Hint encoding is intentionally versionless: there is no format version byte
//! and no compatibility shim. A hint is encoded as a tag byte followed by
//! variant-specific fields (fixed-size for Range and Manifest, length-prefixed
//! for Prefix). Unknown tags are rejected immediately. Format evolution is additive
//! by introducing new tags, not by in-band version negotiation.
//!
//! # Metadata envelope
//!
//! [`ShardMetadata`] wraps hints as
//! `[hint_len:u32 BE][hint_bytes][connector_extra]`.
//! Non-empty metadata must match this framing exactly.
//!
//! # Error semantics
//!
//! [`ShardHint::decode`] reports precise framing errors for standalone hint
//! frames. [`ShardMetadata::decode`] intentionally collapses any non-empty
//! parse failure into [`ShardHintDecodeError::NotShardMetadataFormat`] so
//! callers can treat malformed metadata as one hard failure mode.

use crate::coordination::shard_spec::MAX_METADATA_SIZE;

const TAG_RANGE: u8 = 0x00;
const TAG_PREFIX: u8 = 0x01;
const TAG_MANIFEST: u8 = 0x02;

const PREFIX_HEADER_LEN: usize = 1 + 4;
const MANIFEST_LEN: usize = 1 + 8 + 8 + 8;
const METADATA_HINT_LEN_PREFIX: usize = 4;

/// Routing hint embedded in shard metadata.
///
/// Hints let downstream components infer the intended key domain (range,
/// prefix, or manifest rows) without inspecting connector-specific payload
/// bytes. The encoding is intentionally compact and versionless to keep decode
/// logic deterministic across components.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardHint {
    /// Generic byte-range shard with no extra structured narrowing.
    ///
    /// Wire form: `[0x00]`.
    Range,
    /// Prefix-bounded shard. `prefix` bytes are connector-defined.
    ///
    /// Wire form: `[0x01][prefix_len:u32 BE][prefix_bytes]`.
    ///
    /// This variant permits an empty prefix at the wire level; higher-level
    /// constructors decide whether empty prefixes are semantically valid.
    Prefix { prefix: Box<[u8]> },
    /// Intended half-open row range within one manifest: `[start_row, end_row)`.
    ///
    /// Wire form:
    /// `[0x02][manifest_id:u64 BE][start_row:u64 BE][end_row:u64 BE]`.
    ///
    /// Decoding enforces `start_row < end_row`; invalid bounds are rejected.
    /// Direct enum construction does not enforce this invariant.
    Manifest {
        /// Connector-defined manifest identifier.
        manifest_id: u64,
        /// Intended inclusive start row.
        start_row: u64,
        /// Intended exclusive end row.
        end_row: u64,
    },
}

/// Decode failures for hint frames and strict metadata framing.
///
/// `ShardHint::decode` returns the specific variant below. `ShardMetadata::decode`
/// uses only `NotShardMetadataFormat` for any non-empty malformed metadata
/// input, regardless of the underlying hint-level reason.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardHintDecodeError {
    /// Input is empty where a hint tag is required.
    EmptyData,
    /// Tag byte is not recognized.
    UnknownTag(u8),
    /// Prefix frame is incomplete.
    TruncatedPrefix { expected_min: usize, actual: usize },
    /// Manifest frame is incomplete.
    TruncatedManifest { expected_min: usize, actual: usize },
    /// Manifest row bounds are inverted or degenerate (`start_row >= end_row`).
    InvertedManifestRows { start_row: u64, end_row: u64 },
    /// Metadata does not match strict shard metadata framing.
    ///
    /// Used by [`ShardMetadata::decode`] when non-empty metadata fails strict
    /// envelope decoding for any reason (bad length prefix, invalid hint tag,
    /// truncated hint payload, manifest row invariant violation, or unconsumed
    /// hint bytes).
    NotShardMetadataFormat,
}

/// Encoding failures for [`ShardMetadata`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MetadataEncodingError {
    /// Encoded metadata exceeds [`MAX_METADATA_SIZE`].
    MetadataTooLarge { size: usize, max: usize },
}

/// Structured shard metadata envelope.
///
/// `hint` is coordination-visible and normalized by this module.
/// `connector_extra` is opaque and copied through untouched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardMetadata {
    pub hint: ShardHint,
    pub connector_extra: Box<[u8]>,
}

impl ShardHint {
    /// Encode this hint into the strict, versionless wire format.
    ///
    /// The encoded bytes contain no trailing length or checksum; callers that
    /// embed hints in a larger payload must frame them explicitly.
    #[must_use = "returns encoded hint bytes"]
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Range => vec![TAG_RANGE],
            Self::Prefix { prefix } => {
                let prefix_len =
                    u32::try_from(prefix.len()).expect("ShardHint::Prefix length exceeds u32::MAX");
                let mut encoded = Vec::with_capacity(PREFIX_HEADER_LEN + prefix.len());
                encoded.push(TAG_PREFIX);
                encoded.extend_from_slice(&prefix_len.to_be_bytes());
                encoded.extend_from_slice(prefix);
                encoded
            }
            Self::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => {
                let mut encoded = Vec::with_capacity(MANIFEST_LEN);
                encoded.push(TAG_MANIFEST);
                encoded.extend_from_slice(&manifest_id.to_be_bytes());
                encoded.extend_from_slice(&start_row.to_be_bytes());
                encoded.extend_from_slice(&end_row.to_be_bytes());
                encoded
            }
        }
    }

    /// Decode one hint from `data`, returning `(hint, bytes_consumed)`.
    ///
    /// Trailing bytes after `bytes_consumed` are intentionally ignored. This
    /// allows callers to decode a hint from a larger frame and enforce exact
    /// consumption at the outer boundary.
    pub fn decode(data: &[u8]) -> Result<(ShardHint, usize), ShardHintDecodeError> {
        let Some(&tag) = data.first() else {
            return Err(ShardHintDecodeError::EmptyData);
        };

        match tag {
            TAG_RANGE => Ok((ShardHint::Range, 1)),
            TAG_PREFIX => decode_prefix(data),
            TAG_MANIFEST => decode_manifest(data),
            other => Err(ShardHintDecodeError::UnknownTag(other)),
        }
    }
}

impl ShardMetadata {
    /// Build metadata containing only a hint.
    ///
    /// Use this when no connector-private metadata bytes are needed.
    #[must_use = "creates shard metadata that should be used or stored"]
    pub fn from_hint(hint: ShardHint) -> Self {
        Self {
            hint,
            connector_extra: Box::new([]),
        }
    }

    /// Build metadata from hint plus connector-opaque bytes.
    ///
    /// `connector_extra` is stored as-is and never interpreted by this module.
    #[must_use = "creates shard metadata that should be used or stored"]
    pub fn new(hint: ShardHint, connector_extra: Vec<u8>) -> Self {
        Self {
            hint,
            connector_extra: connector_extra.into_boxed_slice(),
        }
    }

    /// Encode metadata as `[hint_len:u32 BE][hint_bytes][connector_extra]`.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataEncodingError::MetadataTooLarge`] when the total
    /// envelope would exceed [`MAX_METADATA_SIZE`].
    pub fn encode(&self) -> Result<Vec<u8>, MetadataEncodingError> {
        let hint_bytes = self.hint.encode();
        let total_size = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_bytes.len())
            .and_then(|s| s.checked_add(self.connector_extra.len()))
            .unwrap_or(usize::MAX);

        if total_size > MAX_METADATA_SIZE {
            return Err(MetadataEncodingError::MetadataTooLarge {
                size: total_size,
                max: MAX_METADATA_SIZE,
            });
        }

        let hint_len = u32::try_from(hint_bytes.len())
            .expect("hint length is validated to fit in metadata u32 frame");
        let mut encoded = Vec::with_capacity(total_size);
        encoded.extend_from_slice(&hint_len.to_be_bytes());
        encoded.extend_from_slice(&hint_bytes);
        encoded.extend_from_slice(&self.connector_extra);
        Ok(encoded)
    }

    /// Decode metadata encoded as `[hint_len:u32 BE][hint_bytes][connector_extra]`.
    ///
    /// Empty input is treated as absent metadata and maps to
    /// `ShardHint::Range` with empty connector bytes.
    ///
    /// Any non-empty input that does not strictly conform to this envelope
    /// returns [`ShardHintDecodeError::NotShardMetadataFormat`]. This includes
    /// invalid hint tags, truncated frames, and hint payloads that decode but
    /// leave unconsumed bytes.
    pub fn decode(metadata: &[u8]) -> Result<Self, ShardHintDecodeError> {
        if metadata.is_empty() {
            return Ok(Self::from_hint(ShardHint::Range));
        }

        let Some(hint_len_bytes) = metadata.get(..METADATA_HINT_LEN_PREFIX) else {
            return Err(ShardHintDecodeError::NotShardMetadataFormat);
        };
        let hint_len = u32::from_be_bytes([
            hint_len_bytes[0],
            hint_len_bytes[1],
            hint_len_bytes[2],
            hint_len_bytes[3],
        ]) as usize;

        let hint_frame_end = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_len)
            .ok_or(ShardHintDecodeError::NotShardMetadataFormat)?;
        if hint_frame_end > metadata.len() {
            return Err(ShardHintDecodeError::NotShardMetadataFormat);
        }

        let Some(hint_frame) = metadata.get(METADATA_HINT_LEN_PREFIX..hint_frame_end) else {
            return Err(ShardHintDecodeError::NotShardMetadataFormat);
        };
        let (hint, consumed) = ShardHint::decode(hint_frame)
            // Preserve a single strict-metadata failure surface for callers.
            .map_err(|_| ShardHintDecodeError::NotShardMetadataFormat)?;
        if consumed != hint_frame.len() {
            return Err(ShardHintDecodeError::NotShardMetadataFormat);
        }

        Ok(Self {
            hint,
            connector_extra: metadata[hint_frame_end..].to_vec().into_boxed_slice(),
        })
    }
}

fn decode_prefix(data: &[u8]) -> Result<(ShardHint, usize), ShardHintDecodeError> {
    if data.len() < PREFIX_HEADER_LEN {
        return Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min: PREFIX_HEADER_LEN,
            actual: data.len(),
        });
    }

    let prefix_len = u32::from_be_bytes([data[1], data[2], data[3], data[4]]) as usize;
    let expected_min = PREFIX_HEADER_LEN.saturating_add(prefix_len);
    if data.len() < expected_min {
        return Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min,
            actual: data.len(),
        });
    }

    let Some(prefix) = data.get(PREFIX_HEADER_LEN..expected_min) else {
        return Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min,
            actual: data.len(),
        });
    };

    Ok((
        ShardHint::Prefix {
            prefix: prefix.to_vec().into_boxed_slice(),
        },
        expected_min,
    ))
}

fn decode_manifest(data: &[u8]) -> Result<(ShardHint, usize), ShardHintDecodeError> {
    if data.len() < MANIFEST_LEN {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    }

    let Some(manifest_id) = read_be_u64(data, 1) else {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    };
    let Some(start_row) = read_be_u64(data, 9) else {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    };
    let Some(end_row) = read_be_u64(data, 17) else {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    };

    if start_row >= end_row {
        return Err(ShardHintDecodeError::InvertedManifestRows { start_row, end_row });
    }

    Ok((
        ShardHint::Manifest {
            manifest_id,
            start_row,
            end_row,
        },
        MANIFEST_LEN,
    ))
}

fn read_be_u64(data: &[u8], offset: usize) -> Option<u64> {
    let bytes = data.get(offset..offset + 8)?;
    Some(u64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]))
}
