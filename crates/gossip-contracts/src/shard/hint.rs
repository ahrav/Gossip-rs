//! Shard-hint wire framing shared between coordination and connectors.
//!
//! This module defines the structured prefix of shard metadata. The
//! coordinator decodes only the hint frame, then treats trailing bytes as
//! connector-owned opaque data.
//!
//! # Allocation discipline
//!
//! The public encode/decode APIs are designed for zero heap allocation in
//! steady-state paths:
//! - Decode returns borrowed views into caller-provided input bytes.
//! - Encode writes into a caller-owned reusable [`MetadataBuf`].
//!
//! Decode outputs are lifetime-bound to the provided input slice. In
//! particular, [`ShardHint::Prefix`] and [`ShardMetadata::connector_extra`]
//! borrow from caller memory and must not outlive it.
//!
//! Encode is two-step:
//! - [`ShardHint::encoded_len`] / [`ShardMetadata::encoded_len`] perform
//!   preflight sizing checks.
//! - [`ShardHint::encode_into`] / [`ShardMetadata::encode_into`] write into
//!   caller scratch and return a slice borrowing that scratch.
//!
//! # No-versioning policy
//!
//! Hint encoding is intentionally versionless: there is no format version byte
//! and no compatibility shim. A hint is encoded as a tag plus fixed variant
//! fields. Unknown tags are rejected immediately. Format evolution is additive
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
use core::fmt;

const TAG_RANGE: u8 = 0x00;
const TAG_PREFIX: u8 = 0x01;
const TAG_MANIFEST: u8 = 0x02;

const PREFIX_HEADER_LEN: usize = 1 + 4;
const MANIFEST_LEN: usize = 1 + 8 + 8 + 8;
const METADATA_HINT_LEN_PREFIX: usize = 4;
const U32_MAX_USIZE: usize = u32::MAX as usize;

/// Reusable fixed-capacity metadata scratch buffer.
///
/// This buffer is intended to be allocated once (for example at startup) and
/// reused across repeated metadata/hint encodes without heap allocation.
#[derive(Clone)]
pub struct MetadataBuf {
    buf: [u8; Self::CAPACITY],
    len: usize,
}

impl MetadataBuf {
    /// Maximum number of bytes this buffer can hold.
    pub const CAPACITY: usize = MAX_METADATA_SIZE;

    /// Create an empty metadata buffer.
    #[must_use = "creates a buffer that should be reused by callers"]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; Self::CAPACITY],
            len: 0,
        }
    }

    /// View active bytes.
    #[must_use = "returns encoded bytes that should be consumed by caller"]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Active byte length.
    #[must_use = "returns current active length"]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are active.
    #[must_use = "returns whether the buffer currently has active bytes"]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Mark this buffer empty without touching backing storage.
    pub fn clear(&mut self) {
        self.len = 0;
    }
}

impl Default for MetadataBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MetadataBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MetadataBuf")
            .field("len", &self.len)
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

/// Routing hint embedded in shard metadata.
///
/// Hints let downstream components infer the intended key domain (range,
/// prefix, or manifest rows) without inspecting connector-specific payload
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardHint<'a> {
    /// Generic byte-range shard with no extra structured narrowing.
    ///
    /// Wire form: `[0x00]`.
    Range,
    /// Prefix-bounded shard. `prefix` bytes are connector-defined.
    ///
    /// Wire form: `[0x01][prefix_len:u32 BE][prefix_bytes]`.
    Prefix { prefix: &'a [u8] },
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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
    /// truncated hint payload, or manifest row invariant violation).
    NotShardMetadataFormat,
}

/// Encode failures for [`ShardHint::encode_into`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardHintEncodeError {
    /// Prefix bytes exceed `u32` framing width.
    PrefixTooLarge { size: usize, max: usize },
    /// Encoded hint exceeds metadata capacity.
    EncodedHintTooLarge { size: usize, max: usize },
}

/// Encode failures for [`ShardMetadata::encode_into`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetadataEncodingError {
    /// Encoded metadata exceeds [`MAX_METADATA_SIZE`].
    MetadataTooLarge { size: usize, max: usize },
    /// Encoded hint is too large to frame in metadata.
    HintTooLarge { size: usize, max: usize },
}

/// Structured shard metadata envelope.
///
/// `hint` is coordination-visible and normalized by this module.
/// `connector_extra` is opaque and copied through untouched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardMetadata<'a> {
    /// Coordination-visible routing hint.
    pub hint: ShardHint<'a>,
    /// Connector-private bytes, preserved opaquely by this module.
    pub connector_extra: &'a [u8],
}

impl<'a> ShardHint<'a> {
    /// Return encoded byte length for this hint.
    ///
    /// This is a pure sizing preflight: it does not mutate caller buffers.
    ///
    /// # Errors
    ///
    /// - [`ShardHintEncodeError::PrefixTooLarge`] when a prefix exceeds
    ///   `u32` length framing.
    /// - [`ShardHintEncodeError::EncodedHintTooLarge`] when the resulting hint
    ///   frame would exceed [`MAX_METADATA_SIZE`].
    pub fn encoded_len(&self) -> Result<usize, ShardHintEncodeError> {
        match self {
            Self::Range => Ok(1),
            Self::Prefix { prefix } => {
                if prefix.len() > U32_MAX_USIZE {
                    return Err(ShardHintEncodeError::PrefixTooLarge {
                        size: prefix.len(),
                        max: U32_MAX_USIZE,
                    });
                }
                let size = PREFIX_HEADER_LEN.saturating_add(prefix.len());
                if size > MAX_METADATA_SIZE {
                    return Err(ShardHintEncodeError::EncodedHintTooLarge {
                        size,
                        max: MAX_METADATA_SIZE,
                    });
                }
                Ok(size)
            }
            Self::Manifest { .. } => Ok(MANIFEST_LEN),
        }
    }

    /// Encode this hint into `buf` without heap allocation.
    ///
    /// The returned slice borrows `buf` and is overwritten by subsequent
    /// writes into the same [`MetadataBuf`].
    ///
    /// This method validates framing size only. It does not enforce semantic
    /// invariants beyond framing (for example, manifest row ordering).
    pub fn encode_into<'b>(
        &self,
        buf: &'b mut MetadataBuf,
    ) -> Result<&'b [u8], ShardHintEncodeError> {
        let hint_len = self.encoded_len()?;
        encode_hint_into_slice(*self, &mut buf.buf[..hint_len]);
        buf.len = hint_len;
        Ok(buf.as_bytes())
    }

    /// Decode one hint from `data`, returning `(hint, bytes_consumed)`.
    ///
    /// Trailing bytes after `bytes_consumed` are intentionally ignored. This
    /// allows callers to decode a hint from a larger frame and enforce exact
    /// consumption at the outer boundary.
    ///
    /// For [`ShardHint::Prefix`], the decoded `prefix` borrows from `data`.
    pub fn decode(data: &'a [u8]) -> Result<(ShardHint<'a>, usize), ShardHintDecodeError> {
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

impl<'a> ShardMetadata<'a> {
    /// Build metadata containing only a hint.
    ///
    /// Use this when no connector-private metadata bytes are needed.
    #[must_use = "creates shard metadata that should be used or stored"]
    pub fn from_hint(hint: ShardHint<'a>) -> Self {
        Self {
            hint,
            connector_extra: &[],
        }
    }

    /// Build metadata from hint plus connector-opaque bytes.
    ///
    /// `connector_extra` is stored as-is and never interpreted by this module.
    #[must_use = "creates shard metadata that should be used or stored"]
    pub fn new(hint: ShardHint<'a>, connector_extra: &'a [u8]) -> Self {
        Self {
            hint,
            connector_extra,
        }
    }

    /// Return encoded byte length for this metadata envelope.
    ///
    /// This preflights `[hint_len:u32][hint_bytes][connector_extra]` and
    /// verifies the total framed metadata size fits within
    /// [`MAX_METADATA_SIZE`].
    pub fn encoded_len(&self) -> Result<usize, MetadataEncodingError> {
        let hint_len = self.hint.encoded_len().map_err(map_hint_encode_error)?;
        let total_size = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_len)
            .and_then(|s| s.checked_add(self.connector_extra.len()))
            .unwrap_or(usize::MAX);

        if total_size > MAX_METADATA_SIZE {
            return Err(MetadataEncodingError::MetadataTooLarge {
                size: total_size,
                max: MAX_METADATA_SIZE,
            });
        }

        Ok(total_size)
    }

    /// Encode metadata as `[hint_len:u32 BE][hint_bytes][connector_extra]`
    /// into `buf` without heap allocation.
    ///
    /// The returned slice borrows `buf` and is overwritten by subsequent
    /// writes into the same [`MetadataBuf`].
    pub fn encode_into<'b>(
        &self,
        buf: &'b mut MetadataBuf,
    ) -> Result<&'b [u8], MetadataEncodingError> {
        let hint_len = self.hint.encoded_len().map_err(map_hint_encode_error)?;
        let total_size = self.encoded_len()?;

        let hint_len_u32 =
            u32::try_from(hint_len).expect("hint_len is validated to fit in u32 framing");
        let out = &mut buf.buf[..total_size];

        out[..METADATA_HINT_LEN_PREFIX].copy_from_slice(&hint_len_u32.to_be_bytes());

        let hint_start = METADATA_HINT_LEN_PREFIX;
        let hint_end = hint_start + hint_len;
        encode_hint_into_slice(self.hint, &mut out[hint_start..hint_end]);

        out[hint_end..].copy_from_slice(self.connector_extra);
        buf.len = total_size;
        Ok(buf.as_bytes())
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
    ///
    /// On success, both the decoded hint prefix bytes (if any) and
    /// `connector_extra` borrow from `metadata`.
    pub fn decode(metadata: &'a [u8]) -> Result<Self, ShardHintDecodeError> {
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

        // Bounds validated: METADATA_HINT_LEN_PREFIX <= hint_frame_end <= metadata.len().
        let hint_frame = &metadata[METADATA_HINT_LEN_PREFIX..hint_frame_end];
        let (hint, consumed) = ShardHint::decode(hint_frame)
            // Preserve a single strict-metadata failure surface for callers.
            .map_err(|_| ShardHintDecodeError::NotShardMetadataFormat)?;
        if consumed != hint_frame.len() {
            return Err(ShardHintDecodeError::NotShardMetadataFormat);
        }

        Ok(Self {
            hint,
            connector_extra: &metadata[hint_frame_end..],
        })
    }
}

fn map_hint_encode_error(err: ShardHintEncodeError) -> MetadataEncodingError {
    match err {
        ShardHintEncodeError::PrefixTooLarge { size, max }
        | ShardHintEncodeError::EncodedHintTooLarge { size, max } => {
            MetadataEncodingError::HintTooLarge { size, max }
        }
    }
}

fn encode_hint_into_slice(hint: ShardHint<'_>, out: &mut [u8]) {
    match hint {
        ShardHint::Range => {
            out[0] = TAG_RANGE;
        }
        ShardHint::Prefix { prefix } => {
            out[0] = TAG_PREFIX;
            let prefix_len_u32 =
                u32::try_from(prefix.len()).expect("prefix length validated before encoding");
            out[1..5].copy_from_slice(&prefix_len_u32.to_be_bytes());
            out[PREFIX_HEADER_LEN..PREFIX_HEADER_LEN + prefix.len()].copy_from_slice(prefix);
        }
        ShardHint::Manifest {
            manifest_id,
            start_row,
            end_row,
        } => {
            out[0] = TAG_MANIFEST;
            out[1..9].copy_from_slice(&manifest_id.to_be_bytes());
            out[9..17].copy_from_slice(&start_row.to_be_bytes());
            out[17..25].copy_from_slice(&end_row.to_be_bytes());
        }
    }
}

fn decode_prefix<'a>(data: &'a [u8]) -> Result<(ShardHint<'a>, usize), ShardHintDecodeError> {
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

    // Bounds validated: PREFIX_HEADER_LEN <= expected_min <= data.len().
    let prefix = &data[PREFIX_HEADER_LEN..expected_min];

    Ok((ShardHint::Prefix { prefix }, expected_min))
}

fn decode_manifest<'a>(data: &'a [u8]) -> Result<(ShardHint<'a>, usize), ShardHintDecodeError> {
    if data.len() < MANIFEST_LEN {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    }

    // Bounds validated: data.len() >= MANIFEST_LEN (25 bytes), so all
    // fixed-offset reads below are in-bounds.
    let manifest_id = u64::from_be_bytes([
        data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8],
    ]);
    let start_row = u64::from_be_bytes([
        data[9], data[10], data[11], data[12], data[13], data[14], data[15], data[16],
    ]);
    let end_row = u64::from_be_bytes([
        data[17], data[18], data[19], data[20], data[21], data[22], data[23], data[24],
    ]);

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
