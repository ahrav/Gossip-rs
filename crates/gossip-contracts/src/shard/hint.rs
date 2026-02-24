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
//! frames. [`ShardMetadata::decode`] returns [`ShardMetadataDecodeError`],
//! which preserves the inner [`ShardHintDecodeError`] when the envelope
//! parsed but the hint payload did not.

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
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Active byte length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are active.
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
    /// Both encode and decode enforce `start_row < end_row`; invalid bounds
    /// are rejected. Direct enum construction does not enforce this invariant.
    Manifest {
        /// Connector-defined manifest identifier.
        manifest_id: u64,
        /// Intended inclusive start row.
        start_row: u64,
        /// Intended exclusive end row.
        end_row: u64,
    },
}

/// Decode failures for [`ShardHint::decode`].
///
/// Each variant describes a specific framing error in a standalone hint frame.
/// For metadata-envelope decode failures see [`ShardMetadataDecodeError`].
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
}

/// Decode failure for the [`ShardMetadata`] envelope.
///
/// Any non-empty metadata that fails strict envelope decoding produces
/// this error. When the envelope structure was valid but the inner hint
/// payload was not, `hint_error` carries the underlying cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardMetadataDecodeError {
    /// The hint-level error when the envelope parsed but the hint did not.
    /// `None` for envelope-structural failures (short length prefix,
    /// length exceeds input, or consumed bytes != declared hint length).
    pub hint_error: Option<ShardHintDecodeError>,
}

/// Encode failures for [`ShardHint::encode_into`] and
/// [`ShardMetadata::encode_into`].
///
/// A single error type covers both hint-level and metadata-level encode
/// failures. Callers match on variant to distinguish prefix-framing overflow,
/// hint-size overflow, total-metadata overflow, and invalid manifest bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShardEncodeError {
    /// Prefix bytes exceed `u32` framing width.
    PrefixTooLarge { size: usize, max: usize },
    /// Encoded hint exceeds metadata capacity.
    HintTooLarge { size: usize, max: usize },
    /// Encoded metadata exceeds [`MAX_METADATA_SIZE`].
    MetadataTooLarge { size: usize, max: usize },
    /// Manifest row bounds are inverted or degenerate (`start_row >= end_row`).
    InvertedManifestRows { start_row: u64, end_row: u64 },
}

impl fmt::Display for ShardHintDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyData => write!(f, "shard hint decode: input is empty"),
            Self::UnknownTag(tag) => {
                write!(f, "shard hint decode: unknown tag 0x{tag:02X}")
            }
            Self::TruncatedPrefix {
                expected_min,
                actual,
            } => write!(
                f,
                "shard hint decode: prefix frame truncated (need {expected_min} bytes, got {actual})"
            ),
            Self::TruncatedManifest {
                expected_min,
                actual,
            } => write!(
                f,
                "shard hint decode: manifest frame truncated (need {expected_min} bytes, got {actual})"
            ),
            Self::InvertedManifestRows { start_row, end_row } => write!(
                f,
                "shard hint decode: manifest rows inverted (start_row={start_row} >= end_row={end_row})"
            ),
        }
    }
}

impl std::error::Error for ShardHintDecodeError {}

impl fmt::Display for ShardMetadataDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.hint_error {
            Some(ref inner) => write!(f, "shard metadata decode failed: {inner}"),
            None => write!(
                f,
                "shard metadata decode: input does not conform to metadata envelope format"
            ),
        }
    }
}

impl std::error::Error for ShardMetadataDecodeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.hint_error
            .as_ref()
            .map(|e| e as &dyn std::error::Error)
    }
}

impl fmt::Display for ShardEncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PrefixTooLarge { size, max } => {
                write!(
                    f,
                    "shard encode: prefix too large ({size} bytes, max {max})"
                )
            }
            Self::HintTooLarge { size, max } => {
                write!(f, "shard encode: hint too large ({size} bytes, max {max})")
            }
            Self::MetadataTooLarge { size, max } => {
                write!(
                    f,
                    "shard encode: metadata too large ({size} bytes, max {max})"
                )
            }
            Self::InvertedManifestRows { start_row, end_row } => write!(
                f,
                "shard encode: manifest rows inverted (start_row={start_row} >= end_row={end_row})"
            ),
        }
    }
}

impl std::error::Error for ShardEncodeError {}

/// Structured shard metadata envelope.
///
/// `hint` is coordination-visible and validated by this module.
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
    /// - [`ShardEncodeError::PrefixTooLarge`] when a prefix exceeds
    ///   `u32` length framing.
    /// - [`ShardEncodeError::HintTooLarge`] when the resulting hint
    ///   frame would exceed [`MAX_METADATA_SIZE`].
    /// - [`ShardEncodeError::InvertedManifestRows`] when a manifest's
    ///   `start_row >= end_row`.
    #[inline]
    pub fn encoded_len(&self) -> Result<usize, ShardEncodeError> {
        match self {
            Self::Range => Ok(1),
            Self::Prefix { prefix } => {
                if prefix.len() > U32_MAX_USIZE {
                    return Err(ShardEncodeError::PrefixTooLarge {
                        size: prefix.len(),
                        max: U32_MAX_USIZE,
                    });
                }
                let size = PREFIX_HEADER_LEN.saturating_add(prefix.len());
                if size > MAX_METADATA_SIZE {
                    return Err(ShardEncodeError::HintTooLarge {
                        size,
                        max: MAX_METADATA_SIZE,
                    });
                }
                Ok(size)
            }
            Self::Manifest {
                start_row, end_row, ..
            } => {
                if *start_row >= *end_row {
                    return Err(ShardEncodeError::InvertedManifestRows {
                        start_row: *start_row,
                        end_row: *end_row,
                    });
                }
                Ok(MANIFEST_LEN)
            }
        }
    }

    /// Encode this hint into `buf` without heap allocation.
    ///
    /// The returned slice borrows `buf` and is overwritten by subsequent
    /// writes into the same [`MetadataBuf`].
    #[inline]
    pub fn encode_into<'b>(&self, buf: &'b mut MetadataBuf) -> Result<&'b [u8], ShardEncodeError> {
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
    #[inline]
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
    /// This preflights `[hint_len:u32 BE][hint_bytes][connector_extra]` and
    /// verifies the total framed metadata size fits within
    /// [`MAX_METADATA_SIZE`].
    #[inline]
    pub fn encoded_len(&self) -> Result<usize, ShardEncodeError> {
        let hint_len = self.hint.encoded_len()?;
        let total_size = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_len)
            .and_then(|s| s.checked_add(self.connector_extra.len()))
            .unwrap_or(usize::MAX);

        if total_size > MAX_METADATA_SIZE {
            return Err(ShardEncodeError::MetadataTooLarge {
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
    #[inline]
    pub fn encode_into<'b>(&self, buf: &'b mut MetadataBuf) -> Result<&'b [u8], ShardEncodeError> {
        let hint_len = self.hint.encoded_len()?;
        let total_size = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_len)
            .and_then(|s| s.checked_add(self.connector_extra.len()))
            .unwrap_or(usize::MAX);

        if total_size > MAX_METADATA_SIZE {
            return Err(ShardEncodeError::MetadataTooLarge {
                size: total_size,
                max: MAX_METADATA_SIZE,
            });
        }

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
    /// returns [`ShardMetadataDecodeError`]. When the envelope structure was
    /// valid but the inner hint payload was not, the returned error carries
    /// the underlying [`ShardHintDecodeError`].
    ///
    /// On success, both the decoded hint prefix bytes (if any) and
    /// `connector_extra` borrow from `metadata`.
    #[inline]
    pub fn decode(metadata: &'a [u8]) -> Result<Self, ShardMetadataDecodeError> {
        if metadata.is_empty() {
            return Ok(Self::from_hint(ShardHint::Range));
        }

        let Some(hint_len_bytes) = metadata.get(..METADATA_HINT_LEN_PREFIX) else {
            return Err(ShardMetadataDecodeError { hint_error: None });
        };
        let hint_len = u32::from_be_bytes(hint_len_bytes.try_into().unwrap()) as usize;

        let hint_frame_end = METADATA_HINT_LEN_PREFIX
            .checked_add(hint_len)
            .ok_or(ShardMetadataDecodeError { hint_error: None })?;
        if hint_frame_end > metadata.len() {
            return Err(ShardMetadataDecodeError { hint_error: None });
        }

        // Bounds validated: METADATA_HINT_LEN_PREFIX <= hint_frame_end <= metadata.len().
        let hint_frame = &metadata[METADATA_HINT_LEN_PREFIX..hint_frame_end];
        let (hint, consumed) =
            ShardHint::decode(hint_frame).map_err(|e| ShardMetadataDecodeError {
                hint_error: Some(e),
            })?;
        if consumed != hint_frame.len() {
            return Err(ShardMetadataDecodeError { hint_error: None });
        }

        Ok(Self {
            hint,
            connector_extra: &metadata[hint_frame_end..],
        })
    }
}

/// Write the wire representation of `hint` into `out`.
///
/// Caller must size `out` to at least `hint.encoded_len()` bytes; the
/// debug-assert fires if the slice is too small.
fn encode_hint_into_slice(hint: ShardHint<'_>, out: &mut [u8]) {
    let required = match &hint {
        ShardHint::Range => 1,
        ShardHint::Prefix { prefix } => PREFIX_HEADER_LEN + prefix.len(),
        ShardHint::Manifest { .. } => MANIFEST_LEN,
    };
    debug_assert!(
        out.len() >= required,
        "encode_hint_into_slice: output slice too small (need {required}, got {})",
        out.len()
    );

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

/// Decode a `TAG_PREFIX` frame: `[0x01][prefix_len:u32 BE][prefix_bytes]`.
///
/// `data` must start with the tag byte. Returns the decoded hint and
/// total bytes consumed (header + payload).
fn decode_prefix<'a>(data: &'a [u8]) -> Result<(ShardHint<'a>, usize), ShardHintDecodeError> {
    if data.len() < PREFIX_HEADER_LEN {
        return Err(ShardHintDecodeError::TruncatedPrefix {
            expected_min: PREFIX_HEADER_LEN,
            actual: data.len(),
        });
    }

    let prefix_len = u32::from_be_bytes(data[1..5].try_into().unwrap()) as usize;
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

/// Decode a `TAG_MANIFEST` frame: `[0x02][manifest_id:u64 BE][start_row:u64 BE][end_row:u64 BE]`.
///
/// `data` must start with the tag byte. Rejects frames where
/// `start_row >= end_row`.
fn decode_manifest<'a>(data: &'a [u8]) -> Result<(ShardHint<'a>, usize), ShardHintDecodeError> {
    if data.len() < MANIFEST_LEN {
        return Err(ShardHintDecodeError::TruncatedManifest {
            expected_min: MANIFEST_LEN,
            actual: data.len(),
        });
    }

    // Bounds validated: data.len() >= MANIFEST_LEN (25 bytes), so all
    // fixed-offset reads below are in-bounds.
    let manifest_id = u64::from_be_bytes(data[1..9].try_into().unwrap());
    let start_row = u64::from_be_bytes(data[9..17].try_into().unwrap());
    let end_row = u64::from_be_bytes(data[17..25].try_into().unwrap());

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

#[cfg(test)]
#[path = "hint_tests.rs"]
mod tests;
