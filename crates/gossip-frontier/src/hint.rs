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
//! - Convenience constructors ([`range_shard_ref`], [`prefix_shard_ref`],
//!   [`manifest_shard_ref`]) return borrowed [`ShardSpecRef`] values.
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

use super::key_encoding::{
    KeyBuf, KeyEncoding, ManifestRowKey, PrefixShardError, ShardIntoError, decode_manifest_row_key,
    prefix_successor,
};
use core::fmt;
use gossip_contracts::coordination::shard_spec::{
    IntoShardSpecRef, MAX_KEY_SIZE, MAX_METADATA_SIZE, ShardArena, ShardSpec, ShardSpecHandle,
    ShardSpecInputError, ShardSpecRef,
};

/// Wire tag for [`ShardHint::Range`].
const TAG_RANGE: u8 = 0x00;
/// Wire tag for [`ShardHint::Prefix`].
const TAG_PREFIX: u8 = 0x01;
/// Wire tag for [`ShardHint::Manifest`].
const TAG_MANIFEST: u8 = 0x02;

/// Prefix hint header: 1-byte tag + 4-byte big-endian length.
const PREFIX_HEADER_LEN: usize = 1 + 4;
/// Manifest hint total size: 1-byte tag + three 8-byte big-endian u64 fields.
const MANIFEST_LEN: usize = 1 + 8 + 8 + 8;
/// Metadata envelope hint-length prefix size (4-byte big-endian u32).
const METADATA_HINT_LEN_PREFIX: usize = 4;
/// `u32::MAX` as `usize`, used as the framing width ceiling for prefix length.
const U32_MAX_USIZE: usize = u32::MAX as usize;

/// Reusable fixed-capacity metadata scratch buffer.
///
/// Sized to hold any valid metadata envelope ([`MAX_METADATA_SIZE`] bytes).
/// Allocate one at startup or per-thread and reuse it across repeated
/// `encode_into` calls to avoid per-encode heap allocation.
///
/// The returned slice from `encode_into` borrows this buffer. Any
/// subsequent write overwrites the previous content; callers must
/// consume or copy the slice before the next encode.
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

/// Caller-owned scratch for allocation-free shard-spec construction helpers.
///
/// Bundles a [`KeyBuf`] for the start bound, a [`KeyBuf`] for the end bound,
/// and a [`MetadataBuf`] for the encoded metadata envelope. One scratch can
/// be reused across many helper calls (`range_shard_ref`, `prefix_shard_ref`,
/// `manifest_shard_ref`).
///
/// Returned borrowed `ShardSpecRef` values alias this scratch and become
/// stale once the scratch is mutated again. Callers must allocate the spec
/// into an arena or copy it before reusing the scratch.
#[derive(Debug, Default)]
pub struct ShardSpecScratch {
    start: KeyBuf,
    end: KeyBuf,
    metadata: MetadataBuf,
}

impl ShardSpecScratch {
    /// Create empty reusable scratch.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn metadata_buf(&mut self) -> &mut MetadataBuf {
        &mut self.metadata
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ShardHintDecodeError {
    /// Input is empty where a hint tag is required.
    #[error("shard hint decode: input is empty")]
    EmptyData,
    /// Tag byte is not recognized.
    #[error("shard hint decode: unknown tag 0x{0:02X}")]
    UnknownTag(u8),
    /// Prefix frame is incomplete.
    #[error("shard hint decode: prefix frame truncated (need {expected_min} bytes, got {actual})")]
    TruncatedPrefix { expected_min: usize, actual: usize },
    /// Manifest frame is incomplete.
    #[error(
        "shard hint decode: manifest frame truncated (need {expected_min} bytes, got {actual})"
    )]
    TruncatedManifest { expected_min: usize, actual: usize },
    /// Manifest row bounds are inverted or degenerate (`start_row >= end_row`).
    #[error(
        "shard hint decode: manifest rows inverted (start_row={start_row} >= end_row={end_row})"
    )]
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

/// Encode failures for [`ShardHint::encode_into`] and
/// [`ShardMetadata::encode_into`].
///
/// A single error type covers both hint-level and metadata-level encode
/// failures. Callers match on variant to distinguish prefix-framing overflow,
/// hint-size overflow, total-metadata overflow, and invalid manifest bounds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ShardEncodeError {
    /// Prefix bytes exceed `u32` framing width.
    #[error("shard encode: prefix too large ({size} bytes, max {max})")]
    PrefixTooLarge { size: usize, max: usize },
    /// Encoded hint exceeds metadata capacity.
    #[error("shard encode: hint too large ({size} bytes, max {max})")]
    HintTooLarge { size: usize, max: usize },
    /// Encoded metadata exceeds [`MAX_METADATA_SIZE`].
    #[error("shard encode: metadata too large ({size} bytes, max {max})")]
    MetadataTooLarge { size: usize, max: usize },
    /// Manifest row bounds are inverted or degenerate (`start_row >= end_row`).
    #[error("shard encode: manifest rows inverted (start_row={start_row} >= end_row={end_row})")]
    InvertedManifestRows { start_row: u64, end_row: u64 },
}

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
    /// returns [`ShardMetadataDecodeError`]. When hint decode itself fails, the
    /// returned error carries the underlying [`ShardHintDecodeError`]. Envelope
    /// framing/consumption failures return `hint_error: None`.
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

/// Construct a borrowed range shard with encoded metadata.
///
/// Builds a `ShardSpecRef` for the half-open interval `[start, end)` with a
/// `ShardHint::Range` hint and caller-supplied `connector_extra` bytes.
///
/// The returned `ShardSpecRef` borrows from `scratch`; callers must allocate
/// the spec into an arena or copy it before reusing `scratch`.
///
/// # Errors
///
/// - [`ShardSpecInputError::MetadataTooLarge`] if the encoded metadata
///   (hint + connector_extra) exceeds [`MAX_METADATA_SIZE`].
/// - [`ShardSpecInputError::KeyTooLarge`] if `start` or `end` exceeds
///   [`MAX_KEY_SIZE`].
/// - [`ShardSpecInputError::InvertedRange`] if `start >= end`.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn range_shard_ref<'a>(
    start: &'a [u8],
    end: &'a [u8],
    connector_extra: &[u8],
    scratch: &'a mut ShardSpecScratch,
) -> Result<ShardSpecRef<'a>, ShardSpecInputError> {
    let metadata = ShardMetadata::new(ShardHint::Range, connector_extra)
        .encode_into(scratch.metadata_buf())
        .map_err(map_encode_to_spec_input_error)?;
    let spec = ShardSpecRef::new(start, end, metadata);
    ShardSpec::validate_ref(spec)?;
    Ok(spec)
}

/// Build a range shard spec and allocate it in the given arena.
///
/// Combines [`range_shard_ref`] validation with arena allocation. On
/// success, returns a handle to the arena-backed spec. The handle remains
/// valid until the arena is cleared or the spec is explicitly freed.
///
/// # Errors
///
/// - [`ShardIntoError::Build`] -- range bounds or metadata fail validation.
/// - [`ShardIntoError::SlabFull`] -- arena cannot allocate another spec.
pub fn range_shard_into(
    arena: &mut ShardArena,
    start: &[u8],
    end: &[u8],
    connector_extra: &[u8],
    scratch: &mut ShardSpecScratch,
) -> Result<ShardSpecHandle, ShardIntoError<ShardSpecInputError>> {
    let spec =
        range_shard_ref(start, end, connector_extra, scratch).map_err(ShardIntoError::Build)?;
    arena.alloc_spec(spec).map_err(ShardIntoError::SlabFull)
}

/// Construct a borrowed prefix shard `[prefix, prefix_successor(prefix))`.
///
/// Derives the end bound via [`prefix_successor`] so the resulting shard
/// covers every key that starts with `prefix`. The hint is
/// `ShardHint::Prefix { prefix }`.
///
/// The returned `ShardSpecRef` borrows from `scratch`. Callers must allocate
/// the spec into an arena or copy it before reusing `scratch`.
///
/// # Errors
///
/// - [`PrefixShardError::PrefixTooLarge`] if `prefix.len() > MAX_KEY_SIZE`.
/// - [`PrefixShardError::EmptyPrefix`] if `prefix` is empty.
/// - [`PrefixShardError::NoSuccessor`] if `prefix` is all `0xFF`.
/// - [`PrefixShardError::InvalidShardSpec`] if downstream validation fails.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn prefix_shard_ref<'a>(
    prefix: &'a [u8],
    connector_extra: &[u8],
    scratch: &'a mut ShardSpecScratch,
) -> Result<ShardSpecRef<'a>, PrefixShardError> {
    if prefix.is_empty() {
        return Err(PrefixShardError::EmptyPrefix);
    }
    // Validate prefix size before metadata encoding so callers always see
    // PrefixTooLarge for oversized prefixes, not a generic MetadataTooLarge
    // from the hint encoder hitting the metadata capacity ceiling first.
    if prefix.len() > MAX_KEY_SIZE {
        return Err(PrefixShardError::PrefixTooLarge {
            size: prefix.len(),
            max: MAX_KEY_SIZE,
        });
    }
    let (end_buf, metadata_buf) = (&mut scratch.end, &mut scratch.metadata);
    let end = prefix_successor(prefix, end_buf).ok_or(PrefixShardError::NoSuccessor)?;
    let metadata = ShardMetadata::new(ShardHint::Prefix { prefix }, connector_extra)
        .encode_into(metadata_buf)
        .map_err(map_encode_to_prefix_error)?;
    let spec = ShardSpecRef::new(prefix, end, metadata);
    ShardSpec::validate_ref(spec).map_err(PrefixShardError::from)?;
    Ok(spec)
}

/// Build a prefix shard spec and allocate it in the given arena.
///
/// Combines [`prefix_shard_ref`] validation with arena allocation. On
/// success, returns a handle to the arena-backed spec.
///
/// # Errors
///
/// - [`ShardIntoError::Build`] -- prefix is empty, too large, all-`0xFF`,
///   or derived spec fails validation.
/// - [`ShardIntoError::SlabFull`] -- arena cannot allocate another spec.
pub fn prefix_shard_into(
    arena: &mut ShardArena,
    prefix: &[u8],
    connector_extra: &[u8],
    scratch: &mut ShardSpecScratch,
) -> Result<ShardSpecHandle, ShardIntoError<PrefixShardError>> {
    let spec = prefix_shard_ref(prefix, connector_extra, scratch).map_err(ShardIntoError::Build)?;
    arena.alloc_spec(spec).map_err(ShardIntoError::SlabFull)
}

/// Construct a borrowed same-manifest shard `[start_row, end_row)`.
///
/// Encodes `(manifest_id, start_row)` and `(manifest_id, end_row)` as
/// fixed-width [`ManifestRowKey`] boundaries and stores a
/// `ShardHint::Manifest` hint in the metadata envelope.
///
/// Returned start/end bounds and metadata borrow from `scratch`; callers
/// must allocate the spec before reusing `scratch`.
///
/// # Errors
///
/// - [`ShardSpecInputError::InvertedRange`] if `start_row >= end_row`.
/// - [`ShardSpecInputError::MetadataTooLarge`] if the metadata envelope
///   exceeds capacity (unlikely for manifest hints, which are fixed-size).
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn manifest_shard_ref<'a>(
    manifest_id: u64,
    start_row: u64,
    end_row: u64,
    connector_extra: &[u8],
    scratch: &'a mut ShardSpecScratch,
) -> Result<ShardSpecRef<'a>, ShardSpecInputError> {
    ManifestRowKey::new(manifest_id, start_row).encode_into(&mut scratch.start);
    ManifestRowKey::new(manifest_id, end_row).encode_into(&mut scratch.end);
    let (start_buf, end_buf, metadata_buf) = (&scratch.start, &scratch.end, &mut scratch.metadata);
    let metadata = ShardMetadata::new(
        ShardHint::Manifest {
            manifest_id,
            start_row,
            end_row,
        },
        connector_extra,
    )
    .encode_into(metadata_buf)
    .map_err(map_encode_to_spec_input_error)?;
    let spec = ShardSpecRef::new(start_buf.as_bytes(), end_buf.as_bytes(), metadata);
    ShardSpec::validate_ref(spec)?;
    Ok(spec)
}

/// Build a manifest-row shard spec and allocate it in the given arena.
///
/// Combines [`manifest_shard_ref`] validation with arena allocation. On
/// success, returns a handle to the arena-backed spec.
///
/// # Errors
///
/// - [`ShardIntoError::Build`] -- row range is inverted or metadata fails
///   validation.
/// - [`ShardIntoError::SlabFull`] -- arena cannot allocate another spec.
pub fn manifest_shard_into(
    arena: &mut ShardArena,
    manifest_id: u64,
    start_row: u64,
    end_row: u64,
    connector_extra: &[u8],
    scratch: &mut ShardSpecScratch,
) -> Result<ShardSpecHandle, ShardIntoError<ShardSpecInputError>> {
    let spec = manifest_shard_ref(manifest_id, start_row, end_row, connector_extra, scratch)
        .map_err(ShardIntoError::Build)?;
    arena.alloc_spec(spec).map_err(ShardIntoError::SlabFull)
}

/// Decode typed shard metadata from a borrowed shard spec view.
///
/// This applies strict envelope validation. Empty metadata is interpreted as
/// absent hint bytes and maps to [`ShardHint::Range`] with empty
/// `connector_extra`.
#[must_use = "returns a Result that must be checked for metadata decode errors"]
pub fn decode_metadata<'a, S>(spec: S) -> Result<ShardMetadata<'a>, ShardMetadataDecodeError>
where
    S: IntoShardSpecRef<'a>,
{
    let spec = spec.into_spec_ref();
    ShardMetadata::decode(spec.metadata())
}

/// Decode only the hint portion from a shard metadata envelope.
///
/// This still validates the full envelope first; malformed length prefixes or
/// hint frames are surfaced as decode errors.
#[must_use = "returns a Result that must be checked for metadata decode errors"]
pub fn decode_hint<'a, S>(spec: S) -> Result<ShardHint<'a>, ShardMetadataDecodeError>
where
    S: IntoShardSpecRef<'a>,
{
    decode_metadata(spec).map(|metadata| metadata.hint)
}

/// Decode only connector-opaque trailing bytes from a shard metadata
/// envelope.
///
/// This still validates the hint frame and envelope length prefix; it is not a
/// raw metadata slice accessor.
///
/// The returned slice borrows from `spec` and performs no allocation.
#[must_use = "returns a Result that must be checked for metadata decode errors"]
pub fn decode_connector_extra<'a, S>(spec: S) -> Result<&'a [u8], ShardMetadataDecodeError>
where
    S: IntoShardSpecRef<'a>,
{
    decode_metadata(spec).map(|metadata| metadata.connector_extra)
}

/// Split boundary selector for hint-propagation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitBoundary {
    /// Child start key.
    Start,
    /// Child end key.
    End,
}

impl fmt::Display for SplitBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Start => write!(f, "start"),
            Self::End => write!(f, "end"),
        }
    }
}

/// Errors returned by [`propagate_hint_on_split`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum HintPropagationError {
    /// Prefix child boundary falls outside the parent prefix range.
    #[error("prefix split propagation: invalid child {boundary} boundary for prefix shard")]
    InvalidPrefixBoundary {
        /// Which boundary failed validation.
        boundary: SplitBoundary,
    },
    /// Manifest child boundary is malformed or out of parent bounds.
    ///
    /// This variant covers both key-decode failures (bytes not decodable as
    /// [`ManifestRowKey`]) and decoded-key out-of-bounds conditions (row falls
    /// outside the parent's `[start_row, end_row)` interval).  Splitting into
    /// separate variants is a future option if downstream callers need to
    /// distinguish the two failure modes.
    #[error("manifest split propagation: invalid child {boundary} boundary")]
    InvalidManifestBoundary {
        /// Which boundary failed validation.
        boundary: SplitBoundary,
    },
    /// Manifest child boundary uses a different manifest ID than the parent.
    #[error("manifest split propagation: manifest_id mismatch (parent={parent}, child={child})")]
    ManifestIdMismatch {
        /// Parent manifest ID.
        parent: u64,
        /// Child boundary manifest ID.
        child: u64,
    },
    /// Manifest child rows are inverted or degenerate (`start_row >= end_row`).
    #[error("manifest split propagation: empty or inverted child range ({start_row} >= {end_row})")]
    EmptyManifestRange {
        /// Child start row.
        start_row: u64,
        /// Child end row.
        end_row: u64,
    },
}

/// Derive a child hint from `parent_hint` and child key-range boundaries.
///
/// Propagation rules:
/// - `Range` stays `Range` unconditionally — no child-boundary validation is
///   performed because Range hints carry no structural information to validate
///   against.  Callers must validate child range ordering independently.
/// - `Prefix` validates child bounds and demotes to `Range` because arbitrary
///   split boundaries inside one prefix shard are not representable as a single
///   child prefix. Connectors should treat `[child_start, child_end)` as a
///   sub-range of the original prefix scan; the parent-prefix context is
///   recoverable from shard lineage (`ShardSnapshot::parent`) rather than from
///   the child hint itself.
/// - `Manifest` validates row-key boundaries and returns a narrowed
///   `Manifest` hint.
///
/// `child_start` and `child_end` follow the same half-open interval contract as
/// [`ShardSpec`]: child range is `[child_start, child_end)`.
#[must_use = "returns a Result that must be checked for boundary validation errors"]
pub fn propagate_hint_on_split(
    parent_hint: &ShardHint<'_>,
    child_start: &[u8],
    child_end: &[u8],
) -> Result<ShardHint<'static>, HintPropagationError> {
    match parent_hint {
        ShardHint::Range => Ok(ShardHint::Range),
        ShardHint::Prefix { prefix } => {
            validate_prefix_child_bounds(prefix, child_start, child_end)?;
            Ok(ShardHint::Range)
        }
        ShardHint::Manifest {
            manifest_id,
            start_row,
            end_row,
        } => {
            let start = decode_manifest_row_key(child_start).ok_or(
                HintPropagationError::InvalidManifestBoundary {
                    boundary: SplitBoundary::Start,
                },
            )?;
            let end = decode_manifest_row_key(child_end).ok_or(
                HintPropagationError::InvalidManifestBoundary {
                    boundary: SplitBoundary::End,
                },
            )?;

            if start.manifest_id() != *manifest_id {
                return Err(HintPropagationError::ManifestIdMismatch {
                    parent: *manifest_id,
                    child: start.manifest_id(),
                });
            }
            if end.manifest_id() != *manifest_id {
                return Err(HintPropagationError::ManifestIdMismatch {
                    parent: *manifest_id,
                    child: end.manifest_id(),
                });
            }

            if start.row() < *start_row || start.row() >= *end_row {
                return Err(HintPropagationError::InvalidManifestBoundary {
                    boundary: SplitBoundary::Start,
                });
            }
            if end.row() <= *start_row || end.row() > *end_row {
                return Err(HintPropagationError::InvalidManifestBoundary {
                    boundary: SplitBoundary::End,
                });
            }
            if start.row() >= end.row() {
                return Err(HintPropagationError::EmptyManifestRange {
                    start_row: start.row(),
                    end_row: end.row(),
                });
            }

            Ok(ShardHint::Manifest {
                manifest_id: *manifest_id,
                start_row: start.row(),
                end_row: end.row(),
            })
        }
    }
}

/// Validate child bounds for a split of a prefix shard.
///
/// The child interval `[child_start, child_end)` must satisfy:
/// 1. `prefix <= child_start < prefix_successor(prefix)` -- start is inside
///    the parent prefix range.
/// 2. `prefix < child_end <= prefix_successor(prefix)` -- end does not
///    exceed the parent boundary.
/// 3. `child_start < child_end` -- the interval is non-empty.
fn validate_prefix_child_bounds(
    prefix: &[u8],
    child_start: &[u8],
    child_end: &[u8],
) -> Result<(), HintPropagationError> {
    let mut successor_buf = KeyBuf::new();
    // When `prefix_successor` returns `None`, the parent prefix either has no
    // lexicographic successor (all-0xFF or empty) or exceeds `KeyBuf` capacity.
    // `SplitBoundary::End` is reported because the successor *is* the end bound
    // and therefore cannot be formed. This path is unreachable through the
    // typed prefix helpers: empty prefixes are rejected as
    // `PrefixShardError::EmptyPrefix`, oversized prefixes as
    // `PrefixShardError::PrefixTooLarge`, and all-0xFF prefixes as
    // `PrefixShardError::NoSuccessor`.
    let successor = prefix_successor(prefix, &mut successor_buf).ok_or(
        HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::End,
        },
    )?;

    if child_start < prefix || child_start >= successor {
        return Err(HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::Start,
        });
    }
    if child_end <= prefix || child_end > successor {
        return Err(HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::End,
        });
    }
    if child_start >= child_end {
        return Err(HintPropagationError::InvalidPrefixBoundary {
            boundary: SplitBoundary::End,
        });
    }

    Ok(())
}

/// Map a [`ShardEncodeError`] to the [`ShardSpecInputError`] vocabulary
/// expected by callers of range/manifest shard constructors.
fn map_encode_to_spec_input_error(err: ShardEncodeError) -> ShardSpecInputError {
    match err {
        ShardEncodeError::PrefixTooLarge { size, .. } => ShardSpecInputError::KeyTooLarge {
            size,
            max: MAX_KEY_SIZE,
        },
        ShardEncodeError::HintTooLarge { size, max }
        | ShardEncodeError::MetadataTooLarge { size, max } => {
            ShardSpecInputError::MetadataTooLarge { size, max }
        }
        ShardEncodeError::InvertedManifestRows { .. } => ShardSpecInputError::InvertedRange {
            start_len: ManifestRowKey::ENCODED_LEN,
            end_len: ManifestRowKey::ENCODED_LEN,
        },
    }
}

/// Map a [`ShardEncodeError`] to the [`PrefixShardError`] vocabulary
/// expected by callers of prefix shard constructors.
fn map_encode_to_prefix_error(err: ShardEncodeError) -> PrefixShardError {
    match err {
        ShardEncodeError::PrefixTooLarge { size, .. } => PrefixShardError::PrefixTooLarge {
            size,
            max: MAX_KEY_SIZE,
        },
        ShardEncodeError::HintTooLarge { size, max }
        | ShardEncodeError::MetadataTooLarge { size, max } => {
            PrefixShardError::InvalidShardSpec(ShardSpecInputError::MetadataTooLarge { size, max })
        }
        ShardEncodeError::InvertedManifestRows { .. } => {
            PrefixShardError::InvalidShardSpec(ShardSpecInputError::InvertedRange {
                start_len: ManifestRowKey::ENCODED_LEN,
                end_len: ManifestRowKey::ENCODED_LEN,
            })
        }
    }
}

#[cfg(test)]
#[path = "hint_tests.rs"]
mod tests;
