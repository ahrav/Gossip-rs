//! ShardHint: connector-visible interpretation of shard domain semantics.
//!
//! The hint answers "why does this shard exist?" — metadata that the
//! coordinator stores opaquely inside `ShardSpec.metadata` and the
//! connector decodes on acquire to understand how to efficiently
//! enumerate items within the shard.
//!
//! ## Conceptual Model
//!
//! ```text
//!  CONNECTOR creates shards:            COORDINATOR sees:
//!  ────────────────────────             ─────────────────
//!
//!  PrefixShard {                        ShardSpec {
//!    prefix: "src/",                      key_range_start: b"src/",
//!    computed_end: "src0",      ──►       key_range_end:   b"src0",
//!    hint: Prefix("src/"),                metadata:        [hint_len...hint...extra],
//!  }                                    }
//!
//!  The coordinator compares start/end bytes for splits,
//!  cursor bounds, and monotonicity. It never decodes metadata.
//!
//!  When a worker acquires this shard, it decodes the hint
//!  from metadata to understand "this is a prefix shard for src/".
//! ```
//!
//! ## Design Decisions (locked)
//!
//! D3.6: ShardHint is encoded INTO `ShardSpec.metadata`, not as a
//!       separate field. This preserves the Boundary ② contract
//!       unchanged. The coordinator's ShardSpec stays at three fields
//!       (start, end, metadata). The hint is a structured subregion
//!       within the opaque metadata blob.
//!
//!       Reference: FoundationDB subspace layer — structured data
//!       encoded into opaque byte keys.
//!
//! D3.7: ShardHint uses a tagged binary format with a version byte
//!       for forward compatibility:
//!
//!       ```text
//!       byte 0:    version (currently 0x01)
//!       byte 1:    variant tag (0x00=Range, 0x01=Prefix, 0x02=Manifest)
//!       bytes 2+:  variant-specific payload
//!       ```
//!
//!       Reference: Protocol Buffers wire format — tagged fields with
//!       forward-compatible unknown-field handling.
//!
//! D3.8: ShardHint is round-trip-stable: `decode(encode(hint)) == hint`.
//!       Encoding errors produce structured errors, not panics.
//!
//! D3.9: `ShardMetadata` pairs a `ShardHint` with optional connector-
//!       specific extra data. Encoding:
//!
//!       ```text
//!       [hint_len: u32 BE] [encoded_hint] [connector_extra]
//!       ```
//!
//!       The length prefix allows tooling to skip the hint and read
//!       connector data without understanding the hint encoding.

use core::fmt;

use crate::coordination::shard_spec::ShardSpec;
use super::key_encoding::{
    ManifestRowKey,
    KeyEncoding,
    prefix_successor,
    shard_spec_from_keys,
};

use super::key_encoding::domain::SHARD_HINT_V1;

// ============================================================================
// § ShardHint — connector-visible domain semantics
// ============================================================================

/// The current encoding version for ShardHint.
///
/// Aliased from `domain::SHARD_HINT_V1` for readability in encode/decode.
/// Increment this when the binary format changes. Old versions will
/// fail to decode with `HintDecodeError::UnsupportedVersion`.
pub const SHARD_HINT_VERSION: u8 = SHARD_HINT_V1;

/// Connector-visible metadata describing the domain semantics of a shard.
///
/// ## Variant Semantics
///
/// All three variants produce the same coordinator-visible `ShardSpec`
/// with a half-open `[start, end)` byte range. The hint exists solely
/// for the connector to understand *why* the shard has those boundaries
/// and how to efficiently enumerate items within them.
///
/// ```text
///   Coordinator view (identical for all):
///
///   ShardSpec { start: [...], end: [...], metadata: [...] }
///
///   Connector view (distinguished by hint):
///
///   Range    → "scan everything in [start, end) in lex order"
///   Prefix   → "scan everything under this path prefix"
///   Manifest → "scan rows N..M from manifest file #K"
/// ```
///
/// ## Why an Enum (Not a Trait)
///
/// These are the three domain patterns we support. They are closed-world
/// (not extensible by connectors) because:
/// 1. The encoding format is in the contracts crate.
/// 2. Split logic needs to understand the variant for hint propagation.
/// 3. New variants require new encoding tags and split strategies.
///
/// Connectors that don't fit these patterns use `Range` with
/// connector-specific data in the extra metadata portion.
///
/// Reference: Spanner (Corbett et al., OSDI 2012) — tablets are always
/// key ranges, but the key encoding scheme gives different ranges
/// different semantic meaning while the tablet layer sees only bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardHint {
    /// Generic range shard: scan `[start, end)` in lex order.
    ///
    /// No additional semantic information beyond the key range.
    /// The connector iterates items whose encoded keys fall in the range.
    ///
    /// This is the default for connectors that partition by arbitrary
    /// key splits (e.g., filesystem paths divided at arbitrary midpoints).
    Range,

    /// Prefix shard: scan all items whose keys start with `prefix`.
    ///
    /// The shard's `[start, end)` is computed as
    /// `[prefix, prefix_successor(prefix))`. The hint stores the
    /// original prefix so the connector can use prefix-based listing
    /// APIs (e.g., S3 `ListObjectsV2` with `Prefix` parameter, GitHub
    /// tree listing for a directory).
    ///
    /// ## Why store the prefix separately?
    ///
    /// The `key_range_start` IS the prefix, and `key_range_end` is its
    /// successor. But a connector reading the ShardSpec cannot reliably
    /// reconstruct "this was a prefix shard" from the raw bytes alone —
    /// `key_range_end == prefix_successor(key_range_start)` could be
    /// coincidental. The hint makes the semantics explicit.
    ///
    /// ## Split Propagation
    ///
    /// When a prefix shard is split, child shards lose the Prefix hint
    /// (they become Range shards) unless the split happens at a sub-prefix
    /// boundary.
    Prefix {
        /// The original prefix bytes.
        prefix: Box<[u8]>,
    },

    /// Manifest shard: scan a row range from a pre-built manifest.
    ///
    /// The manifest is an external file (or database table) that lists
    /// all items to scan. Each row is a work unit. The shard covers
    /// rows `[start_row, end_row)` within the manifest identified by
    /// `manifest_id`.
    ///
    /// ## Encoding Alignment
    ///
    /// The shard's `[start, end)` is the `ManifestRowKey` encoding of
    /// `(manifest_id, start_row)` and `(manifest_id, end_row)`. The
    /// hint stores the decoded form for connector convenience.
    ///
    /// ## Split Propagation
    ///
    /// When a manifest shard is split, child shards inherit the
    /// Manifest hint with adjusted row ranges. The split point must
    /// fall on a row boundary (no fractional rows).
    Manifest {
        /// Manifest file identifier.
        manifest_id: u64,
        /// First row in this shard's range (inclusive).
        start_row: u64,
        /// Last row in this shard's range (exclusive).
        end_row: u64,
    },
}

/// Variant discriminant tags for binary encoding.
///
/// These are stable across versions. Adding a new variant means
/// adding a new tag — never reusing or reordering existing ones.
impl ShardHint {
    pub(crate) const TAG_RANGE: u8 = 0x00;
    pub(crate) const TAG_PREFIX: u8 = 0x01;
    pub(crate) const TAG_MANIFEST: u8 = 0x02;
}

// ── Accessor methods ────────────────────────────────────────────────

impl ShardHint {
    /// Returns `true` if this is a `Range` hint.
    #[inline]
    pub fn is_range(&self) -> bool {
        matches!(self, ShardHint::Range)
    }

    /// Returns `true` if this is a `Prefix` hint.
    #[inline]
    pub fn is_prefix(&self) -> bool {
        matches!(self, ShardHint::Prefix { .. })
    }

    /// Returns `true` if this is a `Manifest` hint.
    #[inline]
    pub fn is_manifest(&self) -> bool {
        matches!(self, ShardHint::Manifest { .. })
    }

    /// Extract the prefix bytes if this is a `Prefix` hint.
    pub fn prefix(&self) -> Option<&[u8]> {
        match self {
            ShardHint::Prefix { prefix } => Some(prefix),
            _ => None,
        }
    }

    /// Extract manifest fields if this is a `Manifest` hint.
    ///
    /// Returns `(manifest_id, start_row, end_row)`.
    pub fn manifest_fields(&self) -> Option<(u64, u64, u64)> {
        match self {
            ShardHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => Some((*manifest_id, *start_row, *end_row)),
            _ => None,
        }
    }
}

// ============================================================================
// § ShardHint Binary Encoding
// ============================================================================

impl ShardHint {
    /// Encode this hint into a byte buffer.
    ///
    /// Format:
    /// ```text
    /// version: u8      (SHARD_HINT_VERSION)
    /// tag:     u8      (variant discriminant)
    /// payload: [u8]    (variant-specific, self-describing)
    /// ```
    ///
    /// Payload by variant:
    /// - Range:    (empty — no payload)
    /// - Prefix:   prefix_len: u32 BE, prefix_bytes
    /// - Manifest: manifest_id: u64 BE, start_row: u64 BE, end_row: u64 BE
    pub fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.push(SHARD_HINT_VERSION);

        match self {
            ShardHint::Range => {
                buf.push(Self::TAG_RANGE);
                // No payload.
            }
            ShardHint::Prefix { prefix } => {
                buf.push(Self::TAG_PREFIX);
                assert!(
                    prefix.len() <= u32::MAX as usize,
                    "ShardHint: prefix too long"
                );
                buf.extend_from_slice(&(prefix.len() as u32).to_be_bytes());
                buf.extend_from_slice(prefix);
            }
            ShardHint::Manifest {
                manifest_id,
                start_row,
                end_row,
            } => {
                assert!(
                    start_row < end_row,
                    "ShardHint::Manifest: start_row must be < end_row"
                );
                buf.push(Self::TAG_MANIFEST);
                buf.extend_from_slice(&manifest_id.to_be_bytes());
                buf.extend_from_slice(&start_row.to_be_bytes());
                buf.extend_from_slice(&end_row.to_be_bytes());
            }
        }
    }

    /// Encode this hint into a new `Vec<u8>`.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.encoded_len());
        self.encode_to(&mut buf);
        buf
    }

    /// The encoded byte length of this hint (for pre-allocation).
    pub fn encoded_len(&self) -> usize {
        let header = 2; // version + tag
        match self {
            ShardHint::Range => header,
            ShardHint::Prefix { prefix } => header + 4 + prefix.len(),
            ShardHint::Manifest { .. } => header + 24, // 3 × u64
        }
    }

    /// Decode a hint from a byte slice.
    ///
    /// Returns the decoded hint and the number of bytes consumed.
    /// The caller can use the consumed count to find the start of
    /// connector-extra data in the metadata blob.
    ///
    /// This function does NOT panic on invalid input — it returns a
    /// structured error. Metadata may be corrupt or from a newer
    /// version.
    pub fn decode(data: &[u8]) -> Result<(ShardHint, usize), HintDecodeError> {
        if data.len() < 2 {
            return Err(HintDecodeError::TooShort {
                expected_min: 2,
                actual: data.len(),
            });
        }

        let version = data[0];
        if version != SHARD_HINT_VERSION {
            return Err(HintDecodeError::UnsupportedVersion {
                found: version,
                expected: SHARD_HINT_VERSION,
            });
        }

        let tag = data[1];
        match tag {
            Self::TAG_RANGE => Ok((ShardHint::Range, 2)),

            Self::TAG_PREFIX => {
                // Need at least: version(1) + tag(1) + prefix_len(4) = 6
                if data.len() < 6 {
                    return Err(HintDecodeError::TooShort {
                        expected_min: 6,
                        actual: data.len(),
                    });
                }
                let prefix_len =
                    u32::from_be_bytes(data[2..6].try_into().unwrap()) as usize;
                let total = 6 + prefix_len;
                if data.len() < total {
                    return Err(HintDecodeError::TooShort {
                        expected_min: total,
                        actual: data.len(),
                    });
                }
                let prefix = data[6..total].to_vec().into_boxed_slice();
                Ok((ShardHint::Prefix { prefix }, total))
            }

            Self::TAG_MANIFEST => {
                // Need: version(1) + tag(1) + 3 × u64(24) = 26
                let total = 2 + 24;
                if data.len() < total {
                    return Err(HintDecodeError::TooShort {
                        expected_min: total,
                        actual: data.len(),
                    });
                }
                let manifest_id =
                    u64::from_be_bytes(data[2..10].try_into().unwrap());
                let start_row =
                    u64::from_be_bytes(data[10..18].try_into().unwrap());
                let end_row =
                    u64::from_be_bytes(data[18..26].try_into().unwrap());

                if start_row >= end_row {
                    return Err(HintDecodeError::InvalidPayload {
                        reason: format!(
                            "Manifest: start_row {} >= end_row {}",
                            start_row, end_row,
                        ),
                    });
                }

                Ok((
                    ShardHint::Manifest {
                        manifest_id,
                        start_row,
                        end_row,
                    },
                    total,
                ))
            }

            _ => Err(HintDecodeError::UnknownTag { tag }),
        }
    }
}

// ============================================================================
// § HintDecodeError
// ============================================================================

/// Errors from decoding a `ShardHint` from bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HintDecodeError {
    /// The byte slice is too short to contain the expected data.
    TooShort {
        expected_min: usize,
        actual: usize,
    },
    /// The version byte is not recognized.
    UnsupportedVersion { found: u8, expected: u8 },
    /// The variant tag is not recognized.
    UnknownTag { tag: u8 },
    /// The payload is structurally valid but semantically invalid.
    InvalidPayload { reason: String },
}

impl fmt::Display for HintDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort {
                expected_min,
                actual,
            } => write!(
                f,
                "hint data too short: need at least {} bytes, got {}",
                expected_min, actual,
            ),
            Self::UnsupportedVersion { found, expected } => write!(
                f,
                "unsupported hint version: found 0x{:02X}, expected 0x{:02X}",
                found, expected,
            ),
            Self::UnknownTag { tag } => {
                write!(f, "unknown hint variant tag: 0x{:02X}", tag)
            }
            Self::InvalidPayload { reason } => {
                write!(f, "invalid hint payload: {}", reason)
            }
        }
    }
}

// ============================================================================
// § ShardMetadata — structured metadata blob
// ============================================================================

/// Structured metadata that is encoded into `ShardSpec.metadata`.
///
/// Pairs a `ShardHint` (how the connector interprets this shard's domain)
/// with optional connector-specific extra data (repository URLs,
/// authentication tokens, bucket names, etc.).
///
/// ## Encoding
///
/// ```text
/// ┌───────────────────────┬────────────────────┬──────────────────┐
/// │ hint_len (4 bytes BE) │ encoded_hint       │ connector_extra  │
/// └───────────────────────┴────────────────────┴──────────────────┘
/// ```
///
/// The `hint_len` prefix allows tooling to skip the hint and read
/// connector data directly, and allows the connector to skip
/// connector data and read only the hint.
///
/// ## Invariants
///
/// **Safety (round-trip)**: `decode(encode(metadata)) == metadata`.
///
/// **Safety (isolation)**: The hint encoding and connector_extra are
/// independent. Changing the hint format does not corrupt connector
/// data, and vice versa.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardMetadata {
    /// How the connector interprets this shard's domain.
    pub hint: ShardHint,

    /// Connector-specific opaque data.
    ///
    /// Repository identifiers, authentication scopes, bucket names,
    /// connector configuration, etc. The contracts crate stores this
    /// verbatim and never inspects it.
    pub connector_extra: Box<[u8]>,
}

impl ShardMetadata {
    /// Construct with a hint and no extra data.
    pub fn from_hint(hint: ShardHint) -> Self {
        Self {
            hint,
            connector_extra: Box::new([]),
        }
    }

    /// Construct with a hint and connector-specific extra data.
    pub fn new(hint: ShardHint, connector_extra: Vec<u8>) -> Self {
        Self {
            hint,
            connector_extra: connector_extra.into_boxed_slice(),
        }
    }

    /// Encode into the `metadata` bytes for a `ShardSpec`.
    pub fn encode(&self) -> Vec<u8> {
        let hint_bytes = self.hint.encode();
        assert!(
            hint_bytes.len() <= u32::MAX as usize,
            "ShardMetadata: hint encoding too large"
        );

        let mut buf = Vec::with_capacity(
            4 + hint_bytes.len() + self.connector_extra.len(),
        );
        buf.extend_from_slice(&(hint_bytes.len() as u32).to_be_bytes());
        buf.extend_from_slice(&hint_bytes);
        buf.extend_from_slice(&self.connector_extra);
        buf
    }

    /// Decode from the `metadata` bytes of a `ShardSpec`.
    ///
    /// Returns the decoded metadata or an error if the encoding is
    /// invalid. Does not panic — metadata may be corrupt.
    ///
    /// **Backward compatibility**: Empty metadata decodes to
    /// `ShardHint::Range` with no extra data. This handles ShardSpecs
    /// constructed without structured metadata (legacy B2-era specs).
    pub fn decode(data: &[u8]) -> Result<Self, ShardMetadataDecodeError> {
        if data.is_empty() {
            // Empty metadata → Range hint, no extra data.
            // Backward-compatible default for unstructured ShardSpecs.
            return Ok(Self::from_hint(ShardHint::Range));
        }

        if data.len() < 4 {
            return Err(ShardMetadataDecodeError::TooShort {
                expected_min: 4,
                actual: data.len(),
            });
        }

        let hint_len =
            u32::from_be_bytes(data[0..4].try_into().unwrap()) as usize;

        let hint_end = 4 + hint_len;
        if data.len() < hint_end {
            return Err(ShardMetadataDecodeError::TooShort {
                expected_min: hint_end,
                actual: data.len(),
            });
        }

        let hint_data = &data[4..hint_end];
        let (hint, consumed) = ShardHint::decode(hint_data)
            .map_err(ShardMetadataDecodeError::HintError)?;

        // Verify the hint consumed exactly the bytes we expected.
        if consumed != hint_len {
            return Err(ShardMetadataDecodeError::HintLengthMismatch {
                declared: hint_len,
                consumed,
            });
        }

        let connector_extra = data[hint_end..].to_vec().into_boxed_slice();

        Ok(Self {
            hint,
            connector_extra,
        })
    }
}

// ============================================================================
// § ShardMetadataDecodeError
// ============================================================================

/// Errors from decoding `ShardMetadata`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShardMetadataDecodeError {
    /// Metadata blob is too short.
    TooShort {
        expected_min: usize,
        actual: usize,
    },
    /// The hint portion failed to decode.
    HintError(HintDecodeError),
    /// The declared hint length doesn't match what the hint decoder consumed.
    HintLengthMismatch { declared: usize, consumed: usize },
}

impl fmt::Display for ShardMetadataDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort {
                expected_min,
                actual,
            } => write!(
                f,
                "metadata too short: need at least {} bytes, got {}",
                expected_min, actual,
            ),
            Self::HintError(e) => write!(f, "hint decode error: {}", e),
            Self::HintLengthMismatch {
                declared,
                consumed,
            } => write!(
                f,
                "hint length mismatch: declared {} bytes, consumed {}",
                declared, consumed,
            ),
        }
    }
}

// ============================================================================
// § Typed Shard Constructors
// ============================================================================

/// Construct a `ShardSpec` for a generic key range with a Range hint.
///
/// This is the most common shard type: an arbitrary byte range with
/// no special domain semantics beyond "scan everything in `[start, end)`".
///
/// # Panics
///
/// Panics if `start >= end` (delegated to `ShardSpec::with_range_and_metadata`).
pub fn range_shard(
    start: Vec<u8>,
    end: Vec<u8>,
    connector_extra: Vec<u8>,
) -> ShardSpec {
    let metadata = ShardMetadata::new(ShardHint::Range, connector_extra);
    ShardSpec::with_range_and_metadata(start, end, metadata.encode())
}

/// Construct a `ShardSpec` for a prefix range with a Prefix hint.
///
/// Computes the end key via `prefix_successor` and stores the original
/// prefix in the hint. The connector can recover the prefix from the
/// hint on acquire.
///
/// If the prefix has no successor (all 0xFF), the end is unbounded.
///
/// # Panics
///
/// Panics if `prefix` is empty (use `ShardSpec::unbounded()` instead).
pub fn prefix_shard(prefix: Vec<u8>, connector_extra: Vec<u8>) -> ShardSpec {
    assert!(!prefix.is_empty(), "prefix_shard: prefix must not be empty");

    let end = prefix_successor(&prefix).unwrap_or_default();
    let hint = ShardHint::Prefix {
        prefix: prefix.clone().into_boxed_slice(),
    };
    let metadata = ShardMetadata::new(hint, connector_extra);
    ShardSpec::with_range_and_metadata(prefix, end, metadata.encode())
}

/// Construct a `ShardSpec` for a manifest row range with a Manifest hint.
///
/// Encodes the row range boundaries using `ManifestRowKey` and stores
/// the decoded fields in the hint for connector convenience.
///
/// # Panics
///
/// Panics if `start_row >= end_row`.
pub fn manifest_shard(
    manifest_id: u64,
    start_row: u64,
    end_row: u64,
    connector_extra: Vec<u8>,
) -> ShardSpec {
    assert!(
        start_row < end_row,
        "manifest_shard: start_row {} must be < end_row {}",
        start_row,
        end_row,
    );

    let start_key = ManifestRowKey::new(manifest_id, start_row);
    let end_key = ManifestRowKey::new(manifest_id, end_row);

    let hint = ShardHint::Manifest {
        manifest_id,
        start_row,
        end_row,
    };
    let metadata = ShardMetadata::new(hint, connector_extra);
    shard_spec_from_keys(&start_key, &end_key, metadata.encode())
}

// ============================================================================
// § Metadata Extraction Helpers (ShardSpec extensions)
// ============================================================================

/// Extension methods for `ShardSpec` to access structured metadata.
///
/// These are convenience methods that decode the hint from the
/// metadata blob. They are for connector use, NOT coordinator use.
///
/// ## Error Handling
///
/// These methods return `Result` rather than panicking because the
/// metadata may have been written by a different (possibly buggy)
/// version of the connector. Graceful degradation is better than
/// crashing the worker.
impl ShardSpec {
    /// Decode the structured metadata from this spec.
    ///
    /// Returns the hint and connector extra data.
    ///
    /// If metadata is empty, returns `ShardHint::Range` with no extra data
    /// (backward-compatible default for ShardSpecs from B2).
    pub fn decode_metadata(&self) -> Result<ShardMetadata, ShardMetadataDecodeError> {
        ShardMetadata::decode(&self.metadata)
    }

    /// Extract just the `ShardHint`, discarding connector extra data.
    pub fn decode_hint(&self) -> Result<ShardHint, ShardMetadataDecodeError> {
        self.decode_metadata().map(|m| m.hint)
    }

    /// Extract just the connector extra data, discarding the hint.
    pub fn decode_connector_extra(
        &self,
    ) -> Result<Box<[u8]>, ShardMetadataDecodeError> {
        self.decode_metadata().map(|m| m.connector_extra)
    }
}

// ============================================================================
// § Split Hint Propagation
// ============================================================================

/// Compute the appropriate `ShardHint` for a child shard created by
/// splitting a parent.
///
/// ## Rules
///
/// | Parent Hint     | Child Hint                                        |
/// |-----------------|---------------------------------------------------|
/// | Range           | Range (always)                                    |
/// | Prefix          | Range (child no longer covers exactly one prefix) |
/// | Manifest        | Manifest with adjusted row range                  |
///
/// ## Why Prefix → Range on split
///
/// After splitting, the child's range is a subrange of the prefix.
/// The connector should use range-based listing, not prefix-based.
/// Demoting to Range makes this explicit.
///
/// ## Why Manifest propagates
///
/// Manifest shards have clear row-level structure. The split point is
/// a row boundary, so the child gets the appropriate sub-range of rows.
pub fn propagate_hint_on_split(
    parent_hint: &ShardHint,
    child_start: &[u8],
    child_end: &[u8],
) -> Result<ShardHint, HintPropagationError> {
    match parent_hint {
        ShardHint::Range => Ok(ShardHint::Range),

        ShardHint::Prefix { .. } => {
            // Demote to Range — child no longer covers an exact prefix.
            Ok(ShardHint::Range)
        }

        ShardHint::Manifest { manifest_id, .. } => {
            let start_mrk = decode_manifest_row_key(child_start)
                .ok_or(HintPropagationError::InvalidManifestBoundary {
                    boundary: "start".into(),
                    bytes: child_start.to_vec().into_boxed_slice(),
                })?;
            let end_mrk = decode_manifest_row_key(child_end)
                .ok_or(HintPropagationError::InvalidManifestBoundary {
                    boundary: "end".into(),
                    bytes: child_end.to_vec().into_boxed_slice(),
                })?;

            if start_mrk.manifest_id != *manifest_id {
                return Err(HintPropagationError::ManifestIdMismatch {
                    parent: *manifest_id,
                    child: start_mrk.manifest_id,
                });
            }
            if end_mrk.manifest_id != *manifest_id {
                return Err(HintPropagationError::ManifestIdMismatch {
                    parent: *manifest_id,
                    child: end_mrk.manifest_id,
                });
            }

            assert!(
                start_mrk.row < end_mrk.row,
                "child manifest range must be non-empty"
            );

            Ok(ShardHint::Manifest {
                manifest_id: *manifest_id,
                start_row: start_mrk.row,
                end_row: end_mrk.row,
            })
        }
    }
}

/// Decode a `ManifestRowKey` from encoded bytes.
///
/// Returns `None` if the bytes are not exactly 16 bytes.
fn decode_manifest_row_key(bytes: &[u8]) -> Option<ManifestRowKey> {
    if bytes.len() != ManifestRowKey::ENCODED_LEN {
        return None;
    }
    let manifest_id = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let row = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    Some(ManifestRowKey::new(manifest_id, row))
}

// ============================================================================
// § HintPropagationError
// ============================================================================

/// Errors from hint propagation during shard splits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HintPropagationError {
    /// Child key range boundary is not a valid ManifestRowKey encoding.
    InvalidManifestBoundary {
        boundary: String,
        bytes: Box<[u8]>,
    },
    /// Child's manifest_id doesn't match the parent's.
    ManifestIdMismatch { parent: u64, child: u64 },
}

impl fmt::Display for HintPropagationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifestBoundary { boundary, bytes } => write!(
                f,
                "child {} boundary ({} bytes) is not a valid ManifestRowKey",
                boundary,
                bytes.len(),
            ),
            Self::ManifestIdMismatch { parent, child } => write!(
                f,
                "manifest_id mismatch: parent={}, child={}",
                parent, child,
            ),
        }
    }
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── ShardHint encode/decode round-trip ──────────────────────────────

    #[test]
    fn hint_range_round_trip() {
        let hint = ShardHint::Range;
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hint_prefix_round_trip() {
        let hint = ShardHint::Prefix {
            prefix: b"src/auth/".to_vec().into_boxed_slice(),
        };
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hint_manifest_round_trip() {
        let hint = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 1000,
            end_row: 2000,
        };
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hint_prefix_empty_prefix_round_trip() {
        // An empty prefix is structurally valid at the hint level
        // (the typed shard constructor rejects it, not the hint).
        let hint = ShardHint::Prefix {
            prefix: Box::new([]),
        };
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hint_prefix_long_prefix_round_trip() {
        let prefix = vec![0xAB; 1024]; // 1KB prefix
        let hint = ShardHint::Prefix {
            prefix: prefix.into_boxed_slice(),
        };
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn hint_manifest_edge_rows_round_trip() {
        let hint = ShardHint::Manifest {
            manifest_id: u64::MAX,
            start_row: 0,
            end_row: 1,
        };
        let encoded = hint.encode();
        let (decoded, consumed) = ShardHint::decode(&encoded).unwrap();
        assert_eq!(decoded, hint);
        assert_eq!(consumed, encoded.len());
    }

    // ── Encoded lengths ────────────────────────────────────────────────

    #[test]
    fn hint_encoded_lengths_match() {
        let hints = vec![
            ShardHint::Range,
            ShardHint::Prefix {
                prefix: b"test".to_vec().into_boxed_slice(),
            },
            ShardHint::Manifest {
                manifest_id: 1,
                start_row: 0,
                end_row: 100,
            },
        ];
        for hint in &hints {
            let encoded = hint.encode();
            assert_eq!(
                encoded.len(),
                hint.encoded_len(),
                "encoded_len mismatch for {:?}",
                hint,
            );
        }
    }

    #[test]
    fn hint_range_is_minimal() {
        // Range hint should be the smallest: just version + tag = 2 bytes.
        let hint = ShardHint::Range;
        assert_eq!(hint.encoded_len(), 2);
        assert_eq!(hint.encode().len(), 2);
    }

    #[test]
    fn hint_manifest_is_fixed_size() {
        // Manifest hint is always 2 + 24 = 26 bytes regardless of field values.
        let small = ShardHint::Manifest {
            manifest_id: 0,
            start_row: 0,
            end_row: 1,
        };
        let large = ShardHint::Manifest {
            manifest_id: u64::MAX,
            start_row: u64::MAX - 1,
            end_row: u64::MAX,
        };
        assert_eq!(small.encoded_len(), 26);
        assert_eq!(large.encoded_len(), 26);
    }

    // ── Encoding format verification ───────────────────────────────────

    #[test]
    fn hint_range_encoding_format() {
        let encoded = ShardHint::Range.encode();
        assert_eq!(encoded, vec![SHARD_HINT_VERSION, ShardHint::TAG_RANGE]);
    }

    #[test]
    fn hint_prefix_encoding_format() {
        let hint = ShardHint::Prefix {
            prefix: b"ab".to_vec().into_boxed_slice(),
        };
        let encoded = hint.encode();
        // version(1) + tag(1) + prefix_len(4 BE) + prefix(2)
        assert_eq!(encoded.len(), 8);
        assert_eq!(encoded[0], SHARD_HINT_VERSION);
        assert_eq!(encoded[1], ShardHint::TAG_PREFIX);
        assert_eq!(&encoded[2..6], &2u32.to_be_bytes());
        assert_eq!(&encoded[6..8], b"ab");
    }

    #[test]
    fn hint_manifest_encoding_format() {
        let hint = ShardHint::Manifest {
            manifest_id: 7,
            start_row: 100,
            end_row: 200,
        };
        let encoded = hint.encode();
        assert_eq!(encoded.len(), 26);
        assert_eq!(encoded[0], SHARD_HINT_VERSION);
        assert_eq!(encoded[1], ShardHint::TAG_MANIFEST);
        assert_eq!(&encoded[2..10], &7u64.to_be_bytes());
        assert_eq!(&encoded[10..18], &100u64.to_be_bytes());
        assert_eq!(&encoded[18..26], &200u64.to_be_bytes());
    }

    // ── Accessor methods ───────────────────────────────────────────────

    #[test]
    fn hint_accessors() {
        assert!(ShardHint::Range.is_range());
        assert!(!ShardHint::Range.is_prefix());
        assert!(!ShardHint::Range.is_manifest());
        assert!(ShardHint::Range.prefix().is_none());
        assert!(ShardHint::Range.manifest_fields().is_none());

        let prefix_hint = ShardHint::Prefix {
            prefix: b"src/".to_vec().into_boxed_slice(),
        };
        assert!(!prefix_hint.is_range());
        assert!(prefix_hint.is_prefix());
        assert_eq!(prefix_hint.prefix().unwrap(), b"src/");
        assert!(prefix_hint.manifest_fields().is_none());

        let manifest_hint = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 10,
            end_row: 20,
        };
        assert!(!manifest_hint.is_range());
        assert!(manifest_hint.is_manifest());
        assert!(manifest_hint.prefix().is_none());
        assert_eq!(manifest_hint.manifest_fields().unwrap(), (42, 10, 20));
    }

    // ── ShardHint decode errors ────────────────────────────────────────

    #[test]
    fn hint_decode_empty_is_too_short() {
        let err = ShardHint::decode(&[]).unwrap_err();
        assert!(matches!(
            err,
            HintDecodeError::TooShort {
                expected_min: 2,
                actual: 0
            }
        ));
    }

    #[test]
    fn hint_decode_single_byte_is_too_short() {
        let err = ShardHint::decode(&[SHARD_HINT_VERSION]).unwrap_err();
        assert!(matches!(
            err,
            HintDecodeError::TooShort {
                expected_min: 2,
                actual: 1
            }
        ));
    }

    #[test]
    fn hint_decode_bad_version() {
        let err = ShardHint::decode(&[0xFF, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            HintDecodeError::UnsupportedVersion { found: 0xFF, .. }
        ));
    }

    #[test]
    fn hint_decode_version_zero_rejected() {
        let err = ShardHint::decode(&[0x00, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            HintDecodeError::UnsupportedVersion { found: 0x00, .. }
        ));
    }

    #[test]
    fn hint_decode_unknown_tag() {
        let err =
            ShardHint::decode(&[SHARD_HINT_VERSION, 0xFF]).unwrap_err();
        assert!(matches!(err, HintDecodeError::UnknownTag { tag: 0xFF }));
    }

    #[test]
    fn hint_decode_unknown_tag_0x03() {
        // Next unused tag after Manifest.
        let err =
            ShardHint::decode(&[SHARD_HINT_VERSION, 0x03]).unwrap_err();
        assert!(matches!(err, HintDecodeError::UnknownTag { tag: 0x03 }));
    }

    #[test]
    fn hint_decode_prefix_truncated_length() {
        // Has version + tag but truncated prefix_len.
        let data = vec![SHARD_HINT_VERSION, ShardHint::TAG_PREFIX, 0x00];
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(err, HintDecodeError::TooShort { .. }));
    }

    #[test]
    fn hint_decode_prefix_truncated_payload() {
        // Declares 10-byte prefix but only provides 2 bytes.
        let mut data = vec![SHARD_HINT_VERSION, ShardHint::TAG_PREFIX];
        data.extend_from_slice(&10u32.to_be_bytes());
        data.extend_from_slice(b"ab"); // only 2 of 10
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            HintDecodeError::TooShort {
                expected_min: 16, // 6 + 10
                ..
            }
        ));
    }

    #[test]
    fn hint_decode_manifest_truncated() {
        // Has version + tag but truncated u64 fields.
        let mut data = vec![SHARD_HINT_VERSION, ShardHint::TAG_MANIFEST];
        data.extend_from_slice(&42u64.to_be_bytes());
        // Missing start_row and end_row.
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(err, HintDecodeError::TooShort { .. }));
    }

    #[test]
    fn hint_decode_manifest_inverted_rows() {
        let mut data = vec![SHARD_HINT_VERSION, ShardHint::TAG_MANIFEST];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&100u64.to_be_bytes()); // start
        data.extend_from_slice(&50u64.to_be_bytes()); // end < start!
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(err, HintDecodeError::InvalidPayload { .. }));
    }

    #[test]
    fn hint_decode_manifest_equal_rows() {
        let mut data = vec![SHARD_HINT_VERSION, ShardHint::TAG_MANIFEST];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&100u64.to_be_bytes()); // start
        data.extend_from_slice(&100u64.to_be_bytes()); // end == start!
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(err, HintDecodeError::InvalidPayload { .. }));
    }

    // ── Decode consumes only its bytes (extra trailing data ignored) ────

    #[test]
    fn hint_decode_range_with_trailing_data() {
        let mut data = ShardHint::Range.encode();
        data.extend_from_slice(b"trailing garbage");
        let (hint, consumed) = ShardHint::decode(&data).unwrap();
        assert_eq!(hint, ShardHint::Range);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn hint_decode_prefix_with_trailing_data() {
        let original = ShardHint::Prefix {
            prefix: b"test/".to_vec().into_boxed_slice(),
        };
        let mut data = original.encode();
        data.extend_from_slice(b"extra");
        let (hint, consumed) = ShardHint::decode(&data).unwrap();
        assert_eq!(hint, original);
        assert_eq!(consumed, original.encoded_len());
    }

    // ── HintDecodeError Display ────────────────────────────────────────

    #[test]
    fn hint_decode_error_display() {
        let e = HintDecodeError::TooShort {
            expected_min: 10,
            actual: 3,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("too short"));
        assert!(msg.contains("10"));
        assert!(msg.contains("3"));

        let e = HintDecodeError::UnsupportedVersion {
            found: 0x99,
            expected: 0x01,
        };
        assert!(format!("{}", e).contains("0x99"));

        let e = HintDecodeError::UnknownTag { tag: 0xAB };
        assert!(format!("{}", e).contains("0xAB"));

        let e = HintDecodeError::InvalidPayload {
            reason: "bad rows".into(),
        };
        assert!(format!("{}", e).contains("bad rows"));
    }

    // ── ShardMetadata encode/decode round-trip ─────────────────────────

    #[test]
    fn metadata_range_no_extra_round_trip() {
        let meta = ShardMetadata::from_hint(ShardHint::Range);
        let encoded = meta.encode();
        let decoded = ShardMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn metadata_prefix_with_extra_round_trip() {
        let meta = ShardMetadata::new(
            ShardHint::Prefix {
                prefix: b"data/".to_vec().into_boxed_slice(),
            },
            b"repo:my-repo;branch:main".to_vec(),
        );
        let encoded = meta.encode();
        let decoded = ShardMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn metadata_manifest_with_extra_round_trip() {
        let meta = ShardMetadata::new(
            ShardHint::Manifest {
                manifest_id: 7,
                start_row: 0,
                end_row: 5000,
            },
            b"s3://bucket/manifest-007.csv".to_vec(),
        );
        let encoded = meta.encode();
        let decoded = ShardMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded, meta);
    }

    #[test]
    fn metadata_range_with_large_extra_round_trip() {
        let extra = vec![0xAB; 4096]; // 4KB connector data
        let meta = ShardMetadata::new(ShardHint::Range, extra);
        let encoded = meta.encode();
        let decoded = ShardMetadata::decode(&encoded).unwrap();
        assert_eq!(decoded, meta);
    }

    // ── ShardMetadata backward compatibility ───────────────────────────

    #[test]
    fn metadata_empty_is_backward_compatible() {
        // Empty metadata from B2-era ShardSpecs → Range, no extra.
        let decoded = ShardMetadata::decode(&[]).unwrap();
        assert_eq!(decoded.hint, ShardHint::Range);
        assert!(decoded.connector_extra.is_empty());
    }

    // ── ShardMetadata encoding format ──────────────────────────────────

    #[test]
    fn metadata_encoding_structure() {
        let meta = ShardMetadata::new(
            ShardHint::Range,
            b"extra".to_vec(),
        );
        let encoded = meta.encode();

        // hint_len (4 BE) + hint (2 bytes for Range) + extra (5 bytes)
        assert_eq!(encoded.len(), 4 + 2 + 5);

        // First 4 bytes: hint_len = 2
        assert_eq!(&encoded[0..4], &2u32.to_be_bytes());

        // Next 2 bytes: the Range hint encoding
        assert_eq!(encoded[4], SHARD_HINT_VERSION);
        assert_eq!(encoded[5], ShardHint::TAG_RANGE);

        // Remaining: connector_extra
        assert_eq!(&encoded[6..], b"extra");
    }

    #[test]
    fn metadata_hint_and_extra_are_isolated() {
        // Changing the hint doesn't corrupt connector_extra and vice versa.
        let extra = b"stable-data".to_vec();

        let meta_range = ShardMetadata::new(ShardHint::Range, extra.clone());
        let meta_prefix = ShardMetadata::new(
            ShardHint::Prefix {
                prefix: b"src/".to_vec().into_boxed_slice(),
            },
            extra.clone(),
        );

        let dec_range =
            ShardMetadata::decode(&meta_range.encode()).unwrap();
        let dec_prefix =
            ShardMetadata::decode(&meta_prefix.encode()).unwrap();

        // Same extra data despite different hints.
        assert_eq!(
            dec_range.connector_extra.as_ref(),
            dec_prefix.connector_extra.as_ref()
        );
        assert_eq!(dec_range.connector_extra.as_ref(), b"stable-data");
    }

    // ── ShardMetadata decode errors ────────────────────────────────────

    #[test]
    fn metadata_decode_too_short_for_length_prefix() {
        let err = ShardMetadata::decode(&[0x00, 0x00]).unwrap_err();
        assert!(matches!(
            err,
            ShardMetadataDecodeError::TooShort {
                expected_min: 4,
                ..
            }
        ));
    }

    #[test]
    fn metadata_decode_truncated_hint() {
        // Declares 100-byte hint but only 2 bytes follow.
        let mut data = vec![];
        data.extend_from_slice(&100u32.to_be_bytes());
        data.extend_from_slice(&[0x01, 0x00]); // version + range tag
        let err = ShardMetadata::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            ShardMetadataDecodeError::TooShort { .. }
        ));
    }

    #[test]
    fn metadata_decode_hint_error_propagated() {
        // Valid length prefix pointing to data with bad version.
        let mut data = vec![];
        data.extend_from_slice(&2u32.to_be_bytes());
        data.extend_from_slice(&[0xFF, 0x00]); // bad version
        let err = ShardMetadata::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            ShardMetadataDecodeError::HintError(
                HintDecodeError::UnsupportedVersion { .. }
            )
        ));
    }

    #[test]
    fn metadata_decode_hint_length_mismatch() {
        // Declare hint_len=10 but actual hint (Range) only consumes 2 bytes.
        let mut data = vec![];
        data.extend_from_slice(&10u32.to_be_bytes());
        // Pad to 10 bytes: 2 bytes hint + 8 bytes garbage.
        data.push(SHARD_HINT_VERSION);
        data.push(ShardHint::TAG_RANGE);
        data.extend_from_slice(&[0x00; 8]);
        let err = ShardMetadata::decode(&data).unwrap_err();
        assert!(matches!(
            err,
            ShardMetadataDecodeError::HintLengthMismatch {
                declared: 10,
                consumed: 2,
            }
        ));
    }

    // ── ShardMetadataDecodeError Display ───────────────────────────────

    #[test]
    fn metadata_decode_error_display() {
        let e = ShardMetadataDecodeError::TooShort {
            expected_min: 8,
            actual: 2,
        };
        assert!(format!("{}", e).contains("too short"));

        let e = ShardMetadataDecodeError::HintError(
            HintDecodeError::UnknownTag { tag: 0x99 },
        );
        assert!(format!("{}", e).contains("hint decode error"));

        let e = ShardMetadataDecodeError::HintLengthMismatch {
            declared: 10,
            consumed: 2,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("10"));
        assert!(msg.contains("2"));
    }

    // ── Typed shard constructors ───────────────────────────────────────

    #[test]
    fn range_shard_constructor() {
        let spec = range_shard(
            b"aaa".to_vec(),
            b"zzz".to_vec(),
            b"extra".to_vec(),
        );
        assert_eq!(spec.key_range_start.as_ref(), b"aaa");
        assert_eq!(spec.key_range_end.as_ref(), b"zzz");

        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_range());
        assert_eq!(meta.connector_extra.as_ref(), b"extra");
    }

    #[test]
    fn range_shard_no_extra() {
        let spec = range_shard(b"a".to_vec(), b"z".to_vec(), vec![]);
        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_range());
        assert!(meta.connector_extra.is_empty());
    }

    #[test]
    fn prefix_shard_constructor() {
        let spec = prefix_shard(b"src/".to_vec(), vec![]);
        assert_eq!(spec.key_range_start.as_ref(), b"src/");
        assert_eq!(spec.key_range_end.as_ref(), b"src0");

        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_prefix());
        assert_eq!(meta.hint.prefix().unwrap(), b"src/");
    }

    #[test]
    fn prefix_shard_with_extra() {
        let spec = prefix_shard(
            b"data/".to_vec(),
            b"repo:my-repo".to_vec(),
        );
        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_prefix());
        assert_eq!(meta.connector_extra.as_ref(), b"repo:my-repo");
    }

    #[test]
    fn prefix_shard_all_ff() {
        let spec = prefix_shard(b"\xFF\xFF".to_vec(), vec![]);
        assert_eq!(spec.key_range_start.as_ref(), b"\xFF\xFF");
        assert!(spec.is_end_unbounded());
    }

    #[test]
    fn prefix_shard_contains_matching_keys() {
        let spec = prefix_shard(b"test/".to_vec(), vec![]);

        assert!(spec.contains_key(b"test/"));
        assert!(spec.contains_key(b"test/foo.rs"));
        assert!(spec.contains_key(b"test/nested/deep/file.txt"));
        assert!(!spec.contains_key(b"tesu/"));
        assert!(!spec.contains_key(b"tes"));
    }

    #[test]
    #[should_panic(expected = "prefix must not be empty")]
    fn prefix_shard_rejects_empty() {
        prefix_shard(vec![], vec![]);
    }

    #[test]
    fn manifest_shard_constructor() {
        let spec = manifest_shard(7, 0, 1000, vec![]);

        let start = ManifestRowKey::new(7, 0).encode();
        let end = ManifestRowKey::new(7, 1000).encode();
        assert_eq!(spec.key_range_start.as_ref(), start.as_slice());
        assert_eq!(spec.key_range_end.as_ref(), end.as_slice());

        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_manifest());
        assert_eq!(meta.hint.manifest_fields().unwrap(), (7, 0, 1000));
    }

    #[test]
    fn manifest_shard_with_extra() {
        let spec = manifest_shard(
            1,
            100,
            200,
            b"s3://bucket/manifest.csv".to_vec(),
        );
        let meta = spec.decode_metadata().unwrap();
        assert_eq!(meta.hint.manifest_fields().unwrap(), (1, 100, 200));
        assert_eq!(
            meta.connector_extra.as_ref(),
            b"s3://bucket/manifest.csv"
        );
    }

    #[test]
    fn manifest_shard_contains_interior_rows() {
        let spec = manifest_shard(3, 10, 20, vec![]);

        let row10 = ManifestRowKey::new(3, 10).encode();
        let row15 = ManifestRowKey::new(3, 15).encode();
        let row19 = ManifestRowKey::new(3, 19).encode();
        let row20 = ManifestRowKey::new(3, 20).encode();
        let row9 = ManifestRowKey::new(3, 9).encode();

        assert!(spec.contains_key(&row10));
        assert!(spec.contains_key(&row15));
        assert!(spec.contains_key(&row19));
        assert!(!spec.contains_key(&row20));
        assert!(!spec.contains_key(&row9));
    }

    #[test]
    #[should_panic(expected = "start_row")]
    fn manifest_shard_inverted_rows() {
        manifest_shard(1, 1000, 0, vec![]);
    }

    #[test]
    #[should_panic(expected = "start_row")]
    fn manifest_shard_equal_rows() {
        manifest_shard(1, 50, 50, vec![]);
    }

    // ── ShardSpec decode extensions ────────────────────────────────────

    #[test]
    fn decode_hint_on_legacy_shard_spec() {
        let spec = ShardSpec::with_range_and_metadata(
            b"a".to_vec(),
            b"z".to_vec(),
            vec![],
        );
        let hint = spec.decode_hint().unwrap();
        assert!(hint.is_range());
    }

    #[test]
    fn decode_metadata_on_range_shard() {
        let spec = range_shard(b"a".to_vec(), b"z".to_vec(), b"info".to_vec());
        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_range());
        assert_eq!(meta.connector_extra.as_ref(), b"info");
    }

    #[test]
    fn decode_connector_extra_only() {
        let spec = prefix_shard(b"src/".to_vec(), b"token:abc".to_vec());
        let extra = spec.decode_connector_extra().unwrap();
        assert_eq!(extra.as_ref(), b"token:abc");
    }

    #[test]
    fn decode_hint_on_manifest_shard() {
        let spec = manifest_shard(42, 0, 500, vec![]);
        let hint = spec.decode_hint().unwrap();
        assert_eq!(
            hint,
            ShardHint::Manifest {
                manifest_id: 42,
                start_row: 0,
                end_row: 500,
            }
        );
    }

    #[test]
    fn decode_metadata_error_on_corrupt_data() {
        let spec = ShardSpec::with_range_and_metadata(
            b"a".to_vec(),
            b"z".to_vec(),
            vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
        );
        assert!(spec.decode_metadata().is_err());
    }

    // ── Split hint propagation ─────────────────────────────────────────

    #[test]
    fn propagate_range_stays_range() {
        let child_hint = propagate_hint_on_split(
            &ShardHint::Range,
            b"aaa",
            b"mmm",
        )
        .unwrap();
        assert!(child_hint.is_range());
    }

    #[test]
    fn propagate_prefix_demotes_to_range() {
        let parent = ShardHint::Prefix {
            prefix: b"src/".to_vec().into_boxed_slice(),
        };
        let child_hint = propagate_hint_on_split(
            &parent,
            b"src/a",
            b"src/m",
        )
        .unwrap();
        assert!(child_hint.is_range());
    }

    #[test]
    fn propagate_prefix_always_demotes_regardless_of_child_bounds() {
        let parent = ShardHint::Prefix {
            prefix: b"data/".to_vec().into_boxed_slice(),
        };
        let child_hint = propagate_hint_on_split(
            &parent,
            b"data/",
            b"data0",
        )
        .unwrap();
        assert!(child_hint.is_range());
    }

    #[test]
    fn propagate_manifest_adjusts_rows() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let child_start = ManifestRowKey::new(42, 0).encode();
        let child_end = ManifestRowKey::new(42, 500).encode();

        let child_hint =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap();

        assert_eq!(
            child_hint,
            ShardHint::Manifest {
                manifest_id: 42,
                start_row: 0,
                end_row: 500,
            }
        );
    }

    #[test]
    fn propagate_manifest_second_half() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let child_start = ManifestRowKey::new(42, 500).encode();
        let child_end = ManifestRowKey::new(42, 1000).encode();

        let child_hint =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap();

        assert_eq!(
            child_hint,
            ShardHint::Manifest {
                manifest_id: 42,
                start_row: 500,
                end_row: 1000,
            }
        );
    }

    #[test]
    fn propagate_manifest_single_row_child() {
        let parent = ShardHint::Manifest {
            manifest_id: 1,
            start_row: 0,
            end_row: 100,
        };
        let child_start = ManifestRowKey::new(1, 50).encode();
        let child_end = ManifestRowKey::new(1, 51).encode();

        let child_hint =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap();

        assert_eq!(
            child_hint,
            ShardHint::Manifest {
                manifest_id: 1,
                start_row: 50,
                end_row: 51,
            }
        );
    }

    #[test]
    fn propagate_manifest_rejects_wrong_manifest_id() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let child_start = ManifestRowKey::new(99, 0).encode();
        let child_end = ManifestRowKey::new(99, 500).encode();

        let err =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::ManifestIdMismatch {
                parent: 42,
                child: 99
            }
        ));
    }

    #[test]
    fn propagate_manifest_rejects_mismatched_end_manifest_id() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let child_start = ManifestRowKey::new(42, 0).encode();
        let child_end = ManifestRowKey::new(99, 500).encode();

        let err =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::ManifestIdMismatch {
                parent: 42,
                child: 99,
            }
        ));
    }

    #[test]
    fn propagate_manifest_rejects_non_manifest_bytes() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let err =
            propagate_hint_on_split(&parent, b"abc", b"def").unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::InvalidManifestBoundary { .. }
        ));
    }

    #[test]
    fn propagate_manifest_rejects_wrong_length_start() {
        let parent = ShardHint::Manifest {
            manifest_id: 1,
            start_row: 0,
            end_row: 100,
        };
        let child_end = ManifestRowKey::new(1, 50).encode();

        let err =
            propagate_hint_on_split(&parent, b"too-short", &child_end)
                .unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::InvalidManifestBoundary {
                ref boundary,
                ..
            } if boundary == "start"
        ));
    }

    // ── HintPropagationError Display ───────────────────────────────────

    #[test]
    fn propagation_error_display() {
        let e = HintPropagationError::InvalidManifestBoundary {
            boundary: "start".into(),
            bytes: vec![0x01, 0x02, 0x03].into_boxed_slice(),
        };
        let msg = format!("{}", e);
        assert!(msg.contains("start"));
        assert!(msg.contains("3 bytes"));

        let e = HintPropagationError::ManifestIdMismatch {
            parent: 42,
            child: 99,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("42"));
        assert!(msg.contains("99"));
    }

    // ── End-to-end: construct → encode → decode round-trip ─────────────

    #[test]
    fn end_to_end_range_shard_round_trip() {
        let spec = range_shard(
            b"start".to_vec(),
            b"stop".to_vec(),
            b"context".to_vec(),
        );
        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_range());
        assert_eq!(meta.connector_extra.as_ref(), b"context");
    }

    #[test]
    fn end_to_end_prefix_shard_round_trip() {
        let spec = prefix_shard(b"logs/2024/".to_vec(), b"bucket:prod".to_vec());
        let meta = spec.decode_metadata().unwrap();
        assert_eq!(meta.hint.prefix().unwrap(), b"logs/2024/");
        assert_eq!(meta.connector_extra.as_ref(), b"bucket:prod");
    }

    #[test]
    fn end_to_end_manifest_shard_split_round_trip() {
        let parent_spec = manifest_shard(10, 0, 1000, b"s3://m.csv".to_vec());
        let parent_meta = parent_spec.decode_metadata().unwrap();
        let parent_hint = parent_meta.hint;

        // First child: rows [0, 500)
        let c1_start = ManifestRowKey::new(10, 0).encode();
        let c1_end = ManifestRowKey::new(10, 500).encode();
        let c1_hint =
            propagate_hint_on_split(&parent_hint, &c1_start, &c1_end)
                .unwrap();

        // Second child: rows [500, 1000)
        let c2_start = ManifestRowKey::new(10, 500).encode();
        let c2_end = ManifestRowKey::new(10, 1000).encode();
        let c2_hint =
            propagate_hint_on_split(&parent_hint, &c2_start, &c2_end)
                .unwrap();

        assert_eq!(
            c1_hint,
            ShardHint::Manifest {
                manifest_id: 10,
                start_row: 0,
                end_row: 500,
            }
        );
        assert_eq!(
            c2_hint,
            ShardHint::Manifest {
                manifest_id: 10,
                start_row: 500,
                end_row: 1000,
            }
        );

        // Children's hints are themselves encodable/decodable.
        let c1_encoded = c1_hint.encode();
        let (c1_decoded, _) = ShardHint::decode(&c1_encoded).unwrap();
        assert_eq!(c1_decoded, c1_hint);
    }

    // ── decode_manifest_row_key internal helper ────────────────────────

    #[test]
    fn decode_manifest_row_key_round_trip() {
        let original = ManifestRowKey::new(42, 100);
        let encoded = original.encode();
        let decoded = decode_manifest_row_key(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_manifest_row_key_wrong_length() {
        assert!(decode_manifest_row_key(b"too-short").is_none());
        assert!(decode_manifest_row_key(&[0u8; 15]).is_none());
        assert!(decode_manifest_row_key(&[0u8; 17]).is_none());
    }

    #[test]
    fn decode_manifest_row_key_empty() {
        assert!(decode_manifest_row_key(&[]).is_none());
    }

    // ── Property-based test stubs ──────────────────────────────────────

    // TODO: proptest for ShardHint round-trip:
    //   For any hint h: decode(encode(h)) == (h, encode(h).len())
    //
    // TODO: proptest for ShardMetadata round-trip:
    //   For any (hint, extra): decode(encode(meta)) == meta
    //
    // TODO: proptest for propagate_hint_on_split with Manifest:
    //   For any valid sub-range: propagated hint has correct rows
    //
    // TODO: proptest for prefix_shard constructor:
    //   For any non-empty prefix P and any key K that starts with P:
    //     spec.contains_key(&K.encode()) == true
}
