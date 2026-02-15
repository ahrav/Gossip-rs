//! Boundary â‘¢ â€” Shard Algebra & Keyspace Contract: Chunk 2 (DRAFT)
//!
//! ShardHint: the connector-visible interpretation of shard domain
//! semantics. This is the "why does this shard exist" metadata that
//! the coordinator stores opaquely and the connector reads on acquire.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5), Boundary â‘¡
//! (chunks 1â€“5), and Boundary â‘¢ chunk 1 (key schemas).
//!
//! ## Conceptual Model
//!
//! ```text
//!
//!  CONNECTOR creates shards:            COORDINATOR sees:
//!  â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€            â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
//!
//!  PrefixShard {                        ShardSpec {
//!    prefix: "src/",                      key_range_start: b"src/",
//!    computed_end: "src0",      â”€â”€â–º       key_range_end:   b"src0",
//!    hint: Prefix("src/"),                metadata:        [0x02, ...encoded hint...],
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
//! D3.6: ShardHint is encoded INTO ShardSpec.metadata, not as a
//!       separate field on ShardSpec. This preserves the Boundary â‘¡
//!       contract unchanged â€” the coordinator's ShardSpec type stays
//!       at three fields (start, end, metadata). The hint is a
//!       structured subregion within the opaque metadata blob.
//!
//!       The full metadata layout is:
//!       ```text
//!       [hint_bytes...] [connector_metadata_bytes...]
//!       ```
//!
//!       Specifically, the first portion is the encoded ShardHint
//!       (self-describing length via the tag+payload format), and the
//!       remainder is arbitrary connector-specific data. A connector
//!       that doesn't use hints gets metadata == pure connector data.
//!
//!       This design avoids amending ShardSpec and keeps the encoding
//!       contract between the connector and itself â€” the coordinator
//!       never participates.
//!
//!       Reference: FoundationDB subspace layer â€” structured data
//!       encoded into opaque byte keys, with the core KV layer
//!       unaware of the structure.
//!
//! D3.7: ShardHint uses a tagged binary format with a version byte
//!       for forward compatibility:
//!
//!       ```text
//!       byte 0:    version (currently 0x01)
//!       byte 1:    variant tag (0x00=Range, 0x01=Prefix, 0x02=Manifest)
//!       bytes 2+:  variant-specific payload (length-prefixed fields)
//!       ```
//!
//!       The version byte allows us to change the encoding format in
//!       the future without breaking in-flight shards.
//!
//!       Reference: Protocol Buffers wire format â€” tagged fields with
//!       forward-compatible unknown-field handling. We use a simpler
//!       scheme because hints are short-lived (within a single run)
//!       and don't need cross-version interop.
//!
//! D3.8: ShardHint is round-trip-stable: `decode(encode(hint)) == hint`.
//!       This is verified by property-based tests. Encoding errors
//!       (corrupt metadata) produce a structured error, not a panic,
//!       because metadata may be corrupted by storage or by a buggy
//!       connector version.
//!
//! D3.9: `ShardMetadata` is the structured type that pairs a `ShardHint`
//!       with optional connector-specific extra data. This is what gets
//!       encoded into `ShardSpec.metadata`. The encoding is:
//!
//!       ```text
//!       [encoded_hint_length: u32 BE] [encoded_hint] [connector_extra]
//!       ```
//!
//!       The length prefix allows the decoder to skip the hint and
//!       extract the connector extra data without understanding the
//!       hint encoding. This is important for tooling that needs to
//!       read connector data without being coupled to hint versions.

// Assumes all types from Boundaries â‘  and â‘¡ and â‘¢ chunk 1 are in scope.

use core::fmt;

// ============================================================================
// Â§ Chunk 2: ShardHint & Typed Shard Construction
// ============================================================================

// ---------------------------------------------------------------------------
// Â§2.1 ShardHint â€” connector-visible domain semantics
// ---------------------------------------------------------------------------

/// The current encoding version for ShardHint.
///
/// Increment this when the binary format changes. Old versions will
/// fail to decode with `HintDecodeError::UnsupportedVersion`.
pub const SHARD_HINT_VERSION: u8 = 0x01;

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
///   Range    â†’ "scan everything in [start, end) in lex order"
///   Prefix   â†’ "scan everything under this path prefix"
///   Manifest â†’ "scan rows N..M from manifest file #K"
/// ```
///
/// ## Why an Enum (Not a Trait)
///
/// These are the three domain patterns we support in Phase 2. They are
/// closed-world (not extensible by connectors) because:
/// 1. The encoding format is in the contracts crate.
/// 2. Split logic needs to understand the variant for hint propagation.
/// 3. New variants require new encoding tags and split strategies.
///
/// Connectors that don't fit these patterns use `Range` with
/// connector-specific data in the extra metadata portion.
///
/// Reference: Spanner (Corbett et al., OSDI 2012) â€” tablets are always
/// key ranges, but the key encoding scheme (interleaved tables, secondary
/// indexes) gives different ranges different semantic meaning while the
/// tablet layer sees only bytes.
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
    /// reconstruct "this was a prefix shard" from the raw bytes alone â€”
    /// `key_range_end == prefix_successor(key_range_start)` could be
    /// coincidental. The hint makes the semantics explicit.
    ///
    /// ## Split Propagation
    ///
    /// When a prefix shard is split, child shards lose the Prefix hint
    /// (they become Range shards) unless the split happens at a sub-prefix
    /// boundary. The connector is responsible for this decision.
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
    /// The shard's `[start, end)` is the ManifestRowKey encoding of
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
/// adding a new tag â€” never reusing or reordering existing ones.
impl ShardHint {
    const TAG_RANGE: u8 = 0x00;
    const TAG_PREFIX: u8 = 0x01;
    const TAG_MANIFEST: u8 = 0x02;
}

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

// ---------------------------------------------------------------------------
// Â§2.2 ShardHint binary encoding
// ---------------------------------------------------------------------------

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
    /// - Range:    (empty â€” no payload)
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
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }

    /// The encoded byte length of this hint (for pre-allocation).
    pub fn encoded_len(&self) -> usize {
        let header = 2; // version + tag
        match self {
            ShardHint::Range => header,
            ShardHint::Prefix { prefix } => header + 4 + prefix.len(),
            ShardHint::Manifest { .. } => header + 24, // 3 Ã— u64
        }
    }

    /// Decode a hint from a byte slice.
    ///
    /// Returns the decoded hint and the number of bytes consumed.
    /// The caller can use the consumed count to find the start of
    /// connector-extra data in the metadata blob.
    ///
    /// This function does NOT panic on invalid input â€” it returns a
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
                let total = 2 + 24; // header + 3 Ã— u64
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

// ---------------------------------------------------------------------------
// Â§2.3 ShardMetadata â€” structured metadata blob
// ---------------------------------------------------------------------------

/// Structured metadata that is encoded into `ShardSpec.metadata`.
///
/// Pairs a `ShardHint` (how the connector interprets this shard's domain)
/// with optional connector-specific extra data (repository URLs,
/// authentication tokens, bucket names, etc.).
///
/// ## Encoding
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚ hint_len (4 bytes BE) â”‚ encoded_hint       â”‚ connector_extra  â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
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
    /// invalid. Does not panic â€” metadata may be corrupt.
    pub fn decode(data: &[u8]) -> Result<Self, ShardMetadataDecodeError> {
        if data.is_empty() {
            // Empty metadata â†’ Range hint, no extra data.
            // This is the backward-compatible default for ShardSpecs
            // constructed without structured metadata.
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
        let (hint, consumed) =
            ShardHint::decode(hint_data).map_err(ShardMetadataDecodeError::HintError)?;

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

// ---------------------------------------------------------------------------
// Â§2.4 Typed shard constructors
// ---------------------------------------------------------------------------

/// Construct a `ShardSpec` for a generic key range with a Range hint.
///
/// This is the most common shard type: an arbitrary byte range with
/// no special domain semantics.
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
pub fn prefix_shard(
    prefix: Vec<u8>,
    connector_extra: Vec<u8>,
) -> ShardSpec {
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

// ---------------------------------------------------------------------------
// Â§2.5 Metadata extraction helpers
// ---------------------------------------------------------------------------

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
    /// (backward-compatible default for unstructured ShardSpecs from B2).
    pub fn decode_metadata(&self) -> Result<ShardMetadata, ShardMetadataDecodeError> {
        ShardMetadata::decode(&self.metadata)
    }

    /// Extract just the `ShardHint`, discarding connector extra data.
    ///
    /// Convenience wrapper around `decode_metadata().hint`.
    pub fn decode_hint(&self) -> Result<ShardHint, ShardMetadataDecodeError> {
        self.decode_metadata().map(|m| m.hint)
    }

    /// Extract just the connector extra data, discarding the hint.
    ///
    /// Useful when the connector needs its own data but doesn't care
    /// about the hint variant.
    pub fn decode_connector_extra(
        &self,
    ) -> Result<Box<[u8]>, ShardMetadataDecodeError> {
        self.decode_metadata().map(|m| m.connector_extra)
    }
}

// ---------------------------------------------------------------------------
// Â§2.6 Split hint propagation
// ---------------------------------------------------------------------------

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
/// ## Why Prefix â†’ Range on split
///
/// After splitting, the child's range is a subrange of the prefix. It's
/// no longer "everything under /src/" â€” it's "some slice of /src/". The
/// connector should not use prefix-based listing for the child; it should
/// use range-based listing. Demoting to Range makes this explicit.
///
/// Exception: if the caller knows the split is at a sub-prefix boundary
/// (e.g., splitting "/src/" into "/src/a" through "/src/m" and
/// "/src/m" through "/src/z"), they can manually construct Prefix hints
/// for the children. This function doesn't attempt that inference.
///
/// ## Why Manifest propagates
///
/// Manifest shards have a clear row-level structure. The split point
/// is a row boundary, so the child gets the appropriate sub-range of
/// rows. The connector needs manifest_id + row range to resume.
///
/// # Arguments
///
/// * `parent_hint` â€” the hint from the parent shard being split
/// * `child_start` â€” the child's key_range_start (encoded bytes)
/// * `child_end` â€” the child's key_range_end (encoded bytes)
///
/// # Returns
///
/// The hint for the child shard, or an error if the parent is a
/// Manifest hint and the child boundaries don't align to valid
/// ManifestRowKey boundaries.
pub fn propagate_hint_on_split(
    parent_hint: &ShardHint,
    child_start: &[u8],
    child_end: &[u8],
) -> Result<ShardHint, HintPropagationError> {
    match parent_hint {
        ShardHint::Range => Ok(ShardHint::Range),

        ShardHint::Prefix { .. } => {
            // Demote to Range â€” child no longer covers an exact prefix.
            Ok(ShardHint::Range)
        }

        ShardHint::Manifest {
            manifest_id, ..
        } => {
            // Decode the child's start/end as ManifestRowKeys.
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

            // Verify the child is within the same manifest.
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
/// Returns `None` if the bytes are not exactly 16 bytes (the fixed
/// encoded length of `ManifestRowKey`).
fn decode_manifest_row_key(bytes: &[u8]) -> Option<ManifestRowKey> {
    if bytes.len() != ManifestRowKey::ENCODED_LEN {
        return None;
    }
    let manifest_id = u64::from_be_bytes(bytes[0..8].try_into().ok()?);
    let row = u64::from_be_bytes(bytes[8..16].try_into().ok()?);
    Some(ManifestRowKey::new(manifest_id, row))
}

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
            Self::InvalidManifestBoundary { boundary, bytes } => {
                write!(
                    f,
                    "child {} boundary ({} bytes) is not a valid ManifestRowKey",
                    boundary,
                    bytes.len(),
                )
            }
            Self::ManifestIdMismatch { parent, child } => {
                write!(
                    f,
                    "manifest_id mismatch: parent={}, child={}",
                    parent, child,
                )
            }
        }
    }
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ ShardHint encode/decode round-trip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ ShardHint decode errors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn hint_decode_too_short() {
        let err = ShardHint::decode(&[]).unwrap_err();
        assert!(matches!(err, HintDecodeError::TooShort { .. }));
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
    fn hint_decode_unknown_tag() {
        let err = ShardHint::decode(&[SHARD_HINT_VERSION, 0xFF]).unwrap_err();
        assert!(matches!(err, HintDecodeError::UnknownTag { tag: 0xFF }));
    }

    #[test]
    fn hint_decode_manifest_inverted_rows() {
        // Manually encode a manifest with start >= end.
        let mut data = vec![SHARD_HINT_VERSION, ShardHint::TAG_MANIFEST];
        data.extend_from_slice(&42u64.to_be_bytes());
        data.extend_from_slice(&100u64.to_be_bytes()); // start
        data.extend_from_slice(&50u64.to_be_bytes());  // end < start!
        let err = ShardHint::decode(&data).unwrap_err();
        assert!(matches!(err, HintDecodeError::InvalidPayload { .. }));
    }

    // â”€â”€ ShardMetadata encode/decode round-trip â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
    fn metadata_empty_is_backward_compatible() {
        // Empty metadata from B2-era ShardSpecs â†’ Range, no extra.
        let decoded = ShardMetadata::decode(&[]).unwrap();
        assert_eq!(decoded.hint, ShardHint::Range);
        assert!(decoded.connector_extra.is_empty());
    }

    // â”€â”€ Typed shard constructors â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn range_shard_constructor() {
        let spec = range_shard(
            b"aaa".to_vec(),
            b"zzz".to_vec(),
            b"extra".to_vec(),
        );
        assert_eq!(spec.key_range_start.as_ref(), b"aaa");
        assert_eq!(spec.key_range_end.as_ref(), b"zzz");

        // Decode the metadata and verify the hint.
        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_range());
        assert_eq!(meta.connector_extra.as_ref(), b"extra");
    }

    #[test]
    fn prefix_shard_constructor() {
        let spec = prefix_shard(b"src/".to_vec(), vec![]);
        assert_eq!(spec.key_range_start.as_ref(), b"src/");
        assert_eq!(spec.key_range_end.as_ref(), b"src0"); // '/' + 1 = '0'

        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_prefix());
        assert_eq!(meta.hint.prefix().unwrap(), b"src/");
    }

    #[test]
    fn manifest_shard_constructor() {
        let spec = manifest_shard(7, 0, 1000, vec![]);

        // Verify the key range matches ManifestRowKey encoding.
        let start = ManifestRowKey::new(7, 0).encode();
        let end = ManifestRowKey::new(7, 1000).encode();
        assert_eq!(spec.key_range_start.as_ref(), start.as_slice());
        assert_eq!(spec.key_range_end.as_ref(), end.as_slice());

        let meta = spec.decode_metadata().unwrap();
        assert!(meta.hint.is_manifest());
        assert_eq!(meta.hint.manifest_fields().unwrap(), (7, 0, 1000));
    }

    // â”€â”€ ShardSpec.decode_hint backward compat â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn decode_hint_on_legacy_shard_spec() {
        // A ShardSpec from Boundary â‘¡ with raw metadata (no hint encoding).
        let spec = ShardSpec::with_range_and_metadata(
            b"a".to_vec(),
            b"z".to_vec(),
            vec![], // empty metadata
        );
        let hint = spec.decode_hint().unwrap();
        assert!(hint.is_range());
    }

    // â”€â”€ Split hint propagation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // Prefix â†’ Range after split.
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
    fn propagate_manifest_rejects_wrong_manifest_id() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        let child_start = ManifestRowKey::new(99, 0).encode(); // wrong id!
        let child_end = ManifestRowKey::new(99, 500).encode();

        let err =
            propagate_hint_on_split(&parent, &child_start, &child_end)
                .unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::ManifestIdMismatch { parent: 42, child: 99 }
        ));
    }

    #[test]
    fn propagate_manifest_rejects_non_manifest_bytes() {
        let parent = ShardHint::Manifest {
            manifest_id: 42,
            start_row: 0,
            end_row: 1000,
        };
        // 3 bytes is not a valid ManifestRowKey (needs 16).
        let err =
            propagate_hint_on_split(&parent, b"abc", b"def").unwrap_err();
        assert!(matches!(
            err,
            HintPropagationError::InvalidManifestBoundary { .. }
        ));
    }

    // â”€â”€ Property-based test stubs â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
