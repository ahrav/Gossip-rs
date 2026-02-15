//! Boundary â‘¢ â€” Shard Algebra & Keyspace Contract: Chunk 1 (DRAFT)
//!
//! Key encoding schemas and the fundamental keyspace ordering contract.
//! This is the Stage 2â€“3 bridge: it defines how connectors produce the
//! lex-ordered `Box<[u8]>` values that `ShardSpec` (Boundary â‘¡) and
//! `Cursor` consume.
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5) and Boundary â‘¡
//! (chunks 1â€“5). It uses `CanonicalBytes`, `Hasher`, and `ShardSpec`
//! from those boundaries.
//!
//! ## Conceptual Model
//!
//! ```text
//! â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
//! â”‚ Connector (Stage 3)                                        â”‚
//! â”‚                                                            â”‚
//! â”‚   "src/main.rs" â”€â”€â”                                        â”‚
//! â”‚                   â”‚  PathKey::encode()                      â”‚
//! â”‚                   â–¼                                         â”‚
//! â”‚            [0x73, 0x72, 0x63, 0x2f, 0x6d, ...]            â”‚
//! â”‚                   â”‚                                        â”‚
//! â”‚                   â”‚  lex-ordered bytes                      â”‚
//! â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¼â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
//! â”‚ Coordinator (Stage 2)                                      â”‚
//! â”‚                   â–¼                                         â”‚
//! â”‚   ShardSpec { key_range_start: Box<[u8]>, ... }            â”‚
//! â”‚   Cursor   { last_key: Option<Box<[u8]>>, ... }            â”‚
//! â”‚                                                            â”‚
//! â”‚   Coordinator sees ONLY bytes.                              â”‚
//! â”‚   Compares with lex ordering.                               â”‚
//! â”‚   Never interprets content.                                 â”‚
//! â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
//! ```
//!
//! ## Design Decisions (locked)
//!
//! D3.1: The shard keyspace operates on raw byte slices, not on
//!       `ItemKey` structs from Boundary â‘ . `ItemKey` (ConnectorTag +
//!       path) is the *logical identity*; the shard keyspace uses the
//!       *encoded byte representation* of the path portion only.
//!
//!       Within a single run, all shards share the same connector and
//!       ConnectorTag. The shard key range boundaries are the encoded
//!       path bytes. ConnectorTag is constant and implicit.
//!
//!       Reference: Bigtable (Chang et al., OSDI 2006) â€” row keys are
//!       arbitrary byte strings; tablets are contiguous row ranges.
//!       The row key encoding is application-defined, not built into
//!       the tablet layer.
//!
//! D3.2: Standard key schemas are encoding *types*, not a trait with
//!       dynamic dispatch. Each schema is a concrete type with an
//!       `encode()` method that produces `Vec<u8>`. The coordinator
//!       never needs to be generic over schemas â€” it always sees
//!       `Box<[u8]>`.
//!
//!       However, all schemas share a documented `KeyEncoding` trait
//!       that specifies the ordering contract. This trait exists for:
//!       (a) documentation of the invariant, (b) shared convenience
//!       methods, (c) a hook for property-based testing.
//!
//!       Reference: FoundationDB subspace/directory layer â€” typed key
//!       encoding with a shared tuple encoding scheme, but the core
//!       KV layer sees only bytes.
//!
//! D3.3: Big-endian encoding for numeric fields in composite keys.
//!       Lexicographic byte ordering on big-endian integers matches
//!       numeric ordering. Little-endian does NOT (e.g., 256_u16 LE
//!       = [0x00, 0x01] < 1_u16 LE = [0x01, 0x00] in lex order,
//!       but 256 > 1 numerically).
//!
//!       This is the universal convention for ordered key encodings:
//!       - Bigtable: "store integers in big-endian format"
//!       - Spanner: big-endian encoding for key columns
//!       - CockroachDB: big-endian key encoding
//!       - FoundationDB tuple layer: big-endian integers
//!
//!       Reference: Google Cloud, "Optimizing Schema Design for Cloud
//!       Spanner" (2023) â€” explicitly warns against LE timestamp
//!       encoding because it breaks lex ordering.
//!
//!       Note: This is DIFFERENT from `CanonicalBytes` (Boundary â‘ )
//!       which uses little-endian for hashing. Hashing doesn't need
//!       ordered encoding â€” only collision-freedom. Shard keys need
//!       ordered encoding. These are separate concerns.
//!
//! D3.4: `PathKey` encoding uses raw UTF-8 bytes with no additional
//!       normalization beyond what the connector provides. The
//!       contracts crate specifies the encoding format but does NOT
//!       perform Unicode normalization â€” that is the connector's
//!       responsibility, because normalization rules are source-
//!       specific (e.g., macOS HFS+ uses NFD, Linux is byte-transparent,
//!       S3 keys are opaque bytes).
//!
//!       The connector MUST document its normalization choice and
//!       apply it consistently. The `PathKey` type enforces structural
//!       validity (non-empty, no interior nulls in the path portion)
//!       but not semantic normalization.
//!
//!       Reference: Unicode Technical Report #15 (Unicode Normalization
//!       Forms); POSIX path semantics (byte-transparent); Apple
//!       Technical Note TN1150 (HFS+ NFD normalization).
//!
//! D3.5: `prefix_successor` computes the lexicographic successor of a
//!       byte prefix â€” the smallest byte string that is greater than
//!       all strings that start with the prefix. This is used to
//!       compute PrefixShard end keys.
//!
//!       Algorithm: strip trailing 0xFF bytes, then increment the
//!       last non-0xFF byte. If the prefix is all 0xFF bytes, there
//!       is no successor (the prefix covers through the end of the
//!       keyspace).
//!
//!       Reference: FoundationDB key selectors â€” `strinc()` function;
//!       CockroachDB `Key.PrefixEnd()`.

// Assumes all types from Boundary â‘  and Boundary â‘¡ are in scope:
// use crate::{CanonicalBytes, Hasher, ShardSpec, ItemKey, ConnectorTag};

use core::fmt;

// ============================================================================
// Â§ Chunk 1: Key Encoding Contract & Standard Schemas
// ============================================================================

// ---------------------------------------------------------------------------
// Â§1.1 KeyEncoding trait â€” the fundamental ordering contract
// ---------------------------------------------------------------------------

/// Trait for types that encode themselves into lexicographically ordered bytes.
///
/// ## The Fundamental Contract
///
/// For any two values `a` and `b` of the same concrete type implementing
/// this trait:
///
/// ```text
///   a < b  (in the type's logical ordering)
///     âŸ¹
///   a.encode() < b.encode()  (in lexicographic byte ordering)
/// ```
///
/// This is the **only** property the coordinator relies on. It enables:
/// - **Cursor monotonicity**: comparing `last_key` bytes (Boundary â‘¡)
/// - **Range membership**: `spec.contains_key(&encoded)` (Boundary â‘¡)
/// - **Split validation**: children tile parent by byte range (Boundary â‘¡)
///
/// ## Why a Trait
///
/// The coordinator never uses this trait â€” it works with raw `Box<[u8]>`.
/// The trait exists for:
/// 1. **Documentation**: the ordering contract is the single most important
///    property in the shard algebra. Having a trait makes it visible.
/// 2. **Property-based testing**: generic test harnesses can verify the
///    ordering invariant for any `KeyEncoding` implementation.
/// 3. **Connector guidance**: implementors see exactly what they must satisfy.
///
/// ## Non-Goals
///
/// This trait does NOT provide:
/// - Decoding (the coordinator never decodes keys)
/// - Dynamic dispatch (never used as `dyn KeyEncoding`)
/// - Serialization (that's `CanonicalBytes` from Boundary â‘ , which is
///   for *hashing*, not *ordering*)
///
/// Reference: Bigtable, Spanner, CockroachDB, FoundationDB â€” all use
/// application-defined key encoding with the same ordering contract.
pub trait KeyEncoding: Sized {
    /// Encode this key into a byte buffer.
    ///
    /// Appends the encoded bytes to `buf`. The encoded form MUST satisfy
    /// the lexicographic ordering invariant documented on this trait.
    ///
    /// Implementors MUST NOT allocate beyond extending `buf`.
    fn encode_to(&self, buf: &mut Vec<u8>);

    /// Encode this key into a new `Vec<u8>`.
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.encode_to(&mut buf);
        buf
    }

    /// Encode this key into a `Box<[u8]>`, ready for `ShardSpec` or `Cursor`.
    fn encode_boxed(&self) -> Box<[u8]> {
        self.encode().into_boxed_slice()
    }
}

// ---------------------------------------------------------------------------
// Â§1.2 prefix_successor â€” lexicographic prefix bound computation
// ---------------------------------------------------------------------------

/// Compute the lexicographic successor of a byte prefix.
///
/// Returns the smallest byte string `s` such that for all byte strings `x`:
///
/// ```text
///   x starts with `prefix`  âŸ¹  prefix â‰¤ x < s
/// ```
///
/// This defines the half-open range `[prefix, s)` that contains exactly
/// the strings beginning with `prefix`.
///
/// ## Algorithm
///
/// 1. Strip trailing `0xFF` bytes (they cannot be incremented).
/// 2. Increment the last remaining byte.
/// 3. If the prefix is entirely `0xFF` bytes (or empty), return `None` â€”
///    the prefix covers through the end of the keyspace.
///
/// ## Examples
///
/// ```text
/// prefix_successor(b"abc")      â†’ Some(b"abd")
/// prefix_successor(b"ab\xFF")   â†’ Some(b"ac")
/// prefix_successor(b"\xFF\xFF") â†’ None  (covers to end of keyspace)
/// prefix_successor(b"")         â†’ None  (empty prefix = everything)
/// prefix_successor(b"\x00")     â†’ Some(b"\x01")
/// prefix_successor(b"z\xFF\xFF") â†’ Some(b"{")  ('{' = 'z' + 1)
/// ```
///
/// ## Invariant
///
/// **Safety (completeness)**: For any byte string `x` that starts with
/// `prefix`, `prefix <= x < successor`. No string starting with `prefix`
/// falls outside the range `[prefix, successor)`.
///
/// **Safety (tightness)**: `successor` is the smallest such bound. No
/// byte string between `predecessor_of(successor)` and `successor`
/// starts with `prefix`.
///
/// Reference: FoundationDB `strinc()` â€” identical algorithm;
///            CockroachDB `Key.PrefixEnd()` â€” same logic.
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return None;
    }

    // Find the last byte that is not 0xFF.
    let last_non_ff = prefix.iter().rposition(|&b| b != 0xFF);

    match last_non_ff {
        None => {
            // All bytes are 0xFF â€” no successor exists.
            // The prefix covers through the end of the keyspace.
            None
        }
        Some(pos) => {
            // Truncate trailing 0xFF bytes and increment the last byte.
            let mut result = prefix[..=pos].to_vec();

            // Safety: `pos` is a valid index and `prefix[pos] != 0xFF`,
            // so incrementing cannot overflow.
            assert!(result[pos] < 0xFF, "byte at pos must not be 0xFF");
            result[pos] += 1;

            assert!(!result.is_empty(), "successor must be non-empty");
            assert!(
                result.as_slice() > prefix,
                "successor must be greater than prefix"
            );

            Some(result)
        }
    }
}

// ---------------------------------------------------------------------------
// Â§1.3 PathKey â€” filesystem path encoding
// ---------------------------------------------------------------------------

/// Lex-ordered encoding of a filesystem path for shard key ranges.
///
/// ## Encoding
///
/// The encoded form is simply the raw UTF-8 bytes of the normalized path.
/// UTF-8 has the property that lexicographic byte ordering matches Unicode
/// codepoint ordering for ASCII-range characters, which covers the vast
/// majority of filesystem paths.
///
/// ## Normalization (Connector Responsibility)
///
/// The contracts crate does NOT perform normalization. The connector MUST
/// normalize paths before constructing a `PathKey`:
///
/// | Source | Recommended Normalization |
/// |--------|--------------------------|
/// | Linux ext4 | None (byte-transparent) |
/// | macOS HFS+ | NFD â†’ NFC conversion |
/// | Windows NTFS | Case-fold to lowercase |
/// | S3 | None (keys are opaque bytes) |
/// | Git | None (paths are byte strings) |
///
/// The connector MUST document its choice and apply it consistently across
/// all path encoding within a single run. Inconsistent normalization breaks
/// the ordering invariant and cursor monotonicity.
///
/// ## Structural Validity
///
/// - Path MUST be non-empty.
/// - Path MUST be valid UTF-8.
/// - Path MUST NOT contain interior null bytes (null is reserved as a
///   separator in composite keys like `ItemKey`).
///
/// ## Ordering Properties
///
/// UTF-8 byte ordering matches Unicode codepoint ordering. For ASCII paths:
///
/// ```text
/// "/" < "0" < "9" < "A" < "Z" < "a" < "z"
/// ```
///
/// This means `"src/a.rs" < "src/b.rs"` in both human and byte ordering.
///
/// Reference: UTF-8 was designed so that strcmp() on encoded bytes gives
/// the same result as comparing codepoints (Ken Thompson, Rob Pike, 1992).
/// Bigtable relies on this property for row key ordering.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathKey {
    /// Normalized path bytes (valid UTF-8, no interior nulls).
    path: Box<[u8]>,
}

impl PathKey {
    /// Construct a `PathKey` from normalized path bytes.
    ///
    /// The caller (connector) is responsible for normalization.
    ///
    /// # Panics
    ///
    /// Panics if:
    /// - `path` is empty
    /// - `path` is not valid UTF-8
    /// - `path` contains interior null bytes
    pub fn new(path: &[u8]) -> Self {
        assert!(!path.is_empty(), "PathKey: path must not be empty");
        assert!(
            core::str::from_utf8(path).is_ok(),
            "PathKey: path must be valid UTF-8"
        );
        assert!(
            !path[..path.len() - 1].contains(&0x00),
            "PathKey: path must not contain interior null bytes"
        );

        // Postcondition: path is non-empty valid UTF-8 without interior nulls.
        Self {
            path: path.to_vec().into_boxed_slice(),
        }
    }

    /// Construct from a Rust string slice.
    ///
    /// # Panics
    ///
    /// Panics if `path` is empty or contains interior null bytes.
    pub fn from_str(path: &str) -> Self {
        Self::new(path.as_bytes())
    }

    /// The raw path bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.path
    }
}

impl KeyEncoding for PathKey {
    #[inline]
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.path);
    }
}

// ---------------------------------------------------------------------------
// Â§1.4 TimeIdKey â€” timestamp + tie-breaking ID encoding
// ---------------------------------------------------------------------------

/// Lex-ordered encoding of `(timestamp, id)` composite keys.
///
/// ## Use Case
///
/// Scanning time-ordered data sources (audit logs, event streams,
/// SaaS API results sorted by timestamp). The timestamp provides
/// the primary ordering; the ID breaks ties for items with identical
/// timestamps.
///
/// ## Encoding
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚ timestamp (8 bytes)  â”‚ id_len (2 bytes) â”‚ id (variable)    â”‚
/// â”‚ big-endian u64       â”‚ big-endian u16   â”‚ raw bytes        â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// Total encoded length: `8 + 2 + id.len()` bytes.
///
/// ## Why Big-Endian
///
/// Lexicographic byte ordering on big-endian integers matches numeric
/// ordering:
///
/// ```text
/// timestamp=1  BE: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01]
/// timestamp=2  BE: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]
///
/// Lex comparison: [.., 0x01] < [.., 0x02] âœ“ â€” matches numeric ordering
/// ```
///
/// With little-endian, `256_u64` LE starts with `0x00` while `1_u64` LE
/// starts with `0x01`, so lex ordering gives `256 < 1` â€” WRONG.
///
/// ## Why Length-Prefixed ID
///
/// The `id_len` field ensures that shorter IDs sort before longer IDs
/// when the ID bytes share a common prefix. Without length-prefixing,
/// `"abc"` and `"abcd"` would have ambiguous ordering relative to the
/// bytes that follow.
///
/// **However**, this means that for a given timestamp, IDs are ordered
/// first by length, then by content. This is acceptable because the ID
/// is a tie-breaker, not the primary ordering dimension.
///
/// ## Invariants
///
/// **Safety (encoding fidelity)**: `encode(a) < encode(b)` iff
/// `(a.timestamp, a.id_len, a.id) < (b.timestamp, b.id_len, b.id)`
/// in lexicographic tuple ordering.
///
/// **Safety (bounded ID)**: ID length MUST fit in `u16` (max 65,535 bytes).
/// In practice, IDs are much shorter (UUIDs, SHA hashes, etc.).
///
/// Reference: Google Cloud, "Sharding of timestamp-ordered data in Cloud
/// Spanner" â€” addresses the hot-spot problem with timestamp-ordered keys.
/// Our encoding follows the same structure but delegates anti-hotspot
/// sharding to the shard split mechanism (Boundary â‘¡).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TimeIdKey {
    /// Unix timestamp (seconds, milliseconds, or microseconds â€” the unit
    /// is connector-defined but MUST be consistent within a run).
    pub timestamp: u64,
    /// Tie-breaking identifier (e.g., UUID bytes, auto-increment ID).
    pub id: Box<[u8]>,
}

impl TimeIdKey {
    /// Construct a `TimeIdKey`.
    ///
    /// # Panics
    ///
    /// Panics if `id` exceeds `u16::MAX` bytes.
    pub fn new(timestamp: u64, id: Vec<u8>) -> Self {
        assert!(
            id.len() <= u16::MAX as usize,
            "TimeIdKey: id length {} exceeds u16::MAX",
            id.len()
        );

        Self {
            timestamp,
            id: id.into_boxed_slice(),
        }
    }

    /// Construct a `TimeIdKey` with no tie-breaking ID.
    ///
    /// Suitable when timestamps are globally unique.
    pub fn timestamp_only(timestamp: u64) -> Self {
        Self {
            timestamp,
            id: Box::new([]),
        }
    }

    /// The fixed encoded length of the timestamp + id_len header.
    pub const HEADER_LEN: usize = 8 + 2; // u64 BE + u16 BE
}

impl PartialOrd for TimeIdKey {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for TimeIdKey {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.timestamp
            .cmp(&other.timestamp)
            .then_with(|| self.id.len().cmp(&other.id.len()))
            .then_with(|| self.id.cmp(&other.id))
    }
}

impl KeyEncoding for TimeIdKey {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        let id_len: u16 = self.id.len() as u16;
        // Assertion: id length was validated in constructor.
        assert!(self.id.len() <= u16::MAX as usize);

        // Big-endian for lex ordering = numeric ordering.
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&id_len.to_be_bytes());
        buf.extend_from_slice(&self.id);
    }
}

// ---------------------------------------------------------------------------
// Â§1.5 ManifestRowKey â€” manifest-based work unit encoding
// ---------------------------------------------------------------------------

/// Lex-ordered encoding of `(manifest_id, row)` composite keys.
///
/// ## Use Case
///
/// Manifest-based scanning where a pre-built manifest file lists all
/// work units (e.g., a file listing exported from a data warehouse,
/// a pre-enumerated S3 inventory, or a pre-computed list of API
/// endpoints to scan).
///
/// The manifest is identified by `manifest_id` (e.g., a database
/// sequence number or a hash of the manifest content). Each row in
/// the manifest is a work unit identified by its row number.
///
/// ## Encoding
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¬â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚ manifest_id (8 bytes)â”‚ row (8 bytes)         â”‚
/// â”‚ big-endian u64       â”‚ big-endian u64        â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”´â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// Total encoded length: 16 bytes (fixed).
///
/// ## Ordering
///
/// Items are ordered first by manifest_id, then by row within a manifest.
/// This allows a manifest shard to cover a contiguous range of rows
/// within a single manifest.
///
/// ## Invariant
///
/// **Safety**: `encode(a) < encode(b)` iff
/// `(a.manifest_id, a.row) < (b.manifest_id, b.row)` numerically.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestRowKey {
    /// Manifest identifier (sequence number or content hash truncated to u64).
    pub manifest_id: u64,
    /// Zero-based row number within the manifest.
    pub row: u64,
}

impl ManifestRowKey {
    /// Construct a `ManifestRowKey`.
    pub const fn new(manifest_id: u64, row: u64) -> Self {
        Self { manifest_id, row }
    }

    /// The encoded length is always 16 bytes.
    pub const ENCODED_LEN: usize = 16;
}

impl KeyEncoding for ManifestRowKey {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        // Big-endian for lex ordering = numeric ordering.
        buf.extend_from_slice(&self.manifest_id.to_be_bytes());
        buf.extend_from_slice(&self.row.to_be_bytes());
    }
}

// ---------------------------------------------------------------------------
// Â§1.6 OpaqueFixedKey â€” passthrough for pre-encoded fixed-width keys
// ---------------------------------------------------------------------------

/// Passthrough encoding for connectors that produce fixed-width,
/// pre-ordered byte keys.
///
/// ## Use Case
///
/// Some connectors already produce lex-ordered keys natively (e.g.,
/// UUIDs in binary form, content hashes, or keys from an external
/// system that guarantees lex ordering). `OpaqueFixedKey` wraps these
/// without re-encoding.
///
/// ## Contract
///
/// The connector MUST guarantee that the raw bytes are already in the
/// correct lexicographic order. The contracts crate cannot verify this â€”
/// it trusts the connector and validates only the structural constraint
/// (fixed width matching the declared length).
///
/// ## Why Fixed-Width
///
/// Fixed-width keys have desirable properties for shard algebra:
/// - No length-prefix overhead
/// - Predictable encoded size for capacity planning
/// - Simple midpoint computation for split-point selection
///
/// Connectors with variable-width keys should use `PathKey` or
/// `TimeIdKey` instead, or define their own `KeyEncoding` impl.
///
/// ## Invariant
///
/// **Safety (width)**: All keys within a single run using this schema
/// MUST have the same byte width. Mixing widths breaks lex comparison.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueFixedKey {
    /// The raw key bytes. Length MUST match the schema's declared width.
    bytes: Box<[u8]>,
}

impl OpaqueFixedKey {
    /// Construct an `OpaqueFixedKey` with a declared expected width.
    ///
    /// # Panics
    ///
    /// Panics if `bytes.len() != expected_len`.
    pub fn new(bytes: Vec<u8>, expected_len: usize) -> Self {
        assert_eq!(
            bytes.len(),
            expected_len,
            "OpaqueFixedKey: byte length {} does not match expected {}",
            bytes.len(),
            expected_len,
        );
        assert!(expected_len > 0, "OpaqueFixedKey: length must be > 0");

        Self {
            bytes: bytes.into_boxed_slice(),
        }
    }

    /// Construct from a fixed-size array. The expected length is inferred.
    pub fn from_array<const N: usize>(bytes: [u8; N]) -> Self {
        assert!(N > 0, "OpaqueFixedKey: length must be > 0");
        Self {
            bytes: bytes.to_vec().into_boxed_slice(),
        }
    }

    /// The raw key bytes.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The key width.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl KeyEncoding for OpaqueFixedKey {
    #[inline]
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.bytes);
    }
}

// ---------------------------------------------------------------------------
// Â§1.7 Encoding helpers â€” building ShardSpec from key schemas
// ---------------------------------------------------------------------------

/// Construct a `ShardSpec` from two `KeyEncoding` values and optional metadata.
///
/// This is the primary bridge between typed key schemas and the
/// coordinator's byte-level `ShardSpec`. It encodes both keys and
/// delegates to `ShardSpec::with_range_and_metadata`.
///
/// # Panics
///
/// Panics if the encoded start is not strictly less than the encoded end
/// (delegated to `ShardSpec::with_range_and_metadata`). Also panics if
/// both are empty (unbounded ranges should use `ShardSpec::unbounded()`).
pub fn shard_spec_from_keys<K: KeyEncoding>(
    start: &K,
    end: &K,
    metadata: Vec<u8>,
) -> ShardSpec {
    let start_bytes = start.encode();
    let end_bytes = end.encode();
    ShardSpec::with_range_and_metadata(start_bytes, end_bytes, metadata)
}

/// Construct a `ShardSpec` for a prefix range.
///
/// Given a prefix, computes the end key using `prefix_successor` and
/// constructs a `ShardSpec` covering exactly the keys that start with
/// the prefix.
///
/// If the prefix has no successor (all 0xFF bytes), the end is unbounded
/// (empty), meaning the shard covers from the prefix to the end of the
/// keyspace.
///
/// # Panics
///
/// Panics if `prefix` is empty (use `ShardSpec::unbounded()` instead).
pub fn shard_spec_from_prefix(prefix: &[u8], metadata: Vec<u8>) -> ShardSpec {
    assert!(!prefix.is_empty(), "prefix must not be empty");

    let start = prefix.to_vec();
    let end = prefix_successor(prefix).unwrap_or_default();

    ShardSpec::with_range_and_metadata(start, end, metadata)
}

/// Construct a `ShardSpec` from a `ManifestRowKey` range.
///
/// Covers rows `[start_row, end_row)` within a single manifest.
///
/// # Panics
///
/// Panics if `start_row >= end_row`.
pub fn shard_spec_from_manifest_range(
    manifest_id: u64,
    start_row: u64,
    end_row: u64,
    metadata: Vec<u8>,
) -> ShardSpec {
    assert!(
        start_row < end_row,
        "ManifestShard: start_row {} must be < end_row {}",
        start_row,
        end_row,
    );

    let start_key = ManifestRowKey::new(manifest_id, start_row);
    let end_key = ManifestRowKey::new(manifest_id, end_row);
    shard_spec_from_keys(&start_key, &end_key, metadata)
}

// ---------------------------------------------------------------------------
// Â§1.8 Midpoint computation â€” for split-point selection
// ---------------------------------------------------------------------------

/// Compute an approximate midpoint between two byte keys.
///
/// Used by connectors to select split points when dividing a shard.
/// The midpoint is computed byte-by-byte as the arithmetic mean.
///
/// ## Properties
///
/// - `midpoint(a, b)` is always in `(a, b)` when `a < b`.
/// - The result has the same length as the longer of `a` and `b`.
/// - For very close keys (e.g., adjacent), the midpoint may equal
///   the shorter key â€” callers should handle this case.
///
/// ## Limitations
///
/// This is an approximation. For dense keyspaces it works well. For
/// sparse keyspaces (e.g., only two keys far apart), the midpoint may
/// fall in an empty region. This is acceptable because split-point
/// selection is a heuristic for load balancing, not a correctness
/// requirement.
///
/// Returns `None` if `a >= b` or if no distinct midpoint exists between
/// them (e.g., `a` and `b` are adjacent in the byte ordering).
///
/// Reference: CockroachDB `SplitKey()` uses a similar byte-level
/// midpoint for automatic range splits.
pub fn byte_midpoint(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    assert!(!a.is_empty() || !b.is_empty(), "at least one key must be non-empty");

    if a >= b {
        return None;
    }

    // Pad the shorter key with zeros to match lengths.
    let max_len = a.len().max(b.len());
    let mut result = Vec::with_capacity(max_len);

    let mut carry: u16 = 0;

    // Work from least-significant byte to most-significant.
    // We build the result in reverse, then reverse it.
    let mut digits = Vec::with_capacity(max_len);

    for i in (0..max_len).rev() {
        let a_byte = if i < a.len() { a[i] as u16 } else { 0 };
        let b_byte = if i < b.len() { b[i] as u16 } else { 0 };

        let sum = a_byte + b_byte + carry;
        digits.push((sum % 256) as u8);
        carry = sum / 256;
    }

    // Now divide the sum by 2.
    digits.reverse();
    let mut remainder: u16 = 0;
    for byte in digits.iter_mut() {
        let val = remainder * 256 + (*byte as u16);
        *byte = (val / 2) as u8;
        remainder = val % 2;
    }

    result.extend_from_slice(&digits);

    // Trim trailing zeros that extend beyond both input lengths.
    while result.len() > a.len().max(b.len()) && result.last() == Some(&0) {
        result.pop();
    }

    // Verify the midpoint is strictly between a and b.
    if result.as_slice() <= a || result.as_slice() >= b {
        return None;
    }

    Some(result)
}

// ---------------------------------------------------------------------------
// Â§1.9 Domain constant additions
// ---------------------------------------------------------------------------

/// Domain constants for Boundary â‘¢.
pub mod domain {
    // ... existing constants from Boundaries â‘  and â‘¡ ...

    /// Shard hint encoding version tag.
    pub const SHARD_HINT_V1: &[u8] = b"gossip/shard-hint/v1";
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ prefix_successor â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn prefix_successor_basic() {
        assert_eq!(
            prefix_successor(b"abc"),
            Some(b"abd".to_vec()),
        );
    }

    #[test]
    fn prefix_successor_trailing_ff() {
        assert_eq!(
            prefix_successor(b"ab\xff"),
            Some(b"ac".to_vec()),
        );
    }

    #[test]
    fn prefix_successor_multiple_trailing_ff() {
        assert_eq!(
            prefix_successor(b"a\xff\xff"),
            Some(b"b".to_vec()),
        );
    }

    #[test]
    fn prefix_successor_all_ff() {
        assert_eq!(prefix_successor(b"\xff\xff\xff"), None);
    }

    #[test]
    fn prefix_successor_empty() {
        assert_eq!(prefix_successor(b""), None);
    }

    #[test]
    fn prefix_successor_single_byte() {
        assert_eq!(prefix_successor(b"\x00"), Some(b"\x01".to_vec()));
        assert_eq!(prefix_successor(b"\xfe"), Some(b"\xff".to_vec()));
        assert_eq!(prefix_successor(b"\xff"), None);
    }

    #[test]
    fn prefix_successor_preserves_ordering_invariant() {
        // For any string that starts with prefix, it must be < successor.
        let prefix = b"hello";
        let succ = prefix_successor(prefix).unwrap();

        // "hello" starts with "hello" â†’ must be < successor
        assert!(prefix.as_slice() < succ.as_slice());

        // "helloXYZ" starts with "hello" â†’ must be < successor
        let extended = b"helloXYZ";
        assert!(extended.as_slice() < succ.as_slice());

        // "hellp" does NOT start with "hello" â†’ not required to be < successor
        // (it should be >= successor since 'p' > 'o')
        assert!(b"hellp".as_slice() >= succ.as_slice());
    }

    // â”€â”€ PathKey â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn path_key_encode_round_trip() {
        let pk = PathKey::from_str("src/main.rs");
        assert_eq!(pk.encode(), b"src/main.rs");
    }

    #[test]
    fn path_key_ordering_matches_string() {
        let a = PathKey::from_str("aaa/file.rs");
        let b = PathKey::from_str("zzz/file.rs");
        assert!(a.encode() < b.encode());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn path_key_rejects_empty() {
        PathKey::new(b"");
    }

    #[test]
    #[should_panic(expected = "valid UTF-8")]
    fn path_key_rejects_invalid_utf8() {
        PathKey::new(&[0xFF, 0xFE]);
    }

    #[test]
    #[should_panic(expected = "interior null")]
    fn path_key_rejects_interior_null() {
        PathKey::new(b"src\x00main.rs");
    }

    // â”€â”€ TimeIdKey â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn time_id_key_encoding_format() {
        let k = TimeIdKey::new(1, b"id".to_vec());
        let encoded = k.encode();
        // 8 bytes BE timestamp + 2 bytes BE id_len + 2 bytes id
        assert_eq!(encoded.len(), 12);
        assert_eq!(&encoded[0..8], &1u64.to_be_bytes());
        assert_eq!(&encoded[8..10], &2u16.to_be_bytes());
        assert_eq!(&encoded[10..12], b"id");
    }

    #[test]
    fn time_id_key_timestamp_ordering() {
        let a = TimeIdKey::timestamp_only(100);
        let b = TimeIdKey::timestamp_only(200);
        assert!(a.encode() < b.encode());
    }

    #[test]
    fn time_id_key_same_timestamp_different_id() {
        let a = TimeIdKey::new(100, b"aaa".to_vec());
        let b = TimeIdKey::new(100, b"zzz".to_vec());
        assert!(a.encode() < b.encode());
    }

    #[test]
    fn time_id_key_logical_and_encoded_order_agree() {
        let a = TimeIdKey::new(100, b"abc".to_vec());
        let b = TimeIdKey::new(200, b"abc".to_vec());
        let c = TimeIdKey::new(200, b"xyz".to_vec());

        // Logical: a < b < c
        assert!(a < b);
        assert!(b < c);

        // Encoded: same ordering
        assert!(a.encode() < b.encode());
        assert!(b.encode() < c.encode());
    }

    // â”€â”€ ManifestRowKey â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn manifest_row_key_encoding_format() {
        let k = ManifestRowKey::new(42, 100);
        let encoded = k.encode();
        assert_eq!(encoded.len(), ManifestRowKey::ENCODED_LEN);
        assert_eq!(&encoded[0..8], &42u64.to_be_bytes());
        assert_eq!(&encoded[8..16], &100u64.to_be_bytes());
    }

    #[test]
    fn manifest_row_key_ordering() {
        let a = ManifestRowKey::new(1, 50);
        let b = ManifestRowKey::new(1, 100);
        let c = ManifestRowKey::new(2, 0);

        assert!(a.encode() < b.encode());
        assert!(b.encode() < c.encode());

        // Logical ordering matches.
        assert!(a < b);
        assert!(b < c);
    }

    // â”€â”€ OpaqueFixedKey â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn opaque_fixed_key_passthrough() {
        let k = OpaqueFixedKey::new(vec![0x01, 0x02, 0x03], 3);
        assert_eq!(k.encode(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    #[should_panic(expected = "does not match")]
    fn opaque_fixed_key_wrong_length() {
        OpaqueFixedKey::new(vec![0x01, 0x02], 3);
    }

    #[test]
    fn opaque_fixed_key_from_array() {
        let k = OpaqueFixedKey::from_array([0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(k.len(), 4);
        assert_eq!(k.encode(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    // â”€â”€ shard_spec_from_prefix â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_spec_from_prefix_basic() {
        let spec = shard_spec_from_prefix(b"src/", vec![]);
        assert_eq!(spec.key_range_start.as_ref(), b"src/");
        // "src/" successor is "src0" (0x2F + 1 = 0x30 = '0')
        assert_eq!(spec.key_range_end.as_ref(), b"src0");
    }

    #[test]
    fn shard_spec_from_prefix_all_ff() {
        let spec = shard_spec_from_prefix(b"\xff\xff", vec![]);
        assert_eq!(spec.key_range_start.as_ref(), b"\xff\xff");
        // No successor â†’ unbounded end.
        assert!(spec.is_end_unbounded());
    }

    // â”€â”€ shard_spec_from_manifest_range â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_spec_from_manifest_range_basic() {
        let spec = shard_spec_from_manifest_range(7, 0, 1000, vec![]);
        let start = ManifestRowKey::new(7, 0).encode();
        let end = ManifestRowKey::new(7, 1000).encode();
        assert_eq!(spec.key_range_start.as_ref(), start.as_slice());
        assert_eq!(spec.key_range_end.as_ref(), end.as_slice());
    }

    #[test]
    #[should_panic(expected = "start_row")]
    fn shard_spec_from_manifest_range_inverted() {
        shard_spec_from_manifest_range(7, 1000, 0, vec![]);
    }

    // â”€â”€ byte_midpoint â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn byte_midpoint_basic() {
        let mid = byte_midpoint(b"\x00", b"\x02").unwrap();
        assert_eq!(mid, vec![0x01]);
    }

    #[test]
    fn byte_midpoint_same_length() {
        let mid = byte_midpoint(b"\x00\x00", b"\x00\x04").unwrap();
        assert_eq!(mid, vec![0x00, 0x02]);
    }

    #[test]
    fn byte_midpoint_returns_none_for_equal() {
        assert!(byte_midpoint(b"abc", b"abc").is_none());
    }

    #[test]
    fn byte_midpoint_returns_none_for_inverted() {
        assert!(byte_midpoint(b"zzz", b"aaa").is_none());
    }

    #[test]
    fn byte_midpoint_returns_none_for_adjacent() {
        // \x00 and \x01 are adjacent â€” no byte string strictly between.
        assert!(byte_midpoint(b"\x00", b"\x01").is_none());
    }

    // â”€â”€ Property-based tests (stubs) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: proptest for KeyEncoding ordering invariant:
    //   For any schema S and keys a < b: S::encode(a) < S::encode(b)
    //
    // TODO: proptest for prefix_successor completeness:
    //   For any prefix P and string X that starts with P:
    //     P <= X < prefix_successor(P) (when successor exists)
    //
    // TODO: proptest for byte_midpoint:
    //   For any a < b where midpoint exists: a < midpoint(a,b) < b
    //
    // TODO: proptest for ManifestRowKey round-trip ordering:
    //   For any (m1,r1) < (m2,r2): encode(m1,r1) < encode(m2,r2)
    //
    // TODO: proptest for TimeIdKey ordering fidelity:
    //   For any a.cmp(b) == a.encode().cmp(b.encode())
}
