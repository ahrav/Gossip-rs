//! Key encoding contract and standard schemas for the shard keyspace.
//!
//! This module defines how connectors produce the lex-ordered `Box<[u8]>`
//! values that `ShardSpec` (Boundary ②) and `Cursor` consume. The core
//! contract is the `KeyEncoding` trait: for any two values `a < b` in the
//! type's logical ordering, `a.encode() < b.encode()` in lexicographic
//! byte ordering.
//!
//! The coordinator never uses `KeyEncoding` — it works exclusively with
//! raw `Box<[u8]>`. The trait exists for documentation, property-based
//! testing, and connector guidance.
//!
//! ## Design Decisions (locked)
//!
//! D3.1: The shard keyspace operates on raw byte slices, not on `ItemKey`
//!       structs from Boundary ①. `ItemKey` (ConnectorTag + path) is the
//!       *logical identity*; the shard keyspace uses the *encoded byte
//!       representation* of the path portion only. ConnectorTag is constant
//!       per run and implicit.
//!
//!       Reference: Bigtable (Chang et al., OSDI 2006) — row keys are
//!       arbitrary byte strings; tablets are contiguous row ranges.
//!
//! D3.2: Standard key schemas are encoding *types*, not a trait with
//!       dynamic dispatch. Each schema is a concrete type with an
//!       `encode()` method. The coordinator always sees `Box<[u8]>`.
//!       However, all schemas share a documented `KeyEncoding` trait
//!       for: (a) documentation, (b) property-based testing, (c) connector
//!       guidance.
//!
//!       Reference: FoundationDB subspace/directory layer — typed key
//!       encoding with a shared tuple encoding scheme, but the core
//!       KV layer sees only bytes.
//!
//! D3.3: Big-endian encoding for numeric fields in composite keys.
//!       Lex byte ordering on big-endian integers matches numeric
//!       ordering. Little-endian does NOT.
//!
//!       This is the universal convention: Bigtable, Spanner,
//!       CockroachDB, FoundationDB tuple layer.
//!
//!       Note: DIFFERENT from `CanonicalBytes` (Boundary ①) which uses
//!       little-endian for hashing. Hashing needs collision-freedom
//!       only; shard keys need ordered encoding. Separate concerns.
//!
//! D3.5: `prefix_successor` computes the lexicographic successor of a
//!       byte prefix — the smallest byte string greater than all strings
//!       starting with the prefix.
//!
//!       Algorithm: strip trailing 0xFF bytes, increment the last
//!       non-0xFF byte. All-0xFF prefix → None (covers to end of
//!       keyspace).
//!
//!       Reference: FoundationDB `strinc()`; CockroachDB
//!       `Key.PrefixEnd()`.
//!
//! D3.4: `PathKey` encoding uses raw UTF-8 bytes with no additional
//!       normalization beyond what the connector provides. Normalization
//!       is connector-specific (HFS+ NFD, Linux byte-transparent, S3
//!       opaque bytes). The connector MUST document its choice.
//!
//!       Reference: Unicode Technical Report #15; POSIX path semantics.

use crate::coordination::shard_spec::ShardSpec;

// ============================================================================
// § Domain Constants
// ============================================================================

/// Domain constants for Boundary ③ (shard algebra).
///
/// These constants provide domain separation for shard-layer encoding
/// and hashing, following the same pattern as Boundary ① and ② constants.
///
/// Add these inside `pub mod domain { ... }` in `identity/mod.rs`,
/// under a `// -- Shard algebra (B3) --` section header.
pub mod domain {
    /// Shard hint encoding version tag.
    ///
    /// Used as the version discriminant in the `ShardHint` binary
    /// encoding format. The version byte is the first byte of the
    /// encoded hint, enabling forward-compatible decoding.
    ///
    /// Format context:
    /// ```text
    /// ShardHint encoding: [version: u8][tag: u8][payload]
    /// ```
    ///
    /// This constant identifies the `v1` encoding scheme. Future
    /// versions (v2, v3, ...) would use different version bytes,
    /// and decoders can dispatch on the version to handle evolution.
    pub const SHARD_HINT_V1: u8 = 0x01;
}

// ============================================================================
// § KeyEncoding Trait — the fundamental ordering contract
// ============================================================================

/// Trait for types that encode themselves into lexicographically ordered bytes.
///
/// ## The Fundamental Contract
///
/// For any two values `a` and `b` of the same concrete type implementing
/// this trait:
///
/// ```text
///   a < b  (in the type's logical ordering)
///     ⟹
///   a.encode() < b.encode()  (in lexicographic byte ordering)
/// ```
///
/// This is the **only** property the coordinator relies on. It enables:
/// - **Cursor monotonicity**: comparing `last_key` bytes (Boundary ②)
/// - **Range membership**: `spec.contains_key(&encoded)` (Boundary ②)
/// - **Split validation**: children tile parent by byte range (Boundary ②)
///
/// ## Why a Trait
///
/// The coordinator never uses this trait — it works with raw `Box<[u8]>`.
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
/// - Serialization (that's `CanonicalBytes` from Boundary ①, which is
///   for *hashing*, not *ordering*)
///
/// Reference: Bigtable, Spanner, CockroachDB, FoundationDB — all use
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

// ============================================================================
// § prefix_successor — lexicographic prefix bound computation
// ============================================================================

/// Compute the lexicographic successor of a byte prefix.
///
/// Returns the smallest byte string `s` such that for all byte strings `x`:
///
/// ```text
///   x starts with `prefix`  ⟹  prefix ≤ x < s
/// ```
///
/// This defines the half-open range `[prefix, s)` that contains exactly
/// the strings beginning with `prefix`.
///
/// ## Algorithm
///
/// 1. Strip trailing `0xFF` bytes (they cannot be incremented).
/// 2. Increment the last remaining byte.
/// 3. If the prefix is entirely `0xFF` bytes (or empty), return `None` —
///    the prefix covers through the end of the keyspace.
///
/// ## Examples
///
/// ```text
/// prefix_successor(b"abc")      → Some(b"abd")
/// prefix_successor(b"ab\xFF")   → Some(b"ac")
/// prefix_successor(b"\xFF\xFF") → None  (covers to end of keyspace)
/// prefix_successor(b"")         → None  (empty prefix = everything)
/// prefix_successor(b"\x00")     → Some(b"\x01")
/// prefix_successor(b"z\xFF\xFF") → Some(b"{")  ('{' = 'z' + 1)
/// ```
///
/// ## Invariants
///
/// **Safety (completeness)**: For any byte string `x` that starts with
/// `prefix`, `prefix <= x < successor`. No string starting with `prefix`
/// falls outside the range `[prefix, successor)`.
///
/// **Safety (tightness)**: `successor` is the smallest such bound. No
/// byte string between `predecessor_of(successor)` and `successor`
/// starts with `prefix`.
///
/// Reference: FoundationDB `strinc()` — identical algorithm;
///            CockroachDB `Key.PrefixEnd()` — same logic.
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    if prefix.is_empty() {
        return None;
    }

    // Find the last byte that is not 0xFF.
    let last_non_ff = prefix.iter().rposition(|&b| b != 0xFF);

    match last_non_ff {
        None => {
            // All bytes are 0xFF — no successor exists.
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

            // Postconditions: the result is a valid successor.
            assert!(!result.is_empty(), "successor must be non-empty");
            assert!(
                result.as_slice() > prefix,
                "successor must be greater than prefix"
            );

            Some(result)
        }
    }
}

// ============================================================================
// § PathKey — filesystem path encoding
// ============================================================================

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
/// | macOS HFS+ | NFD → NFC conversion |
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
        // Hot-path: avoid repeated reallocations when callers use `encode()`.
        buf.reserve(self.path.len());
        buf.extend_from_slice(&self.path);
    }
}

// ============================================================================
// § TimeIdKey — timestamp + tie-breaking ID encoding
// ============================================================================

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
/// ┌──────────────────────┬─────────────────┬───────────────────┐
/// │ timestamp (8 bytes)  │ id_len (2 bytes) │ id (variable)    │
/// │ big-endian u64       │ big-endian u16   │ raw bytes        │
/// └──────────────────────┴─────────────────┴───────────────────┘
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
/// Lex comparison: [.., 0x01] < [.., 0x02] ✓ — matches numeric ordering
/// ```
///
/// With little-endian, `256_u64` LE starts with `0x00` while `1_u64` LE
/// starts with `0x01`, so lex ordering gives `256 < 1` — WRONG.
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
///
/// Reference: Google Cloud, "Sharding of timestamp-ordered data in Cloud
/// Spanner" — addresses the hot-spot problem with timestamp-ordered keys.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TimeIdKey {
    /// Unix timestamp (seconds, milliseconds, or microseconds — the unit
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

        // Hot-path: avoid repeated reallocations when callers use `encode()`.
        buf.reserve(Self::HEADER_LEN + self.id.len());

        // Big-endian for lex ordering = numeric ordering.
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(&id_len.to_be_bytes());
        buf.extend_from_slice(&self.id);
    }
}

// ============================================================================
// § ManifestRowKey — manifest-based work unit encoding
// ============================================================================

/// Lex-ordered encoding of `(manifest_id, row)` composite keys.
///
/// ## Use Case
///
/// Manifest-based scanning where a pre-built manifest file lists all
/// work units (e.g., a file listing exported from a data warehouse,
/// a pre-enumerated S3 inventory, or a pre-computed list of API
/// endpoints to scan).
///
/// ## Encoding
///
/// ```text
/// ┌──────────────────────┬──────────────────────┐
/// │ manifest_id (8 bytes)│ row (8 bytes)         │
/// │ big-endian u64       │ big-endian u64        │
/// └──────────────────────┴──────────────────────┘
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
        // Hot-path: avoid repeated reallocations when callers use `encode()`.
        buf.reserve(Self::ENCODED_LEN);

        // Big-endian for lex ordering = numeric ordering.
        buf.extend_from_slice(&self.manifest_id.to_be_bytes());
        buf.extend_from_slice(&self.row.to_be_bytes());
    }
}

// ============================================================================
// § OpaqueFixedKey — passthrough for pre-encoded fixed-width keys
// ============================================================================

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
/// correct lexicographic order. The contracts crate cannot verify this —
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
    /// Panics if `bytes.len() != expected_len` or `expected_len == 0`.
    pub fn new(bytes: Vec<u8>, expected_len: usize) -> Self {
        assert!(expected_len > 0, "OpaqueFixedKey: length must be > 0");
        assert_eq!(
            bytes.len(),
            expected_len,
            "OpaqueFixedKey: byte length {} does not match expected {}",
            bytes.len(),
            expected_len,
        );

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
        // Hot-path: avoid repeated reallocations when callers use `encode()`.
        buf.reserve(self.bytes.len());
        buf.extend_from_slice(&self.bytes);
    }
}

// ============================================================================
// § Bridge helpers — building ShardSpec from key schemas
// ============================================================================

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

// ============================================================================
// § byte_midpoint — split-point selection
// ============================================================================

/// Compute an approximate midpoint between two byte keys.
///
/// Used by connectors and the split planner to select split points when
/// dividing a shard. The midpoint is computed as the arithmetic mean of
/// the two keys interpreted as big-endian unsigned integers.
///
/// ## Properties
///
/// - `midpoint(a, b)` is always in the open interval `(a, b)` when it
///   returns `Some`.
/// - The result has the same length as the longer of `a` and `b`.
/// - For very close keys (e.g., adjacent), no midpoint exists and the
///   function returns `None`.
///
/// ## Algorithm
///
/// 1. Pad the shorter key with 0x00 bytes on the right to match lengths.
/// 2. Add the two keys byte-by-byte (treating as a big-endian integer),
///    carrying overflow between positions.
/// 3. Divide the sum by 2, byte-by-byte from MSB to LSB.
/// 4. Verify the result is strictly between `a` and `b`.
///
/// ## Limitations
///
/// This is an approximation. For dense keyspaces it works well. For
/// sparse keyspaces (e.g., only two keys far apart), the midpoint may
/// fall in an empty region. This is acceptable because split-point
/// selection is a heuristic for load balancing, not a correctness
/// requirement.
///
/// Returns `None` if:
/// - `a >= b` (inverted or equal)
/// - No distinct midpoint exists between them (adjacent keys)
///
/// Reference: CockroachDB `SplitKey()` uses a similar byte-level
/// midpoint for automatic range splits.
pub fn byte_midpoint(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    assert!(
        !a.is_empty() || !b.is_empty(),
        "at least one key must be non-empty"
    );

    if a >= b {
        return None;
    }

    // Pad the shorter key with zeros to match lengths.
    let max_len = a.len().max(b.len());

    // Step 1: Add byte-by-byte from LSB (rightmost) to MSB (leftmost).
    // We accumulate in reverse, then reverse.
    let mut sum_digits = Vec::with_capacity(max_len);
    let mut carry: u16 = 0;

    for i in (0..max_len).rev() {
        let a_byte = if i < a.len() { a[i] as u16 } else { 0 };
        let b_byte = if i < b.len() { b[i] as u16 } else { 0 };

        let sum = a_byte + b_byte + carry;
        sum_digits.push((sum % 256) as u8);
        carry = sum / 256;
    }

    // Step 2: Reverse to get MSB-first order for division.
    sum_digits.reverse();

    // Step 3: Divide the sum by 2 from MSB to LSB.
    let mut remainder: u16 = 0;
    for byte in sum_digits.iter_mut() {
        let val = remainder * 256 + (*byte as u16);
        *byte = (val / 2) as u8;
        remainder = val % 2;
    }

    let result = sum_digits;

    // Postcondition: the midpoint must be strictly between a and b.
    if result.as_slice() <= a || result.as_slice() >= b {
        return None;
    }

    Some(result)
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── prefix_successor ────────────────────────────────────────────────

    #[test]
    fn prefix_successor_basic() {
        assert_eq!(prefix_successor(b"abc"), Some(b"abd".to_vec()));
    }

    #[test]
    fn prefix_successor_trailing_ff() {
        assert_eq!(prefix_successor(b"ab\xff"), Some(b"ac".to_vec()));
    }

    #[test]
    fn prefix_successor_multiple_trailing_ff() {
        assert_eq!(prefix_successor(b"a\xff\xff"), Some(b"b".to_vec()));
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
        let prefix = b"hello";
        let succ = prefix_successor(prefix).unwrap();

        assert!(prefix.as_slice() < succ.as_slice());

        let extended = b"helloXYZ";
        assert!(extended.as_slice() < succ.as_slice());

        assert!(b"hellp".as_slice() >= succ.as_slice());
    }

    #[test]
    fn prefix_successor_z_trailing_ff() {
        let succ = prefix_successor(b"z\xff\xff").unwrap();
        assert_eq!(succ, b"{".to_vec());
    }

    #[test]
    fn prefix_successor_mixed_ff_positions() {
        let succ = prefix_successor(b"\x00\xFF\x00\xFF\xFF").unwrap();
        assert_eq!(succ, b"\x00\xFF\x01".to_vec());
    }

    // ── KeyEncoding trait (minimal impl for testing) ────────────────────

    #[derive(Clone, Debug, PartialEq, Eq)]
    struct TrivialKey(Vec<u8>);

    impl KeyEncoding for TrivialKey {
        fn encode_to(&self, buf: &mut Vec<u8>) {
            buf.extend_from_slice(&self.0);
        }
    }

    #[test]
    fn key_encoding_encode_returns_bytes() {
        let k = TrivialKey(vec![0x01, 0x02, 0x03]);
        assert_eq!(k.encode(), vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn key_encoding_encode_boxed_returns_box() {
        let k = TrivialKey(vec![0xAA, 0xBB]);
        let boxed = k.encode_boxed();
        assert_eq!(boxed.as_ref(), &[0xAA, 0xBB]);
    }

    #[test]
    fn key_encoding_encode_to_appends() {
        let k = TrivialKey(vec![0x03, 0x04]);
        let mut buf = vec![0x01, 0x02];
        k.encode_to(&mut buf);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn key_encoding_empty_key_produces_empty_output() {
        let k = TrivialKey(vec![]);
        assert!(k.encode().is_empty());
        assert!(k.encode_boxed().is_empty());
    }

    // ── Domain constant ─────────────────────────────────────────────────

    #[test]
    fn shard_hint_v1_is_version_one() {
        assert_eq!(domain::SHARD_HINT_V1, 0x01);
    }

    // ── PathKey ─────────────────────────────────────────────────────────

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
    fn path_key_as_bytes() {
        let pk = PathKey::from_str("hello");
        assert_eq!(pk.as_bytes(), b"hello");
    }

    #[test]
    fn path_key_encode_boxed_for_shard_spec() {
        let pk = PathKey::from_str("src/lib.rs");
        let boxed = pk.encode_boxed();
        assert_eq!(boxed.as_ref(), b"src/lib.rs");
    }

    #[test]
    fn path_key_directory_ordering() {
        // "/" < "0" < "A" < "a" in ASCII
        let slash = PathKey::from_str("/root");
        let zero = PathKey::from_str("0dir");
        let upper = PathKey::from_str("Adir");
        let lower = PathKey::from_str("adir");

        assert!(slash.encode() < zero.encode());
        assert!(zero.encode() < upper.encode());
        assert!(upper.encode() < lower.encode());
    }

    #[test]
    fn path_key_derived_ord_matches_encode_ord() {
        // PathKey derives PartialOrd/Ord on the raw bytes, which must
        // agree with KeyEncoding ordering.
        let a = PathKey::from_str("abc");
        let b = PathKey::from_str("abd");
        assert!(a < b);
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

    #[test]
    fn path_key_allows_trailing_null() {
        // A trailing null is OK — only *interior* nulls are rejected.
        // (Interior = everything except the last byte.)
        let pk = PathKey::new(b"path\x00");
        assert_eq!(pk.as_bytes(), b"path\x00");
    }

    // ── TimeIdKey ───────────────────────────────────────────────────────

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

        // Encoded: same ordering.
        assert!(a.encode() < b.encode());
        assert!(b.encode() < c.encode());
    }

    #[test]
    fn time_id_key_empty_id() {
        let k = TimeIdKey::timestamp_only(42);
        let encoded = k.encode();
        assert_eq!(encoded.len(), TimeIdKey::HEADER_LEN);
        assert_eq!(&encoded[0..8], &42u64.to_be_bytes());
        assert_eq!(&encoded[8..10], &0u16.to_be_bytes());
    }

    #[test]
    fn time_id_key_length_prefix_ordering() {
        // Same timestamp, same prefix bytes, different lengths.
        // Shorter ID sorts first because id_len is encoded before id bytes.
        let short = TimeIdKey::new(100, b"ab".to_vec());
        let long = TimeIdKey::new(100, b"abc".to_vec());
        assert!(short.encode() < long.encode());
        assert!(short < long);
    }

    #[test]
    fn time_id_key_big_endian_numeric_ordering() {
        // Critical D3.3 invariant: big-endian encoding preserves numeric
        // ordering under lexicographic byte comparison.
        let small = TimeIdKey::timestamp_only(1);
        let big = TimeIdKey::timestamp_only(256);

        // With big-endian: 1 → [0,0,0,0,0,0,0,1], 256 → [0,0,0,0,0,0,1,0]
        // Lex: [..,0,1] < [..,1,0] ✓
        assert!(small.encode() < big.encode());

        // Verify this is NOT what little-endian would give:
        // With LE: 1 → [1,0,...], 256 → [0,1,...] → lex says 256 < 1! WRONG.
        // (We don't test LE, just document why BE is correct.)
    }

    // ── ManifestRowKey ──────────────────────────────────────────────────

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

    #[test]
    fn manifest_row_key_fixed_width() {
        // All ManifestRowKeys encode to exactly 16 bytes, regardless of values.
        let zero = ManifestRowKey::new(0, 0);
        let max = ManifestRowKey::new(u64::MAX, u64::MAX);
        assert_eq!(zero.encode().len(), 16);
        assert_eq!(max.encode().len(), 16);
    }

    #[test]
    fn manifest_row_key_same_manifest_row_ordering() {
        // Within a single manifest, row ordering is numeric.
        let r0 = ManifestRowKey::new(7, 0);
        let r1 = ManifestRowKey::new(7, 1);
        let r999 = ManifestRowKey::new(7, 999);

        assert!(r0.encode() < r1.encode());
        assert!(r1.encode() < r999.encode());
    }

    #[test]
    fn manifest_row_key_cross_manifest_ordering() {
        // Manifest 1, row 999 sorts BEFORE manifest 2, row 0.
        let m1_last = ManifestRowKey::new(1, 999);
        let m2_first = ManifestRowKey::new(2, 0);
        assert!(m1_last.encode() < m2_first.encode());
    }

    // ── OpaqueFixedKey ──────────────────────────────────────────────────

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

    #[test]
    fn opaque_fixed_key_as_bytes() {
        let k = OpaqueFixedKey::from_array([0x01, 0x02]);
        assert_eq!(k.as_bytes(), &[0x01, 0x02]);
    }

    #[test]
    fn opaque_fixed_key_ordering_is_lex() {
        let a = OpaqueFixedKey::from_array([0x00, 0xFF]);
        let b = OpaqueFixedKey::from_array([0x01, 0x00]);
        assert!(a.encode() < b.encode());
        assert!(a < b);
    }

    #[test]
    #[should_panic(expected = "length must be > 0")]
    fn opaque_fixed_key_rejects_zero_len() {
        OpaqueFixedKey::new(vec![], 0);
    }

    // ── shard_spec_from_prefix ──────────────────────────────────────────

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
        // No successor → unbounded end.
        assert!(spec.is_end_unbounded());
    }

    #[test]
    fn shard_spec_from_prefix_contains_matching_keys() {
        let spec = shard_spec_from_prefix(b"test/", vec![]);

        assert!(spec.contains_key(b"test/"));
        assert!(spec.contains_key(b"test/foo.rs"));
        assert!(spec.contains_key(b"test/deeply/nested/file.txt"));

        // Keys outside the prefix.
        assert!(!spec.contains_key(b"tesu/"));  // "u" > "t/" successor
        assert!(!spec.contains_key(b"tes"));    // before prefix
    }

    #[test]
    fn shard_spec_from_prefix_with_metadata() {
        let meta = b"repo:github/org/repo".to_vec();
        let spec = shard_spec_from_prefix(b"src/", meta.clone());
        assert_eq!(spec.metadata.as_ref(), meta.as_slice());
    }

    #[test]
    #[should_panic(expected = "prefix must not be empty")]
    fn shard_spec_from_prefix_rejects_empty() {
        shard_spec_from_prefix(b"", vec![]);
    }

    // ── shard_spec_from_keys ────────────────────────────────────────────

    #[test]
    fn shard_spec_from_keys_path() {
        let start = PathKey::from_str("a/");
        let end = PathKey::from_str("z/");
        let spec = shard_spec_from_keys(&start, &end, vec![]);

        assert_eq!(spec.key_range_start.as_ref(), b"a/");
        assert_eq!(spec.key_range_end.as_ref(), b"z/");
        assert!(spec.contains_key(b"m/file.txt"));
    }

    #[test]
    fn shard_spec_from_keys_manifest() {
        let start = ManifestRowKey::new(1, 0);
        let end = ManifestRowKey::new(1, 100);
        let spec = shard_spec_from_keys(&start, &end, vec![]);

        let row50 = ManifestRowKey::new(1, 50).encode();
        assert!(spec.contains_key(&row50));

        let row100 = ManifestRowKey::new(1, 100).encode();
        assert!(!spec.contains_key(&row100)); // exclusive end
    }

    // ── shard_spec_from_manifest_range ──────────────────────────────────

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

    #[test]
    fn shard_spec_from_manifest_range_contains_interior_rows() {
        let spec = shard_spec_from_manifest_range(3, 10, 20, vec![]);

        let row10 = ManifestRowKey::new(3, 10).encode();
        let row15 = ManifestRowKey::new(3, 15).encode();
        let row19 = ManifestRowKey::new(3, 19).encode();
        let row20 = ManifestRowKey::new(3, 20).encode();
        let row9 = ManifestRowKey::new(3, 9).encode();

        assert!(spec.contains_key(&row10));  // inclusive start
        assert!(spec.contains_key(&row15));
        assert!(spec.contains_key(&row19));
        assert!(!spec.contains_key(&row20)); // exclusive end
        assert!(!spec.contains_key(&row9));  // before start
    }

    #[test]
    #[should_panic(expected = "start_row")]
    fn shard_spec_from_manifest_range_equal_bounds() {
        shard_spec_from_manifest_range(1, 50, 50, vec![]);
    }

    // ── byte_midpoint ───────────────────────────────────────────────────

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
        // \x00 and \x01 are adjacent — no byte string strictly between.
        assert!(byte_midpoint(b"\x00", b"\x01").is_none());
    }

    #[test]
    fn byte_midpoint_wide_gap() {
        // midpoint of 0x00 and 0xFF = 0x7F (127.5 → 127)
        let mid = byte_midpoint(b"\x00", b"\xFF").unwrap();
        assert_eq!(mid, vec![0x7F]);
        // Verify: 0x00 < 0x7F < 0xFF
        assert!(b"\x00".as_slice() < mid.as_slice());
        assert!(mid.as_slice() < b"\xFF".as_slice());
    }

    #[test]
    fn byte_midpoint_multi_byte() {
        // midpoint of [0x00, 0x00] and [0x01, 0x00]
        // sum = [0x01, 0x00], half = [0x00, 0x80]
        let mid = byte_midpoint(b"\x00\x00", b"\x01\x00").unwrap();
        assert_eq!(mid, vec![0x00, 0x80]);
    }

    #[test]
    fn byte_midpoint_carries_across_bytes() {
        // midpoint of [0x00, 0xFF] and [0x01, 0x01]
        // sum = [0x02, 0x00], half = [0x01, 0x00]
        let mid = byte_midpoint(b"\x00\xFF", b"\x01\x01").unwrap();
        assert_eq!(mid, vec![0x01, 0x00]);
    }

    #[test]
    fn byte_midpoint_manifest_row_keys() {
        // Verify midpoint works for fixed-width ManifestRowKey encodings.
        let start = ManifestRowKey::new(1, 0).encode();
        let end = ManifestRowKey::new(1, 100).encode();

        let mid = byte_midpoint(&start, &end).unwrap();
        let expected = ManifestRowKey::new(1, 50).encode();
        assert_eq!(mid, expected);
    }

    #[test]
    fn byte_midpoint_preserves_strict_ordering() {
        // For several test pairs, verify a < mid < b.
        let pairs: Vec<(&[u8], &[u8])> = vec![
            (b"\x10", b"\x20"),
            (b"\x00\x00", b"\xFF\xFF"),
            (b"\x10\x00", b"\x10\x10"),
            (b"\x00", b"\x04"),
        ];

        for (a, b) in pairs {
            if let Some(mid) = byte_midpoint(a, b) {
                assert!(
                    a < mid.as_slice(),
                    "expected {:?} < {:?}",
                    a,
                    mid,
                );
                assert!(
                    mid.as_slice() < b,
                    "expected {:?} < {:?}",
                    mid,
                    b,
                );
            }
        }
    }

    #[test]
    fn byte_midpoint_different_lengths_short_a() {
        // a = [0x00], b = [0x00, 0x04]
        // Padded: a = [0x00, 0x00], b = [0x00, 0x04]
        // sum = [0x00, 0x04], half = [0x00, 0x02]
        let mid = byte_midpoint(b"\x00", b"\x00\x04").unwrap();
        assert_eq!(mid, vec![0x00, 0x02]);
    }

    // ── Property-based tests (proptest) ─────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        // Keep cases moderate: these run in every PR.
        #![proptest_config(ProptestConfig {
            cases: 512,
            .. ProptestConfig::default()
        })]

        // D3.3: For fixed-width integers, big-endian bytes sort lexicographically
        // the same way the integers sort numerically.
        #[test]
        fn prop_u64_be_lex_order_matches_numeric(a in any::<u64>(), b in any::<u64>()) {
            prop_assert_eq!(a.cmp(&b), a.to_be_bytes().cmp(&b.to_be_bytes()));
        }

        #[test]
        fn prop_u16_be_lex_order_matches_numeric(a in any::<u16>(), b in any::<u16>()) {
            prop_assert_eq!(a.cmp(&b), a.to_be_bytes().cmp(&b.to_be_bytes()));
        }

        // Composite key schemas: logical ordering must exactly match encoded ordering.
        #[test]
        fn prop_manifest_row_key_order_matches_encoding(
            manifest_a in any::<u64>(),
            row_a in any::<u64>(),
            manifest_b in any::<u64>(),
            row_b in any::<u64>(),
        ) {
            let a = ManifestRowKey::new(manifest_a, row_a);
            let b = ManifestRowKey::new(manifest_b, row_b);

            prop_assert_eq!(a.cmp(&b), a.encode().cmp(&b.encode()));
        }

        #[test]
        fn prop_time_id_key_order_matches_encoding(
            ts_a in any::<u64>(),
            ts_b in any::<u64>(),
            id_a in proptest::collection::vec(any::<u8>(), 0..=64),
            id_b in proptest::collection::vec(any::<u8>(), 0..=64),
        ) {
            let a = TimeIdKey::new(ts_a, id_a);
            let b = TimeIdKey::new(ts_b, id_b);

            prop_assert_eq!(a.cmp(&b), a.encode().cmp(&b.encode()));
        }

        // Prefix successor: for any key that starts with `prefix`, `key < prefix_successor(prefix)`.
        #[test]
        fn prop_prefix_successor_upper_bounds_prefix_space(
            prefix in proptest::collection::vec(any::<u8>(), 1..=32),
            suffix in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            // Only test prefixes with a successor (i.e., not all 0xFF).
            prop_assume!(prefix.iter().any(|b| *b != 0xFF));

            let succ = prefix_successor(&prefix).expect("successor must exist");
            prop_assert!(prefix.as_slice() < succ.as_slice());

            let mut candidate = prefix.clone();
            candidate.extend_from_slice(&suffix);

            // Candidate starts with prefix by construction.
            prop_assert!(candidate.as_slice() >= prefix.as_slice());
            prop_assert!(candidate.as_slice() < succ.as_slice());
        }

        // Midpoint: whenever it exists, it must be strictly between the inputs.
        #[test]
        fn prop_byte_midpoint_is_strictly_between(
            a in proptest::collection::vec(any::<u8>(), 0..=32),
            b in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            // `byte_midpoint` requires at least one non-empty key.
            prop_assume!(!(a.is_empty() && b.is_empty()));

            let (lo, hi) = if a < b { (a, b) } else { (b, a) };
            prop_assume!(lo < hi);

            if let Some(mid) = byte_midpoint(&lo, &hi) {
                prop_assert!(lo.as_slice() < mid.as_slice());
                prop_assert!(mid.as_slice() < hi.as_slice());
            }
        }
    }

}
