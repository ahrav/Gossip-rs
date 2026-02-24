//! Core key-encoding primitives for shard algebra.
//!
//! Shards partition the keyspace into half-open intervals `[start, end)` over
//! lexicographically ordered byte strings (the same model used by Bigtable,
//! Spanner, and FoundationDB).
//!
//! This module provides five building blocks:
//!
//! 1. **Ordering contract** ([`KeyEncoding`]) -- a trait that connectors
//!    implement so their typed keys produce byte encodings whose lexicographic
//!    order matches logical order. The coordinator itself never touches this
//!    trait; it works with raw `&[u8]` boundaries.
//!
//! 2. **Typed key schemas** -- [`PathKey`] and [`ManifestRowKey`] provide
//!    canonical encodings for current shard-algebra consumers.
//!
//! 3. **ShardSpec bridge helpers** -- fallible constructors that translate
//!    typed key inputs into owned [`ShardSpec`] values while preserving
//!    coordination-side validation and error semantics.
//!
//! 4. **Key arithmetic** -- three pure functions for computing boundary keys
//!    during split planning:
//!    - [`prefix_successor`]: exclusive upper bound for a prefix scan
//!      (analogous to FoundationDB `strinc` / CockroachDB `Key.PrefixEnd`).
//!    - [`key_successor`]: minimal strict successor of an arbitrary key,
//!      respecting the [`MAX_KEY_SIZE`] ceiling.
//!    - [`byte_midpoint`]: approximate bisection point between two keys,
//!      used by the split planner to halve a shard's range.
//!
//!    All three return `Option` -- `None` signals that the requested successor
//!    or midpoint does not exist within representable bounds.
//!
//! 5. **Error type** ([`PrefixShardError`]) -- models the failure modes when
//!    converting a user-supplied prefix into a bounded key range.
//!
//! # Zero-allocation calling convention
//!
//! Arithmetic helpers take a mutable [`KeyBuf`] supplied by the caller and
//! return a slice borrowed from that buffer. The returned slice remains valid
//! only until the same buffer is written again. Callers that need to retain a
//! key across later operations must copy it.
//!
//! # Scope boundary
//!
//! This module handles local, single-key arithmetic only.
//! Whole-partition invariants (coverage, disjointness, child ordering across
//! sibling shards) are validated in [`crate::coordination::shard_spec`].

use crate::coordination::shard_spec::{MAX_KEY_SIZE, ShardSpec, ShardSpecInputError};
use core::fmt;

/// Reusable stack buffer for shard-key arithmetic.
///
/// The buffer owns fixed-capacity storage and tracks the active key prefix via
/// `len`. Bytes after `len` are scratch space and not part of the logical key.
///
/// Capacity is `MAX_KEY_SIZE + 1` to allow `byte_midpoint`'s internal
/// carry-expanded arithmetic sum.
#[derive(Clone)]
pub struct KeyBuf {
    buf: [u8; Self::CAPACITY],
    len: usize,
}

impl KeyBuf {
    /// Maximum number of bytes this buffer can hold.
    pub const CAPACITY: usize = MAX_KEY_SIZE + 1;

    /// Create an empty key buffer.
    #[must_use]
    pub fn new() -> Self {
        Self {
            buf: [0u8; Self::CAPACITY],
            len: 0,
        }
    }

    /// View the active key bytes.
    ///
    /// The returned slice borrows this buffer and is invalidated by the next
    /// mutating write to the same `KeyBuf`.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Active byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether no bytes are active.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Copy `src` into this buffer and set the active length.
    ///
    /// This overwrites the active prefix `[0..src.len())`. Bytes beyond the new
    /// length are left unchanged and remain scratch space.
    ///
    /// # Panics
    ///
    /// Panics if `src.len() > Self::CAPACITY`.
    pub fn copy_from_slice(&mut self, src: &[u8]) {
        assert!(
            src.len() <= Self::CAPACITY,
            "key bytes exceed KeyBuf capacity: {} > {}",
            src.len(),
            Self::CAPACITY
        );
        self.buf[..src.len()].copy_from_slice(src);
        self.len = src.len();
    }
}

impl Default for KeyBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for KeyBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyBuf")
            .field("len", &self.len)
            .field("bytes", &self.as_bytes())
            .finish()
    }
}

/// Trait for key types that encode into lexicographically ordered bytes.
///
/// # Ordering contract
///
/// ```text
/// a < b  (logical ordering)  =>  encode(a) < encode(b)  (byte lex ordering)
/// ```
///
/// This invariant is load-bearing: cursor monotonicity, shard range-membership
/// checks, and deterministic split planning all rely on it. Violating it
/// silently corrupts range boundaries.
///
/// # Canonicality
///
/// Implementations must be canonical and deterministic:
/// - Logically equal keys must encode to identical byte strings.
/// - A single key must not encode differently across calls.
///
/// These properties ensure that key comparisons are stable regardless of when
/// or where they happen (local planner, coordinator, or across restarts).
///
/// # Usage
///
/// Connectors implement this trait for their domain-specific key types (e.g.,
/// file paths, manifest row IDs). The coordinator never calls `encode_into`
/// directly -- it operates on raw `&[u8]` boundaries produced by the shard
/// builder or split planner.
///
/// # Buffer contract
///
/// Implementations must write a complete canonical encoding into `buf` whose
/// length does not exceed [`KeyBuf::CAPACITY`]. Calling
/// [`KeyBuf::copy_from_slice`] satisfies this contract.
pub trait KeyEncoding: Sized {
    /// Encode this key into bytes that preserve logical ordering under
    /// lexicographic byte comparison.
    fn encode_into(&self, buf: &mut KeyBuf);
}

/// UTF-8 path key encoded as identity bytes.
///
/// # Invariants
///
/// Encoding is exactly `path.as_bytes()`: no separator rewriting, Unicode
/// normalization, or case folding.
///
/// # Trade-off
///
/// This keeps encoding deterministic and allocation-free, but logically
/// equivalent filesystem paths with different textual forms compare as
/// different keys. Callers that need canonical path semantics must normalize
/// before constructing [`PathKey`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PathKey<'a> {
    path: &'a str,
}

impl<'a> PathKey<'a> {
    /// Create a path key from UTF-8 path text.
    #[must_use]
    pub const fn new(path: &'a str) -> Self {
        Self { path }
    }

    /// Borrow the underlying UTF-8 path.
    #[must_use]
    pub const fn as_str(self) -> &'a str {
        self.path
    }
}

impl KeyEncoding for PathKey<'_> {
    fn encode_into(&self, buf: &mut KeyBuf) {
        buf.copy_from_slice(self.path.as_bytes());
    }
}

/// Fixed-width manifest row key encoded as `(manifest_id, row)` in big-endian
/// `u64`s.
///
/// Lexicographic byte ordering matches tuple ordering: compare by
/// `manifest_id` first, then by `row`. The fixed 16-byte layout avoids
/// delimiters/varints and keeps decode cost constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ManifestRowKey {
    manifest_id: u64,
    row: u64,
}

impl ManifestRowKey {
    /// Fixed encoded width in bytes: 8-byte manifest ID + 8-byte row.
    pub const ENCODED_LEN: usize = 16;

    /// Create a manifest row key.
    #[must_use]
    pub const fn new(manifest_id: u64, row: u64) -> Self {
        Self { manifest_id, row }
    }

    /// Manifest identifier component.
    #[must_use]
    pub const fn manifest_id(self) -> u64 {
        self.manifest_id
    }

    /// Row component.
    #[must_use]
    pub const fn row(self) -> u64 {
        self.row
    }

    fn encode_bytes(self) -> [u8; Self::ENCODED_LEN] {
        let mut out = [0u8; Self::ENCODED_LEN];
        out[..8].copy_from_slice(&self.manifest_id.to_be_bytes());
        out[8..].copy_from_slice(&self.row.to_be_bytes());
        out
    }
}

impl KeyEncoding for ManifestRowKey {
    fn encode_into(&self, buf: &mut KeyBuf) {
        let encoded = self.encode_bytes();
        buf.copy_from_slice(&encoded);
    }
}

/// Decode a fixed-width [`ManifestRowKey`] byte encoding.
///
/// Returns `(manifest_id, row)` when `key` is exactly
/// [`ManifestRowKey::ENCODED_LEN`] bytes containing two big-endian `u64`
/// fields. Returns `None` for any other length.
///
/// This function validates framing only; semantic checks (for example,
/// monotonic row ranges) are performed by higher-level helpers.
#[must_use]
pub fn decode_manifest_row_key(key: &[u8]) -> Option<(u64, u64)> {
    if key.len() != ManifestRowKey::ENCODED_LEN {
        return None;
    }

    let mut manifest_id_bytes = [0u8; 8];
    manifest_id_bytes.copy_from_slice(&key[..8]);
    let manifest_id = u64::from_be_bytes(manifest_id_bytes);

    let mut row_bytes = [0u8; 8];
    row_bytes.copy_from_slice(&key[8..]);
    let row = u64::from_be_bytes(row_bytes);

    Some((manifest_id, row))
}

/// Construct a [`ShardSpec`] from typed start/end boundaries.
///
/// `start` and `end` are encoded via [`KeyEncoding`] and then validated by
/// [`ShardSpec::try_with_range_and_metadata`]. This keeps range/metadata
/// validation single-sourced in coordination code.
///
/// # Trade-offs
///
/// - Allocates owned `Vec<u8>` values for both boundaries and metadata because
///   [`ShardSpec`] stores owned bytes.
/// - Performs no local pre-validation so callers receive canonical
///   [`ShardSpecInputError`] variants from coordination validation.
pub fn shard_spec_from_keys<Start: KeyEncoding, End: KeyEncoding>(
    start: &Start,
    end: &End,
    metadata: &[u8],
) -> Result<ShardSpec, ShardSpecInputError> {
    let mut encoded = KeyBuf::new();
    start.encode_into(&mut encoded);
    let start = encoded.as_bytes().to_vec();

    end.encode_into(&mut encoded);
    let end = encoded.as_bytes().to_vec();

    ShardSpec::try_with_range_and_metadata(start, end, metadata.to_vec())
}

/// Construct a prefix-bounded [`ShardSpec`] as `[prefix, prefix_successor)`.
///
/// The helper performs cheap prefix-specific checks first, then delegates final
/// range/metadata validation to [`ShardSpec::try_with_range_and_metadata`].
///
/// # Errors
///
/// - [`PrefixShardError::EmptyPrefix`] if `prefix` is empty.
/// - [`PrefixShardError::PrefixTooLarge`] if `prefix` exceeds
///   [`MAX_KEY_SIZE`].
/// - [`PrefixShardError::NoSuccessor`] for all-`0xFF` prefixes.
/// - [`PrefixShardError::InvalidShardSpec`] if coordination-level shard-spec
///   validation fails.
pub fn shard_spec_from_prefix(
    prefix: &[u8],
    metadata: &[u8],
) -> Result<ShardSpec, PrefixShardError> {
    if prefix.is_empty() {
        return Err(PrefixShardError::EmptyPrefix);
    }
    if prefix.len() > MAX_KEY_SIZE {
        return Err(PrefixShardError::PrefixTooLarge {
            size: prefix.len(),
            max: MAX_KEY_SIZE,
        });
    }

    let mut successor = KeyBuf::new();
    let end = prefix_successor(prefix, &mut successor).ok_or(PrefixShardError::NoSuccessor)?;

    ShardSpec::try_with_range_and_metadata(prefix.to_vec(), end.to_vec(), metadata.to_vec())
        .map_err(PrefixShardError::from)
}

/// Construct a same-manifest [`ShardSpec`] from a half-open row range.
///
/// Both boundaries use the same `manifest_id`, so the resulting shard covers
/// `[start_row, end_row)` within one manifest.
///
/// # Errors
///
/// Propagates [`ShardSpecInputError`] from [`shard_spec_from_keys`], including
/// inverted/degenerate ranges (for example, `start_row >= end_row`) and
/// metadata validation failures.
pub fn shard_spec_from_manifest_range(
    manifest_id: u64,
    start_row: u64,
    end_row: u64,
    metadata: &[u8],
) -> Result<ShardSpec, ShardSpecInputError> {
    let start = ManifestRowKey::new(manifest_id, start_row);
    let end = ManifestRowKey::new(manifest_id, end_row);
    shard_spec_from_keys(&start, &end, metadata)
}

/// Compute the lexicographic successor of a byte prefix.
///
/// Returns the smallest byte string strictly greater than `prefix` that also
/// acts as an exclusive upper bound for *every* key that starts with `prefix`.
/// Formally, if `Some(succ)` is returned then for every key `k`:
///
/// ```text
/// k.starts_with(prefix)  =>  k < succ
/// ```
///
/// # Algorithm
///
/// 1. Find the rightmost byte that is not `0xFF`.
/// 2. Truncate the prefix to include that byte, discarding the trailing
///    `0xFF` suffix.
/// 3. Increment the last remaining byte by one.
///
/// Truncation is essential: incrementing *after* trailing `0xFF` bytes would
/// produce a longer string that is not a tight upper bound (it would leave a
/// gap). Truncation + increment produces the shortest possible successor.
///
/// # Returns `None`
///
/// - Empty prefix: no bytes to increment.
/// - All-`0xFF` prefix: the prefix already covers the top of the keyspace;
///   there is no byte string that can serve as an exclusive upper bound.
/// - Prefix length exceeds [`KeyBuf::CAPACITY`].
///
/// # Output buffer semantics
///
/// The returned slice aliases `buf`; reusing `buf` for another operation
/// overwrites that output.
///
/// # Complexity
///
/// `O(prefix.len())` time, no heap allocation.
///
/// # Examples
///
/// ```text
/// let mut buf = KeyBuf::new();
/// prefix_successor(b"abc", &mut buf)     => Some(b"abd")
/// prefix_successor(b"ab\xff", &mut buf)  => Some(b"ac")      // trailing 0xFF stripped
/// prefix_successor(b"\xff", &mut buf)    => None              // top of keyspace
/// prefix_successor(b"", &mut buf)        => None              // nothing to increment
/// ```
#[must_use]
pub fn prefix_successor<'a>(prefix: &[u8], buf: &'a mut KeyBuf) -> Option<&'a [u8]> {
    if prefix.len() > KeyBuf::CAPACITY {
        return None;
    }

    // Strip trailing 0xFF bytes by finding the last byte that can be incremented.
    let last_non_ff = prefix.iter().rposition(|&byte| byte != u8::MAX)?;
    let out_len = last_non_ff + 1;

    // Truncate and increment: the result is shorter than or equal to `prefix`,
    // which guarantees it is the tightest possible upper bound.
    buf.buf[..out_len].copy_from_slice(&prefix[..out_len]);
    debug_assert!(buf.buf[last_non_ff] < u8::MAX);
    buf.buf[last_non_ff] += 1;
    buf.len = out_len;
    Some(buf.as_bytes())
}

/// Compute a midpoint key in the open interval `(a, b)`.
///
/// Designed for split planning to bisect a shard's key range. The caller can
/// then create two child shards covering `[parent_start, mid)` and
/// `[mid, parent_end)`.
///
/// # Algorithm
///
/// The shorter input is right-padded with `0x00` to
/// `max_len = max(a.len(), b.len())`, then the function executes this exact
/// sequence:
///
/// 1. **Add** padded `a + b` from LSB to MSB with carry, yielding
///    `max_len` or `max_len + 1` bytes.
/// 2. **Halve** that sum by long division from MSB to LSB.
/// 3. **Try overflow-normalized candidate**: when the quotient is
///    `max_len + 1` bytes and begins with `0x00`, drop exactly that one
///    leading byte and return it if `a < candidate < b`.
/// 4. **Try fixed-width candidate**: test the unmodified quotient bytes and
///    return them if they do not exceed [`MAX_KEY_SIZE`] and `a < candidate < b`.
/// 5. **Fallback successor**: if both arithmetic candidates fail, compute
///    `key_successor(a)` and return it only if it remains `< b`.
///
/// No other canonicalization is applied (notably, no general leading-zero
/// trimming).
///
/// The successor fallback handles dense lexicographic ranges where the
/// arithmetic midpoint lands on a boundary, e.g. `[0x01]..[0x02]` returns
/// `[0x01, 0x00]`.
///
/// # Returns `None`
///
/// - `a >= b` (precondition violated; includes both-empty inputs).
/// - Either input exceeds [`MAX_KEY_SIZE`].
/// - Neither arithmetic candidate is strictly inside `(a, b)`, and
///   `key_successor(a)` is missing or `>= b`.
///
/// # Output buffer semantics
///
/// The returned midpoint aliases `out`; subsequent writes to `out` replace it.
///
/// # Complexity
///
/// `O(max(a.len(), b.len()))` time using stack-resident scratch buffers
/// (bounded by [`KeyBuf::CAPACITY`]), with no heap allocation.
#[must_use]
pub fn byte_midpoint<'a>(a: &[u8], b: &[u8], out: &'a mut KeyBuf) -> Option<&'a [u8]> {
    if a >= b {
        return None;
    }

    let max_len = a.len().max(b.len());
    if max_len == 0 || max_len > MAX_KEY_SIZE {
        return None;
    }

    // Phase 1: Big-endian addition from LSB to MSB with direct positional writes.
    let mut sum = KeyBuf::new();
    let mut carry: u16 = 0;
    for idx in (0..max_len).rev() {
        let a_byte = if idx < a.len() { u16::from(a[idx]) } else { 0 };
        let b_byte = if idx < b.len() { u16::from(b[idx]) } else { 0 };
        let total = a_byte + b_byte + carry;
        sum.buf[idx + 1] = (total & 0xFF) as u8;
        carry = total >> 8;
    }
    sum.buf[0] = carry as u8;
    sum.len = max_len + 1;

    // Phase 2: Divide by 2 from MSB to LSB.
    let mut remainder: u16 = 0;
    for idx in 0..sum.len {
        let value = (remainder << 8) | u16::from(sum.buf[idx]);
        sum.buf[idx] = (value / 2) as u8;
        remainder = value % 2;
    }

    // Phase 3: Validate arithmetic candidates.
    if sum.len == max_len + 1 && sum.buf[0] == 0 {
        let normalized = &sum.buf[1..sum.len];
        if normalized > a && normalized < b {
            out.copy_from_slice(normalized);
            return Some(out.as_bytes());
        }
    }

    let arithmetic = &sum.buf[..sum.len];
    if arithmetic.len() <= MAX_KEY_SIZE && arithmetic > a && arithmetic < b {
        out.copy_from_slice(arithmetic);
        return Some(out.as_bytes());
    }

    // Phase 4: If neither arithmetic candidate is interior, use the minimal
    // strict successor of `a`.
    let mut successor_buf = KeyBuf::new();
    let successor = key_successor(a, &mut successor_buf)?;
    if successor < b {
        out.copy_from_slice(successor);
        return Some(out.as_bytes());
    }

    None
}

/// Compute the smallest representable key that is strictly greater than `key`.
///
/// This primitive derives an exclusive
/// end-bound from an inclusive key, subject to the system-wide key size
/// limit ([`MAX_KEY_SIZE`] = 4 KiB).
///
/// # Strategy
///
/// | Condition | Action | Rationale |
/// |---|---|---|
/// | `key.len() < MAX_KEY_SIZE` | Append `0x00` | Minimal extension: `key` is a proper prefix of `key \|\| [0x00]`, so it sorts immediately after `key` but before any other extension sharing the same prefix. |
/// | `key.len() == MAX_KEY_SIZE` | Delegate to [`prefix_successor`] | Cannot grow; must increment in place. |
/// | `key.len() > MAX_KEY_SIZE` | Return `None` | Key already violates the size ceiling. |
///
/// Appending `0x00` is preferred over incrementing because it never fails
/// (any byte string can be extended with a zero byte), whereas incrementing
/// fails for the all-`0xFF` case.
///
/// # Returns `None`
///
/// - Key exceeds `MAX_KEY_SIZE`.
/// - Key is exactly `MAX_KEY_SIZE` bytes and all bytes are `0xFF` (no
///   successor exists within the representable keyspace).
///
/// # Output buffer semantics
///
/// The returned slice aliases `buf`; reusing `buf` overwrites that output.
///
/// # Complexity
///
/// `O(key.len())` time, no heap allocation.
#[must_use]
pub fn key_successor<'a>(key: &[u8], buf: &'a mut KeyBuf) -> Option<&'a [u8]> {
    if key.len() > MAX_KEY_SIZE {
        return None;
    }

    // Prefer append-zero: it is infallible and produces the tightest
    // possible successor (the key extended by the smallest byte value).
    if key.len() < MAX_KEY_SIZE {
        let out_len = key.len() + 1;
        buf.buf[..key.len()].copy_from_slice(key);
        buf.buf[key.len()] = 0;
        buf.len = out_len;
        return Some(buf.as_bytes());
    }

    // At the size ceiling: cannot grow, so fall back to in-place increment.
    prefix_successor(key, buf)
}

/// Error for invalid prefix-based shard operations.
///
/// Models failures when converting a user-supplied byte prefix into a valid
/// `[prefix, prefix_successor)` key range for shard construction. Each variant
/// represents a distinct failure mode, ordered roughly from cheapest to most
/// expensive to detect:
///
/// 1. [`EmptyPrefix`](Self::EmptyPrefix) -- trivially invalid.
/// 2. [`PrefixTooLarge`](Self::PrefixTooLarge) -- violates the system key-size ceiling.
/// 3. [`NoSuccessor`](Self::NoSuccessor) -- the prefix is valid but has no
///    lexicographic successor (all `0xFF`), so the half-open range cannot be
///    bounded.
/// 4. [`InvalidShardSpec`](Self::InvalidShardSpec) -- the derived range failed
///    downstream validation in [`ShardSpec`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrefixShardError {
    /// Prefix cannot be empty for prefix-only shard operations.
    EmptyPrefix,
    /// Prefix exceeds the shard-key size ceiling ([`MAX_KEY_SIZE`]).
    PrefixTooLarge {
        /// Actual prefix size in bytes.
        size: usize,
        /// Maximum allowed key size in bytes.
        max: usize,
    },
    /// Prefix has no lexicographic successor (all bytes are `0xFF`), so the
    /// exclusive end-bound of the half-open range cannot be computed.
    NoSuccessor,
    /// The derived key range passed local validation but failed downstream
    /// [`ShardSpec`] construction.
    InvalidShardSpec(ShardSpecInputError),
}

impl fmt::Display for PrefixShardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyPrefix => write!(f, "prefix shard requires a non-empty prefix"),
            Self::PrefixTooLarge { size, max } => {
                write!(f, "prefix too large ({size} bytes, max {max})")
            }
            Self::NoSuccessor => {
                write!(
                    f,
                    "prefix has no lexicographic successor (all bytes are 0xFF)"
                )
            }
            Self::InvalidShardSpec(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for PrefixShardError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidShardSpec(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ShardSpecInputError> for PrefixShardError {
    fn from(value: ShardSpecInputError) -> Self {
        Self::InvalidShardSpec(value)
    }
}
