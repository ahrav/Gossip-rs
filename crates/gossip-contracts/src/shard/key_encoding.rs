//! Core key-encoding primitives for shard algebra.
//!
//! Shards partition the keyspace into half-open intervals `[start, end)` over
//! lexicographically ordered byte strings (the same model used by Bigtable,
//! Spanner, and FoundationDB).
//!
//! This module provides three building blocks:
//!
//! 1. **Ordering contract** ([`KeyEncoding`]) -- a trait that connectors
//!    implement so their typed keys produce byte encodings whose lexicographic
//!    order matches logical order. The coordinator itself never touches this
//!    trait; it works with raw `&[u8]` boundaries.
//!
//! 2. **Key arithmetic** -- three pure functions for computing boundary keys
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
//! 3. **Error type** ([`PrefixShardError`]) -- models the failure modes when
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

use crate::coordination::shard_spec::{MAX_KEY_SIZE, ShardSpecInputError};
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
/// Used by the split planner to bisect a shard's key range. The caller can
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
///    return them if `a < candidate < b`.
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
/// This is the primitive the split planner uses to derive an exclusive
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
///    downstream validation in [`ShardSpec`](crate::coordination::shard_spec::ShardSpec).
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
    /// [`ShardSpec`](crate::coordination::shard_spec::ShardSpec) construction.
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

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rstest::rstest;

    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct BytesKey(Vec<u8>);

    impl KeyEncoding for BytesKey {
        fn encode_into(&self, buf: &mut KeyBuf) {
            buf.copy_from_slice(&self.0);
        }
    }

    #[test]
    fn key_encoding_returns_encoded_bytes() {
        let key = BytesKey(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        let mut buf = KeyBuf::new();
        key.encode_into(&mut buf);
        assert_eq!(buf.as_bytes(), [0xDE, 0xAD, 0xBE, 0xEF].as_slice());
    }

    #[test]
    fn prefix_successor_basic() {
        let mut buf = KeyBuf::new();
        assert_eq!(prefix_successor(b"abc", &mut buf), Some(b"abd".as_slice()));
        assert_eq!(
            prefix_successor(b"ab\xff", &mut buf),
            Some(b"ac".as_slice())
        );
        assert_eq!(prefix_successor(b"\xff\xff", &mut buf), None);
        assert_eq!(prefix_successor(b"", &mut buf), None);
    }

    #[test]
    fn key_successor_prefers_append_when_capacity_available() {
        let mut buf = KeyBuf::new();
        assert_eq!(key_successor(b"abc", &mut buf), Some(b"abc\0".as_slice()));
    }

    #[test]
    fn key_successor_uses_increment_when_at_max_size() {
        let mut key = vec![0; MAX_KEY_SIZE];
        key[MAX_KEY_SIZE - 1] = 0x7F;
        let mut expected = key.clone();
        expected[MAX_KEY_SIZE - 1] = 0x80;

        let mut buf = KeyBuf::new();
        assert_eq!(key_successor(&key, &mut buf), Some(expected.as_slice()));
    }

    #[test]
    fn key_successor_none_for_all_ff_at_max_size() {
        let key = vec![u8::MAX; MAX_KEY_SIZE];
        let mut buf = KeyBuf::new();
        assert_eq!(key_successor(&key, &mut buf), None);
    }

    #[test]
    fn byte_midpoint_rejects_oversized_inputs() {
        let oversized_a = vec![0x40; MAX_KEY_SIZE + 1];
        let oversized_b = vec![0xC0; MAX_KEY_SIZE + 1];

        let mut buf = KeyBuf::new();
        assert_eq!(
            byte_midpoint(&oversized_a, &oversized_b, &mut buf),
            None,
            "inputs exceeding MAX_KEY_SIZE should be rejected"
        );
    }

    #[test]
    fn byte_midpoint_output_respects_max_key_size() {
        let a = vec![0x40; MAX_KEY_SIZE];
        let b = vec![0xC0; MAX_KEY_SIZE];

        let mut buf = KeyBuf::new();
        if let Some(mid) = byte_midpoint(&a, &b, &mut buf) {
            assert!(
                mid.len() <= MAX_KEY_SIZE,
                "midpoint length {} exceeds MAX_KEY_SIZE {}",
                mid.len(),
                MAX_KEY_SIZE
            );
        }
    }

    #[test]
    fn byte_midpoint_carry_regression() {
        let mut buf = KeyBuf::new();
        assert_eq!(
            byte_midpoint(&[0x40], &[0xC0], &mut buf),
            Some([0x80].as_slice())
        );
    }

    #[test]
    fn byte_midpoint_finds_interior_for_single_byte_gap() {
        let mut buf = KeyBuf::new();
        assert_eq!(
            byte_midpoint(&[0x01], &[0x02], &mut buf),
            Some([0x01, 0x00].as_slice())
        );
    }

    // -- rstest parameterized: byte_midpoint edge cases with different lengths --

    #[rstest]
    #[case::both_empty(&[], &[], None)]
    #[case::empty_vs_nonempty(&[], &[0x02], Some(vec![0x01]))]
    #[case::full_byte_range(&[0x00], &[0xFF], Some(vec![0x7F]))]
    #[case::shared_leading_zero_prefix(&[0x00, 0x00], &[0x00, 0x02], Some(vec![0x00, 0x01]))]
    #[case::second_byte_gap(&[0x01, 0x00], &[0x01, 0x04], Some(vec![0x01, 0x02]))]
    #[case::different_lengths_close(&[0x01], &[0x01, 0x00], None)]
    #[case::high_bytes_different_lengths(&[0xFF], &[0xFF, 0x02], Some(vec![0xFF, 0x01]))]
    #[case::wide_gap_different_lengths(&[0x10], &[0x10, 0x80], Some(vec![0x10, 0x40]))]
    fn byte_midpoint_edge_cases(
        #[case] a: &[u8],
        #[case] b: &[u8],
        #[case] expected: Option<Vec<u8>>,
    ) {
        let mut buf = KeyBuf::new();
        assert_eq!(byte_midpoint(a, b, &mut buf), expected.as_deref());
    }

    // -- rstest parameterized: PrefixShardError Display formatting --

    #[rstest]
    #[case::empty_prefix(PrefixShardError::EmptyPrefix, "non-empty prefix")]
    #[case::prefix_too_large(
        PrefixShardError::PrefixTooLarge { size: 5000, max: 4096 },
        "5000 bytes, max 4096",
    )]
    #[case::no_successor(PrefixShardError::NoSuccessor, "all bytes are 0xFF")]
    fn prefix_shard_error_display_contains(
        #[case] error: PrefixShardError,
        #[case] expected_substr: &str,
    ) {
        let msg = error.to_string();
        assert!(
            msg.contains(expected_substr),
            "expected Display output to contain {expected_substr:?}, got {msg:?}"
        );
    }

    #[test]
    fn prefix_shard_error_source_delegates_for_invalid_shard_spec() {
        use std::error::Error;

        let inner = ShardSpecInputError::KeyTooLarge {
            size: 5000,
            max: MAX_KEY_SIZE,
        };
        let err = PrefixShardError::InvalidShardSpec(inner.clone());
        let source = err.source().expect("InvalidShardSpec should have a source");
        assert_eq!(source.to_string(), inner.to_string());

        // Non-delegating variants have no source.
        assert!(PrefixShardError::EmptyPrefix.source().is_none());
        assert!(PrefixShardError::NoSuccessor.source().is_none());
        assert!(
            PrefixShardError::PrefixTooLarge { size: 1, max: 4096 }
                .source()
                .is_none()
        );
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn prefix_successor_is_strictly_greater(prefix in proptest::collection::vec(any::<u8>(), 0..=32)) {
            let mut buf = KeyBuf::new();
            if let Some(succ) = prefix_successor(&prefix, &mut buf) {
                prop_assert!(succ > prefix.as_slice());
            } else {
                let no_successor = prefix.is_empty() || prefix.iter().all(|&byte| byte == u8::MAX);
                prop_assert!(no_successor);
            }
        }

        #[test]
        fn prefix_successor_is_upper_bound_for_prefixed_keys(
            prefix in proptest::collection::vec(any::<u8>(), 1..=32),
            suffix in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            prop_assume!(prefix.iter().any(|&byte| byte != u8::MAX));
            let mut buf = KeyBuf::new();
            let succ = prefix_successor(&prefix, &mut buf).expect("non-all-ff prefix has successor");

            let mut key = prefix.clone();
            key.extend_from_slice(&suffix);

            prop_assert!(key.as_slice() < succ);
        }

        #[test]
        fn byte_midpoint_is_strictly_between_when_present(
            a in proptest::collection::vec(any::<u8>(), 0..=32),
            b in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            let mut buf = KeyBuf::new();
            if let Some(mid) = byte_midpoint(&a, &b, &mut buf) {
                prop_assert!(a.as_slice() < mid);
                prop_assert!(mid < b.as_slice());
            }
        }

        // -- key_successor property tests --

        /// `key_successor` result is strictly greater than the input when `Some`.
        #[test]
        fn key_successor_is_strictly_greater(
            key in proptest::collection::vec(any::<u8>(), 0..=MAX_KEY_SIZE),
        ) {
            let mut buf = KeyBuf::new();
            if let Some(succ) = key_successor(&key, &mut buf) {
                prop_assert!(
                    succ > key.as_slice(),
                    "successor {succ:?} must be > input {key:?}"
                );
            }
        }

        /// `key_successor` returns `None` only when the key exceeds `MAX_KEY_SIZE`
        /// or is all-`0xFF` at exactly `MAX_KEY_SIZE`.
        #[test]
        fn key_successor_none_only_when_expected(
            key in proptest::collection::vec(any::<u8>(), 0..=(MAX_KEY_SIZE + 8)),
        ) {
            let mut buf = KeyBuf::new();
            match key_successor(&key, &mut buf) {
                Some(_) => {
                    prop_assert!(key.len() <= MAX_KEY_SIZE);
                }
                None => {
                    let oversized = key.len() > MAX_KEY_SIZE;
                    let all_ff_at_max = key.len() == MAX_KEY_SIZE
                        && key.iter().all(|&b| b == u8::MAX);
                    prop_assert!(
                        oversized || all_ff_at_max,
                        "key_successor returned None unexpectedly for key of len {} \
                         (oversized={oversized}, all_ff_at_max={all_ff_at_max})",
                        key.len()
                    );
                }
            }
        }

        /// Below `MAX_KEY_SIZE`, `key_successor` always appends `0x00`.
        #[test]
        fn key_successor_appends_zero_when_below_max(
            key in proptest::collection::vec(any::<u8>(), 0..MAX_KEY_SIZE),
        ) {
            let mut buf = KeyBuf::new();
            let succ = key_successor(&key, &mut buf).expect("below MAX_KEY_SIZE always has a successor");
            let mut expected = key.clone();
            expected.push(0x00);
            prop_assert_eq!(succ, expected.as_slice());
        }

        /// At `MAX_KEY_SIZE`, `key_successor` delegates to `prefix_successor`.
        #[test]
        fn key_successor_delegates_to_prefix_successor_at_max(
            key in proptest::collection::vec(any::<u8>(), MAX_KEY_SIZE..=MAX_KEY_SIZE),
        ) {
            let mut succ_buf = KeyBuf::new();
            let mut prefix_buf = KeyBuf::new();
            let succ = key_successor(&key, &mut succ_buf).map(|bytes| bytes.to_vec());
            let prefix = prefix_successor(&key, &mut prefix_buf).map(|bytes| bytes.to_vec());
            prop_assert_eq!(succ, prefix);
        }

        /// `byte_midpoint` with different-length inputs: the result (when `Some`)
        /// is always strictly between `a` and `b`.
        #[test]
        fn byte_midpoint_different_lengths_strictly_between(
            a in proptest::collection::vec(any::<u8>(), 0..=16),
            extra in proptest::collection::vec(any::<u8>(), 1..=16),
        ) {
            // Build `b` by extending `a` so lengths differ.
            let mut b = a.clone();
            b.extend_from_slice(&extra);
            // Ensure a < b (skip if not — the function returns None anyway).
            let mut buf = KeyBuf::new();
            if a.as_slice() < b.as_slice()
                && let Some(mid) = byte_midpoint(&a, &b, &mut buf)
            {
                prop_assert!(a.as_slice() < mid);
                prop_assert!(mid < b.as_slice());
            }
        }
    }
}
