//! Core key-encoding primitives for shard algebra.
//!
//! Shards partition the keyspace into half-open intervals `[start, end)` over
//! lexicographically ordered byte strings (the same model used by Bigtable,
//! Spanner, and FoundationDB). This module provides three things:
//!
//! 1. **Ordering contract** ([`KeyEncoding`]) -- a trait that connectors
//!    implement so their typed keys produce byte encodings whose lexicographic
//!    order matches logical order. The coordinator itself never touches this
//!    trait; it works with raw `&[u8]` / `Vec<u8>`.
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
//! **Scope boundary.** This module handles local, single-key arithmetic only.
//! Whole-partition invariants (coverage, disjointness, child ordering across
//! sibling shards) are validated in [`crate::coordination::shard_spec`].

use crate::coordination::shard_spec::{MAX_KEY_SIZE, ShardSpecInputError};
use core::fmt;

/// Trait for key types that encode into lexicographically ordered bytes.
///
/// # Ordering contract
///
/// ```text
/// a < b  (logical ordering)  =>  a.encode() < b.encode()  (byte lex ordering)
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
/// file paths, manifest row IDs). The coordinator never calls `encode()`
/// directly -- it operates on raw `&[u8]` boundaries produced by the shard
/// builder or split planner.
pub trait KeyEncoding: Sized {
    /// Encode this key into bytes that preserve logical ordering under
    /// lexicographic byte comparison.
    fn encode(&self) -> Vec<u8>;
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
///
/// # Examples
///
/// ```text
/// prefix_successor(b"abc")     => Some(b"abd")
/// prefix_successor(b"ab\xff")  => Some(b"ac")      // trailing 0xFF stripped
/// prefix_successor(b"\xff")    => None              // top of keyspace
/// prefix_successor(b"")        => None              // nothing to increment
/// ```
#[must_use]
pub fn prefix_successor(prefix: &[u8]) -> Option<Vec<u8>> {
    // Strip trailing 0xFF bytes by finding the last byte that can be incremented.
    let last_non_ff = prefix.iter().rposition(|&byte| byte != u8::MAX)?;

    // Truncate and increment: the result is shorter than or equal to `prefix`,
    // which guarantees it is the tightest possible upper bound.
    let mut next = prefix[..=last_non_ff].to_vec();
    debug_assert!(next[last_non_ff] < u8::MAX);
    next[last_non_ff] += 1;
    Some(next)
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
/// # Complexity
///
/// `O(max(a.len(), b.len()))` time and space.
#[must_use]
pub fn byte_midpoint(a: &[u8], b: &[u8]) -> Option<Vec<u8>> {
    if a >= b {
        return None;
    }

    let max_len = a.len().max(b.len());
    if max_len == 0 || max_len > MAX_KEY_SIZE {
        return None;
    }

    // Phase 1: Big-endian addition from LSB to MSB with direct positional writes.
    //
    // We walk the bytes in reverse (least-significant first) so that carry
    // propagates naturally toward the most-significant byte. Shorter inputs
    // are implicitly zero-padded on the right (i.e., lower-significance
    // positions beyond their length contribute zero).
    //
    // The sum buffer is pre-allocated at `max_len + 1` to hold a possible
    // carry into the most-significant position. Each byte is written
    // directly at its final position (`idx + 1`), avoiding a post-loop
    // reverse.
    let sum_len = max_len + 1;
    let mut sum = vec![0u8; sum_len];
    let mut carry: u16 = 0;
    for idx in (0..max_len).rev() {
        let a_byte = if idx < a.len() { u16::from(a[idx]) } else { 0 };
        let b_byte = if idx < b.len() { u16::from(b[idx]) } else { 0 };
        let total = a_byte + b_byte + carry;
        sum[idx + 1] = (total & 0xFF) as u8;
        carry = total >> 8;
    }
    sum[0] = carry as u8;

    // Phase 2: Divide by 2 from MSB to LSB.
    //
    // Standard long division: carry the remainder from each byte into the
    // next lower byte. Because the dividend is the sum of two byte strings,
    // the quotient is their arithmetic mean.
    let mut remainder: u16 = 0;
    for byte in &mut sum {
        let value = (remainder << 8) | u16::from(*byte);
        *byte = (value / 2) as u8;
        remainder = value % 2;
    }

    // Phase 3: Validate arithmetic candidates.
    //
    // If addition overflowed by one byte, halving yields a synthetic leading
    // zero because the carried byte is at most 0x01. Drop exactly one byte and
    // test that normalized candidate first.
    if sum.len() == max_len + 1 && sum[0] == 0 {
        let normalized = &sum[1..];
        if normalized > a && normalized < b {
            return Some(normalized.to_vec());
        }
    }

    // Keep the fixed-width arithmetic candidate as-is when it lands in range.
    // Leading zero bytes from input width are significant for lex ordering.
    if sum.as_slice() > a && sum.as_slice() < b {
        return Some(sum);
    }

    // Phase 4: If neither arithmetic candidate is interior, use the minimal
    // strict successor of `a`.
    let successor = key_successor(a)?;
    if successor.as_slice() < b {
        return Some(successor);
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
#[must_use]
pub fn key_successor(key: &[u8]) -> Option<Vec<u8>> {
    if key.len() > MAX_KEY_SIZE {
        return None;
    }

    // Prefer append-zero: it is infallible and produces the tightest
    // possible successor (the key extended by the smallest byte value).
    if key.len() < MAX_KEY_SIZE {
        let mut next = Vec::with_capacity(key.len() + 1);
        next.extend_from_slice(key);
        next.push(0);
        return Some(next);
    }

    // At the size ceiling: cannot grow, so fall back to in-place increment.
    prefix_successor(key)
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
        fn encode(&self) -> Vec<u8> {
            self.0.clone()
        }
    }

    #[test]
    fn key_encoding_returns_encoded_bytes() {
        let key = BytesKey(vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(key.encode(), vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn prefix_successor_basic() {
        assert_eq!(prefix_successor(b"abc"), Some(b"abd".to_vec()));
        assert_eq!(prefix_successor(b"ab\xff"), Some(b"ac".to_vec()));
        assert_eq!(prefix_successor(b"\xff\xff"), None);
        assert_eq!(prefix_successor(b""), None);
    }

    #[test]
    fn key_successor_prefers_append_when_capacity_available() {
        assert_eq!(key_successor(b"abc"), Some(b"abc\0".to_vec()));
    }

    #[test]
    fn key_successor_uses_increment_when_at_max_size() {
        let mut key = vec![0; MAX_KEY_SIZE];
        key[MAX_KEY_SIZE - 1] = 0x7F;
        let mut expected = key.clone();
        expected[MAX_KEY_SIZE - 1] = 0x80;
        assert_eq!(key_successor(&key), Some(expected));
    }

    #[test]
    fn key_successor_none_for_all_ff_at_max_size() {
        let key = vec![u8::MAX; MAX_KEY_SIZE];
        assert_eq!(key_successor(&key), None);
    }

    #[test]
    fn byte_midpoint_rejects_oversized_inputs() {
        let oversized_a = vec![0x40; MAX_KEY_SIZE + 1];
        let oversized_b = vec![0xC0; MAX_KEY_SIZE + 1];
        assert_eq!(
            byte_midpoint(&oversized_a, &oversized_b),
            None,
            "inputs exceeding MAX_KEY_SIZE should be rejected"
        );
    }

    #[test]
    fn byte_midpoint_output_respects_max_key_size() {
        let a = vec![0x40; MAX_KEY_SIZE];
        let b = vec![0xC0; MAX_KEY_SIZE];
        if let Some(mid) = byte_midpoint(&a, &b) {
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
        assert_eq!(byte_midpoint(&[0x40], &[0xC0]), Some(vec![0x80]));
    }

    #[test]
    fn byte_midpoint_finds_interior_for_single_byte_gap() {
        assert_eq!(byte_midpoint(&[0x01], &[0x02]), Some(vec![0x01, 0x00]));
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
        assert_eq!(byte_midpoint(a, b), expected);
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
            if let Some(succ) = prefix_successor(&prefix) {
                prop_assert!(succ.as_slice() > prefix.as_slice());
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
            let succ = prefix_successor(&prefix).expect("non-all-ff prefix has successor");

            let mut key = prefix.clone();
            key.extend_from_slice(&suffix);

            prop_assert!(key.as_slice() < succ.as_slice());
        }

        #[test]
        fn byte_midpoint_is_strictly_between_when_present(
            a in proptest::collection::vec(any::<u8>(), 0..=32),
            b in proptest::collection::vec(any::<u8>(), 0..=32),
        ) {
            if let Some(mid) = byte_midpoint(&a, &b) {
                prop_assert!(a.as_slice() < mid.as_slice());
                prop_assert!(mid.as_slice() < b.as_slice());
            }
        }

        // -- key_successor property tests --

        /// `key_successor` result is strictly greater than the input when `Some`.
        #[test]
        fn key_successor_is_strictly_greater(
            key in proptest::collection::vec(any::<u8>(), 0..=MAX_KEY_SIZE),
        ) {
            if let Some(succ) = key_successor(&key) {
                prop_assert!(
                    succ.as_slice() > key.as_slice(),
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
            match key_successor(&key) {
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
            let succ = key_successor(&key).expect("below MAX_KEY_SIZE always has a successor");
            let mut expected = key.clone();
            expected.push(0x00);
            prop_assert_eq!(succ, expected);
        }

        /// At `MAX_KEY_SIZE`, `key_successor` delegates to `prefix_successor`.
        #[test]
        fn key_successor_delegates_to_prefix_successor_at_max(
            key in proptest::collection::vec(any::<u8>(), MAX_KEY_SIZE..=MAX_KEY_SIZE),
        ) {
            prop_assert_eq!(key_successor(&key), prefix_successor(&key));
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
            if a.as_slice() < b.as_slice()
                && let Some(mid) = byte_midpoint(&a, &b)
            {
                prop_assert!(a.as_slice() < mid.as_slice());
                prop_assert!(mid.as_slice() < b.as_slice());
            }
        }
    }
}
