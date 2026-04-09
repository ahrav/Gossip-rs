//! Cursor progress markers for shard checkpoint tracking.
//!
//! A cursor update carries two layers:
//!
//! - `last_key`: coordinator-visible ordered progress key.
//! - `token`: connector-opaque pagination/resume state.
//!
//! This module intentionally uses borrowed views ([`CursorUpdate`]) so
//! runtime paths can remain allocation-free.
//!
//! ## Constructor Families
//!
//! [`CursorUpdate`] provides two parallel constructor sets:
//!
//! - **Panicking** ([`CursorUpdate::new`], [`CursorUpdate::with_token`]):
//!   for internal code paths where inputs are already validated by the
//!   slab layer. These enforce non-empty `last_key` via `assert!` but do
//!   not check size limits.
//! - **Fallible** ([`CursorUpdate::try_new`], [`CursorUpdate::try_with_token`]):
//!   for boundaries accepting untrusted input. These validate both
//!   emptiness and size limits, returning [`CursorInputError`] on
//!   violations.
//!
//! ## Boundary interop
//!
//! Connector-facing code uses the owned `connector::Cursor` wrapper. Boundary
//! import (`connector::Cursor::try_from_update`) copies into owned wrappers,
//! while export (`connector::Cursor::as_update`) projects borrowed slices
//! allocation-free so coordination paths stay lean.

use blake3::Hasher;

use super::shard_spec::ShardSpecRef;
use crate::identity::CanonicalBytes;

/// Maximum size of a cursor `last_key` in bytes (4 KiB).
pub const MAX_KEY_SIZE: usize = 4_096;

/// Maximum size of a cursor `token` in bytes (16 KiB).
pub const MAX_TOKEN_SIZE: usize = 16_384;

/// Borrowed cursor view for allocation-free checkpoint/complete updates.
///
/// ## Invariants
///
/// - When `last_key` is `Some`, the slice is guaranteed non-empty. All
///   constructors enforce this: panicking (`new`, `with_token`) or
///   returning `Err` (`try_new`, `try_with_token`).
/// - `token` without `last_key` is not representable. A token only has
///   meaning as a continuation marker for an established position.
/// - Size limits ([`MAX_KEY_SIZE`], [`MAX_TOKEN_SIZE`]) are enforced
///   by the `try_*` constructors but not by the panicking constructors.
///   Use the `try_*` variants when accepting untrusted input.
///
/// ## Lifetime contract
///
/// `CursorUpdate` borrows slices from caller-owned storage. It does not retain
/// or clone data, so the referenced bytes must outlive the update value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorUpdate<'a> {
    last_key: Option<&'a [u8]>,
    token: Option<&'a [u8]>,
}

impl<'a> CursorUpdate<'a> {
    /// Initial update: no progress, no token.
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// Construct an update with a `last_key` and no token.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty.
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn new(last_key: &'a [u8]) -> Self {
        assert!(
            !last_key.is_empty(),
            "last_key must not be empty when present"
        );
        Self {
            last_key: Some(last_key),
            token: None,
        }
    }

    /// Alias for [`Self::new`].
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty (delegates to [`Self::new`]).
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn with_last_key(last_key: &'a [u8]) -> Self {
        Self::new(last_key)
    }

    /// Construct an update from key + token.
    ///
    /// Empty `token` normalizes to `None`.
    ///
    /// `token`-without-`last_key` is unrepresentable because the API requires
    /// `last_key` as the first argument.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty.
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn with_token(last_key: &'a [u8], token: &'a [u8]) -> Self {
        assert!(
            !last_key.is_empty(),
            "last_key must not be empty when present"
        );
        Self {
            last_key: Some(last_key),
            token: if token.is_empty() { None } else { Some(token) },
        }
    }

    /// Alias for [`Self::with_token`].
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty (delegates to [`Self::with_token`]).
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn from_parts(last_key: &'a [u8], token: &'a [u8]) -> Self {
        Self::with_token(last_key, token)
    }

    /// Fallible constructor for `last_key`-only updates.
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds [`MAX_KEY_SIZE`].
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_new(last_key: &'a [u8]) -> Result<Self, CursorInputError> {
        if last_key.is_empty() {
            return Err(CursorInputError::EmptyLastKey);
        }
        if last_key.len() > MAX_KEY_SIZE {
            return Err(CursorInputError::KeyTooLarge {
                size: last_key.len(),
                max: MAX_KEY_SIZE,
            });
        }
        Ok(Self {
            last_key: Some(last_key),
            token: None,
        })
    }

    /// Alias for [`Self::try_new`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::try_new`].
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_last_key(last_key: &'a [u8]) -> Result<Self, CursorInputError> {
        Self::try_new(last_key)
    }

    /// Fallible constructor for key + token updates.
    ///
    /// Empty `token` normalizes to `None`.
    /// This is a convenience for connectors that encode "no token" as
    /// an empty byte slice.
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds [`MAX_KEY_SIZE`].
    /// - [`CursorInputError::TokenTooLarge`] — `token` exceeds [`MAX_TOKEN_SIZE`].
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_token(last_key: &'a [u8], token: &'a [u8]) -> Result<Self, CursorInputError> {
        if last_key.is_empty() {
            return Err(CursorInputError::EmptyLastKey);
        }
        if last_key.len() > MAX_KEY_SIZE {
            return Err(CursorInputError::KeyTooLarge {
                size: last_key.len(),
                max: MAX_KEY_SIZE,
            });
        }
        if token.len() > MAX_TOKEN_SIZE {
            return Err(CursorInputError::TokenTooLarge {
                size: token.len(),
                max: MAX_TOKEN_SIZE,
            });
        }
        Ok(Self {
            last_key: Some(last_key),
            token: if token.is_empty() { None } else { Some(token) },
        })
    }

    /// Alias for [`Self::try_with_token`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::try_with_token`].
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_from_parts(last_key: &'a [u8], token: &'a [u8]) -> Result<Self, CursorInputError> {
        Self::try_with_token(last_key, token)
    }

    /// The key of the last fully-processed item, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn last_key(&self) -> Option<&'a [u8]> {
        self.last_key
    }

    /// The connector-opaque resume token, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn token(&self) -> Option<&'a [u8]> {
        self.token
    }
}

#[cfg(test)]
impl<'a> CursorUpdate<'a> {
    /// Test-only escape hatch for constructing states that public constructors
    /// intentionally forbid, so boundary adapters can exercise defensive paths.
    #[must_use]
    pub(crate) fn from_raw_parts_for_test(
        last_key: Option<&'a [u8]>,
        token: Option<&'a [u8]>,
    ) -> Self {
        Self { last_key, token }
    }
}

/// Encode cursor fields into a BLAKE3 hasher using a tagged-option format.
///
/// Each optional field is prefixed with a discriminant byte (`0` for `None`,
/// `1` for `Some`) followed by the canonical encoding of the inner value.
/// This prevents ambiguity between `None` and an empty slice, and ensures
/// identical cursors always produce identical digests regardless of
/// construction path.
#[inline]
fn write_cursor_canonical_parts(last_key: Option<&[u8]>, token: Option<&[u8]>, h: &mut Hasher) {
    match last_key {
        None => 0u8.write_canonical(h),
        Some(key) => {
            1u8.write_canonical(h);
            key.write_canonical(h);
        }
    }
    match token {
        None => 0u8.write_canonical(h),
        Some(tok) => {
            1u8.write_canonical(h);
            tok.write_canonical(h);
        }
    }
}

/// Feeds the cursor's `last_key` and `token` into a BLAKE3 hasher using
/// the tagged-option encoding: each optional field is prefixed with a
/// discriminant byte (`0` for `None`, `1` for `Some`) followed by the
/// canonical encoding of the inner value.
impl CanonicalBytes for CursorUpdate<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        write_cursor_canonical_parts(self.last_key(), self.token(), h);
    }
}

/// Error returned by fallible [`CursorUpdate`] constructors.
///
/// This type captures local field validation only. There is intentionally no
/// `TokenWithoutLastKey` variant because that state is unrepresentable through
/// the public constructors on [`CursorUpdate`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CursorInputError {
    /// The `last_key` was empty.
    #[error("last_key must not be empty when present")]
    EmptyLastKey,

    /// The `last_key` exceeds [`MAX_KEY_SIZE`].
    #[error("last_key too large ({size} bytes, max {max})")]
    KeyTooLarge {
        /// Actual size of the key in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_KEY_SIZE`]).
        max: usize,
    },

    /// The `token` exceeds [`MAX_TOKEN_SIZE`].
    #[error("token too large ({size} bytes, max {max})")]
    TokenTooLarge {
        /// Actual size of the token in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_TOKEN_SIZE`]).
        max: usize,
    },
}

/// Result of comparing two cursor updates for monotonic forward progress.
///
/// Coordination calls this before accepting a checkpoint or complete
/// operation so that a shard's scan position never regresses. Replays
/// at the same `last_key` are treated as `Forward`, a strictly lower key
/// yields `Regression`, and dropping an established key produces
/// `ResetToNone`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "advance check result must be inspected to enforce monotonicity"]
#[non_exhaustive]
pub enum CursorAdvance {
    /// New cursor represents forward progress (or idempotent same-position).
    Forward,
    /// New cursor has a `last_key` that is strictly less than the old one
    /// (lexicographic byte comparison).
    Regression,
    /// New cursor has `last_key = None` when old cursor had `Some`,
    /// indicating an attempt to erase established progress.
    ResetToNone,
}

/// Compare two cursor updates for monotonic forward progress.
///
/// Comparison uses lexicographic byte ordering on `last_key`. The token
/// field is ignored because it is connector-opaque and has no defined
/// ordering, so only the coordinator-visible progress key governs monotonicity.
///
/// Returns [`CursorAdvance::Forward`] for any transition that does not
/// move backwards, including same-position idempotent replays.
#[inline]
#[must_use = "ignoring the advance check defeats the monotonicity safety invariant"]
pub fn check_cursor_advance(old: CursorUpdate<'_>, new: CursorUpdate<'_>) -> CursorAdvance {
    let old_key = old.last_key();
    let new_key = new.last_key();
    debug_assert!(old_key.is_none_or(|k| !k.is_empty()));
    debug_assert!(new_key.is_none_or(|k| !k.is_empty()));

    match (old_key, new_key) {
        (None, Some(_)) => CursorAdvance::Forward,
        (None, None) => CursorAdvance::Forward,
        (Some(_), None) => CursorAdvance::ResetToNone,
        (Some(old_key), Some(new_key)) => {
            if new_key >= old_key {
                CursorAdvance::Forward
            } else {
                CursorAdvance::Regression
            }
        }
    }
}

/// Result of checking a cursor update against a shard's half-open key range
/// `[start, end)`.
///
/// Coordination layers call this whenever a shard reports progress to ensure
/// its `last_key` remains inside the assigned `ShardSpecRef`. An empty
/// `start` or `end` in the shard spec makes that boundary unbounded (negative
/// or positive infinity, respectively), so a fully unbounded spec
/// (`start = []`, `end = []`) always yields [`InBounds`](Self::InBounds)
/// for any non-`None` key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "bounds check result must be inspected to enforce range safety"]
#[non_exhaustive]
pub enum CursorBoundsCheck {
    /// Cursor has no `last_key`.
    NoKey,
    /// `last_key` is within the shard's key range.
    InBounds,
    /// `last_key` is below the shard's key range start.
    BelowRange,
    /// `last_key` is at or above the shard's key range end.
    AboveRange,
}

/// Check whether a cursor update's `last_key` falls within a shard's
/// half-open key range `[start, end)`.
///
/// An empty `start` or `end` in `spec` is treated as unbounded on that
/// side, so bounds checking is skipped for that boundary.
/// If the cursor contains no `last_key`, the check immediately returns
/// [`CursorBoundsCheck::NoKey`] because there is nothing to compare.
#[inline]
#[must_use = "ignoring the bounds check defeats the range safety invariant"]
pub fn check_cursor_bounds(cursor: CursorUpdate<'_>, spec: ShardSpecRef<'_>) -> CursorBoundsCheck {
    let Some(last_key) = cursor.last_key() else {
        return CursorBoundsCheck::NoKey;
    };

    let start = spec.key_range_start();
    if !start.is_empty() && last_key < start {
        return CursorBoundsCheck::BelowRange;
    }

    let end = spec.key_range_end();
    if !end.is_empty() && last_key >= end {
        return CursorBoundsCheck::AboveRange;
    }

    CursorBoundsCheck::InBounds
}

/// Compute the lexicographic prefix-successor of `prefix` into `out`.
///
/// The prefix-successor is the shortest byte string that is strictly
/// greater than `prefix` *and* is not a prefix-extension of `prefix`.
/// It is computed by stripping trailing `0xFF` bytes and incrementing the
/// last non-`0xFF` byte:
///
/// ```text
///   "abc"      -> "abd"          (increment last byte)
///   "ab\xFF"   -> "ac"           (strip 0xFF, increment 'b')
///   "\xFF\xFF" -> None           (all-0xFF has no prefix successor)
/// ```
///
/// Returns `None` when the input is empty, exceeds `MAX_KEY_SIZE`, or
/// consists entirely of `0xFF` bytes (the maximum element in the
/// lexicographic byte order has no successor).
///
/// Writes into caller-owned `out` so the result borrows from the caller's
/// scratch buffer rather than allocating.
/// The returned slice always points at the scratch buffer's prefix up to
/// the last non-`0xFF` byte that was incremented, keeping the representation
/// minimal for range math.
#[inline]
pub fn prefix_successor_into<'a>(
    prefix: &[u8],
    out: &'a mut [u8; MAX_KEY_SIZE],
) -> Option<&'a [u8]> {
    if prefix.is_empty() || prefix.len() > MAX_KEY_SIZE {
        return None;
    }
    let last_non_ff = prefix.iter().rposition(|&byte| byte != u8::MAX)?;
    let out_len = last_non_ff + 1;
    out[..out_len].copy_from_slice(&prefix[..out_len]);
    debug_assert!(out[last_non_ff] < u8::MAX);
    out[last_non_ff] += 1;
    Some(&out[..out_len])
}

/// Compute the lexicographic key-successor of `key` into `out`.
///
/// The key-successor is the smallest byte string that is strictly greater
/// than `key` in the lexicographic byte order. Two strategies are used
/// depending on the key length:
///
/// Callers (for example shard-splitting helpers) use this to produce the
/// minimal exclusive upper bound for a key while reusing the provided
/// `out` buffer to avoid allocating.
///
/// 1. **Short keys** (`len < MAX_KEY_SIZE`): append a `0x00` byte.
///    `"abc"` becomes `"abc\x00"`. This is the immediate successor
///    because no byte string exists between `"abc"` and `"abc\x00"` in
///    lexicographic order.
///
/// 2. **Maximum-length keys** (`len == MAX_KEY_SIZE`): appending is
///    impossible, so fall back to [`prefix_successor_into`], which strips
///    trailing `0xFF` bytes and increments. Returns `None` when the key
///    is all-`0xFF` at maximum length (the absolute maximum of the
///    keyspace).
///
/// Keys longer than `MAX_KEY_SIZE` are rejected (returns `None`).
/// An all-`0xFF` key at `MAX_KEY_SIZE` is already the lexicographic ceiling,
/// so no successor exists and `None` is returned in that case as well.
#[inline]
pub fn key_successor_into<'a>(key: &[u8], out: &'a mut [u8; MAX_KEY_SIZE]) -> Option<&'a [u8]> {
    if key.len() > MAX_KEY_SIZE {
        return None;
    }

    if key.len() < MAX_KEY_SIZE {
        out[..key.len()].copy_from_slice(key);
        out[key.len()] = 0;
        return Some(&out[..key.len() + 1]);
    }

    prefix_successor_into(key, out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::shard_spec::ShardSpec;
    use crate::test_util::{arb_bounded_shard_spec, arb_shard_spec, canonical_digest};
    use proptest::prelude::*;
    use rstest::rstest;

    #[test]
    fn initial_has_no_key_or_token() {
        let update = CursorUpdate::initial();
        assert!(update.last_key().is_none());
        assert!(update.token().is_none());
    }

    #[test]
    fn empty_token_normalizes_to_none() {
        let update = CursorUpdate::with_token(b"k", b"");
        assert_eq!(update.last_key(), Some(b"k".as_slice()));
        assert!(update.token().is_none());
    }

    #[test]
    fn fallible_constructors_enforce_size_limits() {
        let over_key = vec![0xAA; MAX_KEY_SIZE + 1];
        let over_token = vec![0xBB; MAX_TOKEN_SIZE + 1];
        assert!(matches!(
            CursorUpdate::try_new(&over_key),
            Err(CursorInputError::KeyTooLarge { .. })
        ));
        assert!(matches!(
            CursorUpdate::try_with_token(b"key", &over_token),
            Err(CursorInputError::TokenTooLarge { .. })
        ));
    }

    #[test]
    fn advance_truth_table() {
        let none = CursorUpdate::initial();
        let a = CursorUpdate::new(b"a");
        let b = CursorUpdate::new(b"b");

        assert_eq!(check_cursor_advance(none, none), CursorAdvance::Forward);
        assert_eq!(check_cursor_advance(none, a), CursorAdvance::Forward);
        assert_eq!(check_cursor_advance(a, a), CursorAdvance::Forward);
        assert_eq!(check_cursor_advance(a, b), CursorAdvance::Forward);
        assert_eq!(check_cursor_advance(b, a), CursorAdvance::Regression);
        assert_eq!(check_cursor_advance(a, none), CursorAdvance::ResetToNone);
    }

    #[test]
    fn bounds_truth_table() {
        let spec = ShardSpec::with_range(vec![b'a'], vec![b'z']);
        let start_unbounded = ShardSpec::with_range(vec![], vec![b'z']);
        let end_unbounded = ShardSpec::with_range(vec![b'a'], vec![]);

        assert_eq!(
            check_cursor_bounds(CursorUpdate::initial(), spec.as_ref()),
            CursorBoundsCheck::NoKey
        );
        assert_eq!(
            check_cursor_bounds(CursorUpdate::new(b"m"), spec.as_ref()),
            CursorBoundsCheck::InBounds
        );
        assert_eq!(
            check_cursor_bounds(CursorUpdate::new(b"0"), spec.as_ref()),
            CursorBoundsCheck::BelowRange
        );
        assert_eq!(
            check_cursor_bounds(CursorUpdate::new(b"z"), spec.as_ref()),
            CursorBoundsCheck::AboveRange
        );
        assert_eq!(
            check_cursor_bounds(CursorUpdate::new(b"m"), start_unbounded.as_ref()),
            CursorBoundsCheck::InBounds
        );
        assert_eq!(
            check_cursor_bounds(CursorUpdate::new(b"m"), end_unbounded.as_ref()),
            CursorBoundsCheck::InBounds
        );
    }

    #[test]
    fn canonical_digest_is_stable() {
        let a = CursorUpdate::with_token(b"abc", b"token");
        let b = CursorUpdate::with_token(b"abc", b"token");
        assert_eq!(canonical_digest(&a), canonical_digest(&b));
    }

    // -- prefix_successor_into smoke tests --

    #[test]
    fn prefix_successor_into_basic() {
        let mut out = [0u8; MAX_KEY_SIZE];

        // Normal increment.
        assert_eq!(
            prefix_successor_into(b"abc", &mut out),
            Some(b"abd".as_slice())
        );

        // Trailing 0xFF strip.
        assert_eq!(
            prefix_successor_into(b"ab\xFF", &mut out),
            Some(b"ac".as_slice()),
        );

        // All-0xFF → None.
        assert_eq!(prefix_successor_into(&[0xFF, 0xFF], &mut out), None);

        // Empty → None.
        assert_eq!(prefix_successor_into(b"", &mut out), None);
    }

    // -- key_successor_into smoke tests --

    #[test]
    fn key_successor_into_basic() {
        let mut out = [0u8; MAX_KEY_SIZE];

        // Short key: append 0x00.
        assert_eq!(
            key_successor_into(b"abc", &mut out),
            Some(b"abc\x00".as_slice()),
        );

        // MAX_KEY_SIZE key: fallback to prefix successor.
        let mut max_key = [0x50u8; MAX_KEY_SIZE];
        let result = key_successor_into(&max_key, &mut out).unwrap();
        max_key[MAX_KEY_SIZE - 1] = 0x51;
        assert_eq!(result, &max_key);

        // All-0xFF at MAX_KEY_SIZE → None.
        assert_eq!(key_successor_into(&[0xFF; MAX_KEY_SIZE], &mut out), None);
    }

    // rstest parameterized tests for prefix_successor_into
    #[rstest]
    #[case::normal(b"abc", Some(b"abd".as_slice()))]
    #[case::trailing_ff_strip(b"ab\xFF", Some(b"ac".as_slice()))]
    #[case::multi_ff_strip(b"a\xFF\xFF", Some(b"b".as_slice()))]
    #[case::all_ff(&[0xFF, 0xFF], None)]
    #[case::single_ff(&[0xFF], None)]
    #[case::empty(b"", None)]
    #[case::single_byte(b"a", Some(b"b".as_slice()))]
    #[case::single_byte_fe(&[0xFE], Some([0xFF].as_slice()))]
    fn prefix_successor_into_cases(#[case] input: &[u8], #[case] expected: Option<&[u8]>) {
        let mut out = [0u8; MAX_KEY_SIZE];
        assert_eq!(prefix_successor_into(input, &mut out), expected);
    }

    // rstest parameterized tests for key_successor_into
    #[rstest]
    #[case::short_key(b"abc".as_slice(), Some(b"abc\x00".as_slice()))]
    #[case::empty_key(b"".as_slice(), Some([0x00].as_slice()))]
    #[case::all_ff_at_max([0xFF; MAX_KEY_SIZE].as_slice(), None)]
    fn key_successor_into_cases(#[case] input: &[u8], #[case] expected: Option<&[u8]>) {
        let mut out = [0u8; MAX_KEY_SIZE];
        assert_eq!(key_successor_into(input, &mut out), expected);
    }

    #[test]
    fn key_successor_into_max_key_prefix_fallback() {
        let key = [0x50u8; MAX_KEY_SIZE];
        let mut out = [0u8; MAX_KEY_SIZE];
        let result = key_successor_into(&key, &mut out).unwrap();
        let mut expected = [0x50u8; MAX_KEY_SIZE];
        expected[MAX_KEY_SIZE - 1] = 0x51;
        assert_eq!(result, &expected);
    }

    #[test]
    fn key_successor_into_oversized_key() {
        let key = vec![0x42u8; MAX_KEY_SIZE + 1];
        let mut out = [0u8; MAX_KEY_SIZE];
        assert_eq!(key_successor_into(&key, &mut out), None);
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn bounds_matches_contains_key(
            key in proptest::collection::vec(any::<u8>(), 1..64),
            spec in arb_shard_spec(),
        ) {
            let update = CursorUpdate::new(&key);
            let bounds = check_cursor_bounds(update, spec.as_ref());
            prop_assert_eq!(bounds == CursorBoundsCheck::InBounds, spec.contains_key(&key));
        }

        #[test]
        fn bounds_matches_contains_key_bounded(
            key in proptest::collection::vec(any::<u8>(), 1..64),
            spec in arb_bounded_shard_spec(),
        ) {
            let update = CursorUpdate::new(&key);
            let bounds = check_cursor_bounds(update, spec.as_ref());
            prop_assert_eq!(bounds == CursorBoundsCheck::InBounds, spec.contains_key(&key));
        }

        #[test]
        fn advance_matches_lex_order(
            old in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..32)),
            new in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..32)),
        ) {
            let old_update = old
                .as_ref()
                .map_or(CursorUpdate::initial(), |k| CursorUpdate::new(k));
            let new_update = new
                .as_ref()
                .map_or(CursorUpdate::initial(), |k| CursorUpdate::new(k));
            let got = check_cursor_advance(old_update, new_update);
            let want = match (old.as_deref(), new.as_deref()) {
                (None, _) => CursorAdvance::Forward,
                (Some(_), None) => CursorAdvance::ResetToNone,
                (Some(a), Some(b)) if b >= a => CursorAdvance::Forward,
                (Some(_), Some(_)) => CursorAdvance::Regression,
            };
            prop_assert_eq!(got, want);
        }

        #[test]
        fn prefix_successor_into_is_strictly_greater(
            input in proptest::collection::vec(any::<u8>(), 1..64)
                .prop_filter("must not be all-0xFF", |v| v.iter().any(|&b| b != 0xFF)),
        ) {
            let mut out = [0u8; MAX_KEY_SIZE];
            let succ = prefix_successor_into(&input, &mut out).unwrap();
            prop_assert!(succ > input.as_slice(), "successor {succ:?} must be > input {input:?}");
        }

        #[test]
        fn key_successor_into_is_strictly_greater(
            input in proptest::collection::vec(any::<u8>(), 0..MAX_KEY_SIZE)
                .prop_filter("must not be all-0xFF at MAX_KEY_SIZE", |v| {
                    v.len() < MAX_KEY_SIZE || v.iter().any(|&b| b != 0xFF)
                }),
        ) {
            let mut out = [0u8; MAX_KEY_SIZE];
            let succ = key_successor_into(&input, &mut out).unwrap();
            prop_assert!(succ > input.as_slice(), "successor {succ:?} must be > input {input:?}");
        }
    }
}
