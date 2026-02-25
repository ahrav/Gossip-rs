//! Cursor progress markers for shard checkpoint tracking.
//!
//! A cursor update carries two layers:
//!
//! - `last_key`: coordinator-visible ordered progress key.
//! - `token`: connector-opaque pagination/resume state.
//!
//! This module intentionally uses borrowed views (`CursorUpdate`) so runtime
//! paths can remain allocation-free.

use std::fmt;

use blake3::Hasher;

use super::shard_spec::ShardSpecRef;
use crate::identity::CanonicalBytes;

/// Maximum size of a cursor `last_key` in bytes (4 KiB).
pub const MAX_KEY_SIZE: usize = 4_096;

/// Maximum size of a cursor `token` in bytes (16 KiB).
pub const MAX_TOKEN_SIZE: usize = 16_384;

/// Borrowed cursor view for allocation-free checkpoint/complete updates.
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
    #[must_use = "creates a cursor update that should be stored or passed to a coordinator"]
    pub fn with_last_key(last_key: &'a [u8]) -> Self {
        Self::new(last_key)
    }

    /// Construct an update from key + token.
    ///
    /// Empty `token` normalizes to `None`.
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
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_last_key(last_key: &'a [u8]) -> Result<Self, CursorInputError> {
        Self::try_new(last_key)
    }

    /// Fallible constructor for key + token updates.
    ///
    /// Empty `token` normalizes to `None`.
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

impl CanonicalBytes for CursorUpdate<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        write_cursor_canonical_parts(self.last_key(), self.token(), h);
    }
}

/// Error returned by fallible [`CursorUpdate`] constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorInputError {
    /// The `last_key` was empty.
    EmptyLastKey,

    /// The `last_key` exceeds [`MAX_KEY_SIZE`].
    KeyTooLarge {
        /// Actual size of the key in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_KEY_SIZE`]).
        max: usize,
    },

    /// The `token` exceeds [`MAX_TOKEN_SIZE`].
    TokenTooLarge {
        /// Actual size of the token in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_TOKEN_SIZE`]).
        max: usize,
    },
}

impl fmt::Display for CursorInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLastKey => write!(f, "last_key must not be empty when present"),
            Self::KeyTooLarge { size, max } => {
                write!(f, "last_key too large ({size} bytes, max {max})")
            }
            Self::TokenTooLarge { size, max } => {
                write!(f, "token too large ({size} bytes, max {max})")
            }
        }
    }
}

impl std::error::Error for CursorInputError {}

/// Result of comparing two cursor updates for monotonic forward progress.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "advance check result must be inspected to enforce monotonicity"]
#[non_exhaustive]
pub enum CursorAdvance {
    /// New cursor represents forward progress (or idempotent same-position).
    Forward,
    /// New cursor has a `last_key` that is strictly less than the old one.
    Regression,
    /// New cursor has `last_key = None` when old cursor had `Some`.
    ResetToNone,
}

/// Compare two cursor updates for monotonicity.
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

/// Result of checking a cursor update against a half-open key range.
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

/// Check whether a cursor update's `last_key` falls within a shard range.
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::shard_spec::ShardSpec;
    use crate::test_util::{arb_bounded_shard_spec, arb_shard_spec, canonical_digest};
    use proptest::prelude::*;

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
    }
}
