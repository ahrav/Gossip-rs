//! Cursor: two-layer progress marker for shard checkpoint tracking.
//!
//! The cursor answers "where are we in the scan?" with two layers:
//!
//! - **`last_key`** (coordinator-visible): the lexicographically ordered
//!   key of the last fully-processed (or durably dispatched) item. The
//!   coordinator uses this for monotonicity enforcement, bounds checking,
//!   and progress observability.
//!
//! - **`token`** (connector-opaque): the connector's internal pagination
//!   or resume state. The coordinator stores and returns this verbatim
//!   but never inspects it.
//!
//! The owned [`Cursor`] is used for durable snapshots and by-value APIs.
//! [`CursorUpdate`] is the borrowed companion used on checkpoint/complete
//! hot paths to avoid building intermediate owned cursors.
//!
//! Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017) —
//! query restart protocol with opaque restart tokens + ordered resume keys.

use std::fmt;

use blake3::Hasher;

use super::shard_spec::ShardSpec;
use crate::identity::CanonicalBytes;

/// Maximum size of a cursor `last_key` in bytes (4 KiB).
///
/// Sized to the row-key ceiling of DynamoDB / Bigtable. Keys larger than
/// this are almost certainly a serialisation bug, not legitimate progress.
pub const MAX_KEY_SIZE: usize = 4_096;

/// Maximum size of a cursor `token` in bytes (16 KiB).
///
/// Ceiling for opaque connector resume state. Observed tokens:
/// GitHub API (~50 B), Elasticsearch scroll (2-10 KB), Azure AD JWT (~15 KB).
/// 16 KiB accommodates the largest observed token with minimal margin.
pub const MAX_TOKEN_SIZE: usize = 16_384;

// ============================================================================
// Cursor
// ============================================================================

/// Two-layer checkpoint cursor for shard progress tracking.
///
/// ## Structure
///
/// ```text
/// ┌──────────────────────────────────────────────────────┐
/// │ last_key: Option<Box<[u8]>>                          │
/// │   → coordinator-visible, lex-comparable              │
/// │   → represents the last item key fully processed     │
/// ├──────────────────────────────────────────────────────┤
/// │ token: Option<Box<[u8]>>                             │
/// │   → connector-opaque resume state                    │
/// │   → pagination cursor, continuation token, etc.      │
/// └──────────────────────────────────────────────────────┘
/// ```
///
/// ## Monotonicity Rules
///
/// | old.last_key | new.last_key | Verdict |
/// |--------------|--------------|---------|
/// | `None`       | `None`       | OK — no-op checkpoint |
/// | `None`       | `Some(k)`    | OK — first progress |
/// | `Some(a)`    | `Some(b)`    | OK iff `b >= a` (lex) |
/// | `Some(a)`    | `Some(a)`    | OK — idempotent retry |
/// | `Some(_)`    | `None`       | **REJECT** — reset to none |
/// | `Some(a)`    | `Some(b)`    | **REJECT** if `b < a` |
///
/// ## Invariants
///
/// **Safety (monotonicity)**: `last_key` MUST NOT decrease across
/// checkpoints within the same lease epoch.
///
/// **Safety (bounds)**: `last_key` MUST fall within the shard's
/// `[spec.start, spec.end)`.
///
/// **Liveness**: The cursor MUST eventually advance if work remains,
/// or the shard MUST reach a terminal state (Done or Parked).
///
/// ## Encapsulation
///
/// Fields are private — constructors enforce invariants (e.g.,
/// `last_key` must not be empty when present), and public accessors
/// return borrowed views.
///
/// Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The key of the last fully-processed item (lex-ordered).
    ///
    /// `None` = no items processed yet (initial state or empty shard).
    last_key: Option<Box<[u8]>>,

    /// Connector-opaque resume token.
    ///
    /// `None` = start from the beginning of the shard's key range.
    ///
    /// The coordinator stores this verbatim and returns it on acquisition.
    /// It MUST NOT be interpreted, compared, or logged at the coordination
    /// layer.
    token: Option<Box<[u8]>>,
}

/// Borrowed cursor view for allocation-free checkpoint/complete updates.
///
/// `CursorUpdate` borrows key/token bytes from caller-owned storage so hot
/// checkpoint paths can avoid building owned `Cursor` values first.
///
/// Empty tokens normalize to `None` to preserve `Cursor::from_parts` semantics
/// and idempotency-hash compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CursorUpdate<'a> {
    last_key: Option<&'a [u8]>,
    token: Option<&'a [u8]>,
}

impl Cursor {
    /// Initial cursor: no progress, no resume token.
    #[must_use = "creates a cursor that should be stored or passed to a connector"]
    pub fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// Construct a cursor with a `last_key` and no resume token.
    ///
    /// Useful for connectors that don't need opaque pagination state.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty. A present key must contain at
    /// least one byte to be meaningful in the lex-ordered keyspace.
    #[must_use = "creates a cursor that should be stored or passed to a connector"]
    pub fn with_last_key(last_key: Vec<u8>) -> Self {
        assert!(
            !last_key.is_empty(),
            "last_key must not be empty when present"
        );
        Self {
            last_key: Some(last_key.into_boxed_slice()),
            token: None,
        }
    }

    /// Construct a cursor from both layers.
    ///
    /// Empty `token` is normalized to `None` — the coordinator never
    /// distinguishes between "no token" and "empty token."
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty.
    #[must_use = "creates a cursor that should be stored or passed to a connector"]
    pub fn from_parts(last_key: Vec<u8>, token: Vec<u8>) -> Self {
        assert!(
            !last_key.is_empty(),
            "last_key must not be empty when present"
        );
        Self {
            last_key: Some(last_key.into_boxed_slice()),
            token: if token.is_empty() {
                None
            } else {
                Some(token.into_boxed_slice())
            },
        }
    }

    /// Fallible constructor: returns `Err` if `last_key` is empty or
    /// exceeds [`MAX_KEY_SIZE`].
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_last_key(last_key: Vec<u8>) -> Result<Self, CursorInputError> {
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
            last_key: Some(last_key.into_boxed_slice()),
            token: None,
        })
    }

    /// Fallible constructor: returns `Err` if `last_key` is empty,
    /// `last_key` exceeds [`MAX_KEY_SIZE`], or `token` exceeds
    /// [`MAX_TOKEN_SIZE`].
    ///
    /// Empty `token` is normalized to `None`.
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
    /// - [`CursorInputError::TokenTooLarge`] — `token` exceeds
    ///   [`MAX_TOKEN_SIZE`] bytes.
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_from_parts(last_key: Vec<u8>, token: Vec<u8>) -> Result<Self, CursorInputError> {
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
            last_key: Some(last_key.into_boxed_slice()),
            token: if token.is_empty() {
                None
            } else {
                Some(token.into_boxed_slice())
            },
        })
    }

    /// Construct a `Cursor` from pre-built parts, bypassing validation.
    ///
    /// Only available in test builds — allows constructing intentionally
    /// invalid cursors (e.g., with an empty `last_key`) for testing.
    #[cfg(test)]
    pub(crate) fn from_raw_parts(last_key: Option<Box<[u8]>>, token: Option<Box<[u8]>>) -> Self {
        Self { last_key, token }
    }

    /// Returns `true` if no progress has been made (`last_key` is `None`).
    /// The `token` field is not considered — progress is measured solely
    /// by `last_key`.
    #[inline]
    #[must_use = "returns a bool that should be checked"]
    pub fn is_initial(&self) -> bool {
        self.last_key.is_none()
    }

    /// The key of the last fully-processed item, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn last_key(&self) -> Option<&[u8]> {
        self.last_key.as_deref()
    }

    /// The connector-opaque resume token, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn token(&self) -> Option<&[u8]> {
        self.token.as_deref()
    }

    /// Consume the cursor and return its parts.
    #[inline]
    #[must_use = "returns owned data that should be used"]
    #[allow(clippy::type_complexity)]
    pub fn into_parts(self) -> (Option<Box<[u8]>>, Option<Box<[u8]>>) {
        (self.last_key, self.token)
    }
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

    /// Construct an update from both layers.
    ///
    /// Empty `token` is normalized to `None`.
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

    /// Fallible constructor for `last_key`-only updates.
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
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

    /// Fallible constructor for key+token updates.
    ///
    /// Empty `token` is normalized to `None`.
    ///
    /// # Errors
    ///
    /// - [`CursorInputError::EmptyLastKey`] — `last_key` is empty.
    /// - [`CursorInputError::KeyTooLarge`] — `last_key` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
    /// - [`CursorInputError::TokenTooLarge`] — `token` exceeds
    ///   [`MAX_TOKEN_SIZE`] bytes.
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

    /// Borrows key and token from an existing [`Cursor`].
    ///
    /// This is the standard way to create a `CursorUpdate` from a `Cursor`
    /// when you need to pass owned cursor data through the borrowed API.
    pub fn from_cursor(cursor: &'a Cursor) -> Self {
        match (cursor.last_key(), cursor.token()) {
            (None, _) => Self::initial(),
            (Some(k), None) => Self::new(k),
            (Some(k), Some(t)) => Self::with_token(k, t),
        }
    }

    /// The key of the last fully-processed item, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn last_key(&self) -> Option<&[u8]> {
        self.last_key
    }

    /// The connector-opaque resume token, if any.
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn token(&self) -> Option<&[u8]> {
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

/// `CanonicalBytes` for `Cursor`.
///
/// Encoding:
/// ```text
/// last_key_present : u8  (0 = None, 1 = Some)
/// [if present] last_key : length-prefixed bytes
/// token_present : u8  (0 = None, 1 = Some)
/// [if present] token : length-prefixed bytes
/// ```
///
/// Both optional fields use a presence byte + length-prefixed payload.
/// This encoding is unambiguous: the presence byte distinguishes
/// `None` from `Some([])`, and the length prefix handles variable-width.
impl CanonicalBytes for Cursor {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        write_cursor_canonical_parts(self.last_key(), self.token(), h);
    }
}

/// `CursorUpdate` uses the same canonical encoding as [`Cursor`].
///
/// This keeps op-log idempotency payload hashes stable across owned and
/// borrowed checkpoint/complete call paths.
impl CanonicalBytes for CursorUpdate<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        write_cursor_canonical_parts(self.last_key(), self.token(), h);
    }
}

// ============================================================================
// CursorInputError
// ============================================================================

/// Error returned by fallible [`Cursor`] and [`CursorUpdate`] constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CursorInputError {
    /// The `last_key` was empty. A present key must contain at least
    /// one byte to be meaningful in the lex-ordered keyspace.
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

// ============================================================================
// Cursor Monotonicity
// ============================================================================

/// Result of comparing two cursors for monotonic forward progress.
///
/// Used by the coordinator on the checkpoint path: non-[`Forward`] variants
/// cause the checkpoint to be rejected, protecting against data loss from
/// cursor regression.
///
/// [`Forward`]: CursorAdvance::Forward
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

/// Compare two cursors for monotonicity.
///
/// Compares only the `last_key` layer — the `token` layer is opaque
/// and not subject to ordering.
///
/// Returns `CursorAdvance::Forward` if the new cursor is ≥ the old
/// cursor in the `last_key` ordering. Returns a rejection variant
/// otherwise.
///
/// The comparison is lexicographic byte ordering — the natural ordering
/// for range-sharded keyspaces.
///
/// ## Why this is a free function
///
/// The cursor doesn't know whether it's "old" or "new." The
/// directionality is a property of the checkpoint operation, not the
/// cursor. A free function makes the comparison direction explicit at
/// the call site.
///
/// Reference: Bigtable, Spanner, CockroachDB, FoundationDB all use
/// lex-ordered byte keys for range comparisons.
#[inline]
#[must_use = "ignoring the advance check defeats the monotonicity safety invariant"]
pub fn check_cursor_advance(old: &Cursor, new: &Cursor) -> CursorAdvance {
    debug_assert!(old.last_key.as_ref().is_none_or(|k| !k.is_empty()));
    debug_assert!(new.last_key.as_ref().is_none_or(|k| !k.is_empty()));

    match (&old.last_key, &new.last_key) {
        // No progress → first progress: always valid.
        (None, Some(_)) => CursorAdvance::Forward,

        // No progress → no progress: valid (no-op).
        (None, None) => CursorAdvance::Forward,

        // Had progress → lost progress: regression.
        (Some(_), None) => CursorAdvance::ResetToNone,

        // Both present: lexicographic comparison.
        (Some(old_key), Some(new_key)) => {
            if new_key.as_ref() >= old_key.as_ref() {
                CursorAdvance::Forward
            } else {
                CursorAdvance::Regression
            }
        }
    }
}

// ============================================================================
// Cursor Bounds Checking
// ============================================================================

/// Result of checking a cursor's `last_key` against a [`ShardSpec`]'s
/// half-open key range `[start, end)`.
///
/// Non-[`InBounds`] results (other than [`NoKey`]) are safety violations:
/// the worker reported progress outside its assigned range. The
/// coordinator rejects the checkpoint.
///
/// [`InBounds`]: CursorBoundsCheck::InBounds
/// [`NoKey`]: CursorBoundsCheck::NoKey
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "bounds check result must be inspected to enforce range safety"]
#[non_exhaustive]
pub enum CursorBoundsCheck {
    /// Cursor has no `last_key` — nothing to check (initial state).
    NoKey,
    /// `last_key` is within the shard's key range.
    InBounds,
    /// `last_key` is below the shard's key range start.
    BelowRange,
    /// `last_key` is at or above the shard's key range end.
    AboveRange,
}

/// Check whether a cursor's `last_key` falls within a shard spec's
/// half-open range `[start, end)`.
///
/// Returns [`CursorBoundsCheck::NoKey`] if the cursor has no `last_key`
/// (initial state). Returns `InBounds`, `BelowRange`, or `AboveRange`
/// otherwise.
///
/// `BelowRange` and `AboveRange` are safety violations — the worker is
/// reporting progress on items outside its assigned key range. The
/// coordinator rejects the checkpoint.
///
/// See [`ShardSpec::contains_key`] for the underlying range membership
/// logic.
#[inline]
#[must_use = "ignoring the bounds check defeats the range safety invariant"]
pub fn check_cursor_bounds(cursor: &Cursor, spec: &ShardSpec) -> CursorBoundsCheck {
    let Some(last_key) = cursor.last_key() else {
        return CursorBoundsCheck::NoKey;
    };

    if spec.contains_key(last_key) {
        return CursorBoundsCheck::InBounds;
    }

    if !spec.is_start_unbounded() && last_key < spec.key_range_start() {
        CursorBoundsCheck::BelowRange
    } else {
        CursorBoundsCheck::AboveRange
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{arb_bounded_shard_spec, arb_shard_spec, canonical_digest};
    use proptest::prelude::*;

    /// Table row: (label, old_key, new_key, expected).
    type AdvanceCase = (
        &'static str,
        Option<&'static [u8]>,
        Option<&'static [u8]>,
        CursorAdvance,
    );

    /// Table row: (label, key, range_start, range_end, expected).
    type BoundsCase = (
        &'static str,
        Option<&'static [u8]>,
        &'static [u8],
        &'static [u8],
        CursorBoundsCheck,
    );

    // -------------------------------------------------------------------
    // Cursor construction
    // -------------------------------------------------------------------

    #[test]
    fn cursor_initial_is_empty() {
        let c = Cursor::initial();
        assert!(c.is_initial());
        assert!(c.last_key().is_none());
        assert!(c.token().is_none());
    }

    #[test]
    fn cursor_with_last_key() {
        let c = Cursor::with_last_key(b"org/repo\0src/main.rs".to_vec());
        assert!(!c.is_initial());
        assert_eq!(c.last_key(), Some(b"org/repo\0src/main.rs".as_slice()));
        assert!(c.token().is_none());
    }

    #[test]
    fn cursor_from_parts() {
        let c = Cursor::from_parts(b"key".to_vec(), b"token-data".to_vec());
        assert!(!c.is_initial());
        assert_eq!(c.last_key(), Some(b"key".as_slice()));
        assert_eq!(c.token(), Some(b"token-data".as_slice()));
    }

    #[test]
    fn cursor_from_parts_empty_token_becomes_none() {
        let c = Cursor::from_parts(b"key".to_vec(), vec![]);
        assert_eq!(c.last_key(), Some(b"key".as_slice()));
        assert!(c.token().is_none());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn cursor_with_empty_last_key_panics() {
        let _ = Cursor::with_last_key(vec![]);
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn cursor_from_parts_empty_last_key_panics() {
        let _ = Cursor::from_parts(vec![], b"token".to_vec());
    }

    #[test]
    fn cursor_update_with_token_empty_token_becomes_none() {
        let u = CursorUpdate::with_token(b"key", b"");
        assert_eq!(u.last_key(), Some(b"key".as_slice()));
        assert!(u.token().is_none());
    }

    #[test]
    fn cursor_update_try_with_token_over_max() {
        let token = vec![0xCD; MAX_TOKEN_SIZE + 1];
        let err = CursorUpdate::try_with_token(b"key", &token).unwrap_err();
        assert_eq!(
            err,
            CursorInputError::TokenTooLarge {
                size: MAX_TOKEN_SIZE + 1,
                max: MAX_TOKEN_SIZE,
            }
        );
    }

    #[test]
    fn cursor_update_views_match_inputs() {
        let u = CursorUpdate::with_token(b"k", b"t");
        assert_eq!(u.last_key(), Some(b"k".as_slice()));
        assert_eq!(u.token(), Some(b"t".as_slice()));
    }

    // -------------------------------------------------------------------
    // Fallible constructors
    // -------------------------------------------------------------------

    #[test]
    fn try_with_last_key_valid() {
        let c = Cursor::try_with_last_key(b"key".to_vec()).unwrap();
        assert_eq!(c.last_key(), Some(b"key".as_slice()));
        assert!(c.token().is_none());
    }

    #[test]
    fn try_with_last_key_empty() {
        let err = Cursor::try_with_last_key(vec![]).unwrap_err();
        assert_eq!(err, CursorInputError::EmptyLastKey);
    }

    #[test]
    fn try_from_parts_valid() {
        let c = Cursor::try_from_parts(b"key".to_vec(), b"tok".to_vec()).unwrap();
        assert_eq!(c.last_key(), Some(b"key".as_slice()));
        assert_eq!(c.token(), Some(b"tok".as_slice()));
    }

    #[test]
    fn try_from_parts_empty_key() {
        let err = Cursor::try_from_parts(vec![], b"tok".to_vec()).unwrap_err();
        assert_eq!(err, CursorInputError::EmptyLastKey);
    }

    #[test]
    fn try_from_parts_empty_token_normalized() {
        let c = Cursor::try_from_parts(b"key".to_vec(), vec![]).unwrap();
        assert!(c.token().is_none());
    }

    #[test]
    fn cursor_input_error_display() {
        let err = CursorInputError::EmptyLastKey;
        let msg = err.to_string();
        assert!(msg.contains("must not be empty"));
    }

    // -------------------------------------------------------------------
    // Size-limit validation
    // -------------------------------------------------------------------

    #[test]
    fn try_with_last_key_at_max_size() {
        let key = vec![0xAB; MAX_KEY_SIZE];
        let c = Cursor::try_with_last_key(key).unwrap();
        assert_eq!(c.last_key().unwrap().len(), MAX_KEY_SIZE);
    }

    #[test]
    fn try_with_last_key_over_max_size() {
        let key = vec![0xAB; MAX_KEY_SIZE + 1];
        let err = Cursor::try_with_last_key(key).unwrap_err();
        assert_eq!(
            err,
            CursorInputError::KeyTooLarge {
                size: MAX_KEY_SIZE + 1,
                max: MAX_KEY_SIZE,
            }
        );
    }

    #[test]
    fn try_from_parts_key_over_max() {
        let key = vec![0xAB; MAX_KEY_SIZE + 1];
        let err = Cursor::try_from_parts(key, b"tok".to_vec()).unwrap_err();
        assert!(matches!(err, CursorInputError::KeyTooLarge { .. }));
    }

    #[test]
    fn try_from_parts_token_at_max_size() {
        let token = vec![0xCD; MAX_TOKEN_SIZE];
        let c = Cursor::try_from_parts(b"key".to_vec(), token).unwrap();
        assert_eq!(c.token().unwrap().len(), MAX_TOKEN_SIZE);
    }

    #[test]
    fn try_from_parts_token_over_max() {
        let token = vec![0xCD; MAX_TOKEN_SIZE + 1];
        let err = Cursor::try_from_parts(b"key".to_vec(), token).unwrap_err();
        assert_eq!(
            err,
            CursorInputError::TokenTooLarge {
                size: MAX_TOKEN_SIZE + 1,
                max: MAX_TOKEN_SIZE,
            }
        );
    }

    #[test]
    fn cursor_input_error_display_key_too_large() {
        let err = CursorInputError::KeyTooLarge {
            size: 5000,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000"));
        assert!(msg.contains("4096"));
    }

    #[test]
    fn cursor_input_error_display_token_too_large() {
        let err = CursorInputError::TokenTooLarge {
            size: 20000,
            max: 16384,
        };
        let msg = err.to_string();
        assert!(msg.contains("20000"));
        assert!(msg.contains("16384"));
    }

    // -------------------------------------------------------------------
    // Cursor monotonicity
    // -------------------------------------------------------------------

    #[test]
    fn cursor_advance_truth_table() {
        let cases: &[AdvanceCase] = &[
            ("none→none", None, None, CursorAdvance::Forward),
            ("none→some", None, Some(b"abc"), CursorAdvance::Forward),
            (
                "some→greater",
                Some(b"abc"),
                Some(b"def"),
                CursorAdvance::Forward,
            ),
            (
                "same key",
                Some(b"abc"),
                Some(b"abc"),
                CursorAdvance::Forward,
            ),
            (
                "some→lesser",
                Some(b"def"),
                Some(b"abc"),
                CursorAdvance::Regression,
            ),
            ("some→none", Some(b"abc"), None, CursorAdvance::ResetToNone),
            (
                "longer prefix",
                Some(b"abc"),
                Some(b"abcd"),
                CursorAdvance::Forward,
            ),
            (
                "shorter prefix",
                Some(b"abcd"),
                Some(b"abc"),
                CursorAdvance::Regression,
            ),
        ];

        for (label, old_key, new_key, expected) in cases {
            let old = match old_key {
                Some(k) => Cursor::with_last_key(k.to_vec()),
                None => Cursor::initial(),
            };
            let new = match new_key {
                Some(k) => Cursor::with_last_key(k.to_vec()),
                None => Cursor::initial(),
            };
            assert_eq!(check_cursor_advance(&old, &new), *expected, "case: {label}");
        }
    }

    // -------------------------------------------------------------------
    // Cursor bounds checking
    // -------------------------------------------------------------------

    #[test]
    fn cursor_bounds_check_truth_table() {
        let cases: &[BoundsCase] = &[
            ("no key", None, b"a", b"z", CursorBoundsCheck::NoKey),
            (
                "in range",
                Some(b"m"),
                b"a",
                b"z",
                CursorBoundsCheck::InBounds,
            ),
            (
                "below range",
                Some(b"a"),
                b"m",
                b"z",
                CursorBoundsCheck::BelowRange,
            ),
            (
                "above range",
                Some(b"z"),
                b"a",
                b"m",
                CursorBoundsCheck::AboveRange,
            ),
            (
                "at start (inclusive)",
                Some(b"a"),
                b"a",
                b"z",
                CursorBoundsCheck::InBounds,
            ),
            (
                "at end (exclusive)",
                Some(b"z"),
                b"a",
                b"z",
                CursorBoundsCheck::AboveRange,
            ),
            (
                "unbounded spec",
                Some(b"anything"),
                b"",
                b"",
                CursorBoundsCheck::InBounds,
            ),
            (
                "half-unbounded start, in range",
                Some(b"m"),
                b"",
                b"z",
                CursorBoundsCheck::InBounds,
            ),
            (
                "half-unbounded start, above",
                Some(b"z"),
                b"",
                b"m",
                CursorBoundsCheck::AboveRange,
            ),
            (
                "half-unbounded end, in range",
                Some(b"m"),
                b"a",
                b"",
                CursorBoundsCheck::InBounds,
            ),
            (
                "half-unbounded end, below",
                Some(b"a"),
                b"m",
                b"",
                CursorBoundsCheck::BelowRange,
            ),
        ];

        for (label, key, start, end, expected) in cases {
            let cursor = match key {
                Some(k) => Cursor::with_last_key(k.to_vec()),
                None => Cursor::initial(),
            };
            let spec = if start.is_empty() && end.is_empty() {
                ShardSpec::unbounded()
            } else {
                ShardSpec::with_range(start.to_vec(), end.to_vec())
            };
            assert_eq!(
                check_cursor_bounds(&cursor, &spec),
                *expected,
                "case: {label}"
            );
        }
    }

    // -------------------------------------------------------------------
    // CanonicalBytes
    // -------------------------------------------------------------------

    #[test]
    fn cursor_canonical_bytes_deterministic() {
        let c = Cursor::with_last_key(b"key".to_vec());
        let d1 = canonical_digest(&c);
        let d2 = canonical_digest(&c);
        assert_eq!(d1, d2);
    }

    #[test]
    fn cursor_canonical_bytes_none_vs_some_empty_distinct() {
        let c_none = Cursor::initial();
        // Bypass the panic in with_last_key by constructing via from_raw_parts.
        let c_some_empty = Cursor::from_raw_parts(Some(Box::new([])), None);
        assert_ne!(canonical_digest(&c_none), canonical_digest(&c_some_empty));
    }

    #[test]
    fn cursor_update_canonical_bytes_matches_cursor() {
        let c = Cursor::from_parts(b"key".to_vec(), b"token".to_vec());
        let u = CursorUpdate::with_token(b"key", b"token");
        assert_eq!(canonical_digest(&c), canonical_digest(&u));
    }

    #[test]
    fn cursor_update_empty_token_hash_compatible_with_cursor() {
        let c = Cursor::from_parts(b"key".to_vec(), vec![]);
        let u = CursorUpdate::with_token(b"key", b"");
        assert_eq!(canonical_digest(&c), canonical_digest(&u));
    }

    // -------------------------------------------------------------------
    // Property-based tests
    // -------------------------------------------------------------------

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // -- Reflexivity: advance(c, c) == Forward --------------------------

        #[test]
        fn cursor_advance_reflexive(
            key in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let c = Cursor::with_last_key(key);
            prop_assert_eq!(check_cursor_advance(&c, &c), CursorAdvance::Forward);
        }

        // -- Stability: same cursor → same digest ---------------------------

        #[test]
        fn cursor_canonical_bytes_stable(
            key in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
            token in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
        ) {
            let c = Cursor::from_raw_parts(
                key.map(|v| v.into_boxed_slice()),
                token.map(|v| v.into_boxed_slice()),
            );
            prop_assert_eq!(canonical_digest(&c), canonical_digest(&c));
        }

        // -- Transitivity: a <= b <= c implies a <= c -----------------------

        #[test]
        fn cursor_advance_transitivity(
            a_key in proptest::collection::vec(any::<u8>(), 1..32),
            b_suffix in proptest::collection::vec(any::<u8>(), 1..8),
            c_suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut b_key = a_key.clone();
            b_key.extend_from_slice(&b_suffix);
            let mut c_key = b_key.clone();
            c_key.extend_from_slice(&c_suffix);

            let a = Cursor::with_last_key(a_key);
            let b = Cursor::with_last_key(b_key);
            let c = Cursor::with_last_key(c_key);

            prop_assert_eq!(check_cursor_advance(&a, &b), CursorAdvance::Forward);
            prop_assert_eq!(check_cursor_advance(&b, &c), CursorAdvance::Forward);
            prop_assert_eq!(check_cursor_advance(&a, &c), CursorAdvance::Forward);
        }

        // -- Collision-freedom: distinct cursors → distinct digests ---------

        #[test]
        fn cursor_canonical_bytes_collision_free(
            k1 in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
            t1 in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
            k2 in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
            t2 in proptest::option::of(proptest::collection::vec(any::<u8>(), 1..64)),
        ) {
            let c1 = Cursor::from_raw_parts(
                k1.map(|v| v.into_boxed_slice()),
                t1.map(|v| v.into_boxed_slice()),
            );
            let c2 = Cursor::from_raw_parts(
                k2.map(|v| v.into_boxed_slice()),
                t2.map(|v| v.into_boxed_slice()),
            );
            prop_assume!(c1 != c2);
            prop_assert_ne!(canonical_digest(&c1), canonical_digest(&c2));
        }

        // -- Anti-symmetry: regression(a,b) ⟹ forward(b,a) ----------------

        #[test]
        fn cursor_advance_anti_symmetric(
            a_key in proptest::collection::vec(any::<u8>(), 1..64),
            b_key in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let a = Cursor::with_last_key(a_key);
            let b = Cursor::with_last_key(b_key);
            let ab = check_cursor_advance(&a, &b);
            let ba = check_cursor_advance(&b, &a);
            match ab {
                CursorAdvance::Regression => {
                    prop_assert_eq!(ba, CursorAdvance::Forward,
                        "advance(a,b)==Regression but advance(b,a)!=Forward");
                }
                CursorAdvance::Forward => {
                    // b >= a, so a <= b, meaning advance(b,a) is Forward (a==b)
                    // or Regression (a < b).
                    prop_assert!(
                        ba == CursorAdvance::Forward || ba == CursorAdvance::Regression,
                        "advance(a,b)==Forward but advance(b,a) is {:?}", ba
                    );
                }
                CursorAdvance::ResetToNone => {
                    // Not reachable when both have Some keys.
                    prop_assert!(false, "ResetToNone with two Some keys");
                }
            }
        }

        // -- Cross-type: bounds_check ↔ contains_key -----------------------

        #[test]
        fn bounds_check_iff_contains_key(
            key in proptest::collection::vec(any::<u8>(), 1..64),
            spec in arb_shard_spec(),
        ) {
            let cursor = Cursor::with_last_key(key.clone());
            let bounds = check_cursor_bounds(&cursor, &spec);
            let contains = spec.contains_key(&key);
            prop_assert_eq!(
                bounds == CursorBoundsCheck::InBounds,
                contains,
                "bounds_check and contains_key disagree for key={:?}", key
            );
        }

        // -- Cross-type: bounded spec bounds_check ↔ contains_key ----------

        #[test]
        fn bounds_check_iff_contains_key_bounded(
            key in proptest::collection::vec(any::<u8>(), 1..64),
            spec in arb_bounded_shard_spec(),
        ) {
            let cursor = Cursor::with_last_key(key.clone());
            let bounds = check_cursor_bounds(&cursor, &spec);
            let contains = spec.contains_key(&key);
            prop_assert_eq!(
                bounds == CursorBoundsCheck::InBounds,
                contains,
                "bounds_check and contains_key disagree for key={:?}", key
            );
        }
    }
}
