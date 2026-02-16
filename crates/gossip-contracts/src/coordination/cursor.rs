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
//! ## Design Decisions (locked)
//!
//! D2.1: Two-layer `(last_key, token)` cursor structure.
//!       Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017) —
//!       query restart protocol with opaque restart tokens + ordered resume
//!       keys.
//!
//! D2.3: Cursor monotonicity is a hard safety invariant.
//!       `new.last_key >= old.last_key` (lex) on every checkpoint.
//!
//! D2.4: Cursor bounds checking is a hard safety invariant.
//!       `cursor.last_key ∈ [spec.start, spec.end)`.
//!
//! D2.5: A checkpoint requires a `last_key`.
//!       Connector-internal bookkeeping without committed items is not
//!       coordination state.

use blake3::Hasher;

use super::shard_spec::ShardSpec;
use crate::identity::CanonicalBytes;

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
/// | `Some(_)`    | `None`       | **REJECT** — regression |
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
/// Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cursor {
    /// The key of the last fully-processed item (lex-ordered).
    ///
    /// `None` = no items processed yet (initial state or empty shard).
    pub last_key: Option<Box<[u8]>>,

    /// Connector-opaque resume token.
    ///
    /// `None` = start from the beginning of the shard's key range.
    ///
    /// The coordinator stores this verbatim and returns it on acquisition.
    /// It MUST NOT be interpreted, compared, or logged at the coordination
    /// layer.
    pub token: Option<Box<[u8]>>,
}

impl Cursor {
    /// Initial cursor: no progress, no resume token.
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

    /// Returns `true` if no progress has been made.
    #[inline]
    pub fn is_initial(&self) -> bool {
        self.last_key.is_none()
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
        match &self.last_key {
            None => 0u8.write_canonical(h),
            Some(key) => {
                1u8.write_canonical(h);
                key.as_ref().write_canonical(h);
            }
        }
        match &self.token {
            None => 0u8.write_canonical(h),
            Some(tok) => {
                1u8.write_canonical(h);
                tok.as_ref().write_canonical(h);
            }
        }
    }
}

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
pub fn check_cursor_advance(old: &Cursor, new: &Cursor) -> CursorAdvance {
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
pub fn check_cursor_bounds(cursor: &Cursor, spec: &ShardSpec) -> CursorBoundsCheck {
    let Some(ref last_key) = cursor.last_key else {
        return CursorBoundsCheck::NoKey;
    };

    let key = last_key.as_ref();

    if !spec.is_start_unbounded() && key < spec.key_range_start.as_ref() {
        return CursorBoundsCheck::BelowRange;
    }

    if !spec.is_end_unbounded() && key >= spec.key_range_end.as_ref() {
        return CursorBoundsCheck::AboveRange;
    }

    CursorBoundsCheck::InBounds
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher;
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

    /// Helper: hash a value via CanonicalBytes and return the digest.
    fn canonical_digest<T: CanonicalBytes>(val: &T) -> blake3::Hash {
        let mut h = Hasher::new();
        val.write_canonical(&mut h);
        h.finalize()
    }

    // -------------------------------------------------------------------
    // Cursor construction
    // -------------------------------------------------------------------

    #[test]
    fn cursor_initial_is_empty() {
        let c = Cursor::initial();
        assert!(c.is_initial());
        assert!(c.last_key.is_none());
        assert!(c.token.is_none());
    }

    #[test]
    fn cursor_with_last_key() {
        let c = Cursor::with_last_key(b"org/repo\0src/main.rs".to_vec());
        assert!(!c.is_initial());
        assert_eq!(
            c.last_key.as_deref(),
            Some(b"org/repo\0src/main.rs".as_slice())
        );
        assert!(c.token.is_none());
    }

    #[test]
    fn cursor_from_parts() {
        let c = Cursor::from_parts(b"key".to_vec(), b"token-data".to_vec());
        assert!(!c.is_initial());
        assert_eq!(c.last_key.as_deref(), Some(b"key".as_slice()));
        assert_eq!(c.token.as_deref(), Some(b"token-data".as_slice()));
    }

    #[test]
    fn cursor_from_parts_empty_token_becomes_none() {
        let c = Cursor::from_parts(b"key".to_vec(), vec![]);
        assert_eq!(c.last_key.as_deref(), Some(b"key".as_slice()));
        assert!(c.token.is_none());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn cursor_with_empty_last_key_panics() {
        let _ = Cursor::with_last_key(vec![]);
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
        // Bypass the panic in with_last_key by constructing directly.
        let c_some_empty = Cursor {
            last_key: Some(Box::new([])),
            token: None,
        };
        assert_ne!(canonical_digest(&c_none), canonical_digest(&c_some_empty));
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
            let c = Cursor {
                last_key: key.map(|v| v.into_boxed_slice()),
                token: token.map(|v| v.into_boxed_slice()),
            };
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
            let c1 = Cursor {
                last_key: k1.map(|v| v.into_boxed_slice()),
                token: t1.map(|v| v.into_boxed_slice()),
            };
            let c2 = Cursor {
                last_key: k2.map(|v| v.into_boxed_slice()),
                token: t2.map(|v| v.into_boxed_slice()),
            };
            prop_assume!(c1 != c2);
            prop_assert_ne!(canonical_digest(&c1), canonical_digest(&c2));
        }

        // -- Cross-type: bounds_check ↔ contains_key -----------------------

        #[test]
        fn bounds_check_iff_contains_key(
            key in proptest::collection::vec(any::<u8>(), 1..64),
            start in proptest::collection::vec(any::<u8>(), 1..32),
            suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut end = start.clone();
            end.extend_from_slice(&suffix);
            let spec = ShardSpec::with_range(start, end);
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
