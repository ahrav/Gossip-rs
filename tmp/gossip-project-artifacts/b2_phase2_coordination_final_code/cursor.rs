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

use crate::identity::CanonicalBytes;
use crate::coordination::shard_spec::ShardSpec;

// ============================================================================
// § Cursor
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
// § Cursor Monotonicity
// ============================================================================

/// Monotonicity check result for cursor advancement.
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
// § Cursor Bounds Checking
// ============================================================================

/// Result of checking a cursor's `last_key` against a shard spec's range.
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

/// Check whether a cursor's `last_key` falls within a shard spec's range.
///
/// Returns `CursorBoundsCheck::NoKey` if the cursor has no `last_key`
/// (initial state). Returns `InBounds`, `BelowRange`, or `AboveRange`
/// otherwise.
///
/// `BelowRange` and `AboveRange` are safety violations — the worker is
/// reporting progress on items outside its assigned key range. The
/// coordinator rejects the checkpoint.
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
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Cursor construction ──────────────────────────────────────────

    // TODO: test cursor_initial_is_empty
    //   - Cursor::initial() → is_initial(), last_key.is_none(), token.is_none()

    // TODO: test cursor_with_last_key
    //   - Cursor::with_last_key(b"org/repo\0src/main.rs") → !is_initial(),
    //     last_key matches, token.is_none()

    // TODO: test cursor_from_parts
    //   - Cursor::from_parts(key, token) → both fields present

    // TODO: test cursor_from_parts_empty_token_becomes_none
    //   - Cursor::from_parts(b"key", vec![]) → token.is_none()

    // TODO: test cursor_with_empty_last_key_panics
    //   - #[should_panic(expected = "must not be empty")]
    //   - Cursor::with_last_key(vec![])

    // ── Cursor monotonicity ──────────────────────────────────────────

    // TODO: test advance_none_to_none_is_forward
    // TODO: test advance_none_to_some_is_forward
    // TODO: test advance_some_to_greater_is_forward
    // TODO: test advance_same_key_is_forward (idempotent)
    // TODO: test advance_some_to_lesser_is_regression
    // TODO: test advance_some_to_none_is_reset
    // TODO: test advance_longer_prefix_is_forward (b"abc" → b"abcd")
    // TODO: test advance_shorter_prefix_is_regression (b"abcd" → b"abc")

    // ── Cursor bounds checking ───────────────────────────────────────

    // TODO: test bounds_check_no_key → NoKey
    // TODO: test bounds_check_in_range → InBounds
    // TODO: test bounds_check_below_range → BelowRange
    // TODO: test bounds_check_above_range → AboveRange
    // TODO: test bounds_check_at_start_inclusive → InBounds (key == start)
    // TODO: test bounds_check_at_end_exclusive → AboveRange (key == end)
    // TODO: test bounds_check_unbounded_spec → InBounds for any key

    // ── CanonicalBytes ───────────────────────────────────────────────

    // TODO: test cursor_canonical_bytes_deterministic
    //   - Same cursor → same hash output across two calls

    // TODO: test cursor_canonical_bytes_none_vs_some_empty_distinct
    //   - Cursor { last_key: None, .. } hashes differently from
    //     Cursor { last_key: Some(Box::new([])), .. }
    //   - This validates the presence-byte encoding

    // ── Property-based (proptest) ────────────────────────────────────

    // TODO: proptest cursor_advance_reflexive
    //   - ∀ key: check_cursor_advance(c, c) == Forward

    // TODO: proptest cursor_canonical_bytes_stable
    //   - ∀ (key, tok): two hash calls produce identical output

    // TODO: proptest cursor_advance_transitivity
    //   - If advance(a, b) == Forward && advance(b, c) == Forward,
    //     then advance(a, c) == Forward
}
