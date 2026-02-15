//! Boundary â‘¡ â€” Coordination & Shard Frontier: Chunk 1 (DRAFT)
//!
//! Cursor and ShardSpec: the types that answer "where are we in the scan"
//! and "what key range does this shard cover."
//!
//! This file is additive to Boundary â‘  (chunks 1â€“5). It uses `CanonicalBytes`
//! and the `domain` module from Boundary â‘  chunk 1.
//!
//! ## Design Decisions (locked)
//!
//! D2.1: Cursor is a two-layer `(last_key, token)` structure.
//!       `last_key` is a lexicographically ordered byte sequence the
//!       coordinator compares for monotonicity enforcement.
//!       `token` is an opaque connector resume state the coordinator
//!       stores but never inspects.
//!
//!       Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017) â€”
//!       query restart protocol with opaque restart tokens + ordered resume
//!       keys. Our two-layer cursor solves the same problem: the coordinator
//!       needs a comparable progress marker without understanding the
//!       connector's internal pagination state.
//!
//! D2.2: ShardSpec has a half-open key range `[start, end)` with
//!       lex-ordered byte boundaries, plus opaque connector metadata.
//!
//!       Reference: Bigtable (Chang et al., OSDI 2006) â€” tablets as
//!       contiguous row ranges; Spanner (Corbett et al., OSDI 2012) â€”
//!       directory-based sharding with key-range tablets; CockroachDB â€”
//!       ranges with half-open `[start, end)` intervals; FoundationDB
//!       (Zhou et al., SIGMOD 2021) â€” key ranges as `[begin, end)` byte
//!       strings.
//!
//! D2.3: Cursor monotonicity is a hard safety invariant.
//!       The coordinator rejects any checkpoint where
//!       `new.last_key < old.last_key` (lexicographic). No advisory
//!       mode, no exceptions.
//!
//! D2.4: Cursor bounds checking is a hard safety invariant.
//!       If a cursor's `last_key` falls outside the shard's
//!       `[start, end)`, the coordinator rejects the checkpoint.
//!       A worker processing items outside its assigned range is
//!       a correctness violation.
//!
//! D2.5: A checkpoint requires a `last_key`.
//!       A worker that has not processed any items has not made
//!       verifiable progress and must not checkpoint. Connector-internal
//!       bookkeeping (pagination tokens without committed items) is not
//!       coordination state.

// Assumes these are in scope from Boundary â‘ :
// use crate::{CanonicalBytes, Hasher};

// ============================================================================
// Â§ Chunk 1: Cursor & ShardSpec
// ============================================================================

// ---------------------------------------------------------------------------
// Â§1.1 Cursor â€” two-layer progress marker
// ---------------------------------------------------------------------------

/// Two-layer checkpoint cursor for shard progress tracking.
///
/// ## Structure
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚ last_key: Option<Box<[u8]>>                          â”‚
/// â”‚   â†‘ coordinator-visible, lex-comparable              â”‚
/// â”‚   â†‘ represents the last item key fully processed     â”‚
/// â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤
/// â”‚ token: Option<Box<[u8]>>                             â”‚
/// â”‚   â†‘ connector-opaque resume state                    â”‚
/// â”‚   â†‘ pagination cursor, continuation token, etc.      â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// ## Layer Semantics
///
/// **`last_key`** (coordinator-visible):
/// The lexicographically ordered key of the last item the worker has
/// fully processed (under `CursorSemantics::Completed`) or durably
/// dispatched (under `CursorSemantics::Dispatched`). The coordinator
/// uses this for:
/// - **Monotonicity enforcement**: `new.last_key >= old.last_key` (lex)
/// - **Bounds checking**: `last_key âˆˆ [spec.start, spec.end)`
/// - **Progress observability**: human-readable progress within a shard
///
/// `None` means "no items processed yet" (initial state).
///
/// The byte encoding is connector-defined but MUST be lexicographically
/// ordered: if item A should be processed before item B, then
/// `key(A) < key(B)` in byte ordering.
///
/// **`token`** (connector-opaque):
/// The connector's internal pagination/resume state. The coordinator
/// stores and returns this verbatim on acquisition but never inspects
/// it. Examples: GitHub GraphQL cursor, S3 `ContinuationToken`, Git
/// ref bookmark. `None` means "start from the beginning."
///
/// ## Checkpoint Requirement
///
/// A checkpoint MUST include a `last_key`. A worker that has not
/// processed any items has not made verifiable progress. Connector-
/// internal state (pagination tokens) without a committed item key
/// is not eligible for checkpointing â€” the coordinator cannot verify
/// monotonicity without `last_key`, creating an unverifiable state.
///
/// ## Monotonicity Rules
///
/// The coordinator enforces these transitions on checkpoint:
///
/// | old.last_key | new.last_key | Verdict |
/// |-------------|-------------|---------|
/// | `None`      | `Some(k)`   | OK â€” first progress |
/// | `Some(a)`   | `Some(b)`   | OK iff `b >= a` (lexicographic) |
/// | `Some(a)`   | `Some(a)`   | OK â€” idempotent retry at same position |
/// | `Some(_)`   | `None`      | **REJECT** â€” regression |
/// | `Some(a)`   | `Some(b)`   | **REJECT** if `b < a` â€” regression |
///
/// Note: `None â†’ None` does not arise because checkpoints require a
/// `last_key`.
///
/// ## Invariants
///
/// **Safety (monotonicity)**: `last_key` MUST NOT decrease across
/// checkpoints for the same shard within the same lease epoch.
///
/// **Safety (bounds)**: `last_key` MUST fall within the shard's
/// `[spec.start, spec.end)`. Violation is a hard reject.
///
/// **Liveness**: The cursor MUST eventually advance if work remains,
/// or the shard MUST reach a terminal state (Done or Parked).
///
/// Reference: Bacon et al., "Spanner: Becoming a SQL System" (2017) â€”
/// query restart with opaque restart tokens + ordered resume keys.
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

    /// Construct a cursor with a last_key and no resume token.
    ///
    /// Useful for connectors that don't need opaque pagination state.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty. A present key must contain at
    /// least one byte to be meaningful in the lex-ordered keyspace.
    pub fn with_last_key(last_key: Vec<u8>) -> Self {
        assert!(!last_key.is_empty(), "last_key must not be empty when present");
        Self {
            last_key: Some(last_key.into_boxed_slice()),
            token: None,
        }
    }

    /// Construct a cursor from both layers.
    ///
    /// # Panics
    ///
    /// Panics if `last_key` is empty.
    pub fn from_parts(last_key: Vec<u8>, token: Vec<u8>) -> Self {
        assert!(!last_key.is_empty(), "last_key must not be empty when present");
        Self {
            last_key: Some(last_key.into_boxed_slice()),
            token: if token.is_empty() { None } else { Some(token.into_boxed_slice()) },
        }
    }

    /// Returns `true` if no progress has been made.
    #[inline]
    pub fn is_initial(&self) -> bool {
        self.last_key.is_none()
    }
}

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
/// Compares only the `last_key` layer â€” the `token` layer is opaque
/// and not subject to ordering.
///
/// Returns `CursorAdvance::Forward` if the new cursor is â‰¥ the old
/// cursor in the `last_key` ordering. Returns a rejection variant
/// otherwise.
///
/// The comparison is lexicographic byte ordering â€” the natural ordering
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
        // No progress â†’ first progress: always valid.
        (None, Some(_)) => CursorAdvance::Forward,

        // No progress â†’ no progress: valid (no-op).
        (None, None) => CursorAdvance::Forward,

        // Had progress â†’ lost progress: regression.
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

// ---------------------------------------------------------------------------
// Â§1.2 ShardSpec â€” structured key range + opaque metadata
// ---------------------------------------------------------------------------

/// Shard specification with coordinator-visible key range bounds.
///
/// ## Key Range: Half-Open Interval `[start, end)`
///
/// ```text
/// â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
/// â”‚  start (inclusive)          end (exclusive)          â”‚
/// â”‚  â”œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”¤                       â”‚
/// â”‚  â—„â”€â”€ this shard covers â”€â”€â–º                          â”‚
/// â”‚                                                     â”‚
/// â”‚  Items with key k are in this shard iff:            â”‚
/// â”‚    start <= k < end    (lexicographic byte order)   â”‚
/// â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
/// ```
///
/// **Empty start** (`[]`): begins at the start of the keyspace.
/// **Empty end** (`[]`): extends to the end of the keyspace (unbounded).
///
/// This is the universal convention in range-sharded systems:
/// - Bigtable: `[startRow, endRow)` (Chang et al., OSDI 2006)
/// - Spanner: half-open key-range tablets (Corbett et al., OSDI 2012)
/// - CockroachDB: `[StartKey, EndKey)` ranges
/// - FoundationDB: `[begin, end)` byte strings (Zhou et al., SIGMOD 2021)
///
/// ## Opaque Metadata
///
/// The `metadata` field carries connector-specific information the
/// coordinator doesn't interpret: repository identifiers, bucket names,
/// authentication scopes, connector configuration, etc.
///
/// ## Invariants
///
/// **Safety (well-formed range)**: If both `start` and `end` are
/// non-empty, then `start < end` (lexicographic). An inverted or
/// degenerate range contains no items and must not exist.
///
/// **Safety (partition completeness)**: For a fully-partitioned run,
/// the union of all shard specs covers the entire keyspace without
/// gaps. This is a property of the partitioning logic, not enforced
/// by `ShardSpec` alone.
///
/// **Safety (partition disjointness)**: No two active shards in the
/// same run have overlapping key ranges. Also a partitioning invariant.
///
/// **Safety (cursor bounds)**: On checkpoint, `cursor.last_key` MUST
/// fall within `[start, end)`. Enforced by the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSpec {
    /// Inclusive lower bound of the key range.
    ///
    /// Empty (`[]`) means "start of keyspace."
    pub key_range_start: Box<[u8]>,

    /// Exclusive upper bound of the key range.
    ///
    /// Empty (`[]`) means "end of keyspace" (unbounded).
    pub key_range_end: Box<[u8]>,

    /// Connector-opaque metadata.
    ///
    /// Carries information the worker needs but the coordinator doesn't
    /// interpret: repository identifiers, authentication scopes, bucket
    /// names, connector-specific configuration, etc.
    ///
    /// Participates in payload hashing for idempotency but is not used
    /// for any coordination decision.
    pub metadata: Box<[u8]>,
}

impl ShardSpec {
    /// Unbounded shard covering the entire keyspace, no metadata.
    pub fn unbounded() -> Self {
        Self {
            key_range_start: Box::new([]),
            key_range_end: Box::new([]),
            metadata: Box::new([]),
        }
    }

    /// Construct a shard spec with explicit key range bounds.
    ///
    /// # Panics
    ///
    /// Panics if `start` and `end` are both non-empty and `start >= end`.
    pub fn with_range(start: Vec<u8>, end: Vec<u8>) -> Self {
        Self::with_range_and_metadata(start, end, vec![])
    }

    /// Construct a shard spec with key range bounds and metadata.
    ///
    /// # Panics
    ///
    /// Panics if `start` and `end` are both non-empty and `start >= end`.
    pub fn with_range_and_metadata(
        start: Vec<u8>,
        end: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Self {
        if !start.is_empty() && !end.is_empty() {
            assert!(
                start.as_slice() < end.as_slice(),
                "ShardSpec: start must be strictly less than end \
                 (start: {} bytes, end: {} bytes)",
                start.len(),
                end.len(),
            );
        }
        Self {
            key_range_start: start.into_boxed_slice(),
            key_range_end: end.into_boxed_slice(),
            metadata: metadata.into_boxed_slice(),
        }
    }

    /// Returns `true` if the key range has no lower bound.
    #[inline]
    pub fn is_start_unbounded(&self) -> bool {
        self.key_range_start.is_empty()
    }

    /// Returns `true` if the key range has no upper bound.
    #[inline]
    pub fn is_end_unbounded(&self) -> bool {
        self.key_range_end.is_empty()
    }

    /// Returns `true` if the shard covers the entire keyspace.
    #[inline]
    pub fn is_unbounded(&self) -> bool {
        self.is_start_unbounded() && self.is_end_unbounded()
    }

    /// Check whether a key falls within this shard's key range.
    ///
    /// Returns `true` if `key âˆˆ [start, end)` (lexicographic byte order).
    ///
    /// An empty key `[]` is at the very start of the keyspace â€” less
    /// than any non-empty key.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        let above_start = self.is_start_unbounded()
            || key >= self.key_range_start.as_ref();

        let below_end = self.is_end_unbounded()
            || key < self.key_range_end.as_ref();

        above_start && below_end
    }
}

/// `CanonicalBytes` for `ShardSpec`.
///
/// Encoding:
/// ```text
/// key_range_start : length-prefixed bytes
/// key_range_end   : length-prefixed bytes
/// metadata        : length-prefixed bytes
/// ```
///
/// All three fields are variable-length, so all are length-prefixed.
impl CanonicalBytes for ShardSpec {
    fn write_canonical(&self, h: &mut Hasher) {
        self.key_range_start.as_ref().write_canonical(h);
        self.key_range_end.as_ref().write_canonical(h);
        self.metadata.as_ref().write_canonical(h);
    }
}

// ---------------------------------------------------------------------------
// Â§1.3 Cursor bounds checking
// ---------------------------------------------------------------------------

/// Result of checking a cursor's `last_key` against a shard spec's range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CursorBoundsCheck {
    /// Cursor has no `last_key` â€” nothing to check (initial state).
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
/// `BelowRange` and `AboveRange` are safety violations â€” the worker is
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

// ---------------------------------------------------------------------------
// Â§1.4 Split validation
// ---------------------------------------------------------------------------

/// Validate that a proposed split produces children whose key ranges
/// exactly cover the parent's range without gaps or overlaps.
///
/// Children must form a contiguous partition of `[parent.start, parent.end)`:
///
/// 1. At least 2 children (a split that produces 1 child is not a split).
/// 2. First child's start == parent's start.
/// 3. Last child's end == parent's end.
/// 4. Each child's end == the next child's start (contiguous, no gaps).
/// 5. Each child is individually well-formed (start < end).
///
/// Reference: CockroachDB range split/merge validation; Spanner tablet
/// split with key-range continuity check.
pub fn validate_split_coverage(
    parent: &ShardSpec,
    children: &[ShardSpec],
) -> Result<(), SplitValidationError> {
    if children.is_empty() {
        return Err(SplitValidationError::NoChildren);
    }

    if children.len() == 1 {
        return Err(SplitValidationError::SingleChild);
    }

    // First child start == parent start.
    if children[0].key_range_start != parent.key_range_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent.key_range_start.clone(),
            first_child_start: children[0].key_range_start.clone(),
        });
    }

    // Last child end == parent end.
    let last = &children[children.len() - 1];
    if last.key_range_end != parent.key_range_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent.key_range_end.clone(),
            last_child_end: last.key_range_end.clone(),
        });
    }

    // Contiguity: each child's end == next child's start.
    for i in 0..children.len() - 1 {
        if children[i].key_range_end != children[i + 1].key_range_start {
            return Err(SplitValidationError::Gap {
                child_index: i,
                child_end: children[i].key_range_end.clone(),
                next_child_start: children[i + 1].key_range_start.clone(),
            });
        }
    }

    // Each child individually well-formed.
    for (i, child) in children.iter().enumerate() {
        if !child.key_range_start.is_empty()
            && !child.key_range_end.is_empty()
            && child.key_range_start >= child.key_range_end
        {
            return Err(SplitValidationError::InvertedChild { child_index: i });
        }
    }

    Ok(())
}

/// Errors from split coverage validation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitValidationError {
    /// Split must produce at least 2 children.
    NoChildren,
    /// A single child is not a split.
    SingleChild,
    /// First child's start doesn't match parent's start.
    StartMismatch {
        parent_start: Box<[u8]>,
        first_child_start: Box<[u8]>,
    },
    /// Last child's end doesn't match parent's end.
    EndMismatch {
        parent_end: Box<[u8]>,
        last_child_end: Box<[u8]>,
    },
    /// Gap between adjacent children.
    Gap {
        child_index: usize,
        child_end: Box<[u8]>,
        next_child_start: Box<[u8]>,
    },
    /// Child has inverted key range (start >= end).
    InvertedChild {
        child_index: usize,
    },
}

/// Validate that a residual split partitions the parent correctly.
///
/// A residual split shrinks the parent's range and creates a residual
/// shard covering the remainder:
///
/// ```text
/// old_parent:  [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
/// new_parent:  [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
/// residual:                [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
/// ```
///
/// The parent keeps the left portion (lower keys, already partially
/// processed) and the residual gets the right portion (higher keys,
/// unprocessed). This aligns with cursor monotonicity: the parent's
/// cursor has been advancing through the lower keys.
///
/// Delegates to `validate_split_coverage` â€” a residual split is a
/// two-child split.
pub fn validate_residual_split(
    old_parent: &ShardSpec,
    new_parent: &ShardSpec,
    residual: &ShardSpec,
) -> Result<(), SplitValidationError> {
    validate_split_coverage(old_parent, &[new_parent.clone(), residual.clone()])
}

// ---------------------------------------------------------------------------
// Â§1.5 Domain constant additions
// ---------------------------------------------------------------------------

pub mod domain {
    // ... existing constants from Boundary â‘  ...

    /// Cursor payload hashing for checkpoint idempotency.
    pub const CURSOR_V1: &[u8] = b"gossip/coord/v1/cursor";

    /// ShardSpec payload hashing for split idempotency.
    pub const SHARD_SPEC_V1: &[u8] = b"gossip/coord/v1/shard-spec";
}

// ============================================================================
// Â§ Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // â”€â”€ Cursor construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
            Some(b"org/repo\0src/main.rs".as_slice()),
        );
        assert!(c.token.is_none());
    }

    #[test]
    fn cursor_from_parts() {
        let c = Cursor::from_parts(
            b"org/repo\0src/main.rs".to_vec(),
            b"ghp_cursor_abc123".to_vec(),
        );
        assert!(!c.is_initial());
        assert!(c.last_key.is_some());
        assert!(c.token.is_some());
    }

    #[test]
    fn cursor_from_parts_empty_token_becomes_none() {
        let c = Cursor::from_parts(b"key".to_vec(), vec![]);
        assert!(c.last_key.is_some());
        assert!(c.token.is_none());
    }

    #[test]
    #[should_panic(expected = "must not be empty")]
    fn cursor_with_empty_last_key_panics() {
        Cursor::with_last_key(vec![]);
    }

    // â”€â”€ Cursor monotonicity â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn advance_none_to_none_is_forward() {
        let old = Cursor::initial();
        let new = Cursor::initial();
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Forward);
    }

    #[test]
    fn advance_none_to_some_is_forward() {
        let old = Cursor::initial();
        let new = Cursor::with_last_key(b"a".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Forward);
    }

    #[test]
    fn advance_some_to_greater_is_forward() {
        let old = Cursor::with_last_key(b"abc".to_vec());
        let new = Cursor::with_last_key(b"abd".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Forward);
    }

    #[test]
    fn advance_same_key_is_forward() {
        let old = Cursor::with_last_key(b"abc".to_vec());
        let new = Cursor::with_last_key(b"abc".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Forward);
    }

    #[test]
    fn advance_some_to_lesser_is_regression() {
        let old = Cursor::with_last_key(b"abd".to_vec());
        let new = Cursor::with_last_key(b"abc".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Regression);
    }

    #[test]
    fn advance_some_to_none_is_reset() {
        let old = Cursor::with_last_key(b"abc".to_vec());
        let new = Cursor::initial();
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::ResetToNone);
    }

    #[test]
    fn advance_longer_prefix_is_forward() {
        let old = Cursor::with_last_key(b"abc".to_vec());
        let new = Cursor::with_last_key(b"abcd".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Forward);
    }

    #[test]
    fn advance_shorter_prefix_is_regression() {
        let old = Cursor::with_last_key(b"abcd".to_vec());
        let new = Cursor::with_last_key(b"abc".to_vec());
        assert_eq!(check_cursor_advance(&old, &new), CursorAdvance::Regression);
    }

    // â”€â”€ ShardSpec construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn shard_spec_unbounded() {
        let s = ShardSpec::unbounded();
        assert!(s.is_unbounded());
        assert!(s.is_start_unbounded());
        assert!(s.is_end_unbounded());
    }

    #[test]
    fn shard_spec_with_range() {
        let s = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        assert!(!s.is_unbounded());
        assert_eq!(s.key_range_start.as_ref(), b"a");
        assert_eq!(s.key_range_end.as_ref(), b"m");
    }

    #[test]
    fn shard_spec_half_unbounded_start() {
        let s = ShardSpec::with_range(vec![], b"m".to_vec());
        assert!(s.is_start_unbounded());
        assert!(!s.is_end_unbounded());
    }

    #[test]
    fn shard_spec_half_unbounded_end() {
        let s = ShardSpec::with_range(b"m".to_vec(), vec![]);
        assert!(!s.is_start_unbounded());
        assert!(s.is_end_unbounded());
    }

    #[test]
    #[should_panic(expected = "start must be strictly less than end")]
    fn shard_spec_inverted_panics() {
        ShardSpec::with_range(b"z".to_vec(), b"a".to_vec());
    }

    #[test]
    #[should_panic(expected = "start must be strictly less than end")]
    fn shard_spec_equal_bounds_panics() {
        ShardSpec::with_range(b"a".to_vec(), b"a".to_vec());
    }

    // â”€â”€ ShardSpec::contains_key â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn contains_key_unbounded() {
        let s = ShardSpec::unbounded();
        assert!(s.contains_key(b"anything"));
        assert!(s.contains_key(b""));
        assert!(s.contains_key(b"\xff\xff\xff"));
    }

    #[test]
    fn contains_key_bounded_range() {
        let s = ShardSpec::with_range(b"d".to_vec(), b"m".to_vec());
        assert!(!s.contains_key(b"a"));   // below start
        assert!(!s.contains_key(b"c"));   // below start
        assert!(s.contains_key(b"d"));    // at start (inclusive)
        assert!(s.contains_key(b"f"));    // in range
        assert!(s.contains_key(b"l"));    // in range
        assert!(!s.contains_key(b"m"));   // at end (exclusive)
        assert!(!s.contains_key(b"z"));   // above end
    }

    #[test]
    fn contains_key_unbounded_start() {
        let s = ShardSpec::with_range(vec![], b"m".to_vec());
        assert!(s.contains_key(b""));
        assert!(s.contains_key(b"a"));
        assert!(!s.contains_key(b"m"));
    }

    #[test]
    fn contains_key_unbounded_end() {
        let s = ShardSpec::with_range(b"m".to_vec(), vec![]);
        assert!(!s.contains_key(b"a"));
        assert!(s.contains_key(b"m"));
        assert!(s.contains_key(b"z"));
        assert!(s.contains_key(b"\xff"));
    }

    // â”€â”€ Cursor bounds checking â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn bounds_check_no_key() {
        let c = Cursor::initial();
        let s = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::NoKey);
    }

    #[test]
    fn bounds_check_in_range() {
        let c = Cursor::with_last_key(b"m".to_vec());
        let s = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::InBounds);
    }

    #[test]
    fn bounds_check_below_range() {
        let c = Cursor::with_last_key(b"a".to_vec());
        let s = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::BelowRange);
    }

    #[test]
    fn bounds_check_above_range() {
        let c = Cursor::with_last_key(b"z".to_vec());
        let s = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::AboveRange);
    }

    #[test]
    fn bounds_check_at_start_inclusive() {
        let c = Cursor::with_last_key(b"a".to_vec());
        let s = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::InBounds);
    }

    #[test]
    fn bounds_check_at_end_exclusive() {
        let c = Cursor::with_last_key(b"z".to_vec());
        let s = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::AboveRange);
    }

    #[test]
    fn bounds_check_unbounded_spec() {
        let c = Cursor::with_last_key(b"\xff\xff".to_vec());
        let s = ShardSpec::unbounded();
        assert_eq!(check_cursor_bounds(&c, &s), CursorBoundsCheck::InBounds);
    }

    // â”€â”€ Split validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn split_valid_two_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_valid_three_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"a".to_vec(), b"h".to_vec()),
            ShardSpec::with_range(b"h".to_vec(), b"p".to_vec()),
            ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_valid_unbounded_parent() {
        let parent = ShardSpec::unbounded();
        let children = vec![
            ShardSpec::with_range(vec![], b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), vec![]),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_no_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        assert_eq!(
            validate_split_coverage(&parent, &[]),
            Err(SplitValidationError::NoChildren),
        );
    }

    #[test]
    fn split_single_child() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        ];
        assert_eq!(
            validate_split_coverage(&parent, &children),
            Err(SplitValidationError::SingleChild),
        );
    }

    #[test]
    fn split_start_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"b".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        assert!(matches!(
            validate_split_coverage(&parent, &children),
            Err(SplitValidationError::StartMismatch { .. }),
        ));
    }

    #[test]
    fn split_end_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"y".to_vec()),
        ];
        assert!(matches!(
            validate_split_coverage(&parent, &children),
            Err(SplitValidationError::EndMismatch { .. }),
        ));
    }

    #[test]
    fn split_gap_between_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = vec![
            ShardSpec::with_range(b"a".to_vec(), b"h".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        assert!(matches!(
            validate_split_coverage(&parent, &children),
            Err(SplitValidationError::Gap { .. }),
        ));
    }

    #[test]
    fn residual_split_valid() {
        let old = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let new_parent = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        assert!(validate_residual_split(&old, &new_parent, &residual).is_ok());
    }

    #[test]
    fn residual_split_gap() {
        let old = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let new_parent = ShardSpec::with_range(b"a".to_vec(), b"h".to_vec());
        let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        assert!(validate_residual_split(&old, &new_parent, &residual).is_err());
    }

    // â”€â”€ CanonicalBytes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn cursor_canonical_bytes_deterministic() {
        let c = Cursor::from_parts(b"key".to_vec(), b"tok".to_vec());
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        c.write_canonical(&mut h1);
        c.write_canonical(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn cursor_canonical_bytes_none_vs_some_empty_distinct() {
        // Verify the presence-byte encoding distinguishes None from
        // Some(empty). Constructed manually since the public API
        // prevents empty last_key.
        let c_none = Cursor { last_key: None, token: None };
        let c_some_empty = Cursor {
            last_key: Some(Box::new([]) as Box<[u8]>),
            token: None,
        };

        let mut h_none = Hasher::new();
        let mut h_some = Hasher::new();
        c_none.write_canonical(&mut h_none);
        c_some_empty.write_canonical(&mut h_some);
        assert_ne!(h_none.finalize(), h_some.finalize());
    }

    #[test]
    fn shard_spec_canonical_bytes_deterministic() {
        let s = ShardSpec::with_range_and_metadata(
            b"a".to_vec(), b"z".to_vec(), b"meta".to_vec(),
        );
        let mut h1 = Hasher::new();
        let mut h2 = Hasher::new();
        s.write_canonical(&mut h1);
        s.write_canonical(&mut h2);
        assert_eq!(h1.finalize(), h2.finalize());
    }

    #[test]
    fn shard_spec_canonical_bytes_different_ranges_differ() {
        let a = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let b = ShardSpec::with_range(b"a".to_vec(), b"n".to_vec());

        let mut ha = Hasher::new();
        let mut hb = Hasher::new();
        a.write_canonical(&mut ha);
        b.write_canonical(&mut hb);
        assert_ne!(ha.finalize(), hb.finalize());
    }

    // â”€â”€ Property-based â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    proptest::proptest! {
        #[test]
        fn cursor_advance_reflexive(
            key in proptest::collection::vec(proptest::num::u8::ANY, 1..64)
        ) {
            let c = Cursor::with_last_key(key);
            prop_assert_eq!(check_cursor_advance(&c, &c), CursorAdvance::Forward);
        }

        #[test]
        fn cursor_canonical_bytes_stable(
            key in proptest::option::of(
                proptest::collection::vec(proptest::num::u8::ANY, 1..64)
            ),
            tok in proptest::option::of(
                proptest::collection::vec(proptest::num::u8::ANY, 1..64)
            ),
        ) {
            let c = Cursor {
                last_key: key.map(|v| v.into_boxed_slice()),
                token: tok.map(|v| v.into_boxed_slice()),
            };
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            c.write_canonical(&mut h1);
            c.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn shard_spec_canonical_bytes_stable(
            start in proptest::collection::vec(proptest::num::u8::ANY, 0..32),
            end_suffix in proptest::collection::vec(proptest::num::u8::ANY, 1..32),
            metadata in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
        ) {
            // Ensure valid range by appending suffix to start.
            let mut end = start.clone();
            end.extend_from_slice(&end_suffix);

            let s = ShardSpec::with_range_and_metadata(start, end, metadata);
            let mut h1 = Hasher::new();
            let mut h2 = Hasher::new();
            s.write_canonical(&mut h1);
            s.write_canonical(&mut h2);
            prop_assert_eq!(h1.finalize(), h2.finalize());
        }

        #[test]
        fn contains_key_matches_manual_check(
            start in proptest::collection::vec(proptest::num::u8::ANY, 1..8),
            end_suffix in proptest::collection::vec(proptest::num::u8::ANY, 1..8),
            key in proptest::collection::vec(proptest::num::u8::ANY, 0..16),
        ) {
            let mut end = start.clone();
            end.extend_from_slice(&end_suffix);

            let s = ShardSpec::with_range(start.clone(), end.clone());
            let expected = key.as_slice() >= start.as_slice()
                && key.as_slice() < end.as_slice();
            prop_assert_eq!(s.contains_key(&key), expected);
        }
    }
}
