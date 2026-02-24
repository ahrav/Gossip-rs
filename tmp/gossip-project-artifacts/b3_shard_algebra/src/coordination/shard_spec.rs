//! ShardSpec and CursorSemantics: structured key ranges, cursor modes,
//! and split validation.
//!
//! `ShardSpec` answers "what key range does this shard cover?" with a
//! half-open interval `[start, end)` in lexicographic byte order, plus
//! opaque connector metadata the coordinator stores but never interprets.
//!
//! `CursorSemantics` controls when cursor advancement counts as
//! committed progress â€” per-run configuration that affects the strength
//! of the progress guarantee.
//!
//! ## Design Decisions (locked)
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

use blake3::Hasher;

use crate::identity::CanonicalBytes;

// ============================================================================
// Â§ CursorSemantics
// ============================================================================

/// Determines when cursor advancement counts as committed progress.
///
/// This is a per-run configuration choice that affects the strength of
/// the progress guarantee:
///
/// - `Completed`: strongest guarantee. The cursor only advances after
///   all work up to that point is fully processed and results are durable.
///   Failure after checkpoint means no work is lost.
///
/// - `Dispatched`: weaker but higher throughput. The cursor advances
///   after work is durably *dispatched* (e.g., to a separate work queue)
///   but not necessarily fully processed. Requires the dispatch target
///   to provide its own exactly-once guarantee.
///
/// ## Invariants
///
/// **Safety**: The coordinator enforces monotonicity and bounds checking
/// identically under both semantics. The difference is in what the
/// worker promises the cursor position represents.
///
/// **Safety (discriminant stability)**: The `u8` discriminant values are
/// persisted in coordination state. Existing values MUST NOT be reused
/// or reordered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CursorSemantics {
    /// Cursor advances only after work prior to the cursor is fully
    /// scanned and authoritative progress is committed.
    Completed = 0,

    /// Cursor advances after work prior to the cursor is durably
    /// dispatched to a separate work log. The work log is responsible
    /// for its own delivery guarantees.
    Dispatched = 1,
}

impl CursorSemantics {
    /// Parse a `u8` discriminant to the corresponding variant.
    ///
    /// Returns `None` for unrecognized values â€” forward compatibility.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Completed),
            1 => Some(Self::Dispatched),
            _ => None,
        }
    }

    /// Return the stable `u8` discriminant.
    #[inline]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl CanonicalBytes for CursorSemantics {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.as_u8().write_canonical(h);
    }
}

// ============================================================================
// Â§ ShardSpec
// ============================================================================

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
        let above_start =
            self.is_start_unbounded() || key >= self.key_range_start.as_ref();

        let below_end =
            self.is_end_unbounded() || key < self.key_range_end.as_ref();

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

// ============================================================================
// Â§ Split Validation
// ============================================================================

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
    InvertedChild { child_index: usize },
}

/// Validate that a proposed split produces children whose key ranges
/// exactly cover the parent's range without gaps or overlaps.
///
/// Children must form a contiguous partition of `[parent.start, parent.end)`:
///
/// 1. At least 2 children (a split that produces 1 child is not a split).
/// 2. First child's start == parent's start.
/// 3. Last child's end == parent's end.
/// 4. Each child's end == the next child's start (contiguous, no gaps).
/// 5. Each child is individually well-formed (start < end, unless one
///    bound is empty for the unbounded edge).
///
/// Children are sorted by `key_range_start` before validation so callers
/// need not provide them in order. This is a robustness choice: the
/// function validates the *set* of children, not an ordered sequence.
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

    // Sort children by start key for order-independent validation.
    // Empty start key sorts first (it's the keyspace minimum).
    let mut sorted: Vec<&ShardSpec> = children.iter().collect();
    sorted.sort_by(|a, b| a.key_range_start.cmp(&b.key_range_start));

    // First child start == parent start.
    if sorted[0].key_range_start != parent.key_range_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent.key_range_start.clone(),
            first_child_start: sorted[0].key_range_start.clone(),
        });
    }

    // Last child end == parent end.
    let last = sorted[sorted.len() - 1];
    if last.key_range_end != parent.key_range_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent.key_range_end.clone(),
            last_child_end: last.key_range_end.clone(),
        });
    }

    // Contiguity: each child's end == next child's start.
    for i in 0..sorted.len() - 1 {
        if sorted[i].key_range_end != sorted[i + 1].key_range_start {
            return Err(SplitValidationError::Gap {
                child_index: i,
                child_end: sorted[i].key_range_end.clone(),
                next_child_start: sorted[i + 1].key_range_start.clone(),
            });
        }
    }

    // Each child individually well-formed.
    for (i, child) in sorted.iter().enumerate() {
        if !child.key_range_start.is_empty()
            && !child.key_range_end.is_empty()
            && child.key_range_start >= child.key_range_end
        {
            return Err(SplitValidationError::InvertedChild { child_index: i });
        }
    }

    Ok(())
}

/// Validate that a residual split partitions the parent correctly.
///
/// A residual split shrinks the parent's range and creates a residual
/// shard covering the remainder:
///
/// ```text
/// old_parent:  [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
/// new_parent:  [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
/// residual:               [â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€)
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

// ============================================================================
// Â§ InitialShard & Manifest Validation
// ============================================================================

use core::fmt;

use crate::identity::ShardId;
use super::cursor::Cursor;

/// A shard as provided by the connector during `register_shards`.
///
/// Contains the spec (key range + metadata) and an initial cursor
/// (typically `Cursor::initial()`). The coordinator validates uniqueness
/// of shard IDs and non-overlap of key ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InitialShard {
    /// Shard ID assigned by the caller. The coordinator validates uniqueness.
    pub shard_id: ShardId,

    /// The shard's key range and connector metadata.
    pub spec: ShardSpec,

    /// Initial cursor (usually `Cursor::initial()`).
    pub cursor: Cursor,
}

/// Validation errors for a set of initial shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ManifestValidationError {
    /// No shards in the manifest.
    Empty,

    /// Duplicate shard IDs in the manifest.
    DuplicateId { shard_id: ShardId },

    /// Two shards have overlapping key ranges.
    OverlappingRanges {
        shard_a: ShardId,
        shard_b: ShardId,
        overlap_start: Box<[u8]>,
    },

    /// A shard has an invalid spec (e.g., start >= end).
    InvalidSpec {
        shard_id: ShardId,
        reason: String,
    },
}

impl fmt::Display for ManifestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "manifest is empty: at least one shard required"),
            Self::DuplicateId { shard_id } => {
                write!(f, "duplicate shard ID: {:?}", shard_id)
            }
            Self::OverlappingRanges {
                shard_a,
                shard_b,
                overlap_start,
            } => write!(
                f,
                "overlapping ranges: shards {:?} and {:?} overlap at {:?}",
                shard_a,
                shard_b,
                &overlap_start[..overlap_start.len().min(16)],
            ),
            Self::InvalidSpec { shard_id, reason } => {
                write!(f, "invalid spec for {:?}: {}", shard_id, reason)
            }
        }
    }
}

/// Validate a manifest of initial shards.
///
/// Checks:
/// 1. Non-empty.
/// 2. No duplicate shard IDs.
/// 3. No overlapping key ranges.
/// 4. Each spec is internally valid (start < end).
///
/// Gaps between shards are allowed.
pub fn validate_manifest(
    shards: &[InitialShard],
) -> Result<(), ManifestValidationError> {
    if shards.is_empty() {
        return Err(ManifestValidationError::Empty);
    }

    // Check for duplicate IDs.
    let mut ids: Vec<ShardId> = shards.iter().map(|s| s.shard_id).collect();
    ids.sort_by_key(|id| id.0);
    for window in ids.windows(2) {
        if window[0] == window[1] {
            return Err(ManifestValidationError::DuplicateId {
                shard_id: window[0],
            });
        }
    }

    // Check each spec is valid.
    for shard in shards {
        if !shard.spec.is_start_unbounded()
            && !shard.spec.is_end_unbounded()
            && shard.spec.key_range_start >= shard.spec.key_range_end
        {
            return Err(ManifestValidationError::InvalidSpec {
                shard_id: shard.shard_id,
                reason: "key_range_start must be < key_range_end".into(),
            });
        }
    }

    // Sort by key range start to check for overlaps.
    let mut sorted: Vec<&InitialShard> = shards.iter().collect();
    sorted.sort_by(|a, b| a.spec.key_range_start.cmp(&b.spec.key_range_start));

    for window in sorted.windows(2) {
        let a = window[0];
        let b = window[1];

        // `key_range_end == []` means "unbounded end" (∞), which overlaps
        // with any subsequent shard that starts at or after `a.start`.
        let a_end_unbounded = a.spec.is_end_unbounded();

        // Overlap exists iff a.end is unbounded OR a.end > b.start.
        // Adjacency (a.end == b.start) is allowed and does not overlap.
        if a_end_unbounded || a.spec.key_range_end > b.spec.key_range_start {
            return Err(ManifestValidationError::OverlappingRanges {
                shard_a: a.shard_id,
                shard_b: b.shard_id,
                overlap_start: b.spec.key_range_start.clone(),
            });
        }
    }

    Ok(())
}

// ============================================================================
// § Split Plan Types
// ============================================================================

/// A child shard in a `SplitReplacePlan`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplaceChild {
    pub spec: ShardSpec,
    pub cursor: Cursor,
}

impl CanonicalBytes for SplitReplaceChild {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.spec.write_canonical(h);
        self.cursor.write_canonical(h);
    }
}

/// Plan for replacing a shard with N children.
///
/// The coordinator validates that the children's key ranges collectively
/// cover the parent's range exactly (no gaps, no overlaps) using
/// `validate_split_coverage`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitReplacePlan {
    pub children: Vec<SplitReplaceChild>,
}

impl CanonicalBytes for SplitReplacePlan {
    fn write_canonical(&self, h: &mut Hasher) {
        (self.children.len() as u32).write_canonical(h);
        for child in &self.children {
            child.write_canonical(h);
        }
    }
}

/// Plan for shrinking a shard and creating a residual.
///
/// ```text
/// old_parent:  [████████████████████████)
/// new_parent:  [██████████)
/// residual:                [█████████████)
/// ```
///
/// Parent keeps the left portion (lower keys, partially processed).
/// Residual gets the right portion (higher keys, unprocessed).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SplitResidualPlan {
    pub parent_new_spec: ShardSpec,
    pub residual_spec: ShardSpec,
    pub residual_cursor: Cursor,
}

impl CanonicalBytes for SplitResidualPlan {
    fn write_canonical(&self, h: &mut Hasher) {
        self.parent_new_spec.write_canonical(h);
        self.residual_spec.write_canonical(h);
        self.residual_cursor.write_canonical(h);
    }
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    // â”€â”€ CursorSemantics â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test from_u8 roundtrip
    //   - CursorSemantics::from_u8(0) == Some(Completed)
    //   - CursorSemantics::from_u8(1) == Some(Dispatched)
    //   - CursorSemantics::from_u8(2) == None

    // TODO: test as_u8 stability
    //   - Completed.as_u8() == 0, Dispatched.as_u8() == 1

    // TODO: test canonical_bytes_discriminant_distinct
    //   - Completed and Dispatched produce different hash output

    // â”€â”€ ShardSpec construction â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test shard_spec_unbounded
    //   - ShardSpec::unbounded() â†’ is_unbounded(), is_start_unbounded(),
    //     is_end_unbounded()

    // TODO: test shard_spec_with_range
    //   - ShardSpec::with_range(b"a", b"m") â†’ correct fields, !is_unbounded()

    // TODO: test shard_spec_half_unbounded_start
    //   - ShardSpec::with_range(vec![], b"m") â†’ is_start_unbounded(),
    //     !is_end_unbounded()

    // TODO: test shard_spec_half_unbounded_end
    //   - ShardSpec::with_range(b"m", vec![]) â†’ !is_start_unbounded(),
    //     is_end_unbounded()

    // TODO: test shard_spec_inverted_panics
    //   - #[should_panic(expected = "start must be strictly less than end")]
    //   - ShardSpec::with_range(b"z", b"a")

    // TODO: test shard_spec_equal_bounds_panics
    //   - #[should_panic(expected = "start must be strictly less than end")]
    //   - ShardSpec::with_range(b"a", b"a")

    // â”€â”€ ShardSpec::contains_key â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test contains_key_unbounded â†’ true for any key
    // TODO: test contains_key_bounded_range â†’ inclusive start, exclusive end
    // TODO: test contains_key_unbounded_start â†’ includes empty key
    // TODO: test contains_key_unbounded_end â†’ includes high bytes

    // â”€â”€ CanonicalBytes â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test shard_spec_canonical_bytes_deterministic
    // TODO: test shard_spec_canonical_bytes_different_ranges_differ

    // â”€â”€ Split validation â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test split_valid_two_way â†’ Ok
    // TODO: test split_valid_three_way â†’ Ok
    // TODO: test split_valid_unbounded_parent â†’ Ok
    // TODO: test split_no_children â†’ Err(NoChildren)
    // TODO: test split_single_child â†’ Err(SingleChild)
    // TODO: test split_start_mismatch â†’ Err(StartMismatch)
    // TODO: test split_end_mismatch â†’ Err(EndMismatch)
    // TODO: test split_gap_between_children â†’ Err(Gap)
    // TODO: test split_children_out_of_order_still_valid
    //   - Provide children in reverse order; sorting makes it pass.

    // â”€â”€ Residual split â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: test residual_split_valid â†’ Ok
    // TODO: test residual_split_gap â†’ Err

    // â”€â”€ Property-based (proptest) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    // TODO: proptest shard_spec_canonical_bytes_stable
    // TODO: proptest contains_key_matches_manual_check
    //   - âˆ€ (start, end_suffix, key):
    //     spec.contains_key(key) == (key >= start && key < end)

    // â"€â"€ validate_manifest â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€â"€

    fn make_initial_shard(id: u64, start: &[u8], end: &[u8]) -> InitialShard {
        InitialShard {
            shard_id: ShardId(id),
            spec: ShardSpec::with_range(start.to_vec(), end.to_vec()),
            cursor: Cursor::initial(),
        }
    }

    #[test]
    fn validate_manifest_ok() {
        let shards = vec![
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_ok_with_gaps() {
        let shards = vec![
            make_initial_shard(0, b"a", b"f"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_ok_unordered_input() {
        let shards = vec![
            make_initial_shard(1, b"m", b"z"),
            make_initial_shard(0, b"a", b"m"),
        ];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_empty() {
        assert_eq!(
            validate_manifest(&[]),
            Err(ManifestValidationError::Empty),
        );
    }

    #[test]
    fn validate_manifest_duplicate_id() {
        let shards = vec![
            make_initial_shard(0, b"a", b"m"),
            make_initial_shard(0, b"m", b"z"),
        ];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::DuplicateId { .. }),
        ));
    }

    #[test]
    fn validate_manifest_overlap() {
        let shards = vec![
            make_initial_shard(0, b"a", b"n"),
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::OverlappingRanges { .. }),
        ));
    }

    #[test]
    fn validate_manifest_overlap_with_unbounded_end() {
        // A shard with an unbounded end overlaps any later shard.
        let shards = vec![
            make_initial_shard(0, b"a", b""), // unbounded end (∞)
            make_initial_shard(1, b"m", b"z"),
        ];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::OverlappingRanges { .. }),
        ));
    }

    #[test]
    fn validate_manifest_invalid_spec() {
        // Construct directly to bypass ShardSpec::with_range panic.
        let shards = vec![InitialShard {
            shard_id: ShardId(0),
            spec: ShardSpec {
                key_range_start: b"z".to_vec().into_boxed_slice(),
                key_range_end: b"a".to_vec().into_boxed_slice(),
                metadata: vec![].into_boxed_slice(),
            },
            cursor: Cursor::initial(),
        }];
        assert!(matches!(
            validate_manifest(&shards),
            Err(ManifestValidationError::InvalidSpec { .. }),
        ));
    }

    #[test]
    fn validate_manifest_single_shard_ok() {
        let shards = vec![make_initial_shard(0, b"a", b"z")];
        assert!(validate_manifest(&shards).is_ok());
    }

    #[test]
    fn validate_manifest_error_display() {
        let e = ManifestValidationError::Empty;
        assert!(format!("{}", e).contains("empty"));

        let e = ManifestValidationError::DuplicateId {
            shard_id: ShardId(42),
        };
        assert!(format!("{}", e).contains("duplicate"));

        let e = ManifestValidationError::OverlappingRanges {
            shard_a: ShardId(0),
            shard_b: ShardId(1),
            overlap_start: b"mid".to_vec().into_boxed_slice(),
        };
        assert!(format!("{}", e).contains("overlap"));

        let e = ManifestValidationError::InvalidSpec {
            shard_id: ShardId(0),
            reason: "bad range".into(),
        };
        assert!(format!("{}", e).contains("bad range"));
    }
}
