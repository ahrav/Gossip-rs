//! ShardSpec and CursorSemantics: structured key ranges, cursor modes,
//! and split validation.
//!
//! `ShardSpec` answers "what key range does this shard cover?" with a
//! half-open interval `[start, end)` in lexicographic byte order, plus
//! opaque connector metadata the coordinator stores but never interprets.
//!
//! `CursorSemantics` controls when cursor advancement counts as
//! committed progress — per-run configuration that affects the strength
//! of the progress guarantee.
//!
//! ## Design Decisions (locked)
//!
//! D2.2: ShardSpec has a half-open key range `[start, end)` with
//! lex-ordered byte boundaries, plus opaque connector metadata.
//!
//! Reference: Bigtable (Chang et al., OSDI 2006) — tablets as
//! contiguous row ranges; Spanner (Corbett et al., OSDI 2012) —
//! half-open key-range splits; CockroachDB —
//! ranges with half-open `[start, end)` intervals; FoundationDB
//! (Zhou et al., SIGMOD 2021) — key ranges as `[begin, end)` byte
//! strings.

use blake3::Hasher;

use crate::identity::CanonicalBytes;

// ============================================================================
// CursorSemantics
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
/// **Safety**: The coordinator enforces monotonicity
/// ([`check_cursor_advance`](super::cursor::check_cursor_advance)) and
/// bounds checking
/// ([`check_cursor_bounds`](super::cursor::check_cursor_bounds))
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
    /// Returns `None` for unrecognized values — forward compatibility.
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

// Compile-time assertions for CursorSemantics discriminant stability.
const _: () = assert!(CursorSemantics::Completed as u8 == 0);
const _: () = assert!(CursorSemantics::Dispatched as u8 == 1);

// ============================================================================
// ShardSpec
// ============================================================================

/// Shard specification with coordinator-visible key range bounds.
///
/// ## Key Range: Half-Open Interval `[start, end)`
///
/// ```text
/// ┌─────────────────────────────────────────────────────┐
/// │  start (inclusive)          end (exclusive)          │
/// │  ├──────────────────────────┤                       │
/// │  ◄── this shard covers ──►                          │
/// │                                                     │
/// │  Items with key k are in this shard iff:            │
/// │    start <= k < end    (lexicographic byte order)   │
/// └─────────────────────────────────────────────────────┘
/// ```
///
/// **Empty start** (`[]`): begins at the start of the keyspace.
/// **Empty end** (`[]`): extends to the end of the keyspace (unbounded).
///
/// This is the universal convention in range-sharded systems:
/// - Bigtable: `[startRow, endRow)` (Chang et al., OSDI 2006)
/// - Spanner: half-open key-range splits (Corbett et al., OSDI 2012)
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
    pub fn with_range_and_metadata(start: Vec<u8>, end: Vec<u8>, metadata: Vec<u8>) -> Self {
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

    /// Returns `true` if the range bounds are well-formed.
    ///
    /// Valid iff either bound is unbounded (empty), or `start < end` (lex).
    #[inline]
    pub fn is_valid(&self) -> bool {
        if !self.key_range_start.is_empty() && !self.key_range_end.is_empty() {
            self.key_range_start.as_ref() < self.key_range_end.as_ref()
        } else {
            true
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
    /// Returns `true` if `key ∈ [start, end)` (lexicographic byte order).
    ///
    /// An empty key `[]` is at the very start of the keyspace — less
    /// than any non-empty key.
    pub fn contains_key(&self, key: &[u8]) -> bool {
        let above_start = self.is_start_unbounded() || key >= self.key_range_start.as_ref();

        let below_end = self.is_end_unbounded() || key < self.key_range_end.as_ref();

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
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.key_range_start.as_ref().write_canonical(h);
        self.key_range_end.as_ref().write_canonical(h);
        self.metadata.as_ref().write_canonical(h);
    }
}

// ============================================================================
// Split Validation
// ============================================================================

/// Errors returned by [`validate_split_coverage`] and
/// [`validate_residual_split`] when proposed child shards do not form
/// a valid partition of the parent's key range.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SplitValidationError {
    /// No children were provided (need at least 2).
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

    /// Residual split must not strand the parent by shrinking its spec past
    /// the current cursor.
    ///
    /// Not produced by the pure-validation functions in this module. The
    /// coordination backend raises this when a residual split would move the
    /// parent's range boundary behind the cursor's `last_key`.
    ParentCursorOutOfBounds {
        cursor: Box<[u8]>,
        new_parent_start: Box<[u8]>,
        new_parent_end: Box<[u8]>,
    },
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
/// old_parent:  [─────────────────────────)
/// new_parent:  [──────────)
/// residual:               [─────────────)
/// ```
///
/// The parent keeps the left portion (lower keys, already partially
/// processed) and the residual gets the right portion (higher keys,
/// unprocessed). This aligns with cursor monotonicity: the parent's
/// cursor has been advancing through the lower keys.
///
/// Delegates to `validate_split_coverage` — a residual split is a
/// two-child split.
pub fn validate_residual_split(
    old_parent: &ShardSpec,
    new_parent: &ShardSpec,
    residual: &ShardSpec,
) -> Result<(), SplitValidationError> {
    validate_split_coverage(old_parent, &[new_parent.clone(), residual.clone()])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use blake3::Hasher;
    use proptest::prelude::*;

    /// Helper: hash a value via CanonicalBytes and return the digest.
    fn canonical_digest<T: CanonicalBytes>(val: &T) -> blake3::Hash {
        let mut h = Hasher::new();
        val.write_canonical(&mut h);
        h.finalize()
    }

    // -------------------------------------------------------------------
    // CursorSemantics
    // -------------------------------------------------------------------

    #[test]
    fn from_u8_roundtrip() {
        assert_eq!(
            CursorSemantics::from_u8(0),
            Some(CursorSemantics::Completed)
        );
        assert_eq!(
            CursorSemantics::from_u8(1),
            Some(CursorSemantics::Dispatched)
        );
        assert_eq!(CursorSemantics::from_u8(2), None);
    }

    #[test]
    fn as_u8_stability() {
        assert_eq!(CursorSemantics::Completed.as_u8(), 0);
        assert_eq!(CursorSemantics::Dispatched.as_u8(), 1);
    }

    #[test]
    fn canonical_bytes_discriminant_distinct() {
        let d_completed = canonical_digest(&CursorSemantics::Completed);
        let d_dispatched = canonical_digest(&CursorSemantics::Dispatched);
        assert_ne!(d_completed, d_dispatched);
    }

    // -------------------------------------------------------------------
    // ShardSpec construction
    // -------------------------------------------------------------------

    #[test]
    fn shard_spec_unbounded() {
        let spec = ShardSpec::unbounded();
        assert!(spec.is_unbounded());
        assert!(spec.is_start_unbounded());
        assert!(spec.is_end_unbounded());
        assert!(spec.key_range_start.is_empty());
        assert!(spec.key_range_end.is_empty());
        assert!(spec.metadata.is_empty());
    }

    #[test]
    fn shard_spec_with_range() {
        let spec = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        assert_eq!(&*spec.key_range_start, b"a");
        assert_eq!(&*spec.key_range_end, b"m");
        assert!(!spec.is_unbounded());
        assert!(!spec.is_start_unbounded());
        assert!(!spec.is_end_unbounded());
        assert!(spec.is_valid());
    }

    #[test]
    fn shard_spec_half_unbounded_start() {
        let spec = ShardSpec::with_range(vec![], b"m".to_vec());
        assert!(spec.is_start_unbounded());
        assert!(!spec.is_end_unbounded());
        assert!(!spec.is_unbounded());
    }

    #[test]
    fn shard_spec_half_unbounded_end() {
        let spec = ShardSpec::with_range(b"m".to_vec(), vec![]);
        assert!(!spec.is_start_unbounded());
        assert!(spec.is_end_unbounded());
        assert!(!spec.is_unbounded());
    }

    #[test]
    #[should_panic(expected = "start must be strictly less than end")]
    fn shard_spec_inverted_panics() {
        let _ = ShardSpec::with_range(b"z".to_vec(), b"a".to_vec());
    }

    #[test]
    #[should_panic(expected = "start must be strictly less than end")]
    fn shard_spec_equal_bounds_panics() {
        let _ = ShardSpec::with_range(b"a".to_vec(), b"a".to_vec());
    }

    // -------------------------------------------------------------------
    // Split validation
    // -------------------------------------------------------------------

    #[test]
    fn split_valid_two_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = [
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_valid_three_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = [
            ShardSpec::with_range(b"a".to_vec(), b"g".to_vec()),
            ShardSpec::with_range(b"g".to_vec(), b"p".to_vec()),
            ShardSpec::with_range(b"p".to_vec(), b"z".to_vec()),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_valid_unbounded_parent() {
        let parent = ShardSpec::unbounded();
        let children = [
            ShardSpec::with_range(vec![], b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), vec![]),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_no_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(&parent, &[]);
        assert!(matches!(result, Err(SplitValidationError::NoChildren)));
    }

    #[test]
    fn split_single_child() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(
            &parent,
            &[ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())],
        );
        assert!(matches!(result, Err(SplitValidationError::SingleChild)));
    }

    #[test]
    fn split_start_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = [
            ShardSpec::with_range(b"b".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        let result = validate_split_coverage(&parent, &children);
        assert!(matches!(
            result,
            Err(SplitValidationError::StartMismatch { .. })
        ));
    }

    #[test]
    fn split_end_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = [
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec::with_range(b"m".to_vec(), b"y".to_vec()),
        ];
        let result = validate_split_coverage(&parent, &children);
        assert!(matches!(
            result,
            Err(SplitValidationError::EndMismatch { .. })
        ));
    }

    #[test]
    fn split_gap_between_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let children = [
            ShardSpec::with_range(b"a".to_vec(), b"g".to_vec()),
            ShardSpec::with_range(b"h".to_vec(), b"z".to_vec()),
        ];
        let result = validate_split_coverage(&parent, &children);
        assert!(matches!(result, Err(SplitValidationError::Gap { .. })));
    }

    #[test]
    fn split_children_out_of_order_still_valid() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // Provide children in reverse order; sorting makes it pass.
        let children = [
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ];
        assert!(validate_split_coverage(&parent, &children).is_ok());
    }

    #[test]
    fn split_inverted_child() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // A zero-width child [m, m) passes contiguity but fails
        // the well-formedness check (start >= end).
        let children = [
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            ShardSpec {
                key_range_start: b"m".as_slice().into(),
                key_range_end: b"m".as_slice().into(),
                metadata: Box::new([]),
            },
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
        ];
        let result = validate_split_coverage(&parent, &children);
        assert!(matches!(
            result,
            Err(SplitValidationError::InvertedChild { .. })
        ));
    }

    // -------------------------------------------------------------------
    // Residual split
    // -------------------------------------------------------------------

    #[test]
    fn residual_split_valid() {
        let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let new_parent = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let residual = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        assert!(validate_residual_split(&old_parent, &new_parent, &residual).is_ok());
    }

    #[test]
    fn residual_split_gap() {
        let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let new_parent = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
        let residual = ShardSpec::with_range(b"h".to_vec(), b"z".to_vec());
        let result = validate_residual_split(&old_parent, &new_parent, &residual);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // Property-based tests
    // -------------------------------------------------------------------

    /// Generate a valid bounded ShardSpec: end = start ++ non-empty suffix,
    /// guaranteeing `start < end` lexicographically.
    fn arb_bounded_shard_spec() -> impl Strategy<Value = ShardSpec> {
        (
            proptest::collection::vec(any::<u8>(), 1..64),
            proptest::collection::vec(any::<u8>(), 1..8),
        )
            .prop_map(|(start, suffix)| {
                let mut end = start.clone();
                end.extend_from_slice(&suffix);
                ShardSpec::with_range(start, end)
            })
    }

    /// Generate a ShardSpec covering all four boundedness variants.
    fn arb_shard_spec() -> impl Strategy<Value = ShardSpec> {
        proptest::prop_oneof![
            4 => arb_bounded_shard_spec(),
            1 => proptest::collection::vec(any::<u8>(), 1..64)
                .prop_map(|end| ShardSpec::with_range(vec![], end)),
            1 => proptest::collection::vec(any::<u8>(), 1..64)
                .prop_map(|start| ShardSpec::with_range(start, vec![])),
            1 => Just(ShardSpec::unbounded()),
        ]
    }

    /// Generate a valid parent + 2–4 contiguous children via suffix
    /// accumulation (same proven pattern as `arb_bounded_shard_spec`).
    fn arb_valid_n_way_split() -> impl Strategy<Value = (ShardSpec, Vec<ShardSpec>)> {
        (
            proptest::collection::vec(any::<u8>(), 1..16),
            proptest::collection::vec(proptest::collection::vec(any::<u8>(), 1..8), 2..=4),
        )
            .prop_map(|(base, suffixes)| {
                let mut boundaries = vec![base.clone()];
                let mut current = base;
                for suffix in &suffixes {
                    current.extend_from_slice(suffix);
                    boundaries.push(current.clone());
                }
                let parent = ShardSpec::with_range(
                    boundaries[0].clone(),
                    boundaries.last().unwrap().clone(),
                );
                let children: Vec<ShardSpec> = boundaries
                    .windows(2)
                    .map(|w| ShardSpec::with_range(w[0].clone(), w[1].clone()))
                    .collect();
                (parent, children)
            })
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        // -- Stability: same input → same digest ----------------------------

        #[test]
        fn shard_spec_canonical_bytes_stable(
            start in proptest::collection::vec(any::<u8>(), 1..64),
            suffix in proptest::collection::vec(any::<u8>(), 1..8),
        ) {
            let mut end = start.clone();
            end.extend_from_slice(&suffix);
            let spec = ShardSpec::with_range(start, end);
            prop_assert_eq!(canonical_digest(&spec), canonical_digest(&spec));
        }

        // -- Collision-freedom: distinct specs → distinct digests -----------

        #[test]
        fn shard_spec_canonical_bytes_collision_free(
            a in arb_bounded_shard_spec(),
            b in arb_bounded_shard_spec(),
        ) {
            prop_assume!(a != b);
            prop_assert_ne!(canonical_digest(&a), canonical_digest(&b));
        }

        // -- contains_key equivalence with manual check ---------------------

        #[test]
        fn contains_key_matches_manual_check(
            spec in arb_shard_spec(),
            key in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let above_start = spec.is_start_unbounded()
                || key.as_slice() >= spec.key_range_start.as_ref();
            let below_end = spec.is_end_unbounded()
                || key.as_slice() < spec.key_range_end.as_ref();
            let expected = above_start && below_end;
            prop_assert_eq!(spec.contains_key(&key), expected);
        }

        // -- split coverage: key in parent iff in exactly one child ----------

        #[test]
        fn split_coverage_roundtrip(
            (parent, children) in arb_valid_n_way_split(),
            key in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            prop_assert!(validate_split_coverage(&parent, &children).is_ok());
            let parent_has = parent.contains_key(&key);
            let child_count = children.iter().filter(|c| c.contains_key(&key)).count();
            if parent_has {
                prop_assert_eq!(child_count, 1,
                    "key in parent but in {} children", child_count);
            } else {
                prop_assert_eq!(child_count, 0,
                    "key outside parent but in {} children", child_count);
            }
        }

        // -- residual split: old_parent == new_parent ∪ residual -------------

        #[test]
        fn residual_split_roundtrip(
            start in proptest::collection::vec(any::<u8>(), 1..16),
            mid_suffix in proptest::collection::vec(any::<u8>(), 1..8),
            end_suffix in proptest::collection::vec(any::<u8>(), 1..8),
            key in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut mid = start.clone();
            mid.extend_from_slice(&mid_suffix);
            let mut end = mid.clone();
            end.extend_from_slice(&end_suffix);

            let old_parent = ShardSpec::with_range(start.clone(), end.clone());
            let new_parent = ShardSpec::with_range(start, mid.clone());
            let residual = ShardSpec::with_range(mid, end);

            prop_assert!(validate_residual_split(&old_parent, &new_parent, &residual).is_ok());

            let in_old = old_parent.contains_key(&key);
            let in_new = new_parent.contains_key(&key);
            let in_res = residual.contains_key(&key);
            prop_assert_eq!(in_old, in_new || in_res);
            prop_assert!(!(in_new && in_res), "key in both new_parent and residual");
        }
    }
}
