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

use std::fmt;

use blake3::Hasher;

use crate::identity::CanonicalBytes;

/// Maximum size of a shard-spec key (start or end) in bytes (4 KiB).
///
/// Same ceiling as [`super::cursor::MAX_KEY_SIZE`] — both operate in the
/// same lexicographic keyspace. Defined per-module to avoid cross-dependency
/// on an unrelated constant.
pub const MAX_KEY_SIZE: usize = 4_096;

/// Maximum size of shard-spec opaque metadata in bytes (64 KiB).
///
/// Metadata is stored verbatim by the coordinator. Unbounded metadata
/// would bloat coordination state.
pub const MAX_METADATA_SIZE: usize = 65_536;

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
///
/// ## Encapsulation
///
/// Fields are private — constructors enforce the well-formed range
/// invariant (`start < end`), and public accessors return borrowed
/// views.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShardSpec {
    /// Inclusive lower bound of the key range.
    ///
    /// Empty (`[]`) means "start of keyspace."
    key_range_start: Box<[u8]>,

    /// Exclusive upper bound of the key range.
    ///
    /// Empty (`[]`) means "end of keyspace" (unbounded).
    key_range_end: Box<[u8]>,

    /// Connector-opaque metadata.
    ///
    /// Carries information the worker needs but the coordinator doesn't
    /// interpret: repository identifiers, authentication scopes, bucket
    /// names, connector-specific configuration, etc.
    ///
    /// Participates in payload hashing for idempotency but is not used
    /// for any coordination decision.
    metadata: Box<[u8]>,
}

impl ShardSpec {
    /// Unbounded shard covering the entire keyspace, no metadata.
    #[must_use = "creates a shard spec that should be stored or used"]
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
    #[must_use = "creates a shard spec that should be stored or used"]
    pub fn with_range(start: Vec<u8>, end: Vec<u8>) -> Self {
        Self::with_range_and_metadata(start, end, vec![])
    }

    /// Construct a shard spec with key range bounds and metadata.
    ///
    /// # Panics
    ///
    /// Panics if `start` and `end` are both non-empty and `start >= end`.
    #[must_use = "creates a shard spec that should be stored or used"]
    pub fn with_range_and_metadata(start: Vec<u8>, end: Vec<u8>, metadata: Vec<u8>) -> Self {
        assert!(
            start.len() <= MAX_KEY_SIZE,
            "ShardSpec: key too large ({} bytes, max {MAX_KEY_SIZE})",
            start.len(),
        );
        assert!(
            end.len() <= MAX_KEY_SIZE,
            "ShardSpec: key too large ({} bytes, max {MAX_KEY_SIZE})",
            end.len(),
        );
        assert!(
            metadata.len() <= MAX_METADATA_SIZE,
            "ShardSpec: metadata too large ({} bytes, max {MAX_METADATA_SIZE})",
            metadata.len(),
        );
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

    /// Fallible constructor: returns `Err` if range is inverted or keys
    /// exceed [`MAX_KEY_SIZE`].
    ///
    /// # Errors
    ///
    /// - [`ShardSpecInputError::KeyTooLarge`] — `start` or `end` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
    /// - [`ShardSpecInputError::InvertedRange`] — both `start` and `end`
    ///   are non-empty and `start >= end`.
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_range(start: Vec<u8>, end: Vec<u8>) -> Result<Self, ShardSpecInputError> {
        Self::try_with_range_and_metadata(start, end, vec![])
    }

    /// Fallible constructor: returns `Err` if range is inverted, keys
    /// exceed [`MAX_KEY_SIZE`], or metadata exceeds [`MAX_METADATA_SIZE`].
    ///
    /// # Errors
    ///
    /// - [`ShardSpecInputError::KeyTooLarge`] — `start` or `end` exceeds
    ///   [`MAX_KEY_SIZE`] bytes.
    /// - [`ShardSpecInputError::InvertedRange`] — both `start` and `end`
    ///   are non-empty and `start >= end`.
    /// - [`ShardSpecInputError::MetadataTooLarge`] — `metadata` exceeds
    ///   [`MAX_METADATA_SIZE`] bytes.
    #[must_use = "returns a Result that must be checked for validation errors"]
    pub fn try_with_range_and_metadata(
        start: Vec<u8>,
        end: Vec<u8>,
        metadata: Vec<u8>,
    ) -> Result<Self, ShardSpecInputError> {
        if start.len() > MAX_KEY_SIZE {
            return Err(ShardSpecInputError::KeyTooLarge {
                size: start.len(),
                max: MAX_KEY_SIZE,
            });
        }
        if end.len() > MAX_KEY_SIZE {
            return Err(ShardSpecInputError::KeyTooLarge {
                size: end.len(),
                max: MAX_KEY_SIZE,
            });
        }
        if metadata.len() > MAX_METADATA_SIZE {
            return Err(ShardSpecInputError::MetadataTooLarge {
                size: metadata.len(),
                max: MAX_METADATA_SIZE,
            });
        }
        if !start.is_empty() && !end.is_empty() && start.as_slice() >= end.as_slice() {
            return Err(ShardSpecInputError::InvertedRange {
                start_len: start.len(),
                end_len: end.len(),
            });
        }
        Ok(Self {
            key_range_start: start.into_boxed_slice(),
            key_range_end: end.into_boxed_slice(),
            metadata: metadata.into_boxed_slice(),
        })
    }

    /// Construct a `ShardSpec` from pre-built parts, bypassing validation.
    ///
    /// Only available in test builds — allows constructing intentionally
    /// invalid specs for testing validation logic.
    #[cfg(test)]
    pub(crate) fn from_raw_parts(
        key_range_start: Box<[u8]>,
        key_range_end: Box<[u8]>,
        metadata: Box<[u8]>,
    ) -> Self {
        Self {
            key_range_start,
            key_range_end,
            metadata,
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
    #[must_use = "returns a bool that should be checked"]
    pub fn is_unbounded(&self) -> bool {
        self.is_start_unbounded() && self.is_end_unbounded()
    }

    /// Inclusive lower bound of the key range (borrowed).
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn key_range_start(&self) -> &[u8] {
        &self.key_range_start
    }

    /// Exclusive upper bound of the key range (borrowed).
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn key_range_end(&self) -> &[u8] {
        &self.key_range_end
    }

    /// Connector-opaque metadata (borrowed).
    #[inline]
    #[must_use = "returns a reference that should be used"]
    pub fn metadata(&self) -> &[u8] {
        &self.metadata
    }

    /// Check whether a key falls within this shard's key range.
    ///
    /// Returns `true` if `key ∈ [start, end)` (lexicographic byte order).
    ///
    /// An empty key `[]` is at the very start of the keyspace — less
    /// than any non-empty key.
    #[inline]
    #[must_use = "returns a bool that should be checked"]
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
// ShardSpecInputError
// ============================================================================

/// Error returned by fallible [`ShardSpec`] constructors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShardSpecInputError {
    /// The key range is inverted: `start >= end` when both are non-empty.
    InvertedRange {
        /// Length of the start key in bytes.
        start_len: usize,
        /// Length of the end key in bytes.
        end_len: usize,
    },

    /// A key (start or end) exceeds [`MAX_KEY_SIZE`].
    KeyTooLarge {
        /// Actual size of the key in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_KEY_SIZE`]).
        max: usize,
    },

    /// The metadata exceeds [`MAX_METADATA_SIZE`].
    MetadataTooLarge {
        /// Actual size of the metadata in bytes.
        size: usize,
        /// Maximum allowed size ([`MAX_METADATA_SIZE`]).
        max: usize,
    },
}

impl fmt::Display for ShardSpecInputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvertedRange { start_len, end_len } => write!(
                f,
                "ShardSpec: start must be strictly less than end \
                 (start: {start_len} bytes, end: {end_len} bytes)"
            ),
            Self::KeyTooLarge { size, max } => {
                write!(f, "ShardSpec: key too large ({size} bytes, max {max})")
            }
            Self::MetadataTooLarge { size, max } => {
                write!(f, "ShardSpec: metadata too large ({size} bytes, max {max})")
            }
        }
    }
}

impl std::error::Error for ShardSpecInputError {}

// ============================================================================
// Split Validation
// ============================================================================

/// Whether a shard limit breach is per-tenant or global.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShardLimitScope {
    /// Per-tenant shard count limit.
    PerTenant,
    /// Global (all tenants) shard count limit.
    Global,
}

impl fmt::Display for ShardLimitScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PerTenant => write!(f, "per-tenant"),
            Self::Global => write!(f, "global"),
        }
    }
}

/// Errors produced during split validation — by
/// [`validate_split_coverage`], [`validate_residual_split`], and the
/// coordinator's cursor-bounds check — when proposed child shards do
/// not form a valid partition of the parent's key range.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Boundary mismatch (gap or overlap) between adjacent children.
    BoundaryMismatch {
        /// Index in the caller's input order, not the internal sorted order.
        child_index: usize,
        /// Index in the caller's input order, not the internal sorted order.
        next_child_index: usize,
        child_end: Box<[u8]>,
        next_child_start: Box<[u8]>,
    },
    /// Child has inverted key range (start >= end).
    InvertedChild {
        /// Index in the caller's input order, not the internal sorted order.
        child_index: usize,
    },

    /// A non-last child has an unbounded end, causing it to overlap with
    /// subsequent children.
    OverlappingChild {
        child_index: usize,
        next_child_index: usize,
    },

    /// The parent's current cursor falls outside the proposed new (shrunk)
    /// parent spec after a residual split. Accepting this split would
    /// strand the cursor outside the parent's key range, violating
    /// cursor bounds (D2.4).
    ParentCursorOutOfBounds {
        cursor: Box<[u8]>,
        new_parent_start: Box<[u8]>,
        new_parent_end: Box<[u8]>,
    },

    /// The split would exceed the parent's spawn capacity
    /// ([`MAX_SPAWNED_PER_SHARD`](super::split::MAX_SPAWNED_PER_SHARD)).
    ///
    /// Production backends would surface this as a constraint violation;
    /// the in-memory reference spec matches by returning this error
    /// instead of panicking at `assert_invariants`.
    SpawnLimitExceeded {
        current: usize,
        additional: usize,
        max: usize,
    },

    /// The split would exceed a shard count limit (per-tenant or global).
    ///
    /// Prevents unbounded resource growth from split-flooding (CWE-400).
    ShardLimitExceeded {
        current: usize,
        additional: usize,
        max: usize,
        scope: ShardLimitScope,
    },

    /// A derived shard ID collided with an existing shard in the map.
    ///
    /// With BLAKE3 + domain separation this is astronomically unlikely,
    /// but returning an error is safer than panicking on external input.
    DerivedIdCollision {
        derived_id: crate::identity::ShardId,
    },
}

impl fmt::Display for SplitValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoChildren => write!(f, "split requires at least 2 children"),
            Self::SingleChild => write!(f, "a single child is not a split"),
            Self::StartMismatch {
                parent_start,
                first_child_start,
            } => write!(
                f,
                "first child start ({} bytes) does not match parent start ({} bytes)",
                first_child_start.len(),
                parent_start.len(),
            ),
            Self::EndMismatch {
                parent_end,
                last_child_end,
            } => write!(
                f,
                "last child end ({} bytes) does not match parent end ({} bytes)",
                last_child_end.len(),
                parent_end.len(),
            ),
            Self::BoundaryMismatch {
                child_index,
                next_child_index,
                child_end,
                next_child_start,
            } => write!(
                f,
                "boundary mismatch between child {child_index} end ({} bytes) \
                 and child {next_child_index} start ({} bytes)",
                child_end.len(),
                next_child_start.len(),
            ),
            Self::InvertedChild { child_index } => {
                write!(
                    f,
                    "child {child_index} has inverted key range (start >= end)"
                )
            }
            Self::OverlappingChild {
                child_index,
                next_child_index,
            } => write!(
                f,
                "child {child_index} has unbounded end, overlapping with child {next_child_index}"
            ),
            Self::ParentCursorOutOfBounds {
                cursor,
                new_parent_start,
                new_parent_end,
            } => write!(
                f,
                "parent cursor ({} bytes) falls outside new parent range \
                 (start: {} bytes, end: {} bytes)",
                cursor.len(),
                new_parent_start.len(),
                new_parent_end.len(),
            ),
            Self::SpawnLimitExceeded {
                current,
                additional,
                max,
            } => write!(
                f,
                "spawn limit exceeded: {current} existing + {additional} new > {max} max",
            ),
            Self::ShardLimitExceeded {
                current,
                additional,
                max,
                scope,
            } => write!(
                f,
                "shard limit exceeded ({scope}): {current} existing + {additional} new > {max} max",
            ),
            Self::DerivedIdCollision { derived_id } => {
                write!(f, "derived shard id collision: {derived_id:?}")
            }
        }
    }
}

impl std::error::Error for SplitValidationError {}

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
/// Error indices (`child_index`) refer to the caller's input order, not
/// the internal sorted order.
///
/// # Errors
///
/// - [`SplitValidationError::NoChildren`] — empty children slice.
/// - [`SplitValidationError::SingleChild`] — only one child provided.
/// - [`SplitValidationError::StartMismatch`] — first child's start ≠
///   parent's start.
/// - [`SplitValidationError::EndMismatch`] — last child's end ≠ parent's
///   end.
/// - [`SplitValidationError::BoundaryMismatch`] — gap or overlap between
///   adjacent children.
/// - [`SplitValidationError::OverlappingChild`] — a non-last child has
///   an unbounded end.
/// - [`SplitValidationError::InvertedChild`] — a child has `start >= end`.
///
/// Reference: CockroachDB range split/merge validation; Spanner tablet
/// split with key-range continuity check.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn validate_split_coverage(
    parent: &ShardSpec,
    children: &[&ShardSpec],
) -> Result<(), SplitValidationError> {
    if children.is_empty() {
        return Err(SplitValidationError::NoChildren);
    }

    if children.len() == 1 {
        return Err(SplitValidationError::SingleChild);
    }

    // Pair each child with its original index, then sort by start key.
    // This lets us report the caller's input indices in errors.
    let mut indexed: Vec<(usize, &ShardSpec)> = children.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.key_range_start.cmp(&b.1.key_range_start));

    // First child start == parent start.
    if indexed[0].1.key_range_start != parent.key_range_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent.key_range_start.clone(),
            first_child_start: indexed[0].1.key_range_start.clone(),
        });
    }

    // Last child end == parent end.
    let last = indexed[indexed.len() - 1];
    if last.1.key_range_end != parent.key_range_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent.key_range_end.clone(),
            last_child_end: last.1.key_range_end.clone(),
        });
    }

    // Contiguity: each child's end == next child's start.
    // Also reject empty internal boundaries: an empty `key_range_end` means
    // "extends to end of keyspace" which is only valid for the last child.
    // Empty internal boundaries indicate overlapping children (e.g. two
    // fully-unbounded children `[[], [])` pass the equality check but
    // cover the same keyspace).
    for i in 0..indexed.len() - 1 {
        if indexed[i].1.key_range_end != indexed[i + 1].1.key_range_start {
            return Err(SplitValidationError::BoundaryMismatch {
                child_index: indexed[i].0,
                next_child_index: indexed[i + 1].0,
                child_end: indexed[i].1.key_range_end.clone(),
                next_child_start: indexed[i + 1].1.key_range_start.clone(),
            });
        }
        if indexed[i].1.key_range_end.is_empty() {
            return Err(SplitValidationError::OverlappingChild {
                child_index: indexed[i].0,
                next_child_index: indexed[i + 1].0,
            });
        }
    }

    // Each child individually well-formed.
    for &(orig_idx, child) in &indexed {
        if !child.key_range_start.is_empty()
            && !child.key_range_end.is_empty()
            && child.key_range_start >= child.key_range_end
        {
            return Err(SplitValidationError::InvertedChild {
                child_index: orig_idx,
            });
        }
    }

    // Defense-in-depth: child keys derive from parent range boundaries.
    // If parent was validated, children cannot exceed MAX_KEY_SIZE.
    // This assert catches logic bugs where specs are constructed without validation.
    for &(_, child) in &indexed {
        assert!(
            child.key_range_start().len() <= MAX_KEY_SIZE,
            "child start key exceeds MAX_KEY_SIZE"
        );
        assert!(
            child.key_range_end().len() <= MAX_KEY_SIZE || child.key_range_end().is_empty(),
            "child end key exceeds MAX_KEY_SIZE"
        );
    }

    debug_assert!(indexed.first().unwrap().1.key_range_start == parent.key_range_start);
    debug_assert!(indexed.last().unwrap().1.key_range_end == parent.key_range_end);

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
/// Enforces role assignment before delegating to `validate_split_coverage`:
/// `new_parent` must retain the left portion (start matches old parent)
/// and `residual` must cover the right portion (end matches old parent).
/// This prevents callers from accidentally swapping the two arguments.
///
/// # Errors
///
/// - [`SplitValidationError::StartMismatch`] — `new_parent`'s start ≠
///   `old_parent`'s start (roles may be swapped).
/// - [`SplitValidationError::EndMismatch`] — `residual`'s end ≠
///   `old_parent`'s end.
/// - Any error from [`validate_split_coverage`] when the two children
///   don't form a valid partition.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn validate_residual_split(
    old_parent: &ShardSpec,
    new_parent: &ShardSpec,
    residual: &ShardSpec,
) -> Result<(), SplitValidationError> {
    // The parent must keep the left (lower) portion of the range.
    if new_parent.key_range_start != old_parent.key_range_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: old_parent.key_range_start.clone(),
            first_child_start: new_parent.key_range_start.clone(),
        });
    }
    // The residual must cover the right (upper) portion.
    if residual.key_range_end != old_parent.key_range_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: old_parent.key_range_end.clone(),
            last_child_end: residual.key_range_end.clone(),
        });
    }
    validate_split_coverage(old_parent, &[new_parent, residual])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;
    use crate::test_util::{
        arb_bounded_shard_spec, arb_bounded_shard_spec_with_metadata, arb_shard_spec,
        canonical_digest,
    };
    use proptest::prelude::*;

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

    #[rstest]
    #[case::unbounded(ShardSpec::unbounded(), b"" as &[u8], b"" as &[u8], true, true, true)]
    #[case::bounded_a_m(ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()), b"a", b"m", false, false, false)]
    #[case::start_unbounded(ShardSpec::with_range(vec![], b"m".to_vec()), b"", b"m", true, false, false)]
    #[case::end_unbounded(ShardSpec::with_range(b"m".to_vec(), vec![]), b"m", b"", false, true, false)]
    fn shard_spec_construction_truth_table(
        #[case] spec: ShardSpec,
        #[case] exp_start: &[u8],
        #[case] exp_end: &[u8],
        #[case] start_ub: bool,
        #[case] end_ub: bool,
        #[case] full_ub: bool,
    ) {
        assert_eq!(spec.key_range_start(), exp_start);
        assert_eq!(spec.key_range_end(), exp_end);
        assert_eq!(spec.is_start_unbounded(), start_ub);
        assert_eq!(spec.is_end_unbounded(), end_ub);
        assert_eq!(spec.is_unbounded(), full_ub);
    }

    #[test]
    fn shard_spec_unbounded_has_empty_metadata() {
        assert!(ShardSpec::unbounded().metadata().is_empty());
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

    #[test]
    #[should_panic(expected = "key too large")]
    fn with_range_panics_on_oversized_start_key() {
        let _ = ShardSpec::with_range(vec![0x01; MAX_KEY_SIZE + 1], vec![]);
    }

    #[test]
    #[should_panic(expected = "key too large")]
    fn with_range_panics_on_oversized_end_key() {
        let _ = ShardSpec::with_range(vec![], vec![0xFF; MAX_KEY_SIZE + 1]);
    }

    #[test]
    #[should_panic(expected = "metadata too large")]
    fn with_range_and_metadata_panics_on_oversized_metadata() {
        let _ = ShardSpec::with_range_and_metadata(
            b"a".to_vec(),
            b"z".to_vec(),
            vec![0xAA; MAX_METADATA_SIZE + 1],
        );
    }

    // -------------------------------------------------------------------
    // Fallible constructors
    // -------------------------------------------------------------------

    #[test]
    fn try_with_range_inverted() {
        let err = ShardSpec::try_with_range(b"z".to_vec(), b"a".to_vec()).unwrap_err();
        assert_eq!(
            err,
            ShardSpecInputError::InvertedRange {
                start_len: 1,
                end_len: 1,
            }
        );
    }

    #[test]
    fn try_with_range_equal_bounds() {
        let err = ShardSpec::try_with_range(b"a".to_vec(), b"a".to_vec()).unwrap_err();
        assert!(matches!(err, ShardSpecInputError::InvertedRange { .. }));
    }

    #[test]
    fn try_with_range_and_metadata_valid() {
        let spec =
            ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), b"meta".to_vec())
                .unwrap();
        assert_eq!(spec.key_range_start(), b"a");
        assert_eq!(spec.key_range_end(), b"z");
        assert_eq!(spec.metadata(), b"meta");
    }

    #[test]
    fn shard_spec_input_error_display() {
        let err = ShardSpecInputError::InvertedRange {
            start_len: 3,
            end_len: 1,
        };
        let msg = err.to_string();
        assert!(msg.contains("start must be strictly less than end"));
        assert!(msg.contains("3 bytes"));
        assert!(msg.contains("1 bytes"));
    }

    // -------------------------------------------------------------------
    // Size-limit validation
    // -------------------------------------------------------------------

    #[test]
    fn try_with_range_start_key_at_max() {
        let start = vec![0x01; MAX_KEY_SIZE];
        // Use an unbounded end so it doesn't also exceed MAX_KEY_SIZE.
        let spec = ShardSpec::try_with_range(start, vec![]).unwrap();
        assert_eq!(spec.key_range_start().len(), MAX_KEY_SIZE);
    }

    #[test]
    fn try_with_range_start_key_over_max() {
        let start = vec![0x01; MAX_KEY_SIZE + 1];
        let mut end = start.clone();
        end.push(0xFF);
        let err = ShardSpec::try_with_range(start, end).unwrap_err();
        assert_eq!(
            err,
            ShardSpecInputError::KeyTooLarge {
                size: MAX_KEY_SIZE + 1,
                max: MAX_KEY_SIZE,
            }
        );
    }

    #[test]
    fn try_with_range_end_key_over_max() {
        let end = vec![0xFF; MAX_KEY_SIZE + 1];
        let err = ShardSpec::try_with_range(b"a".to_vec(), end).unwrap_err();
        assert!(matches!(err, ShardSpecInputError::KeyTooLarge { .. }));
    }

    #[test]
    fn try_with_range_and_metadata_at_max() {
        let meta = vec![0xAA; MAX_METADATA_SIZE];
        let spec =
            ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), meta).unwrap();
        assert_eq!(spec.metadata().len(), MAX_METADATA_SIZE);
    }

    #[test]
    fn try_with_range_and_metadata_over_max() {
        let meta = vec![0xAA; MAX_METADATA_SIZE + 1];
        let err =
            ShardSpec::try_with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), meta).unwrap_err();
        assert_eq!(
            err,
            ShardSpecInputError::MetadataTooLarge {
                size: MAX_METADATA_SIZE + 1,
                max: MAX_METADATA_SIZE,
            }
        );
    }

    #[test]
    fn shard_spec_input_error_display_key_too_large() {
        let err = ShardSpecInputError::KeyTooLarge {
            size: 5000,
            max: 4096,
        };
        let msg = err.to_string();
        assert!(msg.contains("5000"));
        assert!(msg.contains("4096"));
    }

    #[test]
    fn shard_spec_input_error_display_metadata_too_large() {
        let err = ShardSpecInputError::MetadataTooLarge {
            size: 70000,
            max: 65536,
        };
        let msg = err.to_string();
        assert!(msg.contains("70000"));
        assert!(msg.contains("65536"));
    }

    // -------------------------------------------------------------------
    // Split validation
    // -------------------------------------------------------------------

    #[test]
    fn split_valid_two_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let c2 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
    }

    #[test]
    fn split_valid_three_way() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
        let c2 = ShardSpec::with_range(b"g".to_vec(), b"p".to_vec());
        let c3 = ShardSpec::with_range(b"p".to_vec(), b"z".to_vec());
        assert!(validate_split_coverage(&parent, &[&c1, &c2, &c3]).is_ok());
    }

    #[test]
    fn split_valid_unbounded_parent() {
        let parent = ShardSpec::unbounded();
        let c1 = ShardSpec::with_range(vec![], b"m".to_vec());
        let c2 = ShardSpec::with_range(b"m".to_vec(), vec![]);
        assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
    }

    #[test]
    fn split_no_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let empty: &[&ShardSpec] = &[];
        let result = validate_split_coverage(&parent, empty);
        assert!(matches!(result, Err(SplitValidationError::NoChildren)));
    }

    #[test]
    fn split_single_child() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(&parent, &[&c1]);
        assert!(matches!(result, Err(SplitValidationError::SingleChild)));
    }

    #[test]
    fn split_start_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"b".to_vec(), b"m".to_vec());
        let c2 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(&parent, &[&c1, &c2]);
        assert!(matches!(
            result,
            Err(SplitValidationError::StartMismatch { .. })
        ));
    }

    #[test]
    fn split_end_mismatch() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let c2 = ShardSpec::with_range(b"m".to_vec(), b"y".to_vec());
        let result = validate_split_coverage(&parent, &[&c1, &c2]);
        assert!(matches!(
            result,
            Err(SplitValidationError::EndMismatch { .. })
        ));
    }

    #[test]
    fn split_boundary_mismatch_between_children() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
        let c2 = ShardSpec::with_range(b"h".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(&parent, &[&c1, &c2]);
        assert!(matches!(
            result,
            Err(SplitValidationError::BoundaryMismatch { .. })
        ));
    }

    #[test]
    fn split_children_out_of_order_still_valid() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // Provide children in reverse order; sorting makes it pass.
        let c1 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let c2 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        assert!(validate_split_coverage(&parent, &[&c1, &c2]).is_ok());
    }

    #[test]
    fn split_inverted_child() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // A zero-width child [m, m) passes contiguity but fails
        // the well-formedness check (start >= end).
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let c2 =
            ShardSpec::from_raw_parts(b"m".as_slice().into(), b"m".as_slice().into(), Box::new([]));
        let c3 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let result = validate_split_coverage(&parent, &[&c1, &c2, &c3]);
        assert!(matches!(
            result,
            Err(SplitValidationError::InvertedChild { .. })
        ));
    }

    #[test]
    fn split_boundary_mismatch_reports_original_indices() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // Pass children in reverse order: index 0 is [m,z), index 1 is [a,g).
        // After sorting: [a,g) then [m,z) — gap between them.
        // The gap is between sorted[0]=original[1] and sorted[1]=original[0].
        let c0 = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let c1 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
        let result = validate_split_coverage(&parent, &[&c0, &c1]);
        match result {
            Err(SplitValidationError::BoundaryMismatch {
                child_index,
                next_child_index,
                ..
            }) => {
                // Original index of [a,g) is 1, original index of [m,z) is 0.
                assert_eq!(child_index, 1, "gap child should be original index 1");
                assert_eq!(next_child_index, 0, "next child should be original index 0");
            }
            other => panic!("expected BoundaryMismatch, got {other:?}"),
        }
    }

    #[test]
    fn split_inverted_child_reports_original_index() {
        let parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // Degenerate [g,g) at original index 0, normal children at 1 and 2.
        // Stable sort on start key produces:
        //   sorted[0] = (orig 2, [a,g))
        //   sorted[1] = (orig 0, [g,g))   ← degenerate, at sorted position 1
        //   sorted[2] = (orig 1, [g,z))
        // The inverted child is at sorted position 1 but original index 0.
        let c0 =
            ShardSpec::from_raw_parts(b"g".as_slice().into(), b"g".as_slice().into(), Box::new([]));
        let c1 = ShardSpec::with_range(b"g".to_vec(), b"z".to_vec());
        let c2 = ShardSpec::with_range(b"a".to_vec(), b"g".to_vec());
        let result = validate_split_coverage(&parent, &[&c0, &c1, &c2]);
        match result {
            Err(SplitValidationError::InvertedChild { child_index }) => {
                assert_eq!(child_index, 0, "inverted child should be original index 0");
            }
            other => panic!("expected InvertedChild, got {other:?}"),
        }
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

    #[test]
    fn residual_split_swapped_roles_rejected() {
        let old_parent = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        // Swap: new_parent gets upper range, residual gets lower.
        let new_parent = ShardSpec::with_range(b"m".to_vec(), b"z".to_vec());
        let residual = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let result = validate_residual_split(&old_parent, &new_parent, &residual);
        assert!(
            matches!(result, Err(SplitValidationError::StartMismatch { .. })),
            "swapped residual split should be rejected: {result:?}"
        );
    }

    #[test]
    fn split_two_unbounded_children_rejected() {
        let parent = ShardSpec::unbounded();
        let c1 = ShardSpec::unbounded();
        let c2 = ShardSpec::unbounded();
        let result = validate_split_coverage(&parent, &[&c1, &c2]);
        assert!(
            matches!(result, Err(SplitValidationError::OverlappingChild { .. })),
            "two fully-unbounded children should be rejected: {result:?}"
        );
    }

    #[test]
    fn split_non_last_child_unbounded_end_rejected() {
        let parent = ShardSpec::unbounded();
        // First child covers everything, second is also unbounded.
        let c1 = ShardSpec::with_range(vec![], vec![]);
        let c2 = ShardSpec::with_range(vec![], vec![]);
        let result = validate_split_coverage(&parent, &[&c1, &c2]);
        assert!(result.is_err());
    }

    // -------------------------------------------------------------------
    // SplitValidationError Display
    // -------------------------------------------------------------------

    #[test]
    fn split_validation_error_display() {
        let err = SplitValidationError::BoundaryMismatch {
            child_index: 0,
            next_child_index: 1,
            child_end: b"g".as_slice().into(),
            next_child_start: b"h".as_slice().into(),
        };
        let msg = err.to_string();
        assert!(msg.contains("boundary mismatch"));
        assert!(msg.contains("child 0"));
        assert!(msg.contains("child 1"));
    }

    // -------------------------------------------------------------------
    // Metadata participates in canonical hashing
    // -------------------------------------------------------------------

    #[test]
    fn with_range_and_metadata_stores_and_hashes_metadata() {
        let spec_no_meta = ShardSpec::with_range_and_metadata(b"a".to_vec(), b"z".to_vec(), vec![]);
        let spec_with_meta = ShardSpec::with_range_and_metadata(
            b"a".to_vec(),
            b"z".to_vec(),
            b"repo:org/foo".to_vec(),
        );

        // Metadata is stored.
        assert_eq!(spec_with_meta.metadata(), b"repo:org/foo");

        // Same range, different metadata → different canonical digest.
        assert_ne!(
            canonical_digest(&spec_no_meta),
            canonical_digest(&spec_with_meta),
        );
    }

    // -------------------------------------------------------------------
    // Property-based tests
    // -------------------------------------------------------------------

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
                || key.as_slice() >= spec.key_range_start();
            let below_end = spec.is_end_unbounded()
                || key.as_slice() < spec.key_range_end();
            let expected = above_start && below_end;
            prop_assert_eq!(spec.contains_key(&key), expected);
        }

        // -- split coverage: key in parent iff in exactly one child ----------

        #[test]
        fn split_coverage_roundtrip(
            (parent, children) in arb_valid_n_way_split(),
            key in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let refs: Vec<&ShardSpec> = children.iter().collect();
            prop_assert!(validate_split_coverage(&parent, &refs).is_ok());
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

        // -- Constructor equivalence: try_with_range ≡ with_range ------------

        #[test]
        fn try_with_range_equivalent_to_with_range(
            spec in arb_shard_spec(),
        ) {
            let start = spec.key_range_start().to_vec();
            let end = spec.key_range_end().to_vec();
            let expected = ShardSpec::with_range(start.clone(), end.clone());
            let result = ShardSpec::try_with_range(start, end);
            prop_assert_eq!(result, Ok(expected));
        }

        // -- Constructor equivalence: try_with_range_and_metadata -------------

        #[test]
        fn try_with_range_and_metadata_equivalent(
            start in proptest::collection::vec(any::<u8>(), 1..64),
            suffix in proptest::collection::vec(any::<u8>(), 1..8),
            metadata in proptest::collection::vec(any::<u8>(), 0..32),
        ) {
            let mut end = start.clone();
            end.extend_from_slice(&suffix);
            let try_result = ShardSpec::try_with_range_and_metadata(
                start.clone(), end.clone(), metadata.clone(),
            );
            let direct = ShardSpec::with_range_and_metadata(start, end, metadata);
            prop_assert_eq!(try_result, Ok(direct));
        }

        // -- Metadata distinction: different metadata → different digest -----

        #[test]
        fn metadata_changes_canonical_digest(
            spec in arb_bounded_shard_spec_with_metadata(),
        ) {
            let no_meta = ShardSpec::with_range(
                spec.key_range_start().to_vec(),
                spec.key_range_end().to_vec(),
            );
            // If the spec has non-empty metadata, digests must differ.
            if !spec.metadata().is_empty() {
                prop_assert_ne!(
                    canonical_digest(&spec),
                    canonical_digest(&no_meta),
                    "non-empty metadata must change the canonical digest"
                );
            }
        }
    }
}
