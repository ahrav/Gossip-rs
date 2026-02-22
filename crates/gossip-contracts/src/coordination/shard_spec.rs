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

/// Maximum size of shard-spec opaque metadata in bytes (16 KiB).
///
/// Ceiling for opaque connector metadata. Observed metadata:
/// TruffleHog (200-500 B), JWT (2-4 KB), config drift (~8 KB).
/// 16 KiB provides 2x headroom over worst observed.
pub const MAX_METADATA_SIZE: usize = 16_384;

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
    /// - `start` exceeds [`MAX_KEY_SIZE`] bytes.
    /// - `end` exceeds [`MAX_KEY_SIZE`] bytes.
    /// - `start` and `end` are both non-empty and `start >= end`.
    #[must_use = "creates a shard spec that should be stored or used"]
    pub fn with_range(start: Vec<u8>, end: Vec<u8>) -> Self {
        Self::with_range_and_metadata(start, end, vec![])
    }

    /// Construct a shard spec with key range bounds and metadata.
    ///
    /// # Panics
    ///
    /// - `start` exceeds [`MAX_KEY_SIZE`] bytes.
    /// - `end` exceeds [`MAX_KEY_SIZE`] bytes.
    /// - `metadata` exceeds [`MAX_METADATA_SIZE`] bytes.
    /// - `start` and `end` are both non-empty and `start >= end`.
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
    /// Used by [`PooledShardSpec::to_spec`] to reconstruct an owned spec
    /// from slab-backed bytes (which were originally validated on creation).
    /// Also available in test builds for constructing intentionally invalid
    /// specs.
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
/// key_range_start : 4-byte LE length prefix + bytes
/// key_range_end   : 4-byte LE length prefix + bytes
/// metadata        : 4-byte LE length prefix + bytes
/// ```
///
/// All three fields are variable-length, so all use the
/// [`CanonicalBytes for [u8]`](crate::identity::CanonicalBytes) 4-byte
/// little-endian length prefix.
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

    debug_assert!(indexed.first().unwrap().1.key_range_start() == parent_start);
    debug_assert!(indexed.last().unwrap().1.key_range_end() == parent_end);

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
    validate_residual_split_bounds(
        old_parent.key_range_start(),
        old_parent.key_range_end(),
        new_parent,
        residual,
    )
}

/// Validate residual split using borrowed old-parent bounds.
///
/// Equivalent to [`validate_residual_split`] but avoids requiring an owned
/// old-parent `ShardSpec` when callers already have borrowed bounds.
/// Used by coordinator split precondition checks to avoid materializing
/// temporary parent specs from pooled storage.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn validate_residual_split_bounds(
    old_parent_start: &[u8],
    old_parent_end: &[u8],
    new_parent: &ShardSpec,
    residual: &ShardSpec,
) -> Result<(), SplitValidationError> {
    // The parent must keep the left (lower) portion of the range.
    if new_parent.key_range_start() != old_parent_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: old_parent_start.to_vec().into_boxed_slice(),
            first_child_start: new_parent.key_range_start().to_vec().into_boxed_slice(),
        });
    }
    // The residual must cover the right (upper) portion.
    if residual.key_range_end() != old_parent_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: old_parent_end.to_vec().into_boxed_slice(),
            last_child_end: residual.key_range_end().to_vec().into_boxed_slice(),
        });
    }
    validate_split_coverage_bounds(old_parent_start, old_parent_end, &[new_parent, residual])
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[path = "shard_spec_tests.rs"]
mod tests;
