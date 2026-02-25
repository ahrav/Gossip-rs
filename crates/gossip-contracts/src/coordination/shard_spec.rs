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
use gossip_stdx::{ByteSlab, SlabFull};

use crate::coordination::pooled::PooledShardSpec;
use crate::identity::CanonicalBytes;

/// Re-exported from [`super::cursor`] — single source of truth for the
/// system-wide key-size ceiling. Both cursor keys and shard-spec range
/// boundaries operate in the same lexicographic keyspace.
pub use super::cursor::MAX_KEY_SIZE;

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
// ShardSpecRef
// ============================================================================

/// Borrowed shard-spec view.
///
/// This is the allocation-free companion to [`ShardSpec`], used for B3 hot-path
/// APIs that must avoid per-call heap traffic. It borrows caller-owned buffers
/// and is therefore valid only for the lifetime of those buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardSpecRef<'a> {
    key_range_start: &'a [u8],
    key_range_end: &'a [u8],
    metadata: &'a [u8],
}

impl<'a> ShardSpecRef<'a> {
    /// Construct a borrowed shard-spec view from raw slices.
    ///
    /// This constructor is intentionally lightweight and performs no
    /// validation. Call [`ShardSpec::validate_ref`] (or
    /// [`ShardSpec::try_from_ref`]) before persisting or trusting external
    /// input.
    #[inline]
    #[must_use]
    pub const fn new(
        key_range_start: &'a [u8],
        key_range_end: &'a [u8],
        metadata: &'a [u8],
    ) -> Self {
        Self {
            key_range_start,
            key_range_end,
            metadata,
        }
    }

    /// Unbounded key range with empty metadata.
    #[inline]
    #[must_use]
    pub const fn unbounded() -> Self {
        Self::new(&[], &[], &[])
    }

    /// Inclusive lower bound of the key range.
    #[inline]
    #[must_use]
    pub fn key_range_start(self) -> &'a [u8] {
        self.key_range_start
    }

    /// Exclusive upper bound of the key range.
    #[inline]
    #[must_use]
    pub fn key_range_end(self) -> &'a [u8] {
        self.key_range_end
    }

    /// Connector-opaque metadata.
    #[inline]
    #[must_use]
    pub fn metadata(self) -> &'a [u8] {
        self.metadata
    }

    /// Returns `true` if the key range has no lower bound.
    #[inline]
    #[must_use]
    pub fn is_start_unbounded(self) -> bool {
        self.key_range_start.is_empty()
    }

    /// Returns `true` if the key range has no upper bound.
    #[inline]
    #[must_use]
    pub fn is_end_unbounded(self) -> bool {
        self.key_range_end.is_empty()
    }

    /// Returns `true` if the shard covers the entire keyspace.
    #[inline]
    #[must_use]
    pub fn is_unbounded(self) -> bool {
        self.is_start_unbounded() && self.is_end_unbounded()
    }

    /// Check whether a key falls within this shard's key range.
    #[inline]
    #[must_use]
    pub fn contains_key(self, key: &[u8]) -> bool {
        let above_start = self.is_start_unbounded() || key >= self.key_range_start;
        let below_end = self.is_end_unbounded() || key < self.key_range_end;
        above_start && below_end
    }
}

impl CanonicalBytes for ShardSpecRef<'_> {
    #[inline]
    fn write_canonical(&self, h: &mut Hasher) {
        self.key_range_start.write_canonical(h);
        self.key_range_end.write_canonical(h);
        self.metadata.write_canonical(h);
    }
}

/// Conversion trait for APIs that accept borrowed spec views.
///
/// This allows callers to pass either a direct [`ShardSpecRef`] or a borrowed
/// [`&ShardSpec`](ShardSpec) view without allocation.
///
/// Implementations must produce a [`ShardSpecRef`] whose lifetime reflects the
/// true ownership of the underlying bytes. The result is call-scoped input:
/// consuming APIs copy bytes into their own storage before returning.
pub trait IntoShardSpecRef<'a> {
    /// Produce a borrowed shard-spec view for call-scoped validation/encoding.
    fn into_spec_ref(self) -> ShardSpecRef<'a>;
}

impl<'a> IntoShardSpecRef<'a> for ShardSpecRef<'a> {
    fn into_spec_ref(self) -> ShardSpecRef<'a> {
        self
    }
}

impl<'a> IntoShardSpecRef<'a> for &'a ShardSpec {
    fn into_spec_ref(self) -> ShardSpecRef<'a> {
        self.as_ref()
    }
}

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
    /// Borrow this spec as a [`ShardSpecRef`].
    #[inline]
    #[must_use]
    pub fn as_ref(&self) -> ShardSpecRef<'_> {
        ShardSpecRef::new(
            self.key_range_start(),
            self.key_range_end(),
            self.metadata(),
        )
    }

    /// Validate a borrowed spec view.
    ///
    /// # Errors
    ///
    /// - [`ShardSpecInputError::KeyTooLarge`] when `start` or `end` exceeds
    ///   [`MAX_KEY_SIZE`].
    /// - [`ShardSpecInputError::MetadataTooLarge`] when `metadata` exceeds
    ///   [`MAX_METADATA_SIZE`].
    /// - [`ShardSpecInputError::InvertedRange`] when both bounds are non-empty
    ///   and `start >= end`.
    pub fn validate_ref(spec: ShardSpecRef<'_>) -> Result<(), ShardSpecInputError> {
        if spec.key_range_start().len() > MAX_KEY_SIZE {
            return Err(ShardSpecInputError::KeyTooLarge {
                size: spec.key_range_start().len(),
                max: MAX_KEY_SIZE,
            });
        }
        if spec.key_range_end().len() > MAX_KEY_SIZE {
            return Err(ShardSpecInputError::KeyTooLarge {
                size: spec.key_range_end().len(),
                max: MAX_KEY_SIZE,
            });
        }
        if spec.metadata().len() > MAX_METADATA_SIZE {
            return Err(ShardSpecInputError::MetadataTooLarge {
                size: spec.metadata().len(),
                max: MAX_METADATA_SIZE,
            });
        }
        if !spec.key_range_start().is_empty()
            && !spec.key_range_end().is_empty()
            && spec.key_range_start() >= spec.key_range_end()
        {
            return Err(ShardSpecInputError::InvertedRange {
                start_len: spec.key_range_start().len(),
                end_len: spec.key_range_end().len(),
            });
        }
        Ok(())
    }

    /// Materialize an owned [`ShardSpec`] from a borrowed view.
    ///
    /// # Errors
    ///
    /// Returns the same validation errors as [`Self::validate_ref`].
    pub fn try_from_ref(spec: ShardSpecRef<'_>) -> Result<Self, ShardSpecInputError> {
        Self::validate_ref(spec)?;
        Ok(Self {
            key_range_start: spec.key_range_start().into(),
            key_range_end: spec.key_range_end().into(),
            metadata: spec.metadata().into(),
        })
    }

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
    #[cfg(any(test, feature = "test-support"))]
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
// ShardArena
// ============================================================================

/// Opaque handle for a spec allocated in [`ShardArena`].
///
/// Handles are slot + generation pairs. The generation prevents use-after-free:
/// freeing a slot increments the generation, so stale handles pointing to the
/// same slot index are detected and rejected by `view_spec`. Handles are `Copy`
/// (cheap to pass around) but the underlying bytes live in the arena's slab.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ShardSpecHandle {
    slot: u32,
    generation: u32,
}

#[derive(Debug)]
struct ArenaSlot {
    generation: u32,
    spec: Option<PooledShardSpec>,
}

/// Startup-preallocated arena for persistent shard specs.
///
/// `ShardArena` stores spec bytes in a shared [`ByteSlab`] and tracks live
/// entries with generational slot handles ([`ShardSpecHandle`]). Allocation is
/// bounded by both byte capacity and slot capacity; runtime calls never touch
/// the global allocator once the arena itself is provisioned.
///
/// ## When to Use
///
/// Use `ShardArena` when specs are long-lived and frequently accessed by
/// reference (e.g., the run-level manifest that maps shard IDs to their
/// specs). For short-lived, per-operation spec views, prefer borrowing
/// directly via [`ShardSpecRef`].
///
/// ## Generational Slots
///
/// Each slot carries a `generation` counter. Freeing a slot increments the
/// generation so that stale [`ShardSpecHandle`] values (pointing to the same
/// slot index but an earlier generation) are detected by `view_spec` and
/// cause a panic rather than silently returning unrelated data. The generation
/// wraps at `u32::MAX`; in practice, a single slot would need 4 billion
/// alloc/free cycles to wrap, which is not a realistic concern.
///
/// ## Cleanup
///
/// `ShardArena` does not implement `Drop` for individual specs. Callers
/// must call [`free_spec`](Self::free_spec) to release slab bytes. Dropping
/// the arena drops the slab, reclaiming all memory at once.
pub struct ShardArena {
    slab: ByteSlab,
    slots: Vec<ArenaSlot>,
    free_slots: Vec<u32>,
}

impl ShardArena {
    /// Create a new arena with fixed slot and byte capacity.
    #[must_use]
    pub fn with_capacity(spec_slots: usize, byte_capacity: usize) -> Self {
        let mut slots = Vec::with_capacity(spec_slots);
        let mut free_slots = Vec::with_capacity(spec_slots);
        for i in 0..spec_slots {
            slots.push(ArenaSlot {
                generation: 0,
                spec: None,
            });
            free_slots.push((spec_slots - 1 - i) as u32);
        }
        Self {
            slab: ByteSlab::with_capacity(byte_capacity),
            slots,
            free_slots,
        }
    }

    /// Allocate a spec in the arena and return a stable slot handle.
    ///
    /// The spec bytes are copied into arena-owned storage. The returned handle
    /// is independent of the caller's input buffers.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] when either:
    /// - the slab lacks byte capacity for this spec, or
    /// - no free slots remain.
    pub fn alloc_spec(&mut self, spec: ShardSpecRef<'_>) -> Result<ShardSpecHandle, SlabFull> {
        assert!(
            ShardSpec::validate_ref(spec).is_ok(),
            "alloc_spec called with invalid ShardSpecRef; callers must validate first"
        );
        let Some(slot_index) = self.free_slots.pop() else {
            return Err(SlabFull {
                requested: 1,
                available: 0,
            });
        };

        let pooled = match PooledShardSpec::from_spec_ref(spec, &mut self.slab) {
            Ok(pooled) => pooled,
            Err(err) => {
                self.free_slots.push(slot_index);
                return Err(err);
            }
        };

        let slot = &mut self.slots[slot_index as usize];
        assert!(slot.spec.is_none(), "free slot unexpectedly occupied");
        slot.spec = Some(pooled);

        Ok(ShardSpecHandle {
            slot: slot_index,
            generation: slot.generation,
        })
    }

    /// Borrow a spec view from a previously allocated handle.
    ///
    /// The returned view borrows arena-owned bytes and stays valid while the
    /// handle remains allocated. Once the handle is freed, any previously
    /// returned view must be considered invalid for future use.
    ///
    /// Use [`try_view_spec`](Self::try_view_spec) for non-panicking lookup.
    ///
    /// # Panics
    ///
    /// Panics if `handle` is stale or invalid.
    #[must_use]
    pub fn view_spec(&self, handle: &ShardSpecHandle) -> ShardSpecRef<'_> {
        self.try_view_spec(handle)
            .expect("ShardArena::view_spec: invalid, stale, or freed handle")
    }

    /// Borrow a spec view from a previously allocated handle.
    ///
    /// Returns `None` when the handle is invalid, stale, or points to a
    /// freed slot. This API is intended for call sites where stale handles
    /// are an expected runtime outcome.
    #[must_use]
    pub fn try_view_spec(&self, handle: &ShardSpecHandle) -> Option<ShardSpecRef<'_>> {
        let slot = self.slots.get(handle.slot as usize)?;
        if slot.generation != handle.generation {
            return None;
        }
        let spec = slot.spec.as_ref()?;
        Some(spec.as_spec_ref(&self.slab))
    }

    /// Free a previously allocated handle.
    ///
    /// Stale or already-freed handles are ignored (returns silently).
    /// In debug builds, an invalid slot index triggers a debug_assert
    /// to catch corrupted handles early.
    pub fn free_spec(&mut self, handle: ShardSpecHandle) {
        let Some(slot) = self.slots.get_mut(handle.slot as usize) else {
            debug_assert!(false, "free_spec: invalid slot index {}", handle.slot);
            return;
        };
        if slot.generation != handle.generation {
            return;
        }
        let Some(spec) = slot.spec.take() else {
            return;
        };
        spec.deallocate(&mut self.slab);
        slot.generation = slot.generation.wrapping_add(1);
        self.free_slots.push(handle.slot);
    }
}

// ============================================================================
// Split Validation
// ============================================================================

/// Whether a shard limit breach is per-tenant or global.
///
/// Split operations check both per-tenant and global shard count ceilings
/// before creating new children. This enum distinguishes which ceiling was
/// hit, enabling callers to produce targeted error messages (e.g., "tenant
/// X is at the limit" vs "system-wide limit reached").
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
///
/// ## Security-Sensitive Variants
///
/// `SpawnLimitExceeded` and `ShardLimitExceeded` are resource exhaustion
/// guards that prevent a malicious or buggy worker from creating unbounded
/// shards via repeated splits. `DerivedIdCollision` is an astronomically
/// unlikely BLAKE3 collision that the system handles gracefully rather
/// than panicking on external input.
///
/// ## Display Redaction
///
/// Byte field lengths are shown instead of raw content in `Display` output,
/// consistent with the cursor redaction policy in [`CoordError`](super::error::CoordError).
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

    /// A child spec exceeds size limits (`MAX_KEY_SIZE` or `MAX_METADATA_SIZE`).
    ///
    /// `ShardSpecRef` is intentionally unvalidated at construction time;
    /// this variant surfaces when the coordinator's precondition check
    /// detects oversized fields before they reach `AcquireScratch::write_spec`.
    InvalidChildSpec { child_index: usize },
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
            Self::InvalidChildSpec { child_index } => {
                write!(
                    f,
                    "child {child_index} spec exceeds size limits \
                     (MAX_KEY_SIZE or MAX_METADATA_SIZE)",
                )
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
pub fn validate_split_coverage<'a, P, C>(
    parent: P,
    children: &[C],
) -> Result<(), SplitValidationError>
where
    P: IntoShardSpecRef<'a>,
    C: Copy + IntoShardSpecRef<'a>,
{
    let parent = parent.into_spec_ref();
    let children: Vec<ShardSpecRef<'a>> = children
        .iter()
        .copied()
        .map(IntoShardSpecRef::into_spec_ref)
        .collect();
    validate_split_coverage_bounds(parent.key_range_start(), parent.key_range_end(), &children)
}

/// Validate split coverage using borrowed parent bounds (slab-friendly variant).
///
/// Equivalent to [`validate_split_coverage`] but takes `parent_start` and
/// `parent_end` as raw slices rather than requiring a `ShardSpec` or
/// `ShardSpecRef`. This is the preferred entry point for the coordinator's
/// pooled-record hot paths where parent bounds are already available as
/// slab-backed `&[u8]` slices — no temporary `ShardSpec` materialization needed.
///
/// ## Algorithm
///
/// 1. Sort children by `key_range_start` (preserving original indices for errors).
/// 2. Assert first child's start matches parent's start.
/// 3. Assert last child's end matches parent's end.
/// 4. Walk adjacent pairs, checking contiguity (`child[i].end == child[i+1].start`).
/// 5. Reject any child with an inverted range (`start >= end`).
///
/// ## Complexity
///
/// O(N log N) for the sort, O(N) for the linear contiguity scan,
/// where N is the number of children.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn validate_split_coverage_bounds(
    parent_start: &[u8],
    parent_end: &[u8],
    children: &[ShardSpecRef<'_>],
) -> Result<(), SplitValidationError> {
    if children.is_empty() {
        return Err(SplitValidationError::NoChildren);
    }

    if children.len() == 1 {
        return Err(SplitValidationError::SingleChild);
    }

    // Pair each child with its original index, then sort by start key.
    // This lets us report the caller's input indices in errors.
    let mut indexed: Vec<(usize, ShardSpecRef<'_>)> =
        children.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| a.1.key_range_start().cmp(b.1.key_range_start()));

    // First child start == parent start.
    if indexed[0].1.key_range_start() != parent_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent_start.to_vec().into_boxed_slice(),
            first_child_start: indexed[0].1.key_range_start().to_vec().into_boxed_slice(),
        });
    }

    // Last child end == parent end.
    let last = indexed[indexed.len() - 1];
    if last.1.key_range_end() != parent_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent_end.to_vec().into_boxed_slice(),
            last_child_end: last.1.key_range_end().to_vec().into_boxed_slice(),
        });
    }

    // Contiguity: each child's end == next child's start.
    // Also reject empty internal boundaries: an empty `key_range_end` means
    // "extends to end of keyspace" which is only valid for the last child.
    // Empty internal boundaries indicate overlapping children (e.g. two
    // fully-unbounded children `[[], [])` pass the equality check but
    // cover the same keyspace).
    for i in 0..indexed.len() - 1 {
        if indexed[i].1.key_range_end() != indexed[i + 1].1.key_range_start() {
            return Err(SplitValidationError::BoundaryMismatch {
                child_index: indexed[i].0,
                next_child_index: indexed[i + 1].0,
                child_end: indexed[i].1.key_range_end().to_vec().into_boxed_slice(),
                next_child_start: indexed[i + 1]
                    .1
                    .key_range_start()
                    .to_vec()
                    .into_boxed_slice(),
            });
        }
        if indexed[i].1.key_range_end().is_empty() {
            return Err(SplitValidationError::OverlappingChild {
                child_index: indexed[i].0,
                next_child_index: indexed[i + 1].0,
            });
        }
    }

    // Each child individually well-formed.
    for &(orig_idx, child) in &indexed {
        if !child.key_range_start().is_empty()
            && !child.key_range_end().is_empty()
            && child.key_range_start() >= child.key_range_end()
        {
            return Err(SplitValidationError::InvertedChild {
                child_index: orig_idx,
            });
        }
    }

    // Validate per-spec size limits. ShardSpecRef is intentionally
    // unvalidated at construction; this gate prevents oversized fields
    // (keys or metadata) from reaching AcquireScratch::write_spec's
    // panicking asserts.
    for &(orig_idx, child) in &indexed {
        if ShardSpec::validate_ref(child).is_err() {
            return Err(SplitValidationError::InvalidChildSpec {
                child_index: orig_idx,
            });
        }
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
pub fn validate_residual_split<'a, O, N, R>(
    old_parent: O,
    new_parent: N,
    residual: R,
) -> Result<(), SplitValidationError>
where
    O: IntoShardSpecRef<'a>,
    N: IntoShardSpecRef<'a>,
    R: IntoShardSpecRef<'a>,
{
    let old_parent = old_parent.into_spec_ref();
    let new_parent = new_parent.into_spec_ref();
    let residual = residual.into_spec_ref();
    validate_residual_split_bounds(
        old_parent.key_range_start(),
        old_parent.key_range_end(),
        new_parent,
        residual,
    )
}

/// Validate residual split using borrowed old-parent bounds (slab-friendly variant).
///
/// Same semantics as [`validate_residual_split`] but takes raw `&[u8]`
/// slices for the old parent's range bounds rather than a full spec.
/// Used by the coordinator's split precondition checks to avoid
/// materializing a temporary `ShardSpec` from pooled slab storage.
#[must_use = "returns a Result that must be checked for validation errors"]
pub fn validate_residual_split_bounds(
    old_parent_start: &[u8],
    old_parent_end: &[u8],
    new_parent: ShardSpecRef<'_>,
    residual: ShardSpecRef<'_>,
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
