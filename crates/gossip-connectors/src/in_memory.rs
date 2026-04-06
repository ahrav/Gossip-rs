//! Deterministic in-memory connector for test and harness use.
//!
//! This module provides [`InMemoryDeterministicConnector`], which implements
//! read and split-point operations keeping all data in memory. It guarantees
//! deterministic ordering across runs for the same input set. Designed for
//! environments where reproducibility matters more than source realism: unit
//! tests and simulation workloads.
//!
//! # Algorithm
//!
//! 1. **Construction** -- Items are sorted by [`ItemKey`] once (O(n log n)),
//!    uniqueness is verified, and per-item metadata is precomputed into
//!    internal `PreparedItem` records.
//! 2. **Split hints** -- `choose_split_point*` bulk-loads the remaining
//!    sorted range into `StreamingSplitEstimator`,
//!    keeping byte-weighted split selection aligned with the filesystem and
//!    git connectors without storing mutable estimator state.
//!
//! # Unique key requirement
//!
//! The constructor **panics** if duplicate keys are present after sorting.
//! Duplicate keys are unsupported because split-point selection can return a
//! duplicate key, producing empty shards. Callers must deduplicate before
//! construction.
//!
//! # Resume semantics
//!
//! When tokens are enabled, the cursor token carries the next-index as a
//! big-endian `u64`. On resume, the token is used as an O(1) fast path:
//! the item just before the token index is validated against `last_key`. If
//! the token is missing, malformed, or stale, the connector falls back to
//! O(log n) `upper_bound` binary search. This validation runs in all build
//! profiles (not just debug). When tokens are disabled, resume is always
//! key-based via binary search.
//!
//! # Budget expiry
//!
//! An expired deadline returns `Err(EnumerateError::retryable(...))` rather
//! than an empty page. This avoids ambiguity with the empty-page-means-EOF
//! signal and lets callers distinguish budget exhaustion from scan completion.
//!
//! # Scope and limitations
//!
//! - Designed for single-threaded sequential page calls; no interior
//!   synchronization for concurrent access.
//! - [`ItemRef`] values are positional indices into the sorted vector, not
//!   stable cross-instance identifiers. Adding or removing items changes
//!   the sort order and invalidates all prior references.
//! - No lazy loading or streaming; the full dataset must fit in memory.
//! - The connector is cheaply [`Clone`]able; internal data is shared via
//!   [`Arc`].

use std::{io, sync::Arc};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, ItemKey, ItemRef, ReadError,
    },
    coordination::ShardSpec,
};

use crate::common::{self, borrowed_shard_bound, parse_u64_be};

/// One in-memory record served by [`InMemoryDeterministicConnector`].
#[derive(Clone, Debug)]
pub struct MemItem {
    /// Item key used for lexicographic ordering and cursor progression.
    pub key: ItemKey,
    /// Immutable payload returned by read operations.
    ///
    /// Wrapped in `Arc` to keep fixture duplication cheap.
    pub bytes: Arc<[u8]>,
}

impl MemItem {
    /// Build a memory-backed item with shared immutable bytes.
    ///
    /// Accepting `Into<Arc<[u8]>>` keeps fixture construction ergonomic while
    /// preserving zero-copy sharing across cloned fixture items.
    pub fn new(key: ItemKey, bytes: impl Into<Arc<[u8]>>) -> Self {
        Self {
            key,
            bytes: bytes.into(),
        }
    }
}

/// Precomputed per-item metadata, built once at construction time.
///
/// `size_hint` is precomputed as `bytes.len()` at construction time.
/// Computing it once avoids repeated length queries during split-point
/// estimation.
struct PreparedItem {
    /// Sorted item key for ordering and cursor progression.
    key: ItemKey,
    /// Immutable payload bytes for read operations.
    bytes: Arc<[u8]>,
    /// Precomputed `bytes.len() as u64`.
    size_hint: u64,
}

impl common::KeyedEntry for PreparedItem {
    fn key_bytes(&self) -> &[u8] {
        self.key.as_bytes()
    }
}

/// Deterministic in-memory connector for shard-based enumeration and reads.
///
/// The connector is cheaply [`Clone`]able: internal prepared-item storage is
/// shared via [`Arc`], so cloning costs only an atomic reference count bump
/// plus one `Copy` field. Trait methods take `&mut self` because the trait
/// signatures require it, but no internal mutation occurs after construction.
///
/// # Determinism contract
///
/// Given the same input `Vec<MemItem>`:
///
/// - Items are sorted lexicographically by [`ItemKey`] at construction time.
/// - Duplicate keys are **rejected** (the constructor panics).
/// - [`ItemRef`] values are big-endian `u64` indices into that sorted vector,
///   so the Nth item always gets `ItemRef(N)`.
///
/// Together these choices make ordering and read handles reproducible across
/// runs for identical inputs.
///
/// # Resume semantics
///
/// When tokens are enabled (the default), the cursor token carries the
/// next-index as a big-endian `u64`. On resume, the token is used as an
/// O(1) fast path with validation against `last_key`; on mismatch the
/// connector falls back to O(log n) binary search. See module docs for full
/// detail.
///
/// # Capabilities
///
/// The connector advertises `seek_by_key`, `token_resume` (when enabled),
/// `range_read`, and `split_hints` -- the full capability set.
#[derive(Clone)]
pub struct InMemoryDeterministicConnector {
    /// Sorted, precomputed item storage shared via [`Arc`] for cheap cloning.
    /// Built once at construction; never mutated afterward.
    items: Arc<[PreparedItem]>,
    /// When `true`, enumeration pages emit big-endian index tokens and the
    /// resume path uses them as an O(1) fast path with key-based fallback.
    /// When `false`, tokens are neither emitted nor consumed.
    emit_tokens: bool,
}

impl InMemoryDeterministicConnector {
    /// Build a connector from an unordered collection of in-memory items.
    ///
    /// Items are sorted lexicographically by key (O(n log n)), verified to
    /// contain no duplicate keys, and then all per-item metadata is
    /// precomputed into internal records. Subsequent page emission pays
    /// only clone/copy costs.
    ///
    /// Token emission is enabled by default. Use [`with_tokens(false)`] to
    /// disable it.
    ///
    /// # Panics
    ///
    /// Panics if any two items share the same key. Duplicate keys are a
    /// test-setup bug and cannot be paginated correctly (see module docs).
    /// The panic message reports the offending key through [`ItemKey`] display
    /// formatting so diagnostics stay redacted under the toxic-byte policy.
    ///
    /// [`with_tokens(false)`]: Self::with_tokens
    pub fn new(mut items: Vec<MemItem>) -> Self {
        items.sort_by(|left, right| left.key.cmp(&right.key));

        // INVARIANT: Unique keys are strictly required.
        // Duplicate keys break the `upper_bound` binary search logic during
        // cursor resumption and produce invalid split-point selections resulting
        // in empty shards. The offending key is surfaced to diagnostics securely.
        if let Some(pos) = items.windows(2).position(|w| w[0].key == w[1].key) {
            panic!(
                "InMemoryDeterministicConnector requires unique item keys; \
                 duplicate key {} at sorted position {pos}",
                items[pos].key
            );
        }

        let prepared: Arc<[PreparedItem]> = items
            .into_iter()
            .map(|item| {
                let size_hint = item.bytes.len() as u64;
                PreparedItem {
                    key: item.key,
                    bytes: item.bytes,
                    size_hint,
                }
            })
            .collect();

        Self {
            items: prepared,
            emit_tokens: true,
        }
    }

    /// Enable or disable pagination token emission/consumption.
    ///
    /// Disabling tokens is useful when callers want to validate key-only resume
    /// behavior or simulate connectors that cannot persist opaque token state.
    #[must_use]
    pub fn with_tokens(mut self, enabled: bool) -> Self {
        self.emit_tokens = enabled;
        self
    }

    /// Return a split-point hint over the explicit half-open key range
    /// `[start, end)`.
    ///
    /// This entry point mirrors shard-based split behavior without requiring a
    /// [`ShardSpec`], keeping split-point unit tests focused and self-contained.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start.as_bytes()), Some(end.as_bytes()), cursor)
    }

    /// Choose a midpoint key that can be used as a shard split hint.
    ///
    /// Delegates to [`common::estimate_split_from_sorted`] after resolving
    /// bounds and the cursor resume position. Returns `None` when fewer than
    /// two keys remain, the estimator produces no candidate, or the candidate
    /// fails validation.
    fn choose_split_point_bounds(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let bounds = common::resolve_bounds(&self.items, start, end)?;
        let start_idx = common::key_resume_start(&self.items, cursor, bounds.range_start);
        if start_idx >= bounds.range_end {
            return Ok(None);
        }

        let range = &self.items[start_idx..bounds.range_end];
        common::estimate_split_from_sorted(
            range
                .iter()
                .map(|item| (item.key.as_bytes(), item.size_hint)),
            range.len(),
            cursor,
            end,
        )
    }

    /// Resolve an [`ItemRef`] into the backing bytes.
    ///
    /// `ItemRef` values are interpreted as big-endian indices into the sorted
    /// prepared-item array. This keeps references compact and deterministic,
    /// but also means references are connector-instance-local.
    fn open_ref_internal(&self, item_ref: &ItemRef) -> Result<&Arc<[u8]>, ReadError> {
        let idx_u64 = parse_u64_be(item_ref.as_bytes())
            .ok_or_else(|| ReadError::permanent("invalid item_ref encoding"))?;
        let idx = usize::try_from(idx_u64)
            .map_err(|_| ReadError::permanent("item_ref index too large"))?;

        self.items
            .get(idx)
            .map(|item| &item.bytes)
            .ok_or_else(|| ReadError::permanent("item_ref out of bounds"))
    }
}

impl InMemoryDeterministicConnector {
    /// Advertise the connector features that planners may rely on.
    ///
    /// `token_resume` mirrors the current `emit_tokens` setting exactly, so a
    /// connector configured with [`with_tokens(false)`](Self::with_tokens)
    /// never claims opaque-token resume support.
    pub fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    /// Choose a shard-local split hint for the given [`ShardSpec`].
    ///
    /// The shard's half-open key bounds are resolved first, then the same
    /// sorted-range estimator used by
    /// [`Self::choose_split_point_range`] is applied within those bounds.
    ///
    /// Budgets are accepted but not consumed: split-point selection is a
    /// metadata-only operation with no I/O or time-bounded work.
    pub fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor)
    }

    /// Returns a reader over the full item content.
    ///
    /// Budget enforcement is left to the runtime layer (which wraps the
    /// returned reader in a bounded adapter), consistent with the advisory
    /// budget contract. This matches [`read_range`](Self::read_range)
    /// semantics, which also does not reject items based on total size.
    ///
    /// # Errors
    ///
    /// Returns `ReadError::permanent` when `item_ref` is malformed, cannot be
    /// decoded as a big-endian index, or points outside the prepared item set.
    pub fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let bytes = self.open_ref_internal(item_ref)?.clone();
        Ok(Box::new(io::Cursor::new(bytes)))
    }

    /// Copy a byte range from the referenced item into `dst`.
    ///
    /// The copy length is clamped to `min(dst.len(), max_bytes, available)` so
    /// the budget acts as an additional upper bound on bytes returned.
    ///
    /// Returns `Ok(0)` when `offset` is at or beyond the end of the item, or
    /// when the offset cannot fit in `usize` on the current platform.
    ///
    /// # Errors
    ///
    /// Returns `ReadError::permanent` when `item_ref` is malformed or when
    /// `offset + dst.len()` overflows `u64`.
    pub fn read_range(
        &mut self,
        item_ref: &ItemRef,
        offset: u64,
        dst: &mut [u8],
        budgets: Budgets,
    ) -> Result<usize, ReadError> {
        if offset.checked_add(dst.len() as u64).is_none() {
            return Err(ReadError::permanent("offset + dst length overflow"));
        }

        let bytes = self.open_ref_internal(item_ref)?;
        let start = match usize::try_from(offset) {
            Ok(start) => start,
            Err(_) => return Ok(0),
        };
        if start >= bytes.len() {
            return Ok(0);
        }

        let max_bytes = usize::try_from(budgets.max_bytes()).unwrap_or(usize::MAX);
        let allowed = dst.len().min(max_bytes);
        if allowed == 0 {
            return Ok(0);
        }

        let to_copy = (bytes.len() - start).min(allowed);
        dst[..to_copy].copy_from_slice(&bytes[start..(start + to_copy)]);
        Ok(to_copy)
    }
}

#[cfg(test)]
#[path = "in_memory_tests.rs"]
mod tests;
