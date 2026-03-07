//! Deterministic in-memory connector for test and harness use.
//!
//! This module provides [`InMemoryDeterministicConnector`], an implementation of
//! [`EnumerationConnector`] and [`ReadConnector`] that keeps all data in memory
//! and guarantees bit-identical enumeration across runs for the same input set.
//! It is designed for environments where reproducibility matters more than source
//! realism: unit tests, conformance harnesses, and simulation workloads.
//!
//! # Algorithm
//!
//! 1. **Construction** -- Items are sorted by [`ItemKey`] once (O(n log n)),
//!    uniqueness is verified, and all per-item metadata ([`StableItemId`],
//!    [`ObjectVersionId`], [`ItemRef`], size hint) is precomputed into internal
//!    `PreparedItem` records. Subsequent pages pay only clone/copy costs.
//! 2. **Enumeration** -- Shard bounds are normalized via the internal
//!    `borrowed_shard_bound` helper (`[]` means unbounded, oversize is rejected)
//!    and resolved with binary search (O(log n)), then up to
//!    [`Budgets::max_items`] are yielded by index iteration over precomputed
//!    metadata.
//! 3. **Split hints** -- `choose_split_point*` bulk-loads the remaining
//!    sorted range into `StreamingSplitEstimator`,
//!    keeping byte-weighted split selection aligned with the filesystem and
//!    git connectors without storing mutable estimator state.
//! 4. **Deterministic IDs** -- [`StableItemId`] derived via
//!    [`ItemIdentityKey::stable_id`](gossip_contracts::identity::ItemIdentityKey::stable_id)
//!    (connector-tag + connector-instance + key, domain-separated),
//!    [`ObjectVersionId`] via [`ObjectVersionId::from_version_bytes`]
//!    (domain-separated BLAKE3 of content bytes), [`ItemRef`] = big-endian
//!    index. All items carry [`VersionId::Strong`] since content is immutable.
//!
//! # Pooled toxic-byte page assembly
//!
//! Enumeration stages item keys, item refs, and optional token bytes into a
//! page-local [`gossip_stdx::ByteSlab`], then materializes wrappers with
//! [`ItemKey::try_from_slot`], [`ItemRef::try_from_slot`], and token
//! construction from slots. This incurs one copy per staged field but keeps
//! wrapper cloning allocation-free in the HOT page-emission loop.
//!
//! The page's cursor and items share the same slab owner
//! ([`gossip_contracts::connector::PooledByteSlab`]), so returning either one
//! by value keeps pooled bytes valid until the last clone is dropped.
//!
//! # Unique key requirement
//!
//! The constructor **panics** if duplicate keys are present after sorting.
//! Duplicate keys are unsupported because:
//!
//! - Cursor resume via `upper_bound(last_key)` skips remaining duplicates.
//! - [`StableItemId`] is derived from `(connector_tag, connector_instance, key)`, so duplicates
//!   collide on identity.
//! - Split-point selection can return a duplicate key, producing empty shards.
//!
//! Callers must deduplicate before construction.
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
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorInstanceIdHash, ConnectorTag, ObjectVersionId, StableItemId},
};

use crate::common::{self, borrowed_shard_bound, derive_stable_item_id, parse_u64_be};

/// One in-memory record served by [`InMemoryDeterministicConnector`].
#[derive(Clone, Debug)]
pub struct MemItem {
    /// Item key used for lexicographic ordering and cursor progression.
    pub key: ItemKey,
    /// Immutable payload returned by [`ReadConnector`] operations.
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
/// Every field except `key` and `bytes` is precomputed at construction time.
/// `stable_item_id` and `version_id` are derived from key/bytes plus the
/// connector tag; `item_ref` is the item's positional index in the sorted
/// array; `size_hint` is `bytes.len()`. All are deterministic for a fixed
/// input set. Computing them once eliminates redundant BLAKE3 hashing and
/// index-to-[`ItemRef`] conversion on every page emission. This mirrors the
/// `FileEntry` pattern used by `FilesystemConnector`.
struct PreparedItem {
    /// Sorted item key for ordering and cursor progression.
    key: ItemKey,
    /// Immutable payload bytes for [`ReadConnector`] operations.
    bytes: Arc<[u8]>,
    /// Big-endian `u64` index into the sorted item array.
    item_ref: ItemRef,
    /// Domain-separated BLAKE3 hash of `(connector_tag, connector_instance, key)`.
    stable_item_id: StableItemId,
    /// Domain-separated BLAKE3 hash of the content bytes.
    version_id: ObjectVersionId,
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
/// - [`StableItemId`] is derived via [`ItemIdentityKey::stable_id`](gossip_contracts::identity::ItemIdentityKey::stable_id)
///   (domain-separated BLAKE3 of connector-tag + connector-instance + key)
///   and [`ObjectVersionId`]
///   via [`ObjectVersionId::from_version_bytes`] (domain-separated BLAKE3 of
///   the item's content bytes), both deterministic and precomputed once at
///   construction. All items are emitted with [`VersionId::Strong`] because
///   the in-memory content is immutable.
///
/// Together these choices make enumeration order, identity fields, and read
/// handles reproducible across runs for identical inputs.
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
    pub fn new(
        connector_tag: ConnectorTag,
        connector_instance_id: impl AsRef<[u8]>,
        mut items: Vec<MemItem>,
    ) -> Self {
        items.sort_by(|left, right| left.key.cmp(&right.key));
        let connector_instance =
            ConnectorInstanceIdHash::from_instance_id_bytes(connector_instance_id.as_ref());

        // Enforce unique keys. Duplicate keys break cursor resume
        // (upper_bound skips remaining duplicates), StableItemId derivation
        // (collisions), and split-point selection (empty shards). Format the
        // duplicate through ItemKey itself so panic diagnostics stay redacted.
        if let Some(pos) = items.windows(2).position(|w| w[0].key == w[1].key) {
            panic!(
                "InMemoryDeterministicConnector requires unique item keys; \
                 duplicate key {} at sorted position {pos}",
                items[pos].key
            );
        }

        let prepared: Arc<[PreparedItem]> = items
            .into_iter()
            .enumerate()
            .map(|(idx, item)| {
                let idx_u64 = u64::try_from(idx).expect("item count must fit in u64");
                let item_ref = ItemRef::try_from_slice(&idx_u64.to_be_bytes())
                    .expect("8-byte big-endian index is always valid for ItemRef");
                let stable_item_id =
                    derive_stable_item_id(connector_tag, connector_instance, &item.key);
                let version_id = ObjectVersionId::from_version_bytes(&item.bytes);
                let size_hint = item.bytes.len() as u64;
                PreparedItem {
                    key: item.key,
                    bytes: item.bytes,
                    item_ref,
                    stable_item_id,
                    version_id,
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

    /// Enumerate one page over the explicit half-open key range `[start, end)`.
    ///
    /// This entry point bypasses [`ShardSpec`] decoding, letting tests exercise
    /// the core pagination logic with known-good bounds and without needing to
    /// construct a full shard object.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if `start > end`.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(
            Some(start.as_bytes()),
            Some(end.as_bytes()),
            cursor,
            budgets,
        )
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

    /// Core page enumeration for both shard-based and explicit-range callers.
    ///
    /// # Algorithm
    ///
    /// 1. **Budget gate** -- Return retryable error if deadline expired.
    /// 2. **Range validation** -- Reject `start > end` as a permanent error.
    /// 3. **Range resolution** -- Map keys to indices via binary search.
    /// 4. **Cursor advancement** -- Resume from `last_key` position.
    ///    The shared helper establishes this as the canonical floor; token
    ///    handling below may advance further but never behind key-derived state.
    ///    When tokens are enabled, the token is used as an O(1) fast path:
    ///    validated by checking `items[token_idx - 1].key == last_key`. On
    ///    mismatch, falls back to O(log n) `upper_bound` binary search.
    /// 5. **Page extraction** -- Yield up to `max_items` consecutive items
    ///    from precomputed metadata (clone/copy only, no hashing).
    fn enumerate_page_bounds(
        &self,
        start: Option<&[u8]>,
        end: Option<&[u8]>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let bounds = common::resolve_page_bounds(&self.items, start, end, budgets)?;
        let key_resume = common::key_resume_start(&self.items, cursor, bounds.range_start);
        let mut start_idx = key_resume;

        // O(1) token fast path: when tokens are enabled and the cursor carries
        // a well-formed token whose preceding item matches `last_key`, jump
        // directly to the token index. On mismatch, fall back to the
        // key-authoritative position computed above.
        if let Some(last_key) = cursor.last_key() {
            let token_idx = self
                .emit_tokens
                .then(|| common::cursor_token_index(cursor))
                .flatten();

            if let Some(token_idx) = token_idx
                && token_idx > 0
                && token_idx <= self.items.len()
                && self.items[token_idx - 1].key == *last_key
            {
                start_idx = start_idx.max(token_idx);

                #[cfg(debug_assertions)]
                debug_assert_eq!(
                    token_idx, key_resume,
                    "token index {token_idx} disagrees with \
                     key-derived resume position {key_resume}"
                );
            }
        }

        if start_idx >= bounds.range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(bounds.range_end - start_idx);
        let page_items = &self.items[start_idx..start_idx + take];

        let staged = common::assemble_pooled_page(
            page_items
                .iter()
                .map(|item| (item.key.as_bytes(), item.item_ref.as_bytes())),
            self.emit_tokens,
            start_idx,
        )?;

        let common::StagedPage { wrappers, token } = staged;
        let mut out = Vec::with_capacity(wrappers.len());
        for ((item_key, item_ref), item) in wrappers.into_iter().zip(page_items) {
            out.push(
                ScanItem::new(
                    item_key,
                    item_ref,
                    item.stable_item_id,
                    VersionId::Strong(item.version_id),
                )
                .with_size_hint(item.size_hint),
            );
        }

        // Build continuation cursor from the last emitted key.
        // Defensive match: if `out` is unexpectedly empty (e.g., all staged
        // items failed validation), return an empty page instead of panicking.
        let last_key = match out.last() {
            Some(item) => item.item_key().clone(),
            None => return Ok(EnumerationPage::new(Vec::new(), cursor.clone())),
        };
        let next_cursor = common::build_next_cursor_from_staged(
            last_key,
            start_idx,
            out.len(),
            self.emit_tokens,
            token,
        )?;

        Ok(EnumerationPage::new(out, next_cursor))
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

impl EnumerationConnector for InMemoryDeterministicConnector {
    fn caps(&self) -> ConnectorCapabilities {
        ConnectorCapabilities {
            seek_by_key: true,
            token_resume: self.emit_tokens,
            range_read: true,
            split_hints: true,
        }
    }

    /// Shard bounds are validated allocation-free via the internal
    /// `borrowed_shard_bound` helper:
    /// empty means unbounded, oversize bounds are permanent input errors.
    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start, end, cursor, budgets)
    }

    /// Budgets are accepted for trait conformance but not consumed: split-point
    /// selection is a metadata-only operation with no I/O or time-bounded work.
    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = borrowed_shard_bound(shard.key_range_start(), "start")?;
        let end = borrowed_shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start, end, cursor)
    }
}

impl ReadConnector for InMemoryDeterministicConnector {
    /// Returns a reader over the full item content.
    ///
    /// Budget enforcement is left to the runtime layer (which wraps the
    /// returned reader in a bounded adapter), consistent with the advisory
    /// budget contract in [`ReadConnector`]. This matches [`read_range`]
    /// semantics, which also does not reject items based on total size.
    ///
    /// [`read_range`]: ReadConnector::read_range
    fn open(
        &mut self,
        item_ref: &ItemRef,
        _budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let bytes = self.open_ref_internal(item_ref)?.clone();
        Ok(Box::new(io::Cursor::new(bytes)))
    }

    /// Clamps the copy length to `min(dst.len(), max_bytes, available)` so
    /// the budget acts as an additional upper bound on bytes returned.
    fn read_range(
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
