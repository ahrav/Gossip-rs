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
//! 1. **Construction** -- Items are sorted by [`ItemKey`] once (O(n log n)).
//! 2. **Enumeration** -- Binary search resolves shard bounds (O(log n)),
//!    then yields up to [`Budgets::max_items`] by index iteration.
//! 3. **Deterministic IDs** -- [`StableItemId`] derived via
//!    [`ItemIdentityKey::stable_id`] (connector-tag + key, domain-separated),
//!    [`ObjectVersionId`] via [`ObjectVersionId::from_version_bytes`]
//!    (domain-separated BLAKE3 of content bytes), [`ItemRef`] = big-endian
//!    index. All items carry [`VersionId::Strong`] since content is immutable.
//!
//! # Resume semantics
//!
//! Cursor progression is anchored on key ordering, not opaque tokens. The
//! authoritative resume position is always `Cursor::last_key`, resolved to the
//! first index strictly greater than that key (`upper_bound`), clamped to the
//! shard range start. Tokens, when enabled, serve only as a consistency
//! cross-check: in debug builds a `debug_assert_eq!` fires when the token
//! index disagrees with the key-derived position (indicating a connector bug),
//! while in release builds the mismatch is silently ignored. Pagination
//! advances monotonically by key regardless of token state.
//!
//! # Scope and limitations
//!
//! - Designed for single-threaded sequential page calls; no interior
//!   synchronization for concurrent access.
//! - [`ItemRef`] values are positional indices into the sorted vector, not
//!   stable cross-instance identifiers. Adding or removing items changes
//!   the sort order and invalidates all prior references.
//! - No lazy loading or streaming; the full dataset must fit in memory.

use std::{io, sync::Arc, time::Instant};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, TokenBytes,
        VersionId,
    },
    coordination::ShardSpec,
    identity::{ConnectorTag, ItemIdentityKey, ObjectVersionId, StableItemId},
};

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

/// Deterministic in-memory connector for shard-based enumeration and reads.
///
/// After construction the internal item vector is logically immutable: none
/// of the public methods mutate state. Trait methods take `&mut self` because
/// the trait signatures require it; convenience methods (`enumerate_page_range`,
/// `choose_split_point_range`) also take `&mut self` for API uniformity.
///
/// # Determinism contract
///
/// Given the same input `Vec<MemItem>`:
///
/// - Items are sorted lexicographically by [`ItemKey`] at construction time.
/// - [`ItemRef`] values are big-endian `u64` indices into that sorted vector,
///   so the Nth item always gets `ItemRef(N)`.
/// - [`StableItemId`] is derived via [`ItemIdentityKey::stable_id`]
///   (domain-separated BLAKE3 of connector-tag + key) and [`ObjectVersionId`]
///   via [`ObjectVersionId::from_version_bytes`] (domain-separated BLAKE3 of
///   the item's content bytes), both deterministic. All items are emitted with
///   [`VersionId::Strong`] because the in-memory content is immutable after
///   construction.
///
/// Together these choices make enumeration order, identity fields, and read
/// handles reproducible across runs for identical inputs.
///
/// # Resume semantics
///
/// See module docs. Token-based resume is enabled by default (`emit_tokens:
/// true`); disable via [`with_tokens(false)`](Self::with_tokens). Tokens are
/// cross-checked against key-based positions in debug builds.
///
/// # Capabilities
///
/// The connector advertises `seek_by_key`, `token_resume` (when enabled),
/// `range_read`, and `split_hints` -- the full capability set.
pub struct InMemoryDeterministicConnector {
    /// Lexicographically sorted item storage. Sorted once at construction;
    /// not mutated afterward.
    items: Vec<MemItem>,
    /// Source-system discriminator included in [`ItemIdentityKey`] derivation.
    /// Ensures `StableItemId` values are connector-scoped, preventing
    /// cross-connector collisions when multiple connectors share key spaces.
    connector_tag: ConnectorTag,
    /// When `true`, enumeration pages emit big-endian index tokens and the
    /// resume path cross-checks them against key-derived positions. When
    /// `false`, tokens are neither emitted nor consumed.
    emit_tokens: bool,
}

impl InMemoryDeterministicConnector {
    /// Build a connector from an unordered collection of in-memory items.
    ///
    /// Items are sorted lexicographically by key (O(n log n)) so that all
    /// subsequent page and split operations can resolve bounds via O(log n)
    /// binary search and iterate by direct indexing.
    ///
    /// Token emission is enabled by default. Use [`with_tokens(false)`] to
    /// disable it.
    ///
    /// [`with_tokens(false)`]: Self::with_tokens
    pub fn new(connector_tag: ConnectorTag, mut items: Vec<MemItem>) -> Self {
        items.sort_by(|left, right| left.key.cmp(&right.key));
        Self {
            items,
            connector_tag,
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
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(Some(start), Some(end), cursor, budgets)
    }

    /// Return a split-point hint over the explicit half-open key range
    /// `[start, end)`.
    ///
    /// This entry point mirrors shard-based split behavior without requiring a
    /// [`ShardSpec`], keeping split-point unit tests focused and self-contained.
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start), Some(end), cursor)
    }

    /// Core page enumeration for both shard-based and explicit-range callers.
    ///
    /// # Algorithm
    ///
    /// 1. **Budget gate** -- Return empty page if deadline expired.
    /// 2. **Range resolution** -- Map keys to indices via binary search.
    /// 3. **Cursor advancement** -- Resume from `last_key` position.
    ///    When tokens are enabled, a `debug_assert_eq!` verifies the token
    ///    agrees with the key-derived index (fires in debug builds only).
    /// 4. **Page extraction** -- Yield up to `max_items` consecutive items
    ///    with deterministic identity fields.
    ///
    /// # Errors
    ///
    /// Returns `EnumerateError::permanent` if an internal index exceeds `u64`
    /// capacity (only possible with more than `u64::MAX` items, i.e., never
    /// in practice).
    fn enumerate_page_bounds(
        &self,
        start: Option<&ItemKey>,
        end: Option<&ItemKey>,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        if budgets.is_expired_at(Instant::now()) {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        // Phase 2: resolve key bounds to vector indices.
        let range_start = start.map_or(0, |bound| lower_bound(&self.items, bound.as_bytes()));
        let range_end = end.map_or(self.items.len(), |bound| {
            lower_bound(&self.items, bound.as_bytes())
        });

        // Phase 3: advance past the cursor's last-emitted key.
        let mut start_idx = range_start;
        if let Some(last_key) = cursor.last_key() {
            let expected = upper_bound(&self.items, last_key.as_bytes());
            start_idx = start_idx.max(expected);

            // Token cross-check: when tokens are enabled and the cursor carries a
            // well-formed token, verify that it agrees with the key-derived resume
            // position. For this deterministic connector the data is immutable after
            // construction, so a mismatch indicates a bug in token emission/parsing
            // rather than legitimate staleness. The entire block is compiled out in
            // release builds so the parsing chain has zero runtime cost.
            #[cfg(debug_assertions)]
            if self.emit_tokens
                && let Some(token) = cursor.token()
                && let Some(token_idx_u64) = parse_u64_be(token.as_bytes())
                && let Ok(token_idx) = usize::try_from(token_idx_u64)
            {
                debug_assert_eq!(
                    token_idx, expected,
                    "token index {token_idx} disagrees with key-derived resume \
                     position {expected}; data is immutable so this is a connector bug"
                );
            }
        }

        if start_idx >= range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        // Phase 4: extract up to max_items consecutive items.
        let take = budgets.max_items().min(range_end - start_idx);
        let mut out = Vec::with_capacity(take);
        for idx in start_idx..(start_idx + take) {
            let item = &self.items[idx];
            let idx_u64 = u64::try_from(idx)
                .map_err(|_| EnumerateError::permanent("item index exceeds u64 capacity"))?;
            let item_ref = ItemRef::try_from_slice(&idx_u64.to_be_bytes())
                .map_err(|err| EnumerateError::permanent(format!("invalid item_ref: {err}")))?;

            let stable_item_id = derive_stable_item_id(self.connector_tag, &item.key);
            let version_id = ObjectVersionId::from_version_bytes(&item.bytes);
            let scan_item = ScanItem::new(
                item.key.clone(),
                item_ref,
                stable_item_id,
                VersionId::Strong(version_id),
            )
            .with_size_hint(item.bytes.len() as u64);
            out.push(scan_item);
        }

        // Build continuation cursor from the last emitted key.
        let last_key = out
            .last()
            .expect("non-empty page must have a last key")
            .item_key()
            .clone();
        let mut next_cursor = Cursor::with_last_key(last_key.clone());

        if self.emit_tokens {
            let next_idx = start_idx
                .checked_add(out.len())
                .and_then(|sum| u64::try_from(sum).ok())
                .ok_or_else(|| EnumerateError::permanent("next index exceeds capacity"))?;
            let token = TokenBytes::try_from_slice(&next_idx.to_be_bytes())
                .map_err(|err| EnumerateError::permanent(format!("invalid token: {err}")))?;
            next_cursor = Cursor::with_token(last_key, token);
        }

        Ok(EnumerationPage::new(out, next_cursor))
    }

    /// Choose a midpoint key that can be used as a shard split hint.
    ///
    /// The candidate is the median of remaining keys after cursor progress.
    /// Returns `None` when fewer than two keys remain, when the candidate
    /// would not advance past the cursor, or when it falls at or beyond the
    /// upper shard bound (which would produce an empty right shard).
    fn choose_split_point_bounds(
        &self,
        start: Option<&ItemKey>,
        end: Option<&ItemKey>,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let range_start = start.map_or(0, |bound| lower_bound(&self.items, bound.as_bytes()));
        let range_end = end.map_or(self.items.len(), |bound| {
            lower_bound(&self.items, bound.as_bytes())
        });
        let resume_start = cursor.last_key().map_or(range_start, |last| {
            upper_bound(&self.items, last.as_bytes())
        });

        let start_idx = range_start.max(resume_start);
        if range_end.saturating_sub(start_idx) < 2 {
            return Ok(None);
        }

        let split_idx = start_idx + (range_end - start_idx) / 2;
        let candidate = self.items[split_idx].key.clone();

        // Reject candidates that would not advance past the cursor. Splitting
        // behind or at the cursor position would assign already-processed keys
        // to the left shard, violating the forward-progress guarantee.
        if cursor.last_key().is_some_and(|last| &candidate <= last) {
            return Ok(None);
        }
        // Reject candidates at or beyond the upper bound. A split at exactly
        // `end` would produce an empty right shard [end, end), which is valid
        // but useless. Rejecting >= keeps both shards non-trivially sized.
        if end.is_some_and(|upper| &candidate >= upper) {
            return Ok(None);
        }

        Ok(Some(candidate))
    }

    /// Decode a shard bound.
    ///
    /// Empty bounds are treated as unbounded to match `ShardSpec` semantics.
    fn shard_bound(bound: &[u8], which: &'static str) -> Result<Option<ItemKey>, EnumerateError> {
        if bound.is_empty() {
            return Ok(None);
        }
        ItemKey::try_from_slice(bound)
            .map(Some)
            .map_err(|err| EnumerateError::permanent(format!("invalid shard {which} bound: {err}")))
    }

    /// Resolve an [`ItemRef`] into the backing bytes.
    ///
    /// `ItemRef` values are interpreted as big-endian indices into the sorted
    /// in-memory vector. This keeps references compact and deterministic, but
    /// also means references are connector-instance-local.
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

    fn enumerate_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        let start = Self::shard_bound(shard.key_range_start(), "start")?;
        let end = Self::shard_bound(shard.key_range_end(), "end")?;
        self.enumerate_page_bounds(start.as_ref(), end.as_ref(), cursor, budgets)
    }

    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        let start = Self::shard_bound(shard.key_range_start(), "start")?;
        let end = Self::shard_bound(shard.key_range_end(), "end")?;
        self.choose_split_point_bounds(start.as_ref(), end.as_ref(), cursor)
    }
}

impl ReadConnector for InMemoryDeterministicConnector {
    /// Eagerly rejects items whose total size exceeds `max_bytes` before
    /// returning the reader, since the full content is already in memory.
    fn open(
        &mut self,
        item_ref: &ItemRef,
        budgets: Budgets,
    ) -> Result<Box<dyn io::Read + Send>, ReadError> {
        let bytes = self.open_ref_internal(item_ref)?.clone();
        if bytes.len() as u64 > budgets.max_bytes() {
            return Err(ReadError::permanent("item exceeds max_bytes budget"));
        }
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

/// Return the first index whose key is `>= key`.
fn lower_bound(items: &[MemItem], key: &[u8]) -> usize {
    items.partition_point(|item| item.key.as_bytes() < key)
}

/// Return the first index whose key is `> key`.
///
/// Used to advance past the last emitted key, preventing duplicate emission
/// when resuming enumeration.
fn upper_bound(items: &[MemItem], key: &[u8]) -> usize {
    items.partition_point(|item| item.key.as_bytes() <= key)
}

/// Parse an 8-byte big-endian index.
///
/// Returning `None` for any non-8-byte input lets callers decide whether to
/// treat malformed values as permanent errors (`ItemRef`) or as advisory-state
/// misses (`Cursor` tokens).
fn parse_u64_be(bytes: &[u8]) -> Option<u64> {
    let array: [u8; 8] = bytes.try_into().ok()?;
    Some(u64::from_be_bytes(array))
}

/// Derive a stable per-key identity via the canonical [`ItemIdentityKey`] path.
///
/// This matches production connectors: the hash input includes both the
/// [`ConnectorTag`] and the key bytes under domain-separated BLAKE3, so
/// identical key bytes from different connectors produce distinct IDs.
fn derive_stable_item_id(connector: ConnectorTag, key: &ItemKey) -> StableItemId {
    ItemIdentityKey::new(connector, key.as_bytes()).stable_id()
}

#[cfg(test)]
#[path = "in_memory_tests.rs"]
mod tests;
