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
//!    (domain-separated BLAKE3), [`ItemRef`] = big-endian index.
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
///   via [`ObjectVersionId::from_version_bytes`] (domain-separated BLAKE3),
///   both deterministic.
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
            // rather than legitimate staleness. The assert fires in debug/test
            // builds; in release builds it is stripped and the key-based position
            // remains authoritative (tokens are advisory per the module contract).
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
    /// The candidate is selected from remaining keys after cursor progress so
    /// the hint stays forward-only. Returning `None` means the remaining range
    /// is too small to split while keeping meaningful work on both sides.
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
mod tests {
    use std::io::Read as _;
    use std::time::{Duration, Instant};

    use gossip_contracts::connector::conformance::{ConformanceConfig, check_connector_conforms};

    use super::*;

    const TAG: ConnectorTag = ConnectorTag::from_ascii(b"inmemdet");

    fn make_key(s: &[u8]) -> ItemKey {
        ItemKey::try_from_slice(s).expect("test key")
    }

    fn make_item(key: &[u8], data: &[u8]) -> MemItem {
        MemItem::new(make_key(key), Vec::from(data))
    }

    fn default_budgets() -> Budgets {
        Budgets::try_new(100, u64::MAX, None).unwrap()
    }

    fn small_page_budgets(max_items: usize) -> Budgets {
        Budgets::try_new(max_items, u64::MAX, None).unwrap()
    }

    /// Collect all items from a connector by paging until empty.
    fn collect_all(
        connector: &mut InMemoryDeterministicConnector,
        start: &ItemKey,
        end: &ItemKey,
    ) -> Vec<ScanItem> {
        let mut all = Vec::new();
        let mut cursor = Cursor::initial();
        loop {
            let page = connector
                .enumerate_page_range(start, end, &cursor, default_budgets())
                .unwrap();
            if page.items().is_empty() {
                break;
            }
            cursor = page.next_cursor().clone();
            all.extend(page.into_parts().0);
        }
        all
    }

    // ---------------------------------------------------------------
    // Conformance harness integration
    // ---------------------------------------------------------------

    #[test]
    fn conformance_harness_passes() {
        let items = vec![
            make_item(b"alpha", b"data-a"),
            make_item(b"bravo", b"data-b"),
            make_item(b"charlie", b"data-c"),
            make_item(b"delta", b"data-d"),
            make_item(b"echo", b"data-e"),
        ];
        let start = make_key(b"a");
        let end = make_key(b"z");

        check_connector_conforms(
            || InMemoryDeterministicConnector::new(TAG, items.clone()),
            |c| c.caps(),
            |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
            &start,
            &end,
            ConformanceConfig::default(),
        )
        .expect("conformance harness should pass");
    }

    #[test]
    fn conformance_harness_no_tokens() {
        let items = vec![
            make_item(b"alpha", b"data-a"),
            make_item(b"bravo", b"data-b"),
            make_item(b"charlie", b"data-c"),
        ];
        let start = make_key(b"a");
        let end = make_key(b"z");

        check_connector_conforms(
            || InMemoryDeterministicConnector::new(TAG, items.clone()).with_tokens(false),
            |c| c.caps(),
            |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
            &start,
            &end,
            ConformanceConfig::default(),
        )
        .expect("conformance harness should pass without tokens");
    }

    #[test]
    fn conformance_harness_small_pages() {
        let items = vec![
            make_item(b"a1", b"1"),
            make_item(b"b2", b"2"),
            make_item(b"c3", b"3"),
            make_item(b"d4", b"4"),
            make_item(b"e5", b"5"),
        ];
        let start = make_key(b"a");
        let end = make_key(b"z");

        let cfg = ConformanceConfig {
            page_budgets: small_page_budgets(2),
            ..ConformanceConfig::default()
        };

        check_connector_conforms(
            || InMemoryDeterministicConnector::new(TAG, items.clone()),
            |c| c.caps(),
            |c, cursor, budgets| c.enumerate_page_range(&start, &end, cursor, budgets),
            &start,
            &end,
            cfg,
        )
        .expect("conformance harness should pass with small pages");
    }

    // ---------------------------------------------------------------
    // Empty set
    // ---------------------------------------------------------------

    #[test]
    fn empty_set_returns_empty_page() {
        let mut c = InMemoryDeterministicConnector::new(TAG, vec![]);
        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        assert!(page.items().is_empty());
    }

    // ---------------------------------------------------------------
    // Single item
    // ---------------------------------------------------------------

    #[test]
    fn single_item_enumeration_and_resume() {
        let items = vec![make_item(b"key", b"payload")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        // First page returns the single item.
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        assert_eq!(page.items().len(), 1);
        assert_eq!(page.items()[0].item_key().as_bytes(), b"key");

        // Resume from the cursor returns empty (exhausted).
        let page2 = c
            .enumerate_page_range(&start, &end, page.next_cursor(), default_budgets())
            .unwrap();
        assert!(page2.items().is_empty());
    }

    // ---------------------------------------------------------------
    // Expired budget
    // ---------------------------------------------------------------

    #[test]
    fn expired_budget_returns_empty_page() {
        let items = vec![make_item(b"key", b"payload")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        let expired =
            Budgets::try_new(100, u64::MAX, Some(Instant::now() - Duration::from_secs(1))).unwrap();
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), expired)
            .unwrap();
        assert!(page.items().is_empty());
    }

    // ---------------------------------------------------------------
    // Shard bounds that fall between/on items
    // ---------------------------------------------------------------

    #[test]
    fn shard_bounds_between_items() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
            make_item(b"d", b"4"),
        ];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        // Range [b, d) should yield b, c.
        let start = make_key(b"b");
        let end = make_key(b"d");
        let all = collect_all(&mut c, &start, &end);
        let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
        assert_eq!(keys, vec![b"b".as_slice(), b"c".as_slice()]);
    }

    #[test]
    fn shard_bounds_exact_on_items() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
        ];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        // Range [a, c) should yield a, b.
        let start = make_key(b"a");
        let end = make_key(b"c");
        let all = collect_all(&mut c, &start, &end);
        let keys: Vec<&[u8]> = all.iter().map(|i| i.item_key().as_bytes()).collect();
        assert_eq!(keys, vec![b"a".as_slice(), b"b".as_slice()]);
    }

    #[test]
    fn shard_bounds_no_items_in_range() {
        let items = vec![make_item(b"a", b"1"), make_item(b"z", b"2")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        let start = make_key(b"m");
        let end = make_key(b"n");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        assert!(page.items().is_empty());
    }

    // ---------------------------------------------------------------
    // Token-enabled vs token-disabled parity
    // ---------------------------------------------------------------

    #[test]
    fn token_enabled_vs_disabled_parity() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
        ];
        let start = make_key(b"a");
        let end = make_key(b"z");

        let mut with_tokens = InMemoryDeterministicConnector::new(TAG, items.clone());
        let mut without_tokens = InMemoryDeterministicConnector::new(TAG, items).with_tokens(false);

        let items_a = collect_all(&mut with_tokens, &start, &end);
        let items_b = collect_all(&mut without_tokens, &start, &end);

        // Same items, same order.
        assert_eq!(items_a.len(), items_b.len());
        for (a, b) in items_a.iter().zip(items_b.iter()) {
            assert_eq!(a.item_key(), b.item_key());
            assert_eq!(a.stable_item_id(), b.stable_item_id());
            assert_eq!(a.version(), b.version());
        }
    }

    // ---------------------------------------------------------------
    // Split point tests
    // ---------------------------------------------------------------

    #[test]
    fn split_point_fewer_than_two_remaining_returns_none() {
        let items = vec![make_item(b"only", b"1")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        let split = c
            .choose_split_point_range(&start, &end, &Cursor::initial())
            .unwrap();
        assert!(split.is_none());
    }

    #[test]
    fn split_point_empty_set_returns_none() {
        let mut c = InMemoryDeterministicConnector::new(TAG, vec![]);
        let start = make_key(b"a");
        let end = make_key(b"z");

        let split = c
            .choose_split_point_range(&start, &end, &Cursor::initial())
            .unwrap();
        assert!(split.is_none());
    }

    #[test]
    fn split_point_cursor_past_midpoint_returns_none() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
        ];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        // Advance cursor past b — only c remains, fewer than 2.
        let cursor = Cursor::with_last_key(make_key(b"b"));
        let split = c.choose_split_point_range(&start, &end, &cursor).unwrap();
        assert!(split.is_none());
    }

    #[test]
    fn split_point_valid_returns_key_between_bounds() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
            make_item(b"d", b"4"),
        ];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        let split = c
            .choose_split_point_range(&start, &end, &Cursor::initial())
            .unwrap();
        let split = split.expect("should produce a split point");
        assert!(split > make_key(b"a"));
        assert!(split < make_key(b"z"));
    }

    // ---------------------------------------------------------------
    // ReadConnector: read_range edge cases
    // ---------------------------------------------------------------

    #[test]
    fn read_range_offset_beyond_length_returns_zero() {
        let items = vec![make_item(b"key", b"short")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        // Get the ItemRef from enumeration.
        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        let item_ref = page.items()[0].item_ref().clone();

        let mut buf = [0u8; 32];
        let n = c
            .read_range(&item_ref, 1000, &mut buf, default_budgets())
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_range_zero_length_dst_returns_zero() {
        let items = vec![make_item(b"key", b"payload")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        let item_ref = page.items()[0].item_ref().clone();

        let mut buf = [];
        let n = c
            .read_range(&item_ref, 0, &mut buf, default_budgets())
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn read_range_overflow_offset_returns_error() {
        let items = vec![make_item(b"key", b"payload")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        let item_ref = page.items()[0].item_ref().clone();

        let mut buf = [0u8; 16];
        let result = c.read_range(&item_ref, u64::MAX, &mut buf, default_budgets());
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // ReadConnector: open
    // ---------------------------------------------------------------

    #[test]
    fn open_reads_full_content() {
        let items = vec![make_item(b"key", b"hello world")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        let item_ref = page.items()[0].item_ref().clone();

        let mut reader = c.open(&item_ref, default_budgets()).unwrap();
        let mut buf = Vec::new();
        reader.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello world");
    }

    #[test]
    fn open_budget_exceeded_returns_error() {
        let items = vec![make_item(b"key", b"large payload here")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        let start = make_key(b"a");
        let end = make_key(b"z");
        let page = c
            .enumerate_page_range(&start, &end, &Cursor::initial(), default_budgets())
            .unwrap();
        let item_ref = page.items()[0].item_ref().clone();

        // Budget smaller than the payload.
        let small_budget = Budgets::try_new(100, 5, None).unwrap();
        let result = c.open(&item_ref, small_budget);
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------
    // Invalid/out-of-bounds ItemRef
    // ---------------------------------------------------------------

    #[test]
    fn invalid_item_ref_returns_error() {
        let items = vec![make_item(b"key", b"data")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        // Index 999 is out of bounds.
        let bad_ref = ItemRef::try_from_slice(&999u64.to_be_bytes()).unwrap();
        assert!(c.open(&bad_ref, default_budgets()).is_err());

        let mut buf = [0u8; 16];
        assert!(
            c.read_range(&bad_ref, 0, &mut buf, default_budgets())
                .is_err()
        );
    }

    #[test]
    fn malformed_item_ref_returns_error() {
        let items = vec![make_item(b"key", b"data")];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);

        // Not 8 bytes — malformed.
        let bad_ref = ItemRef::try_from_slice(b"short").unwrap();
        assert!(c.open(&bad_ref, default_budgets()).is_err());
    }

    // ---------------------------------------------------------------
    // Capabilities
    // ---------------------------------------------------------------

    #[test]
    fn caps_reflect_token_setting() {
        let c_with = InMemoryDeterministicConnector::new(TAG, vec![]);
        assert!(c_with.caps().token_resume);

        let c_without = InMemoryDeterministicConnector::new(TAG, vec![]).with_tokens(false);
        assert!(!c_without.caps().token_resume);
    }

    // ---------------------------------------------------------------
    // Pagination with small budgets
    // ---------------------------------------------------------------

    #[test]
    fn pagination_respects_max_items_budget() {
        let items = vec![
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
            make_item(b"c", b"3"),
            make_item(b"d", b"4"),
            make_item(b"e", b"5"),
        ];
        let mut c = InMemoryDeterministicConnector::new(TAG, items);
        let start = make_key(b"a");
        let end = make_key(b"z");

        // Page size 2: should get 3 pages (2+2+1).
        let budgets = small_page_budgets(2);
        let mut cursor = Cursor::initial();
        let mut total = 0;
        let mut page_count = 0;
        loop {
            let page = c
                .enumerate_page_range(&start, &end, &cursor, budgets)
                .unwrap();
            if page.items().is_empty() {
                break;
            }
            assert!(page.items().len() <= 2);
            total += page.items().len();
            page_count += 1;
            cursor = page.next_cursor().clone();
        }
        assert_eq!(total, 5);
        assert_eq!(page_count, 3);
    }

    // ---------------------------------------------------------------
    // Determinism: two connectors from same input
    // ---------------------------------------------------------------

    #[test]
    fn determinism_same_input_same_output() {
        let items = vec![
            make_item(b"c", b"3"),
            make_item(b"a", b"1"),
            make_item(b"b", b"2"),
        ];
        let start = make_key(b"a");
        let end = make_key(b"z");

        let mut c1 = InMemoryDeterministicConnector::new(TAG, items.clone());
        let mut c2 = InMemoryDeterministicConnector::new(TAG, items);

        let items1 = collect_all(&mut c1, &start, &end);
        let items2 = collect_all(&mut c2, &start, &end);

        assert_eq!(items1.len(), items2.len());
        for (a, b) in items1.iter().zip(items2.iter()) {
            assert_eq!(a.item_key(), b.item_key());
            assert_eq!(a.item_ref(), b.item_ref());
            assert_eq!(a.stable_item_id(), b.stable_item_id());
            assert_eq!(a.version(), b.version());
        }
    }

    // ---------------------------------------------------------------
    // Identity derivation uses domain separation
    // ---------------------------------------------------------------

    #[test]
    fn different_tags_produce_different_stable_ids() {
        let tag_a = ConnectorTag::from_ascii(b"tagA");
        let tag_b = ConnectorTag::from_ascii(b"tagB");
        let key = make_key(b"same-key");

        let id_a = derive_stable_item_id(tag_a, &key);
        let id_b = derive_stable_item_id(tag_b, &key);
        assert_ne!(id_a, id_b);
    }

    // ---------------------------------------------------------------
    // Property-based tests
    // ---------------------------------------------------------------

    mod prop {
        use super::*;
        use proptest::collection::vec as pvec;
        use proptest::prelude::*;

        /// Strategy: generate 0..max_items unique keys as short byte strings.
        fn item_vec_strategy(max_items: usize) -> impl Strategy<Value = Vec<MemItem>> {
            pvec(pvec(1u8..=127u8, 1..8usize), 0..max_items).prop_map(|key_vecs| {
                // Deduplicate keys.
                let mut seen = std::collections::HashSet::new();
                key_vecs
                    .into_iter()
                    .filter(|k| seen.insert(k.clone()))
                    .map(|k| {
                        let data = k.clone();
                        make_item(&k, &data)
                    })
                    .collect()
            })
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(64))]

            #[test]
            fn full_enum_yields_sorted_input(items in item_vec_strategy(30)) {
                let start = make_key(b"\x01");
                let end = make_key(b"\x80");
                let mut expected_keys: Vec<Vec<u8>> = items
                    .iter()
                    .map(|i| i.key.as_bytes().to_vec())
                    .collect();
                expected_keys.sort();
                expected_keys.dedup();
                // Filter to range [start, end).
                let expected_keys: Vec<Vec<u8>> = expected_keys
                    .into_iter()
                    .filter(|k| k.as_slice() >= b"\x01" && k.as_slice() < b"\x80")
                    .collect();

                let mut c = InMemoryDeterministicConnector::new(TAG, items);
                let all = collect_all(&mut c, &start, &end);
                let got_keys: Vec<Vec<u8>> = all
                    .iter()
                    .map(|i| i.item_key().as_bytes().to_vec())
                    .collect();

                prop_assert_eq!(got_keys, expected_keys);
            }

            #[test]
            fn token_vs_no_token_same_items(items in item_vec_strategy(20)) {
                let start = make_key(b"\x01");
                let end = make_key(b"\x80");

                let mut with = InMemoryDeterministicConnector::new(TAG, items.clone());
                let mut without = InMemoryDeterministicConnector::new(TAG, items)
                    .with_tokens(false);

                let a = collect_all(&mut with, &start, &end);
                let b = collect_all(&mut without, &start, &end);

                prop_assert_eq!(a.len(), b.len());
                for (x, y) in a.iter().zip(b.iter()) {
                    prop_assert_eq!(x.item_key(), y.item_key());
                }
            }

            #[test]
            fn split_point_strictly_between_cursor_and_end(
                items in item_vec_strategy(30),
            ) {
                let start = make_key(b"\x01");
                let end = make_key(b"\x80");
                let mut c = InMemoryDeterministicConnector::new(TAG, items);

                if let Ok(Some(split)) = c.choose_split_point_range(
                    &start, &end, &Cursor::initial(),
                ) {
                    prop_assert!(split > start);
                    prop_assert!(split < end);
                }
            }

            #[test]
            fn determinism_property(items in item_vec_strategy(20)) {
                let start = make_key(b"\x01");
                let end = make_key(b"\x80");

                let mut c1 = InMemoryDeterministicConnector::new(TAG, items.clone());
                let mut c2 = InMemoryDeterministicConnector::new(TAG, items);

                let a = collect_all(&mut c1, &start, &end);
                let b = collect_all(&mut c2, &start, &end);

                prop_assert_eq!(a.len(), b.len());
                for (x, y) in a.iter().zip(b.iter()) {
                    prop_assert_eq!(x.item_key(), y.item_key());
                    prop_assert_eq!(x.item_ref(), y.item_ref());
                    prop_assert_eq!(x.stable_item_id(), y.stable_item_id());
                    prop_assert_eq!(x.version(), y.version());
                }
            }
        }
    }
}
