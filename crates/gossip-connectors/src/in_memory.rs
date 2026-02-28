//! Deterministic in-memory connector implementation.
//!
//! This connector is primarily useful where reproducibility matters more than
//! source realism (for example tests and harnesses). It keeps all data in
//! memory, sorts by key once at construction, and then serves enumeration/read
//! requests from immutable storage.
//!
//! Resume correctness is anchored on key ordering, not opaque tokens. Tokens are
//! emitted only when enabled and are accepted only when they agree with the
//! expected index derived from `Cursor::last_key`; malformed or stale tokens are
//! ignored so pagination still advances monotonically by key.

use std::{io, sync::Arc, time::Instant};

use gossip_contracts::{
    connector::{
        Budgets, ConnectorCapabilities, Cursor, EnumerateError, EnumerationConnector,
        EnumerationPage, ItemKey, ItemRef, ReadConnector, ReadError, ScanItem, TokenBytes,
        VersionId,
    },
    coordination::ShardSpec,
    identity::{ObjectVersionId, StableItemId},
};

/// One in-memory record served by [`InMemoryDeterministicConnector`].
///
/// A `MemItem` carries the minimum information needed to project into
/// `ScanItem`: a key for ordering/identity and bytes for content/version hash.
#[derive(Clone)]
pub struct MemItem {
    /// Item key used for lexicographic ordering and cursor progression.
    pub key: ItemKey,
    /// Immutable payload returned by [`ReadConnector`] operations.
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

/// Deterministic in-memory connector implementation.
///
/// # Determinism Contract
///
/// - Items are sorted lexicographically by [`ItemKey`] during construction.
/// - `ItemRef` values are encoded as big-endian `u64` indices into that sorted
///   vector.
/// - Stable IDs and version IDs are derived from BLAKE3 hashes of key/bytes.
///
/// Together these choices keep enumeration and reads reproducible across runs
/// for identical input vectors.
///
/// # Resume Semantics
///
/// Key-based resume (`Cursor::last_key`) is authoritative. Token resume is
/// optional and conservative: tokens are consumed only when enabled and exactly
/// consistent with the index implied by `last_key`.
pub struct InMemoryDeterministicConnector {
    items: Vec<MemItem>,
    emit_tokens: bool,
}

impl InMemoryDeterministicConnector {
    /// Build a connector from in-memory items.
    ///
    /// Sorting once up front shifts ordering cost out of steady-state
    /// enumeration, so page calls can rely on binary-search bounds and direct
    /// index iteration.
    pub fn new(mut items: Vec<MemItem>) -> Self {
        items.sort_by(|left, right| left.key.cmp(&right.key));
        Self {
            items,
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

    /// Enumerate one page in an explicit bounded range `[start, end)`.
    ///
    /// This bypasses `ShardSpec` decoding so tests can exercise the pagination
    /// logic directly with known-good bounds.
    pub fn enumerate_page_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<EnumerationPage, EnumerateError> {
        self.enumerate_page_bounds(Some(start), Some(end), cursor, budgets)
    }

    /// Return a split-point hint in an explicit bounded range `[start, end)`.
    ///
    /// This helper mirrors shard split behavior without requiring a full shard
    /// object, which keeps split-point tests focused and deterministic.
    pub fn choose_split_point_range(
        &mut self,
        start: &ItemKey,
        end: &ItemKey,
        cursor: &Cursor,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        self.choose_split_point_bounds(Some(start), Some(end), cursor)
    }

    /// Shared page enumeration logic for both shard-based and explicit ranges.
    ///
    /// The function enforces monotonic key progression by starting after
    /// `cursor.last_key()` and treating token state as advisory.
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

        let range_start = start.map_or(0, |bound| lower_bound(&self.items, bound.as_bytes()));
        let range_end =
            end.map_or(self.items.len(), |bound| lower_bound(&self.items, bound.as_bytes()));

        let mut start_idx = range_start;
        if let Some(last_key) = cursor.last_key() {
            let expected = upper_bound(&self.items, last_key.as_bytes());
            start_idx = start_idx.max(expected);

            // Tokens are accepted only as a consistency check against
            // key-derived position; they never override key ordering.
            if self.emit_tokens
                && let Some(token) = cursor.token()
                && let Some(token_idx_u64) = parse_u64_be(token.as_bytes())
                && let Ok(token_idx) = usize::try_from(token_idx_u64)
                && token_idx == expected
            {
                start_idx = start_idx.max(token_idx);
            }
        }

        if start_idx >= range_end {
            return Ok(EnumerationPage::new(Vec::new(), cursor.clone()));
        }

        let take = budgets.max_items().min(range_end - start_idx);
        let mut out = Vec::with_capacity(take);
        for idx in start_idx..(start_idx + take) {
            let item = &self.items[idx];
            let idx_u64 = u64::try_from(idx)
                .map_err(|_| EnumerateError::permanent("item index exceeds u64 capacity"))?;
            let item_ref = ItemRef::try_from_slice(&idx_u64.to_be_bytes())
                .map_err(|err| EnumerateError::permanent(format!("invalid item_ref: {err}")))?;

            let stable_item_id = derive_stable_item_id(&item.key);
            let version_id = derive_object_version_id(&item.bytes);
            let scan_item = ScanItem::new(
                item.key.clone(),
                item_ref,
                stable_item_id,
                VersionId::Strong(version_id),
            )
            .with_size_hint(item.bytes.len() as u64);
            out.push(scan_item);
        }

        let last_key = out
            .last()
            .expect("non-empty page must have a last key")
            .item_key()
            .clone();
        let mut next_cursor = Cursor::with_last_key(last_key.clone());

        if self.emit_tokens {
            let next_idx = u64::try_from(start_idx + out.len())
                .map_err(|_| EnumerateError::permanent("next index exceeds u64 capacity"))?;
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
        let range_end =
            end.map_or(self.items.len(), |bound| lower_bound(&self.items, bound.as_bytes()));
        let resume_start = cursor
            .last_key()
            .map_or(range_start, |last| upper_bound(&self.items, last.as_bytes()));

        let start_idx = range_start.max(resume_start);
        if range_end.saturating_sub(start_idx) < 2 {
            return Ok(None);
        }

        let split_idx = start_idx + (range_end - start_idx) / 2;
        let candidate = self.items[split_idx].key.clone();

        if cursor.last_key().is_some_and(|last| &candidate <= last) {
            return Ok(None);
        }
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
        let idx =
            usize::try_from(idx_u64).map_err(|_| ReadError::permanent("item_ref index too large"))?;

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
///
/// A hand-rolled binary search keeps ordering semantics explicit and mirrors
/// the companion `upper_bound` implementation used for cursor advancement.
fn lower_bound(items: &[MemItem], key: &[u8]) -> usize {
    let mut low = 0usize;
    let mut high = items.len();
    while low < high {
        let mid = low + (high - low) / 2;
        if items[mid].key.as_bytes() < key {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
}

/// Return the first index whose key is `> key`.
///
/// This is used to advance past the last emitted key, preventing duplicate
/// emission when resuming enumeration.
fn upper_bound(items: &[MemItem], key: &[u8]) -> usize {
    let mut low = 0usize;
    let mut high = items.len();
    while low < high {
        let mid = low + (high - low) / 2;
        if items[mid].key.as_bytes() <= key {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    low
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

/// Derive a stable per-key identity used to deduplicate across scans.
fn derive_stable_item_id(key: &ItemKey) -> StableItemId {
    let hash = blake3::hash(key.as_bytes());
    StableItemId::from_bytes(*hash.as_bytes())
}

/// Derive a strong content version identifier from payload bytes.
fn derive_object_version_id(bytes: &[u8]) -> ObjectVersionId {
    let hash = blake3::hash(bytes);
    ObjectVersionId::from_bytes(*hash.as_bytes())
}
