//! Set-associative cache for tree delta base bytes.
//!
//! Stores decompressed tree payloads keyed by `(pack_id, offset)` in
//! fixed-size slots backed by a pre-allocated arena. Uses the generic
//! [`super::cache_common`] framework with CLOCK eviction.
//!
//! Tree payloads larger than the slot size are not cached.

use super::cache_common::{CacheHandle, CacheSlot, SetAssociativeCache, SlotBase};
use super::pack_inflate::ObjectKind;

/// Extra metadata carried by delta cache handles.
#[derive(Clone, Copy, Debug)]
pub struct DeltaHandleExtra {
    kind: ObjectKind,
    chain_len: u8,
}

/// Cache slot for delta bases, keyed by `(pack_id, offset)`.
#[derive(Clone, Debug)]
struct DeltaSlot {
    pack_id: u16,
    /// Byte offset of the object within the pack.
    offset: u64,
    /// Resolved object kind of the base (e.g. Tree, Commit).
    kind: ObjectKind,
    /// Number of delta links traversed to reach this base (0 = non-delta).
    chain_len: u8,
    base: SlotBase,
}

impl CacheSlot for DeltaSlot {
    type Key = (u16, u64);
    type InsertArgs = (ObjectKind, u8);
    type HandleExtra = DeltaHandleExtra;

    fn empty() -> Self {
        Self {
            pack_id: 0,
            offset: 0,
            kind: ObjectKind::Tree,
            chain_len: 0,
            base: SlotBase::empty(),
        }
    }

    #[inline]
    fn base(&self) -> &SlotBase {
        &self.base
    }

    #[inline]
    fn base_mut(&mut self) -> &mut SlotBase {
        &mut self.base
    }

    #[inline]
    fn matches_key(&self, key: &(u16, u64)) -> bool {
        self.pack_id == key.0 && self.offset == key.1
    }

    fn write_key(&mut self, key: &(u16, u64), args: &(ObjectKind, u8)) {
        self.pack_id = key.0;
        self.offset = key.1;
        self.kind = args.0;
        self.chain_len = args.1;
    }

    fn update_existing(&mut self, args: &(ObjectKind, u8)) {
        self.kind = args.0;
        self.chain_len = args.1;
    }

    fn handle_extra(&self) -> DeltaHandleExtra {
        DeltaHandleExtra {
            kind: self.kind,
            chain_len: self.chain_len,
        }
    }

    fn hash_key(key: &(u16, u64)) -> u64 {
        let (pack_id, offset) = *key;
        let mut hash = offset ^ ((pack_id as u64) << 48);
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51afd7ed558ccd);
        hash ^= hash >> 33;
        hash
    }
}

/// Set-associative cache for tree delta base bytes.
///
/// See [`super::cache_common`] for layout, eviction, and pinning details.
/// When the capacity is too small the cache enters a disabled state where
/// all operations are no-ops; this avoids special-casing callers.
///
/// Not thread-safe; callers must synchronize shared access.
#[derive(Debug)]
pub struct TreeDeltaCache {
    inner: SetAssociativeCache<DeltaSlot>,
}

/// Handle to a pinned delta base stored in the cache.
///
/// While this handle exists the underlying slot is pinned (its pin count
/// is > 0), preventing the CLOCK eviction algorithm from reclaiming the
/// slot. Dropping the handle releases the pin.
///
/// In addition to the raw bytes, the handle carries the resolved
/// [`ObjectKind`] and `chain_len` so the delta resolver does not need a
/// second lookup.
///
/// # Lifetime constraint
///
/// The inner [`CacheHandle`] stores raw pointers into the cache's
/// heap-allocated storage buffers. Callers must ensure the cache is not
/// dropped while any handle is live.
#[derive(Debug)]
pub struct TreeDeltaCacheHandle {
    inner: CacheHandle<DeltaSlot>,
}

impl TreeDeltaCacheHandle {
    /// Returns the cached base bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    /// Returns the cached object kind.
    #[must_use]
    pub fn kind(&self) -> ObjectKind {
        self.inner.extra().kind
    }

    /// Returns the cached delta chain length for this base.
    #[must_use]
    pub fn chain_len(&self) -> u8 {
        self.inner.extra().chain_len
    }

    /// Returns the cached payload length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Returns true if the cached payload is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }
}

impl TreeDeltaCache {
    /// Creates a new cache sized to approximately `capacity_bytes`.
    ///
    /// The actual usable capacity may be slightly smaller: the constructor
    /// rounds `slot_size` down to a power of two and the set count down to
    /// a power of two so that set indexing is a simple bitmask.
    ///
    /// If the budget is too small for even one full set (`WAYS` ×
    /// `MIN_SLOT_SIZE`), the cache enters a disabled state where all
    /// operations are no-ops.
    #[must_use]
    pub fn new(capacity_bytes: u32) -> Self {
        Self {
            inner: SetAssociativeCache::new(capacity_bytes),
        }
    }

    /// Returns the configured capacity (rounded to usable bytes).
    #[must_use]
    pub const fn capacity_bytes(&self) -> u32 {
        self.inner.capacity_bytes()
    }

    /// Returns the fixed slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        self.inner.slot_size()
    }

    /// Looks up cached base bytes by `(pack_id, offset)` and returns a pinned handle.
    ///
    /// Returns `None` if the cache is disabled or if the entry is missing.
    /// On hit, the slot is pinned and the CLOCK bit is set.
    pub fn get_handle(&mut self, pack_id: u16, offset: u64) -> Option<TreeDeltaCacheHandle> {
        self.inner
            .get_handle(&(pack_id, offset))
            .map(|h| TreeDeltaCacheHandle { inner: h })
    }

    /// Inserts base bytes into the cache.
    ///
    /// If the key `(pack_id, offset)` is already present the clock bit is
    /// refreshed and `kind`/`chain_len` are updated without copying bytes
    /// (dedup fast path). Otherwise a victim slot is selected via the CLOCK
    /// algorithm and overwritten.
    ///
    /// Returns `true` if the entry was cached (including dedup hits).
    /// Returns `false` if the cache is disabled, the payload exceeds
    /// `slot_size`, or all candidate slots are pinned.
    pub fn insert(
        &mut self,
        pack_id: u16,
        offset: u64,
        kind: ObjectKind,
        chain_len: u8,
        bytes: &[u8],
    ) -> bool {
        self.inner
            .insert(&(pack_id, offset), &(kind, chain_len), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::super::cache_common::WAYS;
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = TreeDeltaCache::new(64 * 1024);
        let payload = b"tree-bytes";

        assert!(cache.insert(7, 42, ObjectKind::Tree, 0, payload));
        let handle = cache.get_handle(7, 42).unwrap();
        assert_eq!(handle.as_slice(), payload);
        assert_eq!(handle.kind(), ObjectKind::Tree);
        assert_eq!(handle.chain_len(), 0);
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = TreeDeltaCache::new(64 * 1024);
        let payload = vec![0u8; cache.slot_size() as usize + 1];

        assert!(!cache.insert(1, 99, ObjectKind::Tree, 0, &payload));
        assert!(cache.get_handle(1, 99).is_none());
    }

    #[test]
    fn eviction_within_set() {
        let mut cache = TreeDeltaCache::new(16 * 1024);
        let slots_total = cache.capacity_bytes() as usize / cache.slot_size() as usize;
        let sets = slots_total / WAYS;
        assert_eq!(sets, 1);

        let mut offsets = Vec::new();
        for i in 0..=WAYS {
            let offset = (i as u64) << 20;
            offsets.push(offset);
        }

        for offset in &offsets {
            assert!(cache.insert(1, *offset, ObjectKind::Tree, 0, b"x"));
        }

        let hits = offsets
            .iter()
            .filter(|offset| cache.get_handle(1, **offset).is_some())
            .count();
        assert!(hits <= WAYS);
    }

    #[test]
    fn reinsertion_updates_kind_and_chain_len() {
        let mut cache = TreeDeltaCache::new(64 * 1024);
        assert!(cache.insert(1, 42, ObjectKind::Tree, 0, b"data"));

        // Re-insert same key with different metadata.
        assert!(cache.insert(1, 42, ObjectKind::Commit, 5, b"ignored"));

        let handle = cache.get_handle(1, 42).unwrap();
        assert_eq!(handle.kind(), ObjectKind::Commit);
        assert_eq!(handle.chain_len(), 5);
        // Bytes should NOT have changed (dedup fast-path skips the copy).
        assert_eq!(handle.as_slice(), b"data");
    }
}
