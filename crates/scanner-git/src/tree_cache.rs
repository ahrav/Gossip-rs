//! Set-associative cache for tree object bytes.
//!
//! Stores decompressed tree payloads in fixed-size slots backed by a
//! pre-allocated arena. Uses the generic [`super::cache_common`] framework
//! with [`OidBytes`] keys and CLOCK eviction.
//!
//! Tree payloads larger than the slot size are not cached.

use super::cache_common::{CacheHandle, CacheSlot, SetAssociativeCache, SlotBase};
use super::object_id::OidBytes;

/// Cache slot for tree payloads, keyed by OID.
#[derive(Clone, Debug)]
struct TreeSlot {
    oid: OidBytes,
    base: SlotBase,
}

impl CacheSlot for TreeSlot {
    type Key = OidBytes;
    type InsertArgs = ();
    type HandleExtra = ();

    fn empty() -> Self {
        Self {
            oid: OidBytes::default(),
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
    fn matches_key(&self, key: &OidBytes) -> bool {
        self.oid == *key
    }

    fn write_key(&mut self, key: &OidBytes, _args: &()) {
        self.oid = *key;
    }

    fn update_existing(&mut self, _args: &()) {}

    fn handle_extra(&self) {}

    fn hash_key(key: &OidBytes) -> u64 {
        let bytes = key.as_slice();
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[..8]);
        u64::from_le_bytes(buf)
    }
}

/// Set-associative cache for tree payload bytes.
///
/// See [`super::cache_common`] for layout, eviction, and pinning details.
/// When the capacity is too small the cache enters a disabled state where
/// all operations are no-ops; this avoids special-casing callers.
///
/// Not thread-safe; callers must synchronize shared access.
#[derive(Debug)]
pub struct TreeCache {
    inner: SetAssociativeCache<TreeSlot>,
}

/// Handle to a pinned tree payload stored in the cache.
///
/// While this handle exists the underlying slot is pinned (its pin count
/// is > 0), preventing the CLOCK eviction algorithm from reclaiming the
/// slot. Dropping the handle releases the pin.
///
/// # Lifetime constraint
///
/// The inner [`CacheHandle`] stores raw pointers into the cache's
/// heap-allocated storage buffers. Callers must ensure the cache is not
/// dropped while any handle is live. This is a runtime contract; it is
/// not enforced by Rust lifetimes.
#[derive(Debug)]
pub struct TreeCacheHandle {
    inner: CacheHandle<TreeSlot>,
}

impl TreeCacheHandle {
    /// Returns the cached tree bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }
}

impl TreeCache {
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

    /// Returns the configured capacity (rounded to usable bytes, or the
    /// raw input when the cache is disabled).
    #[must_use]
    pub const fn capacity_bytes(&self) -> u32 {
        self.inner.capacity_bytes()
    }

    /// Returns the fixed slot size in bytes.
    #[must_use]
    pub const fn slot_size(&self) -> u32 {
        self.inner.slot_size()
    }

    /// Looks up cached tree bytes by OID and returns a pinned handle.
    ///
    /// Returns `None` if the cache is disabled, the entry is missing, or
    /// the slot's pin count is saturated (`u16::MAX`).
    /// On hit, the slot is pinned and the CLOCK bit is set.
    pub fn get_handle(&mut self, oid: &OidBytes) -> Option<TreeCacheHandle> {
        self.inner
            .get_handle(oid)
            .map(|h| TreeCacheHandle { inner: h })
    }

    /// Inserts tree bytes into the cache.
    ///
    /// If the OID is already present the clock bit is refreshed without
    /// copying bytes (dedup fast path). Otherwise a victim slot is selected
    /// via the CLOCK algorithm and overwritten.
    ///
    /// Returns `true` if the entry was cached (including dedup hits).
    /// Returns `false` if the cache is disabled, the payload exceeds
    /// `slot_size`, or all candidate slots are pinned.
    pub fn insert(&mut self, oid: OidBytes, bytes: &[u8]) -> bool {
        self.inner.insert(&oid, &(), bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::super::cache_common::{MIN_SLOT_SIZE, WAYS};
    use super::*;

    #[test]
    fn insert_and_get() {
        let mut cache = TreeCache::new(64 * 1024);
        let oid = OidBytes::sha1([0x11; 20]);
        let payload = b"tree-bytes";

        assert!(cache.insert(oid, payload));
        let handle = cache.get_handle(&oid).unwrap();
        assert_eq!(handle.as_slice(), payload);
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = TreeCache::new(64 * 1024);
        let oid = OidBytes::sha1([0x22; 20]);
        let payload = vec![0u8; cache.slot_size() as usize + 1];

        assert!(!cache.insert(oid, &payload));
        assert!(cache.get_handle(&oid).is_none());
    }

    #[test]
    fn eviction_within_set() {
        let mut cache = TreeCache::new(64 * 1024);
        assert!(cache.capacity_bytes() > 0);

        let mut oids = Vec::new();
        for i in 0..=WAYS {
            let mut bytes = [0u8; 20];
            bytes[..8].copy_from_slice(&[0x55; 8]);
            bytes[8] = i as u8;
            oids.push(OidBytes::sha1(bytes));
        }

        for (idx, oid) in oids.iter().enumerate() {
            let data = vec![idx as u8];
            assert!(cache.insert(*oid, &data));
        }

        assert!(cache.get_handle(&oids[0]).is_none());
        let mut hit_count = 0;
        for oid in oids.iter().skip(1) {
            if cache.get_handle(oid).is_some() {
                hit_count += 1;
            }
        }
        assert!(hit_count >= 1);
    }

    #[test]
    fn disabled_when_capacity_too_small() {
        let mut cache = TreeCache::new(MIN_SLOT_SIZE * WAYS as u32 - 1);
        let oid = OidBytes::sha1([0x33; 20]);
        assert!(!cache.insert(oid, b"data"));
        assert!(cache.get_handle(&oid).is_none());
    }
}
