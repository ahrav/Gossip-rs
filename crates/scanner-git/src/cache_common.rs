//! Generic set-associative cache with CLOCK eviction.
//!
//! Provides a reusable cache framework parameterized over slot metadata.
//! Cache-specific slot types implement [`CacheSlot`] to specialize key
//! matching, hashing, and per-handle metadata. Concrete caches
//! ([`super::tree_cache::TreeCache`], [`super::tree_delta_cache::TreeDeltaCache`])
//! compose [`SetAssociativeCache`] with those slot types.
//!
//! # Layout
//! - `WAYS` slots per set (fixed at 4)
//! - Number of sets is rounded down to a power of two
//! - Each slot owns a fixed `slot_size` byte range in a pre-allocated arena
//!
//! # Invariants
//! - `sets` is 0 (disabled) or a power of two
//! - `slot_size` is a power of two >= `MIN_SLOT_SIZE`, or 0 when disabled
//! - `storage.len() == sets * WAYS * slot_size` (0 when disabled)
//! - Pinned slots are never evicted; handles must be dropped to release pins
//! - In debug builds, stale handles panic if used or dropped after cache drop
//!
//! # Why raw pointers in `CacheHandle`?
//!
//! A lifetime-parameterized `CacheHandle<'cache, S>` would be the ideal
//! Rust approach, but it is not viable here.  Handles are stored inside
//! the `TreeBytes` enum which lives in `DiffFrame` stack frames during
//! tree-diff traversal.  Those frames outlive any `&mut self` borrow of
//! the cache, so a lifetime parameter would create an unresolvable
//! conflict: the cache needs `&mut self` for insertions while existing
//! handles are still live in ancestor frames.
//!
//! The raw-pointer approach is safe under these invariants:
//! - **Single-threaded**: the cache is only accessed from one worker thread.
//! - **No reallocation**: `storage` and `slots` `Vec`s are allocated once
//!   in `new()` and never resized, so heap pointers remain stable.
//! - **Pin-based eviction prevention**: a non-zero pin count on a slot
//!   prevents the CLOCK eviction sweep from reusing that slot, ensuring
//!   the pointed-to bytes are not overwritten while a handle exists.
//!
//! # Design rationale
//!
//! - **CLOCK over LRU**: CLOCK requires only a single reference bit per
//!   slot (O(1) metadata per access) and avoids the linked-list pointer
//!   chasing that LRU demands on every hit.
//! - **WAYS = 4**: balances conflict-miss rate against scan cost.  With 4
//!   ways per set, a lookup or eviction sweep inspects at most 8 slots
//!   (4 valid + 4 clock sweeps in the worst case).
//! - **MIN_SLOT_SIZE = 256**: prevents degenerate configurations with too
//!   many tiny sets, which would increase conflict rates without improving
//!   hit ratios for the tree-object payloads this cache targets.

use std::cell::Cell;
use std::fmt::Debug;
#[cfg(debug_assertions)]
use std::rc::Rc;

/// Default slot size for cached payloads.
const DEFAULT_SLOT_SIZE: u32 = 4096;
/// Minimum slot size (prevents tiny, inefficient caches).
pub(super) const MIN_SLOT_SIZE: u32 = 256;
/// Number of ways per set.
pub(super) const WAYS: usize = 4;

#[cfg(debug_assertions)]
#[derive(Debug)]
struct HandleEpoch {
    generation: Cell<u64>,
    alive: Cell<bool>,
}

#[cfg(debug_assertions)]
impl HandleEpoch {
    #[inline]
    fn new() -> Self {
        Self {
            generation: Cell::new(1),
            alive: Cell::new(true),
        }
    }

    #[inline]
    fn snapshot(&self) -> u64 {
        self.generation.get()
    }

    #[inline]
    fn is_live_generation(&self, generation: u64) -> bool {
        self.alive.get() && self.generation.get() == generation
    }

    #[inline]
    fn invalidate(&self) {
        self.alive.set(false);
        self.generation.set(self.generation.get().wrapping_add(1));
    }
}

/// Common fields shared by every cache slot.
#[derive(Clone, Debug)]
pub(super) struct SlotBase {
    /// Byte length of the stored payload (≤ slot_size).
    pub(super) len: u32,
    /// CLOCK reference bit: 1 = recently accessed, 0 = eligible for eviction.
    pub(super) clock: u8,
    /// True if this slot contains a valid cached entry.
    pub(super) valid: bool,
    /// Pin counter via interior mutability; >0 prevents eviction.
    pub(super) pins: Cell<u16>,
}

impl SlotBase {
    /// Returns a zeroed-out, invalid slot base.
    #[inline]
    pub(super) fn empty() -> Self {
        Self {
            len: 0,
            clock: 0,
            valid: false,
            pins: Cell::new(0),
        }
    }
}

/// Trait that cache slots must implement to specialize the generic cache.
///
/// `Key` is the lookup/insertion key (e.g. `OidBytes` or `(u16, u64)`).
/// `InsertArgs` carries any extra metadata stored alongside the key
/// (e.g. `ObjectKind` + `chain_len`); use `()` when there is none.
/// `HandleExtra` is the extra data surfaced on cache-hit handles.
pub(super) trait CacheSlot: Clone + Debug {
    type Key;
    type InsertArgs;
    type HandleExtra: Copy;

    fn empty() -> Self;
    fn base(&self) -> &SlotBase;
    fn base_mut(&mut self) -> &mut SlotBase;

    /// Returns `true` if this valid slot matches `key`.
    fn matches_key(&self, key: &Self::Key) -> bool;

    /// Writes the key (and any extra metadata from `args`) into the slot.
    /// The caller sets `base.len`, `base.clock`, `base.valid`, and `base.pins`.
    fn write_key(&mut self, key: &Self::Key, args: &Self::InsertArgs);

    /// Updates extra metadata on an already-matching slot (re-insertion).
    fn update_existing(&mut self, args: &Self::InsertArgs);

    /// Extracts extra metadata for a cache-hit handle.
    fn handle_extra(&self) -> Self::HandleExtra;

    /// Hashes the key for set selection.
    fn hash_key(key: &Self::Key) -> u64;
}

/// Set-associative cache with CLOCK eviction, generic over slot type.
#[derive(Debug)]
pub(super) struct SetAssociativeCache<S: CacheSlot> {
    capacity_bytes: u32,
    slot_size: u32,
    sets: usize,
    storage: Vec<u8>,
    slots: Vec<S>,
    clock_hands: Vec<u8>,
    #[cfg(debug_assertions)]
    handle_epoch: Rc<HandleEpoch>,
}

/// Handle to a pinned payload stored in the cache.
///
/// Keeps the slot pinned until drop so cached bytes are not overwritten
/// while the caller is still borrowing them.
///
/// # Safety
///
/// The handle stores raw pointers directly into the heap-allocated
/// `Vec<u8>` (storage) and `Vec<S>` (slots) buffers owned by the parent
/// [`SetAssociativeCache`]. These heap pointers remain valid as long as
/// the backing `Vec`s are not reallocated or dropped — which is
/// guaranteed because:
/// - `storage` is never resized after construction.
/// - `slots` is never resized after construction.
/// - The cache must not be dropped while handles are live.
///
/// Callers must ensure the [`SetAssociativeCache`] outlives every handle
/// obtained from it. In practice this is enforced structurally: handles
/// are created and consumed within the same tree-walk scope.
///
/// In debug builds, each handle snapshots a cache generation token.
/// `as_slice()` and `drop` panic if the cache has already been dropped.
pub(super) struct CacheHandle<S: CacheSlot> {
    /// Pointer to the start of this slot's byte range in the storage arena.
    data: *const u8,
    /// Pointer to the slot's pin counter (heap-allocated in the slots vec).
    pins: *const Cell<u16>,
    len: usize,
    extra: S::HandleExtra,
    #[cfg(debug_assertions)]
    handle_epoch: Rc<HandleEpoch>,
    #[cfg(debug_assertions)]
    handle_generation: u64,
    _marker: std::marker::PhantomData<S>,
}

// Manual Debug: PhantomData is fine, but we want a meaningful debug repr.
impl<S: CacheSlot> std::fmt::Debug for CacheHandle<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CacheHandle")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<S: CacheSlot> CacheHandle<S> {
    #[cfg(debug_assertions)]
    #[inline]
    fn debug_assert_live(&self, op: &'static str) {
        if !self.handle_epoch.is_live_generation(self.handle_generation) {
            panic!("stale cache handle used in {op}");
        }
    }

    /// Returns the cached bytes.
    #[must_use]
    pub(super) fn as_slice(&self) -> &[u8] {
        #[cfg(debug_assertions)]
        self.debug_assert_live("as_slice");

        // SAFETY: `data` points into the cache's heap-allocated storage
        // arena. The arena is never reallocated after construction, and
        // the pinned slot prevents the cache from overwriting these bytes.
        // Callers ensure the cache outlives the handle.
        unsafe { std::slice::from_raw_parts(self.data, self.len) }
    }

    /// Returns the handle's extra metadata.
    #[must_use]
    #[inline]
    pub(super) fn extra(&self) -> S::HandleExtra {
        self.extra
    }

    /// Returns the cached payload length in bytes.
    #[must_use]
    #[inline]
    pub(super) const fn len(&self) -> usize {
        self.len
    }

    /// Returns true if the cached payload is empty.
    #[must_use]
    #[inline]
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl<S: CacheSlot> Drop for CacheHandle<S> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        if !self.handle_epoch.is_live_generation(self.handle_generation) {
            // Avoid a double panic if a stale-handle panic is already unwinding.
            if std::thread::panicking() {
                return;
            }
            panic!("stale cache handle dropped after cache invalidation");
        }

        // SAFETY: `pins` points into the cache's heap-allocated slot vec.
        // The slot vec is never reallocated after construction, and callers
        // ensure the cache outlives the handle.
        unsafe {
            let pins = &*self.pins;
            let count = pins.get();
            assert!(count > 0, "cache pin count underflow");
            pins.set(count.saturating_sub(1));
        }
    }
}

impl<S: CacheSlot> Drop for SetAssociativeCache<S> {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        self.handle_epoch.invalidate();
    }
}

impl<S: CacheSlot> SetAssociativeCache<S> {
    /// Creates a new cache with a byte capacity.
    ///
    /// If the capacity is too small to hold at least one set, the cache is
    /// initialized in a disabled state (all operations are no-ops).
    #[must_use]
    pub(super) fn new(capacity_bytes: u32) -> Self {
        let min_bytes = MIN_SLOT_SIZE.saturating_mul(WAYS as u32);
        if capacity_bytes < min_bytes {
            return Self::disabled(capacity_bytes);
        }

        let mut slot_size = (capacity_bytes / WAYS as u32).min(DEFAULT_SLOT_SIZE);
        slot_size = round_down_power_of_two_u32(slot_size).max(MIN_SLOT_SIZE);

        let slots_total = capacity_bytes / slot_size;
        let sets = round_down_power_of_two_usize((slots_total / WAYS as u32) as usize);
        if sets == 0 {
            return Self::disabled(capacity_bytes);
        }

        let total_slots = sets * WAYS;
        let storage_len = (total_slots as u32).saturating_mul(slot_size) as usize;

        Self {
            capacity_bytes: storage_len as u32,
            slot_size,
            sets,
            storage: vec![0u8; storage_len],
            slots: vec![S::empty(); total_slots],
            clock_hands: vec![0u8; sets],
            #[cfg(debug_assertions)]
            handle_epoch: Rc::new(HandleEpoch::new()),
        }
    }

    /// Returns the configured capacity in bytes.
    ///
    /// When the cache is enabled, this is rounded to a multiple of the slot size.
    /// When disabled, this returns the raw input capacity.
    #[must_use]
    pub(super) const fn capacity_bytes(&self) -> u32 {
        self.capacity_bytes
    }

    /// Returns the fixed slot size in bytes.
    #[must_use]
    pub(super) const fn slot_size(&self) -> u32 {
        self.slot_size
    }

    /// Looks up cached bytes by key and returns a pinned handle.
    ///
    /// Returns `None` if the cache is disabled, the entry is missing, or
    /// the slot's pin count is at `u16::MAX` (saturated).
    /// On hit, the slot is pinned and the CLOCK bit is set.
    pub(super) fn get_handle(&mut self, key: &S::Key) -> Option<CacheHandle<S>> {
        if self.sets == 0 {
            return None;
        }

        let set = self.set_index(key);
        let base = set * WAYS;
        for way in 0..WAYS {
            let idx = base + way;
            let slot = &mut self.slots[idx];
            if slot.base().valid && slot.matches_key(key) {
                let new_pins = slot.base().pins.get().checked_add(1)?;
                slot.base_mut().clock = 1;
                slot.base().pins.set(new_pins);
                let extra = slot.handle_extra();
                let len = slot.base().len as usize;
                let offset = idx * self.slot_size as usize;
                #[cfg(debug_assertions)]
                let handle_generation = self.handle_epoch.snapshot();
                // SAFETY: `storage` and `slots` are heap-allocated Vecs
                // that are never resized after construction. The raw
                // pointers point directly into these heap buffers.
                let data = unsafe { self.storage.as_ptr().add(offset) };
                let pins = &slot.base().pins as *const Cell<u16>;
                return Some(CacheHandle {
                    data,
                    pins,
                    len,
                    extra,
                    #[cfg(debug_assertions)]
                    handle_epoch: Rc::clone(&self.handle_epoch),
                    #[cfg(debug_assertions)]
                    handle_generation,
                    _marker: std::marker::PhantomData,
                });
            }
        }
        None
    }

    /// Inserts bytes into the cache.
    ///
    /// Returns true if the entry was cached. Returns false if the cache is
    /// disabled, the payload is too large for a slot, or all candidate slots
    /// are pinned.
    #[must_use]
    pub(super) fn insert(&mut self, key: &S::Key, args: &S::InsertArgs, bytes: &[u8]) -> bool {
        if self.sets == 0 {
            return false;
        }
        if bytes.len() > self.slot_size as usize {
            return false;
        }

        let set = self.set_index(key);
        let base_idx = set * WAYS;

        for way in 0..WAYS {
            let idx = base_idx + way;
            let slot = &mut self.slots[idx];
            if slot.base().valid && slot.matches_key(key) {
                slot.base_mut().clock = 1;
                slot.update_existing(args);
                return true;
            }
        }

        let Some(victim) = self.select_victim(base_idx, set) else {
            return false;
        };
        self.write_slot(victim, key, args, bytes);
        true
    }

    fn disabled(capacity_bytes: u32) -> Self {
        Self {
            capacity_bytes,
            slot_size: 0,
            sets: 0,
            storage: Vec::new(),
            slots: Vec::new(),
            clock_hands: Vec::new(),
            #[cfg(debug_assertions)]
            handle_epoch: Rc::new(HandleEpoch::new()),
        }
    }

    #[inline]
    fn set_index(&self, key: &S::Key) -> usize {
        let hash = S::hash_key(key);
        hash as usize & (self.sets - 1)
    }

    fn select_victim(&mut self, base: usize, set: usize) -> Option<usize> {
        // CLOCK: pick the first slot with clock=0, clearing clock bits as we go.
        let mut hand = self.clock_hands[set] as usize % WAYS;
        for _ in 0..(WAYS * 2) {
            let idx = base + hand;
            let pins = self.slots[idx].base().pins.get();
            if pins > 0 {
                hand = (hand + 1) % WAYS;
                continue;
            }
            let slot = &mut self.slots[idx];
            if !slot.base().valid || slot.base().clock == 0 {
                self.clock_hands[set] = ((hand + 1) % WAYS) as u8;
                return Some(idx);
            }
            slot.base_mut().clock = 0;
            hand = (hand + 1) % WAYS;
        }

        None
    }

    fn write_slot(&mut self, idx: usize, key: &S::Key, args: &S::InsertArgs, bytes: &[u8]) {
        let offset = idx * self.slot_size as usize;
        let end = offset + bytes.len();
        self.storage[offset..end].copy_from_slice(bytes);

        let slot = &mut self.slots[idx];
        slot.write_key(key, args);
        let base = slot.base_mut();
        base.len = bytes.len() as u32;
        base.clock = 1;
        base.valid = true;
        base.pins.set(0);
    }
}

fn round_down_power_of_two_usize(val: usize) -> usize {
    if val == 0 {
        return 0;
    }
    1_usize << (usize::BITS - val.leading_zeros() - 1)
}

fn round_down_power_of_two_u32(val: u32) -> u32 {
    if val == 0 {
        return 0;
    }
    1_u32 << (u32::BITS - val.leading_zeros() - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal test slot keyed by a single `u64`.
    #[derive(Clone, Debug)]
    struct TestSlot {
        key: u64,
        base: SlotBase,
    }

    impl CacheSlot for TestSlot {
        type Key = u64;
        type InsertArgs = ();
        type HandleExtra = ();

        fn empty() -> Self {
            Self {
                key: 0,
                base: SlotBase::empty(),
            }
        }
        fn base(&self) -> &SlotBase {
            &self.base
        }
        fn base_mut(&mut self) -> &mut SlotBase {
            &mut self.base
        }
        fn matches_key(&self, key: &u64) -> bool {
            self.key == *key
        }
        fn write_key(&mut self, key: &u64, _args: &()) {
            self.key = *key;
        }
        fn update_existing(&mut self, _args: &()) {}
        fn handle_extra(&self) {}
        fn hash_key(key: &u64) -> u64 {
            *key
        }
    }

    #[test]
    fn insert_and_get() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(64 * 1024);
        let payload = b"hello";
        assert!(cache.insert(&42, &(), payload));
        let handle = cache.get_handle(&42).unwrap();
        assert_eq!(handle.as_slice(), payload);
    }

    #[test]
    fn oversize_entry_not_cached() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(64 * 1024);
        let payload = vec![0u8; cache.slot_size() as usize + 1];
        assert!(!cache.insert(&1, &(), &payload));
        assert!(cache.get_handle(&1).is_none());
    }

    #[test]
    fn disabled_when_capacity_too_small() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32 - 1);
        assert!(!cache.insert(&1, &(), b"data"));
        assert!(cache.get_handle(&1).is_none());
    }

    #[test]
    fn eviction_within_set() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(64 * 1024);
        assert!(cache.sets > 0);

        let mut keys = Vec::new();
        for i in 0..=WAYS {
            // All keys hash to the same set.
            keys.push((i as u64) * (cache.sets as u64));
        }

        for key in &keys {
            assert!(cache.insert(key, &(), &[*key as u8]));
        }

        // At least one should have been evicted.
        let hits = keys
            .iter()
            .filter(|k| cache.get_handle(k).is_some())
            .count();
        assert!(hits <= WAYS);
        assert!(hits >= 1);
    }

    #[test]
    fn pinned_slot_not_evicted() {
        // Use a small cache with exactly 1 set so all keys map to the same set.
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
        assert!(cache.sets > 0);

        // Fill all WAYS slots.
        let mut keys = Vec::new();
        for i in 0..WAYS {
            let key = (i as u64) * (cache.sets as u64);
            keys.push(key);
            assert!(cache.insert(&key, &(), &[i as u8]));
        }

        // Pin the first slot by holding a handle.
        let handle = cache.get_handle(&keys[0]).unwrap();

        // Insert one more key into the same set, forcing eviction.
        let overflow_key = (WAYS as u64) * (cache.sets as u64);
        assert!(cache.insert(&overflow_key, &(), &[0xff]));

        // The pinned slot must still be present (not evicted).
        assert_eq!(handle.as_slice(), &[0u8]);
        // Verify via a fresh lookup that the pinned key is still cached.
        assert!(cache.get_handle(&keys[0]).is_some());

        drop(handle);
    }

    #[test]
    fn insert_fails_when_all_slots_pinned() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
        assert!(cache.sets > 0);

        // Fill and pin all WAYS slots.
        let mut keys = Vec::new();
        let mut handles = Vec::new();
        for i in 0..WAYS {
            let key = (i as u64) * (cache.sets as u64);
            keys.push(key);
            assert!(cache.insert(&key, &(), &[i as u8]));
            handles.push(cache.get_handle(&key).unwrap());
        }

        // Try to insert a new key into the same (fully pinned) set.
        let overflow_key = (WAYS as u64) * (cache.sets as u64);
        assert!(
            !cache.insert(&overflow_key, &(), &[0xff]),
            "insert should fail when all candidate slots are pinned"
        );

        drop(handles);
    }

    #[test]
    fn drop_releases_pin_for_eviction() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
        assert!(cache.sets > 0);

        let key: u64 = 0;
        assert!(cache.insert(&key, &(), b"data"));

        // Pin and then unpin by dropping the handle.
        let handle = cache.get_handle(&key).unwrap();
        drop(handle);

        // Fill the set to force eviction of the now-unpinned slot.
        for i in 1..=WAYS {
            let k = (i as u64) * (cache.sets as u64);
            assert!(cache.insert(&k, &(), b"x"));
        }
        assert!(
            cache.get_handle(&key).is_none(),
            "unpinned slot should have been evicted"
        );
    }

    #[test]
    fn pin_saturation_returns_none() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
        assert!(cache.insert(&0, &(), b"data"));

        // Manually saturate pins to u16::MAX - 1 so the next get_handle
        // bumps to u16::MAX (the last success), then the one after
        // returns None because checked_add(1) overflows.
        let slot = &cache.slots[0];
        slot.base().pins.set(u16::MAX - 1);

        // This bumps to u16::MAX — should succeed.
        let handle = cache.get_handle(&0).unwrap();

        // Now at u16::MAX — checked_add(1) overflows, returns None.
        assert!(
            cache.get_handle(&0).is_none(),
            "pin counter at u16::MAX should refuse new handles"
        );

        drop(handle);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn stale_handle_slice_panics_after_cache_drop() {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
            assert!(cache.insert(&7, &(), b"data"));
            let handle = cache.get_handle(&7).unwrap();
            drop(cache);
            let _ = handle.as_slice();
        }));
        assert!(
            panic.is_err(),
            "using a stale handle should panic in debug builds"
        );
    }

    #[cfg(debug_assertions)]
    #[test]
    fn stale_handle_drop_panics_after_cache_drop() {
        let mut cache = SetAssociativeCache::<TestSlot>::new(MIN_SLOT_SIZE * WAYS as u32);
        assert!(cache.insert(&8, &(), b"data"));
        let handle = cache.get_handle(&8).unwrap();
        drop(cache);
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || drop(handle)));
        assert!(
            panic.is_err(),
            "dropping a stale handle should panic in debug builds"
        );
    }
}
