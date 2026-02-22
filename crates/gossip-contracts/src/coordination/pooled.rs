//! Arena-pooled wrappers for [`ShardSpec`] and [`Cursor`] byte fields.
//!
//! ## Problem
//!
//! Each [`ShardRecord`](super::record::ShardRecord) stores 3-5 variable-size
//! byte fields (key range start/end, metadata, cursor last-key, cursor
//! token). Without pooling, every field is a separate `Box<[u8]>` heap
//! allocation, making per-field allocation the dominant cost on the
//! `checkpoint` and `acquire_and_restore` hot paths.
//!
//! ## Solution
//!
//! `PooledShardSpec` and `PooledCursor` replace `Box<[u8]>` fields with
//! [`ByteSlot`] handles into a shared [`ByteSlab`]. The slab pre-allocates
//! a single contiguous buffer and carves out variable-size regions via
//! bump-pointer + free-list, turning N heap allocations per shard into
//! N slab operations and removing per-field `malloc`/`free` on hot paths.
//!
//! ## Accessor lifetime pattern
//!
//! Accessors take `&self` and `&'a ByteSlab`, returning `&'a [u8]`. The
//! returned slice borrows from the *slab*, not from `self`. This means
//! the caller can drop or mutate the pooled wrapper while the slice is
//! still live, as long as the slab borrow is held. This is safe because
//! the slab owns the backing memory, and the slot merely indexes into it.
//!
//! ## Ownership model
//!
//! Fields are private to prevent `ByteSlot` (which is `Copy`) from escaping
//! the wrapper. If a raw slot were exposed, callers could inadvertently
//! create aliased handles, violating SLAB-2.
//!
//! ## Drop
//!
//! Neither type implements `Drop` — they cannot access the slab without a
//! `&mut ByteSlab` parameter, which `Drop::drop` cannot accept. The owning
//! [`ShardRecord`](super::record::ShardRecord) (and transitively the
//! coordinator) must call [`release_fields`] or [`deallocate`] before
//! discarding a pooled value. The coordinator's `Drop` impl releases all
//! slab-backed fields: in debug builds it iterates all records and calls
//! `release_fields` on each `spec` and `cursor`; in release builds it
//! calls `slab.clear()` for O(1) bulk reset.
//!
//! ## Cleanup methods: `deallocate` vs `release_fields`
//!
//! - **`deallocate(self)`** — consumes the wrapper. Use when the wrapper
//!   itself is being removed (e.g., rolling back a failed record creation).
//! - **`release_fields(&mut self)`** — resets fields to EMPTY in place,
//!   leaving the wrapper alive. Use when the wrapper will be reused (e.g.,
//!   the `update` method deallocates old fields, then writes new ones).
//!   Calling `release_fields` twice is safe: the second call is a no-op
//!   because `ByteSlab::deallocate(EMPTY)` is a no-op.
//!
//! ## Invariants
//!
//! - **SLAB-1 (Provenance)**: Every non-EMPTY `ByteSlot` has `owner_id`
//!   matching the slab's current `owner_id`. Enforced by `ByteSlab::get`.
//! - **SLAB-2 (No aliasing)**: No two pooled wrappers hold `ByteSlot`s
//!   with the same offset (enforced by construction — wrappers are not
//!   `Copy` or `Clone`).
//! - **SLAB-3 (Balance)**: `release_fields` decreases `live_count` by
//!   exactly the number of non-empty fields.
//! - **SLAB-4 (Conservation)**: `slab.live_count()` equals the total
//!   non-empty fields across all records (harness-level assertion).
//! - **SLAB-5 (Leak freedom)**: `slab.live_count() == 0` when the
//!   coordinator is dropped.

use gossip_stdx::{ByteSlab, ByteSlot, SlabFull};

use crate::coordination::cursor::Cursor;
use crate::coordination::shard_spec::ShardSpec;

// ============================================================================
// Staged allocation helper
// ============================================================================

/// Allocate multiple byte slices into the slab atomically: all succeed or
/// none do.
///
/// Provides a strong exception guarantee for multi-field allocation. If the
/// k-th allocation fails, fields 0..k-1 are deallocated in reverse order
/// and the slab is left in the same state as before the call. This is the
/// building block for `PooledShardSpec::from_spec`, which needs 3 fields
/// allocated atomically.
///
/// Empty input slices (`&[]`) produce `ByteSlot::EMPTY` without consuming
/// any slab space, so unbounded range endpoints are free.
///
/// # Errors
///
/// Returns [`SlabFull`] if any allocation fails, after rolling back all
/// prior allocations.
fn allocate_with_rollback<const N: usize>(
    fields: [&[u8]; N],
    slab: &mut ByteSlab,
) -> Result<[ByteSlot; N], SlabFull> {
    let mut slots = [ByteSlot::EMPTY; N];
    for (i, &data) in fields.iter().enumerate() {
        match slab.allocate(data) {
            Ok(slot) => slots[i] = slot,
            Err(e) => {
                for slot in slots[..i].iter().rev() {
                    slab.deallocate(*slot);
                }
                return Err(e);
            }
        }
    }
    Ok(slots)
}

// ============================================================================
// PooledShardSpec
// ============================================================================

/// Arena-pooled mirror of [`ShardSpec`], backed by [`ByteSlot`] handles.
///
/// Holds exactly 3 `ByteSlot` handles corresponding to `ShardSpec`'s 3
/// byte fields: `key_range_start`, `key_range_end`, and `metadata`.
/// Unbounded range endpoints (empty `[]` in `ShardSpec`) are stored as
/// `ByteSlot::EMPTY`, which consumes no slab space and returns `&[]` on
/// access.
///
/// Intentionally not `Copy` or `Clone` to enforce SLAB-2 (no aliasing).
/// Duplicating a `ByteSlot` without going through `slab.allocate` would
/// create two wrappers that "own" the same slab region, leading to
/// double-deallocation.
#[derive(Debug)]
pub(crate) struct PooledShardSpec {
    key_range_start: ByteSlot,
    key_range_end: ByteSlot,
    metadata: ByteSlot,
}

impl PooledShardSpec {
    /// Copy a `ShardSpec`'s byte fields into the slab, returning a pooled
    /// handle.
    ///
    /// All 3 fields are allocated atomically via [`allocate_with_rollback`]:
    /// if the slab runs out of space mid-way, earlier allocations are rolled
    /// back and no slab space is leaked.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] if the slab cannot accommodate all 3 fields.
    pub(crate) fn from_spec(spec: &ShardSpec, slab: &mut ByteSlab) -> Result<Self, SlabFull> {
        let slots = allocate_with_rollback(
            [
                spec.key_range_start(),
                spec.key_range_end(),
                spec.metadata(),
            ],
            slab,
        )?;
        Ok(Self {
            key_range_start: slots[0],
            key_range_end: slots[1],
            metadata: slots[2],
        })
    }

    /// Inclusive lower bound of the key range.
    #[inline]
    pub(crate) fn key_range_start<'a>(&self, slab: &'a ByteSlab) -> &'a [u8] {
        slab.get(self.key_range_start)
    }

    /// Exclusive upper bound of the key range.
    #[inline]
    pub(crate) fn key_range_end<'a>(&self, slab: &'a ByteSlab) -> &'a [u8] {
        slab.get(self.key_range_end)
    }

    /// Connector-opaque metadata.
    #[inline]
    pub(crate) fn metadata<'a>(&self, slab: &'a ByteSlab) -> &'a [u8] {
        slab.get(self.metadata)
    }

    /// Materialize an owned `ShardSpec` by copying bytes out of the slab
    /// into fresh `Box<[u8]>` allocations.
    ///
    /// Used when crossing API boundaries (e.g., `ShardRecord::snapshot`)
    /// that require heap-owned types. The pooled handle remains valid
    /// afterward — this is a read, not a move.
    ///
    /// Bypasses `ShardSpec` validation via [`ShardSpec::from_raw_parts`]
    /// because the data was validated when the original spec was created.
    pub(crate) fn to_spec(&self, slab: &ByteSlab) -> ShardSpec {
        ShardSpec::from_raw_parts(
            self.key_range_start(slab).into(),
            self.key_range_end(slab).into(),
            self.metadata(slab).into(),
        )
    }

    /// Replace all fields with data from `new_spec`, providing a strong
    /// exception guarantee.
    ///
    /// The update follows allocate-then-release ordering: the new fields
    /// are fully allocated *before* the old fields are deallocated. If
    /// the slab is too full for the new data, the old data is untouched
    /// and `SlabFull` is returned. This avoids a window where the spec
    /// is in a partially-updated state.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] if the slab cannot accommodate the new fields.
    /// On error, `self` is unchanged.
    pub(crate) fn update(
        &mut self,
        new_spec: &ShardSpec,
        slab: &mut ByteSlab,
    ) -> Result<(), SlabFull> {
        let PooledShardSpec {
            key_range_start,
            key_range_end,
            metadata,
        } = PooledShardSpec::from_spec(new_spec, slab)?;
        // New allocation succeeded — now safe to release old fields.
        self.release_fields(slab);
        self.key_range_start = key_range_start;
        self.key_range_end = key_range_end;
        self.metadata = metadata;
        Ok(())
    }

    /// Deallocate all fields and consume the wrapper.
    ///
    /// Use when the `PooledShardSpec` itself is being discarded (e.g.,
    /// rolling back a partially-constructed `ShardRecord`).
    pub(crate) fn deallocate(self, slab: &mut ByteSlab) {
        slab.deallocate(self.key_range_start);
        slab.deallocate(self.key_range_end);
        slab.deallocate(self.metadata);
    }

    /// Deallocate all fields in-place, resetting each handle to
    /// `ByteSlot::EMPTY`.
    ///
    /// After this call, all accessors return `&[]`. Safe to call
    /// multiple times: `ByteSlab::deallocate(EMPTY)` is a no-op, so
    /// the second call has no effect.
    pub(crate) fn release_fields(&mut self, slab: &mut ByteSlab) {
        let start = std::mem::replace(&mut self.key_range_start, ByteSlot::EMPTY);
        let end = std::mem::replace(&mut self.key_range_end, ByteSlot::EMPTY);
        let meta = std::mem::replace(&mut self.metadata, ByteSlot::EMPTY);
        slab.deallocate(start);
        slab.deallocate(end);
        slab.deallocate(meta);
    }
}

// ============================================================================
// PooledCursor
// ============================================================================

/// Arena-pooled mirror of [`Cursor`], backed by [`ByteSlot`] handles.
///
/// Holds 0-2 `ByteSlot` handles corresponding to `Cursor`'s two optional
/// byte fields.
///
/// ## `Option<ByteSlot>` vs bare `ByteSlot`
///
/// Unlike `PooledShardSpec` (which uses `ByteSlot::EMPTY` for absent
/// range endpoints), `PooledCursor` wraps each slot in `Option`. This
/// preserves the semantic distinction from `Cursor`: `None` means "no
/// progress" / "no token", which is different from "present but empty."
/// `ByteSlot::EMPTY` would conflate the two because `slab.get(EMPTY)`
/// returns `&[]`.
///
/// Intentionally not `Copy` or `Clone` to enforce SLAB-2 (no aliasing).
#[derive(Debug)]
pub(crate) struct PooledCursor {
    last_key: Option<ByteSlot>,
    token: Option<ByteSlot>,
}

impl PooledCursor {
    /// Copy a `Cursor`'s byte fields into the slab, returning a pooled
    /// handle.
    ///
    /// Cannot reuse [`allocate_with_rollback`] because cursor fields are
    /// `Option`-wrapped (0, 1, or 2 allocations depending on which fields
    /// are `Some`). Rollback is handled manually: if the `token` allocation
    /// fails, any already-allocated `last_key` slot is deallocated before
    /// returning the error.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] if the slab cannot accommodate all present
    /// fields. On error, no slab space is leaked.
    pub(crate) fn from_cursor(cursor: &Cursor, slab: &mut ByteSlab) -> Result<Self, SlabFull> {
        let last_key = match cursor.last_key() {
            Some(k) => Some(slab.allocate(k)?),
            None => None,
        };

        let token = match cursor.token() {
            Some(t) => match slab.allocate(t) {
                Ok(slot) => Some(slot),
                Err(e) => {
                    if let Some(slot) = last_key {
                        slab.deallocate(slot);
                    }
                    return Err(e);
                }
            },
            None => None,
        };

        Ok(Self { last_key, token })
    }

    /// Create an initial (no-progress) cursor without any slab allocation.
    pub(crate) fn initial() -> Self {
        Self {
            last_key: None,
            token: None,
        }
    }

    /// The last processed key, or `None` if no progress has been made.
    #[inline]
    pub(crate) fn last_key<'a>(&self, slab: &'a ByteSlab) -> Option<&'a [u8]> {
        self.last_key.map(|slot| slab.get(slot))
    }

    /// The connector-opaque resume token, or `None`.
    #[inline]
    pub(crate) fn token<'a>(&self, slab: &'a ByteSlab) -> Option<&'a [u8]> {
        self.token.map(|slot| slab.get(slot))
    }

    /// Materialize an owned `Cursor` by copying bytes out of the slab
    /// into heap allocations.
    ///
    /// Used when crossing API boundaries (e.g., `ShardRecord::snapshot`).
    /// The pooled handle remains valid afterward.
    ///
    /// The `(None, Some(_))` state is theoretically impossible: `Cursor`
    /// does not support token-without-last-key. Keep an explicit arm so
    /// debug builds surface invariant drift early; release builds degrade to
    /// `Cursor::initial()` to keep conversion total even under corruption.
    pub(crate) fn to_cursor(&self, slab: &ByteSlab) -> Cursor {
        let last_key = self.last_key(slab).map(|k| k.to_vec());
        let token = self.token(slab).map(|t| t.to_vec());
        match (last_key, token) {
            (None, None) => Cursor::initial(),
            (None, Some(_)) => {
                debug_assert!(
                    false,
                    "pooled cursor invariant violated: token present without last_key",
                );
                Cursor::initial()
            }
            (Some(k), None) => Cursor::with_last_key(k),
            (Some(k), Some(t)) => Cursor::from_parts(k, t),
        }
    }

    /// Replace all fields with data from `new_cursor`, providing a strong
    /// exception guarantee.
    ///
    /// Same allocate-then-release pattern as `PooledShardSpec::update`:
    /// new fields are fully allocated before old fields are released. On
    /// failure, `self` is untouched.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] if the slab cannot accommodate the new fields.
    /// On error, `self` is unchanged.
    pub(crate) fn update(
        &mut self,
        new_cursor: &Cursor,
        slab: &mut ByteSlab,
    ) -> Result<(), SlabFull> {
        let PooledCursor { last_key, token } = PooledCursor::from_cursor(new_cursor, slab)?;
        // New allocation succeeded — now safe to release old fields.
        self.release_fields(slab);
        self.last_key = last_key;
        self.token = token;
        Ok(())
    }

    /// Deallocate all fields in-place, resetting both to `None`.
    ///
    /// After this call, `is_initial()` returns `true`. Safe to call
    /// multiple times: the second call is a no-op because both fields
    /// are already `None` (`.take()` on `None` returns `None`).
    pub(crate) fn release_fields(&mut self, slab: &mut ByteSlab) {
        if let Some(slot) = self.last_key.take() {
            slab.deallocate(slot);
        }
        if let Some(slot) = self.token.take() {
            slab.deallocate(slot);
        }
    }
}

// ============================================================================
// Test-only helpers
// ============================================================================

#[cfg(test)]
impl PooledShardSpec {
    /// Test whether `key` falls within `[start, end)`.
    pub(crate) fn contains_key(&self, key: &[u8], slab: &ByteSlab) -> bool {
        let start = self.key_range_start(slab);
        let end = self.key_range_end(slab);

        let above_start = start.is_empty() || key >= start;
        let below_end = end.is_empty() || key < end;
        above_start && below_end
    }
}

#[cfg(test)]
impl PooledCursor {
    /// Returns `true` if this cursor represents the initial (no-progress) state.
    #[inline]
    pub(crate) fn is_initial(&self) -> bool {
        self.last_key.is_none()
    }

    /// Deallocate all fields and consume the wrapper.
    pub(crate) fn deallocate(self, slab: &mut ByteSlab) {
        if let Some(slot) = self.last_key {
            slab.deallocate(slot);
        }
        if let Some(slot) = self.token {
            slab.deallocate(slot);
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{
        arb_bounded_shard_spec, arb_cursor, arb_shard_spec, miri_proptest_config,
    };
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn spec_roundtrip_property(spec in arb_shard_spec()) {
            let mut slab = ByteSlab::with_capacity(4096);
            let pooled = PooledShardSpec::from_spec(&spec, &mut slab).unwrap();
            let reconstructed = pooled.to_spec(&slab);

            prop_assert_eq!(reconstructed.key_range_start(), spec.key_range_start());
            prop_assert_eq!(reconstructed.key_range_end(), spec.key_range_end());
            prop_assert_eq!(reconstructed.metadata(), spec.metadata());

            pooled.deallocate(&mut slab);
            prop_assert_eq!(slab.live_count(), 0);
        }

        #[test]
        fn cursor_roundtrip_property(cursor in arb_cursor()) {
            let mut slab = ByteSlab::with_capacity(4096);
            let pooled = PooledCursor::from_cursor(&cursor, &mut slab).unwrap();
            let reconstructed = pooled.to_cursor(&slab);

            prop_assert_eq!(reconstructed.last_key(), cursor.last_key());
            prop_assert_eq!(reconstructed.token(), cursor.token());

            pooled.deallocate(&mut slab);
            prop_assert_eq!(slab.live_count(), 0);
        }

        #[test]
        fn contains_key_cross_check(
            spec in arb_bounded_shard_spec(),
            key in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let mut slab = ByteSlab::with_capacity(4096);
            let pooled = PooledShardSpec::from_spec(&spec, &mut slab).unwrap();

            prop_assert_eq!(pooled.contains_key(&key, &slab), spec.contains_key(&key));

            pooled.deallocate(&mut slab);
        }
    }

    #[test]
    fn pooled_cursor_roundtrip_initial() {
        let slab = ByteSlab::with_capacity(4096);
        let pooled = PooledCursor::initial();
        assert!(pooled.is_initial());
        assert!(pooled.last_key(&slab).is_none());
        assert!(pooled.token(&slab).is_none());

        let cursor = pooled.to_cursor(&slab);
        assert!(cursor.is_initial());
    }

    #[test]
    fn pooled_spec_update_strong_exception_guarantee() {
        let mut slab = ByteSlab::with_capacity(4096);
        let spec1 = ShardSpec::with_range(b"a".to_vec(), b"m".to_vec());
        let spec2 = ShardSpec::with_range(b"n".to_vec(), b"z".to_vec());

        let mut pooled = PooledShardSpec::from_spec(&spec1, &mut slab).unwrap();
        let live_before = slab.live_count();

        pooled.update(&spec2, &mut slab).unwrap();
        assert_eq!(pooled.key_range_start(&slab), b"n");
        assert_eq!(pooled.key_range_end(&slab), b"z");
        // Same number of live slots (old deallocated, new allocated).
        assert_eq!(slab.live_count(), live_before);

        pooled.release_fields(&mut slab);
        assert_eq!(slab.live_count(), 0);
    }

    #[test]
    fn pooled_cursor_update_strong_exception_guarantee() {
        let mut slab = ByteSlab::with_capacity(4096);
        let c1 = Cursor::with_last_key(b"aaa".to_vec());
        let c2 = Cursor::from_parts(b"bbb".to_vec(), b"tok".to_vec());

        let mut pooled = PooledCursor::from_cursor(&c1, &mut slab).unwrap();
        pooled.update(&c2, &mut slab).unwrap();
        assert_eq!(pooled.last_key(&slab), Some(b"bbb".as_slice()));
        assert_eq!(pooled.token(&slab), Some(b"tok".as_slice()));

        pooled.release_fields(&mut slab);
        assert_eq!(slab.live_count(), 0);
    }

    #[test]
    fn rollback_on_second_field_failure() {
        // Slab large enough for one 16-byte allocation (min block) but not two.
        let mut slab = ByteSlab::with_capacity(16);
        let spec = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let result = PooledShardSpec::from_spec(&spec, &mut slab);
        assert!(result.is_err(), "should fail: slab too small for 2 fields");
        assert_eq!(slab.live_count(), 0, "rollback must clean up partial alloc");
    }

    #[test]
    fn rollback_cursor_token_failure() {
        // Slab sized for exactly one 16-byte allocation.
        let mut slab = ByteSlab::with_capacity(16);
        let cursor = Cursor::from_parts(b"k".to_vec(), b"t".to_vec());
        let result = PooledCursor::from_cursor(&cursor, &mut slab);
        assert!(result.is_err(), "should fail: slab too small for 2 fields");
        assert_eq!(slab.live_count(), 0, "rollback must clean up partial alloc");
    }

    #[test]
    fn release_fields_is_idempotent() {
        let mut slab = ByteSlab::with_capacity(4096);
        let spec = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
        let mut pooled = PooledShardSpec::from_spec(&spec, &mut slab).unwrap();

        pooled.release_fields(&mut slab);
        assert_eq!(slab.live_count(), 0);

        // Second release is a no-op (EMPTY slots).
        pooled.release_fields(&mut slab);
        assert_eq!(slab.live_count(), 0);
    }
}
