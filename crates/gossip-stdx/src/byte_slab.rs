//! Pre-allocated contiguous byte pool with hybrid bump + free-list allocator.
//!
//! # Motivation
//!
//! Each shard in the gossip protocol stores 3–5 variable-size byte fields
//! (start key, end key, metadata, cursor last key, cursor token). Without pooling,
//! each field is a separate `Box<[u8]>` heap allocation — the dominant
//! allocation source on hot paths (`checkpoint`, `acquire_and_restore`).
//!
//! `ByteSlab` pre-allocates a single contiguous buffer at startup and
//! carves out variable-size regions from it. This turns N per-shard heap
//! allocations into N pointer-bump or free-list operations within a single
//! `Vec<u8>`.
//!
//! # Design
//!
//! Allocation uses a two-phase strategy borrowed from production allocators
//! (dlmalloc, linked-list-allocator):
//!
//! 1. **Free list first** — best-fit lookup via linear scan of a single
//!    sorted `Vec<(offset, size)>`. For the typical F≤5 entries, this fits
//!    in one cache line (40 bytes) and avoids all heap-allocated tree nodes.
//!    Splits oversized blocks if remainder >= MIN_BLOCK.
//! 2. **Bump pointer second** — advances through virgin memory. O(1), no
//!    metadata overhead per allocation.
//!
//! Deallocation inserts into the sorted free list and eagerly coalesces with
//! adjacent neighbors (dlmalloc pattern). Trailing free blocks abutting the
//! bump pointer are reclaimed back into the bump pointer
//! (linked-list-allocator pattern), keeping the free list minimal.
//!
//! All sizes are rounded to the next power of 2 (min 16 bytes). This matches
//! the cursor-update workload: keys grow monotonically by small increments,
//! so a power-of-2 block absorbs several rounds of growth before needing
//! reallocation.
//!
//! # Slot provenance
//!
//! Each slab instance carries an `owner_id` that is copied into every
//! non-empty [`ByteSlot`]. [`ByteSlab::get`] and [`ByteSlab::deallocate`]
//! assert that the slot's owner matches the slab's owner, rejecting slots
//! from other slab instances.
//!
//! `clear` rotates the owner id, so stale slots from before clear are
//! rejected by the provenance check, catching use-after-clear bugs.
//!
//! # Memory layout
//!
//! The slab buffer is a flat `Vec<u8>` divided into two contiguous zones:
//!
//! ```text
//!  0                                    bump              capacity
//!  ├──────────── used region ────────────┤──── virgin ────────┤
//!  │  [live alloc] [free] [live] [free]  │  (never touched)   │
//!  └─────────────────────────────────────┴────────────────────┘
//! ```
//!
//! - **Used region** `[0, bump)`: partitioned into live allocations and
//!   free-list blocks, with no gaps.
//! - **Virgin region** `[bump, capacity)`: untouched memory that the bump
//!   pointer advances through.
//!
//! All offsets, lengths, and capacities are `u32`, limiting the maximum slab
//! size to ~4 GiB. This keeps [`ByteSlot`] handles at 16 bytes (four `u32`
//! fields) instead of 32 bytes with `usize` on 64-bit targets.
//!
//! # Invariants
//!
//! 1. `bump <= capacity` (bump pointer never exceeds buffer).
//! 2. Free list sorted by offset, non-overlapping, no adjacent blocks
//!    (coalescing completeness).
//! 3. `free_bytes` equals the sum of all free-list block sizes.
//! 4. `live_bytes + free_bytes + (capacity - bump) == capacity`
//!    (byte conservation — every byte is live, free-listed, or virgin).
//! 5. Region `[0, bump)` fully partitioned into live allocations and
//!    free-list blocks.
//!
//! Invariants 1–4 are directly machine-checked via
//! [`ByteSlab::debug_assert_invariants`], which runs after every mutation
//! in debug builds. Invariant 5 is implied by byte conservation
//! (invariant 4) rather than independently verified.
//!
//! # Threading
//!
//! Not synchronized; assumes single-threaded usage (same as `InlineVec`,
//! `RingBuffer`).
//!
//! # Examples
//!
//! ```
//! use gossip_stdx::{ByteSlab, ByteSlot};
//!
//! let mut slab = ByteSlab::with_capacity(1024);
//!
//! // Allocate regions and get handles back.
//! let key = slab.allocate(b"shard_start_key").unwrap();
//! let token = slab.allocate(b"cursor_token_data").unwrap();
//!
//! assert_eq!(slab.get(key), b"shard_start_key");
//! assert_eq!(slab.live_count(), 2);
//!
//! // Update pattern: deallocate old, allocate new (possibly larger).
//! slab.deallocate(key);
//! let key = slab.allocate(b"shard_start_key_v2").unwrap();
//! assert_eq!(slab.get(key), b"shard_start_key_v2");
//!
//! slab.deallocate(key);
//! slab.deallocate(token);
//! ```

use std::sync::atomic::{AtomicU32, Ordering};

/// Minimum allocation size in bytes. Prevents degenerate fragmentation
/// from tiny allocations.
const MIN_BLOCK: u32 = 16;

/// Reserved `ByteSlot` owner id used by [`ByteSlot::EMPTY`].
const EMPTY_OWNER_ID: u32 = 0;

/// Incrementing slab owner ids (wraps after ~2^32 creations).
///
/// `0` is reserved for [`ByteSlot::EMPTY`]. Non-empty slots always carry a
/// non-zero owner id.
static NEXT_SLAB_ID: AtomicU32 = AtomicU32::new(1);

/// Returns the next non-zero slab owner id.
///
/// Owner ids are process-local provenance tags, not durable capabilities.
/// They may wrap and be reused after enough slab creations.
#[inline]
fn next_slab_id() -> u32 {
    loop {
        let id = NEXT_SLAB_ID.fetch_add(1, Ordering::Relaxed);
        if id != EMPTY_OWNER_ID {
            return id;
        }
    }
}

/// Constructs a [`SlabFull`] error.
///
/// Isolated as `#[cold]` + `#[inline(never)]` to keep the error-path code
/// out of the hot instruction stream in `allocate`. Without this, the
/// compiler may inline the error construction and branch setup into the
/// fast path, bloating the generated code and polluting the instruction
/// cache for the common (success) case.
#[cold]
#[inline(never)]
fn slab_full_err(requested: u32, available: u32) -> SlabFull {
    SlabFull {
        requested,
        available,
    }
}

/// Sentinel byte written to freed regions in debug builds.
/// Reads from stale `ByteSlot` handles may observe this before the region is
/// reused, making use-after-free easier to spot during debugging.
#[cfg(debug_assertions)]
const POISON: u8 = 0xDE;

/// Converts a logical byte length into `u32`.
///
/// Allocation rejects lengths that do not fit in `u32`, so slab arithmetic can
/// remain overflow-checked in `u32` space.
#[inline]
fn checked_len_u32(n: usize) -> Option<u32> {
    u32::try_from(n).ok()
}

/// Rounds `n` up to the next power of 2, with a floor of [`MIN_BLOCK`] (16).
/// Zero maps to zero (for [`ByteSlot::EMPTY`]).
///
/// Returns `None` when the rounded result would overflow `u32` (i.e., for
/// inputs above `2^31`). [`ByteSlab::allocate`] maps this to [`SlabFull`].
///
/// Worst-case internal fragmentation: ~50% (e.g., 17 -> 32).
/// For the cursor-update workload (keys 50-4096 bytes, tokens 100-16384
/// bytes), measured average waste is ~25%.
#[inline]
fn alloc_size(n: usize) -> Option<u32> {
    if n == 0 {
        return Some(0);
    }
    let n = u32::try_from(n).ok()?;
    n.max(MIN_BLOCK).checked_next_power_of_two()
}

// ============================================================================
// ByteSlot
// ============================================================================

/// Handle into a [`ByteSlab`]. Stores the offset, logical length, and
/// allocated capacity (power-of-2 rounded size) of one byte region.
///
/// `Copy` + `Clone` — the slab is the owner, slots are just coordinates.
/// Fixed size: 16 bytes (`u32 offset`, `u32 len`, `u32 alloc_size`,
/// `u32 owner_id`).
///
/// Storing `alloc_size` explicitly (rather than recomputing via
/// `alloc_size(len)`) eliminates a bug class where the rounding function
/// changes between allocate and deallocate.
///
/// # Validity
///
/// A `ByteSlot` is only meaningful when used with the [`ByteSlab`] that
/// created it. Using a slot with a different slab is a logic error that
/// panics.
///
/// Slots created before [`ByteSlab::clear`] are rejected because `clear`
/// rotates the owner id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteSlot {
    offset: u32,
    len: u32,
    alloc_size: u32,
    owner_id: u32,
}

// 16 bytes keeps slot handles cache-friendly. Using `u32` fields instead of
// `usize` halves the handle size on 64-bit targets (16 vs 32 bytes), which
// matters when shards store 3-5 slots inline.
const _: () = assert!(std::mem::size_of::<ByteSlot>() == 16);

impl ByteSlot {
    /// Sentinel for zero-length allocations. `get()` on this returns `&[]`.
    pub const EMPTY: Self = Self {
        offset: 0,
        len: 0,
        alloc_size: 0,
        owner_id: EMPTY_OWNER_ID,
    };

    /// Logical length of the stored data (what the caller wrote).
    #[inline]
    pub fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns `true` when this slot holds no data.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

// ============================================================================
// SlabFull
// ============================================================================

/// Error returned when a [`ByteSlab`] cannot satisfy an allocation request.
///
/// This error is produced when:
/// 1. the request cannot be represented in `u32` (input length > 4 GiB), or
/// 2. the free list and bump region cannot satisfy the rounded request.
///
/// In case (2), free-list space may still exist but was either too fragmented
/// or had no single block large enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlabFull {
    /// The rounded power-of-2 request size. For oversized logical input
    /// lengths (> 4 GiB), this field is `u32::MAX` as a sentinel.
    pub requested: u32,
    /// Remaining bytes in the virgin (bump) region. Does not include
    /// free-list bytes, which exist but could not satisfy the request.
    pub available: u32,
}

impl std::fmt::Display for SlabFull {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ByteSlab full: requested {} bytes, {} virgin bytes remaining",
            self.requested, self.available
        )
    }
}

impl std::error::Error for SlabFull {}

// ============================================================================
// ByteSlab
// ============================================================================

/// Pre-allocated contiguous byte pool with hybrid bump + free-list allocator.
///
/// See the module-level documentation for design details, memory
/// layout, and invariants.
///
/// # Complexity
///
/// | Operation    | Time                                   |
/// |------------- |----------------------------------------|
/// | `allocate`   | O(F) best-fit scan + O(1) bump fallback|
/// | `deallocate` | O(F) neighbor lookup + insert/reclaim  |
/// | `get`        | O(1)                                   |
/// | `clear`      | O(1) (Vec::clear)                      |
///
/// Where F = number of free-list entries (typically 0-5 in practice).
/// At F≤5, the entire free list fits in a single cache line (40 bytes),
/// making the O(F) operations faster than O(log F) BTree operations
/// that require pointer chasing through heap-allocated nodes.
pub struct ByteSlab {
    /// Single allocation at construction, never resized.
    buf: Vec<u8>,
    /// Next free offset in the virgin (never-allocated) region.
    /// Monotonically increases except when trailing free blocks are
    /// reclaimed back into the bump region.
    bump: u32,
    /// `buf.len()` as `u32`, cached to avoid repeated conversion.
    capacity: u32,
    /// Free blocks sorted by offset. Each entry is `(offset, size)`.
    ///
    /// Single contiguous array replaces dual BTree indexes for cache
    /// locality. Operations are O(F) but F is typically 0-5, fitting
    /// in one cache line (40 bytes). Binary search locates neighbors
    /// for coalescing; linear scan finds best-fit for allocation.
    free_list: Vec<(u32, u32)>,
    /// Cached sum of all free-list bytes.
    ///
    /// Maintained incrementally on every insert/remove so metric queries
    /// stay O(1) instead of re-summing.
    free_bytes: u32,
    /// Sum of `alloc_size` for all live slots. Participates in the
    /// byte-conservation invariant.
    live_bytes: u32,
    /// Number of live allocations (non-EMPTY slots that haven't been
    /// deallocated).
    live_count: u32,
    /// Per-instance provenance id used to reject slots from other slabs
    /// (may wrap after ~2^32 slab creations).
    owner_id: u32,
}

impl ByteSlab {
    /// Creates a new slab with the given byte capacity.
    ///
    /// The buffer is allocated once and never resized. All bytes are
    /// initialized to zero.
    ///
    /// # Panics
    ///
    /// Panics if `capacity` exceeds `u32::MAX`.
    pub fn with_capacity(capacity: usize) -> Self {
        assert!(
            capacity <= u32::MAX as usize,
            "ByteSlab capacity must fit in u32"
        );
        let slab = Self {
            buf: vec![0u8; capacity],
            bump: 0,
            capacity: capacity as u32,
            free_list: Vec::new(),
            free_bytes: 0,
            live_bytes: 0,
            live_count: 0,
            owner_id: next_slab_id(),
        };
        slab.debug_assert_invariants();
        slab
    }

    /// Returns bytes remaining in the virgin region (`[bump, capacity)`).
    ///
    /// Uses saturating subtraction so diagnostics stay defined even if an
    /// invariant bug temporarily skews `bump`.
    #[inline]
    fn available_virgin_bytes(&self) -> u32 {
        self.capacity.saturating_sub(self.bump)
    }

    /// Inserts a free block into the sorted free list and updates
    /// [`Self::free_bytes`].
    ///
    /// Uses binary search to find the correct insertion point by offset,
    /// maintaining sorted order. This is the only valid way to add a free
    /// block.
    ///
    /// Zero-size insertions are silently ignored (no-op) to simplify
    /// callers that may produce zero remainders from block splits.
    #[inline]
    fn insert_free_block(&mut self, offset: u32, size: u32) {
        if size == 0 {
            return;
        }
        let pos = self.free_list.partition_point(|&(o, _)| o < offset);
        debug_assert!(
            pos == self.free_list.len() || self.free_list[pos].0 != offset,
            "free block at offset {offset} inserted twice"
        );
        self.free_list.insert(pos, (offset, size));
        self.free_bytes = self
            .free_bytes
            .checked_add(size)
            .expect("free_bytes overflow");
    }

    /// Finds and removes the smallest free block whose size is `>= needed`.
    ///
    /// Linear scan for best-fit: finds the smallest block that can satisfy
    /// the request. For F≤5 this is a trivial 5-iteration loop over
    /// contiguous memory. Ties are broken by lowest offset (natural from
    /// scan order since the vec is sorted by offset).
    #[inline]
    fn take_best_fit(&mut self, needed: u32) -> Option<(u32, u32)> {
        let mut best: Option<(usize, u32)> = None; // (index, size)
        for (i, &(_, size)) in self.free_list.iter().enumerate() {
            if size >= needed {
                match best {
                    Some((_, best_size)) if size < best_size => best = Some((i, size)),
                    None => best = Some((i, size)),
                    _ => {}
                }
            }
        }
        let (idx, _) = best?;
        let (offset, size) = self.free_list.remove(idx);
        self.free_bytes = self
            .free_bytes
            .checked_sub(size)
            .expect("free_bytes underflow");
        Some((offset, size))
    }

    /// Eagerly coalesces a just-freed block with adjacent free neighbors.
    ///
    /// The merge order is right neighbor first, then left neighbor. At most
    /// one merge happens per side because the free list is maintained in
    /// already-coalesced form: if right-of-right were also free, it would
    /// have already been merged into right during a prior deallocation.
    ///
    /// Since the vec is sorted by offset, binary search finds the insertion
    /// point and neighbors are at adjacent indices.
    ///
    /// Returns the `(offset, size)` of the final coalesced block.
    #[inline]
    fn merge_with_neighbors(&mut self, mut offset: u32, mut size: u32) -> (u32, u32) {
        // Right neighbor: the entry at offset+size (if it exists).
        if let Some(end) = offset.checked_add(size) {
            let pos = self.free_list.partition_point(|&(o, _)| o < end);
            if pos < self.free_list.len() && self.free_list[pos].0 == end {
                let (_, right_size) = self.free_list.remove(pos);
                self.free_bytes = self
                    .free_bytes
                    .checked_sub(right_size)
                    .expect("free_bytes underflow on right merge");
                size = size
                    .checked_add(right_size)
                    .expect("coalesced block size overflow");
            }
        }

        // Left neighbor: the entry just before our offset whose end == offset.
        let pos = self.free_list.partition_point(|&(o, _)| o < offset);
        if pos > 0 {
            let (left_off, left_size) = self.free_list[pos - 1];
            if left_off.checked_add(left_size) == Some(offset) {
                self.free_list.remove(pos - 1);
                self.free_bytes = self
                    .free_bytes
                    .checked_sub(left_size)
                    .expect("free_bytes underflow on left merge");
                offset = left_off;
                size = size
                    .checked_add(left_size)
                    .expect("coalesced block size overflow");
            }
        }

        (offset, size)
    }

    /// Panics when `slot` did not originate from this slab instance.
    ///
    /// This enforces cross-slab provenance and also rejects stale slots
    /// after [`clear`](Self::clear), which rotates the owner id.
    #[inline]
    fn assert_slot_owner(&self, slot: ByteSlot) {
        assert_eq!(
            slot.owner_id, self.owner_id,
            "ByteSlot belongs to a different ByteSlab"
        );
    }

    /// Writes payload bytes, updates live-byte/live-count accounting, and
    /// returns a slot tagged with this slab's owner id.
    ///
    /// Only the first `data.len()` bytes of the region are written. Trailing
    /// padding bytes (between `data.len()` and `alloc_size`) are left as-is:
    /// zeroes for virgin memory, poison bytes (0xDE) for reused free-list
    /// blocks in debug builds. This is safe because [`get`](Self::get) only
    /// exposes `slot.len` bytes.
    #[inline]
    fn write_allocation(
        &mut self,
        offset: u32,
        logical_len: u32,
        alloc_size: u32,
        data: &[u8],
    ) -> ByteSlot {
        self.buf[offset as usize..offset as usize + data.len()].copy_from_slice(data);
        self.live_bytes = self
            .live_bytes
            .checked_add(alloc_size)
            .expect("live_bytes overflow");
        self.live_count = self.live_count.checked_add(1).expect("live_count overflow");
        ByteSlot {
            offset,
            len: logical_len,
            alloc_size,
            owner_id: self.owner_id,
        }
    }

    /// Allocates a region and copies `data` into it.
    ///
    /// The physical allocation size is `data.len()` rounded up to the next
    /// power of 2 (minimum 16 bytes). Caller data is written at the front of
    /// that region; trailing padding is internal fragmentation.
    ///
    /// Returns a [`ByteSlot`] handle that can be passed to [`get`](Self::get)
    /// or [`deallocate`](Self::deallocate). Empty slices return
    /// [`ByteSlot::EMPTY`] and consume no slab space.
    ///
    /// # Allocation strategy
    ///
    /// 1. Search the free-list size index for a best-fit block.
    /// 2. Split the block if the remainder is large enough to stay useful.
    /// 3. Fall back to bump allocation from virgin memory.
    ///
    /// # Overflow behavior
    ///
    /// - Logical lengths must fit in `u32`; oversized inputs return
    ///   [`SlabFull`] rather than panicking.
    /// - Bump arithmetic uses `checked_add`; overflow also returns
    ///   [`SlabFull`] instead of wrapping.
    ///
    /// # Errors
    ///
    /// Returns [`SlabFull`] if neither free-list space nor virgin bump space
    /// can satisfy the rounded request.
    #[inline]
    pub fn allocate(&mut self, data: &[u8]) -> Result<ByteSlot, SlabFull> {
        if data.is_empty() {
            return Ok(ByteSlot::EMPTY);
        }

        let logical_len = match checked_len_u32(data.len()) {
            Some(len) => len,
            None => return Err(slab_full_err(u32::MAX, self.available_virgin_bytes())),
        };
        let needed = match alloc_size(data.len()) {
            Some(n) => n,
            None => return Err(slab_full_err(u32::MAX, self.available_virgin_bytes())),
        };

        // Phase 1: best-fit from free-list index.
        if let Some((offset, block_size)) = self.take_best_fit(needed) {
            let remainder = block_size - needed;
            let actual_size = if remainder >= MIN_BLOCK {
                let remainder_offset = offset.checked_add(needed).expect("split offset overflow");
                self.insert_free_block(remainder_offset, remainder);
                needed
            } else {
                // Remainder is too small to become a standalone free block,
                // so the caller absorbs the extra bytes. This trades minor
                // internal fragmentation for avoiding degenerate free-list
                // entries that could never satisfy future allocations.
                block_size
            };

            // Verify poison sentinel on reuse (catches buffer overruns
            // from adjacent allocations).
            #[cfg(debug_assertions)]
            {
                let start = offset as usize;
                let end = start + actual_size as usize;
                debug_assert!(
                    self.buf[start..end].iter().all(|&b| b == POISON),
                    "freed region [{start}..{end}) was corrupted before reallocation"
                );
            }

            let slot = self.write_allocation(offset, logical_len, actual_size, data);
            self.debug_assert_invariants();
            return Ok(slot);
        }

        // Phase 2: Bump allocate from virgin memory.
        let next_bump = match self.bump.checked_add(needed) {
            Some(next) if next <= self.capacity => next,
            _ => return Err(slab_full_err(needed, self.available_virgin_bytes())),
        };
        let offset = self.bump;
        self.bump = next_bump;

        let slot = self.write_allocation(offset, logical_len, needed, data);
        self.debug_assert_invariants();
        Ok(slot)
    }

    /// Returns the logical bytes stored at `slot` (the exact bytes passed
    /// to [`allocate`](Self::allocate), not the full power-of-2 allocation).
    ///
    /// For [`ByteSlot::EMPTY`], returns an empty slice.
    ///
    /// # Panics
    ///
    /// Panics if the slot belongs to a different slab, or if the slot range
    /// exceeds the buffer (corrupt or forged slot metadata).
    #[inline]
    pub fn get(&self, slot: ByteSlot) -> &[u8] {
        if slot.is_empty() {
            return &[];
        }
        self.assert_slot_owner(slot);
        debug_assert!(
            slot.len <= slot.alloc_size,
            "slot len ({}) exceeds alloc_size ({})",
            slot.len,
            slot.alloc_size,
        );
        debug_assert!(
            slot.offset + slot.alloc_size <= self.bump,
            "slot region [{}, {}) exceeds bump ({})",
            slot.offset,
            slot.offset + slot.alloc_size,
            self.bump,
        );
        let start = slot.offset as usize;
        let end = start + slot.len as usize;
        &self.buf[start..end]
    }

    /// Releases the region backing `slot`, making it available for reuse.
    ///
    /// Deallocating [`ByteSlot::EMPTY`] is a no-op. The `slot` must not
    /// be used after deallocation; debug builds poison the freed bytes
    /// and will detect use-after-free via the poison check on reallocation.
    ///
    /// # Coalescing strategy
    ///
    /// The freed region is eagerly merged with adjacent free blocks to
    /// prevent fragmentation:
    ///
    /// 1. **Right neighbor**: if the block immediately following the freed
    ///    region is free, absorb it.
    /// 2. **Left neighbor**: if the block immediately preceding the freed
    ///    region is free, extend it rightward.
    /// 3. **Bump reclamation**: if the (possibly coalesced) block abuts
    ///    the bump pointer, retract the bump pointer instead of inserting
    ///    into the free list. This keeps the free list minimal and
    ///    recovers contiguous virgin space.
    #[inline]
    pub fn deallocate(&mut self, slot: ByteSlot) {
        if slot.is_empty() {
            return;
        }
        self.assert_slot_owner(slot);
        debug_assert!(
            slot.len <= slot.alloc_size,
            "slot len ({}) exceeds alloc_size ({})",
            slot.len,
            slot.alloc_size,
        );
        debug_assert!(
            slot.offset + slot.alloc_size <= self.bump,
            "slot region [{}, {}) exceeds bump ({})",
            slot.offset,
            slot.offset + slot.alloc_size,
            self.bump,
        );

        let slot_start = slot.offset;

        // Overlap check and poison: only in debug builds.
        #[cfg(debug_assertions)]
        {
            let slot_end = slot_start
                .checked_add(slot.alloc_size)
                .expect("slot end overflow");

            for (i, &(block_offset, block_size)) in self.free_list.iter().enumerate() {
                let block_end = block_offset
                    .checked_add(block_size)
                    .expect("free block end overflow");
                debug_assert!(
                    slot_end <= block_offset || slot_start >= block_end,
                    "deallocate: slot [{slot_start}..{slot_end}) overlaps free block {i} \
                     [{}, {}); likely double-free",
                    block_offset,
                    block_end
                );
            }

            self.buf[slot_start as usize..slot_end as usize].fill(POISON);
        }

        self.live_bytes = self
            .live_bytes
            .checked_sub(slot.alloc_size)
            .expect("live_bytes underflow");
        self.live_count = self
            .live_count
            .checked_sub(1)
            .expect("live_count underflow");

        let (merged_offset, merged_size) = self.merge_with_neighbors(slot_start, slot.alloc_size);
        if merged_offset.checked_add(merged_size) == Some(self.bump) {
            // The coalesced block is the trailing-most allocation before
            // the virgin region. Retract the bump pointer instead of
            // inserting into the free list, recovering contiguous virgin
            // space for future bump allocations.
            self.bump = merged_offset;
        } else {
            self.insert_free_block(merged_offset, merged_size);
        }
        self.debug_assert_invariants();
    }

    /// Total byte capacity of the slab (set at construction).
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity as usize
    }

    /// Sum of rounded allocation sizes for all live (not yet deallocated)
    /// slots. This counts padding bytes as "live" — it reflects physical
    /// slab usage, not logical data bytes.
    #[inline]
    pub fn live_bytes(&self) -> usize {
        self.live_bytes as usize
    }

    /// Number of live allocations (excludes [`ByteSlot::EMPTY`] slots).
    #[inline]
    pub fn live_count(&self) -> usize {
        self.live_count as usize
    }

    /// Current bump pointer offset — the boundary between the used region
    /// and the virgin region. Decreases when trailing free blocks are
    /// reclaimed during deallocation.
    #[inline]
    pub fn bump_offset(&self) -> usize {
        self.bump as usize
    }

    /// Sum of bytes across all free-list blocks. These bytes have been
    /// allocated and freed but are not yet reclaimable by the bump
    /// pointer (because a live allocation sits between them and the bump).
    ///
    /// This is an O(1) cached metric (`free_bytes`), not a list traversal.
    #[inline]
    pub fn free_list_bytes(&self) -> usize {
        self.free_bytes as usize
    }

    /// Total bytes available for new allocations (free-list + virgin).
    ///
    /// This is an upper bound, not a guarantee: available bytes may be
    /// fragmented across multiple non-contiguous free blocks, so a single
    /// allocation of this size may fail with [`SlabFull`]. For example,
    /// two free blocks of 32 bytes each yield `available_bytes() == 64`,
    /// but `allocate(&[0u8; 50])` (which rounds to 64) will still fail
    /// because no single block is large enough.
    #[inline]
    pub fn available_bytes(&self) -> usize {
        self.free_bytes as usize + self.available_virgin_bytes() as usize
    }

    /// Returns `true` when no allocations are live.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.live_count == 0
    }

    /// Resets the slab to its initial state without releasing the backing
    /// buffer. All outstanding [`ByteSlot`] handles become invalid —
    /// passing them to [`get`](Self::get) or [`deallocate`](Self::deallocate)
    /// after a clear will panic (owner id mismatch).
    ///
    /// `clear` rotates the `owner_id`, so stale slots from before clear are
    /// rejected by the provenance check. This catches use-after-clear bugs
    /// that would otherwise silently return stale data.
    ///
    /// Unlike deallocating every slot individually, `clear` runs in O(1)
    /// (Vec::clear) rather than O(N_live * F). It also satisfies the
    /// debug-build leak assertion in [`Drop`] (by resetting `live_count`
    /// to zero) rather than requiring every slot to be individually
    /// deallocated.
    pub fn clear(&mut self) {
        self.bump = 0;
        self.free_list.clear();
        self.free_bytes = 0;
        self.live_bytes = 0;
        self.live_count = 0;
        self.owner_id = next_slab_id();
        self.debug_assert_invariants();
    }

    /// Checks all structural invariants listed in the module-level docs.
    ///
    /// Called after every mutation in debug builds. This is the same
    /// "assert-after-every-mutation" pattern used by consensus-rs
    /// `BoundedArray`, which caught several off-by-one bugs during
    /// initial development.
    ///
    /// In release builds this compiles to nothing (`#[inline(always)]`
    /// empty body on the `#[cfg(not(debug_assertions))]` twin).
    #[cfg(debug_assertions)]
    fn debug_assert_invariants(&self) {
        // Invariant 1: bump never exceeds capacity.
        debug_assert!(
            self.bump <= self.capacity,
            "bump ({}) > capacity ({})",
            self.bump,
            self.capacity
        );

        // Invariant 2: free list sorted by offset, non-overlapping,
        // no adjacent blocks.
        let mut sum = 0u32;
        let mut prev: Option<(u32, u32)> = None;
        for &(offset, size) in &self.free_list {
            sum = sum.checked_add(size).expect("free list total overflow");

            if let Some((prev_offset, prev_size)) = prev {
                let prev_end = prev_offset
                    .checked_add(prev_size)
                    .expect("free block end overflow");
                debug_assert!(
                    prev_end < offset,
                    "free list not sorted/non-overlapping/coalesced: \
                     block [{}, {}) followed by [{}, {})",
                    prev_offset,
                    prev_end,
                    offset,
                    offset + size
                );
            }

            // Free list blocks must be within [0, bump).
            debug_assert!(
                offset + size <= self.bump,
                "free block [{}, {}) exceeds bump ({})",
                offset,
                offset + size,
                self.bump
            );

            prev = Some((offset, size));
        }

        // Invariant 3: free_bytes cached sum.
        debug_assert_eq!(
            sum, self.free_bytes,
            "free list total ({sum}) != cached free bytes ({})",
            self.free_bytes
        );

        // Invariant 4: byte conservation.
        let virgin = self
            .capacity
            .checked_sub(self.bump)
            .expect("bump exceeds capacity");
        debug_assert_eq!(
            self.live_bytes + self.free_bytes + virgin,
            self.capacity,
            "byte conservation violated: live={} + free_list={} + virgin={} != capacity={}",
            self.live_bytes,
            self.free_bytes,
            virgin,
            self.capacity
        );
    }

    #[cfg(not(debug_assertions))]
    #[inline(always)]
    fn debug_assert_invariants(&self) {}
}

impl Drop for ByteSlab {
    /// Debug-only leak detector.
    ///
    /// Every slot should be explicitly deallocated or the slab should be
    /// `clear()`ed before drop. Catching leaks here surfaces ownership
    /// bugs early rather than silently losing track of allocated regions.
    ///
    /// This is a debug assertion only — release builds do not check,
    /// because the backing `Vec<u8>` is freed regardless and there is no
    /// per-slot destructor to run.
    fn drop(&mut self) {
        debug_assert_eq!(
            self.live_count, 0,
            "ByteSlab dropped with {} live allocations ({} bytes still allocated)",
            self.live_count, self.live_bytes,
        );
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // alloc_size truth table
    // -----------------------------------------------------------------------

    #[test]
    fn power_of_two_rounding() {
        assert_eq!(alloc_size(0), Some(0));
        assert_eq!(alloc_size(1), Some(16));
        assert_eq!(alloc_size(15), Some(16));
        assert_eq!(alloc_size(16), Some(16));
        assert_eq!(alloc_size(17), Some(32));
        assert_eq!(alloc_size(100), Some(128));
        assert_eq!(alloc_size(4096), Some(4096));
        assert_eq!(alloc_size(16384), Some(16384));
    }

    #[test]
    fn alloc_size_returns_none_on_overflow() {
        assert_eq!(alloc_size((1u32 << 31) as usize + 1), None);
        assert_eq!(alloc_size(u32::MAX as usize), None);
        assert_eq!(alloc_size(u32::MAX as usize + 1), None);
    }

    #[test]
    fn checked_len_rejects_oversized_lengths() {
        assert_eq!(checked_len_u32(u32::MAX as usize), Some(u32::MAX));
        assert_eq!(checked_len_u32(u32::MAX as usize + 1), None);
    }

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    #[test]
    fn new_is_empty() {
        let slab = ByteSlab::with_capacity(1024);
        assert_eq!(slab.capacity(), 1024);
        assert_eq!(slab.live_bytes(), 0);
        assert_eq!(slab.live_count(), 0);
        assert_eq!(slab.bump_offset(), 0);
        assert!(slab.is_empty());
        assert_eq!(slab.available_bytes(), 1024);
    }

    // -----------------------------------------------------------------------
    // Allocate + get roundtrip
    // -----------------------------------------------------------------------

    #[test]
    fn allocate_and_get_roundtrip() {
        let mut slab = ByteSlab::with_capacity(1024);
        let data = b"hello world";
        let slot = slab.allocate(data).unwrap();
        assert_eq!(slab.get(slot), data);
        assert_eq!(slot.len(), data.len());
        slab.deallocate(slot);
    }

    #[test]
    fn allocate_zero_length() {
        let mut slab = ByteSlab::with_capacity(1024);
        let slot = slab.allocate(&[]).unwrap();
        assert_eq!(slot, ByteSlot::EMPTY);
        assert!(slot.is_empty());
        assert_eq!(slab.get(slot), &[]);
        assert_eq!(slab.live_count(), 0);
        // Deallocating EMPTY is a no-op.
        slab.deallocate(slot);
    }

    // -----------------------------------------------------------------------
    // Best-fit selection
    // -----------------------------------------------------------------------

    #[test]
    fn best_fit_selection() {
        let mut slab = ByteSlab::with_capacity(4096);
        // Allocate three blocks separated by "pin" allocations to prevent
        // coalescing when the target blocks are freed.
        let s64 = slab.allocate(&[1u8; 33]).unwrap(); // alloc_size = 64
        let pin1 = slab.allocate(&[0u8; 1]).unwrap(); // pin
        let s32 = slab.allocate(&[2u8; 17]).unwrap(); // alloc_size = 32
        let pin2 = slab.allocate(&[0u8; 1]).unwrap(); // pin
        let s128 = slab.allocate(&[3u8; 65]).unwrap(); // alloc_size = 128
        let _pin3 = slab.allocate(&[0u8; 1]).unwrap(); // pin bump

        // Free the three target blocks. Pins prevent coalescing.
        slab.deallocate(s64);
        slab.deallocate(s32);
        slab.deallocate(s128);

        // Request 30 bytes → alloc_size = 32.
        // Best-fit should pick the 32-byte block (exact fit), not 64 or 128.
        let reused = slab.allocate(&[4u8; 30]).unwrap();
        assert_eq!(reused.offset, s32.offset);

        slab.deallocate(reused);
        slab.deallocate(pin1);
        slab.deallocate(pin2);
        slab.deallocate(_pin3);
    }

    // -----------------------------------------------------------------------
    // Deallocate behavior
    // -----------------------------------------------------------------------

    #[test]
    fn deallocate_empty_is_noop() {
        let mut slab = ByteSlab::with_capacity(1024);
        // Should not panic.
        slab.deallocate(ByteSlot::EMPTY);
        assert!(slab.is_empty());
    }

    #[test]
    fn deallocate_rejects_foreign_slot() {
        let mut a = ByteSlab::with_capacity(256);
        let mut b = ByteSlab::with_capacity(256);
        let slot = a.allocate(b"abc").unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            b.deallocate(slot);
        }));
        assert!(result.is_err(), "foreign slot deallocation must panic");

        // Clean up the original allocation to satisfy drop leak checks.
        a.deallocate(slot);
    }

    #[test]
    fn get_rejects_foreign_slot() {
        let mut a = ByteSlab::with_capacity(256);
        let b = ByteSlab::with_capacity(256);
        let slot = a.allocate(b"abc").unwrap();

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| b.get(slot)));
        assert!(result.is_err(), "foreign slot read must panic");

        // Clean up the original allocation to satisfy drop leak checks.
        a.deallocate(slot);
    }

    // -----------------------------------------------------------------------
    // Free list coalescing
    // -----------------------------------------------------------------------

    #[test]
    fn free_list_coalescing_right() {
        let mut slab = ByteSlab::with_capacity(4096);
        let a = slab.allocate(&[1u8; 16]).unwrap(); // 16 bytes at offset 0
        let b = slab.allocate(&[2u8; 16]).unwrap(); // 16 bytes at offset 16

        // Free b first (right), then a (left) — a should coalesce with b.
        slab.deallocate(b);
        slab.deallocate(a);

        // Both freed and coalesced → bump should reclaim everything.
        assert_eq!(slab.bump_offset(), 0);
        assert_eq!(slab.free_list_bytes(), 0);
        assert_eq!(slab.available_bytes(), 4096);
    }

    #[test]
    fn free_list_coalescing_left() {
        let mut slab = ByteSlab::with_capacity(4096);
        let a = slab.allocate(&[1u8; 16]).unwrap();
        let b = slab.allocate(&[2u8; 16]).unwrap();
        let _c = slab.allocate(&[3u8; 16]).unwrap(); // keeps bump from reclaiming

        // Free a first (left), then b (right) — b should coalesce with a.
        slab.deallocate(a);
        slab.deallocate(b);

        // One coalesced block of 32 bytes.
        assert_eq!(slab.free_list_bytes(), 32);

        slab.deallocate(_c);
    }

    #[test]
    fn free_list_coalescing_three_way() {
        let mut slab = ByteSlab::with_capacity(4096);
        let a = slab.allocate(&[1u8; 16]).unwrap();
        let b = slab.allocate(&[2u8; 16]).unwrap();
        let c = slab.allocate(&[3u8; 16]).unwrap();

        // Free a and c (creating a gap at b), then free b — three-way coalesce.
        slab.deallocate(a);
        slab.deallocate(c);
        slab.deallocate(b);

        // Everything coalesced and reclaimed into bump.
        assert_eq!(slab.bump_offset(), 0);
        assert_eq!(slab.free_list_bytes(), 0);
    }

    // -----------------------------------------------------------------------
    // Split
    // -----------------------------------------------------------------------

    #[test]
    fn free_list_split() {
        let mut slab = ByteSlab::with_capacity(4096);
        // Allocate 128-byte block, free it, then request 32 bytes from it.
        let big = slab.allocate(&[1u8; 65]).unwrap(); // alloc_size = 128
        let _pin = slab.allocate(&[2u8; 16]).unwrap(); // pin bump
        slab.deallocate(big);

        let small = slab.allocate(&[3u8; 17]).unwrap(); // alloc_size = 32
        assert_eq!(small.offset, big.offset);
        assert_eq!(small.alloc_size, 32);

        // Remainder (128 - 32 = 96) stays in free list.
        assert_eq!(slab.free_list_bytes(), 96);

        slab.deallocate(small);
        slab.deallocate(_pin);
    }

    #[test]
    fn split_minimum_size() {
        let mut slab = ByteSlab::with_capacity(4096);
        // Allocate a 32-byte block, free it, then request 17 bytes (alloc_size = 32).
        // Remainder = 0, so no split.
        let block = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32
        let _pin = slab.allocate(&[2u8; 16]).unwrap();
        slab.deallocate(block);

        // Request same size — should use entire block.
        let reused = slab.allocate(&[3u8; 17]).unwrap();
        assert_eq!(reused.offset, block.offset);
        assert_eq!(reused.alloc_size, 32);
        assert_eq!(slab.free_list_bytes(), 0);

        slab.deallocate(reused);
        slab.deallocate(_pin);
    }

    // -----------------------------------------------------------------------
    // Bump reclamation
    // -----------------------------------------------------------------------

    #[test]
    fn bump_reclamation() {
        let mut slab = ByteSlab::with_capacity(1024);
        let a = slab.allocate(&[1u8; 16]).unwrap();
        let bump_before = slab.bump_offset();

        slab.deallocate(a);

        // Trailing free block reclaimed into bump → free list stays empty.
        assert_eq!(slab.bump_offset(), 0);
        assert!(slab.bump_offset() < bump_before);
        assert_eq!(slab.free_list_bytes(), 0);
    }

    #[test]
    fn bump_reclamation_after_coalesce() {
        let mut slab = ByteSlab::with_capacity(1024);
        let a = slab.allocate(&[1u8; 16]).unwrap();
        let b = slab.allocate(&[2u8; 16]).unwrap();

        // Free b (reclaims bump), then free a (also reclaims bump via coalesce).
        slab.deallocate(b);
        assert_eq!(slab.bump_offset(), 16); // reclaimed b's 16 bytes

        slab.deallocate(a);
        assert_eq!(slab.bump_offset(), 0); // reclaimed a's 16 bytes
        assert_eq!(slab.free_list_bytes(), 0);
    }

    // -----------------------------------------------------------------------
    // Workload patterns
    // -----------------------------------------------------------------------

    #[test]
    fn cursor_update_pattern() {
        let mut slab = ByteSlab::with_capacity(4096);
        // Simulate: alloc key+token, dealloc, realloc with larger data.
        let key = slab.allocate(b"cursor_key_v1").unwrap();
        let token = slab.allocate(b"token_data_bytes").unwrap();

        // "Update" by dealloc + realloc.
        slab.deallocate(key);
        slab.deallocate(token);

        let key2 = slab.allocate(b"cursor_key_v2_longer").unwrap();
        let token2 = slab.allocate(b"token_data_bytes_v2").unwrap();

        assert_eq!(slab.get(key2), b"cursor_key_v2_longer");
        assert_eq!(slab.get(token2), b"token_data_bytes_v2");

        slab.deallocate(key2);
        slab.deallocate(token2);
    }

    #[test]
    fn shard_creation_pattern() {
        let mut slab = ByteSlab::with_capacity(4096);
        let start = slab.allocate(b"shard_start_key").unwrap();
        let end = slab.allocate(b"shard_end_key").unwrap();
        let meta = slab.allocate(b"metadata_blob").unwrap();

        assert_eq!(slab.get(start), b"shard_start_key");
        assert_eq!(slab.get(end), b"shard_end_key");
        assert_eq!(slab.get(meta), b"metadata_blob");

        slab.deallocate(start);
        slab.deallocate(end);
        slab.deallocate(meta);
    }

    // -----------------------------------------------------------------------
    // Slab full
    // -----------------------------------------------------------------------

    #[test]
    fn allocate_until_full() {
        let mut slab = ByteSlab::with_capacity(64);
        // 64 bytes capacity. Alloc 32 + 32 = 64 → full.
        let _a = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32
        let _b = slab.allocate(&[2u8; 17]).unwrap(); // alloc_size = 32

        let err = slab.allocate(&[3u8; 1]).unwrap_err();
        assert_eq!(err.requested, 16); // alloc_size(1) = 16
        assert_eq!(err.available, 0);

        slab.deallocate(_a);
        slab.deallocate(_b);
    }

    #[test]
    fn slab_full_error_info() {
        let mut slab = ByteSlab::with_capacity(48);
        let _a = slab.allocate(&[1u8; 17]).unwrap(); // alloc_size = 32

        // 16 bytes of virgin space remain, but we need 32.
        let err = slab.allocate(&[2u8; 17]).unwrap_err();
        assert_eq!(err.requested, 32);
        assert_eq!(err.available, 16);

        slab.deallocate(_a);
    }

    #[test]
    fn allocate_overflow_returns_error_instead_of_panicking() {
        // Construct a slab state that exercises u32 bump arithmetic overflow.
        // This mirrors release-build wraparound behavior without allocating a
        // multi-gigabyte backing buffer.
        let mut slab = ByteSlab::with_capacity(64);
        slab.bump = u32::MAX - 8;
        slab.capacity = u32::MAX;

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.allocate(&[3u8; 32])));
        assert!(
            result.is_ok(),
            "allocate should return SlabFull, not panic on overflow"
        );

        let err = result.unwrap().unwrap_err();
        assert_eq!(err.requested, 32);
        assert_eq!(err.available, 8);
    }

    // -----------------------------------------------------------------------
    // Clear
    // -----------------------------------------------------------------------

    #[test]
    fn clear_resets_state() {
        let mut slab = ByteSlab::with_capacity(1024);
        let _ = slab.allocate(&[1u8; 100]).unwrap();
        let _ = slab.allocate(&[2u8; 200]).unwrap();

        slab.clear();

        assert_eq!(slab.bump_offset(), 0);
        assert_eq!(slab.live_bytes(), 0);
        assert_eq!(slab.live_count(), 0);
        assert_eq!(slab.free_list_bytes(), 0);
        assert_eq!(slab.available_bytes(), 1024);
        assert!(slab.is_empty());
    }

    #[test]
    fn clear_rejects_stale_slots() {
        let mut slab = ByteSlab::with_capacity(1024);
        let stale = slab.allocate(b"before_clear").unwrap();
        slab.clear();

        // get() with a pre-clear slot must panic (owner id rotated).
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.get(stale)));
        assert!(result.is_err(), "stale slot after clear must be rejected");
    }

    // -----------------------------------------------------------------------
    // Stale slot detection (debug_assert sanity checks)
    // -----------------------------------------------------------------------

    /// Allocate a single trailing block, deallocate it (bump retracts),
    /// then use the stale copy. The `debug_assert!(offset + alloc_size <= bump)`
    /// in `get()` catches the stale handle because the bump pointer has
    /// retracted past the slot's region.
    #[test]
    fn stale_slot_after_bump_retraction_panics_on_get() {
        let mut slab = ByteSlab::with_capacity(1024);
        let slot = slab.allocate(b"hello").unwrap();
        let stale = slot; // Copy the handle.
        slab.deallocate(slot);

        // Bump retracted: stale.offset + stale.alloc_size > slab.bump.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.get(stale)));
        assert!(
            result.is_err(),
            "stale slot after bump retraction must panic in debug builds"
        );
    }

    /// Same scenario but through `deallocate()`: the debug_assert catches
    /// the stale handle before it corrupts slab accounting.
    #[test]
    fn stale_slot_after_bump_retraction_panics_on_deallocate() {
        let mut slab = ByteSlab::with_capacity(1024);
        let slot = slab.allocate(b"hello").unwrap();
        let stale = slot;
        slab.deallocate(slot);

        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| slab.deallocate(stale)));
        assert!(
            result.is_err(),
            "stale slot deallocation after bump retraction must panic in debug builds"
        );
    }

    // -----------------------------------------------------------------------
    // SlabFull display
    // -----------------------------------------------------------------------

    #[test]
    fn slab_full_display() {
        let err = SlabFull {
            requested: 32,
            available: 16,
        };
        let msg = format!("{err}");
        assert!(msg.contains("32"));
        assert!(msg.contains("16"));
    }

    // -----------------------------------------------------------------------
    // Property tests (Vec oracle)
    // -----------------------------------------------------------------------

    fn miri_proptest_config() -> proptest::test_runner::Config {
        if cfg!(miri) {
            proptest::test_runner::Config {
                failure_persistence: None,
                cases: 32,
                ..Default::default()
            }
        } else {
            proptest::test_runner::Config::default()
        }
    }

    mod prop {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(super::miri_proptest_config())]

            /// Allocate then get returns identical bytes for all live slots.
            #[test]
            fn allocate_get_roundtrip(
                data_list in proptest::collection::vec(
                    proptest::collection::vec(0u8..=255, 0..512),
                    1..20,
                )
            ) {
                let total: usize = data_list.iter().map(|d| alloc_size(d.len()).unwrap_or(0) as usize).sum();
                let cap = total.max(1024);
                let mut slab = ByteSlab::with_capacity(cap);
                let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

                for data in &data_list {
                    if let Ok(slot) = slab.allocate(data) {
                        if !data.is_empty() {
                            prop_assert_eq!(slab.get(slot), &data[..]);
                        }
                        live.push((slot, data.clone()));
                    }
                }

                // Verify all live slots still return correct data.
                for (slot, data) in &live {
                    if !data.is_empty() {
                        prop_assert_eq!(slab.get(*slot), &data[..]);
                    }
                }

                for (slot, _) in live {
                    slab.deallocate(slot);
                }
            }

            /// State machine: random Alloc/Dealloc/Get ops vs a Vec shadow model.
            #[test]
            fn state_machine_oracle(
                ops in proptest::collection::vec(
                    prop_oneof![
                        proptest::collection::vec(0u8..=255, 0..512)
                            .prop_map(|d| (0u8, d, 0usize)),      // Allocate
                        (0usize..100).prop_map(|i| (1u8, vec![], i)), // Deallocate(idx)
                        (0usize..100).prop_map(|i| (2u8, vec![], i)), // Get(idx)
                        Just((3u8, vec![], 0usize)),                   // Clear
                    ],
                    0..200,
                )
            ) {
                let mut slab = ByteSlab::with_capacity(64 * 1024);
                let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

                for (op, data, idx) in &ops {
                    match op {
                        0 => {
                            // Allocate
                            if let Ok(slot) = slab.allocate(data) {
                                live.push((slot, data.clone()));
                            }
                        }
                        1 => {
                            // Deallocate
                            if !live.is_empty() {
                                let i = idx % live.len();
                                let (slot, _) = live.swap_remove(i);
                                slab.deallocate(slot);
                            }
                        }
                        2 => {
                            // Get
                            if !live.is_empty() {
                                let i = idx % live.len();
                                let (slot, expected) = &live[i];
                                if !expected.is_empty() {
                                    prop_assert_eq!(slab.get(*slot), &expected[..]);
                                }
                            }
                        }
                        3 => {
                            // Clear
                            live.clear();
                            slab.clear();
                        }
                        _ => unreachable!(),
                    }

                    // Metrics consistent after every op.
                    prop_assert_eq!(slab.live_count(), live.iter().filter(|(s, _)| !s.is_empty()).count());

                    // Conservation invariant.
                    prop_assert_eq!(
                        slab.live_bytes() + slab.free_list_bytes() + (slab.capacity() - slab.bump_offset()),
                        slab.capacity()
                    );
                }

                // Cleanup.
                for (slot, _) in live {
                    slab.deallocate(slot);
                }
            }

            /// No two live slots have overlapping physical ranges.
            #[test]
            fn no_overlap(
                data_list in proptest::collection::vec(
                    proptest::collection::vec(0u8..=255, 1..256),
                    1..30,
                )
            ) {
                let total: usize = data_list.iter().map(|d| alloc_size(d.len()).unwrap_or(0) as usize).sum();
                let cap = total.max(1024);
                let mut slab = ByteSlab::with_capacity(cap);
                let mut live: Vec<ByteSlot> = Vec::new();

                for data in &data_list {
                    if let Ok(slot) = slab.allocate(data) {
                        live.push(slot);
                    }
                }

                // Check all pairs for overlap.
                for i in 0..live.len() {
                    for j in (i + 1)..live.len() {
                        let a = &live[i];
                        let b = &live[j];
                        if a.is_empty() || b.is_empty() { continue; }
                        let a_end = a.offset + a.alloc_size;
                        let b_end = b.offset + b.alloc_size;
                        prop_assert!(
                            a_end <= b.offset || b_end <= a.offset,
                            "overlap: [{}, {}) and [{}, {})",
                            a.offset, a_end, b.offset, b_end
                        );
                    }
                }

                for slot in live {
                    slab.deallocate(slot);
                }
            }

            /// alloc_size always returns Some(0) or Some(power of 2), and for
            /// nonzero input: result >= MIN_BLOCK and result >= input.
            #[test]
            fn alloc_size_is_power_of_two(n in 0usize..100_000) {
                let result = alloc_size(n);
                if n == 0 {
                    prop_assert_eq!(result, Some(0));
                } else if let Some(r) = result {
                    prop_assert!(r >= MIN_BLOCK);
                    prop_assert!(r >= n as u32);
                    prop_assert!(r.is_power_of_two());
                }
                // None is valid for inputs > 2^31 (not exercised by this range).
            }

            /// No two adjacent free blocks exist after any dealloc sequence.
            #[test]
            fn coalescing_completeness(
                alloc_count in 2usize..20,
                dealloc_indices in proptest::collection::vec(0usize..100, 1..20),
            ) {
                let mut slab = ByteSlab::with_capacity(64 * 1024);
                let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

                for i in 0..alloc_count {
                    let data = vec![i as u8; 16 + (i * 7) % 100];
                    if let Ok(slot) = slab.allocate(&data) {
                        live.push((slot, data));
                    }
                }

                for &idx in &dealloc_indices {
                    if !live.is_empty() {
                        let i = idx % live.len();
                        let (slot, _) = live.swap_remove(i);
                        slab.deallocate(slot);
                    }
                }

                // Invariants are checked by debug_assert_invariants on every
                // dealloc call, which already asserts no adjacent blocks.
                // We also explicitly verify here.
                // (Access free_list via the conservation check.)
                prop_assert_eq!(
                    slab.live_bytes() + slab.free_list_bytes() + (slab.capacity() - slab.bump_offset()),
                    slab.capacity()
                );

                // Cleanup.
                for (slot, _) in live {
                    slab.deallocate(slot);
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Randomized acquire/release cycle (consensus-rs NodePoolType pattern)
    // -----------------------------------------------------------------------

    /// Weighted random alloc/dealloc cycle modeled on consensus-rs NodePoolType
    /// tests. Uses a simple deterministic PRNG (xorshift32) for
    /// Miri-compatibility.
    ///
    /// Phase 1: 60% allocate / 40% deallocate (fill up).
    /// Phase 2: 40% allocate / 60% deallocate (drain down).
    /// Phase 3: deallocate everything, verify slab is fully reclaimed.
    #[test]
    fn randomized_acquire_release_cycle() {
        // Simple deterministic xorshift32 PRNG — Miri-compatible.
        struct Rng(u32);
        impl Rng {
            fn next(&mut self) -> u32 {
                self.0 ^= self.0 << 13;
                self.0 ^= self.0 >> 17;
                self.0 ^= self.0 << 5;
                self.0
            }
            fn range(&mut self, lo: u32, hi: u32) -> u32 {
                lo + self.next() % (hi - lo)
            }
            fn percent(&mut self) -> u32 {
                self.next() % 100
            }
        }

        let mut rng = Rng(0xDEAD_BEEF);
        let mut slab = ByteSlab::with_capacity(64 * 1024);
        let mut live: Vec<(ByteSlot, Vec<u8>)> = Vec::new();

        // Phase 1: biased toward allocate (60/40).
        for _ in 0..500 {
            if rng.percent() < 60 && slab.available_bytes() >= 16 {
                let size = rng.range(1, 513) as usize;
                let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                if let Ok(slot) = slab.allocate(&data) {
                    live.push((slot, data));
                }
            } else if !live.is_empty() {
                let idx = rng.next() as usize % live.len();
                let (slot, expected) = live.swap_remove(idx);
                assert_eq!(slab.get(slot), &expected[..]);
                slab.deallocate(slot);
            }
        }

        // Phase 2: biased toward deallocate (40/60).
        for _ in 0..500 {
            if rng.percent() < 40 && slab.available_bytes() >= 16 {
                let size = rng.range(1, 513) as usize;
                let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
                if let Ok(slot) = slab.allocate(&data) {
                    live.push((slot, data));
                }
            } else if !live.is_empty() {
                let idx = rng.next() as usize % live.len();
                let (slot, expected) = live.swap_remove(idx);
                assert_eq!(slab.get(slot), &expected[..]);
                slab.deallocate(slot);
            }
        }

        // Phase 3: drain all, verify full reclamation.
        for (slot, expected) in live.drain(..) {
            assert_eq!(slab.get(slot), &expected[..]);
            slab.deallocate(slot);
        }
        assert!(slab.is_empty());
        assert_eq!(slab.live_count(), 0);
        assert_eq!(slab.live_bytes(), 0);
        assert_eq!(slab.available_bytes(), slab.capacity());
    }
}
