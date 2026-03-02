//! Hashed timing wheel with FIFO per bucket, fixed allocation, and bitmap occupancy.
//!
//! Time unit is "bytes of decoded stream".
//! Bucket key is `ceil(hi_end / G)`.
//!
//! # Semantics
//!
//! This is **bucketed scheduling**, not exact scheduling:
//! - Items are guaranteed to **never fire early** (before `hi_end`)
//! - Items may fire up to `G-1` bytes **late** relative to `hi_end`
//! - For exact scheduling, use `G = 1`
//!
//! # Model
//!
//! Each item represents a window with right edge `hi_end` (exclusive). The caller
//! advances "time" by passing `now_offset` (bytes decoded) to `advance_and_drain`.
//! Items are eligible when their bucket key `ceil(hi_end / G)` is `<= floor(now_offset / G)`.
//!
//! # Data Structure Overview
//!
//! ```text
//!                         TimingWheel<T, G>
//!   +-----------------------------------------------------------------+
//!   |                                                                 |
//!   |  +------------------- Wheel Slots -------------------+          |
//!   |  |  slot:   0      1      2      3     ...    W-1    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |  head: | 5  | | -- | | 0  | | -- | ...  | 12 |    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |  tail: | 7  | | -- | | 3  | | -- | ...  | 12 |    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |  key:  |128 | | ?? | |130 | | ?? | ...  |255 |    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |                                                   |          |
//!   |  |  Occupancy bitmap (Bitset2):                      |          |
//!   |  |  occ:   [1]    [0]    [1]    [0]   ...   [1]      |          |
//!   |  +---------------------------------------------------+          |
//!   |                                                                 |
//!   |  +------------------- Node Pool ---------------------+          |
//!   |  |  idx:    0      1      2      3     ...    C-1    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |  next: | -- | | 3  | | -- | | 4  | ...  | -- |    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |  data: | T  | | ?? | | T  | | ?? | ...  | T  |    |          |
//!   |  |        +----+ +----+ +----+ +----+      +----+    |          |
//!   |  |                 ^                                 |          |
//!   |  |  free_head -----+  (free list: 1 -> 3 -> 4 -> ...)           |
//!   |  +---------------------------------------------------+          |
//!   |                                                                 |
//!   |  Cursor: cursor_abs=128, cursor_slot=0                          |
//!   |          (next bucket to process)                               |
//!   |                                                                 |
//!   +-----------------------------------------------------------------+
//!
//!   Legend: -- = NONE_U32 (empty), ?? = stale/unused, W = wheel_size, C = capacity
//! ```
//!
//! # Key to Slot Mapping
//!
//! ```text
//!   hi_end (bytes)     Bucket Key            Slot
//!   ---------------    --------------        -----------------
//!        0         ->   ceil(0/G) = 0     ->   0 & (W-1) = 0
//!        1         ->   ceil(1/G) = 1     ->   1 & (W-1) = 1
//!       G-1        ->   ceil((G-1)/G) = 1 ->   1 & (W-1) = 1
//!        G         ->   ceil(G/G) = 1     ->   1 & (W-1) = 1
//!       G+1        ->   ceil((G+1)/G) = 2 ->   2 & (W-1) = 2
//!       ...
//!      W*G         ->   W                 ->   0  (wraps!)
//!
//!   Horizon constraint prevents collisions:
//!   +---------------------------------------------------------+
//!   |  Valid key range: [cursor_abs, cursor_abs + W)          |
//!   |  All keys in this range map to distinct slots           |
//!   +---------------------------------------------------------+
//! ```
//!
//! # Algorithm
//!
//! The wheel holds `wheel_size` slots (power of two). Absolute bucket keys are mapped
//! to slots via `key & (wheel_size - 1)`. Each slot is a FIFO list of nodes, and
//! `slot_key[slot]` records which absolute key occupies the slot. A two-level bitset
//! (`Bitset2`) tracks non-empty slots, letting `advance_and_drain` jump over empties.
//! A cursor (`cursor_abs`, `cursor_slot`) records the next absolute bucket key that
//! has not been processed as empty or drained.
//!
//! # Invariants
//!
//! - `wheel_size` is a power of two and `>= 2`.
//! - At most one absolute key occupies a slot at a time; this is enforced by the
//!   horizon check (`key < cursor_abs + wheel_size`).
//! - `head[slot] == NONE_U32` iff the slot is empty. When empty, `tail` is `NONE_U32`
//!   and the occupancy bit is clear.
//! - `slot_key[slot]` is only meaningful when `head[slot] != NONE_U32` (it may be
//!   stale in release builds where we skip clearing it).
//! - `now_offset` passed to `advance_and_drain` must be monotone non-decreasing.
//!
//! # Complexity
//!
//! - `push`: O(1) amortized, fixed allocation.
//! - `advance_and_drain`: O(buckets drained + items drained) with bounded scans.
//!
//! # Edge cases
//!
//! - `hi_end = 0` maps to bucket key 0 and is eligible at `now_offset = 0`.

use core::mem::MaybeUninit;

const NONE_U32: u32 = u32::MAX;

/// Errors returned by `TimingWheel::push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushError {
    /// The fixed node pool is exhausted (no free nodes).
    PoolExhausted,
    /// The item is beyond the configured horizon relative to the current base.
    /// (i.e., `key >= cursor_abs + wheel_size`).
    TooFarInFuture {
        key: u64,
        base: u64,
        wheel_size: u64,
    },
    /// Only possible if the wheel is misconfigured (horizon too small).
    /// In correctly-sized wheels, this is mathematically impossible.
    #[cfg(debug_assertions)]
    SlotCollision {
        slot: usize,
        existing_key: u64,
        new_key: u64,
    },
}

/// Result of a successful `TimingWheel::push`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PushOutcome<T> {
    /// Scheduled into the wheel.
    Scheduled,
    /// Already due (or in the past w.r.t. wheel base).
    ///
    /// The item is not enqueued; caller must process it immediately to preserve
    /// ordering semantics with already-drained buckets.
    Ready(T),
}

/// Two-level occupancy bitmap for fast "next non-empty" scans.
///
/// - `l0` bits mark non-empty buckets
/// - `l1` bits mark non-zero `l0` words
/// - `count` tracks total set bits for O(1) `any()`
///
/// # Structure (example: 256 slots)
///
/// ```text
///   Level 1 (l1): 1 word, each bit covers 64 slots
///   +-----------------------------------------------------------------+
///   | bit 0  | bit 1  | bit 2  | bit 3  |  (remaining bits unused)    |
///   |   1    |   1    |   0    |   1    |  0 0 0 0 ...                |
///   +---+----+---+----+---+----+---+----+-----------------------------+
///       |        |        |        |
///       |        |        |        +----------------------------------+
///       |        |        +------------------------------+            |
///       |        +--------------------+                  |            |
///       +--------+                    |                  |            |
///                v                    v                  v            v
///   Level 0 (l0): 4 words, each bit = 1 slot
///   +----------------+----------------+----------------+----------------+
///   |   l0[0]        |   l0[1]        |   l0[2]        |   l0[3]        |
///   | slots 0-63     | slots 64-127   | slots 128-191  | slots 192-255  |
///   | 1100...0101    | 0001...0000    | 0000...0000    | 1010...0001    |
///   +----------------+----------------+----------------+----------------+
///         ^                 ^                 ^                 ^
///       l1 bit 0=1        l1 bit 1=1       l1 bit 2=0        l1 bit 3=1
///       (has bits)        (has bits)        (empty)          (has bits)
/// ```
///
/// # Fast Scan Algorithm
///
/// ```text
///   find_next_set_ge(from=70):
///
///   1. Check l0[1] (word containing bit 70)
///      Mask off bits < 70: l0[1] & (0xFFFF...FFFF << 6)
///      If result != 0 -> found in this word
///
///   2. If not found, use l1 to skip empty l0 words:
///      l1 masked to bits > 1 -> find first set bit
///      Jump directly to that l0 word
///
///   3. Return first set bit in target l0 word
///
///   Complexity: O(1) amortized (<=2 trailing_zeros ops)
/// ```
///
/// # Invariants
///
/// - `l1` bit `i` is set iff `l0[i] != 0`.
/// - Last-word masks (`*_last_mask`) keep out-of-range bits clear.
///
/// This is an internal implementation detail of `TimingWheel`. It is `pub` only
/// for benchmarking purposes and should not be relied upon as a stable API.
#[doc(hidden)]
pub struct Bitset2 {
    bits: usize,
    l0: Box<[u64]>,
    l1: Box<[u64]>,
    l0_last_mask: u64,
    l1_last_mask: u64,
    count: usize, // Track number of set bits for O(1) any() check
}

impl Bitset2 {
    /// Creates an empty bitset that can track `bits` individual flags.
    ///
    /// Both levels are zeroed; `any()` returns false until `set` is called.
    pub fn new(bits: usize) -> Self {
        let l0_words = bits.div_ceil(64);
        let l1_bits = l0_words;
        let l1_words = l1_bits.div_ceil(64);

        let l0_last_mask = mask_last(bits);
        let l1_last_mask = mask_last(l1_bits);

        Self {
            bits,
            l0: vec![0u64; l0_words].into_boxed_slice(),
            l1: vec![0u64; l1_words].into_boxed_slice(),
            l0_last_mask,
            l1_last_mask,
            count: 0,
        }
    }

    #[inline(always)]
    pub fn any(&self) -> bool {
        self.count > 0
    }

    #[inline(always)]
    pub fn set(&mut self, bit: usize) {
        debug_assert!(bit < self.bits);
        let w = bit >> 6;
        let b = bit & 63;
        let m = 1u64 << b;

        let old = self.l0[w];
        let new = old | m;
        if new != old {
            self.l0[w] = new;
            self.count += 1;
            let w1 = w >> 6;
            let b1 = w & 63;
            self.l1[w1] |= 1u64 << b1;
        }
    }

    #[inline(always)]
    pub fn clear(&mut self, bit: usize) {
        debug_assert!(bit < self.bits);
        let w = bit >> 6;
        let b = bit & 63;
        let m = 1u64 << b;

        let old = self.l0[w];
        let new = old & !m;
        if new != old {
            self.l0[w] = new;
            self.count -= 1;
            if new == 0 {
                let w1 = w >> 6;
                let b1 = w & 63;
                self.l1[w1] &= !(1u64 << b1);
            }
        }
    }

    /// Clear all bits in O(l0_words + l1_words) time.
    #[inline]
    pub fn clear_all(&mut self) {
        self.l0.fill(0);
        self.l1.fill(0);
        self.count = 0;
    }

    /// Find next set bit in [from, bits). No wrap.
    #[inline(always)]
    pub fn find_next_set_ge(&self, from: usize) -> Option<usize> {
        if self.bits == 0 || from >= self.bits {
            return None;
        }

        let l0_words = self.l0.len();
        let l0_last = l0_words - 1;

        // 1) Check current l0 word with an in-word mask.
        let w0 = from >> 6;
        let b0 = from & 63;

        let mut w = self.l0[w0];
        if w0 == l0_last {
            w &= self.l0_last_mask;
        }
        w &= (!0u64) << b0;

        if w != 0 {
            return Some((w0 << 6) + (w.trailing_zeros() as usize));
        }

        // 2) Use l1 to find next non-zero l0 word.
        let l1_words = self.l1.len();
        let l1_last = l1_words - 1;

        let mut w1 = w0 >> 6;
        let b1 = w0 & 63;

        // Mask off bits up to and including b1 in the current l1 word.
        let mut s = self.l1[w1];
        if w1 == l1_last {
            s &= self.l1_last_mask;
        }
        s &= mask_strictly_after(b1);

        if s == 0 {
            // Scan subsequent l1 words (usually 0-2 words total in practice).
            let mut found = None;
            for i in (w1 + 1)..l1_words {
                let mut si = self.l1[i];
                if i == l1_last {
                    si &= self.l1_last_mask;
                }
                if si != 0 {
                    found = Some((i, si));
                    break;
                }
            }
            match found {
                None => return None,
                Some((i, si)) => {
                    w1 = i;
                    s = si;
                }
            }
        }

        let next_l0_word = (w1 << 6) + (s.trailing_zeros() as usize);
        debug_assert!(next_l0_word < self.l0.len());

        let mut wnext = self.l0[next_l0_word];
        if next_l0_word == l0_last {
            wnext &= self.l0_last_mask;
        }
        debug_assert!(wnext != 0);

        Some((next_l0_word << 6) + (wnext.trailing_zeros() as usize))
    }

    /// Find next set bit in cyclic order starting at `from`.
    /// Returns None only if bitset is empty.
    #[inline(always)]
    pub fn find_next_set_cyclic(&self, from: usize) -> Option<usize> {
        // Removed redundant any() check - let find_next_set_ge handle it
        if let Some(i) = self.find_next_set_ge(from) {
            return Some(i);
        }
        self.find_next_set_ge(0)
    }
}

/// Returns a bitmask that keeps only the valid bits in the final `u64` word
/// of a bitset with `bits` total bits. If `bits` is a multiple of 64, returns
/// `u64::MAX` (all bits valid).
#[inline(always)]
fn mask_last(bits: usize) -> u64 {
    let rem = bits & 63;
    if rem == 0 {
        u64::MAX
    } else {
        (1u64 << rem) - 1
    }
}

/// Returns a mask that clears bits 0..=b, keeping only bits (b+1)..64.
/// Named to clearly indicate it EXCLUDES bit b and everything before it.
#[inline(always)]
fn mask_strictly_after(b: usize) -> u64 {
    debug_assert!(b < 64);
    if b == 63 { 0 } else { !((1u64 << (b + 1)) - 1) }
}

/// Ceiling division without overflow.
/// Returns ceil(x / d) for any x, d where d > 0.
#[inline(always)]
fn ceil_div_u64(x: u64, d: u64) -> u64 {
    debug_assert!(d != 0, "division by zero");
    // This form cannot overflow: we compute quotient and remainder separately
    let q = x / d;
    let r = x % d;
    q + (r != 0) as u64
}

/// Thin wrapper around `usize::next_power_of_two` for naming clarity at
/// call sites. Panics on overflow (same as the std method).
#[inline(always)]
fn next_pow2_usize(x: usize) -> usize {
    x.next_power_of_two()
}

/// Hashed timing wheel with FIFO per bucket, fixed allocation, and bitmap occupancy.
///
/// Time unit is "bytes of decoded stream".
/// Bucket key is `ceil(hi_end / G)`.
///
/// # Type parameters
///
/// - `T`: Payload type. Must be `Copy` because items are stored in a `MaybeUninit`
///   pool and read with `assume_init_read` on drain (no drops are run).
/// - `G`: Bucket granularity in bytes. `G = 1` gives exact scheduling.
///
/// # FIFO Bucket Structure
///
/// ```text
///   Slot 5 with 3 items (key=133):
///
///   head[5]=2                          tail[5]=8
///       |                                  |
///       v                                  v
///   +-----------+    +-----------+    +-----------+
///   | node[2]   |    | node[6]   |    | node[8]   |
///   | payload=A |--->| payload=B |--->| payload=C |---> NONE
///   | next=6    |    | next=8    |    | next=--   |
///   +-----------+    +-----------+    +-----------+
///        ^                                  ^
///     first in                           last in
///    (drain first)                      (drain last)
///
///   Drain order: A -> B -> C (FIFO)
///   Push appends to tail (D would go after C)
/// ```
///
/// # Node Pool & Free List
///
/// ```text
///   Fixed-size pool with intrusive free list:
///
///   Initial (cap=6):
///     free_head = 0
///     next: [1, 2, 3, 4, 5, --]
///           0 -> 1 -> 2 -> 3 -> 4 -> 5 -> NONE
///
///   After alloc(A), alloc(B), alloc(C):
///     free_head = 3
///     Allocated: 0(A), 1(B), 2(C)
///     Free: 3 -> 4 -> 5 -> NONE
///
///   After free(1):
///     free_head = 1
///     next[1] = 3  (points to old free_head)
///     Free: 1 -> 3 -> 4 -> 5 -> NONE
/// ```
///
/// # Cursor and Time Progression
///
/// ```text
///   Time flows left-to-right (bucket keys increase):
///
///   ------------------------------------------------------------------>
///   |         |                   |                         |
///   0     cursor_abs          now_bucket            cursor_abs +
///         (next to                                   wheel_size
///          process)                                 (horizon limit)
///
///   Buckets in [0, cursor_abs): Already drained or skipped
///   Buckets in [cursor_abs, now_bucket]: Due, drain on advance()
///   Buckets in (now_bucket, cursor_abs + wheel_size): Future, valid to push
///   Buckets >= cursor_abs + wheel_size: TooFarInFuture error
///
///   Slot wrapping (wheel_size=8):
///   +---------------------------------------------------------+
///   | Absolute key:  8   9  10  11  12  13  14  15  16  17 ...|
///   | Slot (key&7):  0   1   2   3   4   5   6   7   0   1 ...|
///   +---------------------------------------------------------+
///   Horizon check ensures keys 8 and 16 never coexist in slot 0.
/// ```
pub struct TimingWheel<T: Copy, const G: u32> {
    wheel_size: usize, // power of two
    wheel_mask: usize, // wheel_size - 1
    wheel_size_u64: u64,

    // Per-slot intrusive list state (SoA).
    head: Box<[u32]>,
    tail: Box<[u32]>,
    // slot_key stores the absolute bucket key for occupied slots.
    // Note: key=0 is valid (for hi_end in (0, G]). Occupancy is determined
    // by head[slot] != NONE_U32, not by slot_key value.
    slot_key: Box<[u64]>,

    occ: Bitset2,

    // Node pool (index-based).
    next: Box<[u32]>,
    payload: Box<[MaybeUninit<T>]>,
    free_head: u32,

    // State of time progression:
    // - cursor_abs is the next absolute bucket key that has not been "processed as empty or drained".
    // - cursor_slot is cursor_abs mod wheel_size.
    cursor_abs: u64,
    cursor_slot: usize,

    // Last observed now_bucket (for monotonicity checks and to allow no-op advances).
    now_bucket: u64,

    len: usize,
    cap: usize,
}

// Compile-time assertions
const _: () = {
    assert!(NONE_U32 == u32::MAX); // Sentinel value check
};

impl<T: Copy, const G: u32> TimingWheel<T, G> {
    // Compile-time check that G > 0
    const _CHECK_G: () = assert!(G > 0, "G must be positive");

    /// Create a timing wheel sized for a maximum scheduling horizon.
    ///
    /// `max_horizon_bytes` must upper-bound `(hi_end - now_offset)` at insertion time.
    /// `node_cap` bounds the number of simultaneously pending windows.
    ///
    /// # Guarantees
    ///
    /// - The wheel size is a power of two (`>= 2`) large enough to avoid slot collisions
    ///   when the horizon bound is respected.
    /// - Allocation is fixed: the node pool size is exactly `node_cap`.
    pub fn new(max_horizon_bytes: u64, node_cap: usize) -> Self {
        // Trigger compile-time check
        const { assert!(G > 0, "G must be positive") };

        let g = G as u64;

        // W_required = ceil((max_horizon_bytes + (G-1))/G) + 1
        let worst = max_horizon_bytes.saturating_add(g - 1);
        let w_required_u64 = ceil_div_u64(worst, g).saturating_add(1);
        let w_required = usize::try_from(w_required_u64).unwrap_or(usize::MAX >> 1);
        let wheel_size = next_pow2_usize(w_required.clamp(2, 1 << 30)); // Cap at 1B slots
        let wheel_mask = wheel_size - 1;

        let mut next = vec![0u32; node_cap];
        if node_cap > 0 {
            for (i, slot) in next.iter_mut().enumerate().take(node_cap - 1) {
                *slot = (i + 1) as u32;
            }
            next[node_cap - 1] = NONE_U32;
        }

        Self {
            wheel_size,
            wheel_mask,
            wheel_size_u64: wheel_size as u64,

            head: vec![NONE_U32; wheel_size].into_boxed_slice(),
            tail: vec![NONE_U32; wheel_size].into_boxed_slice(),
            slot_key: vec![0u64; wheel_size].into_boxed_slice(),

            occ: Bitset2::new(wheel_size),

            next: next.into_boxed_slice(),
            payload: vec![MaybeUninit::uninit(); node_cap].into_boxed_slice(),
            free_head: if node_cap == 0 { NONE_U32 } else { 0 },

            cursor_abs: 0,
            cursor_slot: 0,
            now_bucket: 0,

            len: 0,
            cap: node_cap,
        }
    }

    /// Number of currently scheduled items.
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns true if there are no scheduled items.
    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Fixed capacity of the node pool.
    #[inline(always)]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    /// Reset to the initial empty state without reallocating.
    ///
    /// All pending items are drained (callbacks discarded), the cursor rewinds
    /// to bucket key 0, and the full node pool is returned to the free list.
    /// After this call the wheel accepts items starting from `hi_end = 0` again.
    pub fn reset(&mut self) {
        if self.len != 0 || self.occ.any() {
            self.advance_and_drain(u64::MAX, |_| {});
        }
        self.cursor_abs = 0;
        self.cursor_slot = 0;
        self.now_bucket = 0;
    }

    /// Push a window with right edge `hi_end` (exclusive).
    ///
    /// `hi_end` is mapped to bucket key `ceil(hi_end / G)`.
    ///
    /// # Control Flow
    ///
    /// ```text
    ///   push(hi_end, payload)
    ///         |
    ///         v
    ///   key = ceil(hi_end / G)
    ///         |
    ///         v
    ///   +-----------------+     Yes
    ///   | key < cursor_abs|----------> return Ready(payload)
    ///   +--------+--------+            (already due)
    ///            | No
    ///            v
    ///   +-------------------------+     Yes
    ///   | key >= cursor_abs + W   |----------> return TooFarInFuture
    ///   +--------+----------------+            (beyond horizon)
    ///            | No
    ///            v
    ///   +-----------------+     NONE
    ///   | alloc_node()    |----------> return PoolExhausted
    ///   +--------+--------+
    ///            | idx
    ///            v
    ///   slot = key & (W - 1)
    ///         |
    ///         v
    ///   +-----------------+     Yes     +---------------------+
    ///   | head[slot]==NONE|------------>| Initialize new list |
    ///   +--------+--------+             | head=tail=idx       |
    ///            | No                   | slot_key=key        |
    ///            v                      | occ.set(slot)       |
    ///   +---------------------+         +---------------------+
    ///   | Append to FIFO tail |
    ///   | next[tail]=idx      |
    ///   | tail=idx            |
    ///   +---------------------+
    ///            |
    ///            v
    ///      return Scheduled
    /// ```
    ///
    /// # Returns
    ///
    /// - `Scheduled` if the item is queued in a future bucket.
    /// - `Ready(payload)` if the bucket key is already `< cursor_abs` (already due
    ///   relative to the current base).
    ///
    /// # Errors
    ///
    /// - `PoolExhausted` if the fixed node pool is full.
    /// - `TooFarInFuture` if `hi_end` exceeds the configured horizon.
    #[inline]
    #[must_use = "may return Ready(T) which needs immediate handling"]
    pub fn push(&mut self, hi_end: u64, payload: T) -> Result<PushOutcome<T>, PushError> {
        let g = G as u64;
        let key = ceil_div_u64(hi_end, g);

        // If it's already due w.r.t. our base, do not schedule (avoids late wrap confusion).
        if key < self.cursor_abs {
            return Ok(PushOutcome::Ready(payload));
        }

        // Enforce bounded horizon relative to current base.
        // Use saturating_add to prevent overflow
        let max_key = self.cursor_abs.saturating_add(self.wheel_size_u64);
        if key >= max_key {
            return Err(PushError::TooFarInFuture {
                key,
                base: self.cursor_abs,
                wheel_size: self.wheel_size_u64,
            });
        }

        // Allocate node.
        let idx = self.alloc_node(payload).ok_or(PushError::PoolExhausted)?;

        let slot = (key as usize) & self.wheel_mask;

        // Slot generation check - only in debug builds.
        // Under correct horizon enforcement, collisions are mathematically impossible.
        if self.head[slot] == NONE_U32 {
            self.slot_key[slot] = key;
            self.head[slot] = idx;
            self.tail[slot] = idx;
            self.next[idx as usize] = NONE_U32;
            self.occ.set(slot);
        } else {
            // Slot collision check: verify the existing key matches the new key.
            // Under correct horizon enforcement, collisions are mathematically impossible.
            // In debug builds, return a descriptive error; in release builds, panic
            // to prevent silent data corruption.
            let existing = self.slot_key[slot];
            if existing != key {
                self.free_node(idx);
                #[cfg(debug_assertions)]
                {
                    return Err(PushError::SlotCollision {
                        slot,
                        existing_key: existing,
                        new_key: key,
                    });
                }
                #[cfg(not(debug_assertions))]
                {
                    panic!(
                        "TimingWheel slot collision: slot={}, existing_key={}, new_key={}, \
                         cursor_abs={}, wheel_size={}. This indicates a bug in horizon sizing.",
                        slot, existing, key, self.cursor_abs, self.wheel_size
                    );
                }
            }

            let t = self.tail[slot];
            debug_assert!(t != NONE_U32, "tail must be valid when head is valid");
            self.next[t as usize] = idx;
            self.tail[slot] = idx;
            self.next[idx as usize] = NONE_U32;
        }

        self.len += 1;
        debug_assert!(self.len <= self.cap, "len exceeds capacity");
        Ok(PushOutcome::Scheduled)
    }

    /// Advance time to `now_offset` and drain any buckets with `bucket_key <= floor(now/G)`.
    ///
    /// This is the intended hot-path API: caller pushes windows as they are discovered,
    /// and calls this when decoded offset advances (often only when `now_bucket` changes).
    ///
    /// # Algorithm
    ///
    /// ```text
    ///   advance_and_drain(now_offset=200)
    ///         |
    ///         v
    ///   now_bucket = now_offset / G = 25
    ///         |
    ///         v
    ///   +---------------------------------------+     Yes
    ///   | same bucket AND cursor > now_bucket?  |---------> return 0
    ///   +------------------+--------------------+           (no-op)
    ///                      | No
    ///                      v
    ///            +---------------------+
    ///            | while cursor_abs    |<----------------------+
    ///            |    <= now_bucket    |                       |
    ///            +----------+----------+                       |
    ///                       |                                  |
    ///                       v                                  |
    ///   +------------------------------------+                 |
    ///   | slot = occ.find_next_set_cyclic()  |     None        |
    ///   |        (from cursor_slot)          |--------> break  |
    ///   +------------------+-----------------+                 |
    ///                      | Some(slot)                        |
    ///                      v                                   |
    ///   abs_key = cursor_abs + cyclic_dist(cursor_slot, slot)  |
    ///                      |                                   |
    ///                      v                                   |
    ///   +--------------------------+                           |
    ///   | abs_key > now_bucket?    |---------> break           |
    ///   +------------+-------------+  Yes     (not yet due)    |
    ///                | No                                      |
    ///                v                                         |
    ///   +--------------------------------------+               |
    ///   | Drain entire FIFO list at slot:     |               |
    ///   |   for each node: on_ready(payload)  |               |
    ///   |   free_node(), clear slot, occ.clear|               |
    ///   +------------------+-------------------+               |
    ///                      |                                   |
    ///                      v                                   |
    ///   cursor_abs = abs_key + 1                               |
    ///   cursor_slot = cursor_abs & wheel_mask -----------------+
    ///                      |
    ///                      v (loop exits)
    ///   Fast-forward: cursor_abs = max(cursor_abs, now_bucket + 1)
    ///                      |
    ///                      v
    ///               return drained
    /// ```
    ///
    /// # Cyclic Distance Calculation
    ///
    /// ```text
    ///   wheel_size = 8, cursor_slot = 5, found slot = 2
    ///
    ///   Slots:  [0] [1] [2] [3] [4] [5] [6] [7]
    ///                     ^           ^
    ///                  found       cursor
    ///
    ///   Distance = (2 < 5) ? wheel_size - (5 - 2) : 2 - 5
    ///            = 8 - 3 = 5  (wraps around)
    ///
    ///   abs_key = cursor_abs + 5
    /// ```
    ///
    /// # Ordering
    ///
    /// Buckets are drained in ascending absolute key order. Within a bucket, items
    /// are drained FIFO in insertion order.
    ///
    /// # Preconditions
    ///
    /// `now_offset` must be monotone non-decreasing. Violating this returns 0
    /// without draining (debug builds panic).
    ///
    /// # Returns
    ///
    /// The number of items drained.
    #[inline]
    pub fn advance_and_drain<F>(&mut self, now_offset: u64, mut on_ready: F) -> usize
    where
        F: FnMut(T),
    {
        let g = G as u64;
        let now_bucket = now_offset / g;

        // Time must be monotone non-decreasing. In debug builds, panic on violation.
        // In release builds, return 0 to avoid corrupting internal state.
        if now_bucket < self.now_bucket {
            debug_assert!(
                false,
                "time must be monotone: now_bucket={} < self.now_bucket={}",
                now_bucket, self.now_bucket
            );
            return 0;
        }

        // Only skip if:
        // 1. We're at the same bucket as before, AND
        // 2. We've already processed past this bucket (cursor_abs > now_bucket)
        //
        // This fixes the initialization bug where cursor_abs=0, now_bucket=0
        // would incorrectly skip draining bucket 0.
        if now_bucket == self.now_bucket && self.cursor_abs > now_bucket {
            return 0;
        }
        self.now_bucket = now_bucket;

        let mut drained = 0usize;

        while self.cursor_abs <= self.now_bucket {
            let from = self.cursor_slot;
            let Some(slot) = self.occ.find_next_set_cyclic(from) else {
                break;
            };

            let dist = if slot >= from {
                slot - from
            } else {
                self.wheel_size - (from - slot)
            };
            let abs_key = self.cursor_abs.saturating_add(dist as u64);

            if abs_key > self.now_bucket {
                break;
            }

            // Drain that slot.
            debug_assert_eq!(self.slot_key[slot], abs_key);

            let mut n = self.head[slot];
            self.head[slot] = NONE_U32;
            self.tail[slot] = NONE_U32;

            // Only write slot_key in debug builds - it's not read in release
            #[cfg(debug_assertions)]
            {
                self.slot_key[slot] = 0;
            }

            self.occ.clear(slot);

            while n != NONE_U32 {
                let next = self.next[n as usize];

                // SAFETY: Node was initialized in alloc_node via MaybeUninit::write.
                // T: Copy ensures no double-drop concerns. Node is freed immediately after.
                let val = unsafe { self.payload[n as usize].assume_init_read() };
                self.free_node(n);

                on_ready(val);
                drained += 1;
                self.len -= 1;

                n = next;
            }

            // Mark all buckets up to abs_key as processed (empties are skipped by jumping).
            self.cursor_abs = abs_key.saturating_add(1);
            self.cursor_slot = (self.cursor_abs as usize) & self.wheel_mask;
        }

        // Fast-forward base over empty buckets up to now_bucket.
        // Use saturating_add to prevent overflow
        let target_base = self.now_bucket.saturating_add(1);
        if self.cursor_abs < target_base {
            self.cursor_abs = target_base;
            self.cursor_slot = (self.cursor_abs as usize) & self.wheel_mask;
        }

        drained
    }

    /// Convenience wrapper: drains expired entries into a caller-supplied `Vec`.
    ///
    /// Returns the number of items appended.
    #[inline]
    pub fn advance_and_drain_into(&mut self, now_offset: u64, out: &mut Vec<T>) -> usize {
        self.advance_and_drain(now_offset, |item| out.push(item))
    }

    /// Pops a node from the free list, writes `val` into it, and returns its
    /// index. Returns `None` when the pool is exhausted.
    #[inline(always)]
    fn alloc_node(&mut self, val: T) -> Option<u32> {
        let idx = self.free_head;
        if idx == NONE_U32 {
            return None;
        }
        debug_assert!((idx as usize) < self.cap, "free_head index out of bounds");
        self.free_head = self.next[idx as usize];
        self.payload[idx as usize].write(val);
        Some(idx)
    }

    /// Returns node `idx` to the free list (LIFO push onto `free_head`).
    ///
    /// The caller must ensure `idx` is currently allocated (not already free).
    /// The payload at `idx` is not dropped (`T: Copy`); it becomes stale.
    #[inline(always)]
    fn free_node(&mut self, idx: u32) {
        debug_assert!((idx as usize) < self.cap, "free_node index out of bounds");
        self.next[idx as usize] = self.free_head;
        self.free_head = idx;
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct W {
        hi_end: u64,
        id: u32,
    }

    // G=8 makes boundary behavior easy to eyeball.
    type TW = TimingWheel<W, 8>;

    #[test]
    fn never_fires_early() {
        let mut tw = TW::new(128, 1024);

        // Insert windows at various hi_end, including 0
        for (i, hi) in [0u64, 1, 2, 7, 8, 9, 15, 16, 17, 63, 64, 65]
            .into_iter()
            .enumerate()
        {
            let w = W {
                hi_end: hi,
                id: i as u32,
            };
            match tw.push(hi, w).unwrap() {
                PushOutcome::Scheduled => {}
                PushOutcome::Ready(_) => panic!("should not be ready at time 0 for hi={hi}"),
            }
        }

        // Advance bucket-by-bucket. At each drain, ensure popped hi_end <= now_offset.
        let mut seen = [false; 12];
        for now in 0u64..=80 {
            let mut out = Vec::new();
            let drained = tw.advance_and_drain(now, |w| out.push(w));
            if drained == 0 {
                continue;
            }
            for w in out {
                assert!(
                    w.hi_end <= now,
                    "fired early: hi_end={} now={}",
                    w.hi_end,
                    now
                );
                seen[w.id as usize] = true;
            }
        }
        assert!(seen.iter().all(|&b| b));
    }

    #[test]
    fn fifo_within_bucket() {
        let mut tw = TW::new(128, 16);

        // hi_end in (0..=8] map to key=1 for G=8 (except 0 which maps to key=0).
        for id in 0..5u32 {
            let hi = 1u64 + (id as u64); // all in same bucket key=1
            tw.push(hi, W { hi_end: hi, id }).unwrap();
        }

        // Drain at now=8 (bucket 1 becomes eligible).
        let mut out = Vec::new();
        tw.advance_and_drain(8, |w| out.push(w));

        let ids: Vec<u32> = out.iter().map(|w| w.id).collect();
        assert_eq!(ids, vec![0, 1, 2, 3, 4]);
    }

    #[test]
    fn hi_end_zero_works() {
        // Regression test: hi_end=0 should work correctly
        let mut tw = TW::new(128, 16);

        tw.push(0, W { hi_end: 0, id: 1 }).unwrap();

        let mut out = Vec::new();
        tw.advance_and_drain(0, |w| out.push(w));

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 1);
    }

    #[test]
    fn advance_at_init_drains_bucket_zero() {
        // Regression test for the early-return bug at initialization
        let mut tw = TW::new(128, 16);

        // Push item that should fire at bucket 0
        tw.push(0, W { hi_end: 0, id: 1 }).unwrap();
        tw.push(7, W { hi_end: 7, id: 2 }).unwrap(); // Also bucket 0 (ceil(7/8) = 1, but wait...)
        // Actually ceil(7/8) = 1, ceil(0/8) = 0

        let mut out = Vec::new();
        // First advance at now=0 should drain bucket 0
        tw.advance_and_drain(0, |w| out.push(w));

        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 1);

        // Advance to now=8 should drain bucket 1
        out.clear();
        tw.advance_and_drain(8, |w| out.push(w));
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].id, 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn too_far_in_future_detected_when_wheel_too_small() {
        // Make a deliberately tiny wheel by lying about horizon.
        // G=8, horizon=0 => W_required=2 => W=2 (pow2).
        let mut tw: TimingWheel<W, 8> = TimingWheel::new(0, 8);

        // base starts at 0, so key=1 goes to slot 1.
        tw.push(1, W { hi_end: 1, id: 1 }).unwrap();

        // key=3 would collide with slot 1 when W=2, but TooFarInFuture is caught first.
        let err = tw.push(17, W { hi_end: 17, id: 2 }).unwrap_err();
        match err {
            PushError::TooFarInFuture {
                key: 3,
                base: 0,
                wheel_size: 2,
            } => {}
            other => panic!("expected TooFarInFuture, got {other:?}"),
        }
    }

    #[test]
    fn ceil_div_no_overflow() {
        // Test that ceil_div_u64 doesn't overflow
        assert_eq!(ceil_div_u64(u64::MAX, 1), u64::MAX);
        assert_eq!(ceil_div_u64(u64::MAX, 2), (u64::MAX / 2) + 1);
        assert_eq!(ceil_div_u64(u64::MAX - 1, 2), u64::MAX / 2);
        assert_eq!(ceil_div_u64(0, 100), 0);
        assert_eq!(ceil_div_u64(1, 100), 1);
        assert_eq!(ceil_div_u64(100, 100), 1);
        assert_eq!(ceil_div_u64(101, 100), 2);
    }

    #[test]
    fn reset_restores_to_initial_state() {
        let mut tw = TW::new(128, 32);

        // Fill with items at various positions
        for i in 0..20u32 {
            let hi = (i as u64 % 64) + 1;
            tw.push(hi, W { hi_end: hi, id: i }).unwrap();
        }
        assert_eq!(tw.len(), 20);

        // Advance partway
        tw.advance_and_drain(32, |_| {});

        // Reset
        tw.reset();

        // Verify state is clean
        assert_eq!(tw.len(), 0);
        assert!(tw.is_empty());

        // Should be able to push items again starting from time 0
        for i in 0..10u32 {
            let hi = (i as u64) + 1;
            tw.push(hi, W { hi_end: hi, id: i }).unwrap();
        }
        assert_eq!(tw.len(), 10);

        // Drain should work correctly
        let mut out = Vec::new();
        tw.advance_and_drain(64, |w| out.push(w));
        assert_eq!(out.len(), 10);

        // Validate structure is consistent
        tw.debug_validate();
    }

    #[test]
    fn reset_on_empty_wheel() {
        let mut tw = TW::new(128, 32);

        // Reset without any pushes
        tw.reset();

        assert_eq!(tw.len(), 0);
        assert!(tw.is_empty());

        // Should still work
        tw.push(10, W { hi_end: 10, id: 1 }).unwrap();
        assert_eq!(tw.len(), 1);
    }

    #[test]
    fn reset_preserves_capacity() {
        let mut tw = TW::new(128, 64);

        // Fill to capacity
        for i in 0..64u32 {
            tw.push(
                (i as u64) + 1,
                W {
                    hi_end: (i as u64) + 1,
                    id: i,
                },
            )
            .unwrap();
        }

        // Capacity should be exhausted
        let result = tw.push(
            65,
            W {
                hi_end: 65,
                id: 100,
            },
        );
        assert!(matches!(result, Err(PushError::PoolExhausted)));

        // Reset
        tw.reset();

        // Full capacity should be available again
        for i in 0..64u32 {
            tw.push(
                (i as u64) + 1,
                W {
                    hi_end: (i as u64) + 1,
                    id: i,
                },
            )
            .unwrap();
        }
        assert_eq!(tw.len(), 64);
    }
}

#[cfg(any(test, kani))]
impl Bitset2 {
    #[inline(always)]
    fn is_set(&self, bit: usize) -> bool {
        let w = bit >> 6;
        let b = bit & 63;
        (self.l0[w] >> b) & 1 == 1
    }
}

#[cfg(any(test, kani))]
impl<T: Copy, const G: u32> TimingWheel<T, G> {
    pub(crate) fn debug_validate(&self) {
        let cap = self.next.len();
        let mut mark = vec![0u8; cap]; // 0=unseen, 1=free, 2=used

        // Validate per-slot invariants and mark used nodes.
        let mut used_count = 0usize;

        for slot in 0..self.wheel_size {
            let h = self.head[slot];
            let t = self.tail[slot];

            let occ = self.occ.is_set(slot);
            let empty = h == NONE_U32;

            // Slot state must be consistent.
            if empty {
                assert_eq!(t, NONE_U32);
                // Note: slot_key may have stale values in release builds
                // since we don't clear it. That's fine - we only read it
                // when head != NONE_U32.
                assert!(!occ);
                continue;
            } else {
                assert!(occ);
                assert_ne!(t, NONE_U32);
            }

            // Walk list, ensure indices valid, no cycles, tail is last.
            let mut cur = h;
            let mut last = NONE_U32;
            while cur != NONE_U32 {
                let idx = cur as usize;
                assert!(idx < cap, "node index out of bounds");
                assert_eq!(mark[idx], 0, "node appears twice (cycle or cross-list)");
                mark[idx] = 2;
                used_count += 1;
                last = cur;
                cur = self.next[idx];
            }
            assert_eq!(last, t, "tail must be last node in list");
        }

        assert_eq!(used_count, self.len, "len must match counted used nodes");

        // Validate free list disjointness and coverage.
        let mut free_count = 0usize;
        let mut cur = self.free_head;
        while cur != NONE_U32 {
            let idx = cur as usize;
            assert!(idx < cap, "free index out of bounds");
            assert_eq!(
                mark[idx], 0,
                "node is both free and used (double free or corruption)"
            );
            mark[idx] = 1;
            free_count += 1;
            cur = self.next[idx];
        }

        assert_eq!(
            used_count + free_count,
            cap,
            "every node must be free or used exactly once"
        );
    }
}

// ============================================================================
// Equivalence Tests
// ============================================================================

#[cfg(test)]
mod equivalence_tests {
    use super::*;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Ev {
        id: u32,
        hi_end: u64,
    }

    #[test]
    fn big_advance_equals_stepwise_no_intervening_pushes() {
        const G: u32 = 8;
        type TW = TimingWheel<Ev, G>;

        let horizon = 512u64;
        let cap = 1024usize;
        let mut w1 = TW::new(horizon, cap);
        let mut w2 = TW::new(horizon, cap);

        let pushes = [1u64, 7, 8, 9, 15, 16, 17, 63, 64, 65, 200, 255, 256, 511];

        for (id, &hi) in pushes.iter().enumerate() {
            let id = (id + 1) as u32;
            let e = Ev { id, hi_end: hi };
            w1.push(hi, e).unwrap();
            w2.push(hi, e).unwrap();
        }

        let final_now = 1024u64;

        let mut out_big = Vec::new();
        w1.advance_and_drain(final_now, |e| out_big.push(e));

        let mut out_step = Vec::new();
        // step by 1 byte to exercise all boundaries
        for now in 0..=final_now {
            w2.advance_and_drain(now, |e| out_step.push(e));
        }

        assert_eq!(out_big, out_step);
    }

    #[test]
    fn hi_end_zero_handled_correctly() {
        const G: u32 = 8;
        type TW = TimingWheel<Ev, G>;

        let mut tw = TW::new(128, 16);

        // Push items with hi_end = 0 (key = 0)
        tw.push(0, Ev { id: 1, hi_end: 0 }).unwrap();
        tw.push(0, Ev { id: 2, hi_end: 0 }).unwrap();

        // Should drain at now = 0
        let mut out = Vec::new();
        tw.advance_and_drain(0, |e| out.push(e));

        assert_eq!(out.len(), 2);
        assert_eq!(out[0].id, 1);
        assert_eq!(out[1].id, 2);
    }
}

// Property-based tests and Kani proofs are in the sibling module timing_wheel_tests.rs
#[cfg(any(all(test, feature = "stdx-proptest"), kani))]
#[path = "timing_wheel_tests.rs"]
mod timing_wheel_tests;
