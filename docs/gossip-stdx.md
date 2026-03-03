# gossip-stdx

Shared low-level data structures for gossip-rs. This crate provides
allocation-silent containers and utilities for hot-path coordination
and scanning loops where heap allocation is the dominant cost. It exists
as a separate crate from `gossip-contracts` because several types here
require `unsafe` for `MaybeUninit`-based storage, and `gossip-contracts`
uses `#![forbid(unsafe_code)]`.

## Source File Map

| File | Public Type(s) | Purpose |
|------|---------------|---------|
| `src/lib.rs` | (re-exports) | Module map, crate-level docs, compatibility mapping |
| `src/byte_slab.rs` | `ByteSlab`, `ByteSlot`, `SlabFull`, `MIN_BLOCK` | Pre-allocated contiguous byte pool with hybrid bump + free-list allocator |
| `src/inline_vec.rs` | `InlineVec<T, N>` | Stack-first small vector, one-way spill to heap |
| `src/ring_buffer.rs` | `RingBuffer<T, N>`, `Iter`, `IntoIter` | Fixed-capacity circular buffer with power-of-2 bitwise indexing |
| `src/byte_ring.rs` | `ByteRing` | Byte stream tail ring buffer keyed by absolute stream offsets |
| `src/atomic_bitset.rs` | `AtomicBitSet` | Lock-free bitset with atomic test-and-set for concurrent dedup |
| `src/atomic_seen_sets.rs` | `AtomicSeenSets` | Composite concurrent dedup tracker for git object traversal |
| `src/bitset.rs` | `DynamicBitSet`, `DynamicBitSetIterator`, `words_for_bits` | Runtime-sized bitset backed by `Vec<u64>` |
| `src/fixed_set.rs` | `FixedSet128` | Epoch-resettable hash set for 128-bit keys |
| `src/timing_wheel.rs` | `TimingWheel<T, G>`, `Bitset2`, `PushError`, `PushOutcome` | Hashed timing wheel with FIFO per bucket and bitmap occupancy |
| `src/spsc.rs` | `OwnedSpscProducer`, `OwnedSpscConsumer`, `spsc_channel` | Wait-free SPSC bounded ring buffer |
| `src/fastrange.rs` | `fast_range` | Division-free range reduction via multiply-high |
| `src/fnv.rs` | `FNV_OFFSET`, `FNV_PRIME`, `fnv_mix_byte`, `fnv_mix_bytes`, `fnv_mix_opt_bytes`, `fnv_mix_u64` | FNV-1a 64-bit hashing helpers for deterministic fingerprinting |
| `src/perf_stats.rs` | `sat_add_u64`, `sat_add_u32`, `sat_add_usize`, `max_u64`, `max_u32`, `max_u16`, `set_u32`, `set_u64`, `set_usize` | Saturating counter helpers (no-op outside `perf-stats` + `debug_assertions`) |
| `src/test_support.rs` | `proptest_cases`, `proptest_fuzz_multiplier` | Shared proptest configuration (feature-gated: `stdx-proptest`) |

## Type Decision Tree

Which container for which use case:

| Need | Type | Why |
|------|------|-----|
| Variable-size byte fields per shard (keys, tokens, metadata) | `ByteSlab` / `ByteSlot` | Pre-allocated pool; replaces per-field `Box<[u8]>` heap allocations |
| Small collection, usually 0-8 elements, rarely more | `InlineVec<T, N>` | Stack-resident up to N; one-way spill avoids oscillation |
| Bounded event/history queue with FIFO semantics | `RingBuffer<T, N>` | Fixed-capacity, zero heap allocation, O(1) push/pop |
| Tail of a byte stream with absolute offset lookups | `ByteRing` | Circular buffer with `has_range`/`contiguous_range` by stream offset |
| Concurrent first-writer-wins dedup (bit-level) | `AtomicBitSet` | Lock-free `fetch_or`; exactly one caller wins per bit |
| Git tree/blob/excluded-blob seen tracking | `AtomicSeenSets` | Three independent `AtomicBitSet` instances with domain API |
| Runtime-sized bit tracking (single-threaded) | `DynamicBitSet` | Heap-allocated, set/unset/iterate, padding invariant maintained |
| Per-chunk dedup with frequent resets | `FixedSet128` | O(1) epoch-based reset; open addressing with 128-bit keys |
| Scheduling windows by byte offset with bounded lateness | `TimingWheel<T, G>` | Hashed timing wheel with FIFO buckets; fixed allocation |
| Cross-thread single-producer/single-consumer queue | `spsc_channel` | Wait-free, no CAS, cache-line padded, power-of-2 capacity |
| Map u64 to `[0, p)` without division | `fast_range` | Multiply-high; branch-free O(1) |
| Deterministic cross-platform hashing | `fnv_mix_*` | FNV-1a 64-bit; same hash on all architectures/Rust versions |

## Allocation Tier Mapping

Per the project allocation policy (AGENTS.md), types serve these tiers:

| Tier | Types | Rationale |
|------|-------|-----------|
| **HOT** (per-shard/per-claim/per-tick steady-state) | `ByteSlab`/`ByteSlot`, `InlineVec`, `RingBuffer`, `ByteRing`, `TimingWheel`, `FixedSet128`, `fast_range`, `fnv_mix_*` | All operations on these types are allocation-silent in steady state. `ByteSlab` uses bump + free-list within a pre-allocated buffer. `InlineVec` stays inline for typical small counts. `RingBuffer` is stack-allocated. `FixedSet128` resets via epoch counter. `TimingWheel` uses a fixed node pool. |
| **HOT** (concurrent) | `AtomicBitSet`, `AtomicSeenSets`, `OwnedSpscProducer`/`OwnedSpscConsumer` | Lock-free, wait-free operations with no allocation after construction. |
| **WARM** (frequent read/query/admin operations) | `DynamicBitSet` | Heap-allocated at construction; all operations after construction are O(1) or O(WORDS) with no further allocation. |
| **COLD** (startup, registration, teardown) | All types at construction time | `ByteSlab::with_capacity`, `AtomicBitSet::empty`, `TimingWheel::new`, `spsc_channel`, etc. allocate once at startup. |

## Per-Type Reference

### ByteSlab / ByteSlot

**Purpose**: Pre-allocated contiguous byte pool that replaces per-field `Box<[u8]>`
heap allocations for shard byte fields (start key, end key, metadata, cursor
last key, cursor token).

**Key fields** (`ByteSlab`):
- `buf: Vec<u8>` — single allocation at construction, never resized
- `bump: u32` — next free offset in the virgin region
- `capacity: u32` — `buf.len()` cached as `u32`
- `free_list: Vec<(u32, u32)>` — sorted by offset, pre-allocated at startup, never grows
- `free_bytes: u32` — cached sum of all free-list block sizes
- `live_bytes: u32` — sum of `alloc_size` for all live slots
- `live_count: u32` — number of live allocations
- `owner_id: u32` — per-instance provenance tag

**Key fields** (`ByteSlot`):
- `offset: u32`, `len: u32`, `alloc_size: u32`, `owner_id: u32` — 16 bytes total, `Copy + Clone`

**Key methods**:
- `ByteSlab::with_capacity(usize)` — allocate once at startup
- `ByteSlab::allocate(&[u8]) -> Result<ByteSlot, SlabFull>` — best-fit free-list, then bump
- `ByteSlab::get(ByteSlot) -> &[u8]` — O(1) slice into pool
- `ByteSlab::deallocate(ByteSlot)` — coalesce with neighbors, reclaim trailing blocks into bump
- `ByteSlab::clear()` — O(1) reset; rotates `owner_id` to invalidate stale slots
- `ByteSlab::zeroize_used()` — zero bytes in `[0..bump)` before clear (sensitive data)

**Capacity/Sizing**: All offsets, lengths, and capacities are `u32` (max ~4 GiB).
Allocation sizes are rounded to the next power of 2 (min `MIN_BLOCK` = 16 bytes).
Worst-case internal fragmentation from rounding: ~50%. Expected average for
cursor-update workload: ~25%.

**Thread safety**: Not synchronized. Single-threaded usage assumed. `Send + Sync`
(compile-time asserted).

**Invariants** (machine-checked via `debug_assert_invariants` after every mutation):
1. `bump <= capacity`
2. Free list sorted, non-overlapping, no adjacent blocks
3. `free_bytes == sum(free_list block sizes)`
4. `live_bytes + free_bytes + (capacity - bump) == capacity` (byte conservation)

---

### InlineVec\<T, N\>

**Purpose**: Stack-first small vector. Stores up to `N` elements inline; on the
`N+1`th push, all elements spill one-way to a heap `Vec<T>`. Typical use:
`InlineVec<ShardId, 8>` for spawned-children lists where 99%+ of shards have 0-2
children.

**Key fields** (internal `Repr` enum, no `Drop` impl on `Repr`):
- `Repr::Inline { buf: [MaybeUninit<T>; N], len: u32 }` — stack storage
- `Repr::Heap(Vec<T>)` — after one-way spill

**Key methods**:
- `InlineVec::new()` — empty, inline mode, zero heap allocation
- `push(T)` — inline write or one-way spill
- `extend_from_slice(&[T])` where `T: Clone` — fast-path bulk write when inline fits
- `from_slice(&[T])` where `T: Copy` — bulk `copy_nonoverlapping` when fits inline
- `as_slice() -> &[T]` — unified view regardless of representation
- `as_mut_slice() -> &mut [T]`
- `iter() -> std::slice::Iter<'_, T>`
- `From<Vec<T>>` — moves elements inline if they fit, otherwise adopts the Vec
- `FromIterator<T>` — uses `size_hint` to choose strategy

**Capacity/Sizing**: `N > 0` and `N <= u32::MAX / 2` (compile-time assertion).
The half-u32 upper bound prevents `len + 1` from overflowing during push.

**Thread safety**: No internal synchronization. `Send` when `T: Send`, `Sync`
when `T: Sync` (compile-time asserted).

**Panic safety**: `extend_from_slice` increments `len` after each successful
`clone()` + write (not after the whole loop), so `Drop` sees the correct count
if `T::clone()` panics mid-iteration.

---

### RingBuffer\<T, N\>

**Purpose**: Fixed-capacity circular buffer with power-of-2 bitwise indexing.
Zero heap allocation. Used for bounded event/history queues.

**Key fields**:
- `buf: [MaybeUninit<T>; N]` — stack-allocated storage
- `head: u32` — index of the logical front
- `len: u32` — number of initialized elements

**Key methods**:
- `RingBuffer::new()` — empty, no heap allocation
- `push_back(T) -> Result<(), T>` — returns `Err(value)` if full
- `push_back_overwrite(T) -> Option<T>` — evicts oldest on overflow
- `pop_front() -> Option<T>` — removes oldest
- `get(usize) -> Option<&T>` — logical index 0 = oldest
- `clear()` — drops all elements in FIFO order
- `iter() -> Iter` — borrowing iterator, `DoubleEndedIterator` + `ExactSizeIterator`
- `into_iter() -> IntoIter` — consuming iterator

**Capacity/Sizing**: `N` must be a power of 2, `> 0`, and `<= u32::MAX / 2`
(compile-time assertions). Bitwise AND masking for O(1) index calculation.

**Thread safety**: Not synchronized. Single-threaded usage assumed. `Send + Sync`
when `T: Send + Sync` (compile-time asserted).

---

### ByteRing

**Purpose**: Byte stream tail ring buffer keyed by absolute stream offsets.
Models a logical, ever-growing byte stream; retains only the most recent
`capacity` bytes.

**Key fields**:
- `buf: Vec<u8>` — circular storage, power-of-2 capacity
- `mask: usize` — `capacity - 1` for bitwise AND wrapping
- `head: usize` — physical start of retained data
- `len: usize` — number of retained bytes
- `start_offset: u64` — absolute offset of the first retained byte

**Key methods**:
- `ByteRing::with_capacity(usize)` — rounds up to next power of 2
- `push(&[u8])` — appends bytes, evicts oldest on overflow
- `has_range(lo: u64, hi: u64) -> bool` — checks if `[lo, hi)` is retained
- `contiguous_range(lo: u64, hi: u64) -> Option<&[u8]>` — direct slice if range does not wrap
- `extend_range_to(lo: u64, hi: u64, &mut Vec<u8>) -> bool` — materializes range into output
- `segments() -> (&[u8], &[u8])` — up to two slices in logical order
- `reset()` — clears all data, resets `start_offset` to 0

**Capacity/Sizing**: Capacity is always a power of two. All index wrapping uses
`& mask` instead of modulo division.

**Thread safety**: Not synchronized. Single-threaded usage assumed.

---

### AtomicBitSet

**Purpose**: Lock-free bitset for concurrent first-writer-wins deduplication.
Atomic `fetch_or` guarantees exactly one caller observes "was-unset" per bit.

**Key fields**:
- `words: Vec<AtomicU64>` — atomic storage
- `bit_length: usize` — number of addressable bits

**Key methods**:
- `AtomicBitSet::empty(bit_length: usize)` — all bits zero; panics if `bit_length == 0`
- `test_and_set(idx: usize) -> bool` — atomically sets bit; returns `true` if was previously unset
- `is_set(idx: usize) -> bool` — snapshot read
- `count() -> usize` — popcount across all words (snapshot)
- `clear()` — resets all bits; requires no concurrent `test_and_set` calls in-flight

**Capacity/Sizing**: `ceil(bit_length / 64)` words.

**Thread safety**: `Send + Sync`. All atomic operations use `Relaxed` ordering
(sufficient because `fetch_or` atomicity guarantees exactly one winner per bit,
and no dependent data requires acquire/release synchronization).

---

### AtomicSeenSets

**Purpose**: Composite concurrent dedup tracker wrapping three `AtomicBitSet`
instances (trees, blobs, excluded-blobs) for git object traversal.

**Key fields**:
- `trees: AtomicBitSet`
- `blobs: AtomicBitSet`
- `blobs_excluded: AtomicBitSet`

**Key methods**:
- `AtomicSeenSets::new(tree_capacity: usize, blob_capacity: usize)` — both blob
  bitsets share the same capacity
- `mark_tree(idx) -> bool` / `mark_blob(idx) -> bool` / `mark_blob_excluded(idx) -> bool`
  — first-writer-wins
- `is_tree_seen(idx)` / `is_blob_seen(idx)` / `is_blob_excluded(idx)` — query
- `clear()` — resets all three; requires no concurrent `mark_*` calls

**Thread safety**: `Send + Sync` (derived from `AtomicBitSet`). All operations
are lock-free.

---

### DynamicBitSet

**Purpose**: Runtime-sized bitset backed by `Vec<u64>`. Used when the number
of bits is not known at compile time.

**Key fields**:
- `words: Vec<u64>` — non-atomic storage
- `bit_length: usize`

**Key methods**:
- `DynamicBitSet::empty(bit_length: usize)` — all bits zero; `bit_length` may be zero
- `set(idx)` / `unset(idx)` / `is_set(idx) -> bool` — O(1) operations
- `count() -> usize` — O(WORDS) popcount
- `clear()` — zero all words
- `toggle_all()` — inverts all bits; clears padding bits in last word
- `iter_set() -> DynamicBitSetIterator` — yields set bit indices in ascending order

**Capacity/Sizing**: `words_for_bits(n)` = `ceil(n / 64)` words.

**Thread safety**: Not synchronized. Single-threaded usage assumed.

**Invariant**: Padding bits in the last word are always zero. This is critical
for `PartialEq` correctness (relies on slice equality) and safe serialization.

---

### FixedSet128

**Purpose**: Fixed-capacity hash set for 128-bit key deduplication with O(1)
epoch-based reset. Used for per-chunk finding dedup (`seen_findings` in
`ScanScratch`).

**Key fields**:
- `slots: Vec<Slot128>` — interleaved AoS layout (key `u128` + epoch `u32` + padding; 32 bytes/slot)
- `cur: u32` — current generation counter (never zero)
- `mask: usize` — `slots.len() - 1`

**Key methods**:
- `FixedSet128::with_pow2(cap_pow2: usize)` — capacity must be power of two
- `insert(key: u128) -> bool` — `false` if already present in current epoch; `true` if new
- `reset()` — O(1) generation advance; rare `u32` wraparound triggers one full clear

**Capacity/Sizing**: Power-of-two slot count. Open addressing with linear probing.
Upper 64 bits of the key used for initial probe slot selection.

**Behavior when full**: `insert` returns `true` but does not store the key
(best-effort dedupe). A later insert of the same key may return `true` again.

**Thread safety**: Not synchronized.

---

### TimingWheel\<T: Copy, const G: u32\>

**Purpose**: Hashed timing wheel for scheduling windows by byte offset. Time
unit is "bytes of decoded stream." Bucket key is `ceil(hi_end / G)`. Items are
guaranteed to never fire early; they may fire up to `G-1` bytes late.

**Key fields**:
- `wheel_size: usize` — power of two, `>= 2`
- `head: Box<[u32]>` / `tail: Box<[u32]>` — per-slot intrusive FIFO list
- `slot_key: Box<[u64]>` — absolute bucket key for occupied slots
- `occ: Bitset2` — two-level occupancy bitmap for fast "next non-empty" scans
- `next: Box<[u32]>` / `payload: Box<[MaybeUninit<T>]>` — fixed-size node pool
- `free_head: u32` — free-list head
- `cursor_abs: u64` / `cursor_slot: usize` — next bucket to process
- `len: usize` / `cap: usize` — current count / node pool capacity

**Key methods**:
- `TimingWheel::new(max_horizon_bytes: u64, node_cap: usize)` — fixed allocation at construction
- `push(hi_end: u64, payload: T) -> Result<PushOutcome<T>, PushError>` — O(1);
  returns `Ready(T)` if already due, `Scheduled` if queued, or `PushError`
- `advance_and_drain(now_offset: u64, on_ready: F) -> usize` — drains buckets
  up to `floor(now_offset / G)`; O(buckets + items drained)
- `advance_and_drain_into(now_offset: u64, &mut Vec<T>) -> usize` — convenience wrapper
- `reset()` — clears all state without reallocating; rewinds cursor to bucket 0
- `len()` / `is_empty()` / `capacity()`

**Capacity/Sizing**: Wheel size is a power of two sized from
`ceil((max_horizon_bytes + G-1) / G) + 1`. Node pool is exactly `node_cap`.

**Thread safety**: Not synchronized. Single-threaded usage assumed.

---

### spsc_channel / OwnedSpscProducer / OwnedSpscConsumer

**Purpose**: Wait-free single-producer/single-consumer bounded ring buffer.
Based on Rigtorp's SPSCQueue. No CAS; uses only `Acquire`/`Release` loads and
stores. On x86-64 TSO these compile to plain `MOV` instructions.

**Key fields** (internal `SpscRing<T, N>`):
- `buf: UnsafeCell<[MaybeUninit<T>; N]>` — slot storage
- `head: CachePadded<AtomicU32>` — consumer's read index
- `tail: CachePadded<AtomicU32>` — producer's write index

**Key methods**:
- `spsc_channel::<T, N>() -> (OwnedSpscProducer, OwnedSpscConsumer)` — creates a channel
- `OwnedSpscProducer::try_push(T) -> Result<(), T>` — returns `Err(value)` if full
- `OwnedSpscConsumer::try_pop() -> Option<T>` — returns `None` if empty
- `OwnedSpscConsumer::try_pop_batch(&mut [MaybeUninit<T>]) -> usize` — batch drain

**Capacity/Sizing**: `N` must be a power of 2, `> 0`, and `<= u32::MAX / 2`
(compile-time assertion). Single heap allocation for the shared ring.

**Performance**: Cached remote index reduces cache-coherence traffic. Producer
caches consumer's `head`; consumer caches producer's `tail`. Only refreshed
on apparent-full/apparent-empty. Head and tail live on separate cache lines
(via `CachePadded`) to prevent false sharing.

**Thread safety**: `Send` (not `Sync` by design). Each handle must be used
from exactly one thread (enforced by `&mut self`). Can be moved across threads.

---

### fast_range

**Purpose**: Division-free range reduction. Maps a 64-bit word into `[0, p)`
via multiply-high: `((word as u128) * (p as u128)) >> 64`.

**Signature**: `fast_range(word: u64, p: u64) -> u64`

**Guarantees**: Returns a value in `[0, p)` when `p > 0`. Branch-free O(1).

**Note**: This is not equivalent to `% p` for non-uniform inputs. For uniform
64-bit input, outputs are close to uniform.

---

### FNV-1a Hashing Helpers

**Purpose**: Deterministic 64-bit hashing for page signatures and finding
fingerprints. FNV-1a was chosen over `DefaultHasher`/SipHash for cross-platform
determinism.

**Functions**:
- `fnv_mix_byte(sig: &mut u64, byte: u8)` — mix one byte
- `fnv_mix_u64(sig: &mut u64, value: u64)` — mix u64 as 8 LE bytes
- `fnv_mix_bytes(sig: &mut u64, bytes: &[u8])` — length-prefixed, bulk 8-byte words
- `fnv_mix_opt_bytes(sig: &mut u64, bytes: Option<&[u8]>)` — domain-separated tag byte

**Constants**: `FNV_OFFSET = 0xcbf29ce484222325`, `FNV_PRIME = 0x100000001b3`

**Contract**: Variable-length fields are length-prefixed. `Option<&[u8]>` uses
a tag byte (0 = None, 1 = Some) for domain separation.

---

### perf_stats

**Purpose**: Saturating counter helpers for scan-time instrumentation. All
functions compile to no-ops unless `all(feature = "perf-stats", debug_assertions)`
is enabled.

**Functions**: `sat_add_u64`, `sat_add_u32`, `sat_add_usize`, `max_u64`, `max_u32`,
`max_u16`, `set_u32`, `set_u64`, `set_usize`

## Safety Verification Matrix

| Type | Miri | Kani | Fuzz | Loom | Proptest |
|------|------|------|------|------|----------|
| `ByteSlab` / `ByteSlot` | Yes | — | `fuzz_byte_slab` | — | — |
| `InlineVec<T, N>` | Yes | 9 proofs (8 of 9 unsafe blocks) | `fuzz_inline_vec` | — | — |
| `RingBuffer<T, N>` | Yes | — | `fuzz_ring_buffer` | — | — |
| `ByteRing` | Yes | — | — | — | — |
| `AtomicBitSet` | Yes | 6 proofs | `fuzz_atomic_bitset` | 3 tests (concurrent dedup, no lost updates, three-thread) | Yes (proptest) |
| `AtomicSeenSets` | Yes | 5 proofs | — | 3 tests (tree dedup, blob dedup, independence) | Yes (proptest) |
| `DynamicBitSet` | Yes | 12 proofs | — | — | Yes (proptest: 6 property tests) |
| `FixedSet128` | Yes | — | — | — | Yes (proptest: 5 property tests) |
| `TimingWheel<T, G>` | Yes | 14 proofs | `fuzz_timing_wheel` | — | Yes (proptest) |
| `spsc_channel` | Yes | 8 proofs (bounds, FIFO, full/empty detection, wrapping, batch, drop) | `fuzz_spsc` | 2 tests (FIFO ordering, full retry) | Yes (proptest: FIFO invariant) |
| `fast_range` | Yes | — | — | — | Yes (proptest: range, power-of-2) |
| `fnv_mix_*` | Yes | — | — | — | — |

**Miri**: All tests run under Miri via `cargo +nightly miri test -p gossip-stdx`.

**Kani**: Feature-gated (`cfg(kani)`). 54 total proofs across the crate.
`InlineVec` has 9 formal proofs covering push bounds, spill preservation,
`as_slice`, drop, clone, `from_slice`, `From<Vec>`, `uninit_array`, and spill
element conservation. `spsc_channel` has 8 proofs covering slot index bounds,
FIFO ordering across wrap, full/empty detection, batch pop, wrapping near
`u32::MAX`, and drop coverage. `TimingWheel` has 14 proofs, `DynamicBitSet`
has 12, `AtomicBitSet` has 6, and `AtomicSeenSets` has 5.

**Fuzz**: Targets in `fuzz/fuzz_targets/` exercise randomized operation sequences.

**Loom**: `AtomicBitSet`, `AtomicSeenSets`, and `spsc_channel` have loom tests
that exhaustively explore all thread interleavings for small state spaces.

**Crate-level lints**: `deny(unsafe_op_in_unsafe_fn)` forces explicit `unsafe`
blocks inside `unsafe fn` with `// SAFETY:` comments.
`deny(clippy::undocumented_unsafe_blocks)` requires `// SAFETY:` on every
`unsafe` block.

## Benchmarks

The crate includes Criterion benchmarks:

| Benchmark | File |
|-----------|------|
| `ring_buffer` | `benches/ring_buffer.rs` |
| `inline_vec` | `benches/inline_vec.rs` |
| `byte_slab` | `benches/byte_slab.rs` |
| `bitset_fixedset` | `benches/bitset_fixedset.rs` |
| `fixed_set` | `benches/fixed_set.rs` |
| `fixed_vec` | `benches/fixed_vec.rs` |
| `timing_wheel` | `benches/timing_wheel.rs` |

## scanner-rs Compatibility

During scanner-rs consolidation, duplicate container implementations are avoided:

- `scanner-rs::stdx::fixed_vec::FixedVec<T, N>` maps to `InlineVec<T, N>`
- `scanner-rs::stdx::ring_buffer::RingBuffer<T, N>` maps to `RingBuffer<T, N>`

## Dependencies

- `crossbeam-utils` (runtime) — `CachePadded` for SPSC cache-line separation
- `criterion` (dev) — benchmarking
- `loom` (dev) — concurrency testing for atomic types and SPSC
- `proptest` (dev) — property-based testing

## Features

| Feature | Purpose |
|---------|---------|
| `kani` | Enables Kani formal verification proofs |
| `stdx-proptest` | Enables `test_support` module and proptest-gated test modules |
| `perf-stats` | Enables instrumentation counter updates (combined with `debug_assertions`) |

## Source of Truth

| Artifact | Authoritative Path |
|----------|-------------------|
| Crate root | `crates/gossip-stdx/src/lib.rs` |
| ByteSlab implementation | `crates/gossip-stdx/src/byte_slab.rs` |
| InlineVec implementation | `crates/gossip-stdx/src/inline_vec.rs` |
| RingBuffer implementation | `crates/gossip-stdx/src/ring_buffer.rs` |
| ByteRing implementation | `crates/gossip-stdx/src/byte_ring.rs` |
| AtomicBitSet implementation | `crates/gossip-stdx/src/atomic_bitset.rs` |
| AtomicSeenSets implementation | `crates/gossip-stdx/src/atomic_seen_sets.rs` |
| DynamicBitSet implementation | `crates/gossip-stdx/src/bitset.rs` |
| FixedSet128 implementation | `crates/gossip-stdx/src/fixed_set.rs` |
| TimingWheel implementation | `crates/gossip-stdx/src/timing_wheel.rs` |
| SPSC channel implementation | `crates/gossip-stdx/src/spsc.rs` |
| fast_range implementation | `crates/gossip-stdx/src/fastrange.rs` |
| FNV hashing implementation | `crates/gossip-stdx/src/fnv.rs` |
| perf_stats implementation | `crates/gossip-stdx/src/perf_stats.rs` |
| Fuzz targets | `crates/gossip-stdx/fuzz/fuzz_targets/` |
| Cargo manifest | `crates/gossip-stdx/Cargo.toml` |
| This document | `docs/gossip-stdx.md` |
