//! Shared low-level data structures for gossip-rs.
//!
//! # Motivation
//!
//! The gossip coordination layer needs allocation-silent hot paths: per-shard
//! mutations (checkpoint, complete, cursor updates) run millions of times per
//! session, and heap allocation in those loops is the dominant cost. This crate
//! provides three data structures that eliminate those allocations by keeping
//! storage stack-resident or pre-allocated.
//!
//! It exists as a separate crate from `gossip-contracts` because that crate
//! uses `#![forbid(unsafe_code)]`, and two of the three types here
//! (`InlineVec`, `RingBuffer`) require `unsafe` for `MaybeUninit`-based
//! storage. Key types are re-exported by `gossip-coordination`.
//!
//! # Provided types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`ByteSlab`] / [`ByteSlot`] | Pre-allocated contiguous byte pool with hybrid bump + free-list allocator; replaces per-field `Box<[u8]>` heap allocations for shard byte fields |
//! | [`InlineVec`] | Stack-first small vector; stores up to N elements inline, one-way spill to heap beyond N; replaces `Vec<T>` for small collections (e.g., spawned children per shard) |
//! | [`RingBuffer`] | Fixed-capacity circular buffer with power-of-2 bitwise indexing; zero heap allocation; used for bounded event/history queues |
//!
//! All three share a common design philosophy: the hot-path representation
//! uses contiguous, pre-sized storage, and the hot-path operations
//! (`allocate`/`deallocate`, `push` while inline, `push_back`) perform no
//! heap allocation.
//!
//! # Safety and verification
//!
//! Every `unsafe` block in this crate carries a `// SAFETY:` comment
//! explaining why the preconditions hold. Correctness is verified through
//! three complementary techniques:
//!
//! - **Miri** (runtime): detects undefined behavior, use-after-free, and
//!   uninitialized reads under the stacked-borrows model.
//! - **Kani** (formal): symbolic verification of `InlineVec` unsafe
//!   operations (9 proofs covering 8 of 9 unsafe blocks — bounds, spill
//!   preservation, and drop correctness).
//! - **Fuzz testing** (coverage): `cargo-fuzz` targets exercise randomized
//!   operation sequences for all three types (see `fuzz/fuzz_targets/`).
//!
//! # Crate-level lints
//!
//! - `deny(unsafe_op_in_unsafe_fn)` — forces every `unsafe` operation inside
//!   an `unsafe fn` to be wrapped in an explicit `unsafe` block with a safety
//!   comment, preventing "inherited unsafety" from hiding under-documented
//!   operations.
//! - `deny(clippy::undocumented_unsafe_blocks)` — requires a `// SAFETY:`
//!   comment on every `unsafe` block.
//!
//! # Miri testing
//!
//! All tests in this crate should be run under Miri to verify memory safety:
//! ```sh
//! cargo +nightly miri test -p gossip-stdx
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod byte_slab;
pub mod fnv;
mod inline_vec;
mod ring_buffer;

/// Pre-allocated contiguous byte pool with hybrid bump + free-list allocator.
///
/// - [`ByteSlab`]: the pool itself — allocate, deallocate, and read byte regions.
/// - [`ByteSlot`]: a 16-byte handle (offset + length + alloc size + owner id)
///   returned by [`ByteSlab::allocate`]; acts as coordinates into the pool.
/// - [`SlabFull`]: error returned when neither the free list nor the bump
///   region can satisfy an allocation request.
///
/// See [`ByteSlab`] type-level docs for design details, memory layout
/// diagrams, and invariants.
pub use byte_slab::{ByteSlab, ByteSlot, MIN_BLOCK, SlabFull};

/// FNV-1a 64-bit hashing helpers for deterministic fingerprinting.
///
/// Re-exported from [`fnv`] for convenience. These are the shared primitives
/// used across `gossip-engine` and `gossip-worker` for page signatures and
/// finding fingerprints.
pub use fnv::{FNV_OFFSET, FNV_PRIME, fnv_mix_byte, fnv_mix_bytes, fnv_mix_opt_bytes, fnv_mix_u64};

/// Stack-first small vector backed by `[MaybeUninit<T>; N]`.
///
/// Stores up to `N` elements inline with zero heap allocation. On the
/// `N+1`th push, all elements spill one-way to a heap `Vec<T>`.
/// Typical use: `InlineVec<ShardId, N>` for spawned-children lists where
/// most shards have few children and the inline path avoids allocation.
pub use inline_vec::InlineVec;

/// Fixed-capacity ring buffer with stack-allocated storage and power-of-2
/// bitwise indexing.
///
/// - [`RingBuffer`]: the buffer itself — `push_back`, `pop_front`,
///   `push_back_overwrite` (evict oldest on overflow).
/// - [`Iter`]: borrowing iterator with [`DoubleEndedIterator`] support
///   (forward and reverse traversal).
/// - [`IntoIter`]: consuming iterator that yields owned elements in FIFO
///   order; remaining elements are dropped when the iterator is dropped.
pub use ring_buffer::{IntoIter, Iter, RingBuffer};
