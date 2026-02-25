//! Shared low-level data structures for gossip-rs.
//!
//! This crate encapsulates `unsafe` internals (e.g., `MaybeUninit`-based
//! storage) behind safe public APIs. It exists separately from
//! `gossip-contracts` because that crate uses `#![forbid(unsafe_code)]`.
//!
//! # Provided types
//!
//! | Type | Purpose |
//! |------|---------|
//! | [`ByteSlab`] / [`ByteSlot`] | Pre-allocated contiguous byte pool with bump + free-list allocator |
//! | [`InlineVec`] | Stack-first small vector; stays inline for 0..N elements, spills to heap beyond |
//! | [`RingBuffer`] | Fixed-capacity circular buffer with power-of-2 indexing; zero heap allocation |
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
mod inline_vec;
mod ring_buffer;

/// Pre-allocated contiguous byte pool. See [`byte_slab`](crate) module docs.
pub use byte_slab::{ByteSlab, ByteSlot, SlabFull};
/// Stack-first small vector that avoids heap allocation for common-case small counts.
pub use inline_vec::InlineVec;
/// Fixed-capacity ring buffer and its iterators.
pub use ring_buffer::{IntoIter, Iter, RingBuffer};
