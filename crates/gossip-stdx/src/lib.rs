//! Shared low-level data structures for gossip-rs.
//!
//! This crate encapsulates `unsafe` internals (e.g., `MaybeUninit`-based
//! storage) behind safe public APIs. It exists separately from
//! `gossip-contracts` because that crate uses `#![forbid(unsafe_code)]`.
//!
//! # Miri testing
//!
//! All tests in this crate should be run under Miri to verify memory safety:
//! ```sh
//! cargo +nightly miri test -p gossip-stdx
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(clippy::undocumented_unsafe_blocks)]

mod inline_vec;
mod ring_buffer;

pub use inline_vec::InlineVec;
pub use ring_buffer::{IntoIter, Iter, RingBuffer};
