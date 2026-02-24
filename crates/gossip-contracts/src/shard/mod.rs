//! Public shard key primitives for split planning.
//!
//! This module currently exposes byte-level building blocks from
//! [`key_encoding`]:
//! - [`KeyEncoding`] for mapping logical keys into lexicographically sortable
//!   bytes.
//! - [`prefix_successor`], [`key_successor`], and [`byte_midpoint`] for
//!   deterministic key-boundary derivation in split planning.
//! - [`PrefixShardError`] for invalid prefix-based shard construction inputs.
//!
//! It intentionally does not enforce whole-partition invariants (coverage,
//! disjointness, child ordering). Those checks live in
//! [`crate::coordination::shard_spec`].
//!
//! **Dependency direction:** May depend on `identity` and `coordination`.
//! Must not reference `connector` or `persistence`.
//!
//! **Key invariants:**
//! - Split coverage -- child key ranges produced by split planning tile the
//!   parent range without gaps or overlaps.
//! - Key ordering -- all key-boundary functions preserve lexicographic byte
//!   ordering; `prefix_successor` and `key_successor` produce strict
//!   successors, `byte_midpoint` produces a value strictly between inputs.
//! - Range algebra correctness -- midpoint, successor, and prefix-successor
//!   results stay within representable bounds (`MAX_KEY_SIZE`) or return
//!   `None`.

pub mod key_encoding;

pub use key_encoding::{
    KeyEncoding, PrefixShardError, byte_midpoint, key_successor, prefix_successor,
};
