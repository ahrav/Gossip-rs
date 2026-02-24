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

pub mod key_encoding;

pub use key_encoding::{
    KeyEncoding, PrefixShardError, byte_midpoint, key_successor, prefix_successor,
};
