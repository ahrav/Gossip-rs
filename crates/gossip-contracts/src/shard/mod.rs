//! Public shard key primitives for split planning.
//!
//! This module is a stable re-export surface for allocation-free, byte-level
//! shard key primitives from [`key_encoding`]:
//! - [`KeyBuf`] for reusable stack-backed key output buffers.
//! - [`KeyEncoding`] for mapping logical keys into lexicographically sortable
//!   bytes via caller-provided buffers.
//! - [`prefix_successor`], [`key_successor`], and [`byte_midpoint`] for
//!   deterministic key-boundary derivation in split planning.
//! - [`PrefixShardError`] for invalid prefix-based shard construction inputs.
//!
//! Boundary helpers here are local key arithmetic only: they return either a
//! representable boundary key or `None`, and they write results into
//! caller-provided buffers.
//!
//! **Dependency direction:** May depend on `identity` and `coordination`.
//! Must not reference `connector` or `persistence`.
//!
//! **Integration contracts:**
//! - Ordering: byte encodings and derived boundaries are interpreted under
//!   lexicographic byte order.
//! - Buffer lifetime: helper return values borrow caller-provided [`KeyBuf`]
//!   storage and are replaced on the next write to that buffer.
//! - Partition validation: whole-partition invariants (coverage, disjointness,
//!   child ordering) are enforced in [`crate::coordination::shard_spec`], not
//!   in this re-export module.

pub mod key_encoding;

pub use key_encoding::{
    KeyBuf, KeyEncoding, PrefixShardError, byte_midpoint, key_successor, prefix_successor,
};
