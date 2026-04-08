//! Capacity limits that keep shard split coordination bounded.
//!
//! The coordinator enforces these caps whenever it creates split, residual, or
//! spawn children so that neither a single operation nor a shard's lifetime can
//! drive unbounded allocation (SEC-4: resource exhaustion guard). These
//! constants stay aligned with the split/residual machinery, and the invariants
//! later in the module ensure the relationships remain intact.

/// Hard cap on the number of children a single `SplitReplace` can create.
///
/// The coordinator never issues more than 256 child shards per split.
/// This keeps the metadata carried in the operation and the shard map
/// updates tractable while still permitting fine-grained subdivision.
pub const MAX_SPLIT_CHILDREN: usize = 256;

/// Lifetime cap on children and residual shards produced by one parent.
///
/// Every parent shard must never exceed 1024 spawned descendants, including
/// split children and residual follow-ons that can come from later operations.
/// This keeps a single shard from generating an unbounded tree of descendants
/// over repeated coordinator actions and keeps SEC-4 accountability tractable.
pub const MAX_SPAWNED_PER_SHARD: usize = 1024;

// Compile-time invariants that keep the capacity constants aligned.
// A single split must not exceed the lifetime cap for its parent.
const _: () = assert!(MAX_SPLIT_CHILDREN <= MAX_SPAWNED_PER_SHARD);
// Each split must make progress by producing at least two children.
const _: () = assert!(MAX_SPLIT_CHILDREN >= 2);
// Both caps must stay positive and fit inside the 32-bit shard counters.
const _: () = assert!(MAX_SPAWNED_PER_SHARD > 0);
// The lifetime cap must fit within the network wire format.
const _: () = assert!(MAX_SPAWNED_PER_SHARD <= u32::MAX as usize);
