//! Capacity constants for split operations.
//!
//! These constants bound the fan-out of split operations and cumulative
//! child counts per parent shard, preventing single operations from
//! creating unbounded shard records (SEC-4 resource exhaustion guard).

/// Maximum number of children in a single SplitReplace operation.
///
/// Bounds the fan-out of any single split to prevent a single coordinator
/// operation from creating an unbounded number of shards. 256 children
/// allows fine-grained subdivision while keeping the per-operation metadata
/// size tractable (SEC-4: resource exhaustion guard).
pub const MAX_SPLIT_CHILDREN: usize = 256;

/// Maximum total spawned shards per parent shard.
///
/// Caps the cumulative number of children + residuals a parent may produce
/// across its lifetime (multiple split-residual operations accumulate).
/// 1024 bounds the total spawn count per parent shard (SEC-4).
pub const MAX_SPAWNED_PER_SHARD: usize = 1024;

// Relationship assertion: a single split can't exceed total spawned cap.
const _: () = assert!(MAX_SPLIT_CHILDREN <= MAX_SPAWNED_PER_SHARD);
const _: () = assert!(MAX_SPLIT_CHILDREN >= 2);
const _: () = assert!(MAX_SPAWNED_PER_SHARD > 0);
const _: () = assert!(MAX_SPAWNED_PER_SHARD <= u32::MAX as usize);
