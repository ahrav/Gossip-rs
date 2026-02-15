//! Key encoding schemas, range arithmetic, and split computation.
//!
//! **Phase 0 status:** This module is currently a documentation scaffold. The
//! APIs described below are planned design targets for Phase 1 implementation.
//!
//! This module will own the shard algebra that governs how the scanner's keyspace
//! is partitioned: key encoding schemas (`PathKey`, `NumericPrefixKey`, …),
//! key-range types with intersection/union/containment operations, the split-key
//! computation that divides oversize shards, ordering proofs, and the coverage
//! verification logic that answers "did we scan everything?" after a run settles.
//!
//! **Dependency direction:** May depend on `identity` and `coordination`
//! (for ID types and shard metadata). Must not reference `connector` or
//! `persistence`.
//!
//! **Key invariants:**
//! - Split coverage — child shard key ranges must exactly partition the
//!   parent's range with no gaps and no overlaps.
//! - Key ordering — split keys are deterministic pure functions of their
//!   inputs; same inputs always produce the same split point.
//! - Range algebra correctness — intersection, union, and containment
//!   operations are consistent with lexicographic byte ordering.
