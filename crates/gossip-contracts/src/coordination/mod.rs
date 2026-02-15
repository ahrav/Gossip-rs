//! Shard lifecycle, lease management, and the coordination backend trait.
//!
//! **Phase 0 status:** This module is currently a documentation scaffold. The
//! APIs described below are planned design targets for Phase 1 implementation.
//!
//! This module will own the shard state machine (`Active → Done | Parked | Split`),
//! lease management (`Lease`, `FenceEpoch`), the `CoordinationBackend` trait
//! that all storage backends implement, run lifecycle (`RunRecord`, `RunConfig`,
//! `RunManagement`), and the ergonomic `WorkerSession` wrapper. Together these
//! define how shards are assigned to workers, how progress is checkpointed, and
//! how ownership is transferred via fencing tokens.
//!
//! **Dependency direction:** May depend on `identity` (for ID types and
//! `CanonicalBytes`). Must not reference `shard`, `connector`, or `persistence`.
//!
//! **Key invariants:**
//! - Tenant isolation — every operation verifies `request.tenant == record.tenant`.
//! - Fence monotonicity — `fence_epoch` is monotonically non-decreasing per shard;
//!   stale fences are rejected.
//! - Lease expiry — operations on expired leases are rejected; unrenewed leases
//!   allow re-acquisition by other workers.
//! - OpId idempotency — replayed operations return cached results; conflicting
//!   payloads for the same `OpId` are rejected.
//! - Terminal irreversibility — `Done`, `Parked`, and `Split` shards (and
//!   `Done` / `Failed` runs) reject all further mutations.
