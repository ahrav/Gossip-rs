//! Shared write-side metadata carried with runtime persistence requests.
//!
//! Downstream durability writes need two kinds of scope at the same time:
//!
//! 1. **Identity/routing scope** — `tenant_id` and `policy_hash` decide which
//!    logical namespace the write belongs to.
//! 2. **Ownership/fencing scope** — `(run_id, shard_id, fence_epoch)` ties the
//!    write to the specific lease epoch that produced it.
//!
//! This module freezes the five routing and fencing fields as one explicit
//! value object so the runtime passes fencing metadata as a single copyable
//! token instead of loose scalar arguments. Backends that enforce
//! stale-writer rejection validate the fence fields directly from this
//! context.

use crate::identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId};

/// Shared write-side routing and fencing metadata.
///
/// `WriteContext` is intentionally small and copyable. It is the common shape
/// threaded through runtime commit APIs so backends can enforce stale-writer
/// rejection from a single value rather than scattered scalar parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WriteContext {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
}

impl WriteContext {
    /// Construct a shared write context from explicit routing and fencing
    /// fields.
    #[inline]
    #[must_use]
    pub const fn new(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
    ) -> Self {
        Self {
            tenant_id,
            policy_hash,
            run_id,
            shard_id,
            fence_epoch,
        }
    }

    /// Tenant isolation boundary for downstream writes.
    #[inline]
    #[must_use]
    pub const fn tenant_id(self) -> TenantId {
        self.tenant_id
    }

    /// Detection-policy version under which the write was produced.
    #[inline]
    #[must_use]
    pub const fn policy_hash(self) -> PolicyHash {
        self.policy_hash
    }

    /// Run that produced the write.
    #[inline]
    #[must_use]
    pub const fn run_id(self) -> RunId {
        self.run_id
    }

    /// Shard that produced the write.
    #[inline]
    #[must_use]
    pub const fn shard_id(self) -> ShardId {
        self.shard_id
    }

    /// Fence epoch proving lease ownership when the write was created.
    #[inline]
    #[must_use]
    pub const fn fence_epoch(self) -> FenceEpoch {
        self.fence_epoch
    }
}

const _: () = assert!(core::mem::size_of::<WriteContext>() == 88);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_context_preserves_routing_and_fence_fields() {
        let context = WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(3),
            ShardId::from_raw(4),
            FenceEpoch::from_raw(5),
        );

        assert_eq!(context.tenant_id(), TenantId::from_bytes([0x11; 32]));
        assert_eq!(context.policy_hash(), PolicyHash::from_bytes([0x22; 32]));
        assert_eq!(context.run_id(), RunId::from_raw(3));
        assert_eq!(context.shard_id(), ShardId::from_raw(4));
        assert_eq!(context.fence_epoch(), FenceEpoch::from_raw(5));
    }
}
