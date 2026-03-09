//! Shared shard-count limit validation helpers.
//!
//! Both coordination backends enforce the same two ceilings:
//! - per-tenant shard count
//! - global shard count
//!
//! This module keeps the enforcement logic in one place so every backend
//! evaluates limits with identical ordering and overflow-safe arithmetic.

use gossip_contracts::coordination::shard_spec::ShardLimitScope;

/// Snapshot of shard counts used for shard-limit validation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShardCountSnapshot {
    /// Shards under the requesting tenant's namespace.
    pub tenant: usize,
    /// Shards across all tenants.
    pub total: usize,
}

/// Details for the first shard-limit violation in a growth check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShardLimitViolation {
    /// Count before applying the requested growth.
    pub current: usize,
    /// Requested additional shard count.
    pub additional: usize,
    /// Effective limit for the violated scope.
    pub max: usize,
    /// Whether the violated ceiling is tenant-local or global.
    pub scope: ShardLimitScope,
}

/// Returns the first shard-count ceiling that `additional` would exceed.
///
/// Checks are evaluated in this order:
/// 1. per-tenant
/// 2. global
///
/// Count arithmetic uses saturating addition so oversized caller input
/// cannot overflow and wrap into a false negative.
pub fn shard_limit_violation(
    counts: ShardCountSnapshot,
    additional: usize,
    max_shards_per_tenant: usize,
    max_total_shards: usize,
) -> Option<ShardLimitViolation> {
    if counts.tenant.saturating_add(additional) > max_shards_per_tenant {
        return Some(ShardLimitViolation {
            current: counts.tenant,
            additional,
            max: max_shards_per_tenant,
            scope: ShardLimitScope::PerTenant,
        });
    }

    if counts.total.saturating_add(additional) > max_total_shards {
        return Some(ShardLimitViolation {
            current: counts.total,
            additional,
            max: max_total_shards,
            scope: ShardLimitScope::Global,
        });
    }

    None
}
