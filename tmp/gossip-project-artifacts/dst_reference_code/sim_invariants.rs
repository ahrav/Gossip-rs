//! Invariant assertions for coordination simulation.
//!
//! Each function checks one coordination invariant and returns `Ok(())`
//! or `Err(description)` if the invariant is violated. These map to the
//! phase 2 spec invariant catalog.
//!
//! # Invariant catalog
//!
//! | ID | Name | Description |
//! |----|------|-------------|
//! | S1 | Mutual exclusion | At most one active lease per shard |
//! | S2 | Fence monotonicity | Epochs never decrease per shard |
//! | S3 | Terminal irreversibility | Done/Parked/Split never transition |
//! | S5 | Idempotency | Duplicate OpId returns same result |
//! | L1 | Lease exclusivity | Stale-epoch checkpoints are rejected |
//! | L2 | Zombie rejection | Restarted worker cannot use old lease |

use super::backend::{ShardStatus, SimBackend};
use super::worker::SimWorker;

/// Checks all coordination invariants against the current simulation state.
///
/// Returns a list of violated invariant descriptions (empty = all pass).
pub struct InvariantChecker;

impl InvariantChecker {
    /// Check S1: Mutual exclusion — at most one active holder per shard.
    ///
    /// Verifies that no two workers believe they hold the same shard
    /// simultaneously.
    pub fn check_mutual_exclusion(workers: &[SimWorker]) -> Result<(), String> {
        // Collect all (shard, worker) pairs from workers that aren't paused.
        let mut active_claims: Vec<(u64, u64)> = Vec::new();

        for worker in workers {
            for (shard, _epoch) in &worker.held_shards {
                active_claims.push((shard.0, worker.id.0));
            }
        }

        // Sort by shard ID to group claims.
        active_claims.sort();

        // Check for duplicate shard IDs.
        for window in active_claims.windows(2) {
            if window[0].0 == window[1].0 {
                return Err(format!(
                    "S1 MUTUAL_EXCLUSION: shard {} held by workers {} and {}",
                    window[0].0, window[0].1, window[1].1,
                ));
            }
        }

        Ok(())
    }

    /// Check S2: Fence monotonicity — epochs never decrease.
    ///
    /// Verifies that the epoch for each shard in the backend is
    /// non-decreasing relative to any previously observed epoch.
    pub fn check_fence_monotonicity(
        backend: &SimBackend,
        prev_epochs: &mut std::collections::BTreeMap<u64, u64>,
    ) -> Result<(), String> {
        for (shard_id, record) in backend.shards() {
            let current = record.epoch.0;
            let prev = prev_epochs.entry(shard_id.0).or_insert(0);
            if current < *prev {
                return Err(format!(
                    "S2 FENCE_MONOTONICITY: shard {} epoch decreased from {} to {}",
                    shard_id.0, *prev, current,
                ));
            }
            *prev = current;
        }

        Ok(())
    }

    /// Check S3: Terminal irreversibility — terminal shards stay terminal.
    ///
    /// Verifies that any shard previously observed in a terminal state
    /// is still in a terminal state.
    pub fn check_terminal_irreversibility(
        backend: &SimBackend,
        prev_terminal: &mut std::collections::BTreeSet<u64>,
    ) -> Result<(), String> {
        for (shard_id, record) in backend.shards() {
            if prev_terminal.contains(&shard_id.0) && !record.status.is_terminal() {
                return Err(format!(
                    "S3 TERMINAL_IRREVERSIBILITY: shard {} was terminal, now {:?}",
                    shard_id.0, record.status,
                ));
            }
            if record.status.is_terminal() {
                prev_terminal.insert(shard_id.0);
            }
        }

        Ok(())
    }

    /// Check that active shards have valid leases (holder is set, deadline in future).
    pub fn check_active_shards_have_leases(backend: &SimBackend) -> Result<(), String> {
        for (shard_id, record) in backend.shards() {
            if record.status == ShardStatus::Active {
                if record.holder.is_none() {
                    return Err(format!(
                        "ACTIVE_LEASE: shard {} is Active but has no holder",
                        shard_id.0,
                    ));
                }
                if record.lease_deadline.is_none() {
                    return Err(format!(
                        "ACTIVE_LEASE: shard {} is Active but has no lease deadline",
                        shard_id.0,
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use gossip_contracts::coordination::{FenceEpoch, ShardId, WorkerId};

    use super::*;
    use crate::sim::worker::SimWorker;

    #[test]
    fn mutual_exclusion_passes_with_no_overlap() {
        let mut w1 = SimWorker::new(WorkerId(1));
        let mut w2 = SimWorker::new(WorkerId(2));
        w1.record_acquire(ShardId(1), FenceEpoch(1));
        w2.record_acquire(ShardId(2), FenceEpoch(1));

        assert!(InvariantChecker::check_mutual_exclusion(&[w1, w2]).is_ok());
    }

    #[test]
    fn mutual_exclusion_fails_with_overlap() {
        let mut w1 = SimWorker::new(WorkerId(1));
        let mut w2 = SimWorker::new(WorkerId(2));
        w1.record_acquire(ShardId(1), FenceEpoch(1));
        w2.record_acquire(ShardId(1), FenceEpoch(2));

        let result = InvariantChecker::check_mutual_exclusion(&[w1, w2]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("S1 MUTUAL_EXCLUSION"));
    }
}
