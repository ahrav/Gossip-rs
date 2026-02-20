//! Simplified in-memory coordination backend for simulation testing.
//!
//! This is a lightweight coordination backend that implements the core
//! shard lifecycle operations (acquire, checkpoint, complete, release)
//! with fencing, lease management, and idempotency — just enough to
//! verify the coordination invariants under fault injection.
//!
//! This is NOT the full `InMemoryCoordinator` from the phase 2 spec.
//! It's a simulation-focused subset that exercises the invariants
//! without the full operational complexity.

use std::collections::BTreeMap;

use gossip_contracts::coordination::{FenceEpoch, LogicalTime, OpId, ShardId, WorkerId};

/// Result of a coordination operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpResult {
    /// Operation succeeded.
    Ok,
    /// Shard was acquired, returning the assigned epoch.
    Acquired { epoch: FenceEpoch },
    /// Operation rejected: fence epoch is stale.
    StaleEpoch {
        presented: FenceEpoch,
        current: FenceEpoch,
    },
    /// Operation rejected: lease has expired.
    LeaseExpired {
        deadline: LogicalTime,
        now: LogicalTime,
    },
    /// Operation rejected: shard is in a terminal state.
    TerminalState { shard: ShardId, status: ShardStatus },
    /// Operation rejected: shard not found.
    NotFound { shard: ShardId },
    /// Idempotent replay: operation already executed with same result.
    IdempotentReplay { op_id: OpId },
}

/// Shard lifecycle states.
///
/// Follows the state machine: `Open → Active → {Done, Parked, Split}`.
/// Terminal states (`Done`, `Parked`, `Split`) are irreversible.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShardStatus {
    /// Shard exists but has no active worker.
    Open,
    /// Shard is actively being scanned by a worker.
    Active,
    /// Shard scan completed successfully. Terminal.
    Done,
    /// Shard parked for later processing. Terminal.
    Parked,
    /// Shard split into children. Terminal.
    Split,
}

impl ShardStatus {
    /// Whether this status is terminal (no further transitions allowed).
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Done | Self::Parked | Self::Split)
    }
}

/// Internal shard record in the simulation backend.
#[derive(Debug, Clone)]
pub struct SimShardRecord {
    pub id: ShardId,
    pub status: ShardStatus,
    pub epoch: FenceEpoch,
    pub holder: Option<WorkerId>,
    pub lease_deadline: Option<LogicalTime>,
    pub checkpoint_count: u64,
    pub completed_ops: BTreeMap<OpId, OpResult>,
}

/// Simplified in-memory coordination backend for simulation.
///
/// Implements core coordination operations with fencing, lease management,
/// and idempotency checking. Designed for invariant verification under
/// fault injection, not production use.
pub struct SimBackend {
    shards: BTreeMap<ShardId, SimShardRecord>,
    lease_duration: u64,
}

impl SimBackend {
    /// Create a new backend with the given lease duration (in logical ticks).
    pub fn new(lease_duration: u64) -> Self {
        Self {
            shards: BTreeMap::new(),
            lease_duration,
        }
    }

    /// Register a shard in the `Open` state.
    pub fn register_shard(&mut self, id: ShardId) {
        self.shards.insert(
            id,
            SimShardRecord {
                id,
                status: ShardStatus::Open,
                epoch: FenceEpoch(0),
                holder: None,
                lease_deadline: None,
                checkpoint_count: 0,
                completed_ops: BTreeMap::new(),
            },
        );
    }

    /// Acquire a shard for a worker. Bumps the fence epoch and sets a lease.
    pub fn acquire(
        &mut self,
        shard: ShardId,
        worker: WorkerId,
        op_id: OpId,
        now: LogicalTime,
    ) -> OpResult {
        let Some(record) = self.shards.get_mut(&shard) else {
            return OpResult::NotFound { shard };
        };

        // Idempotency check.
        if let Some(result) = record.completed_ops.get(&op_id) {
            return result.clone();
        }

        // Terminal state check.
        if record.status.is_terminal() {
            return OpResult::TerminalState {
                shard,
                status: record.status,
            };
        }

        // Can only acquire Open shards, or Active shards with expired leases.
        match record.status {
            ShardStatus::Open => {}
            ShardStatus::Active => {
                if let Some(deadline) = record.lease_deadline
                    && now < deadline
                {
                    // Lease still valid — someone else holds it.
                    return OpResult::StaleEpoch {
                        presented: FenceEpoch(0),
                        current: record.epoch,
                    };
                }
                // Lease expired — can re-acquire.
            }
            _ => unreachable!("terminal states handled above"),
        }

        // Bump epoch and assign.
        let new_epoch = record.epoch.next();
        record.epoch = new_epoch;
        record.status = ShardStatus::Active;
        record.holder = Some(worker);
        record.lease_deadline = Some(now.advance(self.lease_duration));

        let result = OpResult::Acquired { epoch: new_epoch };
        record.completed_ops.insert(op_id, result.clone());
        result
    }

    /// Checkpoint progress on a shard. Validates fence epoch and lease.
    pub fn checkpoint(
        &mut self,
        shard: ShardId,
        worker: WorkerId,
        epoch: FenceEpoch,
        op_id: OpId,
        now: LogicalTime,
    ) -> OpResult {
        let Some(record) = self.shards.get_mut(&shard) else {
            return OpResult::NotFound { shard };
        };

        // Idempotency check.
        if let Some(result) = record.completed_ops.get(&op_id) {
            return result.clone();
        }

        // Terminal state check.
        if record.status.is_terminal() {
            return OpResult::TerminalState {
                shard,
                status: record.status,
            };
        }

        // Fence check: reject stale epochs.
        if epoch < record.epoch {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Lease check: reject expired leases.
        if let Some(deadline) = record.lease_deadline
            && now >= deadline
        {
            return OpResult::LeaseExpired { deadline, now };
        }

        // Holder check: only the holder can checkpoint.
        if record.holder != Some(worker) {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Checkpoint: renew lease and increment counter.
        record.checkpoint_count += 1;
        record.lease_deadline = Some(now.advance(self.lease_duration));

        let result = OpResult::Ok;
        record.completed_ops.insert(op_id, result.clone());
        result
    }

    /// Mark a shard as done (terminal).
    pub fn complete(
        &mut self,
        shard: ShardId,
        worker: WorkerId,
        epoch: FenceEpoch,
        op_id: OpId,
        now: LogicalTime,
    ) -> OpResult {
        let Some(record) = self.shards.get_mut(&shard) else {
            return OpResult::NotFound { shard };
        };

        // Idempotency check.
        if let Some(result) = record.completed_ops.get(&op_id) {
            return result.clone();
        }

        // Terminal state check.
        if record.status.is_terminal() {
            return OpResult::TerminalState {
                shard,
                status: record.status,
            };
        }

        // Fence check.
        if epoch < record.epoch {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Lease check.
        if let Some(deadline) = record.lease_deadline
            && now >= deadline
        {
            return OpResult::LeaseExpired { deadline, now };
        }

        // Holder check.
        if record.holder != Some(worker) {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Transition to Done (terminal, irreversible).
        record.status = ShardStatus::Done;
        record.lease_deadline = None;

        let result = OpResult::Ok;
        record.completed_ops.insert(op_id, result.clone());
        result
    }

    /// Release a shard back to Open state (voluntary release, not terminal).
    pub fn release(
        &mut self,
        shard: ShardId,
        worker: WorkerId,
        epoch: FenceEpoch,
        op_id: OpId,
        now: LogicalTime,
    ) -> OpResult {
        let Some(record) = self.shards.get_mut(&shard) else {
            return OpResult::NotFound { shard };
        };

        // Idempotency check.
        if let Some(result) = record.completed_ops.get(&op_id) {
            return result.clone();
        }

        // Terminal state check.
        if record.status.is_terminal() {
            return OpResult::TerminalState {
                shard,
                status: record.status,
            };
        }

        // Fence check.
        if epoch < record.epoch {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Lease check.
        if let Some(deadline) = record.lease_deadline
            && now >= deadline
        {
            return OpResult::LeaseExpired { deadline, now };
        }

        // Holder check.
        if record.holder != Some(worker) {
            return OpResult::StaleEpoch {
                presented: epoch,
                current: record.epoch,
            };
        }

        // Return to Open.
        record.status = ShardStatus::Open;
        record.holder = None;
        record.lease_deadline = None;

        let result = OpResult::Ok;
        record.completed_ops.insert(op_id, result.clone());
        result
    }

    /// Read-only access to all shard records (for invariant checking).
    pub fn shards(&self) -> &BTreeMap<ShardId, SimShardRecord> {
        &self.shards
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(n: u64) -> LogicalTime {
        LogicalTime(n)
    }

    #[test]
    fn acquire_open_shard() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));

        let result = backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));
        assert!(matches!(result, OpResult::Acquired { epoch } if epoch == FenceEpoch(1)));
    }

    #[test]
    fn acquire_bumps_epoch() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));

        // First acquire.
        backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));

        // Release.
        backend.release(ShardId(1), WorkerId(1), FenceEpoch(1), OpId(2), t(10));

        // Second acquire should bump epoch.
        let result = backend.acquire(ShardId(1), WorkerId(2), OpId(3), t(20));
        assert!(matches!(result, OpResult::Acquired { epoch } if epoch == FenceEpoch(2)));
    }

    #[test]
    fn checkpoint_rejects_stale_epoch() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));
        backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));

        // Checkpoint with stale epoch 0 (current is 1).
        let result = backend.checkpoint(ShardId(1), WorkerId(1), FenceEpoch(0), OpId(2), t(10));
        assert!(matches!(result, OpResult::StaleEpoch { .. }));
    }

    #[test]
    fn checkpoint_rejects_expired_lease() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));
        backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));

        // Checkpoint after lease expiry (deadline = 100, now = 200).
        let result = backend.checkpoint(ShardId(1), WorkerId(1), FenceEpoch(1), OpId(2), t(200));
        assert!(matches!(result, OpResult::LeaseExpired { .. }));
    }

    #[test]
    fn complete_makes_terminal() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));
        backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));
        backend.complete(ShardId(1), WorkerId(1), FenceEpoch(1), OpId(2), t(10));

        // Attempt to acquire a Done shard.
        let result = backend.acquire(ShardId(1), WorkerId(2), OpId(3), t(20));
        assert!(matches!(
            result,
            OpResult::TerminalState {
                status: ShardStatus::Done,
                ..
            }
        ));
    }

    #[test]
    fn idempotent_replay() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));

        // Same OpId returns same result.
        let r1 = backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));
        let r2 = backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(5));
        assert_eq!(r1, r2);
    }

    #[test]
    fn expired_lease_allows_reacquire() {
        let mut backend = SimBackend::new(100);
        backend.register_shard(ShardId(1));
        backend.acquire(ShardId(1), WorkerId(1), OpId(1), t(0));

        // After lease expiry, another worker can acquire.
        let result = backend.acquire(ShardId(1), WorkerId(2), OpId(2), t(200));
        assert!(matches!(result, OpResult::Acquired { epoch } if epoch == FenceEpoch(2)));
    }
}
