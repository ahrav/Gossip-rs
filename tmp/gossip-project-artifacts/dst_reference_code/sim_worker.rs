//! Simulated worker for coordination testing.
//!
//! Each `SimWorker` represents a worker node in the simulation. It holds
//! its identity, the shards it currently owns (with their epochs), and
//! an operation counter for generating unique `OpId`s.

use gossip_contracts::coordination::{FenceEpoch, OpId, ShardId, WorkerId};

/// A simulated worker participating in coordination.
#[derive(Debug)]
pub struct SimWorker {
    /// Worker identity.
    pub id: WorkerId,
    /// Shards currently held by this worker, mapped to their fence epochs.
    pub held_shards: Vec<(ShardId, FenceEpoch)>,
    /// Next operation ID to assign.
    next_op: u64,
    /// Whether this worker is currently "paused" (simulating GC pause / network isolation).
    pub paused: bool,
}

impl SimWorker {
    /// Create a new worker with the given ID.
    pub fn new(id: WorkerId) -> Self {
        Self {
            // Spread op_id space across workers to avoid collisions.
            next_op: id.0 * 1_000_000,
            id,
            held_shards: Vec::new(),
            paused: false,
        }
    }

    /// Generate a unique operation ID for this worker.
    pub fn next_op_id(&mut self) -> OpId {
        let op = OpId(self.next_op);
        self.next_op += 1;
        op
    }

    /// Record that this worker acquired a shard with the given epoch.
    ///
    /// Replaces any existing entry for the same shard (e.g., re-acquisition
    /// after release or lease expiry).
    pub fn record_acquire(&mut self, shard: ShardId, epoch: FenceEpoch) {
        self.held_shards.retain(|(s, _)| *s != shard);
        self.held_shards.push((shard, epoch));
    }

    /// Remove a shard from this worker's held set (on release or complete).
    pub fn record_release(&mut self, shard: ShardId) {
        self.held_shards.retain(|(s, _)| *s != shard);
    }

    /// Look up the epoch for a held shard.
    pub fn epoch_for(&self, shard: ShardId) -> Option<FenceEpoch> {
        self.held_shards
            .iter()
            .find(|(s, _)| *s == shard)
            .map(|(_, e)| *e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn op_ids_are_unique_within_worker() {
        let mut w = SimWorker::new(WorkerId(1));
        let a = w.next_op_id();
        let b = w.next_op_id();
        assert_ne!(a, b);
    }

    #[test]
    fn op_ids_are_unique_across_workers() {
        let mut w1 = SimWorker::new(WorkerId(1));
        let mut w2 = SimWorker::new(WorkerId(2));
        let a = w1.next_op_id();
        let b = w2.next_op_id();
        assert_ne!(a, b);
    }

    #[test]
    fn acquire_and_release_tracking() {
        let mut w = SimWorker::new(WorkerId(1));
        w.record_acquire(ShardId(10), FenceEpoch(1));

        assert_eq!(w.epoch_for(ShardId(10)), Some(FenceEpoch(1)));

        w.record_release(ShardId(10));
        assert_eq!(w.epoch_for(ShardId(10)), None);
    }
}
