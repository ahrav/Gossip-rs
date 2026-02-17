//! Simulated worker for deterministic coordination testing.
//!
//! Each [`SimWorker`] tracks its own shard acquisitions, op-ID generation,
//! pause state, and cursor progress. Op-ID spaces are partitioned per worker
//! to guarantee cross-worker uniqueness without coordination.

use std::collections::BTreeMap;

use crate::coordination::Lease;
use crate::identity::{OpId, RunId, ShardId, ShardKey, WorkerId};

/// Maximum number of shards a single worker may hold simultaneously.
///
/// Bounded to prevent unbounded growth in simulation state.
const MAX_HELD_SHARDS: usize = 64;

/// Size of each worker's op-ID partition.
///
/// Worker N generates op-IDs in `[N * PARTITION, (N+1) * PARTITION)`.
const OP_ID_PARTITION: u64 = 1_000_000;

/// Simulated worker that tracks lease bookkeeping, op-ID generation, and
/// cursor progress for the simulation harness.
///
/// This is a **local view** of what the worker believes it holds. It may
/// diverge from the coordinator's ground truth (e.g., after a lease expires
/// without the worker noticing). The [`InvariantChecker`](super::InvariantChecker)
/// always validates against coordinator state, never against `SimWorker`
/// bookkeeping, to avoid masking real invariant violations.
pub struct SimWorker {
    id: WorkerId,
    /// Shards this worker believes it holds.
    ///
    /// Keyed by `(run_raw, shard_raw)` to provide deterministic iteration
    /// order (matching the natural `(RunId, ShardId)` tuple ordering)
    /// without requiring `Ord` on `ShardKey`.
    held_shards: BTreeMap<(u64, u64), (ShardKey, Lease)>,
    next_op: u64,
    op_ceiling: u64,
    paused: bool,
    last_cursors: BTreeMap<(RunId, ShardId), Vec<u8>>,
}

impl SimWorker {
    /// Create a new simulated worker.
    ///
    /// # Panics
    ///
    /// Panics if `id.as_raw() * 1_000_000` overflows `u64`, or if the
    /// resulting partition ceiling `(id + 1) * 1_000_000` overflows, which
    /// means the worker ID is too large for the partitioned op-ID scheme.
    pub fn new(id: WorkerId) -> Self {
        let base = id
            .as_raw()
            .checked_mul(OP_ID_PARTITION)
            .expect("WorkerId too large for op-ID partitioning");
        let ceiling = base
            .checked_add(OP_ID_PARTITION)
            .expect("op-ID partition ceiling overflow");
        Self {
            id,
            held_shards: BTreeMap::new(),
            next_op: base,
            op_ceiling: ceiling,
            paused: false,
            last_cursors: BTreeMap::new(),
        }
    }

    /// This worker's identity.
    #[must_use]
    pub fn id(&self) -> WorkerId {
        self.id
    }

    /// Whether this worker is currently paused (simulating a stall/hang).
    #[must_use]
    pub fn is_paused(&self) -> bool {
        self.paused
    }

    /// Pause this worker.
    pub fn pause(&mut self) {
        self.paused = true;
    }

    /// Resume this worker.
    pub fn resume(&mut self) {
        self.paused = false;
    }

    /// Generate the next op-ID from this worker's partition.
    ///
    /// # Panics
    ///
    /// Panics if the partition is exhausted (more than 1M ops per worker).
    pub fn next_op_id(&mut self) -> OpId {
        assert!(
            self.next_op < self.op_ceiling,
            "op-ID partition exhausted for worker {}",
            self.id.as_raw(),
        );
        let id = OpId::from_raw(self.next_op);
        self.next_op += 1;
        id
    }

    /// Record a successful shard acquisition.
    ///
    /// Replaces any previously tracked lease for the same key.
    ///
    /// # Panics
    ///
    /// Panics if held shard count would exceed `MAX_HELD_SHARDS`.
    pub fn record_acquire(&mut self, key: ShardKey, lease: Lease) {
        let raw = (key.run().as_raw(), key.shard().as_raw());
        if !self.held_shards.contains_key(&raw) {
            assert!(
                self.held_shards.len() < MAX_HELD_SHARDS,
                "SimWorker {}: exceeded MAX_HELD_SHARDS ({MAX_HELD_SHARDS})",
                self.id.as_raw(),
            );
        }
        self.held_shards.insert(raw, (key, lease));
    }

    /// Remove tracking for a released/expired shard.
    pub fn record_release(&mut self, key: &ShardKey) {
        let raw = (key.run().as_raw(), key.shard().as_raw());
        self.held_shards.remove(&raw);
    }

    /// Look up the tracked lease for a shard key.
    #[must_use]
    pub fn lease_for(&self, key: &ShardKey) -> Option<&Lease> {
        let raw = (key.run().as_raw(), key.shard().as_raw());
        self.held_shards.get(&raw).map(|(_, lease)| lease)
    }

    /// Iterator over currently held shard keys in deterministic order.
    ///
    /// `BTreeMap<(u64, u64), _>` iterates in ascending `(run, shard)` order,
    /// so callers get reproducible iteration without collecting and sorting.
    pub fn held_keys(&self) -> impl Iterator<Item = &ShardKey> {
        self.held_shards.values().map(|(key, _)| key)
    }

    /// Number of shards currently held.
    #[must_use]
    pub fn held_count(&self) -> usize {
        self.held_shards.len()
    }

    /// Record the last checkpoint cursor for a shard.
    pub fn record_cursor(&mut self, run: RunId, shard: ShardId, last_key: Vec<u8>) {
        self.last_cursors.insert((run, shard), last_key);
    }

    /// Retrieve the last checkpoint cursor for a shard.
    #[must_use]
    pub fn last_cursor_for(&self, run: RunId, shard: ShardId) -> Option<&[u8]> {
        self.last_cursors.get(&(run, shard)).map(|v| v.as_slice())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{RunId, ShardId};
    use proptest::prelude::*;

    fn test_key() -> ShardKey {
        ShardKey::new(RunId::from_raw(1), ShardId::from_raw(1))
    }

    fn test_key_2() -> ShardKey {
        ShardKey::new(RunId::from_raw(1), ShardId::from_raw(2))
    }

    fn dummy_lease(worker: WorkerId, key: &ShardKey) -> Lease {
        use crate::coordination::Lease;
        use crate::identity::{FenceEpoch, LogicalTime, TenantId};

        Lease::new(
            TenantId::from_bytes([0x01; 32]),
            key.run(),
            key.shard(),
            worker,
            FenceEpoch::INITIAL,
            LogicalTime::from_raw(100),
        )
    }

    #[test]
    fn acquire_release_tracking() {
        let wid = WorkerId::from_raw(0);
        let mut w = SimWorker::new(wid);
        let key = test_key();
        let lease = dummy_lease(wid, &key);

        assert!(w.lease_for(&key).is_none());
        w.record_acquire(key, lease);
        assert!(w.lease_for(&key).is_some());
        assert_eq!(w.held_count(), 1);

        w.record_release(&key);
        assert!(w.lease_for(&key).is_none());
        assert_eq!(w.held_count(), 0);
    }

    #[test]
    fn re_acquire_replaces_old_entry() {
        let wid = WorkerId::from_raw(0);
        let mut w = SimWorker::new(wid);
        let key = test_key();

        let lease1 = dummy_lease(wid, &key);
        w.record_acquire(key, lease1);
        assert_eq!(w.held_count(), 1);

        let lease2 = dummy_lease(wid, &key);
        w.record_acquire(key, lease2);
        assert_eq!(w.held_count(), 1);
    }

    #[test]
    #[should_panic(expected = "op-ID partition exhausted")]
    fn op_id_partition_exhaustion_panics() {
        // Worker 0 has partition [0, 1_000_000).
        let mut w = SimWorker::new(WorkerId::from_raw(0));
        for _ in 0..1_000_001 {
            w.next_op_id();
        }
    }

    #[test]
    #[should_panic(expected = "exceeded MAX_HELD_SHARDS")]
    fn max_held_shards_panics() {
        let wid = WorkerId::from_raw(0);
        let mut w = SimWorker::new(wid);
        for i in 0..=MAX_HELD_SHARDS as u64 {
            let key = ShardKey::new(RunId::from_raw(1), ShardId::from_raw(i));
            let lease = dummy_lease(wid, &key);
            w.record_acquire(key, lease);
        }
    }

    #[test]
    fn pause_resume() {
        let mut w = SimWorker::new(WorkerId::from_raw(0));
        assert!(!w.is_paused());
        w.pause();
        assert!(w.is_paused());
        w.resume();
        assert!(!w.is_paused());
    }

    #[test]
    fn held_keys_iteration() {
        let wid = WorkerId::from_raw(0);
        let mut w = SimWorker::new(wid);
        let k1 = test_key();
        let k2 = test_key_2();
        w.record_acquire(k1, dummy_lease(wid, &k1));
        w.record_acquire(k2, dummy_lease(wid, &k2));

        let keys: Vec<_> = w.held_keys().collect();
        assert_eq!(keys.len(), 2);
    }

    proptest! {
        #![proptest_config(crate::test_util::miri_proptest_config())]

        #[test]
        fn prop_op_ids_unique_across_workers(
            worker_count in 2..8usize,
            ops_per_worker in 1..200usize,
        ) {
            let mut all_ids = std::collections::HashSet::new();
            for i in 0..worker_count as u64 {
                let mut w = SimWorker::new(WorkerId::from_raw(i));
                for _ in 0..ops_per_worker {
                    let id = w.next_op_id();
                    prop_assert!(
                        all_ids.insert(id.as_raw()),
                        "duplicate op-ID {} from worker {}",
                        id.as_raw(),
                        i,
                    );
                }
            }
        }

        #[test]
        fn prop_cursor_last_write_wins(
            run_raw in any::<u64>(),
            shard_raw in any::<u64>(),
            first in proptest::collection::vec(any::<u8>(), 0..64),
            second in proptest::collection::vec(any::<u8>(), 0..64),
        ) {
            let mut w = SimWorker::new(WorkerId::from_raw(0));
            let run = RunId::from_raw(run_raw);
            let shard = ShardId::from_raw(shard_raw);

            // Initially absent.
            prop_assert!(w.last_cursor_for(run, shard).is_none());

            // Record first cursor, read it back.
            w.record_cursor(run, shard, first.clone());
            prop_assert_eq!(
                w.last_cursor_for(run, shard),
                Some(first.as_slice()),
            );

            // Overwrite, last-write-wins.
            w.record_cursor(run, shard, second.clone());
            prop_assert_eq!(
                w.last_cursor_for(run, shard),
                Some(second.as_slice()),
            );
        }
    }
}
