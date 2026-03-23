//! Model-based oracle for convergence verification.
//!
//! The oracle maintains a separate `HashMap<DoneLedgerKey, DoneLedgerRecord>`
//! that tracks the expected durable state by applying
//! [`DoneLedgerRecord::merge`] to committed records. After the liveness
//! phase drains all pending writes, the oracle's committed state must
//! match the ledger snapshot for every key.
//!
//! The oracle verifies **sequence-level** correctness — that the harness
//! applies operations in the right order, commits and aborts the right
//! batches, and that the final state converges. It delegates to the same
//! `DoneLedgerRecord::merge` the production ledger uses; merge-algorithm
//! correctness is covered by dedicated tests on the contracts crate.

use std::collections::HashMap;

use gossip_contracts::persistence::{DoneLedgerKey, DoneLedgerRecord};

use super::invariants::DoneLedgerInvariantViolation;
use crate::{InMemoryDoneLedger, PendingWriteId};

/// Model oracle tracking expected durable state independently of the
/// [`InMemoryDoneLedger`] under test.
#[derive(Debug)]
pub struct DoneLedgerOracle {
    /// Expected durable state: only records whose commits completed
    /// successfully are merged here.
    committed: HashMap<DoneLedgerKey, DoneLedgerRecord>,

    /// Records submitted but not yet committed. Keyed by operation ID
    /// so we can selectively commit or abort individual batches.
    pending: HashMap<PendingWriteId, Vec<DoneLedgerRecord>>,
}

impl DoneLedgerOracle {
    /// Create an empty oracle.
    pub fn new() -> Self {
        Self {
            committed: HashMap::new(),
            pending: HashMap::new(),
        }
    }

    /// Register a batch as pending (submitted but not yet committed).
    ///
    /// The records are cloned because the ledger may have already
    /// consumed the originals. The oracle needs its own copy to replay
    /// the merge when the batch commits.
    pub fn submit(&mut self, op_id: PendingWriteId, records: Vec<DoneLedgerRecord>) {
        self.pending.insert(op_id, records);
    }

    /// Commit a pending batch: merge its records into the committed map.
    ///
    /// Delegates to [`DoneLedgerRecord::merge`] — the same join primitive
    /// the production ledger uses. This is intentional: the oracle verifies
    /// that the *harness applies operations in the correct sequence*, not
    /// that the merge algorithm itself is correct. Merge correctness is
    /// covered by dedicated unit and property-based tests on
    /// `DoneLedgerRecord`.
    ///
    /// Returns `false` if `op_id` was not in the pending set (already
    /// committed or aborted).
    pub fn commit(&mut self, op_id: PendingWriteId) -> bool {
        let Some(records) = self.pending.remove(&op_id) else {
            return false;
        };

        // Deduplicate within the batch first, mirroring
        // DoneLedgerBackend::apply which deduplicates before merging
        // with existing state. Without this, status-dependent fields
        // like findings_count can diverge when a batch contains
        // multiple records for the same key with different statuses.
        let mut deduped: HashMap<DoneLedgerKey, DoneLedgerRecord> =
            HashMap::with_capacity(records.len());
        for record in records {
            let key = record.key();
            match deduped.get(&key) {
                Some(existing) => {
                    let merged = existing.merge(&record).unwrap_or_else(|e| {
                        panic!(
                            "oracle intra-batch merge failure for key {key:?}: {e} \
                             (existing={existing:?}, incoming={record:?})"
                        );
                    });
                    deduped.insert(key, merged);
                }
                None => {
                    deduped.insert(key, record);
                }
            }
        }

        // Merge deduplicated records with committed state.
        for (key, record) in deduped {
            match self.committed.get(&key) {
                Some(existing) => {
                    let merged = existing.merge(&record).unwrap_or_else(|e| {
                        panic!(
                            "oracle merge failure for key {key:?}: {e} \
                             (existing={existing:?}, incoming={record:?})"
                        );
                    });
                    self.committed.insert(key, merged);
                }
                None => {
                    self.committed.insert(key, record);
                }
            }
        }
        true
    }

    /// Abort a pending batch: discard without merging.
    ///
    /// Called when `batch_upsert` returns `Err` (submit failure) or
    /// when `CommitHandle::wait()` returns `Err` (commit failure).
    pub fn abort(&mut self, op_id: PendingWriteId) {
        self.pending.remove(&op_id);
    }

    /// Look up the oracle's expected state for a key.
    pub fn expected_state(&self, key: &DoneLedgerKey) -> Option<&DoneLedgerRecord> {
        self.committed.get(key)
    }

    /// Number of distinct keys with committed state.
    pub fn committed_count(&self) -> usize {
        self.committed.len()
    }

    /// Iterate all committed records.
    ///
    /// Used by the cross-component invariant checker (C1–C4) to validate
    /// provenance fields against coordinator state. The iteration order
    /// is unspecified.
    pub fn committed_iter(&self) -> impl Iterator<Item = (&DoneLedgerKey, &DoneLedgerRecord)> {
        self.committed.iter()
    }

    /// Number of pending (uncommitted) batches.
    pub fn pending_batch_count(&self) -> usize {
        self.pending.len()
    }

    /// Verify convergence (invariant I6): after all pending ops drain,
    /// every key in the oracle's committed state must match the ledger's
    /// durable state, and vice versa.
    ///
    /// Returns an empty `Vec` on convergence, or one
    /// [`DoneLedgerInvariantViolation::LatticeConvergence`] per divergent key.
    pub fn verify_convergence(
        &self,
        ledger: &InMemoryDoneLedger,
    ) -> Vec<DoneLedgerInvariantViolation> {
        assert!(
            self.pending.is_empty(),
            "verify_convergence called with {} pending batches — \
             drain all pending ops first",
            self.pending.len()
        );

        let mut violations = Vec::new();

        let snapshot = ledger
            .snapshot()
            .expect("snapshot should not fail on InMemoryDoneLedger");

        // Build a lookup from the ledger snapshot.
        let ledger_map: HashMap<DoneLedgerKey, &DoneLedgerRecord> =
            snapshot.iter().map(|r| (r.key(), r)).collect();

        // Check every oracle key exists in the ledger with matching state.
        for (key, oracle_record) in &self.committed {
            match ledger_map.get(key) {
                Some(ledger_record) => {
                    if oracle_record != *ledger_record {
                        violations.push(DoneLedgerInvariantViolation::LatticeConvergence {
                            key: *key,
                            oracle: Some(Box::new(oracle_record.clone())),
                            actual: Some(Box::new((*ledger_record).clone())),
                        });
                    }
                }
                None => {
                    violations.push(DoneLedgerInvariantViolation::LatticeConvergence {
                        key: *key,
                        oracle: Some(Box::new(oracle_record.clone())),
                        actual: None,
                    });
                }
            }
        }

        // Check for keys in the ledger that the oracle does not know about.
        for record in &snapshot {
            let key = record.key();
            if !self.committed.contains_key(&key) {
                // Ledger has a record the oracle never committed — this
                // means a batch was applied without going through the
                // oracle's commit path.
                violations.push(DoneLedgerInvariantViolation::LatticeConvergence {
                    key,
                    oracle: None,
                    actual: Some(Box::new(record.clone())),
                });
            }
        }

        violations
    }
}

impl Default for DoneLedgerOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        identity::{FenceEpoch, LogicalTime, RunId, ShardId},
        persistence::{DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord, DoneLedgerStatus},
        test_util::{ovid, policy, tenant},
    };

    use crate::{InMemoryDoneLedger, PendingWriteId};

    use super::*;

    fn make_provenance(finished: u64) -> DoneLedgerProvenance {
        DoneLedgerProvenance::new(
            RunId::from_raw(1),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(finished),
        )
    }

    fn make_record(
        seed: u8,
        status: DoneLedgerStatus,
        bytes: u64,
        findings: u32,
        finished: u64,
    ) -> DoneLedgerRecord {
        let error_code = if status.is_failure() || status.is_skipped() {
            Some(gossip_contracts::persistence::DoneLedgerErrorCode::try_new("TEST_ERROR").unwrap())
        } else {
            None
        };
        DoneLedgerRecord::try_new(
            DoneLedgerKey::new(tenant(seed), policy(seed), ovid(seed)),
            status,
            bytes,
            findings,
            make_provenance(finished),
            error_code,
        )
        .unwrap()
    }

    #[test]
    fn oracle_tracks_committed_state() {
        let mut oracle = DoneLedgerOracle::new();
        let op1 = PendingWriteId::from_raw(1);
        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);

        oracle.submit(op1, vec![rec.clone()]);
        assert_eq!(oracle.pending_batch_count(), 1);
        assert_eq!(oracle.committed_count(), 0);

        oracle.commit(op1);
        assert_eq!(oracle.pending_batch_count(), 0);
        assert_eq!(oracle.committed_count(), 1);
        assert_eq!(oracle.expected_state(&rec.key()), Some(&rec));
    }

    #[test]
    fn oracle_abort_discards_pending() {
        let mut oracle = DoneLedgerOracle::new();
        let op1 = PendingWriteId::from_raw(1);
        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);

        oracle.submit(op1, vec![rec.clone()]);
        oracle.abort(op1);

        assert_eq!(oracle.pending_batch_count(), 0);
        assert_eq!(oracle.committed_count(), 0);
        assert!(oracle.expected_state(&rec.key()).is_none());
    }

    #[test]
    fn oracle_merge_promotes_status() {
        let mut oracle = DoneLedgerOracle::new();
        let op1 = PendingWriteId::from_raw(1);
        let op2 = PendingWriteId::from_raw(2);

        let rec_fail = make_record(1, DoneLedgerStatus::FailedRetryable, 100, 0, 200);
        let rec_scan = make_record(1, DoneLedgerStatus::ScannedClean, 200, 0, 300);

        oracle.submit(op1, vec![rec_fail]);
        oracle.commit(op1);

        oracle.submit(op2, vec![rec_scan]);
        oracle.commit(op2);

        let key = DoneLedgerKey::new(tenant(1), policy(1), ovid(1));
        let committed = oracle.expected_state(&key).unwrap();
        assert_eq!(committed.status(), DoneLedgerStatus::ScannedClean);
        assert_eq!(committed.bytes_scanned(), 200);
    }

    #[test]
    fn verify_convergence_detects_divergence() {
        use gossip_contracts::persistence::{CommitHandle, DoneLedger};

        let oracle = DoneLedgerOracle::new();
        let ledger = InMemoryDoneLedger::new();

        // Write a record to the ledger but not the oracle.
        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);
        let handle = ledger.batch_upsert(&[rec]).unwrap();
        let _receipt = handle.wait().unwrap();

        // Oracle has nothing committed — should detect divergence.
        let violations = oracle.verify_convergence(&ledger);
        assert!(!violations.is_empty());
    }

    #[test]
    fn convergence_violation_distinguishes_oracle_from_ledger_state() {
        use gossip_contracts::persistence::{CommitHandle, DoneLedger};

        let oracle = DoneLedgerOracle::new();
        let ledger = InMemoryDoneLedger::new();

        // Write a record to the ledger without going through the oracle.
        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);
        let handle = ledger.batch_upsert(&[rec]).unwrap();
        let _receipt = handle.wait().unwrap();

        // Oracle has no committed state — should detect divergence.
        let violations = oracle.verify_convergence(&ledger);
        assert!(!violations.is_empty());

        // When the oracle never committed a key but the ledger has it,
        // the violation's oracle field should be None.
        for v in &violations {
            if let DoneLedgerInvariantViolation::LatticeConvergence {
                oracle: oracle_rec,
                actual,
                ..
            } = v
            {
                assert!(
                    oracle_rec.is_none(),
                    "oracle field should be None for keys the oracle never committed"
                );
                assert!(
                    actual.is_some(),
                    "ledger has this key, actual should be Some"
                );
            }
        }
    }

    #[test]
    fn oracle_has_key_ledger_does_not() {
        let mut oracle = DoneLedgerOracle::new();
        let ledger = InMemoryDoneLedger::new();
        let op1 = PendingWriteId::from_raw(1);

        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);
        oracle.submit(op1, vec![rec.clone()]);
        oracle.commit(op1);

        // Oracle has committed state but ledger is empty — should detect
        // divergence with oracle=Some, actual=None.
        let violations = oracle.verify_convergence(&ledger);
        assert_eq!(violations.len(), 1, "expected exactly one violation");
        match &violations[0] {
            DoneLedgerInvariantViolation::LatticeConvergence {
                oracle: oracle_rec,
                actual,
                ..
            } => {
                assert!(
                    oracle_rec.is_some(),
                    "oracle committed this key, oracle field should be Some"
                );
                assert!(
                    actual.is_none(),
                    "ledger never received this key, actual should be None"
                );
            }
            other => panic!("expected LatticeConvergence, got: {other}"),
        }
    }

    #[test]
    fn verify_convergence_passes_when_synced() {
        use gossip_contracts::persistence::{CommitHandle, DoneLedger};

        let mut oracle = DoneLedgerOracle::new();
        let ledger = InMemoryDoneLedger::new();
        let op1 = PendingWriteId::from_raw(1);

        let rec = make_record(1, DoneLedgerStatus::ScannedClean, 100, 0, 200);
        oracle.submit(op1, vec![rec.clone()]);

        let handle = ledger.batch_upsert(&[rec]).unwrap();
        let _receipt = handle.wait().unwrap();

        oracle.commit(op1);

        let violations = oracle.verify_convergence(&ledger);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }
}
