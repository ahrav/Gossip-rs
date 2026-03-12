//! Per-step invariant checker for the done-ledger simulation.
//!
//! Verifies invariants I1–I6 and I8–I10 after every operation. Each
//! invariant is checked by a dedicated method that accepts the operation
//! context (keys involved, result, pre-operation snapshot) and returns
//! violations.
//!
//! # Invariant summary
//!
//! | ID | Name | Checked |
//! |----|------|---------|
//! | I1 | StatusMonotonicity | After committed upsert |
//! | I2 | BytesScanMonotonicity | After committed upsert |
//! | I3 | CommitDurability | After committed upsert |
//! | I4 | SubmitRollback | After failed submission |
//! | I5 | CommitRollback | After failed commit |
//! | I6 | LatticeConvergence | Liveness phase only (via oracle) |
//! | — | *(I7 reserved for findings-layer invariants)* | — |
//! | I8 | ProvenanceFidelity | After committed upsert |
//! | I9 | ReceiptAccuracy | After committed upsert |
//! | I10 | IdempotentUpsert | After committed upsert of identical records |

use std::collections::HashMap;

use gossip_contracts::persistence::{DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerRecord};

use crate::InMemoryDoneLedger;

// ── Violation types ──────────────────────────────────────────────────

/// A specific invariant violation detected by the checker.
#[derive(Debug, Clone)]
pub enum DoneLedgerInvariantViolation {
    /// I1: `status.rank()` decreased for a key after a committed upsert.
    StatusMonotonicity {
        key: DoneLedgerKey,
        prev_rank: u8,
        current_rank: u8,
    },

    /// I2: `bytes_scanned` decreased for a key after a committed upsert.
    BytesScanMonotonicity {
        key: DoneLedgerKey,
        prev_bytes: u64,
        current_bytes: u64,
    },

    /// I3: After `CommitHandle::wait()` returned `Ok(receipt)`, a
    /// `batch_get` for a key in that batch returned `None`.
    CommitDurability { key: DoneLedgerKey },

    /// I4: After `batch_upsert` returned `Err`, a `batch_get` for a
    /// key in the attempted batch returned a different state than the
    /// pre-submission snapshot.
    SubmitRollback {
        key: DoneLedgerKey,
        expected: Option<Box<DoneLedgerRecord>>,
        actual: Option<Box<DoneLedgerRecord>>,
    },

    /// I5: After `CommitHandle::wait()` returned `Err`, a `batch_get`
    /// for a key in the attempted batch returned a different state than
    /// the pre-submission snapshot.
    CommitRollback {
        key: DoneLedgerKey,
        expected: Option<Box<DoneLedgerRecord>>,
        actual: Option<Box<DoneLedgerRecord>>,
    },

    /// I6: After all pending ops drain, the ledger state for a key
    /// differs from the oracle's expected state.
    LatticeConvergence {
        key: DoneLedgerKey,
        oracle: Option<Box<DoneLedgerRecord>>,
        actual: Option<Box<DoneLedgerRecord>>,
    },

    /// I8: After merge, provenance fields come from multiple source
    /// records instead of a single winner.
    ProvenanceFidelity { key: DoneLedgerKey, message: String },

    /// I9: `DoneLedgerCommitReceipt` counts do not match the
    /// deduplicated batch.
    ReceiptAccuracy {
        key_count_expected: u64,
        key_count_actual: u64,
        scanned_expected: u64,
        scanned_actual: u64,
        findings_expected: u64,
        findings_actual: u64,
    },

    /// I10: Upserting an identical record changed the `batch_get`
    /// result.
    IdempotentUpsert {
        key: DoneLedgerKey,
        before: Box<DoneLedgerRecord>,
        after: Box<DoneLedgerRecord>,
    },

    /// I7: `batch_get` returned a record that differs from the oracle's
    /// committed view for a key with no pending writes.
    ReadConsistency {
        key: DoneLedgerKey,
        oracle: Option<Box<DoneLedgerRecord>>,
        actual: Option<Box<DoneLedgerRecord>>,
    },
}

impl std::fmt::Display for DoneLedgerInvariantViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::StatusMonotonicity {
                key,
                prev_rank,
                current_rank,
            } => write!(
                f,
                "I1 StatusMonotonicity: key={key:?} rank {prev_rank} -> {current_rank}"
            ),
            Self::BytesScanMonotonicity {
                key,
                prev_bytes,
                current_bytes,
            } => write!(
                f,
                "I2 BytesScanMonotonicity: key={key:?} bytes {prev_bytes} -> {current_bytes}"
            ),
            Self::CommitDurability { key } => {
                write!(f, "I3 CommitDurability: key={key:?} missing after commit")
            }
            Self::SubmitRollback { key, .. } => {
                write!(
                    f,
                    "I4 SubmitRollback: key={key:?} state changed after failed submit"
                )
            }
            Self::CommitRollback { key, .. } => {
                write!(
                    f,
                    "I5 CommitRollback: key={key:?} state changed after failed commit"
                )
            }
            Self::LatticeConvergence { key, .. } => {
                write!(
                    f,
                    "I6 LatticeConvergence: key={key:?} oracle/ledger divergence"
                )
            }
            Self::ProvenanceFidelity { key, message } => {
                write!(f, "I8 ProvenanceFidelity: key={key:?} {message}")
            }
            Self::ReceiptAccuracy { .. } => {
                write!(f, "I9 ReceiptAccuracy: receipt counts mismatch")
            }
            Self::IdempotentUpsert { key, .. } => {
                write!(
                    f,
                    "I10 IdempotentUpsert: key={key:?} state changed on replay"
                )
            }
            Self::ReadConsistency { key, .. } => {
                write!(
                    f,
                    "I7 ReadConsistency: key={key:?} batch_get/oracle divergence"
                )
            }
        }
    }
}

// ── Checker ──────────────────────────────────────────────────────────

/// Stateful invariant checker maintaining per-key history for temporal
/// monotonicity verification.
///
/// The checker is called after every simulation step. It accumulates
/// per-key history (status rank, bytes_scanned) across steps so it can
/// detect regressions that single-step checks would miss.
#[derive(Debug)]
pub struct DoneLedgerInvariantChecker {
    /// I1: previous status rank per key (for monotonicity).
    prev_status: HashMap<DoneLedgerKey, u8>,

    /// I2: previous bytes_scanned per key (for monotonicity).
    prev_bytes: HashMap<DoneLedgerKey, u64>,
}

impl DoneLedgerInvariantChecker {
    /// Create an empty checker with no history.
    pub fn new() -> Self {
        Self {
            prev_status: HashMap::new(),
            prev_bytes: HashMap::new(),
        }
    }

    /// Check invariants after a committed upsert.
    ///
    /// Verifies I1 (status monotonicity), I2 (bytes_scanned monotonicity),
    /// I3 (commit durability), I8 (provenance fidelity), I9 (receipt accuracy),
    /// and I10 (idempotent upsert when incoming matches pre-existing state).
    ///
    /// `pre_snapshot` is the `batch_get` result for the affected keys
    /// *before* the upsert was submitted.
    pub fn check_after_committed_upsert(
        &mut self,
        ledger: &InMemoryDoneLedger,
        records: &[DoneLedgerRecord],
        receipt: &DoneLedgerCommitReceipt,
        pre_snapshot: &[Option<DoneLedgerRecord>],
    ) -> Vec<DoneLedgerInvariantViolation> {
        let mut violations = Vec::new();

        // Deduplicate within the batch using merge — mirrors what
        // DoneLedgerBackend::apply does internally. A committed batch
        // has already passed upfront validation, so merge should not
        // fail here. Panic if it does to surface the inconsistency.
        let mut deduped: HashMap<DoneLedgerKey, DoneLedgerRecord> =
            HashMap::with_capacity(records.len());
        for rec in records {
            let key = rec.key();
            match deduped.get(&key) {
                Some(existing) => {
                    let merged = existing.merge(rec).unwrap_or_else(|e| {
                        panic!(
                            "invariant checker merge failure for key {key:?}: {e} \
                             — committed batch should not contain records that fail to merge"
                        );
                    });
                    deduped.insert(key, merged);
                }
                None => {
                    deduped.insert(key, rec.clone());
                }
            }
        }

        // I9: Receipt accuracy — the receipt is computed from the
        // deduplicated INCOMING batch, not from the post-merge durable
        // state. This matches DoneLedgerBackend::apply lines 102-111.
        self.check_receipt_accuracy(&deduped, receipt, &mut violations);

        // Build a pre-snapshot map keyed by DoneLedgerKey for efficient
        // lookup (a batch may have duplicate keys, but pre_snapshot is
        // positional — use the first occurrence per key).
        let mut pre_by_key: HashMap<DoneLedgerKey, &DoneLedgerRecord> = HashMap::new();
        for (i, rec) in records.iter().enumerate() {
            if i < pre_snapshot.len()
                && let Some(ref pre_rec) = pre_snapshot[i]
            {
                pre_by_key.entry(rec.key()).or_insert(pre_rec);
            }
        }

        // Per-key checks against post-upsert ledger state (deduplicated).
        for (key, deduped_incoming) in &deduped {
            // Read back from ledger for I3.
            let current = ledger
                .get_record(*key)
                .expect("get_record should not fail on InMemoryDoneLedger");

            // I3: Commit durability — committed key must be readable.
            let Some(current) = current else {
                violations.push(DoneLedgerInvariantViolation::CommitDurability { key: *key });
                continue;
            };

            // I1: Status monotonicity.
            let current_rank = current.status().rank();
            if let Some(&prev_rank) = self.prev_status.get(key)
                && current_rank < prev_rank
            {
                violations.push(DoneLedgerInvariantViolation::StatusMonotonicity {
                    key: *key,
                    prev_rank,
                    current_rank,
                });
            }
            self.prev_status.insert(*key, current_rank);

            // I2: Bytes-scanned monotonicity.
            let current_bytes = current.bytes_scanned();
            if let Some(&prev_bytes) = self.prev_bytes.get(key)
                && current_bytes < prev_bytes
            {
                violations.push(DoneLedgerInvariantViolation::BytesScanMonotonicity {
                    key: *key,
                    prev_bytes,
                    current_bytes,
                });
            }
            self.prev_bytes.insert(*key, current_bytes);

            // I8: Provenance fidelity — the merged record's provenance
            // must match either the pre-existing record's provenance or
            // the deduped incoming record's provenance.
            if let Some(pre_record) = pre_by_key.get(key) {
                self.check_provenance_fidelity(
                    *key,
                    pre_record,
                    deduped_incoming,
                    &current,
                    &mut violations,
                );

                // I10: Idempotent upsert — when the deduped incoming record
                // is identical to the pre-existing record, durable state
                // must not change.
                if *pre_record == deduped_incoming {
                    violations.extend(self.check_idempotent_upsert(*key, pre_record, &current));
                }
            }
        }

        violations
    }

    /// Check invariants after a failed submission (I4: SubmitRollback).
    ///
    /// After `batch_upsert` returns `Err`, every key in the attempted
    /// batch must have the same state as before the submission.
    pub fn check_after_submit_failure(
        &self,
        ledger: &InMemoryDoneLedger,
        records: &[DoneLedgerRecord],
        pre_snapshot: &[Option<DoneLedgerRecord>],
    ) -> Vec<DoneLedgerInvariantViolation> {
        let mut violations = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            let key = rec.key();
            let current = ledger
                .get_record(key)
                .expect("get_record should not fail on InMemoryDoneLedger");

            let expected = pre_snapshot.get(i).cloned().flatten();
            if current != expected {
                violations.push(DoneLedgerInvariantViolation::SubmitRollback {
                    key,
                    expected: expected.map(Box::new),
                    actual: current.map(Box::new),
                });
            }
        }
        violations
    }

    /// Check invariants after a failed commit (I5: CommitRollback).
    ///
    /// After `CommitHandle::wait()` returns `Err`, every key in the
    /// attempted batch must have the same state as before the submission.
    pub fn check_after_commit_failure(
        &self,
        ledger: &InMemoryDoneLedger,
        records: &[DoneLedgerRecord],
        pre_snapshot: &[Option<DoneLedgerRecord>],
    ) -> Vec<DoneLedgerInvariantViolation> {
        let mut violations = Vec::new();
        for (i, rec) in records.iter().enumerate() {
            let key = rec.key();
            let current = ledger
                .get_record(key)
                .expect("get_record should not fail on InMemoryDoneLedger");

            let expected = pre_snapshot.get(i).cloned().flatten();
            if current != expected {
                violations.push(DoneLedgerInvariantViolation::CommitRollback {
                    key,
                    expected: expected.map(Box::new),
                    actual: current.map(Box::new),
                });
            }
        }
        violations
    }

    /// Check I10: idempotent upsert. Upserting an identical record must
    /// produce no state change in `batch_get`.
    pub fn check_idempotent_upsert(
        &self,
        key: DoneLedgerKey,
        before: &DoneLedgerRecord,
        after: &DoneLedgerRecord,
    ) -> Vec<DoneLedgerInvariantViolation> {
        if before != after {
            vec![DoneLedgerInvariantViolation::IdempotentUpsert {
                key,
                before: Box::new(before.clone()),
                after: Box::new(after.clone()),
            }]
        } else {
            Vec::new()
        }
    }

    // ── Private helpers ──────────────────────────────────────────────

    /// I8: Verify provenance comes from a single source record.
    ///
    /// After merge, the provenance of the result must match either
    /// the existing record's provenance or the incoming record's
    /// provenance — not a mix of fields from both.
    fn check_provenance_fidelity(
        &self,
        key: DoneLedgerKey,
        existing: &DoneLedgerRecord,
        incoming: &DoneLedgerRecord,
        merged: &DoneLedgerRecord,
        violations: &mut Vec<DoneLedgerInvariantViolation>,
    ) {
        let merged_prov = merged.provenance();
        let existing_prov = existing.provenance();
        let incoming_prov = incoming.provenance();

        // The merged provenance must be wholly from one source.
        let matches_existing = merged_prov == existing_prov;
        let matches_incoming = merged_prov == incoming_prov;

        if !matches_existing && !matches_incoming {
            violations.push(DoneLedgerInvariantViolation::ProvenanceFidelity {
                key,
                message: format!(
                    "merged provenance {merged_prov:?} matches neither \
                     existing {existing_prov:?} nor incoming {incoming_prov:?}"
                ),
            });
        }
    }

    /// I9: Verify receipt counts match the deduplicated incoming batch.
    ///
    /// The receipt is computed from the deduplicated incoming batch
    /// (before merge with existing state), matching
    /// `DoneLedgerBackend::apply` lines 102-111.
    fn check_receipt_accuracy(
        &self,
        deduped: &HashMap<DoneLedgerKey, DoneLedgerRecord>,
        receipt: &DoneLedgerCommitReceipt,
        violations: &mut Vec<DoneLedgerInvariantViolation>,
    ) {
        let expected_records = deduped.len() as u64;

        // Count scanned and findings from the DEDUPLICATED INCOMING records,
        // not from the post-merge durable state.
        let mut scanned_count: u64 = 0;
        let mut findings_count: u64 = 0;
        for record in deduped.values() {
            if record.status().is_scanned() {
                scanned_count += 1;
            }
            findings_count += u64::from(record.findings_count());
        }

        if receipt.record_count() != expected_records
            || receipt.scanned_count() != scanned_count
            || receipt.findings_count() != findings_count
        {
            violations.push(DoneLedgerInvariantViolation::ReceiptAccuracy {
                key_count_expected: expected_records,
                key_count_actual: receipt.record_count(),
                scanned_expected: scanned_count,
                scanned_actual: receipt.scanned_count(),
                findings_expected: findings_count,
                findings_actual: receipt.findings_count(),
            });
        }
    }
}

impl Default for DoneLedgerInvariantChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use gossip_contracts::{
        identity::{FenceEpoch, LogicalTime, RunId, ShardId},
        persistence::{
            CommitHandle, DoneLedger, DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance,
            DoneLedgerRecord, DoneLedgerStatus,
        },
        test_util::{ovid, policy, tenant},
    };

    use crate::InMemoryDoneLedger;

    use super::*;

    fn prov(finished: u64) -> DoneLedgerProvenance {
        DoneLedgerProvenance::new(
            RunId::from_raw(1),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(finished),
        )
    }

    fn prov_with_run(run: u64, finished: u64) -> DoneLedgerProvenance {
        DoneLedgerProvenance::new(
            RunId::from_raw(run),
            ShardId::from_raw(1),
            FenceEpoch::from_raw(1),
            LogicalTime::from_raw(100),
            LogicalTime::from_raw(finished),
        )
    }

    fn key(seed: u8) -> DoneLedgerKey {
        DoneLedgerKey::new(tenant(seed), policy(seed), ovid(seed))
    }

    fn scanned_clean(seed: u8, bytes: u64, finished: u64) -> DoneLedgerRecord {
        DoneLedgerRecord::try_new(
            key(seed),
            DoneLedgerStatus::ScannedClean,
            bytes,
            0,
            prov(finished),
            None,
        )
        .unwrap()
    }

    fn scanned_with_findings(
        seed: u8,
        bytes: u64,
        findings: u32,
        finished: u64,
    ) -> DoneLedgerRecord {
        DoneLedgerRecord::try_new(
            key(seed),
            DoneLedgerStatus::ScannedWithFindings,
            bytes,
            findings,
            prov(finished),
            None,
        )
        .unwrap()
    }

    // ── I1: StatusMonotonicity ───────────────────────────────────────

    #[test]
    fn i1_detects_status_rank_regression() {
        let mut checker = DoneLedgerInvariantChecker::new();
        let ledger = InMemoryDoneLedger::new();

        // Commit a ScannedClean record (rank 10).
        let rec1 = scanned_clean(1, 100, 200);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec1)).unwrap();
        let receipt = handle.wait().unwrap();

        let pre_snap: Vec<Option<DoneLedgerRecord>> = vec![None];
        let v = checker.check_after_committed_upsert(&ledger, &[rec1], &receipt, &pre_snap);
        assert!(v.is_empty(), "unexpected violations: {v:?}");

        // Artificially insert a lower-rank status in the checker's history
        // to simulate a regression (the ledger won't actually regress due
        // to merge, but the checker should detect it if it did).
        let k = key(1);
        checker
            .prev_status
            .insert(k, DoneLedgerStatus::ScannedWithFindings.rank());

        // Now read back — the ledger has rank 10, but checker expects >= 11.
        let rec2 = scanned_clean(1, 200, 300);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec2)).unwrap();
        let receipt2 = handle.wait().unwrap();

        let pre_snap2 = vec![ledger.get_record(k).unwrap()];
        let v = checker.check_after_committed_upsert(&ledger, &[rec2], &receipt2, &pre_snap2);
        assert!(
            v.iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::StatusMonotonicity { .. })),
            "expected StatusMonotonicity violation, got: {v:?}"
        );
    }

    // ── I2: BytesScanMonotonicity ────────────────────────────────────

    #[test]
    fn i2_detects_bytes_regression() {
        let mut checker = DoneLedgerInvariantChecker::new();
        let ledger = InMemoryDoneLedger::new();
        let k = key(1);

        // Commit a record with 500 bytes.
        let rec1 = scanned_clean(1, 500, 200);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec1)).unwrap();
        let receipt = handle.wait().unwrap();

        let pre_snap = vec![None];
        let v = checker.check_after_committed_upsert(&ledger, &[rec1], &receipt, &pre_snap);
        assert!(v.is_empty());

        // Artificially inflate the checker's byte history to simulate
        // detecting a regression.
        checker.prev_bytes.insert(k, 1000);

        let rec2 = scanned_clean(1, 600, 300);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec2)).unwrap();
        let receipt2 = handle.wait().unwrap();

        let pre_snap2 = vec![ledger.get_record(k).unwrap()];
        let v = checker.check_after_committed_upsert(&ledger, &[rec2], &receipt2, &pre_snap2);
        assert!(
            v.iter().any(|v| matches!(
                v,
                DoneLedgerInvariantViolation::BytesScanMonotonicity { .. }
            )),
            "expected BytesScanMonotonicity violation, got: {v:?}"
        );
    }

    // ── I3: CommitDurability ─────────────────────────────────────────

    #[test]
    fn i3_detects_missing_committed_record() {
        let mut checker = DoneLedgerInvariantChecker::new();

        // Use a ledger that we never actually write to, but pretend a
        // commit happened. The checker should detect the missing record.
        let ledger = InMemoryDoneLedger::new();
        let rec = scanned_clean(1, 100, 200);

        // Fabricate a receipt as if the commit succeeded.
        let receipt = DoneLedgerCommitReceipt::new(1, 1, 0);
        let pre_snap = vec![None];

        let v = checker.check_after_committed_upsert(&ledger, &[rec], &receipt, &pre_snap);
        assert!(
            v.iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::CommitDurability { .. })),
            "expected CommitDurability violation, got: {v:?}"
        );
    }

    // ── I4: SubmitRollback ───────────────────────────────────────────

    #[test]
    fn i4_detects_state_change_on_submit_failure() {
        let checker = DoneLedgerInvariantChecker::new();
        let ledger = InMemoryDoneLedger::new();

        // Pre-populate a record.
        let rec1 = scanned_clean(1, 100, 200);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec1)).unwrap();
        let _receipt = handle.wait().unwrap();

        // Take pre-snapshot.
        let pre_snap = vec![ledger.get_record(key(1)).unwrap()];

        // Inject submit failure.
        ledger.fail_next_submissions(1).unwrap();
        let rec2 = scanned_with_findings(1, 200, 1, 300);
        assert!(ledger.batch_upsert(std::slice::from_ref(&rec2)).is_err());

        // State should be unchanged — no violation.
        let v = checker.check_after_submit_failure(&ledger, std::slice::from_ref(&rec2), &pre_snap);
        assert!(v.is_empty(), "unexpected violations: {v:?}");

        // Now simulate a bug: the pre-snapshot says None but ledger has data.
        let bad_pre = vec![None];
        let v = checker.check_after_submit_failure(&ledger, &[rec2], &bad_pre);
        assert!(
            v.iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::SubmitRollback { .. })),
            "expected SubmitRollback violation, got: {v:?}"
        );
    }

    // ── I5: CommitRollback ───────────────────────────────────────────

    #[test]
    fn i5_detects_state_change_on_commit_failure() {
        let checker = DoneLedgerInvariantChecker::new();
        let ledger = InMemoryDoneLedger::new();

        // Take pre-snapshot (empty).
        let pre_snap: Vec<Option<DoneLedgerRecord>> = vec![None];

        // Inject commit failure.
        ledger.fail_next_commits(1).unwrap();
        let rec = scanned_clean(1, 100, 200);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec)).unwrap();
        assert!(handle.wait().is_err());

        // State should be unchanged — no violation.
        let v = checker.check_after_commit_failure(&ledger, std::slice::from_ref(&rec), &pre_snap);
        assert!(v.is_empty(), "unexpected violations: {v:?}");

        // Simulate a bug: pre-snapshot has a record but ledger is empty.
        let fake_pre = vec![Some(scanned_clean(1, 50, 100))];
        let v = checker.check_after_commit_failure(&ledger, &[rec], &fake_pre);
        assert!(
            v.iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::CommitRollback { .. })),
            "expected CommitRollback violation, got: {v:?}"
        );
    }

    // ── I6: LatticeConvergence ───────────────────────────────────────
    // (Tested via oracle::tests::verify_convergence_detects_divergence)

    // ── I8: ProvenanceFidelity ───────────────────────────────────────

    #[test]
    fn i8_detects_mixed_provenance() {
        let checker = DoneLedgerInvariantChecker::new();

        let existing = DoneLedgerRecord::try_new(
            key(1),
            DoneLedgerStatus::FailedRetryable,
            100,
            0,
            prov_with_run(1, 200),
            Some(DoneLedgerErrorCode::try_new("E1").unwrap()),
        )
        .unwrap();

        let incoming = DoneLedgerRecord::try_new(
            key(1),
            DoneLedgerStatus::FailedRetryable,
            200,
            0,
            prov_with_run(2, 300),
            Some(DoneLedgerErrorCode::try_new("E2").unwrap()),
        )
        .unwrap();

        // Genuine merge result — provenance should come from one source.
        let merged = existing.merge(&incoming).unwrap();

        let mut violations = Vec::new();
        checker.check_provenance_fidelity(key(1), &existing, &incoming, &merged, &mut violations);
        // Real merge picks one source, so no violation expected.
        assert!(violations.is_empty(), "unexpected: {violations:?}");

        // Fabricate a bad merge with provenance from neither source.
        let bad_merged = DoneLedgerRecord::try_new(
            key(1),
            DoneLedgerStatus::FailedRetryable,
            200,
            0,
            prov_with_run(99, 999),
            Some(DoneLedgerErrorCode::try_new("E2").unwrap()),
        )
        .unwrap();

        let mut violations = Vec::new();
        checker.check_provenance_fidelity(
            key(1),
            &existing,
            &incoming,
            &bad_merged,
            &mut violations,
        );
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::ProvenanceFidelity { .. })),
            "expected ProvenanceFidelity violation, got: {violations:?}"
        );
    }

    // ── I9: ReceiptAccuracy ──────────────────────────────────────────

    #[test]
    fn i9_detects_receipt_mismatch() {
        let checker = DoneLedgerInvariantChecker::new();
        let ledger = InMemoryDoneLedger::new();

        let rec = scanned_with_findings(1, 100, 3, 200);
        let handle = ledger.batch_upsert(std::slice::from_ref(&rec)).unwrap();
        let _receipt = handle.wait().unwrap();

        // Fabricate a wrong receipt.
        let bad_receipt = DoneLedgerCommitReceipt::new(1, 0, 0);
        let deduped: HashMap<DoneLedgerKey, DoneLedgerRecord> =
            [(rec.key(), rec)].into_iter().collect();

        let mut violations = Vec::new();
        checker.check_receipt_accuracy(&deduped, &bad_receipt, &mut violations);
        assert!(
            violations
                .iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::ReceiptAccuracy { .. })),
            "expected ReceiptAccuracy violation, got: {violations:?}"
        );
    }

    // ── I10: IdempotentUpsert ────────────────────────────────────────

    #[test]
    fn i10_detects_state_change_on_identical_replay() {
        let checker = DoneLedgerInvariantChecker::new();
        let rec = scanned_clean(1, 100, 200);

        // No change — should be clean.
        let v = checker.check_idempotent_upsert(key(1), &rec, &rec);
        assert!(v.is_empty());

        // Different state — should fire.
        let different = scanned_clean(1, 200, 300);
        let v = checker.check_idempotent_upsert(key(1), &rec, &different);
        assert!(
            v.iter()
                .any(|v| matches!(v, DoneLedgerInvariantViolation::IdempotentUpsert { .. })),
            "expected IdempotentUpsert violation, got: {v:?}"
        );
    }
}
