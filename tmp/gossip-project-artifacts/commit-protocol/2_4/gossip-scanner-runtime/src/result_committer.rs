//! Shared runtime committer for per-item durable results.
//!
//! Epic 2.4 freezes the authoritative write path for completed runtime units:
//!
//! 1. validate one per-item commit request;
//! 2. write findings / occurrences / observations to [`FindingsSink`];
//! 3. wait for findings durability;
//! 4. write the matching done-ledger row to [`DoneLedger`];
//! 5. wait for done-ledger durability; and
//! 6. return one durable runtime [`CommitReceipt`](crate::commit_model::CommitReceipt).
//!
//! The implementation deliberately reuses the persistence typestate machine
//! ([`PageCommit`]) rather than inventing a second ordering protocol inside the
//! runtime. That gives us one compile-time path for findings → done-ledger and
//! keeps later receipt-driven checkpointing on the same durable model.

use std::{collections::HashSet, error::Error, fmt};

use gossip_contracts::{
    identity::TenantId,
    persistence::{
        CommitAdvanceError, CommitScope, DoneLedger, DoneLedgerStatus,
        FindingsSink, FindingsUpsertBatch, OvidHash, PageCommit, PersistenceInputError,
        WriteContext,
    },
};

use crate::{
    commit_model::{CommitReceipt, CommitRequest, CompletedUnit},
    result_translation::PersistenceTranslation,
};

/// Deterministic request-shape validation errors for [`ResultCommitter`].
///
/// These are programming errors, not transient storage failures. Retrying the
/// exact same invalid request will produce the same result.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResultCommitRequestError {
    /// A per-item commit request must carry exactly one done-ledger row.
    DoneLedgerRecordCount {
        /// Number of rows present in the request.
        actual: usize,
    },
    /// The findings batch violated a persistence-layer invariant before any
    /// write was submitted.
    FindingsBatch(PersistenceInputError),
    /// A finding row belonged to a different tenant than the shared write
    /// context.
    FindingTenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// An occurrence row belonged to a different tenant than the shared write
    /// context.
    OccurrenceTenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// An observation row carried different write-context metadata than the
    /// request-level write context.
    ObservationWriteContextMismatch {
        /// Zero-based observation index within the batch.
        index: usize,
    },
    /// An observation row pointed at a different object-version than the
    /// done-ledger row.
    ObservationOvidMismatch {
        /// Zero-based observation index within the batch.
        index: usize,
        /// OVID expected from the done-ledger key.
        expected: OvidHash,
        /// OVID actually stored on the observation.
        actual: OvidHash,
    },
    /// The done-ledger row carried different write-context metadata than the
    /// request-level write context.
    DoneLedgerWriteContextMismatch {
        expected: WriteContext,
        actual: WriteContext,
    },
    /// The request carried findings for a non-scanned terminal status.
    FindingsPresentForUnscannedStatus {
        /// Terminal status on the done-ledger row.
        status: DoneLedgerStatus,
    },
    /// The done-ledger findings count disagreed with the distinct stable
    /// findings in the batch.
    FindingsCountMismatch {
        /// Count stored on the done-ledger row.
        expected: u32,
        /// Distinct stable findings present in the request.
        actual: u32,
    },
    /// Distinct stable findings exceeded the current `u32` done-ledger field.
    DistinctFindingsOverflow {
        /// Number of distinct stable findings observed in the request.
        count: usize,
    },
}

impl fmt::Display for ResultCommitRequestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoneLedgerRecordCount { actual } => write!(
                f,
                "per-item commit requests must carry exactly one done-ledger row; got {actual}"
            ),
            Self::FindingsBatch(err) => write!(f, "invalid findings batch: {err}"),
            Self::FindingTenantMismatch { expected, actual } => write!(
                f,
                "finding tenant mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::OccurrenceTenantMismatch { expected, actual } => write!(
                f,
                "occurrence tenant mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::ObservationWriteContextMismatch { index } => write!(
                f,
                "observation at index {index} does not match the shared write context"
            ),
            Self::ObservationOvidMismatch {
                index,
                expected,
                actual,
            } => write!(
                f,
                "observation at index {index} targets OVID {actual:?}, expected {expected:?}"
            ),
            Self::DoneLedgerWriteContextMismatch { expected, actual } => write!(
                f,
                "done-ledger write context mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::FindingsPresentForUnscannedStatus { status } => write!(
                f,
                "done-ledger status {status:?} cannot be committed with findings payload"
            ),
            Self::FindingsCountMismatch { expected, actual } => write!(
                f,
                "done-ledger findings_count mismatch: expected {expected}, got {actual}"
            ),
            Self::DistinctFindingsOverflow { count } => write!(
                f,
                "distinct findings count {count} exceeds done-ledger u32 capacity"
            ),
        }
    }
}

impl Error for ResultCommitRequestError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::FindingsBatch(err) => Some(err),
            _ => None,
        }
    }
}

impl From<PersistenceInputError> for ResultCommitRequestError {
    #[inline]
    fn from(value: PersistenceInputError) -> Self {
        Self::FindingsBatch(value)
    }
}

/// Immediate submit, wait, or validation failure while committing one runtime
/// unit through findings → done-ledger.
#[derive(Debug)]
pub enum ResultCommitError<FindingsError, DoneLedgerError> {
    /// The request itself was inconsistent.
    InvalidRequest(ResultCommitRequestError),
    /// The findings sink rejected the submission before returning a handle.
    FindingsSubmit(FindingsError),
    /// Waiting for findings durability failed.
    FindingsWait(FindingsError),
    /// The done-ledger rejected the submission before returning a handle.
    DoneLedgerSubmit(DoneLedgerError),
    /// Waiting for done-ledger durability failed, or the receipt did not match
    /// the expected per-item commit scope.
    DoneLedgerAdvance(CommitAdvanceError<DoneLedgerError>),
}

impl<FindingsError, DoneLedgerError> fmt::Display
    for ResultCommitError<FindingsError, DoneLedgerError>
where
    FindingsError: fmt::Display,
    DoneLedgerError: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidRequest(err) => write!(f, "invalid commit request: {err}"),
            Self::FindingsSubmit(err) => write!(f, "findings submission failed: {err}"),
            Self::FindingsWait(err) => write!(f, "findings durability wait failed: {err}"),
            Self::DoneLedgerSubmit(err) => write!(f, "done-ledger submission failed: {err}"),
            Self::DoneLedgerAdvance(err) => write!(f, "done-ledger durability failed: {err}"),
        }
    }
}

impl<FindingsError, DoneLedgerError> Error for ResultCommitError<FindingsError, DoneLedgerError>
where
    FindingsError: Error + Send + Sync + 'static,
    DoneLedgerError: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidRequest(err) => Some(err),
            Self::FindingsSubmit(err) | Self::FindingsWait(err) => Some(err),
            Self::DoneLedgerSubmit(err) => Some(err),
            Self::DoneLedgerAdvance(err) => Some(err),
        }
    }
}

/// Authoritative runtime stage that durably commits one completed item.
///
/// This struct is intentionally thin: ordering and item-count validation come
/// from [`PageCommit`], while idempotency comes from deterministic IDs plus the
/// underlying sink contracts.
pub struct ResultCommitter<F, D> {
    findings_sink: F,
    done_ledger: D,
}

impl<F, D> ResultCommitter<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    /// Construct a new committer over the shared persistence sinks.
    #[must_use]
    pub fn new(findings_sink: F, done_ledger: D) -> Self {
        Self {
            findings_sink,
            done_ledger,
        }
    }

    /// Borrow the findings sink used by this committer.
    #[inline]
    #[must_use]
    pub const fn findings_sink(&self) -> &F {
        &self.findings_sink
    }

    /// Borrow the done-ledger used by this committer.
    #[inline]
    #[must_use]
    pub const fn done_ledger(&self) -> &D {
        &self.done_ledger
    }

    /// Commit one translated item bundle without re-deriving IDs.
    ///
    /// This is the main bridge between EP2.3 translation and EP2.4 durable
    /// commit. The translated persistence rows are reused as-is.
    pub fn commit_translation(
        &self,
        write_context: WriteContext,
        completed_unit: CompletedUnit,
        translation: &PersistenceTranslation,
    ) -> Result<CommitReceipt, ResultCommitError<F::Error, D::Error>> {
        let request = CommitRequest::new(
            write_context,
            completed_unit,
            translation.findings_batch(),
            std::slice::from_ref(translation.done_ledger()),
        );
        self.commit_item(request)
    }

    /// Commit one completed runtime unit through findings → done-ledger.
    ///
    /// The request is validated before any write is submitted. After that,
    /// findings durability is awaited before the done-ledger write is even
    /// submitted, making the runtime ordering structural rather than
    /// conventional.
    pub fn commit_item(
        &self,
        request: CommitRequest<'_>,
    ) -> Result<CommitReceipt, ResultCommitError<F::Error, D::Error>> {
        Self::validate_request(&request).map_err(ResultCommitError::InvalidRequest)?;

        let completed_unit = request.completed_unit().clone();
        let scope = Self::scope_for(request.write_context(), &completed_unit);
        let page = PageCommit::new(scope);

        let findings_handle = self
            .findings_sink
            .upsert_batch(request.findings())
            .map_err(ResultCommitError::FindingsSubmit)?;
        let page = page
            .wait_findings(findings_handle)
            .map_err(ResultCommitError::FindingsWait)?;

        let done_handle = self
            .done_ledger
            .batch_upsert(request.done_ledger())
            .map_err(ResultCommitError::DoneLedgerSubmit)?;
        let page = page
            .wait_done_ledger(done_handle)
            .map_err(ResultCommitError::DoneLedgerAdvance)?;

        Ok(CommitReceipt::new(
            completed_unit,
            page.into_item_commit_receipt(),
        ))
    }

    /// Backwards-compatible alias for [`commit_item`](Self::commit_item).
    #[inline]
    pub fn commit(
        &self,
        request: CommitRequest<'_>,
    ) -> Result<CommitReceipt, ResultCommitError<F::Error, D::Error>> {
        self.commit_item(request)
    }

    fn scope_for(write_context: WriteContext, completed_unit: &CompletedUnit) -> CommitScope {
        CommitScope::from_write_context(
            write_context,
            1,
            completed_unit.checkpoint_boundary().clone(),
        )
    }

    fn validate_request(request: &CommitRequest<'_>) -> Result<(), ResultCommitRequestError> {
        let findings = request.findings();
        findings.validate_observation_identity()?;
        findings.validate_referential_integrity()?;

        let write_context = request.write_context();
        let done_ledger = match request.done_ledger() {
            [record] => record,
            records => {
                return Err(ResultCommitRequestError::DoneLedgerRecordCount {
                    actual: records.len(),
                });
            }
        };

        for finding in findings.findings() {
            if finding.tenant_id() != write_context.tenant_id() {
                return Err(ResultCommitRequestError::FindingTenantMismatch {
                    expected: write_context.tenant_id(),
                    actual: finding.tenant_id(),
                });
            }
        }
        for occurrence in findings.occurrences() {
            if occurrence.tenant_id() != write_context.tenant_id() {
                return Err(ResultCommitRequestError::OccurrenceTenantMismatch {
                    expected: write_context.tenant_id(),
                    actual: occurrence.tenant_id(),
                });
            }
        }
        for (index, observation) in findings.observations().iter().enumerate() {
            if observation.write_context() != write_context {
                return Err(ResultCommitRequestError::ObservationWriteContextMismatch { index });
            }

            let expected_ovid = done_ledger.key().ovid_hash();
            let actual_ovid = observation.ovid_hash();
            if actual_ovid != expected_ovid {
                return Err(ResultCommitRequestError::ObservationOvidMismatch {
                    index,
                    expected: expected_ovid,
                    actual: actual_ovid,
                });
            }
        }

        let done_write_context = done_ledger.write_context();
        if done_write_context != write_context {
            return Err(ResultCommitRequestError::DoneLedgerWriteContextMismatch {
                expected: write_context,
                actual: done_write_context,
            });
        }

        let distinct_findings = distinct_findings_count(findings)?;
        if done_ledger.status().is_scanned() {
            let expected = done_ledger.findings_count();
            if expected != distinct_findings {
                return Err(ResultCommitRequestError::FindingsCountMismatch {
                    expected,
                    actual: distinct_findings,
                });
            }
        } else if !findings.is_empty() {
            return Err(ResultCommitRequestError::FindingsPresentForUnscannedStatus {
                status: done_ledger.status(),
            });
        }

        Ok(())
    }
}

fn distinct_findings_count(
    findings: FindingsUpsertBatch<'_>,
) -> Result<u32, ResultCommitRequestError> {
    let mut distinct = HashSet::with_capacity(findings.findings().len());
    for finding in findings.findings() {
        distinct.insert(finding.finding_id());
    }

    u32::try_from(distinct.len()).map_err(|_| ResultCommitRequestError::DistinctFindingsOverflow {
        count: distinct.len(),
    })
}

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use gossip_contracts::{
        connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
        identity::{
            FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RunId, ShardId,
            StableItemId, TenantId, TenantSecretKey,
        },
        persistence::{DoneLedgerStatus, WriteContext},
    };
    use gossip_persistence_inmemory::{
        CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
        InMemoryStoreKind,
    };
    use scanner_scheduler::FsFindingRecord;

    use super::*;
    use crate::{
        commit_model::CompletedUnit,
        result_translation::{ItemResult, ScanTiming, translate_item_result},
    };

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(33),
            ShardId::from_raw(44),
            FenceEpoch::from_raw(55),
        )
    }

    fn tenant_secret_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0x99; 32])
    }

    fn scan_item() -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x33; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([0x44; 32])),
        )
        .with_location(
            Location::try_new(
                "tenant/repo/path.txt".to_owned(),
                Some("https://example.invalid/tenant/repo/path.txt".to_owned()),
            )
            .expect("location"),
        )
    }

    fn timing() -> ScanTiming {
        ScanTiming::new(LogicalTime::from_raw(1_000), LogicalTime::from_raw(2_000))
    }

    fn finding(rule_id: u32, span_start: u64, span_end: u64, hash_seed: u8) -> FsFindingRecord {
        FsFindingRecord {
            rule_id,
            root_hint_start: span_start,
            root_hint_end: span_end,
            span_start,
            span_end,
            norm_hash: [hash_seed; 32],
            confidence_score: 7,
        }
    }

    fn completed_unit(sequence_no: u64) -> CompletedUnit {
        CompletedUnit::ordered_content(
            sequence_no,
            Cursor::with_last_key(ItemKey::try_from_slice(b"tenant/repo/path.txt").expect("key")),
        )
    }

    fn translated_scan() -> PersistenceTranslation {
        let item = scan_item();
        let findings = [finding(7, 10, 20, 0xAA), finding(9, 30, 45, 0xBB)];
        translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            128,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation")
    }

    fn translated_clean_scan() -> PersistenceTranslation {
        let item = scan_item();
        let findings: [FsFindingRecord; 0] = [];
        translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            32,
            timing(),
            ItemResult::Scanned { findings: &findings },
        )
        .expect("translation")
    }

    fn wait_until(mut predicate: impl FnMut() -> bool) {
        for _ in 0..200 {
            if predicate() {
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
        panic!("condition was not satisfied before timeout");
    }

    #[test]
    fn commit_translation_persists_rows_and_returns_receipt() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let receipt = committer
            .commit_translation(write_context(), completed_unit(1), &translation)
            .expect("commit should succeed");

        assert_eq!(findings_sink.findings_snapshot().expect("snapshot").len(), 2);
        assert_eq!(findings_sink.occurrences_snapshot().expect("snapshot").len(), 2);
        assert_eq!(findings_sink.observations_snapshot().expect("snapshot").len(), 2);
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);

        assert_eq!(receipt.completed_unit().sequence_no(), 1);
        assert_eq!(receipt.durable().scope().committed_units(), 1);
        assert_eq!(receipt.durable().findings().finding_count(), 2);
        assert_eq!(receipt.durable().findings().occurrence_count(), 2);
        assert_eq!(receipt.durable().findings().observation_count(), 2);
        assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        assert_eq!(receipt.durable().done_ledger().findings_count(), 2);
    }

    #[test]
    fn retrying_the_same_translation_is_idempotent() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let first = committer
            .commit_translation(write_context(), completed_unit(2), &translation)
            .expect("first commit should succeed");
        let second = committer
            .commit_translation(write_context(), completed_unit(2), &translation)
            .expect("retry should also succeed");

        assert_eq!(findings_sink.findings_snapshot().expect("snapshot").len(), 2);
        assert_eq!(findings_sink.occurrences_snapshot().expect("snapshot").len(), 2);
        assert_eq!(findings_sink.observations_snapshot().expect("snapshot").len(), 2);
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);

        assert_eq!(first.completed_unit(), second.completed_unit());
        assert_eq!(first.durable().scope(), second.durable().scope());
        assert_eq!(first.durable().findings(), second.durable().findings());
        assert_eq!(first.durable().done_ledger(), second.durable().done_ledger());
    }

    #[test]
    fn done_ledger_submission_waits_for_findings_durability() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::with_auto_complete(false);
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let worker = thread::spawn(move || {
            committer.commit_translation(write_context(), completed_unit(3), &translation)
        });

        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        assert_eq!(done_ledger.pending_count().expect("pending count"), 0);

        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release findings");
        wait_until(|| done_ledger.pending_count().expect("pending count") == 1);

        done_ledger
            .release_next(CompletionOrder::OldestFirst)
            .expect("release done-ledger");

        let receipt = worker
            .join()
            .expect("worker thread should not panic")
            .expect("commit should succeed");
        assert_eq!(receipt.durable().done_ledger().record_count(), 1);
    }

    #[test]
    fn findings_submission_failure_stops_before_done_ledger_submission() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        findings_sink
            .fail_next_submissions(1)
            .expect("fault injection should succeed");
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let err = committer
            .commit_translation(write_context(), completed_unit(4), &translation)
            .expect_err("findings submission should fail");

        match err {
            ResultCommitError::FindingsSubmit(InMemoryPersistenceError::InjectedSubmissionFailure {
                store,
            }) => assert_eq!(store, InMemoryStoreKind::Findings),
            other => panic!("expected findings submission failure, got {other:?}"),
        }

        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn done_ledger_commit_failure_returns_no_receipt_and_leaves_findings_durable() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_commits(1)
            .expect("fault injection should succeed");
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let err = committer
            .commit_translation(write_context(), completed_unit(5), &translation)
            .expect_err("done-ledger commit should fail");

        match err {
            ResultCommitError::DoneLedgerAdvance(CommitAdvanceError::Wait(
                InMemoryPersistenceError::InjectedCommitFailure { store },
            )) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
            other => panic!("expected done-ledger wait failure, got {other:?}"),
        }

        assert_eq!(findings_sink.findings_snapshot().expect("snapshot").len(), 2);
        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn invalid_requests_are_rejected_before_any_write() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_clean_scan();
        let duplicate_rows = vec![translation.done_ledger().clone(), translation.done_ledger().clone()];
        let request = CommitRequest::new(
            write_context(),
            completed_unit(6),
            translation.findings_batch(),
            &duplicate_rows,
        );

        let err = committer
            .commit_item(request)
            .expect_err("multi-row done-ledger request must be rejected");

        match err {
            ResultCommitError::InvalidRequest(ResultCommitRequestError::DoneLedgerRecordCount {
                actual,
            }) => assert_eq!(actual, 2),
            other => panic!("expected invalid request error, got {other:?}"),
        }

        assert!(findings_sink.findings_snapshot().expect("snapshot").is_empty());
        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn clean_scan_request_preserves_zero_findings_commit() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_clean_scan();

        let receipt = committer
            .commit_translation(write_context(), completed_unit(7), &translation)
            .expect("clean commit should succeed");

        assert!(findings_sink.findings_snapshot().expect("snapshot").is_empty());
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);
        assert_eq!(receipt.durable().findings().finding_count(), 0);
        assert_eq!(receipt.durable().done_ledger().findings_count(), 0);
        assert_eq!(translation.done_ledger().status(), DoneLedgerStatus::ScannedClean);
    }
}
