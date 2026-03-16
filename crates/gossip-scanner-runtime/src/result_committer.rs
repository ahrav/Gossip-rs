//! Shared runtime committer for per-item durable results.
//!
//! The runtime's authoritative write path for completed units is:
//!
//! 1. validate one per-item commit request;
//! 2. write findings, occurrences, and observations to [`FindingsSink`];
//! 3. wait for findings durability;
//! 4. write the matching done-ledger row to [`DoneLedger`];
//! 5. wait for done-ledger durability; and
//! 6. return one durable runtime [`UnitCommitReceipt`].
//!
//! The implementation deliberately reuses [`PageCommit`] instead of inventing
//! a second runtime-only ordering protocol. That keeps findings ->
//! done-ledger ordering in one typestate machine and preserves the same
//! durable receipt model the checkpoint stage will consume.

use std::{collections::HashSet, error::Error, fmt, num::NonZeroU64};

use gossip_contracts::{
    identity::TenantId,
    persistence::{
        CommitAdvanceError, CommitScope, DoneLedger, DoneLedgerStatus, FindingsSink,
        FindingsUpsertBatch, OvidHash, PageCommit, PersistenceInputError, WriteContext,
    },
};

use crate::{
    commit_model::{BoundaryMismatchError, CommitRequest, CompletedUnit, UnitCommitReceipt},
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
    /// The done-ledger record violated a cross-field invariant (e.g.
    /// `ScannedClean` with a non-`None` error code).
    DoneLedgerRecord(PersistenceInputError),
    /// A finding or occurrence row belonged to a different tenant than the
    /// shared write context.
    TenantMismatch {
        /// Which layer contained the mismatched tenant.
        layer: &'static str,
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
        expected: Box<WriteContext>,
        actual: Box<WriteContext>,
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
            Self::DoneLedgerRecord(err) => {
                write!(f, "invalid done-ledger record: {err}")
            }
            Self::TenantMismatch {
                layer, expected, ..
            } => {
                write!(f, "{layer} tenant mismatch: expected {expected:?}")
            }
            Self::ObservationWriteContextMismatch { index } => write!(
                f,
                "observation at index {index} does not match the shared write context"
            ),
            Self::ObservationOvidMismatch {
                index, expected, ..
            } => write!(
                f,
                "observation at index {index} targets a different OVID than expected ({expected:?})"
            ),
            Self::DoneLedgerWriteContextMismatch { .. } => write!(
                f,
                "done-ledger write context does not match the request-level write context"
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
            Self::FindingsBatch(err) | Self::DoneLedgerRecord(err) => Some(err),
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
/// unit through findings -> done-ledger.
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
    /// The durable receipt's checkpoint boundary did not match the completed
    /// unit's boundary.
    BoundaryMismatch(Box<BoundaryMismatchError>),
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
            Self::BoundaryMismatch(err) => write!(
                f,
                "boundary mismatch between completed unit and receipt: {err}"
            ),
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
            Self::BoundaryMismatch(err) => Some(err.as_ref()),
        }
    }
}

impl<F, D> From<ResultCommitRequestError> for ResultCommitError<F, D> {
    fn from(err: ResultCommitRequestError) -> Self {
        Self::InvalidRequest(err)
    }
}

/// Authoritative runtime stage that durably commits one completed item.
///
/// This struct is intentionally thin: ordering and item-count validation come
/// from [`PageCommit`], while idempotency comes from deterministic IDs plus the
/// underlying sink contracts.
#[must_use = "committers must be used to commit results"]
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
    pub fn new(findings_sink: F, done_ledger: D) -> Self {
        Self {
            findings_sink,
            done_ledger,
        }
    }

    /// Commit one translated item bundle without re-deriving IDs.
    ///
    /// This accepts pre-translated persistence rows directly instead of
    /// re-deriving them inside the commit stage.
    pub fn commit_translation(
        &self,
        write_context: WriteContext,
        completed_unit: CompletedUnit,
        translation: &PersistenceTranslation,
    ) -> Result<UnitCommitReceipt, ResultCommitError<F::Error, D::Error>> {
        let request = CommitRequest::new(
            write_context,
            completed_unit,
            translation.findings_batch(),
            std::slice::from_ref(translation.done_ledger()),
        );
        self.commit_item(request)
    }

    /// Commit one completed runtime unit through findings -> done-ledger.
    ///
    /// The request is validated before any write is submitted. After that,
    /// findings durability is awaited before the done-ledger write is
    /// submitted, making the ordering structural rather than conventional.
    pub fn commit_item(
        &self,
        request: CommitRequest<'_>,
    ) -> Result<UnitCommitReceipt, ResultCommitError<F::Error, D::Error>> {
        Self::validate_request(&request)?;

        let (write_context, completed_unit, findings, done_ledger) = request.into_parts();

        // `committed_units` is always 1 because `ResultCommitter` commits exactly
        // one completed unit per `commit_item` call. `validate_request` enforces
        // exactly one done-ledger record, and `PageCommit::record_done_ledger`
        // closes the loop by checking the receipt count against the scope.
        let scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::MIN,
            completed_unit.checkpoint_boundary().clone(),
        );
        let page = PageCommit::new(scope);

        let findings_handle = self
            .findings_sink
            .upsert_batch(findings)
            .map_err(ResultCommitError::FindingsSubmit)?;
        let page = page
            .wait_findings(findings_handle)
            .map_err(ResultCommitError::FindingsWait)?;

        let done_handle = self
            .done_ledger
            .batch_upsert(done_ledger)
            .map_err(ResultCommitError::DoneLedgerSubmit)?;
        let page = page
            .wait_done_ledger(done_handle)
            .map_err(ResultCommitError::DoneLedgerAdvance)?;

        UnitCommitReceipt::new(completed_unit, page.into_item_commit_receipt())
            .map_err(ResultCommitError::BoundaryMismatch)
    }

    fn validate_request(request: &CommitRequest<'_>) -> Result<(), ResultCommitRequestError> {
        let write_context = request.write_context();

        // Structural shape check first: exactly one done-ledger row is the
        // cheapest invariant and the most fundamental.
        let done_ledger = match request.done_ledger() {
            [record] => record,
            records => {
                return Err(ResultCommitRequestError::DoneLedgerRecordCount {
                    actual: records.len(),
                });
            }
        };

        done_ledger
            .validate()
            .map_err(ResultCommitRequestError::DoneLedgerRecord)?;

        // Batch-level integrity checks (may allocate HashSets) run after the
        // cheap structural check above has ruled out malformed requests.
        let findings = request.findings();
        findings.validate_observation_identity()?;
        findings.validate_referential_integrity()?;

        // After validate_referential_integrity (which calls
        // validate_tenant_consistency), all records in the batch share one
        // tenant. Checking just the first element suffices.
        if let Some(finding) = findings.findings().first()
            && finding.tenant_id() != write_context.tenant_id()
        {
            return Err(ResultCommitRequestError::TenantMismatch {
                layer: "finding",
                expected: write_context.tenant_id(),
                actual: finding.tenant_id(),
            });
        }
        if let Some(occurrence) = findings.occurrences().first()
            && occurrence.tenant_id() != write_context.tenant_id()
        {
            return Err(ResultCommitRequestError::TenantMismatch {
                layer: "occurrence",
                expected: write_context.tenant_id(),
                actual: occurrence.tenant_id(),
            });
        }

        let expected_ovid = done_ledger.key().ovid_hash();
        for (index, observation) in findings.observations().iter().enumerate() {
            if observation.write_context() != write_context {
                return Err(ResultCommitRequestError::ObservationWriteContextMismatch { index });
            }

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
                expected: Box::new(write_context),
                actual: Box::new(done_write_context),
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
            return Err(
                ResultCommitRequestError::FindingsPresentForUnscannedStatus {
                    status: done_ledger.status(),
                },
            );
        }

        Ok(())
    }
}

fn distinct_findings_count(
    findings: FindingsUpsertBatch<'_>,
) -> Result<u32, ResultCommitRequestError> {
    let count = findings
        .findings()
        .iter()
        .map(|f| f.finding_id())
        .collect::<HashSet<_>>()
        .len();
    u32::try_from(count).map_err(|_| ResultCommitRequestError::DistinctFindingsOverflow { count })
}

// Compile-time proof that request-error types can move across threads.
const _: fn() = || {
    fn assert_impl<T: Send + Sync>() {}
    assert_impl::<ResultCommitRequestError>();
};

#[cfg(test)]
mod tests {
    use std::{thread, time::Duration};

    use gossip_contracts::{
        connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
        identity::{
            FenceEpoch, LogicalTime, NormHash, ObjectVersionId, PolicyHash, RuleFingerprint, RunId,
            ShardId, StableItemId, TenantId, TenantSecretKey, derive_rule_fingerprint,
            key_secret_hash,
        },
        persistence::{
            DoneLedgerErrorCode, DoneLedgerKey, DoneLedgerProvenance, DoneLedgerRecord,
            DoneLedgerStatus, FindingRecord, ObservationRecord, OccurrenceRecord, WriteContext,
        },
    };
    use gossip_persistence_inmemory::{
        CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
        InMemoryStoreKind,
    };
    use scanner_scheduler::store::FsFindingRecord;

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

    fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
        let name = format!("test-rule-{rule_id}");
        derive_rule_fingerprint(&name)
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
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("translation")
    }

    fn scan_item_alt() -> ScanItem {
        ScanItem::new(
            ItemKey::try_from_slice(b"tenant/repo/other.txt").expect("item key"),
            ItemRef::try_from_vec(b"opaque-ref-alt".to_vec()).expect("item ref"),
            StableItemId::from_bytes([0x55; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([0x66; 32])),
        )
        .with_location(
            Location::try_new(
                "tenant/repo/other.txt".to_owned(),
                Some("https://example.invalid/tenant/repo/other.txt".to_owned()),
            )
            .expect("location"),
        )
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
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("translation")
    }

    fn wait_until(mut predicate: impl FnMut() -> bool) {
        for _ in 0..2_000 {
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

        assert_eq!(
            findings_sink.findings_snapshot().expect("snapshot").len(),
            2
        );
        assert_eq!(
            findings_sink
                .occurrences_snapshot()
                .expect("snapshot")
                .len(),
            2
        );
        assert_eq!(
            findings_sink
                .observations_snapshot()
                .expect("snapshot")
                .len(),
            2
        );
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);

        assert_eq!(receipt.completed_unit().sequence_no(), 1);
        assert_eq!(receipt.durable().scope().committed_units().get(), 1);
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

        assert_eq!(
            findings_sink.findings_snapshot().expect("snapshot").len(),
            2
        );
        assert_eq!(
            findings_sink
                .occurrences_snapshot()
                .expect("snapshot")
                .len(),
            2
        );
        assert_eq!(
            findings_sink
                .observations_snapshot()
                .expect("snapshot")
                .len(),
            2
        );
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);

        assert_eq!(first.completed_unit(), second.completed_unit());
        assert_eq!(first.durable().scope(), second.durable().scope());
        assert_eq!(first.durable().findings(), second.durable().findings());
        assert_eq!(
            first.durable().done_ledger(),
            second.durable().done_ledger()
        );
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
            ResultCommitError::FindingsSubmit(
                InMemoryPersistenceError::InjectedSubmissionFailure { store },
            ) => assert_eq!(store, InMemoryStoreKind::Findings),
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

        assert_eq!(
            findings_sink.findings_snapshot().expect("snapshot").len(),
            2
        );
        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn invalid_requests_are_rejected_before_any_write() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::with_auto_complete(false);
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_clean_scan();
        let duplicate_rows = vec![
            translation.done_ledger().clone(),
            translation.done_ledger().clone(),
        ];
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
            ResultCommitError::InvalidRequest(
                ResultCommitRequestError::DoneLedgerRecordCount { actual },
            ) => assert_eq!(actual, 2),
            other => panic!("expected invalid request error, got {other:?}"),
        }

        assert_eq!(findings_sink.pending_count().expect("pending count"), 0);
        assert_eq!(done_ledger.pending_count().expect("pending count"), 0);
        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty()
        );
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

        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty()
        );
        assert_eq!(done_ledger.snapshot().expect("snapshot").len(), 1);
        assert_eq!(receipt.durable().findings().finding_count(), 0);
        assert_eq!(receipt.durable().done_ledger().findings_count(), 0);
        assert_eq!(
            translation.done_ledger().status(),
            DoneLedgerStatus::ScannedClean
        );
    }

    #[test]
    fn findings_durability_failure_stops_before_done_ledger_submission() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        findings_sink.fail_next_commits(1).expect("fault injection");
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let err = committer
            .commit_translation(write_context(), completed_unit(8), &translation)
            .expect_err("findings durability should fail");

        match err {
            ResultCommitError::FindingsWait(InMemoryPersistenceError::InjectedCommitFailure {
                store,
            }) => assert_eq!(store, InMemoryStoreKind::Findings),
            other => panic!("expected findings wait failure, got {other:?}"),
        }

        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn done_ledger_submission_failure_returns_no_receipt_but_findings_are_durable() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_submissions(1)
            .expect("fault injection");
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();

        let err = committer
            .commit_translation(write_context(), completed_unit(9), &translation)
            .expect_err("done-ledger submission should fail");

        match err {
            ResultCommitError::DoneLedgerSubmit(
                InMemoryPersistenceError::InjectedSubmissionFailure { store },
            ) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
            other => panic!("expected done-ledger submission failure, got {other:?}"),
        }

        // Findings are already durable since the failure happened after findings commit.
        assert_eq!(
            findings_sink.findings_snapshot().expect("snapshot").len(),
            2
        );
        assert!(done_ledger.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn findings_count_mismatch_is_rejected_before_any_write() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger_sink = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger_sink.clone());

        // Scanned translation has 2 distinct findings.
        let scanned = translated_scan();
        // Clean-scan done-ledger records findings_count=0 with ScannedClean status.
        let clean = translated_clean_scan();

        let request = CommitRequest::new(
            write_context(),
            completed_unit(10),
            scanned.findings_batch(),
            std::slice::from_ref(clean.done_ledger()),
        );

        let err = committer
            .commit_item(request)
            .expect_err("findings count mismatch should be rejected");

        match err {
            ResultCommitError::InvalidRequest(
                ResultCommitRequestError::FindingsCountMismatch { expected, actual },
            ) => {
                assert_eq!(expected, 0);
                assert_eq!(actual, 2);
            }
            other => panic!("expected findings count mismatch, got {other:?}"),
        }

        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty()
        );
        assert!(done_ledger_sink.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn findings_present_for_unscanned_status_is_rejected_before_any_write() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger_sink = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger_sink.clone());

        let scanned = translated_scan();
        // FailedRetryable done-ledger for the same item — same OVID, same
        // write context, but non-scanned terminal status.
        let failed = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item(),
            128,
            timing(),
            ItemResult::FailedRetryable {
                error_code: DoneLedgerErrorCode::try_new("TIMEOUT").expect("error code"),
            },
            &test_rule_fingerprint,
        )
        .expect("translation");

        let request = CommitRequest::new(
            write_context(),
            completed_unit(11),
            scanned.findings_batch(),
            std::slice::from_ref(failed.done_ledger()),
        );

        let err = committer
            .commit_item(request)
            .expect_err("findings for unscanned status should be rejected");

        match err {
            ResultCommitError::InvalidRequest(
                ResultCommitRequestError::FindingsPresentForUnscannedStatus { status },
            ) => assert_eq!(status, DoneLedgerStatus::FailedRetryable),
            other => panic!("expected findings present for unscanned status, got {other:?}"),
        }

        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty()
        );
        assert!(done_ledger_sink.snapshot().expect("snapshot").is_empty());
    }

    #[test]
    fn observation_ovid_mismatch_is_rejected_before_any_write() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger_sink = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger_sink.clone());

        // Findings from the primary item (observations carry primary OVID).
        let primary = translated_scan();
        // Done-ledger from a different item (different OVID in key).
        let alt = translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &scan_item_alt(),
            64,
            timing(),
            ItemResult::Scanned {
                findings: &[finding(7, 10, 20, 0xAA), finding(9, 30, 45, 0xBB)],
            },
            &test_rule_fingerprint,
        )
        .expect("translation");

        let request = CommitRequest::new(
            write_context(),
            completed_unit(12),
            primary.findings_batch(),
            std::slice::from_ref(alt.done_ledger()),
        );

        let err = committer
            .commit_item(request)
            .expect_err("observation ovid mismatch should be rejected");

        match err {
            ResultCommitError::InvalidRequest(
                ResultCommitRequestError::ObservationOvidMismatch { index, .. },
            ) => assert_eq!(index, 0),
            other => panic!("expected observation ovid mismatch, got {other:?}"),
        }

        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty()
        );
        assert!(done_ledger_sink.snapshot().expect("snapshot").is_empty());
    }

    // ------------------------------------------------------------------
    // Shared validation-rejection helper
    // ------------------------------------------------------------------

    /// Assert that `commit_item` rejects the request with an `InvalidRequest`
    /// error matching the given predicate, and that no writes reached either sink.
    fn assert_validation_rejects(
        request: CommitRequest<'_>,
        check: impl FnOnce(&ResultCommitRequestError),
    ) {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());

        let err = committer
            .commit_item(request)
            .expect_err("validation should reject this request");

        match err {
            ResultCommitError::InvalidRequest(ref inner) => check(inner),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }

        assert!(
            findings_sink
                .findings_snapshot()
                .expect("snapshot")
                .is_empty(),
            "no findings should be written for a rejected request",
        );
        assert!(
            done_ledger.snapshot().expect("snapshot").is_empty(),
            "no done-ledger rows should be written for a rejected request",
        );
    }

    // ------------------------------------------------------------------
    // commit_item happy-path test
    // ------------------------------------------------------------------

    #[test]
    fn commit_item_with_hand_constructed_request_succeeds() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let committer = ResultCommitter::new(findings_sink.clone(), done_ledger.clone());
        let translation = translated_scan();
        let request = CommitRequest::new(
            write_context(),
            completed_unit(10),
            translation.findings_batch(),
            std::slice::from_ref(translation.done_ledger()),
        );

        let receipt = committer.commit_item(request).expect("should succeed");
        assert_eq!(receipt.completed_unit().sequence_no(), 10);
        assert_eq!(receipt.durable().scope().committed_units().get(), 1);
        assert_eq!(receipt.durable().findings().finding_count(), 2);
        assert_eq!(receipt.durable().done_ledger().record_count(), 1);
    }

    // ------------------------------------------------------------------
    // done_ledger.validate() rejection
    // ------------------------------------------------------------------

    #[test]
    fn rejects_done_ledger_cross_field_invariant_violation() {
        let key = DoneLedgerKey::new(
            write_context().tenant_id(),
            write_context().policy_hash(),
            OvidHash::from_bytes([0x55; 32]),
        );
        let prov = DoneLedgerProvenance::from_write_context(
            write_context(),
            LogicalTime::from_raw(1_000),
            LogicalTime::from_raw(2_000),
        );
        let error_code = DoneLedgerErrorCode::try_new("STALE").unwrap();
        // ScannedClean + error_code is accepted by try_new (for deserialization
        // flexibility) but rejected by validate().
        let record = DoneLedgerRecord::try_new(
            key,
            DoneLedgerStatus::ScannedClean,
            1024,
            0,
            prov,
            Some(error_code),
        )
        .expect("try_new accepts this combination");
        let records = [record];

        let request = CommitRequest::new(
            write_context(),
            completed_unit(20),
            FindingsUpsertBatch::new(&[], &[], &[]),
            &records,
        );

        assert_validation_rejects(request, |err| {
            assert!(
                matches!(err, ResultCommitRequestError::DoneLedgerRecord(_)),
                "expected DoneLedgerRecord from validate(), got {err:?}",
            );
        });
    }

    // ------------------------------------------------------------------
    // validation error-path tests
    // ------------------------------------------------------------------

    #[test]
    fn rejects_referential_integrity_violation() {
        // Occurrence that references a finding not present in the batch.
        let phantom_norm = NormHash::from_digest([0xCC; 32]);
        let phantom_secret = key_secret_hash(&tenant_secret_key(), &phantom_norm);
        let phantom_finding = FindingRecord::new(
            write_context().tenant_id(),
            StableItemId::from_bytes([0x33; 32]),
            test_rule_fingerprint(99),
            phantom_secret,
        );
        let orphan = OccurrenceRecord::try_new(
            write_context().tenant_id(),
            phantom_finding.finding_id(),
            ObjectVersionId::from_bytes([0x44; 32]),
            10,
            20,
        )
        .expect("occurrence construction");

        let clean = translated_clean_scan();
        let occurrences = [orphan];
        let batch = FindingsUpsertBatch::new(&[], &occurrences, &[]);
        let request = CommitRequest::new(
            write_context(),
            completed_unit(30),
            batch,
            std::slice::from_ref(clean.done_ledger()),
        );

        assert_validation_rejects(request, |err| {
            assert!(
                matches!(err, ResultCommitRequestError::FindingsBatch(_)),
                "expected FindingsBatch (orphaned reference), got {err:?}",
            );
        });
    }

    #[test]
    fn rejects_finding_tenant_mismatch() {
        let wrong_tenant = TenantId::from_bytes([0xFF; 32]);
        let norm = NormHash::from_digest([0xAA; 32]);
        let secret = key_secret_hash(&tenant_secret_key(), &norm);
        let bad_finding = FindingRecord::new(
            wrong_tenant,
            StableItemId::from_bytes([0x33; 32]),
            test_rule_fingerprint(7),
            secret,
        );

        let clean = translated_clean_scan();
        let findings = [bad_finding];
        let batch = FindingsUpsertBatch::new(&findings, &[], &[]);
        let request = CommitRequest::new(
            write_context(),
            completed_unit(31),
            batch,
            std::slice::from_ref(clean.done_ledger()),
        );

        assert_validation_rejects(request, |err| match err {
            ResultCommitRequestError::TenantMismatch {
                layer,
                expected,
                actual,
            } => {
                assert_eq!(*layer, "finding");
                assert_eq!(*expected, write_context().tenant_id());
                assert_eq!(*actual, wrong_tenant);
            }
            other => panic!("expected TenantMismatch, got {other:?}"),
        });
    }

    #[test]
    fn rejects_observation_write_context_mismatch() {
        let translation = translated_scan();
        let findings = translation.findings_batch().findings();
        let occurrences = translation.findings_batch().occurrences();

        let occ_id = occurrences[0].occurrence_id();
        let bad_obs = ObservationRecord::new(
            write_context().tenant_id(),
            occ_id,
            write_context().policy_hash(),
            translation.done_ledger().key().ovid_hash(),
            RunId::from_raw(999),
            write_context().shard_id(),
            write_context().fence_epoch(),
            LogicalTime::from_raw(1_000),
        );
        let observations = [bad_obs];
        let batch = FindingsUpsertBatch::new(findings, occurrences, &observations);
        let request = CommitRequest::new(
            write_context(),
            completed_unit(32),
            batch,
            std::slice::from_ref(translation.done_ledger()),
        );

        assert_validation_rejects(request, |err| match err {
            ResultCommitRequestError::ObservationWriteContextMismatch { index } => {
                assert_eq!(*index, 0);
            }
            other => panic!("expected ObservationWriteContextMismatch, got {other:?}"),
        });
    }

    #[test]
    fn rejects_done_ledger_write_context_mismatch() {
        let key = DoneLedgerKey::new(
            write_context().tenant_id(),
            write_context().policy_hash(),
            OvidHash::from_bytes([0x55; 32]),
        );
        let prov = DoneLedgerProvenance::new(
            RunId::from_raw(999),
            write_context().shard_id(),
            write_context().fence_epoch(),
            LogicalTime::from_raw(1_000),
            LogicalTime::from_raw(2_000),
        );
        let record =
            DoneLedgerRecord::try_new(key, DoneLedgerStatus::ScannedClean, 1024, 0, prov, None)
                .expect("done-ledger construction");
        let records = [record];

        let request = CommitRequest::new(
            write_context(),
            completed_unit(33),
            FindingsUpsertBatch::new(&[], &[], &[]),
            &records,
        );

        assert_validation_rejects(request, |err| {
            assert!(
                matches!(
                    err,
                    ResultCommitRequestError::DoneLedgerWriteContextMismatch { .. }
                ),
                "expected DoneLedgerWriteContextMismatch, got {err:?}",
            );
        });
    }
}
