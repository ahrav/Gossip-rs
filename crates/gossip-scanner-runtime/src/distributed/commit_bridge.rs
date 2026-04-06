//! Scan-to-commit adapter and commit pipeline draining.
//!
//! [`ReceiptCommitSink`] bridges runtime item execution into the
//! receipt-driven commit pipeline. [`drain_commit_stage`] consumes commit
//! outcomes and feeds the checkpoint aggregator. Helper functions verify
//! that every submitted commit produced exactly one durable outcome.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Result, anyhow};
use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{LogicalTime, ObjectVersionId, RuleFingerprint, TenantSecretKey},
    persistence::{DoneLedger, FindingsSink, WriteContext},
};
use scanner_scheduler::{
    events::{CoreEvent, EventOutput, FindingEvent, SummaryEvent},
    source_kind::SourceKind,
    store::FsFindingRecord,
};

use super::types::{DistributedRuntimeError, LeaseUncertainty, OrderedSourceAssignmentOutcome};
use crate::{
    ScanReport, ScanRuntimeError,
    checkpoint_aggregator::PrefixCheckpointAggregator,
    commit_model::CompletedUnit,
    commit_pipeline::{
        CommitPipelineDrainer, CommitPipelineSender, CommitStageOutput, QueuedCommit,
    },
    commit_sink::{CommitSink, FindingsBatch, ItemMeta},
    coordination_sink::{CommitProgressRecord, CoordinationEventRecorder},
    ordered_content::{
        OrderedContentItemExecution, OrderedContentItemOutcome, OrderedContentReadStop,
    },
    result_translation::{ItemResult, ScanTiming, translate_item_result},
};

// ---------------------------------------------------------------------------
// InFlightItem
// ---------------------------------------------------------------------------

/// One item that has begun scanning but has not yet been submitted to commit.
///
/// Accumulates findings through [`ReceiptCommitSink::upsert_findings`] until
/// [`finish_item`](ReceiptCommitSink::finish_item) translates the accumulated
/// state into a [`QueuedCommit`] and submits it to the pipeline.
///
/// Rollback on failure: if translation or pipeline submission fails,
/// `finish_item` re-inserts the item into the in-flight map so the caller
/// can retry or so that `ReceiptCommitSink::finish()` can detect the
/// leaked item.
#[derive(Debug)]
pub(super) struct InFlightItem {
    /// Monotonic sequence number assigned at `begin_item`, used for
    /// deterministic logical-time derivation and post-drain cross-check.
    pub(super) sequence_no: u64,
    /// Item metadata (stable ID, optional version, size hint) captured at
    /// `begin_item` and used during `finish_item` translation.
    pub(super) meta: ItemMeta,
    /// Accumulated finding records appended by one or more `upsert_findings`
    /// calls before `finish_item` translates them into persistence rows.
    pub(super) findings: Vec<FsFindingRecord>,
}

// ---------------------------------------------------------------------------
// ReceiptCommitSink
// ---------------------------------------------------------------------------

/// Adapter that bridges runtime item execution into the
/// receipt-driven commit pipeline.
///
/// Supports two submission surfaces:
///
/// - The callback-based `CommitSink` lifecycle (`begin_item` /
///   `upsert_findings` / `finish_item`), and
/// - direct ordered-content item outcomes submitted through
///   [`submit_ordered_item`](Self::submit_ordered_item).
///
/// Both surfaces converge on `QueuedCommit` work items containing full
/// persistence translations (findings, occurrences, observations, and
/// done-ledger rows) so the downstream commit pipeline retains one
/// receipt-driven durability path.
///
/// # Item lifecycle
///
/// ```text
/// begin_item(key, meta)          → inserts InFlightItem with sequence_no
///   upsert_findings(key, batch)  → appends FsFindingRecord to InFlightItem
///   upsert_findings(key, batch)  → (may be called multiple times)
/// finish_item(key)               → removes InFlightItem, translates,
///                                  submits QueuedCommit to pipeline
/// ```
///
/// # Threading model
///
/// This sink is driven by a single-threaded drain loop. The interior `Mutex`
/// fields satisfy the `Send + Sync` bound required by [`CommitSink`] without
/// introducing real contention. Sequence numbers assigned by
/// [`next_sequence_no`](Self::next_sequence_no) are therefore monotonically
/// ordered with respect to submission; `Ordering::Relaxed` is sufficient
/// because there is no concurrent caller to race against.
///
/// # Failure modes
///
/// - **Translation failure** (e.g., sequence-number overflow): the item is
///   rolled back into `in_flight` and `finish()` will detect it.
/// - **Submission failure** (e.g., pipeline disconnected): same rollback.
/// - **Recorder failure** (telemetry): logged once, then suppressed; non-fatal
///   because durability flows through the commit pipeline, not the recorder.
pub(super) struct ReceiptCommitSink {
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
    rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
    submitter: CommitPipelineSender,
    pub(super) next_sequence_no: AtomicU64,
    pub(super) in_flight: Mutex<BTreeMap<ItemKey, InFlightItem>>,
    pub(super) submitted: Mutex<Vec<u64>>,
    /// First-failure-only flag for progress telemetry. Mirrors
    /// `CoordinationEventSink`'s suppression to avoid flooding logs during
    /// sustained recorder outages.
    progress_error_logged: AtomicBool,
}

impl ReceiptCommitSink {
    /// Construct one adapter for a single shard's scan lifecycle.
    ///
    /// The `rule_fingerprint` closure maps engine rule IDs to stable
    /// persistence-layer fingerprints. It is called during `finish_item`
    /// translation and must be deterministic for the same rule ID.
    pub(super) fn new(
        recorder: Arc<dyn CoordinationEventRecorder>,
        shard_id: Arc<str>,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
        rule_fingerprint: Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>,
        submitter: CommitPipelineSender,
    ) -> Self {
        Self {
            shard_id,
            recorder,
            write_context,
            tenant_secret_key,
            rule_fingerprint,
            submitter,
            next_sequence_no: AtomicU64::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
            submitted: Mutex::new(Vec::new()),
            progress_error_logged: AtomicBool::new(false),
        }
    }

    /// Consume the sink and return the sequence numbers of successfully
    /// submitted commits. Returns an error if any items remain in-flight
    /// (either because the caller violated the begin/upsert/finish protocol
    /// or because an earlier translation/submission failure rolled the item
    /// back into the in-flight map) or if a mutex is poisoned.
    pub(super) fn finish(self) -> Result<Vec<u64>> {
        let in_flight = self
            .in_flight
            .into_inner()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        if !in_flight.is_empty() {
            return Err(anyhow::anyhow!(
                "receipt commit sink finished with {} item(s) still in flight",
                in_flight.len()
            ));
        }

        self.submitted
            .into_inner()
            .map_err(|_| anyhow::anyhow!("receipt commit sink submitted state lock poisoned"))
    }

    pub(super) fn next_sequence_no(&self) -> u64 {
        self.next_sequence_no.fetch_add(1, Ordering::Relaxed)
    }

    fn record_progress(&self, event: CommitProgressRecord) {
        if let Err(error) = self.recorder.record_commit_progress(&self.shard_id, event)
            && !self.progress_error_logged.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                shard_id = %self.shard_id,
                %error,
                "recorder failed to persist progress event; subsequent failures suppressed",
            );
        }
    }

    /// Derive a pair of non-overlapping logical timestamps from a sequence number.
    ///
    /// Maps sequence `n` to `(2n, 2n+1)`, giving each item a unique
    /// `[started, finished)` interval that never collides with another item's
    /// interval. This is sufficient for the done-ledger provenance columns,
    /// which only require monotonicity within a single shard.
    ///
    /// Returns `Err` when `2 * sequence_no` would overflow `u64`.
    pub(super) fn logical_timing_for(sequence_no: u64) -> Result<ScanTiming> {
        let started = sequence_no.checked_mul(2).ok_or_else(|| {
            anyhow::anyhow!("sequence number overflow while deriving scan timing")
        })?;
        // When checked_mul(2) succeeds, started is even and <= u64::MAX - 1
        // (u64::MAX is odd), so started + 1 fits without overflow.
        let finished = started + 1;

        Ok(ScanTiming::new(
            LogicalTime::from_raw(started),
            LogicalTime::from_raw(finished),
        ))
    }

    /// Records a begin-progress event for telemetry.
    ///
    /// Recorder errors are intentionally non-fatal: durability flows through
    /// the commit pipeline, not the recorder.
    fn record_begin(&self, item_key: &ItemKey, meta: &ItemMeta) {
        self.record_progress(CommitProgressRecord::Begin {
            write_context: self.write_context,
            item_key: item_key.clone(),
            size_hint: meta.size_hint,
        });
    }

    /// Records a finish-progress event for telemetry.
    ///
    /// Pairs with [`record_begin`](Self::record_begin) to close the item's
    /// telemetry lifecycle. Emitted both on successful pipeline submission
    /// and on terminal translation failure so telemetry consumers always see
    /// a balanced Begin/Finish pair. Durability confirmation flows through
    /// the receipt/checkpoint path, not through telemetry.
    fn record_finish(&self, item_key: &ItemKey) {
        self.record_progress(CommitProgressRecord::Finish {
            write_context: self.write_context,
            item_key: item_key.clone(),
        });
    }

    fn submit_queued_commit(
        &self,
        item_key: &ItemKey,
        sequence_no: u64,
        work: QueuedCommit,
    ) -> Result<()> {
        self.submitter
            .submit(work)
            .map_err(|error| anyhow!("execution to commit submission failed: {error}"))?;

        // The commit is in the pipeline. The submitted vec is bookkeeping
        // for ordering assertions, not the durability path — recover
        // through a poisoned mutex rather than returning an error that
        // would mislead the caller into thinking the commit was lost.
        self.submitted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(sequence_no);

        self.record_finish(item_key);
        Ok(())
    }

    fn ordered_item_meta(execution: &OrderedContentItemExecution) -> ItemMeta {
        let item = execution.item();
        ItemMeta {
            stable_item_id: item.stable_item_id(),
            version: Some(item.version()),
            size_hint: item.size_hint(),
        }
    }

    fn translate_ordered_item(
        &self,
        sequence_no: u64,
        execution: &OrderedContentItemExecution,
    ) -> Result<QueuedCommit> {
        let item = execution.item();
        let timing = Self::logical_timing_for(sequence_no)?;
        let checkpoint_cursor = Cursor::with_last_key(item.item_key().clone());
        let result = match execution.outcome() {
            OrderedContentItemOutcome::Scanned { findings } => ItemResult::Scanned { findings },
            OrderedContentItemOutcome::Truncated { .. } => ItemResult::FailedRetryable {
                error_code: OrderedContentReadStop::truncation_code(),
            },
            OrderedContentItemOutcome::Failed(stop) => {
                let error_code = OrderedContentReadStop::failure_code();
                if stop.class().is_retryable() {
                    ItemResult::FailedRetryable { error_code }
                } else {
                    ItemResult::FailedPermanent { error_code }
                }
            }
            OrderedContentItemOutcome::Skipped(reason) => ItemResult::Skipped {
                error_code: reason.done_ledger_code(),
            },
        };
        let translation = translate_item_result(
            self.write_context,
            &self.tenant_secret_key,
            item,
            execution.report().bytes_scanned,
            timing,
            result,
            &*self.rule_fingerprint,
        )?;

        Ok(QueuedCommit::new(
            self.write_context,
            CompletedUnit::ordered_content(sequence_no, checkpoint_cursor),
            translation,
        ))
    }

    pub(super) fn submit_ordered_item(
        &self,
        execution: &OrderedContentItemExecution,
    ) -> Result<()> {
        let item_key = execution.item().item_key().clone();
        let meta = Self::ordered_item_meta(execution);
        // Sequence gap on translation failure is tolerated — the shard terminates
        // on error, so the gap never reaches wait_for_submitted_commits.
        let sequence_no = self.next_sequence_no();

        self.record_begin(&item_key, &meta);
        let work = match self.translate_ordered_item(sequence_no, execution) {
            Ok(work) => work,
            Err(error) => {
                self.record_finish(&item_key);
                return Err(error);
            }
        };
        self.submit_queued_commit(&item_key, sequence_no, work)
    }

    /// Reconstruct the deterministic translation inputs from an in-flight
    /// item's accumulated state and produce a [`QueuedCommit`] ready for the
    /// commit pipeline.
    ///
    /// This is the core bridge logic. It:
    /// 1. Derives a non-overlapping `[started, finished)` logical time pair
    ///    from the item's sequence number.
    /// 2. Falls back to a weak version derived from the item key bytes when
    ///    the connector did not supply an explicit version.
    /// 3. Attaches a display-only [`Location`] when the item key is valid
    ///    UTF-8 and `Location::try_new` accepts the resulting string
    ///    (best-effort; non-UTF-8 keys or keys rejected by `Location`
    ///    construction skip the location).
    /// 4. Delegates to [`translate_item_result`] for deterministic
    ///    persistence row derivation.
    pub(super) fn translate_in_flight(
        &self,
        item_key: &ItemKey,
        item: &InFlightItem,
    ) -> Result<QueuedCommit> {
        let timing = Self::logical_timing_for(item.sequence_no)?;
        let bytes_scanned = item.meta.size_hint.unwrap_or(0);
        let version = item.meta.version.unwrap_or_else(|| {
            VersionId::Weak(ObjectVersionId::from_version_bytes(item_key.as_bytes()))
        });
        let checkpoint_cursor = Cursor::with_last_key(item_key.clone());
        let item_ref = ItemRef::try_from_slice(item_key.as_bytes())?;
        let mut scan_item = ScanItem::new(
            item_key.clone(),
            item_ref,
            item.meta.stable_item_id,
            version,
        );

        if let Some(size_hint) = item.meta.size_hint {
            scan_item = scan_item.with_size_hint(size_hint);
        }

        match std::str::from_utf8(scan_item.item_key().as_bytes()) {
            Ok(display) => match Location::try_new(display.to_owned(), None) {
                Ok(location) => {
                    scan_item = scan_item.with_location(location);
                }
                Err(_) => {
                    tracing::debug!(
                        item_key_len = scan_item.item_key().as_bytes().len(),
                        "item location rejected by Location::try_new; \
                         observation will lack display path"
                    );
                }
            },
            Err(_) => {
                tracing::debug!(
                    item_key_len = scan_item.item_key().as_bytes().len(),
                    "item key is not valid UTF-8; observation will lack display path"
                );
            }
        }

        let translation = translate_item_result(
            self.write_context,
            &self.tenant_secret_key,
            &scan_item,
            bytes_scanned,
            timing,
            ItemResult::Scanned {
                findings: &item.findings,
            },
            &*self.rule_fingerprint,
        )?;

        Ok(QueuedCommit::new(
            self.write_context,
            CompletedUnit::ordered_content(item.sequence_no, checkpoint_cursor),
            translation,
        ))
    }

    /// Re-insert a removed item into the in-flight map on translation or
    /// submission failure.
    ///
    /// Uses `unwrap_or_else` to recover through a poisoned mutex because the
    /// rollback is not on the durability path.
    fn rollback_in_flight(&self, key: ItemKey, item: InFlightItem) {
        let overwritten = self
            .in_flight
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, item);
        debug_assert!(
            overwritten.is_none(),
            "rollback re-insert overwrote a concurrent begin_item entry; \
             ReceiptCommitSink must be driven by a single-threaded drain loop"
        );
    }
}

impl CommitSink for ReceiptCommitSink {
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;

        use std::collections::btree_map::Entry;
        match guard.entry(item_key.clone()) {
            Entry::Occupied(_) => {
                return Err(anyhow::anyhow!(
                    "begin_item called twice without finish_item for the same item"
                ));
            }
            Entry::Vacant(slot) => {
                let sequence_no = self.next_sequence_no();
                slot.insert(InFlightItem {
                    sequence_no,
                    meta: meta.clone(),
                    findings: Vec::new(),
                });
            }
        }
        drop(guard);

        self.record_begin(item_key, meta);
        Ok(())
    }

    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()> {
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow::anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        let item = guard
            .get_mut(item_key)
            .ok_or_else(|| anyhow::anyhow!("upsert_findings called before begin_item for item"))?;

        batch.validate()?;

        // The CommitSink surface provides only start/end offsets.
        // Window fields mirror blob offsets when no chunker-specific
        // context is available. The blob-absolute offsets are the
        // identity-bearing coordinates consumed by
        // `PersistenceFinding::blob_offset_start/blob_offset_end` for
        // `OccurrenceId` derivation.
        item.findings
            .extend(batch.findings.iter().map(|finding| FsFindingRecord {
                rule_id: finding.rule_id,
                blob_offset_start: finding.start,
                blob_offset_end: finding.end,
                window_start: finding.start,
                window_end: finding.end,
                norm_hash: finding.norm_hash,
                confidence_score: finding.confidence_score,
            }));

        Ok(())
    }

    fn finish_item(&self, item_key: &ItemKey) -> Result<()> {
        // Remove the item under a short-lived lock. Translation and
        // submission happen outside the critical section to minimize lock
        // hold duration.
        let (removed_key, item) = {
            let mut guard = self.in_flight.lock().map_err(|_| {
                anyhow::anyhow!("receipt commit sink in-flight state lock poisoned")
            })?;
            guard
                .remove_entry(item_key)
                .ok_or_else(|| anyhow::anyhow!("finish_item called before begin_item for item"))?
        };

        let sequence_no = item.sequence_no;
        let work = match self.translate_in_flight(&removed_key, &item) {
            Ok(work) => work,
            Err(err) => {
                self.rollback_in_flight(removed_key, item);
                return Err(err);
            }
        };

        if let Err(error) = self.submit_queued_commit(&removed_key, sequence_no, work) {
            self.rollback_in_flight(removed_key, item);
            return Err(error);
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Event emission helpers
// ---------------------------------------------------------------------------

/// Emit per-finding events for one ordered-content item execution.
///
/// Only items with a `Scanned` outcome produce events; skipped, truncated,
/// and failed outcomes are silently ignored because their findings list is
/// empty or absent. Each finding becomes one `CoreEvent::Finding` dispatched
/// through the event output, carrying the rule name resolved from the
/// pre-built detection engine.
pub(super) fn emit_ordered_item_findings(
    out: &dyn EventOutput,
    engine: &scanner_engine::Engine,
    execution: &OrderedContentItemExecution,
) {
    let OrderedContentItemOutcome::Scanned { findings } = execution.outcome() else {
        return;
    };

    for finding in findings {
        out.emit_core(CoreEvent::Finding(FindingEvent {
            source: SourceKind::Fs,
            object_path: execution.item().item_key().as_bytes(),
            start: finding.blob_offset_start,
            end: finding.blob_offset_end,
            rule_id: finding.rule_id,
            rule_name: engine.rule_name(finding.rule_id),
            norm_hash: finding.norm_hash,
            blob_oid: None,
            commit_id: None,
            change_kind: None,
            confidence_score: finding.confidence_score,
        }));
    }
}

/// Emit a summary event for one completed ordered-content shard execution.
///
/// Derives elapsed milliseconds and throughput (MiB/s) from the accumulated
/// `ScanReport`, then flushes the event output to ensure the summary is
/// delivered promptly. Called once per shard after all pages have been
/// processed (or the loop exits early with partial progress).
pub(super) fn emit_ordered_summary(out: &dyn EventOutput, report: ScanReport) {
    let elapsed_ms = report.scan_ns / 1_000_000;
    let throughput_mib_s = if report.scan_ns == 0 {
        0.0
    } else {
        (report.bytes_scanned as f64 / (1024.0 * 1024.0))
            / (report.scan_ns as f64 / 1_000_000_000.0)
    };
    out.emit_core(CoreEvent::Summary(SummaryEvent {
        source: SourceKind::Fs,
        status: if report.errors == 0 { "ok" } else { "error" },
        elapsed_ms,
        bytes_scanned: report.bytes_scanned,
        findings_emitted: report.findings_emitted,
        errors: report.errors,
        throughput_mib_s,
    }));
    out.flush();
}

// ---------------------------------------------------------------------------
// Commit stage draining and verification
// ---------------------------------------------------------------------------

/// Accumulated state from draining the commit-stage outcome stream.
///
/// Produced by [`drain_commit_stage`] and consumed by
/// `run_filesystem_lease` to build the receipt-driven checkpoint and verify
/// that every submitted commit produced exactly one durable outcome.
#[derive(Debug)]
pub(super) struct CommitStageDrainResult {
    /// Receipt aggregator tracking the contiguous committed prefix. After
    /// draining completes, its `prepare_checkpoint` method yields the
    /// authoritative checkpoint cursor.
    pub(super) aggregator: PrefixCheckpointAggregator,
    /// Sequence numbers of committed items, in drain order (not necessarily
    /// sorted). Compared against the submitted list by
    /// [`wait_for_submitted_commits`] to detect lost or duplicated outcomes.
    pub(super) committed_sequence_nos: Vec<u64>,
}

/// Resolve the concurrent scan, submission, and drain results from one
/// filesystem lease.
///
/// Lease uncertainty takes absolute precedence: if the deadline watchdog fired,
/// the lease is no longer trusted regardless of whether the scan or durability
/// pipeline also produced errors. After that, scan failures are surfaced before
/// durability failures because a broken scan often cascades into downstream
/// drain errors. Returning the runtime error first gives operators the closest
/// cause.
pub(super) fn resolve_filesystem_lease_results(
    outcome: Result<OrderedSourceAssignmentOutcome, ScanRuntimeError>,
    submitted: Result<Vec<u64>>,
    stage_result: anyhow::Result<anyhow::Result<CommitStageDrainResult>>,
    lease_uncertainty: Option<LeaseUncertainty>,
) -> Result<
    (
        OrderedSourceAssignmentOutcome,
        Vec<u64>,
        CommitStageDrainResult,
    ),
    DistributedRuntimeError,
> {
    if let Some(reason) = lease_uncertainty {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }
    let outcome = outcome.map_err(DistributedRuntimeError::Runtime)?;
    let submitted = submitted.map_err(DistributedRuntimeError::Durability)?;
    let stage_result = stage_result
        .map_err(DistributedRuntimeError::Durability)?
        .map_err(DistributedRuntimeError::Durability)?;
    Ok((outcome, submitted, stage_result))
}

/// Drain commit-stage outcomes to completion while building the receipt-driven
/// checkpoint prefix.
///
/// Any durable commit failure, receipt aggregation violation, or worker panic
/// aborts the shard. The drainer cancels the worker before joining when the
/// first such failure is observed so scan execution does not keep queuing work
/// behind a broken durability path.
///
/// # Cancellation and outcome delivery
///
/// After `drainer.cancel()`, the commit worker uses `try_send` for any
/// in-progress or post-commit outcomes. If the outcome queue is full or
/// disconnected at that moment, the outcome is silently dropped. This is safe
/// because `drain_error` is always set before `drainer.cancel()` is called,
/// so the function returns the original error without reaching the downstream
/// sequence-number cross-check. Callers that cancel for lease uncertainty must
/// branch on that signal before treating submission or drain gaps as
/// durability failures.
pub(super) fn drain_commit_stage<F, D>(
    drainer: CommitPipelineDrainer<F, D>,
    write_context: WriteContext,
    max_buffered: usize,
) -> Result<CommitStageDrainResult>
where
    F: FindingsSink,
    D: DoneLedger,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    // The aggregator's receipt buffer must not share the channel-backpressure
    // limit: the drain model buffers ALL committed receipts before a single
    // checkpoint is prepared (no intermediate `acknowledge_checkpoint` calls).
    // Use an uncapped limit; actual memory is bounded by the number of items
    // the shard produces, which is always finite.
    let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0, usize::MAX);
    let mut committed_sequence_nos = Vec::with_capacity(max_buffered);
    let mut drain_error = None;

    loop {
        match drainer.recv() {
            Ok(CommitStageOutput::Committed {
                checkpoint_input, ..
            }) => {
                if drain_error.is_none() {
                    let sequence_no = checkpoint_input.receipt().completed_unit().sequence_no();
                    match aggregator.record_receipt(checkpoint_input) {
                        Ok(_) => committed_sequence_nos.push(sequence_no),
                        Err(error) => {
                            drain_error = Some(anyhow!("receipt aggregation failed: {error}"));
                            drainer.cancel();
                        }
                    }
                }
            }
            Ok(CommitStageOutput::Failed {
                completed_unit,
                error,
                ..
            }) => {
                if drain_error.is_none() {
                    drain_error = Some(anyhow!(
                        "durable commit failed for sequence {}: {error}",
                        completed_unit.sequence_no()
                    ));
                    drainer.cancel();
                }
            }
            Err(_) => break,
        }
    }

    drainer
        .join()
        .map_err(|_| anyhow!("receipt commit worker thread panicked"))?;

    if let Some(error) = drain_error {
        return Err(error);
    }

    Ok(CommitStageDrainResult {
        aggregator,
        committed_sequence_nos,
    })
}

/// Verify that every submitted commit sequence produced one durable outcome.
///
/// The local commit pipeline exposes an outcome stream rather than per-item
/// completion handles, so this helper matches submitted sequence numbers
/// against the committed sequence numbers drained from that stream.
pub(super) fn wait_for_submitted_commits(
    mut submitted: Vec<u64>,
    mut committed_sequence_nos: Vec<u64>,
) -> Result<()> {
    // Items can finish out of sequence-number order (the atomic counter
    // assigns sequence numbers at begin_item, but finish_item order depends
    // on scan duration per item). Sort both sides so the pairwise comparison
    // below can detect mismatches by value, not by arrival order.
    submitted.sort_unstable();
    committed_sequence_nos.sort_unstable();

    // Reject duplicate sequence numbers — structurally impossible today
    // (atomic counter + aggregator rejection), but a cheap defense-in-depth
    // guard against future regressions.
    if let Some(dup) = submitted
        .windows(2)
        .find_map(|w| (w[0] == w[1]).then_some(w[0]))
    {
        return Err(anyhow!("duplicate submitted sequence number {dup}"));
    }
    if let Some(dup) = committed_sequence_nos
        .windows(2)
        .find_map(|w| (w[0] == w[1]).then_some(w[0]))
    {
        return Err(anyhow!("duplicate committed sequence number {dup}"));
    }

    if submitted.len() != committed_sequence_nos.len() {
        return Err(anyhow!(
            "submitted {} commit(s) but commit stage produced {} durable outcome(s)",
            submitted.len(),
            committed_sequence_nos.len()
        ));
    }

    for (expected, actual) in submitted.into_iter().zip(committed_sequence_nos) {
        if expected != actual {
            return Err(anyhow!(
                "submitted commit sequence {} did not match durable outcome sequence {}",
                expected,
                actual
            ));
        }
    }

    Ok(())
}

/// Derive the logical time used when acknowledging a prepared checkpoint.
///
/// Returns `last_sequence_no + 1`, placing the checkpoint acknowledgment
/// strictly after the last committed item's sequence number. The raw value
/// passed to `LogicalTime::from_raw` is derived from the sequence-number
/// domain, intentionally distinct from the `(2n, 2n+1)` logical-time
/// mapping used by `ReceiptCommitSink`.
///
/// # Errors
///
/// Returns an error if `last_sequence_no` is `u64::MAX` (no room for +1).
#[inline]
pub(super) fn checkpoint_logical_time(last_sequence_no: u64) -> Result<LogicalTime> {
    last_sequence_no
        .checked_add(1)
        .map(LogicalTime::from_raw)
        .ok_or_else(|| anyhow!("checkpoint logical time overflow: last_sequence_no is u64::MAX"))
}
