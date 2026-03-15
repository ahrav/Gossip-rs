//! Distributed runtime entrypoint with receipt-only progression.
//!
//! This module is the EP2.7 cutover for the shared durability model:
//!
//! - scan execution emits per-item work into a bounded execution → commit queue,
//! - the authoritative commit stage durably writes findings then done-ledger rows,
//! - the runtime derives checkpoint progress only from durable per-item receipts,
//!   never from raw scan completion or driver checkpoint hints, and
//! - shard completion happens only after the prepared receipt-driven checkpoint
//!   has been durably recorded.
//!
//! # Lease lifecycle
//!
//! ```text
//! acquire_shard ─► is_shard_done? ──yes──► release_shard (skip)
//!                       │ no
//!                       ▼
//!            execute assignment with telemetry sink
//!                       │
//!                       ▼
//!     receipt commit sink submits per-item work to bounded queue
//!                       │
//!                       ▼
//!        commit stage drains queue → durable per-item receipts
//!                       │
//!                       ▼
//!      prefix aggregator prepares checkpoint from receipts only
//!                       │
//!                       ▼
//!           complete_shard(checkpoint from receipts only)
//!                       │
//!                       ▼
//!                 mark_shard_done
//! ```
//!
//! ## Safe-stop rule
//!
//! Distributed git scanning does not yet emit commit-sink work items, so the
//! receipt-driven durability path is not available there. This runtime rejects
//! such leases instead of silently marking them done without durable receipts.
//! Better pause than overlap, and much better than fake progress.

use std::collections::{BTreeMap, HashSet, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use anyhow::{Error as AnyError, Result, anyhow};
use gossip_connectors::GitExecutionConfig;
use gossip_contracts::{
    connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
    identity::{FenceEpoch, LogicalTime, ObjectVersionId, RunId, ShardId, TenantSecretKey},
    persistence::{CheckpointCommitReceipt, DoneLedger, FindingsSink, WriteContext},
};
use gossip_scan_driver::{
    Assignment, CancellationToken, CommitSink, ConnectorKind, FindingsBatch, ItemMeta, ScanReport,
};
use scanner_scheduler::FsFindingRecord;

use crate::checkpoint_aggregator::PrefixCheckpointAggregator;
use crate::commit_model::CompletedUnit;
use crate::commit_pipeline::{
    CommitCompletion, CommitPipelineBuildError, CommitPipelineStateError, CommitStage,
    CommitStageRunReport, CommitWorkItem, ExecutionCommitSubmitter, bounded_commit_pipeline,
};
use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, CoordinationEventSink, IdentityChainRecord,
    StoredCoreEvent, StoredGitEvent,
};
use crate::result_committer::ResultCommitter;
use crate::result_translation::{ItemResult, ScanTiming, translate_item_result};
use crate::{RuntimeEngineConfig, ScanBudgets, ScanRuntimeError, execute_assignment_with_config};

/// Lease payload consumed by the distributed runtime.
///
/// Bundles a scan [`Assignment`] with the shared write context and tenant
/// secret key needed for downstream durable translation. One lease corresponds
/// to one shard from the coordination layer.
#[derive(Clone, Debug)]
pub struct ShardLease {
    /// Unique shard identifier used for done-ledger tracking.
    ///
    /// `Arc<str>` avoids per-clone heap allocation when the ID is shared
    /// across the event sink, commit sink, and coordinator calls.
    pub shard_id: Arc<str>,
    /// Scan assignment to execute for this shard.
    pub assignment: Assignment,
    /// Shared routing and fencing metadata for all downstream writes emitted
    /// while this lease is active.
    pub write_context: WriteContext,
    /// Tenant secret key used for secret hash derivation.
    pub tenant_secret_key: TenantSecretKey,
}

impl ShardLease {
    /// Construct a lease payload and assert that assignment-level policy scope
    /// matches the shared write context.
    #[must_use]
    pub fn new(
        shard_id: Arc<str>,
        assignment: Assignment,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
    ) -> Self {
        debug_assert_eq!(
            assignment.policy_hash,
            write_context.policy_hash(),
            "lease assignment policy_hash must match write_context.policy_hash"
        );

        Self {
            shard_id,
            assignment,
            write_context,
            tenant_secret_key,
        }
    }
}

/// Coordinator surface required by the distributed runtime.
///
/// Implementors must guarantee:
///
/// - `acquire_shard` returns `None` when no more work is available (the
///   worker loop terminates on `None`).
/// - Production coordinators must make `complete_shard` idempotent or
///   at-least-once tolerant, because crash recovery may replay the call.
///   Test coordinators (e.g., [`InMemoryCoordinator`]) may intentionally
///   relax this to expose replay behavior.
/// - `mark_shard_done` is called only after `complete_shard` succeeds.
/// - `release_shard` must validate lease ownership — releasing another
///   worker's lease is a logic error.
/// - The `event_recorder` is safe to share across the event sink and
///   telemetry-only commit sink for a single shard.
pub trait DistributedCoordinator: Send + Sync {
    /// Acquire the next lease to process, or `None` when no work remains.
    fn acquire_shard(&self) -> Result<Option<ShardLease>>;
    /// Release a lease without marking it complete (used by done-ledger skips).
    ///
    /// Implementations MUST verify that the lease belongs to the calling worker's
    /// active session before releasing. Releasing a lease acquired by another
    /// worker or session is a logic error and must be rejected or ignored.
    fn release_shard(&self, lease: &ShardLease) -> Result<()>;
    /// Mark one lease complete with optional receipt-derived checkpoint metadata.
    fn complete_shard(
        &self,
        lease: &ShardLease,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    ) -> Result<()>;
    /// Query done-ledger status before scanning a shard.
    fn is_shard_done(&self, shard_id: &str) -> Result<bool>;
    /// Persist done-ledger completion after successful scan.
    fn mark_shard_done(&self, lease: &ShardLease) -> Result<()>;
    /// Shared recorder used by both event telemetry and scan-driver progress telemetry.
    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder>;
}

/// Shared persistence backends used by the distributed runtime.
///
/// The runtime clones these handles per shard. Production backends should make
/// that cheap (for example by cloning an `Arc` or a connection-pool handle).
#[derive(Clone)]
pub struct DistributedPersistence<F, D> {
    findings_sink: F,
    done_ledger: D,
}

impl<F, D> DistributedPersistence<F, D> {
    /// Construct one runtime durability bundle.
    #[must_use]
    pub fn new(findings_sink: F, done_ledger: D) -> Self {
        Self {
            findings_sink,
            done_ledger,
        }
    }
}

/// Runtime config for distributed scans.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DistributedRuntimeConfig {
    /// Scan execution budget controls applied to every shard assignment.
    pub budgets: ScanBudgets,
    /// Capacity of the bounded execution → commit queue.
    pub commit_queue_capacity: usize,
}

impl Default for DistributedRuntimeConfig {
    fn default() -> Self {
        Self {
            budgets: ScanBudgets::default(),
            commit_queue_capacity: 64,
        }
    }
}

/// Summary report from one [`run_worker`] invocation.
///
/// On success: `leases_seen == shards_scanned + shards_skipped_done`.
/// On error the worker returns immediately and no report is observable.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    /// Total number of leases dequeued from the coordinator (including skips).
    pub leases_seen: u64,
    /// Number of shards that were actually scanned.
    pub shards_scanned: u64,
    /// Number of shards skipped because the done-ledger already marked them complete.
    pub shards_skipped_done: u64,
}

/// Distributed runtime error.
///
/// Distinguishes coordinator-layer failures (network, locking, persistence)
/// from scan-runtime failures (engine init, driver crashes) and local
/// durability-pipeline failures (translation, commit, checkpoint aggregation).
#[derive(Debug)]
pub enum DistributedRuntimeError {
    /// The coordinator returned an error (acquire, release, or complete).
    Coordinator(AnyError),
    /// The scan runtime failed while executing an assignment.
    Runtime(ScanRuntimeError),
    /// The local durability pipeline failed.
    Durability(AnyError),
}

impl fmt::Display for DistributedRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => write!(f, "coordinator error: {error}"),
            Self::Runtime(error) => write!(f, "runtime error: {error}"),
            Self::Durability(error) => write!(f, "durability pipeline error: {error}"),
        }
    }
}

impl std::error::Error for DistributedRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinator(error) => Some(error.as_ref()),
            Self::Runtime(error) => Some(error),
            Self::Durability(error) => Some(error.as_ref()),
        }
    }
}

impl From<ScanRuntimeError> for DistributedRuntimeError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

#[derive(Debug)]
struct InFlightItem {
    sequence_no: u64,
    item_key: ItemKey,
    meta: ItemMeta,
    findings: Vec<FsFindingRecord>,
}

#[derive(Debug)]
struct SubmittedCommit<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    sequence_no: u64,
    completion: CommitCompletion<F, D>,
}

/// Scan-driver commit sink that bridges begin/upsert/finish callbacks into the
/// EP2 receipt-driven commit pipeline.
///
/// This is intentionally a compatibility adapter. The current scan-driver seam
/// exposes `ItemMeta` and finding batches rather than the richer runtime item
/// result model, so this sink reconstructs the deterministic translation inputs
/// the shared runtime committer expects.
struct ReceiptCommitSink<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    shard_id: Arc<str>,
    recorder: Arc<dyn CoordinationEventRecorder>,
    write_context: WriteContext,
    tenant_secret_key: TenantSecretKey,
    submitter: ExecutionCommitSubmitter<F, D>,
    next_sequence_no: AtomicU64,
    in_flight: Mutex<BTreeMap<Vec<u8>, InFlightItem>>,
    submitted: Mutex<Vec<SubmittedCommit<F, D>>>,
}

impl<F, D> ReceiptCommitSink<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    fn new(
        recorder: Arc<dyn CoordinationEventRecorder>,
        shard_id: Arc<str>,
        write_context: WriteContext,
        tenant_secret_key: TenantSecretKey,
        submitter: ExecutionCommitSubmitter<F, D>,
    ) -> Self {
        Self {
            shard_id,
            recorder,
            write_context,
            tenant_secret_key,
            submitter,
            next_sequence_no: AtomicU64::new(0),
            in_flight: Mutex::new(BTreeMap::new()),
            submitted: Mutex::new(Vec::new()),
        }
    }

    fn finish(self) -> Result<Vec<SubmittedCommit<F, D>>> {
        let in_flight = self
            .in_flight
            .into_inner()
            .map_err(|_| anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        if !in_flight.is_empty() {
            return Err(anyhow!(
                "receipt commit sink finished with {} item(s) still in flight",
                in_flight.len()
            ));
        }

        self.submitted
            .into_inner()
            .map_err(|_| anyhow!("receipt commit sink submitted state lock poisoned"))
    }

    fn next_sequence_no(&self) -> u64 {
        self.next_sequence_no.fetch_add(1, Ordering::Relaxed)
    }

    fn logical_timing_for(sequence_no: u64) -> Result<ScanTiming> {
        let started = sequence_no
            .checked_mul(2)
            .ok_or_else(|| anyhow!("sequence number overflow while deriving scan timing"))?;
        let finished = started
            .checked_add(1)
            .ok_or_else(|| anyhow!("sequence number overflow while deriving scan timing"))?;
        Ok(ScanTiming::new(
            LogicalTime::from_raw(started),
            LogicalTime::from_raw(finished),
        ))
    }

    fn record_begin(&self, item_key: &ItemKey, meta: &ItemMeta) {
        let _ = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Begin {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
                size_hint: meta.size_hint,
            },
        );
    }

    fn record_finish(&self, item_key: &ItemKey) {
        let _ = self.recorder.record_commit_progress(
            &self.shard_id,
            CommitProgressRecord::Finish {
                write_context: self.write_context,
                item_key: item_key.as_bytes().to_vec(),
            },
        );
    }

    fn translate_in_flight(&self, item: InFlightItem) -> Result<CommitWorkItem> {
        let timing = Self::logical_timing_for(item.sequence_no)?;
        let bytes_scanned = item.meta.size_hint.unwrap_or(0);
        let version = item
            .meta
            .version
            .unwrap_or_else(|| VersionId::Weak(ObjectVersionId::from_version_bytes(item.item_key.as_bytes())));
        let item_ref = ItemRef::try_from_slice(item.item_key.as_bytes())?;
        let mut scan_item = ScanItem::new(item.item_key.clone(), item_ref, item.meta.stable_item_id, version);

        if let Ok(display) = std::str::from_utf8(item.item_key.as_bytes()) {
            if let Ok(location) = Location::try_new(display.to_owned(), None) {
                scan_item = scan_item.with_location(location);
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
        )?;

        let completed_unit =
            CompletedUnit::ordered_content(item.sequence_no, Cursor::with_last_key(item.item_key));

        Ok(CommitWorkItem::new(
            self.write_context,
            completed_unit,
            translation,
        ))
    }
}

impl<F, D> CommitSink for ReceiptCommitSink<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    fn begin_item(&self, item_key: &ItemKey, meta: &ItemMeta) -> Result<()> {
        let sequence_no = self.next_sequence_no();
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        let previous = guard.insert(
            item_key.as_bytes().to_vec(),
            InFlightItem {
                sequence_no,
                item_key: item_key.clone(),
                meta: meta.clone(),
                findings: Vec::new(),
            },
        );
        if previous.is_some() {
            return Err(anyhow!(
                "begin_item called twice without finish_item for the same item"
            ));
        }
        drop(guard);

        self.record_begin(item_key, meta);
        Ok(())
    }

    fn upsert_findings(&self, item_key: &ItemKey, batch: &FindingsBatch) -> Result<()> {
        let mut guard = self
            .in_flight
            .lock()
            .map_err(|_| anyhow!("receipt commit sink in-flight state lock poisoned"))?;
        let item = guard
            .get_mut(item_key.as_bytes())
            .ok_or_else(|| anyhow!("upsert_findings called before begin_item for item"))?;

        item.findings.extend(batch.findings.iter().map(|finding| FsFindingRecord {
            rule_id: finding.rule_id,
            root_hint_start: finding.start,
            root_hint_end: finding.end,
            span_start: finding.start,
            span_end: finding.end,
            norm_hash: finding.norm_hash,
            confidence_score: finding.confidence_score,
        }));

        Ok(())
    }

    fn finish_item(&self, item_key: &ItemKey) -> Result<()> {
        let item = self
            .in_flight
            .lock()
            .map_err(|_| anyhow!("receipt commit sink in-flight state lock poisoned"))?
            .remove(item_key.as_bytes())
            .ok_or_else(|| anyhow!("finish_item called before begin_item for item"))?;

        let work = self.translate_in_flight(item)?;
        let sequence_no = work.sequence_no();
        let completion = self
            .submitter
            .submit(work)
            .map_err(|error| anyhow!("execution → commit submission failed: {error}"))?;
        self.submitted
            .lock()
            .map_err(|_| anyhow!("receipt commit sink submitted state lock poisoned"))?
            .push(SubmittedCommit {
                sequence_no,
                completion,
            });

        self.record_finish(item_key);
        Ok(())
    }
}

#[derive(Debug)]
struct CommitStageDrainResult {
    aggregator: PrefixCheckpointAggregator,
    report: CommitStageRunReport,
}

fn drain_commit_stage<F, D>(
    stage: CommitStage<F, D>,
    write_context: WriteContext,
) -> Result<CommitStageDrainResult>
where
    F: FindingsSink,
    D: DoneLedger,
{
    let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);
    let mut receipt_error = None;

    let report = stage
        .run_until_drained_with(|receipt| {
            if receipt_error.is_none() {
                if let Err(error) = aggregator.record_receipt(receipt.clone()) {
                    receipt_error = Some(error);
                }
            }
        })
        .map_err(AnyError::new)?;

    if let Some(error) = receipt_error {
        return Err(AnyError::new(error));
    }

    Ok(CommitStageDrainResult { aggregator, report })
}

fn wait_for_submitted_commits<F, D>(mut submitted: Vec<SubmittedCommit<F, D>>) -> Result<()>
where
    F: FindingsSink,
    D: DoneLedger,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    submitted.sort_by_key(|entry| entry.sequence_no);

    for entry in submitted {
        entry.completion.wait().map_err(|error| {
            anyhow!(
                "durable commit failed for sequence {}: {error}",
                entry.sequence_no
            )
        })?;
    }

    Ok(())
}

fn checkpoint_logical_time(last_sequence_no: u64) -> LogicalTime {
    LogicalTime::from_raw(last_sequence_no.saturating_add(1))
}

fn run_filesystem_lease<F, D>(
    coordinator: &dyn DistributedCoordinator,
    recorder: Arc<dyn CoordinationEventRecorder>,
    persistence: &DistributedPersistence<F, D>,
    lease: &ShardLease,
    config: DistributedRuntimeConfig,
) -> Result<(), DistributedRuntimeError>
where
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let sink = CoordinationEventSink::new(Arc::clone(&recorder), Arc::clone(&lease.shard_id));
    let committer = ResultCommitter::new(
        persistence.findings_sink.clone(),
        persistence.done_ledger.clone(),
    );
    let (submitter, stage) = bounded_commit_pipeline(config.commit_queue_capacity, committer)
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;
    let commit = ReceiptCommitSink::new(
        Arc::clone(&recorder),
        Arc::clone(&lease.shard_id),
        lease.write_context,
        lease.tenant_secret_key,
        submitter,
    );
    let cancel = CancellationToken::new();

    // Build execution config with commit-sink persistence enabled so every
    // successfully scanned item yields one queued durable commit work item.
    //
    // Transitional safety rule for the scan-driver compatibility seam: force
    // a single execution worker so `begin_item` ordering stays deterministic
    // while receipt sequence numbers are still derived at the callback layer.
    let mut runtime = config.budgets.to_execution_config_with_workers(1)?;
    runtime.filesystem.emit_findings_to_commit_sink = true;

    let engine_config = RuntimeEngineConfig::default();
    let (outcome, submitted, stage_result) = std::thread::scope(|scope| {
        let write_context = lease.write_context;
        let stage_handle = scope.spawn(move || drain_commit_stage(stage, write_context));

        let outcome = execute_assignment_with_config(
            &lease.assignment,
            runtime,
            &engine_config,
            &GitExecutionConfig::default(),
            &sink,
            &commit,
            &cancel,
        );
        let submitted = commit.finish();

        let stage_result = stage_handle.join().map_err(|_| {
            DistributedRuntimeError::Durability(anyhow!(
                "receipt commit stage thread panicked for shard '{}'",
                lease.shard_id
            ))
        })?;
        let stage_result = stage_result.map_err(DistributedRuntimeError::Durability)?;

        Ok::<_, DistributedRuntimeError>((outcome, submitted, stage_result))
    })?;

    let outcome = outcome.map_err(DistributedRuntimeError::Runtime)?;
    let submitted = submitted.map_err(DistributedRuntimeError::Durability)?;

    wait_for_submitted_commits(submitted).map_err(DistributedRuntimeError::Durability)?;

    let submitted_units = stage_result.report.processed;
    if submitted_units == 0 && outcome.report.items_scanned > 0 {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' scanned {} item(s) but produced no durable commit receipts",
            lease.shard_id,
            outcome.report.items_scanned
        )));
    }

    if submitted_units != outcome.report.items_scanned {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' reported {} scanned item(s) but durable commit stage processed {} unit(s)",
            lease.shard_id,
            outcome.report.items_scanned,
            submitted_units
        )));
    }

    let mut aggregator = stage_result.aggregator;
    let pending = aggregator
        .prepare_checkpoint()
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    if submitted_units == 0 {
        coordinator
            .complete_shard(lease, None, outcome.report)
            .map_err(DistributedRuntimeError::Coordinator)?;
        coordinator
            .mark_shard_done(lease)
            .map_err(DistributedRuntimeError::Coordinator)?;
        return Ok(());
    }

    let pending = pending.ok_or_else(|| {
        DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' committed {} unit(s) but no receipt-driven checkpoint prefix was prepared",
            lease.shard_id,
            submitted_units
        ))
    })?;

    if pending.committed_units() != submitted_units {
        return Err(DistributedRuntimeError::Durability(anyhow!(
            "filesystem shard '{}' prepared checkpoint for {} unit(s), expected {}",
            lease.shard_id,
            pending.committed_units(),
            submitted_units
        )));
    }

    coordinator
        .complete_shard(lease, Some(pending.checkpoint_cursor().clone()), outcome.report)
        .map_err(DistributedRuntimeError::Coordinator)?;

    let checkpoint_receipt = CheckpointCommitReceipt::new(
        pending.scope().clone(),
        checkpoint_logical_time(pending.last_sequence_no()),
    );
    aggregator
        .acknowledge_checkpoint(checkpoint_receipt)
        .map_err(|error| DistributedRuntimeError::Durability(AnyError::new(error)))?;

    coordinator
        .mark_shard_done(lease)
        .map_err(DistributedRuntimeError::Coordinator)?;

    Ok(())
}

/// Run the distributed worker loop until no more shards are available.
///
/// For each lease the runtime:
/// 1. checks the done ledger and releases already-complete shards without scanning,
/// 2. executes the assignment with coordinator-backed event telemetry and a
///    receipt-producing bounded commit pipeline,
/// 3. derives checkpoint progress only from durable receipts, and
/// 4. records completion before marking the shard done.
///
/// The `complete_shard` → `mark_shard_done` ordering is intentional: if the
/// process crashes between those calls, the shard may be retried, but the system
/// never observes a done-ledger entry without the corresponding report and
/// checkpoint metadata.
pub fn run_worker<F, D>(
    coordinator: &dyn DistributedCoordinator,
    persistence: DistributedPersistence<F, D>,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError>
where
    F: FindingsSink + Clone + Send + Sync + 'static,
    D: DoneLedger + Clone + Send + Sync + 'static,
    F::Error: std::error::Error + Send + Sync + 'static,
    D::Error: std::error::Error + Send + Sync + 'static,
{
    let recorder = coordinator.event_recorder();
    let mut report = DistributedRunReport::default();

    loop {
        let Some(lease) = coordinator
            .acquire_shard()
            .map_err(DistributedRuntimeError::Coordinator)?
        else {
            break;
        };
        report.leases_seen = report.leases_seen.saturating_add(1);

        if coordinator
            .is_shard_done(&lease.shard_id)
            .map_err(DistributedRuntimeError::Coordinator)?
        {
            coordinator
                .release_shard(&lease)
                .map_err(DistributedRuntimeError::Coordinator)?;
            report.shards_skipped_done = report.shards_skipped_done.saturating_add(1);
            continue;
        }

        match lease.assignment.connector_kind {
            ConnectorKind::Filesystem => {
                run_filesystem_lease(
                    coordinator,
                    Arc::clone(&recorder),
                    &persistence,
                    &lease,
                    config,
                )?;
            }
            other => {
                return Err(DistributedRuntimeError::Durability(anyhow!(
                    "distributed receipt-driven runtime is not yet wired for {:?} assignments; refusing to advance shard '{}' without receipts",
                    other,
                    lease.shard_id
                )));
            }
        }

        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    Ok(report)
}

/// In-memory distributed coordinator for tests and local harnesses.
///
/// All state is held behind a single `Mutex` and is `Clone`-safe via `Arc`.
/// This coordinator is intentionally **not** idempotent for `complete_shard`:
/// duplicate calls produce duplicate entries, which is useful for testing
/// crash-recovery semantics (see the `complete_shard_duplicate_call` test).
#[derive(Clone, Default)]
pub struct InMemoryCoordinator {
    state: Arc<Mutex<InMemoryCoordinatorState>>,
}

#[derive(Default)]
struct InMemoryCoordinatorState {
    queue: VecDeque<ShardLease>,
    done: HashSet<String>,
    done_mark_contexts: Vec<WriteContext>,
    released: Vec<String>,
    completed: Vec<CompletedShard>,
    core_events: Vec<(String, StoredCoreEvent)>,
    git_events: Vec<(String, StoredGitEvent)>,
    commit_progress: Vec<(String, CommitProgressRecord)>,
    identity_records: Vec<(String, IdentityChainRecord)>,
}

#[derive(Clone, Debug)]
struct CompletedShard {
    shard_id: String,
    checkpoint: Option<Cursor>,
    report: ScanReport,
}

impl InMemoryCoordinator {
    /// Creates a coordinator pre-loaded with the given lease queue.
    #[must_use]
    pub fn new(leases: Vec<ShardLease>) -> Self {
        let mut queue = VecDeque::new();
        queue.extend(leases);
        Self {
            state: Arc::new(Mutex::new(InMemoryCoordinatorState {
                queue,
                ..InMemoryCoordinatorState::default()
            })),
        }
    }

    /// Marks `shard_id` as done in the done-ledger so it will be skipped during scanning.
    pub fn mark_done(&self, shard_id: impl Into<String>) {
        self.state
            .lock()
            .expect("state lock")
            .done
            .insert(shard_id.into());
    }

    /// Returns a snapshot of all shard IDs currently in the done-ledger.
    #[must_use]
    pub fn done_set(&self) -> HashSet<String> {
        self.state.lock().expect("state lock").done.clone()
    }

    /// Returns the write contexts used when marking shards done.
    #[must_use]
    pub fn done_mark_contexts(&self) -> Vec<WriteContext> {
        self.state
            .lock()
            .expect("state lock")
            .done_mark_contexts
            .clone()
    }

    /// Returns the shard IDs that were released without being completed.
    #[must_use]
    pub fn released_shards(&self) -> Vec<String> {
        self.state.lock().expect("state lock").released.clone()
    }

    /// Returns all completed shards as `(shard_id, checkpoint, report)` tuples.
    #[must_use]
    pub fn completed_shards(&self) -> Vec<(String, Option<Cursor>, ScanReport)> {
        self.state
            .lock()
            .expect("state lock")
            .completed
            .iter()
            .map(|entry| {
                (
                    entry.shard_id.clone(),
                    entry.checkpoint.clone(),
                    entry.report.clone(),
                )
            })
            .collect()
    }

    /// Returns all recorded core events as `(shard_id, event)` pairs.
    #[must_use]
    pub fn core_events(&self) -> Vec<(String, StoredCoreEvent)> {
        self.state.lock().expect("state lock").core_events.clone()
    }

    /// Returns all recorded identity chain records as `(shard_id, record)` pairs.
    #[must_use]
    pub fn identity_records(&self) -> Vec<(String, IdentityChainRecord)> {
        self.state
            .lock()
            .expect("state lock")
            .identity_records
            .clone()
    }
}

impl DistributedCoordinator for InMemoryCoordinator {
    fn acquire_shard(&self) -> Result<Option<ShardLease>> {
        Ok(self.state.lock().expect("state lock").queue.pop_front())
    }

    fn release_shard(&self, lease: &ShardLease) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .released
            .push(lease.shard_id.to_string());
        Ok(())
    }

    fn complete_shard(&self, lease: &ShardLease, checkpoint: Option<Cursor>, report: ScanReport) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .completed
            .push(CompletedShard {
                shard_id: lease.shard_id.to_string(),
                checkpoint,
                report,
            });
        Ok(())
    }

    fn is_shard_done(&self, shard_id: &str) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .expect("state lock")
            .done
            .contains(shard_id))
    }

    fn mark_shard_done(&self, lease: &ShardLease) -> Result<()> {
        let mut guard = self.state.lock().expect("state lock");
        guard.done.insert(lease.shard_id.to_string());
        guard.done_mark_contexts.push(lease.write_context);
        Ok(())
    }

    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder> {
        Arc::new(self.clone())
    }
}

impl CoordinationEventRecorder for InMemoryCoordinator {
    fn record_core_event(&self, shard_id: &str, event: StoredCoreEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .core_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .git_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .commit_progress
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_identity_chain(&self, shard_id: &str, record: IdentityChainRecord) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .identity_records
            .push((shard_id.to_owned(), record));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use gossip_contracts::{
        coordination::ShardSpec,
        identity::{PolicyHash, TenantId},
        persistence::{DoneLedgerStatus, WriteContext},
    };
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use gossip_scan_driver::AssignmentSource;
    use tempfile::tempdir;

    use super::*;

    fn fs_lease(shard_id: &str, path: &std::path::Path) -> ShardLease {
        let policy_hash = PolicyHash::from_bytes([0x55; 32]);
        ShardLease::new(
            Arc::from(shard_id),
            Assignment {
                job_id: format!("job-{shard_id}"),
                connector_kind: ConnectorKind::Filesystem,
                connector_instance_id: path.display().to_string(),
                policy_hash,
                shard_spec: ShardSpec::with_range([], []),
                cursor: Cursor::initial(),
                source: AssignmentSource::Filesystem {
                    root: path.to_path_buf(),
                },
            },
            WriteContext::new(
                TenantId::from_bytes([0xAA; 32]),
                policy_hash,
                RunId::from_raw(100),
                ShardId::from_raw(200),
                FenceEpoch::from_raw(300),
            ),
            TenantSecretKey::from_bytes([0xBB; 32]),
        )
    }

    fn git_lease(shard_id: &str, repo_root: &std::path::Path) -> ShardLease {
        let policy_hash = PolicyHash::from_bytes([0x55; 32]);
        ShardLease::new(
            Arc::from(shard_id),
            Assignment {
                job_id: format!("job-{shard_id}"),
                connector_kind: ConnectorKind::Git,
                connector_instance_id: repo_root.display().to_string(),
                policy_hash,
                shard_spec: ShardSpec::with_range([], []),
                cursor: Cursor::initial(),
                source: AssignmentSource::Git {
                    repo_root: repo_root.to_path_buf(),
                },
            },
            WriteContext::new(
                TenantId::from_bytes([0xAA; 32]),
                policy_hash,
                RunId::from_raw(101),
                ShardId::from_raw(201),
                FenceEpoch::from_raw(301),
            ),
            TenantSecretKey::from_bytes([0xBB; 32]),
        )
    }

    fn test_persistence() -> DistributedPersistence<InMemoryFindingsSink, InMemoryDoneLedger> {
        DistributedPersistence::new(InMemoryFindingsSink::default(), InMemoryDoneLedger::default())
    }

    /// Initialise a git repo at `dir` with one committed secret file.
    fn init_git_repo_with_secret(dir: &std::path::Path) {
        use std::process::Command;
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("git command");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "--initial-branch=main"]);
        run(&["config", "user.email", "test@test.com"]);
        run(&["config", "user.name", "Test"]);
        fs::write(dir.join("secret.txt"), "password=alpha-beta-gamma-delta")
            .expect("write fixture");
        run(&["add", "."]);
        run(&["commit", "-m", "initial"]);
    }

    #[test]
    fn run_worker_skips_done_shards_before_scan() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=already-done").expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![fs_lease("shard-1", dir.path())]);
        coordinator.mark_done("shard-1");

        let report = run_worker(
            &coordinator,
            test_persistence(),
            DistributedRuntimeConfig::default(),
        )
        .expect("run worker");
        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.shards_skipped_done, 1);
        assert_eq!(coordinator.released_shards(), vec!["shard-1".to_owned()]);
    }

    #[test]
    fn run_worker_persists_findings_done_ledger_checkpoint_and_marks_done() {
        let dir = tempdir().expect("tempdir");
        // Secret must be ≥16 high-entropy chars to trigger builtin rules.
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![fs_lease("shard-2", dir.path())]);
        let findings_sink = InMemoryFindingsSink::default();
        let done_ledger = InMemoryDoneLedger::default();

        let report = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
            DistributedRuntimeConfig::default(),
        )
        .expect("run worker");
        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.shards_skipped_done, 0);

        let done = coordinator.done_set();
        assert!(done.contains("shard-2"));

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].2.items_scanned >= 1);
        assert!(completed[0].1.is_some(), "checkpoint should come from durable receipts");
        assert!(
            completed[0].1.as_ref().and_then(|cursor| cursor.last_key()).is_some(),
            "receipt-driven checkpoint should retain a progress key"
        );
        assert!(
            completed[0].1.as_ref().and_then(|cursor| cursor.token()).is_none(),
            "receipt-driven checkpoint should be tokenless"
        );

        let done_mark_contexts = coordinator.done_mark_contexts();
        assert_eq!(done_mark_contexts.len(), 1);
        assert_eq!(done_mark_contexts[0].policy_hash(), PolicyHash::from_bytes([0x55; 32]));
        assert_eq!(done_mark_contexts[0].run_id(), RunId::from_raw(100));
        assert_eq!(done_mark_contexts[0].shard_id(), ShardId::from_raw(200));
        assert_eq!(done_mark_contexts[0].fence_epoch(), FenceEpoch::from_raw(300));

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(!observations.is_empty(), "findings sink should have durable observations");
        assert!(
            observations
                .iter()
                .all(|observation| observation.write_context() == done_mark_contexts[0]),
            "all observations should carry the same shared write context as shard completion"
        );

        let rows = done_ledger.snapshot().expect("done-ledger snapshot");
        assert_eq!(rows.len(), 1, "one scanned file should produce one done-ledger row");
        assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
        assert_eq!(rows[0].write_context(), done_mark_contexts[0]);
    }

    #[test]
    fn commit_failure_prevents_checkpoint_and_done_mark() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![fs_lease("shard-fail", dir.path())]);
        let findings_sink = InMemoryFindingsSink::default();
        let done_ledger = InMemoryDoneLedger::default();
        done_ledger
            .fail_next_commits(1)
            .expect("inject done-ledger commit failure");

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("done-ledger durability failure should abort the worker");
        assert!(
            error.to_string().contains("durable commit failed")
                || error.to_string().contains("done-ledger durability failed"),
            "unexpected error: {error}"
        );

        assert!(
            coordinator.completed_shards().is_empty(),
            "no checkpoint should be recorded without a durable receipt"
        );
        assert!(
            !coordinator.done_set().contains("shard-fail"),
            "shard must not be marked done when the commit stage fails"
        );

        let observations = findings_sink
            .observations_snapshot()
            .expect("observations snapshot");
        assert!(
            !observations.is_empty(),
            "findings may be durable before the done-ledger failure"
        );
        assert!(
            done_ledger.snapshot().expect("done-ledger snapshot").is_empty(),
            "done-ledger failure must prevent done rows from becoming durable"
        );
    }

    /// Verifies that calling `complete_shard` twice for the same lease produces
    /// duplicate entries in the `InMemoryCoordinator`. This confirms the trait
    /// implementation is NOT idempotent — a property that matters for crash+retry
    /// coordinators where a shard may be re-leased after a failure between
    /// `complete_shard` and `mark_shard_done`.
    #[test]
    fn complete_shard_duplicate_call_produces_duplicate_entry() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("dummy.txt"), "nothing-secret").expect("write fixture");

        let lease = fs_lease("idempotency-check", dir.path());
        let coordinator = InMemoryCoordinator::new(vec![]);
        let report = ScanReport::default();

        // First call.
        coordinator
            .complete_shard(&lease, None, report.clone())
            .expect("first complete_shard");
        assert_eq!(
            coordinator.completed_shards().len(),
            1,
            "single call should produce one entry"
        );

        // Second (duplicate) call for the same shard.
        coordinator
            .complete_shard(&lease, None, report)
            .expect("second complete_shard");

        // If complete_shard were idempotent, len would still be 1.
        let completed = coordinator.completed_shards();
        assert_eq!(
            completed.len(),
            2,
            "InMemoryCoordinator::complete_shard is not idempotent — \
             duplicate call produces a second entry"
        );
        assert_eq!(completed[0].0, "idempotency-check");
        assert_eq!(completed[1].0, "idempotency-check");
    }

    #[test]
    fn git_shard_without_receipt_path_is_rejected() {
        let dir = tempdir().expect("tempdir");
        init_git_repo_with_secret(dir.path());

        let coordinator = InMemoryCoordinator::new(vec![git_lease("git-1", dir.path())]);
        let findings_sink = InMemoryFindingsSink::default();
        let done_ledger = InMemoryDoneLedger::default();

        let error = run_worker(
            &coordinator,
            DistributedPersistence::new(findings_sink, done_ledger),
            DistributedRuntimeConfig::default(),
        )
        .expect_err("git shards must not advance without receipt-driven durability");

        assert!(
            error.to_string().contains("not yet wired")
                || error.to_string().contains("without receipts"),
            "unexpected error: {error}"
        );
        assert!(coordinator.completed_shards().is_empty());
        assert!(!coordinator.done_set().contains("git-1"));
    }
}
