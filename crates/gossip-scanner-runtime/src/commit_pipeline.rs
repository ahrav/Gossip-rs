//! Bounded execution -> commit pipeline for the receipt-driven durability model.
//!
//! The runtime needs one structural choke point between scan execution and
//! durable commit:
//!
//! 1. execution translates scan results into owned persistence rows;
//! 2. execution enqueues that owned work on a bounded channel;
//! 3. the commit stage is the only place that performs findings -> done-ledger;
//! 4. the commit stage emits receipt-ready output for checkpoint aggregation.
//!
//! This module implements that producer/consumer boundary as a single commit
//! worker backed by `std::sync::mpsc::sync_channel`.
//!
//! # Why a blocking bounded queue?
//!
//! Slow sinks must pause scanning instead of letting memory usage drift upward.
//! A bounded `sync_channel` gives the runtime exactly that behavior:
//!
//! - if the commit worker is blocked in [`ResultCommitter`] waiting for durable
//!   findings or done-ledger writes, it stops draining the execution queue;
//! - once the queue reaches capacity, `submit(...)` blocks; and
//! - execution pressure therefore propagates backwards instead of creating an
//!   unbounded buffer of half-finished work.
//!
//! # Stage ownership
//!
//! Enqueueing work is not an authoritative finish signal. The only
//! authoritative success output from this stage is a durable receipt wrapped as
//! [`CheckpointAggregatorInput`].
//! That keeps the runtime aligned with the durability rule that checkpoint
//! progress is driven only by receipts, never by raw scan completion.
//!
//! # Cancellation
//!
//! [`CancellationToken`] lets lease-loss or shutdown stop the pipeline quickly
//! without abandoning an in-flight commit:
//!
//! - [`CommitPipelineSender::submit`] checks cancellation before attempting a
//!   blocking send so new work is rejected promptly when the lease is gone;
//! - the worker polls the cancellation token before receive and again after
//!   dequeue, so it exits even when cloned senders keep the submission
//!   channel connected;
//! - if a newly dequeued item is abandoned before durable commit, the worker
//!   attempts to emit a [`CommitStageOutput::Failed`] with
//!   [`ResultCommitError::Cancelled`]; delivery is best-effort because the
//!   outcome queue may be full or disconnected at cancellation time;
//! - the worker still finishes the current in-flight item and attempts to
//!   emit its outcome. If the outcome receiver has already been dropped,
//!   for example during shutdown, the last outcome is silently discarded —
//!   the committed data is durable in storage and checkpoint advancement
//!   resumes from the last durable checkpoint on restart;
//! - once cancellation is observed, the worker exits before committing any
//!   newly dequeued item, so at most the current in-flight commit can finish
//!   after cancellation.
//!
//! Already-blocked producers may still observe a disconnected channel rather
//! than a cancellation error. That delay is bounded by the time needed for the
//! worker to finish the current commit and exit.
//!
//! # Capacity semantics
//!
//! Both channels are bounded. A capacity of `0` is allowed and means rendezvous
//! semantics: the sender and receiver must meet for every item.

use std::sync::mpsc::{
    Receiver, RecvError, RecvTimeoutError, SendError, SyncSender, TryRecvError, sync_channel,
};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use gossip_contracts::persistence::{DoneLedger, FindingsSink, WriteContext};

use crate::{
    CancellationToken,
    commit_model::{CheckpointAggregatorInput, CompletedUnit},
    result_committer::{ResultCommitError, ResultCommitter},
    result_translation::PersistenceTranslation,
};

/// Queue sizing for the bounded execution -> commit pipeline.
///
/// Both capacities are passed directly to [`sync_channel`]. `0` is valid and
/// gives rendezvous behavior rather than buffered queueing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitPipelineConfig {
    /// Maximum number of translated work items buffered between execution and
    /// the commit stage.
    pub execution_queue_capacity: usize,
    /// Maximum number of commit-stage outcomes buffered between the commit
    /// worker and the downstream checkpoint or error-handling stage.
    pub outcome_queue_capacity: usize,
}

impl Default for CommitPipelineConfig {
    fn default() -> Self {
        Self {
            execution_queue_capacity: 64,
            outcome_queue_capacity: 64,
        }
    }
}

/// Owned work item submitted from execution into the commit stage.
///
/// The work item owns the translated persistence rows so it can cross the
/// thread boundary cleanly. The commit worker passes the owned translation
/// by reference while calling [`ResultCommitter::commit_translation`].
#[must_use = "queued commit work must be submitted or explicitly discarded"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedCommit {
    write_context: WriteContext,
    completed_unit: CompletedUnit,
    translation: PersistenceTranslation,
}

impl QueuedCommit {
    /// Construct one owned work item for the commit stage.
    pub fn new(
        write_context: WriteContext,
        completed_unit: CompletedUnit,
        translation: PersistenceTranslation,
    ) -> Self {
        Self {
            write_context,
            completed_unit,
            translation,
        }
    }

    /// Consume the work item into its raw parts.
    #[inline]
    pub fn into_parts(self) -> (WriteContext, CompletedUnit, PersistenceTranslation) {
        (self.write_context, self.completed_unit, self.translation)
    }
}

/// Outcome emitted by the commit stage.
///
/// Success is represented as a receipt-ready checkpoint input paired with the
/// original [`WriteContext`]. Failure keeps the completed unit attached so the
/// runtime can reason about which unit stalled or needs follow-up handling.
#[derive(Debug)]
pub enum CommitStageOutput<FindingsError, DoneLedgerError> {
    /// One queued work item became durably committed and is now eligible for
    /// receipt-driven checkpoint aggregation.
    Committed {
        /// Shared routing and fencing metadata for the successful commit.
        write_context: WriteContext,
        /// Receipt-only checkpoint-stage input produced by the durable commit.
        checkpoint_input: CheckpointAggregatorInput,
    },
    /// One queued work item failed during durable commit or hit a
    /// post-commit invariant violation while preparing checkpoint input.
    ///
    /// The original [`PersistenceTranslation`] is not carried here because
    /// translations are deterministically re-derivable from the scan output.
    /// Keeping the translation out of the error path avoids retaining
    /// heap-allocated persistence rows longer than necessary.
    Failed {
        /// Shared routing and fencing metadata for the failed commit-stage
        /// outcome.
        write_context: WriteContext,
        /// Completed unit whose commit path could not produce usable
        /// checkpoint-stage output.
        completed_unit: CompletedUnit,
        /// Stage-local commit error.
        error: ResultCommitError<FindingsError, DoneLedgerError>,
    },
}

impl<FindingsError, DoneLedgerError> CommitStageOutput<FindingsError, DoneLedgerError> {
    /// Returns the write context for either success or failure.
    #[inline]
    #[must_use]
    pub fn write_context(&self) -> WriteContext {
        match self {
            Self::Committed { write_context, .. } | Self::Failed { write_context, .. } => {
                *write_context
            }
        }
    }
}

/// Errors from attempting to submit work to the commit pipeline.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SubmitError {
    /// The pipeline has been cancelled before the work entered the queue.
    #[error("commit pipeline cancelled")]
    Cancelled(Box<QueuedCommit>),
    /// The commit worker has exited, so the queue is disconnected.
    #[error("commit pipeline worker disconnected")]
    Disconnected(Box<QueuedCommit>),
}

impl SubmitError {
    /// Recover the work item that failed to enter the queue.
    #[inline]
    #[must_use = "call site should resubmit or explicitly drop the recovered work"]
    pub fn into_work(self) -> QueuedCommit {
        match self {
            Self::Cancelled(work) | Self::Disconnected(work) => *work,
        }
    }

    /// Returns `true` when the submission was rejected due to cancellation
    /// rather than a disconnected worker.
    #[inline]
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        matches!(self, Self::Cancelled(_))
    }
}

/// Cloneable execution-side handle for submitting work into the bounded commit
/// queue.
#[derive(Clone, Debug)]
pub struct CommitPipelineSender {
    inner: SyncSender<QueuedCommit>,
    cancel: CancellationToken,
}

impl CommitPipelineSender {
    /// Submit one owned work item into the bounded execution queue.
    ///
    /// This call blocks when the queue is full, which is the intended
    /// backpressure mechanism for slow sinks. If cancellation has already been
    /// requested, the work item is returned immediately instead of blocking.
    ///
    /// The cancellation check and the channel send are not atomic: a concurrent
    /// cancellation between the two steps may allow one more item into the
    /// queue. The worker re-checks cancellation after dequeue and emits a
    /// [`CommitStageOutput::Failed`] with [`ResultCommitError::Cancelled`]
    /// for any item abandoned before durable commit. Callers that need an
    /// authoritative completion signal must wait for [`CommitStageOutput`]
    /// instead of treating `Ok(())` as proof of commit.
    ///
    /// # Errors
    ///
    /// - [`SubmitError::Cancelled`] — cancellation was already requested.
    /// - [`SubmitError::Disconnected`] — the commit worker has exited.
    #[inline]
    pub fn submit(&self, work: QueuedCommit) -> Result<(), SubmitError> {
        if self.cancel.is_cancelled() {
            return Err(SubmitError::Cancelled(Box::new(work)));
        }

        self.inner.send(work).map_err(|SendError(work)| {
            if self.cancel.is_cancelled() {
                SubmitError::Cancelled(Box::new(work))
            } else {
                SubmitError::Disconnected(Box::new(work))
            }
        })
    }
}

/// Bounded execution -> commit pipeline with one dedicated commit worker.
///
/// The worker owns a [`ResultCommitter`] and is therefore the only place where
/// runtime work becomes authoritatively durable. Execution threads only enqueue
/// [`QueuedCommit`] values; they do not write sinks directly.
///
/// # Shutdown vs implicit drop
///
/// [`shutdown`](Self::shutdown) cancels, closes both channels, and **joins**
/// the worker thread — the caller blocks until the in-flight commit finishes.
///
/// Dropping without calling `shutdown` cancels the token and the field
/// destructors close the pipeline's own channel endpoints. If cloned
/// [`CommitPipelineSender`] handles still exist, the submission channel
/// remains connected; the worker exits via cancellation polling rather than
/// channel closure. The `JoinHandle` is dropped, **detaching** the thread.
/// The worker still exits promptly, but the caller does not wait for it.
pub struct CommitPipeline<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    sender: Option<CommitPipelineSender>,
    outcomes: Option<Receiver<CommitStageOutput<F::Error, D::Error>>>,
    worker: Option<JoinHandle<()>>,
}

/// Outcome-drain handle returned by [`CommitPipeline::split`].
///
/// This handle owns the outcome receiver and worker join handle but not the
/// submission sender. Distributed runtimes use it to drain durable receipts
/// concurrently while scan execution continues on another thread.
pub struct CommitPipelineDrainer<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    outcomes: Receiver<CommitStageOutput<F::Error, D::Error>>,
    worker: Option<JoinHandle<()>>,
    cancel: CancellationToken,
}

impl<F, D> CommitPipeline<F, D>
where
    F: FindingsSink + Send + 'static,
    D: DoneLedger + Send + 'static,
{
    /// Start one bounded commit pipeline backed by a dedicated worker thread.
    ///
    /// # Errors
    ///
    /// Returns [`std::io::Error`] if the OS refuses to spawn the worker thread.
    #[must_use = "the pipeline must be shut down to join the worker thread"]
    pub fn start(
        findings_sink: F,
        done_ledger: D,
        config: CommitPipelineConfig,
        cancel: CancellationToken,
    ) -> std::io::Result<Self> {
        let (submit_tx, submit_rx) = sync_channel(config.execution_queue_capacity);
        let (outcome_tx, outcome_rx) = sync_channel(config.outcome_queue_capacity);
        let worker_cancel = cancel.clone();

        let worker = thread::Builder::new()
            .name("runtime-commit-stage".to_owned())
            .spawn(move || {
                run_commit_stage(
                    ResultCommitter::new(findings_sink, done_ledger),
                    submit_rx,
                    outcome_tx,
                    worker_cancel,
                );
            })?;

        Ok(Self {
            sender: Some(CommitPipelineSender {
                inner: submit_tx,
                cancel,
            }),
            outcomes: Some(outcome_rx),
            worker: Some(worker),
        })
    }

    /// Clone the execution-side submission handle.
    #[inline]
    #[must_use]
    pub fn sender(&self) -> CommitPipelineSender {
        self.sender
            .as_ref()
            .expect("commit pipeline sender must exist until split or shutdown")
            .clone()
    }

    /// Split the pipeline into an execution-side sender and an outcome drainer.
    ///
    /// Dropping the returned sender closes the submission channel once all of
    /// its clones are gone, allowing the commit worker to exit naturally after
    /// draining queued work. The returned drainer can receive outcomes and join
    /// the worker thread without retaining an extra submission handle.
    #[must_use = "both the sender and drainer must be used or explicitly dropped"]
    pub fn split(mut self) -> (CommitPipelineSender, CommitPipelineDrainer<F, D>) {
        let sender = self
            .sender
            .take()
            .expect("commit pipeline sender must exist before split");
        let outcomes = self
            .outcomes
            .take()
            .expect("commit pipeline outcomes must exist before split");
        let drainer = CommitPipelineDrainer {
            outcomes,
            worker: self.worker.take(),
            cancel: sender.cancel.clone(),
        };
        (sender, drainer)
    }

    /// Receive the next commit-stage outcome, blocking until one arrives or the
    /// worker exits.
    ///
    /// # Errors
    ///
    /// Returns [`RecvError`] when the worker has exited and all buffered
    /// outcomes have been consumed.
    #[inline]
    pub fn recv(&self) -> Result<CommitStageOutput<F::Error, D::Error>, RecvError> {
        self.outcomes
            .as_ref()
            .expect("commit pipeline outcomes must exist until split or shutdown")
            .recv()
    }

    /// Receive the next commit-stage outcome, blocking for at most `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`RecvTimeoutError::Timeout`] if no outcome arrives within
    /// `timeout`, or [`RecvTimeoutError::Disconnected`] if the worker has
    /// exited and all buffered outcomes have been consumed.
    #[inline]
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<CommitStageOutput<F::Error, D::Error>, RecvTimeoutError> {
        self.outcomes
            .as_ref()
            .expect("commit pipeline outcomes must exist until split or shutdown")
            .recv_timeout(timeout)
    }

    /// Try to receive one commit-stage outcome without blocking.
    ///
    /// # Errors
    ///
    /// Returns [`TryRecvError::Empty`] when no outcome is ready yet, or
    /// [`TryRecvError::Disconnected`] when the worker has exited and all
    /// buffered outcomes have been consumed.
    #[inline]
    pub fn try_recv(&self) -> Result<CommitStageOutput<F::Error, D::Error>, TryRecvError> {
        self.outcomes
            .as_ref()
            .expect("commit pipeline outcomes must exist until split or shutdown")
            .try_recv()
    }

    /// Shut the pipeline down and join the worker thread.
    ///
    /// The cancellation token causes the worker to exit after finishing any
    /// in-flight commit, even when cloned [`CommitPipelineSender`] handles
    /// remain alive. The worker polls the token periodically between receives,
    /// so shutdown completes without requiring all senders to be dropped first.
    ///
    /// Callers *should* still drop all cloned senders before calling `shutdown`
    /// to avoid buffered items being silently abandoned in the queue (the
    /// pipeline's own sender is dropped as part of shutdown).
    ///
    /// There is no timeout on the join. If the worker is blocked inside a
    /// slow persistence operation, this call blocks until that operation
    /// completes. The worker always finishes the current in-flight commit
    /// before exiting.
    pub fn shutdown(mut self) -> thread::Result<()> {
        if let Some(sender) = self.sender.as_ref() {
            sender.cancel.cancel();
        }
        let handle = self.worker.take();
        // Dropping `self` closes both channels, which unblocks the worker
        // if it is waiting on `recv_timeout()` or `send()`. `Drop::drop`
        // re-cancels the token (harmless) but finds `worker == None` — no-op.
        drop(self);
        match handle {
            Some(h) => h.join(),
            None => Ok(()),
        }
    }
}

impl<F, D> Drop for CommitPipeline<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    fn drop(&mut self) {
        if let Some(sender) = self.sender.as_ref() {
            sender.cancel.cancel();
        }
        if self.worker.is_some() {
            tracing::warn!("CommitPipeline dropped without shutdown; worker thread detached");
        }
        // After this method returns, fields are dropped in declaration order:
        // sender -> outcomes -> worker. Channel drops unblock the worker if
        // it is waiting on a timed receive; the JoinHandle drop detaches the
        // thread. The worker also polls cancellation between receives, so it
        // exits promptly even if cloned senders keep the channel connected.
    }
}

impl<F, D> CommitPipelineDrainer<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    /// Request cancellation of the underlying commit worker.
    #[inline]
    pub fn cancel(&self) {
        self.cancel.cancel();
    }

    /// Receive the next commit-stage outcome, blocking until one arrives or the
    /// worker exits.
    #[inline]
    pub fn recv(&self) -> Result<CommitStageOutput<F::Error, D::Error>, RecvError> {
        self.outcomes.recv()
    }

    /// Receive the next commit-stage outcome, blocking for at most `timeout`.
    #[inline]
    pub fn recv_timeout(
        &self,
        timeout: Duration,
    ) -> Result<CommitStageOutput<F::Error, D::Error>, RecvTimeoutError> {
        self.outcomes.recv_timeout(timeout)
    }

    /// Join the commit worker after outcome draining has finished.
    pub fn join(mut self) -> thread::Result<()> {
        match self.worker.take() {
            Some(handle) => handle.join(),
            None => Ok(()),
        }
    }
}

impl<F, D> Drop for CommitPipelineDrainer<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    fn drop(&mut self) {
        self.cancel.cancel();
        if self.worker.is_some() {
            tracing::warn!(
                "CommitPipelineDrainer dropped without join; commit worker thread detached"
            );
        }
    }
}

/// How often the worker wakes from a blocking receive to check the
/// cancellation token. Short enough that `shutdown()` completes promptly;
/// long enough to avoid busy-spinning when the queue is idle.
const CANCEL_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Worker loop that dequeues [`QueuedCommit`] items and commits each through
/// the [`ResultCommitter`], emitting one [`CommitStageOutput`] per item.
///
/// The loop exits on cancellation or channel closure. Between receives, it
/// wakes every [`CANCEL_POLL_INTERVAL`] to check the cancellation token,
/// bounding shutdown latency even when the submission channel is idle.
///
/// Invariant: every successfully dequeued item produces exactly one outcome
/// on `outcome_tx` — either `Committed` or `Failed` — in the non-cancelled
/// path (blocking `send`). During cancellation, the worker uses `try_send`
/// for any in-flight or post-dequeue outcomes; if the outcome queue is full
/// or disconnected, the outcome is silently dropped. Committed data remains
/// durable in storage and checkpoint advancement resumes from the last
/// durable checkpoint on restart.
fn run_commit_stage<F, D>(
    committer: ResultCommitter<F, D>,
    submit_rx: Receiver<QueuedCommit>,
    outcome_tx: SyncSender<CommitStageOutput<F::Error, D::Error>>,
    cancel: CancellationToken,
) where
    F: FindingsSink,
    D: DoneLedger,
{
    tracing::debug!("commit-stage worker started");
    loop {
        if cancel.is_cancelled() {
            tracing::debug!("commit-stage worker exiting: cancellation observed before receive");
            break;
        }

        let work = match submit_rx.recv_timeout(CANCEL_POLL_INTERVAL) {
            Ok(work) => work,
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => {
                tracing::debug!("commit-stage worker exiting: submission channel closed");
                break;
            }
        };

        if cancel.is_cancelled() {
            tracing::debug!(
                "commit-stage worker exiting: cancellation observed after dequeue, before commit"
            );
            let (write_context, completed_unit, _translation) = work.into_parts();
            if outcome_tx
                .try_send(CommitStageOutput::Failed {
                    write_context,
                    completed_unit,
                    error: ResultCommitError::Cancelled,
                })
                .is_err()
            {
                tracing::warn!(
                    "commit-stage: outcome delivery failed on cancellation; \
                     queue full or disconnected"
                );
            }
            break;
        }

        let (write_context, completed_unit, translation) = work.into_parts();
        let expected_kind = completed_unit.checkpoint_boundary_kind();
        let result = committer.commit_translation(write_context, &completed_unit, &translation);

        let outcome = match result {
            Ok(receipt) => match CheckpointAggregatorInput::new(expected_kind, receipt) {
                Ok(checkpoint_input) => CommitStageOutput::Committed {
                    write_context,
                    checkpoint_input,
                },
                // Defense-in-depth: expected_kind was derived from the same
                // completed_unit used to build the receipt, so a mismatch here
                // means durable data was committed but receipt construction
                // violated an internal invariant.
                //
                // The debug_assert panics the worker in debug/CI builds to
                // surface the violation immediately. The tracing::error and
                // Failed outcome below are the release-build recovery path
                // so the worker does not crash in production.
                Err(kind_mismatch) => {
                    debug_assert!(
                        false,
                        "KindMismatch after successful commit is an internal invariant violation: \
                         expected_kind was derived from the same completed_unit that produced the \
                         receipt: {kind_mismatch}"
                    );
                    tracing::error!(
                        %kind_mismatch,
                        "commit-stage: internal invariant violation; durable data was committed \
                         but receipt kind does not match completed unit"
                    );
                    CommitStageOutput::Failed {
                        write_context,
                        completed_unit,
                        error: ResultCommitError::KindMismatch(kind_mismatch),
                    }
                }
            },
            Err(error) => {
                tracing::warn!(%error, "commit-stage: durable commit failed");
                CommitStageOutput::Failed {
                    write_context,
                    completed_unit,
                    error,
                }
            }
        };

        if cancel.is_cancelled() {
            // Cancellation observed after commit. Try to deliver the outcome
            // non-blocking — the data is already durable, so dropping the
            // outcome is safe. A blocking send here could stall shutdown
            // indefinitely if the outcome queue is full and nobody drains it.
            if outcome_tx.try_send(outcome).is_err() {
                tracing::warn!(
                    "commit-stage: outcome delivery failed after commit; \
                     queue full or disconnected"
                );
            }
            tracing::debug!("commit-stage worker exiting: cancellation observed after commit");
            break;
        }
        // Blocking send is safe here: if the queue is full and cancellation fires
        // in the window between the check above and this call, shutdown() or
        // Drop will drop the outcome Receiver, which unblocks this send with
        // Err(SendError) and the worker exits via the branch below.
        if outcome_tx.send(outcome).is_err() {
            tracing::warn!(
                "commit-stage outcome channel disconnected; \
                 discarding result (durable data is safe, \
                 checkpoint recovers on restart)"
            );
            debug_assert!(
                cancel.is_cancelled(),
                "outcome receiver dropped while pipeline is not cancelled"
            );
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use gossip_contracts::{
        connector::{Cursor, ItemKey, ItemRef, Location, ScanItem, VersionId},
        identity::{ObjectVersionId, StableItemId},
        persistence::{CommitAdvanceError, DoneLedgerErrorCode},
    };
    use gossip_persistence_inmemory::{
        CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
        InMemoryStoreKind,
    };

    use super::*;
    use crate::{
        commit_model::CompletedUnit,
        result_committer::ResultCommitError,
        result_translation::{ItemResult, translate_item_result},
        test_fixtures::{
            finding, tenant_secret_key, test_rule_fingerprint, timing_with_offset, wait_until,
            write_context,
        },
    };

    fn scan_item(item_suffix: u8) -> ScanItem {
        let item_key =
            ItemKey::try_from_slice(format!("tenant/repo/file-{item_suffix}.txt").as_bytes())
                .expect("item key");
        let item_ref = ItemRef::try_from_vec(vec![b'r', item_suffix]).expect("item ref");
        let path = format!("tenant/repo/file-{item_suffix}.txt");
        let url = format!("https://example.invalid/file-{item_suffix}.txt");

        ScanItem::new(
            item_key,
            item_ref,
            StableItemId::from_bytes([item_suffix; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes(
                [item_suffix.wrapping_add(1); 32],
            )),
        )
        .with_location(Location::try_new(path, Some(url)).expect("location"))
    }

    fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
        CompletedUnit::ordered_content(
            sequence_no,
            Cursor::with_last_key(
                ItemKey::try_from_slice(format!("tenant/repo/file-{item_suffix}.txt").as_bytes())
                    .expect("item key"),
            ),
        )
    }

    fn translated_scan(item_suffix: u8) -> PersistenceTranslation {
        let item = scan_item(item_suffix);
        let findings = [
            finding(7, 10, 20, item_suffix),
            finding(9, 30, 45, item_suffix.wrapping_add(10)),
        ];
        translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            128,
            timing_with_offset(u64::from(item_suffix)),
            ItemResult::Scanned {
                findings: &findings,
            },
            &test_rule_fingerprint,
        )
        .expect("translation")
    }

    fn translated_failure(item_suffix: u8) -> PersistenceTranslation {
        let item = scan_item(item_suffix);
        translate_item_result(
            write_context(),
            &tenant_secret_key(),
            &item,
            64,
            timing_with_offset(u64::from(item_suffix)),
            ItemResult::FailedRetryable {
                error_code: DoneLedgerErrorCode::try_new("OPEN_FAILED").expect("error code"),
            },
            &test_rule_fingerprint,
        )
        .expect("translation")
    }

    fn queued_commit(sequence_no: u64, item_suffix: u8) -> QueuedCommit {
        QueuedCommit::new(
            write_context(),
            completed_unit(sequence_no, item_suffix),
            translated_scan(item_suffix),
        )
    }

    #[test]
    fn pipeline_emits_receipt_ready_checkpoint_input() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        sender
            .submit(queued_commit(1, 0x31))
            .expect("submit should succeed");

        let outcome = pipeline.recv().expect("outcome should be available");
        match outcome {
            CommitStageOutput::Committed {
                write_context: context,
                checkpoint_input,
            } => {
                assert_eq!(context, write_context());
                let receipt = checkpoint_input.into_receipt();
                assert_eq!(receipt.completed_unit().sequence_no(), 1);
                assert_eq!(receipt.durable().findings().finding_count(), 2);
                assert_eq!(receipt.durable().done_ledger().record_count(), 1);
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected successful outcome, got failure: {error}");
            }
        }

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn slow_findings_sink_backpressures_execution_queue() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 4,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let (ack_tx, ack_rx) = mpsc::channel();

        let producer = thread::spawn(move || {
            sender.submit(queued_commit(1, 0x41)).expect("send 1");
            ack_tx.send(1u8).expect("ack 1");
            sender.submit(queued_commit(2, 0x42)).expect("send 2");
            ack_tx.send(2u8).expect("ack 2");
            sender.submit(queued_commit(3, 0x43)).expect("send 3");
            ack_tx.send(3u8).expect("ack 3");
        });

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        assert!(
            ack_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "third submission should block while the commit worker is stalled and the bounded queue is full"
        );

        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release first findings write")
            .expect("first pending write");

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 3);

        for _ in 0..2 {
            wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
            findings_sink
                .release_next(CompletionOrder::OldestFirst)
                .expect("release remaining findings writes")
                .expect("pending write should exist");
        }

        let mut committed = 0usize;
        while committed < 3 {
            match pipeline
                .recv_timeout(Duration::from_secs(1))
                .expect("outcome")
            {
                CommitStageOutput::Committed { .. } => committed += 1,
                CommitStageOutput::Failed { error, .. } => {
                    panic!("expected success, got failure: {error}")
                }
            }
        }

        producer.join().expect("producer should join");
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn bounded_outcome_queue_backpressures_commit_stage_and_producers() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let (ack_tx, ack_rx) = mpsc::channel();

        let producer = thread::spawn(move || {
            sender.submit(queued_commit(1, 0x51)).expect("send 1");
            ack_tx.send(1u8).expect("ack 1");
            sender.submit(queued_commit(2, 0x52)).expect("send 2");
            ack_tx.send(2u8).expect("ack 2");
            sender.submit(queued_commit(3, 0x53)).expect("send 3");
            ack_tx.send(3u8).expect("ack 3");
            sender.submit(queued_commit(4, 0x54)).expect("send 4");
            ack_tx.send(4u8).expect("ack 4");
        });

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 3);
        assert!(
            ack_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "fourth submission should block once the outcome queue stops the commit worker from draining the execution queue"
        );

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("first outcome")
        {
            CommitStageOutput::Committed { .. } => {}
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected success, got failure: {error}")
            }
        }

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 4);

        let mut committed = 0usize;
        while committed < 3 {
            match pipeline
                .recv_timeout(Duration::from_secs(1))
                .expect("remaining outcome")
            {
                CommitStageOutput::Committed { .. } => committed += 1,
                CommitStageOutput::Failed { error, .. } => {
                    panic!("expected success, got failure: {error}")
                }
            }
        }

        producer.join().expect("producer should join");
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn commit_failures_are_emitted_with_unit_context() {
        let findings_sink = InMemoryFindingsSink::new();
        findings_sink
            .fail_next_submissions(1)
            .expect("fault injection should succeed");
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let failed_unit = completed_unit(9, 0x61);
        let work = QueuedCommit::new(
            write_context(),
            failed_unit.clone(),
            translated_failure(0x61),
        );

        sender.submit(work).expect("submit should succeed");

        let outcome = pipeline.recv().expect("outcome should be available");
        match outcome {
            CommitStageOutput::Committed { .. } => panic!("expected failure"),
            CommitStageOutput::Failed {
                write_context: context,
                completed_unit,
                error,
            } => {
                assert_eq!(context, write_context());
                assert_eq!(completed_unit, failed_unit);
                match error {
                    ResultCommitError::FindingsSubmit(
                        InMemoryPersistenceError::InjectedSubmissionFailure { store },
                    ) => assert_eq!(store, InMemoryStoreKind::Findings),
                    other => panic!("expected findings submission failure, got {other:?}"),
                }
            }
        }

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn cancelled_sender_rejects_submission_immediately() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 4,
            },
            cancel.clone(),
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        sender
            .submit(queued_commit(1, 0x91))
            .expect("first submit should succeed");
        sender
            .submit(queued_commit(2, 0x92))
            .expect("second submit should succeed");

        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        cancel.cancel();

        let work = queued_commit(3, 0x93);
        let expected = work.clone();
        match sender.submit(work) {
            Err(SubmitError::Cancelled(returned)) => assert_eq!(*returned, expected),
            Err(other) => panic!("expected cancellation error, got {other}"),
            Ok(()) => panic!("cancelled sender should not accept new work"),
        }

        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release in-flight findings write")
            .expect("pending write should exist");

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("first outcome should arrive")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                assert_eq!(
                    checkpoint_input
                        .into_receipt()
                        .completed_unit()
                        .sequence_no(),
                    1
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }

        assert!(matches!(
            pipeline.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn cancellation_stops_worker_after_current_item() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 16,
            },
            cancel.clone(),
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let (ack_tx, ack_rx) = mpsc::channel();

        let producer = thread::spawn(move || {
            let mut submitted = 0usize;
            for (sequence_no, suffix) in [(1, 0x71u8), (2, 0x72), (3, 0x73), (4, 0x74), (5, 0x75)] {
                match sender.submit(queued_commit(sequence_no, suffix)) {
                    Ok(()) => {
                        submitted += 1;
                        ack_tx.send(sequence_no as u8).expect("ack");
                    }
                    Err(SubmitError::Cancelled(_) | SubmitError::Disconnected(_)) => break,
                }
            }
            submitted
        });

        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 1);
        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 2);
        assert!(
            ack_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "third submission should still be blocked while the first commit is in flight"
        );

        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release first findings write")
            .expect("first pending write");

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 3);
        assert!(
            ack_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "fourth submission should still be blocked while the second commit is in flight"
        );

        let mut committed_sequences = Vec::new();
        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("first outcome should arrive")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => committed_sequences.push(
                checkpoint_input
                    .into_receipt()
                    .completed_unit()
                    .sequence_no(),
            ),
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }

        // Wait for item 2 to be in-flight in the findings sink before
        // cancelling. This closes the race where the OS could preempt the
        // worker thread between the outcome send for item 1 and the dequeue
        // of item 2, allowing cancel to fire at the pre-receive or
        // post-dequeue check and preventing item 2 from ever reaching the
        // findings sink.
        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        cancel.cancel();

        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release second findings write")
            .expect("second pending write");

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("second outcome should arrive")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => committed_sequences.push(
                checkpoint_input
                    .into_receipt()
                    .completed_unit()
                    .sequence_no(),
            ),
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }

        assert!(matches!(
            pipeline.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));

        let submitted = producer.join().expect("producer should join");
        assert_eq!(
            submitted, 3,
            "cancellation should stop submission before item 4"
        );
        assert_eq!(committed_sequences, vec![1, 2]);
        assert!(committed_sequences.len() < 5);

        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn blocked_sender_returns_cancelled_after_worker_exits_on_cancellation() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 4,
            },
            cancel.clone(),
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        sender
            .submit(queued_commit(1, 0x76))
            .expect("first submit should succeed");
        sender
            .submit(queued_commit(2, 0x77))
            .expect("second submit should succeed");
        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);

        let blocked_sender = sender.clone();
        let blocked_work = queued_commit(3, 0x78);
        let expected = blocked_work.clone();
        let (start_tx, start_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let blocked = thread::spawn(move || {
            start_tx.send(()).expect("started");
            let result = blocked_sender.submit(blocked_work);
            result_tx.send(result).expect("result");
        });

        start_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(
            result_rx.recv_timeout(Duration::from_millis(50)).is_err(),
            "third submit should still be blocked while the execution queue is full"
        );

        cancel.cancel();
        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release in-flight findings write")
            .expect("pending write should exist");

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("first outcome should arrive")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                assert_eq!(
                    checkpoint_input
                        .into_receipt()
                        .completed_unit()
                        .sequence_no(),
                    1
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }

        match result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blocked sender should unblock")
        {
            // The worker exits on cancellation, which also disconnects the
            // channel. The secondary cancellation check in submit() classifies
            // the send failure as Cancelled rather than Disconnected.
            Err(SubmitError::Cancelled(returned)) => assert_eq!(*returned, expected),
            other => panic!("expected cancelled submit result, got {other:?}"),
        }

        assert!(matches!(
            pipeline.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));

        blocked.join().expect("blocked sender should join");
        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn cancellation_does_not_interrupt_in_flight_commit() {
        let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel.clone(),
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        sender
            .submit(queued_commit(1, 0x81))
            .expect("submit should succeed");

        wait_until(|| findings_sink.pending_count().expect("pending count") == 1);
        cancel.cancel();

        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release in-flight findings write")
            .expect("pending write should exist");

        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("outcome should arrive")
        {
            CommitStageOutput::Committed {
                write_context: context,
                checkpoint_input,
            } => {
                assert_eq!(context, write_context());
                assert_eq!(
                    checkpoint_input
                        .into_receipt()
                        .completed_unit()
                        .sequence_no(),
                    1
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }

        assert!(matches!(
            pipeline.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn done_ledger_failure_propagates_through_pipeline() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_submissions(1)
            .expect("fault injection should succeed");
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let failed_unit = completed_unit(10, 0xA1);
        let work = QueuedCommit::new(
            write_context(),
            failed_unit.clone(),
            translated_failure(0xA1),
        );

        sender.submit(work).expect("submit should succeed");

        let outcome = pipeline.recv().expect("outcome should be available");
        match outcome {
            CommitStageOutput::Committed { .. } => panic!("expected failure"),
            CommitStageOutput::Failed {
                write_context: context,
                completed_unit,
                error,
            } => {
                assert_eq!(context, write_context());
                assert_eq!(completed_unit, failed_unit);
                match error {
                    ResultCommitError::DoneLedgerSubmit(
                        InMemoryPersistenceError::InjectedSubmissionFailure { store },
                    ) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
                    other => panic!("expected done-ledger submission failure, got {other:?}"),
                }
            }
        }

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn shutdown_stops_idle_worker() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig::default(),
            cancel,
        )
        .expect("pipeline should start");

        // No work submitted — shutdown directly.
        pipeline
            .shutdown()
            .expect("idle worker should join cleanly");
    }

    #[test]
    fn shutdown_completes_with_live_cloned_sender() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig::default(),
            cancel,
        )
        .expect("pipeline should start");

        // Clone a sender and deliberately keep it alive across shutdown. The
        // worker must still exit because it polls the cancellation token during
        // its timed receive loop.
        let _held_sender = pipeline.sender();

        pipeline
            .shutdown()
            .expect("shutdown must complete even with a live cloned sender");

        // _held_sender still alive here — dropped after the assertion.
    }

    #[test]
    fn rendezvous_capacity_zero_commits_successfully() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 0,
                outcome_queue_capacity: 0,
            },
            cancel,
        )
        .expect("pipeline should start");

        let sender = pipeline.sender();
        let (done_tx, done_rx) = mpsc::channel();

        // Rendezvous channels require sender and receiver to meet. Use a
        // helper thread for the producer so the main thread can drive the
        // receiver side.
        let producer = thread::spawn(move || {
            sender
                .submit(queued_commit(1, 0xB1))
                .expect("rendezvous submit should succeed");
            done_tx.send(()).expect("ack");
        });

        match pipeline
            .recv_timeout(Duration::from_secs(2))
            .expect("rendezvous outcome")
        {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                assert_eq!(
                    checkpoint_input
                        .into_receipt()
                        .completed_unit()
                        .sequence_no(),
                    1
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected success, got failure: {error}")
            }
        }

        done_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("producer should finish");
        producer.join().expect("producer should join");
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn multiple_concurrent_producers_all_outcomes_received() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 8,
                outcome_queue_capacity: 8,
            },
            cancel,
        )
        .expect("pipeline should start");

        let items_per_producer = 2u64;
        let producer_count = 3;
        let total = items_per_producer * producer_count;

        let producers: Vec<_> = (0..producer_count)
            .map(|p| {
                let sender = pipeline.sender();
                thread::spawn(move || {
                    for i in 0..items_per_producer {
                        let seq = p * items_per_producer + i + 1;
                        let suffix = (0xC0 + seq) as u8;
                        sender
                            .submit(queued_commit(seq, suffix))
                            .expect("submit should succeed");
                    }
                })
            })
            .collect();

        let mut committed = 0u64;
        while committed < total {
            match pipeline
                .recv_timeout(Duration::from_secs(2))
                .expect("outcome should arrive")
            {
                CommitStageOutput::Committed { .. } => committed += 1,
                CommitStageOutput::Failed { error, .. } => {
                    panic!("expected success, got failure: {error}")
                }
            }
        }

        assert_eq!(committed, total);

        for p in producers {
            p.join().expect("producer should join");
        }
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn done_ledger_commit_failure_is_emitted_with_unit_context() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        done_ledger
            .fail_next_commits(1)
            .expect("fault injection should succeed");
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();
        let failed_unit = completed_unit(11, 0xD1);
        let work = QueuedCommit::new(write_context(), failed_unit.clone(), translated_scan(0xD1));

        sender.submit(work).expect("submit should succeed");

        let outcome = pipeline.recv().expect("outcome should be available");
        match outcome {
            CommitStageOutput::Committed { .. } => panic!("expected failure"),
            CommitStageOutput::Failed {
                write_context: context,
                completed_unit,
                error,
            } => {
                assert_eq!(context, write_context());
                assert_eq!(completed_unit, failed_unit);
                match error {
                    ResultCommitError::DoneLedgerAdvance(CommitAdvanceError::Wait(
                        InMemoryPersistenceError::InjectedCommitFailure { store },
                    )) => assert_eq!(store, InMemoryStoreKind::DoneLedger),
                    other => panic!("expected done-ledger advance failure, got {other:?}"),
                }
            }
        }

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }

    #[test]
    fn drop_without_shutdown_does_not_hang() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let cancel_check = cancel.clone();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        sender
            .submit(queued_commit(1, 0xE1))
            .expect("submit should succeed");

        // Drop sender first so the pipeline owns the only sender.
        drop(sender);
        // Drop without shutdown — should not hang. The Drop impl cancels the
        // token and detaches the worker thread.
        drop(pipeline);

        assert!(
            cancel_check.is_cancelled(),
            "Drop must cancel the token even without explicit shutdown"
        );
    }

    #[test]
    fn worker_continues_after_commit_failure() {
        let findings_sink = InMemoryFindingsSink::new();
        findings_sink
            .fail_next_submissions(1)
            .expect("fault injection should succeed");
        let done_ledger = InMemoryDoneLedger::new();
        let cancel = CancellationToken::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 2,
                outcome_queue_capacity: 2,
            },
            cancel,
        )
        .expect("pipeline should start");
        let sender = pipeline.sender();

        // First item will fail (injected findings failure), second should
        // succeed — the worker must not exit early on a commit error.
        sender
            .submit(queued_commit(1, 0xF1))
            .expect("submit 1 should succeed");
        sender
            .submit(queued_commit(2, 0xF2))
            .expect("submit 2 should succeed");

        let first = pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("first outcome should arrive");
        assert!(
            matches!(first, CommitStageOutput::Failed { .. }),
            "first outcome should be a failure"
        );

        let second = pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("second outcome should arrive");
        match second {
            CommitStageOutput::Committed {
                checkpoint_input, ..
            } => {
                assert_eq!(
                    checkpoint_input
                        .into_receipt()
                        .completed_unit()
                        .sequence_no(),
                    2
                );
            }
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected second outcome to be committed, got failure: {error}")
            }
        }

        drop(sender);
        pipeline.shutdown().expect("worker should join");
    }
}
