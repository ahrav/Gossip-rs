//! Bounded execution → commit pipeline for the Epic 2 durability model.
//!
//! The runtime needs one structural choke point between scan execution and
//! durable commit:
//!
//! 1. execution translates scan results into owned persistence rows;
//! 2. execution enqueues that owned work on a **bounded** channel;
//! 3. the commit stage is the only place that performs findings → done-ledger;
//! 4. the commit stage emits receipt-ready output for checkpoint aggregation.
//!
//! This module implements that producer/consumer boundary as a single commit
//! worker backed by `std::sync::mpsc::sync_channel`.
//!
//! # Why a blocking bounded queue?
//!
//! Slow sinks must pause scanning instead of letting memory usage drift upward.
//! A bounded `sync_channel` gives us exactly that behavior:
//!
//! - if the commit worker is blocked in `ResultCommitter` waiting for durable
//!   findings or done-ledger writes, it stops draining the execution queue;
//! - once the queue reaches capacity, `submit(...)` blocks; and
//! - execution pressure therefore propagates backwards instead of creating an
//!   unbounded buffer of half-finished work.
//!
//! # Stage ownership
//!
//! Enqueueing work is **not** an authoritative finish signal. The only
//! authoritative success output from this stage is a durable receipt wrapped as
//! [`CheckpointAggregatorInput`](crate::commit_model::CheckpointAggregatorInput).
//! That keeps the runtime aligned with Epic 2's rule that checkpoint progress is
//! driven only by receipts, never by raw scan completion.
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
    commit_model::{CheckpointAggregatorInput, CompletedUnit},
    result_committer::{ResultCommitError, ResultCommitter},
    result_translation::PersistenceTranslation,
};

/// Queue sizing for the bounded execution → commit pipeline.
///
/// Both capacities are passed directly to [`sync_channel`]. `0` is valid and
/// gives rendezvous behavior rather than buffered queueing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitPipelineConfig {
    /// Maximum number of translated work items buffered between execution and
    /// the commit stage.
    pub execution_queue_capacity: usize,
    /// Maximum number of commit-stage outcomes buffered between the commit
    /// worker and the downstream checkpoint/error-handling stage.
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
/// thread boundary cleanly. The commit worker borrows the owned translation only
/// while calling [`ResultCommitter::commit_translation`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueuedCommit {
    write_context: WriteContext,
    completed_unit: CompletedUnit,
    translation: PersistenceTranslation,
}

impl QueuedCommit {
    /// Construct one owned work item for the commit stage.
    #[must_use]
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

    /// Shared routing and fencing metadata for this work item.
    #[inline]
    #[must_use]
    pub fn write_context(&self) -> WriteContext {
        self.write_context
    }

    /// Completed runtime unit this work item is trying to make durable.
    #[inline]
    #[must_use]
    pub fn completed_unit(&self) -> &CompletedUnit {
        &self.completed_unit
    }

    /// Translated persistence rows owned by this work item.
    #[inline]
    #[must_use]
    pub fn translation(&self) -> &PersistenceTranslation {
        &self.translation
    }

    /// Consume the work item into its raw parts.
    #[inline]
    #[must_use]
    pub fn into_parts(self) -> (WriteContext, CompletedUnit, PersistenceTranslation) {
        (self.write_context, self.completed_unit, self.translation)
    }
}

/// Outcome emitted by the commit stage.
///
/// Success is represented as a receipt-ready checkpoint input paired with the
/// original [`WriteContext`]. Failure keeps the completed unit attached so the
/// runtime can reason about which unit stalled or needs retry handling.
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
    /// One queued work item failed during durable commit.
    Failed {
        /// Shared routing and fencing metadata for the failed commit.
        write_context: WriteContext,
        /// Completed unit that failed to become durable.
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

    /// Returns the successful checkpoint input, if present.
    #[inline]
    #[must_use]
    pub fn checkpoint_input(&self) -> Option<&CheckpointAggregatorInput> {
        match self {
            Self::Committed {
                checkpoint_input, ..
            } => Some(checkpoint_input),
            Self::Failed { .. } => None,
        }
    }

    /// Returns the failed completed unit, if present.
    #[inline]
    #[must_use]
    pub fn failed_completed_unit(&self) -> Option<&CompletedUnit> {
        match self {
            Self::Committed { .. } => None,
            Self::Failed { completed_unit, .. } => Some(completed_unit),
        }
    }

    /// Returns the stage-local error, if present.
    #[inline]
    #[must_use]
    pub fn error(&self) -> Option<&ResultCommitError<FindingsError, DoneLedgerError>> {
        match self {
            Self::Committed { .. } => None,
            Self::Failed { error, .. } => Some(error),
        }
    }
}

/// Cloneable execution-side handle for submitting work into the bounded commit
/// queue.
#[derive(Clone, Debug)]
pub struct CommitPipelineSender {
    inner: SyncSender<QueuedCommit>,
}

impl CommitPipelineSender {
    /// Submit one owned work item into the bounded execution queue.
    ///
    /// This call blocks when the queue is full, which is the intended
    /// backpressure mechanism for slow sinks.
    #[inline]
    pub fn submit(&self, work: QueuedCommit) -> Result<(), SendError<QueuedCommit>> {
        self.inner.send(work)
    }
}

/// Bounded execution → commit pipeline with one dedicated commit worker.
///
/// The worker owns a [`ResultCommitter`] and is therefore the only place where
/// runtime work becomes authoritatively durable. Execution threads only enqueue
/// [`QueuedCommit`] values; they do not write sinks directly.
pub struct CommitPipeline<F, D>
where
    F: FindingsSink,
    D: DoneLedger,
{
    sender: CommitPipelineSender,
    outcomes: Receiver<CommitStageOutput<F::Error, D::Error>>,
    worker: JoinHandle<()>,
}

impl<F, D> CommitPipeline<F, D>
where
    F: FindingsSink + Send + 'static,
    D: DoneLedger + Send + 'static,
{
    /// Start one bounded commit pipeline backed by a dedicated worker thread.
    pub fn start(
        findings_sink: F,
        done_ledger: D,
        config: CommitPipelineConfig,
    ) -> std::io::Result<Self> {
        let (submit_tx, submit_rx) = sync_channel(config.execution_queue_capacity);
        let (outcome_tx, outcome_rx) = sync_channel(config.outcome_queue_capacity);

        let worker = thread::Builder::new()
            .name("runtime-commit-stage".to_owned())
            .spawn(move || {
                run_commit_stage(
                    ResultCommitter::new(findings_sink, done_ledger),
                    submit_rx,
                    outcome_tx,
                );
            })?;

        Ok(Self {
            sender: CommitPipelineSender { inner: submit_tx },
            outcomes: outcome_rx,
            worker,
        })
    }

    /// Clone the execution-side submission handle.
    #[inline]
    #[must_use]
    pub fn sender(&self) -> CommitPipelineSender {
        self.sender.clone()
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

    /// Try to receive one commit-stage outcome without blocking.
    #[inline]
    pub fn try_recv(&self) -> Result<CommitStageOutput<F::Error, D::Error>, TryRecvError> {
        self.outcomes.try_recv()
    }

    /// Shut the pipeline down and join the worker thread.
    ///
    /// Callers must drop all cloned [`CommitPipelineSender`] handles before
    /// invoking this method. Dropping the outcome receiver first ensures a
    /// worker blocked on outcome delivery wakes up and exits cleanly.
    pub fn shutdown(self) -> thread::Result<()> {
        let Self {
            sender,
            outcomes,
            worker,
        } = self;
        drop(sender);
        drop(outcomes);
        worker.join()
    }
}

fn run_commit_stage<F, D>(
    committer: ResultCommitter<F, D>,
    submit_rx: Receiver<QueuedCommit>,
    outcome_tx: SyncSender<CommitStageOutput<F::Error, D::Error>>,
) where
    F: FindingsSink,
    D: DoneLedger,
{
    while let Ok(work) = submit_rx.recv() {
        let write_context = work.write_context;
        let completed_unit = work.completed_unit.clone();
        let result = committer.commit_translation(
            write_context,
            work.completed_unit.clone(),
            &work.translation,
        );

        let outcome = match result {
            Ok(receipt) => CommitStageOutput::Committed {
                write_context,
                checkpoint_input: CheckpointAggregatorInput::from_receipt(receipt),
            },
            Err(error) => CommitStageOutput::Failed {
                write_context,
                completed_unit,
                error,
            },
        };

        if outcome_tx.send(outcome).is_err() {
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
        identity::{
            FenceEpoch, LogicalTime, ObjectVersionId, PolicyHash, RunId, ShardId,
            StableItemId, TenantId, TenantSecretKey,
        },
        persistence::{DoneLedgerErrorCode, WriteContext},
    };
    use gossip_persistence_inmemory::{
        CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink, InMemoryPersistenceError,
        InMemoryStoreKind,
    };
    use scanner_scheduler::FsFindingRecord;

    use super::*;
    use crate::{
        commit_model::CompletedUnit,
        result_committer::ResultCommitError,
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

    fn scan_item(item_suffix: u8) -> ScanItem {
        let item_key = ItemKey::try_from_slice(&[b't', b'/', item_suffix]).expect("item key");
        let item_ref = ItemRef::try_from_vec(vec![b'r', item_suffix]).expect("item ref");
        let path = format!("tenant/repo/file-{item_suffix}.txt");
        let url = format!("https://example.invalid/{item_suffix}");

        ScanItem::new(
            item_key,
            item_ref,
            StableItemId::from_bytes([item_suffix; 32]),
            VersionId::Strong(ObjectVersionId::from_bytes([item_suffix.wrapping_add(1); 32])),
        )
        .with_location(Location::try_new(path, Some(url)).expect("location"))
    }

    fn timing(offset: u64) -> ScanTiming {
        ScanTiming::new(
            LogicalTime::from_raw(1_000 + offset),
            LogicalTime::from_raw(2_000 + offset),
        )
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

    fn completed_unit(sequence_no: u64, item_suffix: u8) -> CompletedUnit {
        CompletedUnit::ordered_content(
            sequence_no,
            Cursor::with_last_key(ItemKey::try_from_slice(&[b't', b'/', item_suffix]).expect("key")),
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
            timing(u64::from(item_suffix)),
            ItemResult::Scanned { findings: &findings },
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
            timing(u64::from(item_suffix)),
            ItemResult::FailedRetryable {
                error_code: DoneLedgerErrorCode::try_new("OPEN_FAILED").expect("error code"),
            },
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
    fn pipeline_emits_receipt_ready_checkpoint_input() {
        let findings_sink = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
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
        let pipeline = CommitPipeline::start(
            findings_sink.clone(),
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 4,
            },
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
            .expect("release first findings write");

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 3);

        for _ in 0..2 {
            wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
            findings_sink
                .release_next(CompletionOrder::OldestFirst)
                .expect("release remaining findings writes");
        }

        let mut committed = 0usize;
        while committed < 3 {
            match pipeline.recv_timeout(Duration::from_secs(1)).expect("outcome") {
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
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
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

        match pipeline.recv_timeout(Duration::from_secs(1)).expect("first outcome") {
            CommitStageOutput::Committed { .. } => {}
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected success, got failure: {error}")
            }
        }

        assert_eq!(ack_rx.recv_timeout(Duration::from_secs(1)).unwrap(), 4);

        let mut committed = 0usize;
        while committed < 3 {
            match pipeline.recv_timeout(Duration::from_secs(1)).expect("remaining outcome") {
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
        let pipeline = CommitPipeline::start(
            findings_sink,
            done_ledger,
            CommitPipelineConfig {
                execution_queue_capacity: 1,
                outcome_queue_capacity: 1,
            },
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
}
