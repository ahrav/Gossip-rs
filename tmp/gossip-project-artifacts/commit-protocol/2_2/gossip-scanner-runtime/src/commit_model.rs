//! Shared runtime commit vocabulary frozen for Epic 2.1.
//!
//! The runtime finishes work in two layers:
//!
//! 1. **Per completed unit** — findings and done-ledger writes become durable
//!    and yield an item-level receipt.
//! 2. **Committed prefix checkpoint** — a separate aggregator advances the
//!    family-specific frontier only from durable receipts, never from raw scan
//!    completion signals.
//!
//! This module freezes the family-neutral shapes the later runtime stages will
//! build on:
//!
//! - [`CompletedUnit`] — smallest runtime work unit that can yield an
//!   authoritative durable receipt.
//! - [`CommitRequest`] — runtime-facing input to the future `ResultCommitter`.
//! - [`CommitReceipt`] — durable proof returned by the future `ResultCommitter`.
//! - [`CheckpointAggregatorInput`] — the only thing the future checkpoint
//!   aggregator is allowed to consume.
//!
//! The key design move is that both ordered-content and repo-frontier progress
//! are represented by the shared [`CheckpointBoundary`](gossip_contracts::persistence::CheckpointBoundary)
//! contract. That keeps the runtime durability model family-neutral without
//! guessing ahead about family-specific execution loops.

use gossip_contracts::{
    connector::Cursor,
    persistence::{
        CheckpointBoundary, CheckpointBoundaryKind, DoneLedgerRecord, FindingsUpsertBatch,
        ItemCommitReceipt, WriteContext,
    },
};

/// Smallest runtime work unit that can yield an authoritative durable receipt.
///
/// Ordered-content execution will use one unit per scanned item. Repo-native
/// execution will use one unit per repo target. In both cases the unit carries
/// a deterministic in-shard sequence number plus the family-specific frontier
/// boundary that becomes eligible for prefix checkpointing once the unit is
/// durably committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedUnit {
    sequence_no: u64,
    checkpoint_boundary: CheckpointBoundary,
}

impl CompletedUnit {
    /// Construct a completed unit from an explicit checkpoint boundary.
    #[must_use]
    pub fn new(sequence_no: u64, checkpoint_boundary: impl Into<CheckpointBoundary>) -> Self {
        Self {
            sequence_no,
            checkpoint_boundary: checkpoint_boundary.into(),
        }
    }

    /// Convenience constructor for ordered-content units.
    #[must_use]
    pub fn ordered_content(sequence_no: u64, checkpoint_cursor: Cursor) -> Self {
        Self::new(
            sequence_no,
            CheckpointBoundary::ordered_content(checkpoint_cursor),
        )
    }

    /// Convenience constructor for repo-frontier units.
    #[must_use]
    pub fn repo_frontier(sequence_no: u64, checkpoint_cursor: Cursor) -> Self {
        Self::new(
            sequence_no,
            CheckpointBoundary::repo_frontier(checkpoint_cursor),
        )
    }

    /// Deterministic in-shard ordering position for prefix-commit semantics.
    #[inline]
    #[must_use]
    pub const fn sequence_no(&self) -> u64 {
        self.sequence_no
    }

    /// Family-neutral frontier boundary attached to this unit.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary(&self) -> &CheckpointBoundary {
        &self.checkpoint_boundary
    }

    /// Semantic family of the attached frontier boundary.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary_kind(&self) -> CheckpointBoundaryKind {
        self.checkpoint_boundary.kind()
    }

    /// Underlying monotonic cursor used at the persistence boundary.
    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        self.checkpoint_boundary.cursor()
    }

    /// Consume the unit into its raw parts.
    #[inline]
    #[must_use]
    pub fn into_parts(self) -> (u64, CheckpointBoundary) {
        (self.sequence_no, self.checkpoint_boundary)
    }
}

/// Runtime-facing commit request shape.
///
/// The future `ResultCommitter` receives one request per completed unit and is
/// responsible for deriving IDs, writing findings first, then writing the
/// done-ledger rows, and finally returning a durable [`CommitReceipt`].
///
/// The request borrows the findings batch and done-ledger rows so the runtime
/// can keep buffer ownership outside the commit stage.
#[derive(Clone, Debug)]
pub struct CommitRequest<'a> {
    write_context: WriteContext,
    completed_unit: CompletedUnit,
    findings: FindingsUpsertBatch<'a>,
    done_ledger: &'a [DoneLedgerRecord],
}

impl<'a> CommitRequest<'a> {
    /// Construct a runtime commit request.
    #[must_use]
    pub fn new(
        write_context: WriteContext,
        completed_unit: CompletedUnit,
        findings: FindingsUpsertBatch<'a>,
        done_ledger: &'a [DoneLedgerRecord],
    ) -> Self {
        Self {
            write_context,
            completed_unit,
            findings,
            done_ledger,
        }
    }

    /// Shared routing and fencing metadata for the writes this request will
    /// submit.
    #[inline]
    #[must_use]
    pub const fn write_context(&self) -> WriteContext {
        self.write_context
    }

    /// Completed unit this request will make durable.
    #[inline]
    #[must_use]
    pub fn completed_unit(&self) -> &CompletedUnit {
        &self.completed_unit
    }

    /// Borrowed findings-layer batch for the commit stage.
    #[inline]
    #[must_use]
    pub const fn findings(&self) -> FindingsUpsertBatch<'a> {
        self.findings
    }

    /// Borrowed done-ledger rows for the commit stage.
    #[inline]
    #[must_use]
    pub fn done_ledger(&self) -> &'a [DoneLedgerRecord] {
        self.done_ledger
    }

    /// Consume the request into its raw parts.
    #[inline]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (WriteContext, CompletedUnit, FindingsUpsertBatch<'a>, &'a [DoneLedgerRecord]) {
        (
            self.write_context,
            self.completed_unit,
            self.findings,
            self.done_ledger,
        )
    }
}

/// Durable per-unit runtime receipt.
///
/// This is the runtime-facing proof object returned after findings and
/// done-ledger durability have both succeeded for one completed unit. It does
/// **not** imply checkpoint advancement; the separate checkpoint aggregator is
/// still responsible for computing the committed prefix.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitReceipt {
    completed_unit: CompletedUnit,
    durable: ItemCommitReceipt,
}

impl CommitReceipt {
    /// Construct a durable runtime receipt.
    #[must_use]
    pub fn new(completed_unit: CompletedUnit, durable: ItemCommitReceipt) -> Self {
        Self {
            completed_unit,
            durable,
        }
    }

    /// Completed unit proved durable by this receipt.
    #[inline]
    #[must_use]
    pub fn completed_unit(&self) -> &CompletedUnit {
        &self.completed_unit
    }

    /// Underlying item-level persistence receipt.
    #[inline]
    #[must_use]
    pub fn durable(&self) -> &ItemCommitReceipt {
        &self.durable
    }

    /// Consume the receipt into its raw parts.
    #[inline]
    #[must_use]
    pub fn into_parts(self) -> (CompletedUnit, ItemCommitReceipt) {
        (self.completed_unit, self.durable)
    }
}

/// Receipt-only input to the future checkpoint aggregator.
///
/// The checkpoint stage must never look at raw scan completion signals. By
/// wrapping only [`CommitReceipt`], this type makes the intended runtime shape
/// explicit: checkpoint advancement is driven solely by durable receipts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAggregatorInput {
    receipt: CommitReceipt,
}

impl CheckpointAggregatorInput {
    /// Construct aggregator input from a durable runtime receipt.
    #[inline]
    #[must_use]
    pub fn from_receipt(receipt: CommitReceipt) -> Self {
        Self { receipt }
    }

    /// Durable receipt carried into the checkpoint stage.
    #[inline]
    #[must_use]
    pub fn receipt(&self) -> &CommitReceipt {
        &self.receipt
    }

    /// Consume the wrapper and return the underlying receipt.
    #[inline]
    #[must_use]
    pub fn into_receipt(self) -> CommitReceipt {
        self.receipt
    }
}

impl From<CommitReceipt> for CheckpointAggregatorInput {
    #[inline]
    fn from(receipt: CommitReceipt) -> Self {
        Self::from_receipt(receipt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::{
        connector::ItemKey,
        identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
        persistence::{
            CommitScope, DoneLedgerCommitReceipt, FindingsCommitReceipt, PageCommit,
        },
    };

    fn sample_cursor(seed: u8) -> Cursor {
        Cursor::with_last_key(ItemKey::try_from_slice(&[seed]).expect("cursor key"))
    }

    fn sample_item_receipt(kind: CheckpointBoundaryKind) -> ItemCommitReceipt {
        let boundary = match kind {
            CheckpointBoundaryKind::OrderedContent => {
                CheckpointBoundary::ordered_content(sample_cursor(0x10))
            }
            CheckpointBoundaryKind::RepoFrontier => {
                CheckpointBoundary::repo_frontier(sample_cursor(0x20))
            }
        };

        PageCommit::new(CommitScope::new(
            TenantId::from_bytes([0x11; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            1,
            boundary,
        ))
        .record_findings(FindingsCommitReceipt::new(1, 1, 1))
        .record_done_ledger(DoneLedgerCommitReceipt::new(1, 1, 1))
        .expect("done-ledger receipt should match one committed unit")
        .into_item_commit_receipt()
    }

    fn sample_write_context(seed: u8) -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([seed; 32]),
            PolicyHash::from_bytes([seed.wrapping_add(1); 32]),
            RunId::from_raw(seed as u64 + 10),
            ShardId::from_raw(seed as u64 + 20),
            FenceEpoch::from_raw(seed as u64 + 30),
        )
    }

    #[test]
    fn completed_unit_constructors_tag_boundaries() {
        let ordered = CompletedUnit::ordered_content(7, sample_cursor(1));
        assert_eq!(ordered.sequence_no(), 7);
        assert_eq!(
            ordered.checkpoint_boundary_kind(),
            CheckpointBoundaryKind::OrderedContent
        );
        assert!(ordered.checkpoint_boundary().as_ordered_content().is_some());
        assert!(ordered.checkpoint_boundary().as_repo_frontier().is_none());

        let repo = CompletedUnit::repo_frontier(8, sample_cursor(2));
        assert_eq!(repo.sequence_no(), 8);
        assert_eq!(
            repo.checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
        assert!(repo.checkpoint_boundary().as_ordered_content().is_none());
        assert!(repo.checkpoint_boundary().as_repo_frontier().is_some());
    }

    #[test]
    fn commit_request_preserves_borrowed_payloads() {
        let write_context = sample_write_context(4);
        let request = CommitRequest::new(
            write_context,
            CompletedUnit::ordered_content(3, sample_cursor(3)),
            FindingsUpsertBatch::new(&[], &[], &[]),
            &[],
        );

        assert_eq!(request.write_context(), write_context);
        assert_eq!(request.completed_unit().sequence_no(), 3);
        assert!(request.findings().is_empty());
        assert!(request.done_ledger().is_empty());

        let (round_trip_write_context, completed, findings, done_ledger) = request.into_parts();
        assert_eq!(round_trip_write_context, write_context);
        assert_eq!(completed.sequence_no(), 3);
        assert!(findings.is_empty());
        assert!(done_ledger.is_empty());
    }

    #[test]
    fn checkpoint_aggregator_input_wraps_only_durable_receipts() {
        let completed = CompletedUnit::repo_frontier(9, sample_cursor(9));
        let durable = sample_item_receipt(CheckpointBoundaryKind::RepoFrontier);
        let receipt = CommitReceipt::new(completed.clone(), durable.clone());
        let aggregator_input = CheckpointAggregatorInput::from(receipt.clone());

        assert_eq!(aggregator_input.receipt(), &receipt);
        assert_eq!(aggregator_input.receipt().completed_unit(), &completed);
        assert_eq!(aggregator_input.receipt().durable(), &durable);
        assert_eq!(
            aggregator_input
                .receipt()
                .durable()
                .scope()
                .checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
    }
}
