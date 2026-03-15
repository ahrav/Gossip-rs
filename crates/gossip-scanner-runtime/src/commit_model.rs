//! Shared runtime commit vocabulary for family-neutral durability stages.
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
//! - [`UnitCommitReceipt`] — durable per-unit proof returned after the
//!   findings and done-ledger stages succeed.
//! - [`CheckpointAggregatorInput`] — the only thing the future checkpoint
//!   aggregator is allowed to consume.
//!
//! The key design move is that both ordered-content and repo-frontier progress
//! are represented by the shared [`CheckpointBoundary`] contract. That keeps
//! the runtime durability model family-neutral without
//! guessing ahead about family-specific execution loops.

use std::fmt;

use gossip_contracts::{
    connector::Cursor,
    persistence::{
        CheckpointBoundary, CheckpointBoundaryKind, DoneLedgerRecord, FindingsUpsertBatch,
        ItemCommitReceipt,
    },
};

/// Smallest runtime work unit that can yield an authoritative durable receipt.
///
/// Ordered-content execution uses one unit per scanned item. Repo-native
/// execution uses one unit per repo target. In both cases the unit carries a
/// deterministic in-shard sequence number plus the family-specific frontier
/// boundary that becomes eligible for prefix checkpointing once the unit is
/// durably committed.
#[must_use = "completed units must be committed or explicitly discarded"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedUnit {
    sequence_no: u64,
    checkpoint_boundary: CheckpointBoundary,
}

impl CompletedUnit {
    /// Construct a completed unit from an explicit checkpoint boundary.
    ///
    /// `sequence_no` is a zero-based monotonically increasing position within
    /// one shard's commit stream. All units in the same shard stream must carry
    /// the same [`CheckpointBoundaryKind`]; mixing families within a single
    /// shard stream is a programming error at the checkpoint-aggregator level.
    pub fn new(sequence_no: u64, checkpoint_boundary: CheckpointBoundary) -> Self {
        Self {
            sequence_no,
            checkpoint_boundary,
        }
    }

    /// Convenience constructor for ordered-content units.
    pub fn ordered_content(sequence_no: u64, checkpoint_cursor: Cursor) -> Self {
        Self::new(
            sequence_no,
            CheckpointBoundary::ordered_content(checkpoint_cursor),
        )
    }

    /// Convenience constructor for repo-frontier units.
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
/// done-ledger rows, and finally returning a durable [`UnitCommitReceipt`].
///
/// The request borrows the findings batch and done-ledger rows so the runtime
/// can keep buffer ownership outside the commit stage.
#[must_use = "commit requests must be submitted or explicitly dropped"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitRequest<'a> {
    completed_unit: CompletedUnit,
    findings: FindingsUpsertBatch<'a>,
    done_ledger: &'a [DoneLedgerRecord],
}

impl<'a> CommitRequest<'a> {
    /// Construct a runtime commit request.
    pub fn new(
        completed_unit: CompletedUnit,
        findings: FindingsUpsertBatch<'a>,
        done_ledger: &'a [DoneLedgerRecord],
    ) -> Self {
        Self {
            completed_unit,
            findings,
            done_ledger,
        }
    }

    /// Completed unit this request will make durable.
    #[inline]
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
    pub fn into_parts(
        self,
    ) -> (
        CompletedUnit,
        FindingsUpsertBatch<'a>,
        &'a [DoneLedgerRecord],
    ) {
        (self.completed_unit, self.findings, self.done_ledger)
    }
}

/// Boundary mismatch between a completed unit and its durable receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryMismatchError {
    unit_boundary: CheckpointBoundary,
    receipt_boundary: CheckpointBoundary,
}

impl fmt::Display for BoundaryMismatchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "completed unit boundary {:?} does not match receipt boundary {:?}",
            self.unit_boundary, self.receipt_boundary
        )
    }
}

impl std::error::Error for BoundaryMismatchError {}

/// Durable per-unit runtime receipt.
///
/// This is the runtime-facing proof object returned after findings and
/// done-ledger durability have both succeeded for one completed unit. It does
/// not imply checkpoint advancement; the separate checkpoint aggregator is
/// still responsible for computing the committed prefix.
#[must_use = "unit receipts must feed the checkpoint stage or be explicitly discarded"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UnitCommitReceipt {
    completed_unit: CompletedUnit,
    durable: ItemCommitReceipt,
}

impl UnitCommitReceipt {
    /// Construct a durable runtime receipt.
    ///
    /// Validates only the `checkpoint_boundary` field — full `CommitScope`
    /// correspondence (tenant, run, shard, fence epoch, committed units) is
    /// the caller's responsibility. `CompletedUnit` does not carry scope
    /// identity, so a stronger check is structurally impossible at this layer.
    /// The downstream `PageCommit::record_checkpoint` enforces full-scope
    /// equality against the coordination-side receipt.
    ///
    /// # Errors
    ///
    /// Returns [`BoundaryMismatchError`] if the completed unit's checkpoint
    /// boundary does not match the durable receipt's scope boundary.
    pub fn new(
        completed_unit: CompletedUnit,
        durable: ItemCommitReceipt,
    ) -> Result<Self, Box<BoundaryMismatchError>> {
        if completed_unit.checkpoint_boundary() != durable.scope().checkpoint_boundary() {
            return Err(Box::new(BoundaryMismatchError {
                unit_boundary: completed_unit.checkpoint_boundary().clone(),
                receipt_boundary: durable.scope().checkpoint_boundary().clone(),
            }));
        }

        Ok(Self {
            completed_unit,
            durable,
        })
    }

    /// Completed unit proved durable by this receipt.
    #[inline]
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
    pub fn into_parts(self) -> (CompletedUnit, ItemCommitReceipt) {
        (self.completed_unit, self.durable)
    }
}

/// Receipt-only input to the future checkpoint aggregator.
///
/// The checkpoint stage must never look at raw scan completion signals. By
/// wrapping only [`UnitCommitReceipt`], this type makes the intended runtime
/// shape explicit: checkpoint advancement is driven solely by durable receipts.
#[must_use = "checkpoint aggregator input must be consumed by the checkpoint stage"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAggregatorInput {
    receipt: UnitCommitReceipt,
}

impl CheckpointAggregatorInput {
    /// Construct aggregator input from a durable runtime receipt.
    #[inline]
    pub fn new(receipt: UnitCommitReceipt) -> Self {
        Self { receipt }
    }

    /// Durable receipt carried into the checkpoint stage.
    #[inline]
    pub fn receipt(&self) -> &UnitCommitReceipt {
        &self.receipt
    }

    /// Consume the wrapper and return the underlying receipt.
    #[inline]
    pub fn into_receipt(self) -> UnitCommitReceipt {
        self.receipt
    }
}

impl From<UnitCommitReceipt> for CheckpointAggregatorInput {
    #[inline]
    fn from(receipt: UnitCommitReceipt) -> Self {
        Self::new(receipt)
    }
}

// Compile-time proof that runtime commit types can move across threads.
// Closure-in-const avoids dead_code warnings while keeping assertions local.
const _: fn() = || {
    fn assert_impl<T: Send + Sync>() {}
    assert_impl::<CompletedUnit>();
    assert_impl::<UnitCommitReceipt>();
    assert_impl::<CheckpointAggregatorInput>();

    // CommitRequest borrows data, so prove Send+Sync for an arbitrary lifetime.
    fn assert_borrowing_send_sync<T: Send + Sync + ?Sized>() {}
    assert_borrowing_send_sync::<CommitRequest<'_>>();
};

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::{
        connector::ItemKey,
        identity::{FenceEpoch, RunId, ShardId, TenantId},
        persistence::{CommitScope, DoneLedgerCommitReceipt, FindingsCommitReceipt, PageCommit},
    };

    fn sample_cursor(seed: u8) -> Cursor {
        Cursor::with_last_key(ItemKey::try_from_slice(&[seed]).expect("cursor key"))
    }

    fn sample_item_receipt(boundary: CheckpointBoundary) -> ItemCommitReceipt {
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

    #[test]
    fn checkpoint_boundary_distinguishes_families_with_same_cursor() {
        let cursor = sample_cursor(7);

        assert_ne!(
            CheckpointBoundary::ordered_content(cursor.clone()),
            CheckpointBoundary::repo_frontier(cursor)
        );
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
        let request = CommitRequest::new(
            CompletedUnit::ordered_content(3, sample_cursor(3)),
            FindingsUpsertBatch::new(&[], &[], &[]),
            &[],
        );

        assert_eq!(request.completed_unit().sequence_no(), 3);
        assert!(request.findings().is_empty());
        assert!(request.done_ledger().is_empty());
    }

    #[test]
    fn unit_commit_receipt_supports_both_runtime_families() {
        let ordered_cursor = sample_cursor(11);
        let ordered = UnitCommitReceipt::new(
            CompletedUnit::ordered_content(11, ordered_cursor.clone()),
            sample_item_receipt(CheckpointBoundary::ordered_content(ordered_cursor)),
        )
        .expect("boundary matches");
        assert_eq!(
            ordered.completed_unit().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::OrderedContent
        );
        assert_eq!(
            ordered.durable().scope().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::OrderedContent
        );

        let repo_cursor = sample_cursor(12);
        let repo = UnitCommitReceipt::new(
            CompletedUnit::repo_frontier(12, repo_cursor.clone()),
            sample_item_receipt(CheckpointBoundary::repo_frontier(repo_cursor)),
        )
        .expect("boundary matches");
        assert_eq!(
            repo.completed_unit().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
        assert_eq!(
            repo.durable().scope().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
    }

    #[test]
    fn checkpoint_aggregator_input_wraps_only_durable_receipts() {
        let cursor = sample_cursor(9);
        let completed = CompletedUnit::repo_frontier(9, cursor.clone());
        let durable = sample_item_receipt(CheckpointBoundary::repo_frontier(cursor));
        let receipt =
            UnitCommitReceipt::new(completed.clone(), durable.clone()).expect("boundary matches");
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

    #[test]
    fn completed_unit_into_parts_round_trip() {
        let cursor = sample_cursor(20);
        let unit = CompletedUnit::ordered_content(42, cursor.clone());
        let (seq, boundary) = unit.into_parts();
        assert_eq!(seq, 42);
        assert_eq!(boundary, CheckpointBoundary::ordered_content(cursor));
    }

    #[test]
    fn commit_request_into_parts_round_trip() {
        let unit = CompletedUnit::repo_frontier(7, sample_cursor(21));
        let findings = FindingsUpsertBatch::new(&[], &[], &[]);
        let request = CommitRequest::new(unit.clone(), findings, &[]);
        let (got_unit, got_findings, got_done_ledger) = request.into_parts();
        assert_eq!(got_unit, unit);
        assert!(got_findings.is_empty());
        assert!(got_done_ledger.is_empty());
    }

    #[test]
    fn unit_commit_receipt_into_parts_round_trip() {
        let cursor = sample_cursor(22);
        let unit = CompletedUnit::ordered_content(11, cursor.clone());
        let durable = sample_item_receipt(CheckpointBoundary::ordered_content(cursor));
        let receipt =
            UnitCommitReceipt::new(unit.clone(), durable.clone()).expect("boundary matches");
        let (got_unit, got_durable) = receipt.into_parts();
        assert_eq!(got_unit, unit);
        assert_eq!(got_durable, durable);
    }

    #[test]
    fn unit_commit_receipt_rejects_boundary_mismatch() {
        let unit = CompletedUnit::ordered_content(1, sample_cursor(1));
        let receipt = sample_item_receipt(CheckpointBoundary::repo_frontier(sample_cursor(1)));
        assert!(UnitCommitReceipt::new(unit, receipt).is_err());
    }

    #[test]
    fn unit_commit_receipt_rejects_same_kind_cursor_mismatch() {
        let unit = CompletedUnit::ordered_content(1, sample_cursor(1));
        let receipt = sample_item_receipt(CheckpointBoundary::ordered_content(sample_cursor(2)));
        assert!(
            UnitCommitReceipt::new(unit, receipt).is_err(),
            "same boundary kind but different cursor values must be rejected"
        );
    }
}
