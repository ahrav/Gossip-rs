//! Receipt-driven committed-prefix checkpoint aggregation for Epic 2.
//!
//! The runtime's checkpoint stage must never infer progress from raw scan
//! completion. It advances only from durable per-unit
//! [`CommitReceipt`](crate::commit_model::CommitReceipt) values that already
//! prove findings and done-ledger persistence.
//!
//! This module implements the shared prefix-commit primitive:
//!
//! - accept only [`CheckpointAggregatorInput`](crate::commit_model::CheckpointAggregatorInput),
//! - buffer out-of-order receipts by deterministic in-shard sequence number,
//! - prepare a checkpoint-ready prefix only when the next contiguous sequence is
//!   fully durable,
//! - hold that prepared prefix until the checkpoint receipt itself is durable,
//!   and
//! - normalize emitted checkpoint boundaries to key-only progress by dropping
//!   connector tokens.
//!
//! # Pattern
//!
//! This is a classic **contiguous-prefix commit** / **in-order advancement over
//! out-of-order completions** pattern. The aggregator behaves like a small
//! reorder buffer: later receipts may arrive early and are held until the
//! missing earlier receipt closes the gap. Only the highest contiguous durable
//! prefix may advance the frontier.
//!
//! # Why keep a pending checkpoint state?
//!
//! Prepared prefix state must survive until the checkpoint write itself becomes
//! durable. If the aggregator were to forget receipts as soon as it *prepared*
//! a prefix, a failed checkpoint attempt could create a progress ghost: the
//! runtime would believe the frontier had advanced even though no durable
//! checkpoint existed. This module therefore keeps a prepared prefix alive until
//! [`acknowledge_checkpoint`](PrefixCheckpointAggregator::acknowledge_checkpoint)
//! validates a durable [`CheckpointCommitReceipt`].

use std::collections::{BTreeMap, btree_map::Entry};
use std::{error::Error, fmt};

use gossip_contracts::{
    connector::{Cursor, ItemKey},
    identity::{FenceEpoch, RunId, ShardId, TenantId},
    persistence::{
        CheckpointBoundary, CheckpointBoundaryKind, CheckpointCommitReceipt, CommitScope,
        DoneLedgerCommitReceipt, FindingsCommitReceipt, ItemDurable, PageCommit,
        PageCommitReceipt, PageCommitValidationError, WriteContext,
    },
};

use crate::commit_model::{CheckpointAggregatorInput, CommitReceipt as RuntimeCommitReceipt};

/// Result of recording one per-unit durable receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRecordOutcome {
    /// The receipt was accepted into the in-memory reorder buffer.
    Buffered,
    /// The same durable receipt was already buffered for this sequence number.
    DuplicateBuffered,
    /// The receipt's sequence number is already durably checkpointed.
    AlreadyCheckpointed,
}

/// Highest contiguous durable prefix prepared for checkpoint persistence.
///
/// The carried [`PageCommit<ItemDurable>`] has already reconstructed the
/// durable findings + done-ledger proof for the whole contiguous prefix, so a
/// later checkpoint stage can drive it straight into
/// [`PageCommit::record_checkpoint`](gossip_contracts::persistence::PageCommit::record_checkpoint)
/// once a checkpoint receipt is available.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingPrefixCheckpoint {
    first_sequence_no: u64,
    last_sequence_no: u64,
    page: PageCommit<ItemDurable>,
}

impl PendingPrefixCheckpoint {
    /// First in-shard sequence number included in this prefix.
    #[inline]
    #[must_use]
    pub const fn first_sequence_no(&self) -> u64 {
        self.first_sequence_no
    }

    /// Last in-shard sequence number included in this prefix.
    #[inline]
    #[must_use]
    pub const fn last_sequence_no(&self) -> u64 {
        self.last_sequence_no
    }

    /// Number of newly committed units represented by this prefix.
    #[inline]
    #[must_use]
    pub fn committed_units(&self) -> u64 {
        self.page.scope().committed_units()
    }

    /// Family-neutral checkpoint boundary for the prefix.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary(&self) -> &CheckpointBoundary {
        self.page.scope().checkpoint_boundary()
    }

    /// Semantic family of the emitted checkpoint boundary.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary_kind(&self) -> CheckpointBoundaryKind {
        self.page.scope().checkpoint_boundary_kind()
    }

    /// Tokenless cursor the checkpoint write will make durable.
    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        self.page.scope().checkpoint_boundary().cursor()
    }

    /// Frozen aggregate commit scope for this prepared prefix.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &CommitScope {
        self.page.scope()
    }

    /// Aggregate item-commit proof reconstructed from the durable child
    /// receipts in this prefix.
    #[inline]
    #[must_use]
    pub fn item_commit_receipt(&self) -> &gossip_contracts::persistence::ItemCommitReceipt {
        self.page.item_commit_receipt()
    }

    /// Borrow the checkpoint-ready [`PageCommit<ItemDurable>`].
    #[inline]
    #[must_use]
    pub fn page_commit(&self) -> &PageCommit<ItemDurable> {
        &self.page
    }

    /// Consume the prepared prefix into the checkpoint-ready page commit.
    #[inline]
    #[must_use]
    pub fn into_page_commit(self) -> PageCommit<ItemDurable> {
        self.page
    }
}

/// Shared ownership scope extracted from either [`WriteContext`] or
/// [`CommitScope`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptOwner {
    tenant_id: TenantId,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
}

impl ReceiptOwner {
    #[inline]
    #[must_use]
    pub const fn from_write_context(write_context: WriteContext) -> Self {
        Self {
            tenant_id: write_context.tenant_id(),
            run_id: write_context.run_id(),
            shard_id: write_context.shard_id(),
            fence_epoch: write_context.fence_epoch(),
        }
    }

    #[inline]
    #[must_use]
    pub fn from_scope(scope: &CommitScope) -> Self {
        Self {
            tenant_id: scope.tenant_id(),
            run_id: scope.run_id(),
            shard_id: scope.shard_id(),
            fence_epoch: scope.fence_epoch(),
        }
    }
}

/// Receipt-only committed-prefix aggregator.
///
/// `PrefixCheckpointAggregator` is shard-local and single-family: once the
/// first receipt is accepted, all later receipts must carry the same
/// [`CheckpointBoundaryKind`].
#[derive(Clone, Debug)]
pub struct PrefixCheckpointAggregator {
    write_context: WriteContext,
    next_sequence_no: u64,
    checkpointed_units: u64,
    boundary_kind: Option<CheckpointBoundaryKind>,
    last_checkpoint_key: Option<ItemKey>,
    receipts: BTreeMap<u64, RuntimeCommitReceipt>,
    pending: Option<PendingPrefixCheckpoint>,
}

impl PrefixCheckpointAggregator {
    /// Construct a fresh aggregator starting at `next_sequence_no`.
    ///
    /// The caller is responsible for choosing the next not-yet-checkpointed
    /// in-shard sequence number. Later calls to
    /// [`acknowledge_checkpoint`](Self::acknowledge_checkpoint) advance this
    /// automatically as contiguous durable prefixes become durably
    /// checkpointed.
    #[must_use]
    pub fn new(write_context: WriteContext, next_sequence_no: u64) -> Self {
        Self {
            write_context,
            next_sequence_no,
            checkpointed_units: 0,
            boundary_kind: None,
            last_checkpoint_key: None,
            receipts: BTreeMap::new(),
            pending: None,
        }
    }

    /// Shared write context expected from all accepted receipts.
    #[inline]
    #[must_use]
    pub const fn write_context(&self) -> WriteContext {
        self.write_context
    }

    /// Next sequence number required before another prefix can be checkpointed.
    #[inline]
    #[must_use]
    pub const fn next_sequence_no(&self) -> u64 {
        self.next_sequence_no
    }

    /// Number of committed units durably checkpointed through this aggregator.
    #[inline]
    #[must_use]
    pub const fn checkpointed_units(&self) -> u64 {
        self.checkpointed_units
    }

    /// Pinned checkpoint-boundary family for this aggregator, if any receipt
    /// has been accepted already.
    #[inline]
    #[must_use]
    pub const fn checkpoint_boundary_kind(&self) -> Option<CheckpointBoundaryKind> {
        self.boundary_kind
    }

    /// Number of durable receipts currently retained by the aggregator.
    #[inline]
    #[must_use]
    pub fn buffered_receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Currently prepared checkpoint prefix, if any.
    #[inline]
    #[must_use]
    pub fn pending_checkpoint(&self) -> Option<&PendingPrefixCheckpoint> {
        self.pending.as_ref()
    }

    /// Record one durable per-unit receipt into the reorder buffer.
    ///
    /// Replayed receipts whose sequence number is already durably checkpointed
    /// are ignored idempotently. Replayed receipts for a still-buffered
    /// sequence are ignored only if they are byte-for-byte identical to the
    /// buffered one; conflicting duplicates are rejected as deterministic bugs.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixCheckpointError`] when the incoming receipt violates the
    /// shared runtime durability contract.
    pub fn record_receipt(
        &mut self,
        input: impl Into<CheckpointAggregatorInput>,
    ) -> Result<ReceiptRecordOutcome, PrefixCheckpointError> {
        let receipt = input.into().into_receipt();
        let sequence_no = receipt.completed_unit().sequence_no();
        let boundary_kind = validate_receipt(self.write_context, &receipt)?;

        match self.boundary_kind {
            Some(expected) if expected != boundary_kind => {
                return Err(PrefixCheckpointError::BoundaryKindMismatch {
                    expected,
                    actual: boundary_kind,
                });
            }
            None => self.boundary_kind = Some(boundary_kind),
            Some(_) => {}
        }

        if sequence_no < self.next_sequence_no {
            return Ok(ReceiptRecordOutcome::AlreadyCheckpointed);
        }

        match self.receipts.entry(sequence_no) {
            Entry::Vacant(slot) => {
                slot.insert(receipt);
                Ok(ReceiptRecordOutcome::Buffered)
            }
            Entry::Occupied(existing) if existing.get() == &receipt => {
                Ok(ReceiptRecordOutcome::DuplicateBuffered)
            }
            Entry::Occupied(_) => Err(PrefixCheckpointError::ConflictingReceiptForSequence {
                sequence_no,
            }),
        }
    }

    /// Convenience method: record a receipt and then attempt to prepare the
    /// next checkpointable committed prefix.
    ///
    /// This never marks progress durable by itself. The returned prefix remains
    /// pending until [`acknowledge_checkpoint`](Self::acknowledge_checkpoint)
    /// validates a durable checkpoint receipt.
    pub fn observe(
        &mut self,
        input: impl Into<CheckpointAggregatorInput>,
    ) -> Result<Option<PendingPrefixCheckpoint>, PrefixCheckpointError> {
        let _ = self.record_receipt(input)?;
        self.prepare_checkpoint()
    }

    /// Prepare the next contiguous durable prefix for checkpoint persistence.
    ///
    /// If a checkpoint prefix is already pending, this returns that exact
    /// prefix again and does not widen it. This preserves the invariant that a
    /// prepared prefix cannot silently grow before its checkpoint receipt is
    /// durably acknowledged.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixCheckpointError`] if the buffered receipts imply an
    /// invalid committed-prefix shape (for example a boundary regression or an
    /// impossible aggregate receipt).
    pub fn prepare_checkpoint(
        &mut self,
    ) -> Result<Option<PendingPrefixCheckpoint>, PrefixCheckpointError> {
        if let Some(pending) = self.pending.as_ref() {
            return Ok(Some(pending.clone()));
        }

        let Some(last_sequence_no) = self.contiguous_last_sequence_no() else {
            return Ok(None);
        };

        let pending = self.build_pending_checkpoint(last_sequence_no)?;
        self.pending = Some(pending.clone());
        Ok(Some(pending))
    }

    /// Finalize the prepared prefix after the checkpoint write becomes durable.
    ///
    /// The supplied [`CheckpointCommitReceipt`] must match the scope of the
    /// currently pending prepared prefix. On success, the prefix is forgotten,
    /// the contiguous durable receipts it covered are released, and the next
    /// required sequence number advances.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixCheckpointError::NoPendingCheckpoint`] if no prefix has
    /// been prepared, or [`PrefixCheckpointError::InvalidCheckpointReceipt`]
    /// if the durable checkpoint receipt does not match the prepared scope.
    pub fn acknowledge_checkpoint(
        &mut self,
        receipt: CheckpointCommitReceipt,
    ) -> Result<PageCommitReceipt, PrefixCheckpointError> {
        let pending = self
            .pending
            .take()
            .ok_or(PrefixCheckpointError::NoPendingCheckpoint)?;

        let checkpointed = match pending.page.clone().record_checkpoint(receipt) {
            Ok(page) => page,
            Err(err) => {
                self.pending = Some(pending);
                return Err(PrefixCheckpointError::InvalidCheckpointReceipt(err));
            }
        };

        for sequence_no in pending.first_sequence_no..=pending.last_sequence_no {
            self.receipts.remove(&sequence_no);
        }

        self.next_sequence_no = pending.last_sequence_no.saturating_add(1);
        self.checkpointed_units = self
            .checkpointed_units
            .checked_add(pending.committed_units())
            .ok_or(PrefixCheckpointError::CounterOverflow {
                field: "checkpointed_units",
            })?;
        self.last_checkpoint_key = pending.checkpoint_cursor().last_key().cloned();

        Ok(checkpointed.into_page_commit_receipt())
    }

    fn contiguous_last_sequence_no(&self) -> Option<u64> {
        let mut sequence_no = self.next_sequence_no;
        let mut last = None;
        while self.receipts.contains_key(&sequence_no) {
            last = Some(sequence_no);
            sequence_no = sequence_no.saturating_add(1);
            if sequence_no == u64::MAX && self.receipts.contains_key(&sequence_no) {
                last = Some(sequence_no);
                break;
            }
        }
        last
    }

    fn build_pending_checkpoint(
        &self,
        last_sequence_no: u64,
    ) -> Result<PendingPrefixCheckpoint, PrefixCheckpointError> {
        let first_sequence_no = self.next_sequence_no;

        let mut previous_key = self.last_checkpoint_key.clone();
        let mut checkpoint_boundary = None;
        let mut finding_count = 0_u64;
        let mut occurrence_count = 0_u64;
        let mut observation_count = 0_u64;
        let mut scanned_count = 0_u64;
        let mut ledger_findings_count = 0_u64;
        let mut committed_units = 0_u64;

        for sequence_no in first_sequence_no..=last_sequence_no {
            let receipt = self
                .receipts
                .get(&sequence_no)
                .expect("contiguous prefix must exist in the receipt buffer");

            let tokenless_boundary = strip_checkpoint_token(receipt.completed_unit().checkpoint_boundary())
                .ok_or(PrefixCheckpointError::MissingProgressKey { sequence_no })?;
            let current_key = tokenless_boundary
                .cursor()
                .last_key()
                .expect("tokenless checkpoint boundaries always keep last_key")
                .clone();

            if let Some(previous_key_ref) = previous_key.as_ref() {
                if current_key < *previous_key_ref {
                    return Err(PrefixCheckpointError::BoundaryRegression { sequence_no });
                }
            }

            previous_key = Some(current_key);
            checkpoint_boundary = Some(tokenless_boundary);

            let findings = receipt.durable().findings();
            finding_count = checked_add(
                finding_count,
                findings.finding_count(),
                sequence_no,
                "finding_count",
            )?;
            occurrence_count = checked_add(
                occurrence_count,
                findings.occurrence_count(),
                sequence_no,
                "occurrence_count",
            )?;
            observation_count = checked_add(
                observation_count,
                findings.observation_count(),
                sequence_no,
                "observation_count",
            )?;

            let done_ledger = receipt.durable().done_ledger();
            scanned_count = checked_add(
                scanned_count,
                done_ledger.scanned_count(),
                sequence_no,
                "scanned_count",
            )?;
            ledger_findings_count = checked_add(
                ledger_findings_count,
                done_ledger.findings_count(),
                sequence_no,
                "ledger_findings_count",
            )?;
            committed_units = checked_add(committed_units, 1, sequence_no, "committed_units")?;
        }

        let checkpoint_boundary = checkpoint_boundary
            .expect("non-empty contiguous prefix always has a last checkpoint boundary");
        let scope = CommitScope::from_write_context(
            self.write_context,
            committed_units,
            checkpoint_boundary,
        );
        let findings_receipt =
            FindingsCommitReceipt::new(finding_count, occurrence_count, observation_count);
        let done_ledger_receipt =
            DoneLedgerCommitReceipt::new(committed_units, scanned_count, ledger_findings_count);
        let page = PageCommit::new(scope)
            .record_findings(findings_receipt)
            .record_done_ledger(done_ledger_receipt)
            .map_err(PrefixCheckpointError::InvalidPreparedCheckpoint)?;

        Ok(PendingPrefixCheckpoint {
            first_sequence_no,
            last_sequence_no,
            page,
        })
    }
}

fn validate_receipt(
    write_context: WriteContext,
    receipt: &RuntimeCommitReceipt,
) -> Result<CheckpointBoundaryKind, PrefixCheckpointError> {
    let sequence_no = receipt.completed_unit().sequence_no();
    let scope = receipt.durable().scope();

    let expected_owner = ReceiptOwner::from_write_context(write_context);
    let actual_owner = ReceiptOwner::from_scope(scope);
    if actual_owner != expected_owner {
        return Err(PrefixCheckpointError::OwnershipMismatch {
            sequence_no,
            expected: expected_owner,
            actual: actual_owner,
        });
    }

    if scope.committed_units() != 1 {
        return Err(PrefixCheckpointError::PerUnitReceiptExpected {
            sequence_no,
            actual: scope.committed_units(),
        });
    }

    if scope.checkpoint_boundary() != receipt.completed_unit().checkpoint_boundary() {
        return Err(PrefixCheckpointError::ReceiptBoundaryMismatch { sequence_no });
    }

    if receipt.completed_unit().checkpoint_cursor().last_key().is_none() {
        return Err(PrefixCheckpointError::MissingProgressKey { sequence_no });
    }

    Ok(receipt.completed_unit().checkpoint_boundary_kind())
}

fn strip_checkpoint_token(boundary: &CheckpointBoundary) -> Option<CheckpointBoundary> {
    let last_key = boundary.cursor().last_key().cloned()?;
    let cursor = Cursor::with_last_key(last_key);
    Some(match boundary {
        CheckpointBoundary::OrderedContent(_) => CheckpointBoundary::ordered_content(cursor),
        CheckpointBoundary::RepoFrontier(_) => CheckpointBoundary::repo_frontier(cursor),
    })
}

fn checked_add(
    total: u64,
    next: u64,
    sequence_no: u64,
    field: &'static str,
) -> Result<u64, PrefixCheckpointError> {
    total.checked_add(next).ok_or(PrefixCheckpointError::CountOverflow {
        sequence_no,
        field,
    })
}

/// Deterministic contract violations from [`PrefixCheckpointAggregator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixCheckpointError {
    /// Incoming receipt belongs to a different tenant/run/shard/fence scope.
    OwnershipMismatch {
        /// Sequence number carried by the rejected receipt.
        sequence_no: u64,
        /// Ownership scope expected by the aggregator.
        expected: ReceiptOwner,
        /// Ownership scope carried by the durable receipt.
        actual: ReceiptOwner,
    },
    /// The durable scope disagreed with the runtime completed-unit boundary.
    ReceiptBoundaryMismatch {
        /// Sequence number carried by the rejected receipt.
        sequence_no: u64,
    },
    /// A committed unit must always carry a key-bearing checkpoint boundary.
    MissingProgressKey {
        /// Sequence number carried by the rejected receipt.
        sequence_no: u64,
    },
    /// The aggregator only accepts per-unit receipts.
    PerUnitReceiptExpected {
        /// Sequence number carried by the rejected receipt.
        sequence_no: u64,
        /// `scope.committed_units()` value carried by the receipt.
        actual: u64,
    },
    /// One aggregator instance must not mix ordered-content and repo-frontier
    /// receipts.
    BoundaryKindMismatch {
        /// Pinned boundary kind already accepted by this aggregator.
        expected: CheckpointBoundaryKind,
        /// Boundary kind of the newly observed receipt.
        actual: CheckpointBoundaryKind,
    },
    /// A second receipt arrived for the same still-buffered sequence number,
    /// but it did not match the buffered one exactly.
    ConflictingReceiptForSequence {
        /// Sequence number of the conflicting duplicate receipt.
        sequence_no: u64,
    },
    /// The contiguous prefix would move the checkpoint boundary backwards.
    BoundaryRegression {
        /// Sequence number whose boundary regressed relative to the already
        /// checkpointed floor or the previous receipt in the contiguous prefix.
        sequence_no: u64,
    },
    /// Aggregating receipt counts overflowed `u64`.
    CountOverflow {
        /// Sequence number whose receipt caused the overflow.
        sequence_no: u64,
        /// Counter field that overflowed.
        field: &'static str,
    },
    /// Reconstructing the pending checkpoint-ready aggregate receipt failed.
    InvalidPreparedCheckpoint(PageCommitValidationError),
    /// The runtime tried to acknowledge a checkpoint when none was pending.
    NoPendingCheckpoint,
    /// The supplied checkpoint receipt did not match the pending checkpoint
    /// scope.
    InvalidCheckpointReceipt(PageCommitValidationError),
    /// A counter tracking durable checkpoint progress overflowed.
    CounterOverflow {
        /// Counter field that overflowed.
        field: &'static str,
    },
}

impl fmt::Display for PrefixCheckpointError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OwnershipMismatch {
                sequence_no,
                expected,
                actual,
            } => write!(
                f,
                "receipt for sequence {sequence_no} had owner scope {actual:?}, expected {expected:?}"
            ),
            Self::ReceiptBoundaryMismatch { sequence_no } => write!(
                f,
                "durable receipt for sequence {sequence_no} did not match its completed-unit boundary"
            ),
            Self::MissingProgressKey { sequence_no } => write!(
                f,
                "receipt for sequence {sequence_no} did not carry a key-bearing checkpoint boundary"
            ),
            Self::PerUnitReceiptExpected {
                sequence_no,
                actual,
            } => write!(
                f,
                "receipt for sequence {sequence_no} represented {actual} committed units; expected exactly 1"
            ),
            Self::BoundaryKindMismatch { expected, actual } => write!(
                f,
                "checkpoint boundary kind mismatch: expected {expected:?}, got {actual:?}"
            ),
            Self::ConflictingReceiptForSequence { sequence_no } => write!(
                f,
                "conflicting durable receipts arrived for sequence {sequence_no}"
            ),
            Self::BoundaryRegression { sequence_no } => write!(
                f,
                "checkpoint boundary regressed while aggregating sequence {sequence_no}"
            ),
            Self::CountOverflow { sequence_no, field } => write!(
                f,
                "aggregating {field} overflowed while processing sequence {sequence_no}"
            ),
            Self::InvalidPreparedCheckpoint(err) => {
                write!(f, "reconstructed aggregate receipt was invalid: {err}")
            }
            Self::NoPendingCheckpoint => {
                write!(f, "no checkpoint prefix is currently prepared")
            }
            Self::InvalidCheckpointReceipt(err) => {
                write!(f, "durable checkpoint receipt did not match the pending prefix: {err}")
            }
            Self::CounterOverflow { field } => {
                write!(f, "checkpoint progress counter '{field}' overflowed")
            }
        }
    }
}

impl Error for PrefixCheckpointError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidPreparedCheckpoint(err) | Self::InvalidCheckpointReceipt(err) => Some(err),
            Self::OwnershipMismatch { .. }
            | Self::ReceiptBoundaryMismatch { .. }
            | Self::MissingProgressKey { .. }
            | Self::PerUnitReceiptExpected { .. }
            | Self::BoundaryKindMismatch { .. }
            | Self::ConflictingReceiptForSequence { .. }
            | Self::BoundaryRegression { .. }
            | Self::CountOverflow { .. }
            | Self::NoPendingCheckpoint
            | Self::CounterOverflow { .. } => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::{
        connector::{ItemKey, TokenBytes},
        identity::{LogicalTime, PolicyHash},
        persistence::{CheckpointBoundary, DoneLedgerCommitReceipt, FindingsCommitReceipt},
    };

    use crate::commit_model::{CommitReceipt, CompletedUnit};

    fn item_key(byte: u8) -> ItemKey {
        ItemKey::try_from_slice(&[byte]).expect("item key")
    }

    fn cursor_with_token(last_key: u8, token: u8) -> Cursor {
        Cursor::with_token(
            item_key(last_key),
            TokenBytes::try_from_slice(&[token]).expect("token"),
        )
    }

    fn cursor_without_token(last_key: u8) -> Cursor {
        Cursor::with_last_key(item_key(last_key))
    }

    fn write_context(seed: u8) -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([seed; 32]),
            PolicyHash::from_bytes([seed.wrapping_add(1); 32]),
            RunId::from_raw(seed as u64 + 10),
            ShardId::from_raw(seed as u64 + 20),
            FenceEpoch::from_raw(seed as u64 + 30),
        )
    }

    fn runtime_receipt(
        write_context: WriteContext,
        sequence_no: u64,
        checkpoint_boundary: CheckpointBoundary,
        findings: FindingsCommitReceipt,
        done_ledger: DoneLedgerCommitReceipt,
    ) -> CommitReceipt {
        let scope = CommitScope::from_write_context(write_context, 1, checkpoint_boundary.clone());
        let durable = PageCommit::new(scope)
            .record_findings(findings)
            .record_done_ledger(done_ledger)
            .expect("per-unit done-ledger receipt must match one committed unit")
            .into_item_commit_receipt();

        CommitReceipt::new(CompletedUnit::new(sequence_no, checkpoint_boundary), durable)
    }

    fn ordered_receipt(
        write_context: WriteContext,
        sequence_no: u64,
        cursor: Cursor,
        findings_count: u64,
    ) -> CommitReceipt {
        runtime_receipt(
            write_context,
            sequence_no,
            CheckpointBoundary::ordered_content(cursor),
            FindingsCommitReceipt::new(findings_count, findings_count + 1, findings_count + 2),
            DoneLedgerCommitReceipt::new(1, 1, findings_count),
        )
    }

    fn repo_receipt(write_context: WriteContext, sequence_no: u64, cursor: Cursor) -> CommitReceipt {
        runtime_receipt(
            write_context,
            sequence_no,
            CheckpointBoundary::repo_frontier(cursor),
            FindingsCommitReceipt::new(1, 2, 3),
            DoneLedgerCommitReceipt::new(1, 1, 1),
        )
    }

    #[test]
    fn prefix_checkpoint_waits_for_contiguous_receipts() {
        let write_context = write_context(0x11);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 10);

        assert_eq!(
            aggregator
                .record_receipt(ordered_receipt(write_context, 11, cursor_with_token(b'b', 0xAA), 2))
                .expect("out-of-order receipt should buffer"),
            ReceiptRecordOutcome::Buffered
        );
        assert!(aggregator.prepare_checkpoint().unwrap().is_none());
        assert_eq!(aggregator.next_sequence_no(), 10);
        assert_eq!(aggregator.buffered_receipt_count(), 1);

        assert_eq!(
            aggregator
                .record_receipt(ordered_receipt(write_context, 10, cursor_with_token(b'a', 0xBB), 1))
                .expect("gap-closing receipt should buffer"),
            ReceiptRecordOutcome::Buffered
        );

        let pending = aggregator
            .prepare_checkpoint()
            .expect("contiguous durable receipts should prepare a checkpoint")
            .expect("prefix should now be checkpointable");

        assert_eq!(pending.first_sequence_no(), 10);
        assert_eq!(pending.last_sequence_no(), 11);
        assert_eq!(pending.committed_units(), 2);
        assert_eq!(pending.checkpoint_boundary_kind(), CheckpointBoundaryKind::OrderedContent);
        assert_eq!(pending.checkpoint_cursor().last_key(), Some(&item_key(b'b')));
        assert!(pending.checkpoint_cursor().token().is_none());
        assert_eq!(
            pending.item_commit_receipt().findings(),
            FindingsCommitReceipt::new(3, 5, 7)
        );
        assert_eq!(
            pending.item_commit_receipt().done_ledger(),
            DoneLedgerCommitReceipt::new(2, 2, 3)
        );
        assert_eq!(aggregator.next_sequence_no(), 10);
        assert_eq!(aggregator.buffered_receipt_count(), 2);

        let page_receipt = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(42),
            ))
            .expect("durable checkpoint receipt should finalize the prepared prefix");

        assert_eq!(page_receipt.item_commit().scope().committed_units(), 2);
        assert_eq!(aggregator.next_sequence_no(), 12);
        assert_eq!(aggregator.checkpointed_units(), 2);
        assert_eq!(aggregator.buffered_receipt_count(), 0);
        assert!(aggregator.pending_checkpoint().is_none());
    }

    #[test]
    fn prefix_commit_drops_resume_token_but_preserves_last_key() {
        let write_context = write_context(0x22);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);

        aggregator
            .record_receipt(ordered_receipt(write_context, 0, cursor_with_token(b'k', 0x44), 4))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap();

        assert_eq!(pending.checkpoint_cursor().last_key(), Some(&item_key(b'k')));
        assert!(pending.checkpoint_cursor().token().is_none());
    }

    #[test]
    fn duplicate_and_already_checkpointed_receipts_are_idempotent() {
        let write_context = write_context(0x33);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);
        let receipt = ordered_receipt(write_context, 0, cursor_without_token(b'a'), 1);

        assert_eq!(
            aggregator.record_receipt(receipt.clone()).unwrap(),
            ReceiptRecordOutcome::Buffered
        );
        assert_eq!(
            aggregator.record_receipt(receipt.clone()).unwrap(),
            ReceiptRecordOutcome::DuplicateBuffered
        );

        let pending = aggregator.prepare_checkpoint().unwrap().unwrap();
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(99),
            ))
            .unwrap();

        assert_eq!(
            aggregator.record_receipt(receipt).unwrap(),
            ReceiptRecordOutcome::AlreadyCheckpointed
        );
    }

    #[test]
    fn conflicting_duplicate_sequence_is_rejected() {
        let write_context = write_context(0x44);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 1);

        aggregator
            .record_receipt(ordered_receipt(write_context, 1, cursor_without_token(b'b'), 1))
            .unwrap();

        let error = aggregator
            .record_receipt(ordered_receipt(write_context, 1, cursor_without_token(b'c'), 1))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::ConflictingReceiptForSequence { sequence_no: 1 }
        );
    }

    #[test]
    fn mismatched_write_scope_is_rejected() {
        let expected = write_context(0x55);
        let actual = write_context(0x56);
        let mut aggregator = PrefixCheckpointAggregator::new(expected, 0);

        let error = aggregator
            .record_receipt(ordered_receipt(actual, 0, cursor_without_token(b'a'), 1))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::OwnershipMismatch {
                sequence_no: 0,
                expected: ReceiptOwner::from_write_context(expected),
                actual: ReceiptOwner::from_write_context(actual),
            }
        );
    }

    #[test]
    fn checkpoint_scope_mismatch_keeps_pending_for_retry() {
        let write_context = write_context(0x66);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);

        aggregator
            .record_receipt(ordered_receipt(write_context, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap();

        let wrong_scope = CommitScope::from_write_context(
            write_context,
            1,
            CheckpointBoundary::ordered_content(cursor_without_token(b'z')),
        );
        let error = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                wrong_scope,
                LogicalTime::from_raw(7),
            ))
            .unwrap_err();

        assert!(matches!(
            error,
            PrefixCheckpointError::InvalidCheckpointReceipt(
                PageCommitValidationError::CheckpointScopeMismatch
            )
        ));
        assert!(aggregator.pending_checkpoint().is_some());
        assert_eq!(aggregator.next_sequence_no(), 0);
        assert_eq!(aggregator.buffered_receipt_count(), 1);

        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(8),
            ))
            .expect("correct retry should succeed");
        assert_eq!(aggregator.next_sequence_no(), 1);
    }

    #[test]
    fn cannot_ack_checkpoint_without_pending_prefix() {
        let mut aggregator = PrefixCheckpointAggregator::new(write_context(0x77), 0);

        let error = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                CommitScope::from_write_context(
                    write_context(0x77),
                    1,
                    CheckpointBoundary::ordered_content(cursor_without_token(b'a')),
                ),
                LogicalTime::from_raw(9),
            ))
            .unwrap_err();

        assert_eq!(error, PrefixCheckpointError::NoPendingCheckpoint);
    }

    #[test]
    fn boundary_kind_is_frozen_from_first_receipt() {
        let write_context = write_context(0x88);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);

        aggregator
            .record_receipt(ordered_receipt(write_context, 0, cursor_without_token(b'a'), 1))
            .unwrap();

        let error = aggregator
            .record_receipt(repo_receipt(write_context, 1, cursor_without_token(b'b')))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryKindMismatch {
                expected: CheckpointBoundaryKind::OrderedContent,
                actual: CheckpointBoundaryKind::RepoFrontier,
            }
        );
    }

    #[test]
    fn boundary_regression_is_rejected_when_building_prefix() {
        let write_context = write_context(0x99);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);

        aggregator
            .record_receipt(ordered_receipt(write_context, 1, cursor_without_token(b'a'), 1))
            .unwrap();
        aggregator
            .record_receipt(ordered_receipt(write_context, 0, cursor_without_token(b'b'), 1))
            .unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(error, PrefixCheckpointError::BoundaryRegression { sequence_no: 1 });
    }

    #[test]
    fn observe_convenience_method_records_then_prepares() {
        let write_context = write_context(0xAB);
        let mut aggregator = PrefixCheckpointAggregator::new(write_context, 0);

        assert!(aggregator
            .observe(ordered_receipt(write_context, 1, cursor_without_token(b'b'), 1))
            .unwrap()
            .is_none());

        let pending = aggregator
            .observe(ordered_receipt(write_context, 0, cursor_with_token(b'a', 0x10), 4))
            .unwrap()
            .expect("gap closure should prepare a prefix");

        assert_eq!(pending.first_sequence_no(), 0);
        assert_eq!(pending.last_sequence_no(), 1);
        assert_eq!(pending.scope().committed_units(), 2);
        assert!(aggregator.pending_checkpoint().is_some());
    }
}
