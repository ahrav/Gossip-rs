//! Receipt-driven committed-prefix checkpoint aggregation.
//!
//! The checkpoint stage advances only from durable per-unit receipts that
//! already prove findings and done-ledger persistence. It never infers
//! progress from raw scan completion.

use std::collections::{BTreeMap, btree_map::Entry};
use std::num::NonZeroU64;
use std::{error::Error, fmt};

use gossip_contracts::{
    connector::{Cursor, ItemKey},
    persistence::{
        CheckpointBoundary, CheckpointBoundaryKind, CheckpointCommitReceipt, CommitScope,
        DoneLedgerCommitReceipt, FindingsCommitReceipt, ItemCommitReceipt, ItemDurable, PageCommit,
        PageCommitReceipt, PageCommitValidationError, WriteContext,
    },
};

use crate::commit_model::{CheckpointAggregatorInput, UnitCommitReceipt};

/// Result of recording one durable per-unit receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptRecordOutcome {
    /// The receipt was accepted into the reorder buffer.
    Buffered,
    /// The same receipt was already buffered for this sequence number.
    DuplicateBuffered,
    /// The receipt's sequence number is already durably checkpointed.
    AlreadyCheckpointed,
}

/// Highest contiguous durable prefix prepared for checkpoint persistence.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "pending checkpoints must be acknowledged or explicitly dropped"]
pub struct PendingPrefixCheckpoint {
    first_sequence_no: u64,
    last_sequence_no: u64,
    page: PageCommit<ItemDurable>,
}

impl PendingPrefixCheckpoint {
    /// First sequence number included in this prefix.
    #[inline]
    #[must_use]
    pub const fn first_sequence_no(&self) -> u64 {
        self.first_sequence_no
    }

    /// Last sequence number included in this prefix.
    #[inline]
    #[must_use]
    pub const fn last_sequence_no(&self) -> u64 {
        self.last_sequence_no
    }

    /// Number of committed units represented by this prefix.
    #[inline]
    #[must_use]
    pub fn committed_units(&self) -> u64 {
        self.page.scope().committed_units().get()
    }

    /// Tokenless cursor that will be stored durably if checkpointing succeeds.
    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        self.page.scope().checkpoint_cursor()
    }

    /// Aggregate commit scope for the prepared prefix.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &CommitScope {
        self.page.scope()
    }

    /// Aggregate item-level receipt reconstructed from the buffered prefix.
    #[inline]
    #[must_use]
    pub fn item_commit_receipt(&self) -> &ItemCommitReceipt {
        self.page.item_commit_receipt()
    }
}

/// Deterministic contract violations from [`PrefixCheckpointAggregator`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrefixCheckpointError {
    /// Incoming receipt belongs to a different tenant/run/shard/fence scope.
    OwnershipMismatch {
        sequence_no: u64,
        expected: Box<WriteContext>,
        actual: Box<WriteContext>,
    },
    /// The durable scope disagreed with the runtime completed-unit boundary.
    ReceiptBoundaryMismatch { sequence_no: u64 },
    /// A committed unit must always carry a key-bearing checkpoint boundary.
    MissingProgressKey { sequence_no: u64 },
    /// The aggregator only accepts per-unit receipts.
    PerUnitReceiptExpected { sequence_no: u64, actual: u64 },
    /// One aggregator instance must not mix ordered-content and repo-frontier
    /// receipts.
    BoundaryKindMismatch {
        expected: CheckpointBoundaryKind,
        actual: CheckpointBoundaryKind,
    },
    /// A second receipt arrived for the same still-buffered sequence number,
    /// but it did not match the buffered one exactly.
    ConflictingReceiptForSequence { sequence_no: u64 },
    /// The contiguous prefix would move the checkpoint boundary backwards.
    BoundaryRegression { sequence_no: u64 },
    /// Ordered-content mode requires strictly increasing keys at checkpoint
    /// unit boundaries. Equal keys would cause tokenless resume (which uses
    /// strictly-greater-than semantics) to skip items.
    ///
    /// This error is **unrecoverable** through the aggregator's public API:
    /// the offending receipt remains in the reorder buffer and no method can
    /// remove it. Callers that encounter this error must discard the
    /// aggregator and reconstruct it from the last acknowledged checkpoint.
    OrderedContentEqualKey { sequence_no: u64 },
    /// The reorder buffer has reached its configured capacity. The caller
    /// should drain the buffer by acknowledging a pending checkpoint before
    /// submitting more receipts.
    BufferFull { buffered: usize, capacity: usize },
    /// A `u64` counter overflowed during prefix aggregation or acknowledgement.
    CountOverflow {
        sequence_no: Option<u64>,
        field: &'static str,
    },
    /// Reconstructing the pending aggregate page commit failed validation.
    InvalidPreparedCheckpoint(PageCommitValidationError),
    /// The runtime tried to acknowledge a checkpoint when none was pending.
    NoPendingCheckpoint,
    /// The supplied checkpoint receipt did not match the pending checkpoint.
    InvalidCheckpointReceipt(PageCommitValidationError),
    /// An internal invariant was violated during prefix construction.
    InternalInconsistency { detail: &'static str },
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
            Self::OrderedContentEqualKey { sequence_no } => write!(
                f,
                "ordered-content checkpoint key at sequence {sequence_no} equals the previous \
                 key; strictly increasing keys are required for safe tokenless resume"
            ),
            Self::BufferFull { buffered, capacity } => write!(
                f,
                "reorder buffer is full ({buffered}/{capacity}); acknowledge a pending \
                 checkpoint to drain buffered receipts"
            ),
            Self::CountOverflow {
                sequence_no: Some(seq),
                field,
            } => write!(
                f,
                "aggregating {field} overflowed while processing sequence {seq}"
            ),
            Self::CountOverflow {
                sequence_no: None,
                field,
            } => write!(f, "checkpoint progress counter '{field}' overflowed"),
            Self::InvalidPreparedCheckpoint(err) => {
                write!(f, "reconstructed aggregate receipt was invalid: {err}")
            }
            Self::NoPendingCheckpoint => {
                write!(f, "no checkpoint prefix is currently prepared")
            }
            Self::InvalidCheckpointReceipt(err) => {
                write!(
                    f,
                    "durable checkpoint receipt did not match the pending prefix: {err}"
                )
            }
            Self::InternalInconsistency { detail } => {
                write!(f, "internal inconsistency: {detail}")
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
            | Self::OrderedContentEqualKey { .. }
            | Self::BufferFull { .. }
            | Self::CountOverflow { .. }
            | Self::NoPendingCheckpoint
            | Self::InternalInconsistency { .. } => None,
        }
    }
}

/// Receipt-only committed-prefix aggregator.
#[derive(Clone, Debug)]
pub struct PrefixCheckpointAggregator {
    write_context: WriteContext,
    next_sequence_no: u64,
    checkpointed_units: u64,
    max_buffered: usize,
    boundary_kind: Option<CheckpointBoundaryKind>,
    last_checkpoint_key: Option<ItemKey>,
    receipts: BTreeMap<u64, UnitCommitReceipt>,
    pending: Option<PendingPrefixCheckpoint>,
}

impl PrefixCheckpointAggregator {
    /// Construct a fresh aggregator starting at `next_sequence_no`.
    ///
    /// `max_buffered` sets the maximum number of out-of-order receipts the
    /// reorder buffer will hold before returning [`PrefixCheckpointError::BufferFull`].
    /// Callers should choose a capacity that matches the per-shard in-flight
    /// window.
    ///
    /// # Panics
    ///
    /// Panics if `max_buffered` is zero. A zero-capacity buffer rejects every
    /// receipt and can never make progress.
    #[must_use]
    pub fn new(write_context: WriteContext, next_sequence_no: u64, max_buffered: usize) -> Self {
        assert!(
            max_buffered > 0,
            "max_buffered must be at least 1; a zero-capacity buffer can never make progress"
        );
        Self {
            write_context,
            next_sequence_no,
            checkpointed_units: 0,
            max_buffered,
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

    /// Next sequence number needed before another prefix can be prepared.
    #[inline]
    #[must_use]
    pub const fn next_sequence_no(&self) -> u64 {
        self.next_sequence_no
    }

    /// Number of units durably checkpointed through this aggregator instance.
    #[inline]
    #[must_use]
    pub const fn checkpointed_units(&self) -> u64 {
        self.checkpointed_units
    }

    /// Pinned boundary kind for this shard stream, if any receipt was accepted.
    #[inline]
    #[must_use]
    pub const fn checkpoint_boundary_kind(&self) -> Option<CheckpointBoundaryKind> {
        self.boundary_kind
    }

    /// Number of receipts currently buffered.
    #[inline]
    #[must_use]
    pub fn buffered_receipt_count(&self) -> usize {
        self.receipts.len()
    }

    /// Configured maximum number of receipts the reorder buffer will hold.
    #[inline]
    #[must_use]
    pub const fn buffer_capacity(&self) -> usize {
        self.max_buffered
    }

    /// Currently prepared checkpoint prefix, if any.
    #[inline]
    #[must_use]
    pub fn pending_checkpoint(&self) -> Option<&PendingPrefixCheckpoint> {
        self.pending.as_ref()
    }

    /// Discard the currently prepared checkpoint prefix without acknowledging
    /// it. Returns the discarded prefix, if any. Buffered receipts are not
    /// released; a subsequent `prepare_checkpoint` can reconstruct the prefix
    /// from them.
    #[inline]
    pub fn discard_pending(&mut self) -> Option<PendingPrefixCheckpoint> {
        self.pending.take()
    }

    /// Record one durable per-unit receipt into the reorder buffer.
    ///
    /// Replayed receipts whose sequence number is already durably checkpointed
    /// are ignored idempotently. Replayed receipts for a still-buffered
    /// sequence are ignored only if they are structurally identical (by
    /// `PartialEq`) to the buffered one.
    ///
    /// The reorder buffer is bounded by `max_buffered` (set at construction).
    /// When a new receipt would exceed this capacity, `BufferFull` is returned.
    /// The receipt at exactly `next_sequence_no` is always admitted regardless
    /// of capacity, because it fills the head gap needed for prefix
    /// construction and draining. Acknowledging a pending checkpoint drains
    /// buffered receipts and re-enables insertion.
    ///
    /// # Errors
    ///
    /// Returns [`PrefixCheckpointError`] when the incoming receipt violates the
    /// checkpoint aggregation contract or when the buffer is full.
    pub fn record_receipt(
        &mut self,
        input: CheckpointAggregatorInput,
    ) -> Result<ReceiptRecordOutcome, PrefixCheckpointError> {
        let receipt = input.into_receipt();
        let sequence_no = receipt.completed_unit().sequence_no();
        let boundary_kind = validate_receipt(self.write_context, &receipt)?;

        if sequence_no < self.next_sequence_no {
            return Ok(ReceiptRecordOutcome::AlreadyCheckpointed);
        }

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

        let len = self.receipts.len();
        match self.receipts.entry(sequence_no) {
            Entry::Vacant(slot) => {
                // Always admit the receipt at `next_sequence_no` even when the
                // buffer is at capacity. This receipt fills the gap at the head
                // of the contiguous run, enabling prefix construction and
                // draining via `acknowledge_checkpoint`. Rejecting it would
                // permanently block progress because no other API can drain
                // buffered out-of-order receipts.
                let is_gap_filler = sequence_no == self.next_sequence_no;
                if !is_gap_filler && len >= self.max_buffered {
                    return Err(PrefixCheckpointError::BufferFull {
                        buffered: len,
                        capacity: self.max_buffered,
                    });
                }
                slot.insert(receipt);
                Ok(ReceiptRecordOutcome::Buffered)
            }
            Entry::Occupied(existing) if existing.get() == &receipt => {
                Ok(ReceiptRecordOutcome::DuplicateBuffered)
            }
            Entry::Occupied(_) => {
                Err(PrefixCheckpointError::ConflictingReceiptForSequence { sequence_no })
            }
        }
    }

    /// Prepare the next contiguous durable prefix for checkpoint persistence.
    ///
    /// If a prefix is already pending, this returns that same prefix again
    /// without widening it. The returned reference borrows from the aggregator.
    ///
    /// # Fatal errors
    ///
    /// [`PrefixCheckpointError::OrderedContentEqualKey`] and
    /// [`PrefixCheckpointError::BoundaryRegression`] are **not recoverable**
    /// through the aggregator's API. The offending receipt remains in the
    /// buffer and every subsequent call will return the same error. Callers
    /// must discard the aggregator and reconstruct it from the last
    /// acknowledged checkpoint.
    pub fn prepare_checkpoint(
        &mut self,
    ) -> Result<Option<&PendingPrefixCheckpoint>, PrefixCheckpointError> {
        if self.pending.is_some() {
            return Ok(self.pending.as_ref());
        }

        if let Some(pending) = self.build_contiguous_prefix()? {
            self.pending = Some(pending);
        }
        Ok(self.pending.as_ref())
    }

    /// Finalize the prepared prefix after the checkpoint write becomes durable.
    ///
    /// On success, the prefix is forgotten, the buffered receipts it covered
    /// are released, and the next required sequence number advances.
    ///
    /// On counter overflow the pending prefix is restored but the error is
    /// deterministic — retrying with the same inputs produces the same
    /// failure. On scope mismatch from `record_checkpoint`, the pending
    /// prefix is also restored; the caller can retry with a corrected
    /// `CheckpointCommitReceipt`. Returns `NoPendingCheckpoint` without
    /// modifying aggregator state if no prefix has been prepared.
    pub fn acknowledge_checkpoint(
        &mut self,
        receipt: CheckpointCommitReceipt,
    ) -> Result<PageCommitReceipt, PrefixCheckpointError> {
        let pending = self
            .pending
            .take()
            .ok_or(PrefixCheckpointError::NoPendingCheckpoint)?;

        // Validate arithmetic before consuming the receipt so the pending
        // prefix remains intact on overflow.
        let new_next_sequence_no =
            pending
                .last_sequence_no
                .checked_add(1)
                .ok_or(PrefixCheckpointError::CountOverflow {
                    sequence_no: None,
                    field: "next_sequence_no",
                });
        let new_checkpointed_units = self
            .checkpointed_units
            .checked_add(pending.committed_units())
            .ok_or(PrefixCheckpointError::CountOverflow {
                sequence_no: None,
                field: "checkpointed_units",
            });

        // When both counters overflow, only the first error (`next_sequence_no`)
        // is reported. This is intentional: the recovery action (unable to
        // advance the checkpoint) is the same regardless of which counter
        // saturated.
        let (new_next_sequence_no, new_checkpointed_units) =
            match (new_next_sequence_no, new_checkpointed_units) {
                (Ok(next_sequence_no), Ok(checkpointed_units)) => {
                    (next_sequence_no, checkpointed_units)
                }
                (Err(err), _) | (_, Err(err)) => {
                    self.pending = Some(pending);
                    return Err(err);
                }
            };

        let checkpointed = match pending.page.clone().record_checkpoint(receipt) {
            Ok(page) => page,
            Err(err) => {
                self.pending = Some(pending);
                return Err(PrefixCheckpointError::InvalidCheckpointReceipt(err));
            }
        };

        // The overflow check on `pending.last_sequence_no + 1` at the top of
        // this method guarantees this addition cannot overflow.
        self.receipts = self.receipts.split_off(&(pending.last_sequence_no + 1));

        self.next_sequence_no = new_next_sequence_no;
        self.checkpointed_units = new_checkpointed_units;
        self.last_checkpoint_key = pending.checkpoint_cursor().last_key().cloned();

        Ok(checkpointed.into_page_commit_receipt())
    }

    /// Single-pass contiguous prefix discovery and construction.
    ///
    /// Iterates the reorder buffer once from `next_sequence_no`, verifying
    /// contiguity, enforcing boundary monotonicity, and accumulating totals
    /// in a single traversal.
    fn build_contiguous_prefix(
        &self,
    ) -> Result<Option<PendingPrefixCheckpoint>, PrefixCheckpointError> {
        let first_sequence_no = self.next_sequence_no;
        let mut expected = first_sequence_no;
        let mut previous_key: Option<&ItemKey> = self.last_checkpoint_key.as_ref();
        let mut totals = Totals::default();
        let mut last_sequence_no = None;
        let mut last_boundary: Option<&CheckpointBoundary> = None;

        for (&sequence_no, receipt) in self.receipts.range(expected..) {
            if sequence_no != expected {
                break;
            }

            let current_key = receipt
                .completed_unit()
                .checkpoint_cursor()
                .last_key()
                .ok_or(PrefixCheckpointError::MissingProgressKey { sequence_no })?;

            if let Some(prev) = previous_key {
                if current_key < prev {
                    return Err(PrefixCheckpointError::BoundaryRegression { sequence_no });
                }
                // Ordered-content requires strictly increasing keys at
                // checkpoint unit boundaries. Tokenless resume uses
                // strictly-greater-than semantics, so equal keys would
                // cause items to be skipped on recovery. Repo-frontier
                // allows equal keys because multiple units can share the
                // same ItemKey.
                if current_key == prev
                    && self.boundary_kind == Some(CheckpointBoundaryKind::OrderedContent)
                {
                    return Err(PrefixCheckpointError::OrderedContentEqualKey { sequence_no });
                }
            }
            previous_key = Some(current_key);

            totals.accumulate(receipt, sequence_no)?;
            last_sequence_no = Some(sequence_no);
            last_boundary = Some(receipt.completed_unit().checkpoint_boundary());

            let Some(next) = expected.checked_add(1) else {
                break;
            };
            expected = next;
        }

        let Some(last_seq) = last_sequence_no else {
            return Ok(None);
        };
        // `last_boundary` is always `Some` when `last_sequence_no` is `Some`
        // because both are set in the same loop iteration.
        let boundary = last_boundary.expect("set in the same iteration as last_sequence_no");

        let checkpoint_boundary =
            strip_checkpoint_token(boundary).ok_or(PrefixCheckpointError::MissingProgressKey {
                sequence_no: last_seq,
            })?;
        let committed_units = NonZeroU64::new(totals.committed_units).ok_or(
            PrefixCheckpointError::InternalInconsistency {
                detail: "non-empty contiguous prefix committed zero units",
            },
        )?;
        let scope = CommitScope::from_write_context(
            self.write_context,
            committed_units,
            checkpoint_boundary,
        );
        let findings_receipt = FindingsCommitReceipt::new(
            totals.finding_count,
            totals.occurrence_count,
            totals.observation_count,
        );
        let done_ledger_receipt = DoneLedgerCommitReceipt::new(
            totals.record_count,
            totals.scanned_count,
            totals.done_ledger_findings_count,
        );
        let page = PageCommit::new(scope)
            .record_findings(findings_receipt)
            .record_done_ledger(done_ledger_receipt)
            .map_err(PrefixCheckpointError::InvalidPreparedCheckpoint)?;

        Ok(Some(PendingPrefixCheckpoint {
            first_sequence_no,
            last_sequence_no: last_seq,
            page,
        }))
    }
}

const _: fn() = || {
    fn assert_impl<T: Send + Sync>() {}
    assert_impl::<PrefixCheckpointAggregator>();
    assert_impl::<PendingPrefixCheckpoint>();
};

fn validate_receipt(
    write_context: WriteContext,
    receipt: &UnitCommitReceipt,
) -> Result<CheckpointBoundaryKind, PrefixCheckpointError> {
    let sequence_no = receipt.completed_unit().sequence_no();
    let scope = receipt.durable().scope();

    let actual_write_context = scope.write_context();
    if actual_write_context != write_context {
        return Err(PrefixCheckpointError::OwnershipMismatch {
            sequence_no,
            expected: Box::new(write_context),
            actual: Box::new(actual_write_context),
        });
    }

    if scope.committed_units().get() != 1 {
        return Err(PrefixCheckpointError::PerUnitReceiptExpected {
            sequence_no,
            actual: scope.committed_units().get(),
        });
    }

    if scope.checkpoint_boundary() != receipt.completed_unit().checkpoint_boundary() {
        return Err(PrefixCheckpointError::ReceiptBoundaryMismatch { sequence_no });
    }

    if receipt
        .completed_unit()
        .checkpoint_cursor()
        .last_key()
        .is_none()
    {
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

/// Running totals accumulated across receipts in a contiguous prefix.
#[derive(Default)]
struct Totals {
    finding_count: u64,
    occurrence_count: u64,
    observation_count: u64,
    record_count: u64,
    scanned_count: u64,
    done_ledger_findings_count: u64,
    committed_units: u64,
}

impl Totals {
    fn accumulate(
        &mut self,
        receipt: &UnitCommitReceipt,
        sequence_no: u64,
    ) -> Result<(), PrefixCheckpointError> {
        let findings = receipt.durable().findings();
        self.finding_count = checked_add(
            self.finding_count,
            findings.finding_count(),
            sequence_no,
            "finding_count",
        )?;
        self.occurrence_count = checked_add(
            self.occurrence_count,
            findings.occurrence_count(),
            sequence_no,
            "occurrence_count",
        )?;
        self.observation_count = checked_add(
            self.observation_count,
            findings.observation_count(),
            sequence_no,
            "observation_count",
        )?;

        let done_ledger = receipt.durable().done_ledger();
        self.record_count = checked_add(
            self.record_count,
            done_ledger.record_count(),
            sequence_no,
            "record_count",
        )?;
        self.scanned_count = checked_add(
            self.scanned_count,
            done_ledger.scanned_count(),
            sequence_no,
            "scanned_count",
        )?;
        self.done_ledger_findings_count = checked_add(
            self.done_ledger_findings_count,
            done_ledger.findings_count(),
            sequence_no,
            "done_ledger_findings_count",
        )?;
        self.committed_units = checked_add(
            self.committed_units,
            receipt.durable().scope().committed_units().get(),
            sequence_no,
            "committed_units",
        )?;
        Ok(())
    }
}

fn checked_add(
    total: u64,
    next: u64,
    sequence_no: u64,
    field: &'static str,
) -> Result<u64, PrefixCheckpointError> {
    total
        .checked_add(next)
        .ok_or(PrefixCheckpointError::CountOverflow {
            sequence_no: Some(sequence_no),
            field,
        })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    use gossip_contracts::{
        connector::TokenBytes,
        identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
        persistence::{DoneLedgerCommitReceipt, FindingsCommitReceipt},
    };

    use crate::commit_model::CompletedUnit;

    /// Default buffer capacity for tests. Large enough that existing tests
    /// never hit the limit unless testing capacity behavior explicitly.
    const TEST_CAPACITY: usize = 64;

    fn test_aggregator(
        write_context: WriteContext,
        next_sequence_no: u64,
    ) -> PrefixCheckpointAggregator {
        PrefixCheckpointAggregator::new(write_context, next_sequence_no, TEST_CAPACITY)
    }

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
            RunId::from_raw(u64::from(seed) + 10),
            ShardId::from_raw(u64::from(seed) + 20),
            FenceEpoch::from_raw(u64::from(seed) + 30),
        )
    }

    fn unit_receipt(
        write_context: WriteContext,
        sequence_no: u64,
        checkpoint_boundary: CheckpointBoundary,
        findings: FindingsCommitReceipt,
        done_ledger: DoneLedgerCommitReceipt,
    ) -> UnitCommitReceipt {
        let scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::new(1).expect("per-unit scope"),
            checkpoint_boundary.clone(),
        );
        let durable = PageCommit::new(scope)
            .record_findings(findings)
            .record_done_ledger(done_ledger)
            .expect("per-unit done-ledger receipt must match one committed unit")
            .into_item_commit_receipt();

        UnitCommitReceipt::new(
            CompletedUnit::new(sequence_no, checkpoint_boundary),
            durable,
        )
        .expect("completed unit boundary must match durable scope boundary")
    }

    fn aggregator_input(
        expected_kind: CheckpointBoundaryKind,
        receipt: UnitCommitReceipt,
    ) -> CheckpointAggregatorInput {
        CheckpointAggregatorInput::new(expected_kind, receipt).expect("receipt kind must match")
    }

    fn ordered_input(
        write_context: WriteContext,
        sequence_no: u64,
        cursor: Cursor,
        finding_base: u64,
    ) -> CheckpointAggregatorInput {
        aggregator_input(
            CheckpointBoundaryKind::OrderedContent,
            unit_receipt(
                write_context,
                sequence_no,
                CheckpointBoundary::ordered_content(cursor),
                FindingsCommitReceipt::new(finding_base, finding_base + 1, finding_base + 2),
                DoneLedgerCommitReceipt::new(1, 1, finding_base),
            ),
        )
    }

    fn repo_input(
        write_context: WriteContext,
        sequence_no: u64,
        cursor: Cursor,
        finding_base: u64,
    ) -> CheckpointAggregatorInput {
        aggregator_input(
            CheckpointBoundaryKind::RepoFrontier,
            unit_receipt(
                write_context,
                sequence_no,
                CheckpointBoundary::repo_frontier(cursor),
                FindingsCommitReceipt::new(finding_base, finding_base + 1, finding_base + 2),
                DoneLedgerCommitReceipt::new(1, 1, finding_base),
            ),
        )
    }

    #[test]
    fn prefix_checkpoint_waits_for_contiguous_receipts() {
        let write_context = write_context(0x11);
        let mut aggregator = test_aggregator(write_context, 10);

        assert_eq!(
            aggregator
                .record_receipt(ordered_input(
                    write_context,
                    11,
                    cursor_with_token(b'b', 0xAA),
                    2
                ))
                .expect("out-of-order receipt should buffer"),
            ReceiptRecordOutcome::Buffered
        );
        assert!(aggregator.prepare_checkpoint().unwrap().is_none());
        assert_eq!(aggregator.next_sequence_no(), 10);
        assert_eq!(aggregator.buffered_receipt_count(), 1);

        assert_eq!(
            aggregator
                .record_receipt(ordered_input(
                    write_context,
                    10,
                    cursor_with_token(b'a', 0xBB),
                    1
                ))
                .expect("gap-closing receipt should buffer"),
            ReceiptRecordOutcome::Buffered
        );

        let pending = aggregator
            .prepare_checkpoint()
            .expect("contiguous receipts should prepare a checkpoint")
            .expect("prefix should now be checkpointable")
            .clone();

        assert_eq!(pending.first_sequence_no(), 10);
        assert_eq!(pending.last_sequence_no(), 11);
        assert_eq!(pending.committed_units(), 2);
        assert_eq!(
            pending.scope().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::OrderedContent
        );
        assert_eq!(
            pending.checkpoint_cursor().last_key(),
            Some(&item_key(b'b'))
        );
        assert!(pending.checkpoint_cursor().token().is_none());
        assert_eq!(
            pending.item_commit_receipt().findings(),
            FindingsCommitReceipt::new(3, 5, 7)
        );
        assert_eq!(
            pending.item_commit_receipt().done_ledger(),
            DoneLedgerCommitReceipt::new(2, 2, 3)
        );
        assert_eq!(pending.scope().committed_units().get(), 2);
        assert_eq!(aggregator.next_sequence_no(), 10);
        assert_eq!(aggregator.buffered_receipt_count(), 2);

        let page_receipt = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(42),
            ))
            .expect("matching checkpoint receipt should finalize the prepared prefix");

        assert_eq!(
            page_receipt.item_commit().scope().committed_units().get(),
            2
        );
        assert_eq!(aggregator.next_sequence_no(), 12);
        assert_eq!(aggregator.checkpointed_units(), 2);
        assert_eq!(aggregator.buffered_receipt_count(), 0);
        assert!(aggregator.pending_checkpoint().is_none());
    }

    #[test]
    fn prepare_checkpoint_returns_none_without_next_receipt() {
        let write_context = write_context(0x12);
        let mut aggregator = test_aggregator(write_context, 3);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                4,
                cursor_without_token(b'd'),
                1,
            ))
            .unwrap();

        assert!(aggregator.prepare_checkpoint().unwrap().is_none());
        assert!(aggregator.pending_checkpoint().is_none());
        assert_eq!(aggregator.next_sequence_no(), 3);
    }

    #[test]
    fn prefix_commit_drops_resume_token_but_preserves_last_key() {
        let write_context = write_context(0x22);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_with_token(b'k', 0x44),
                4,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap();

        assert_eq!(
            pending.checkpoint_cursor().last_key(),
            Some(&item_key(b'k'))
        );
        assert!(pending.checkpoint_cursor().token().is_none());
    }

    #[test]
    fn duplicate_and_already_checkpointed_receipts_are_idempotent() {
        let write_context = write_context(0x33);
        let mut aggregator = test_aggregator(write_context, 0);
        let receipt = ordered_input(write_context, 0, cursor_without_token(b'a'), 1);

        assert_eq!(
            aggregator.record_receipt(receipt.clone()).unwrap(),
            ReceiptRecordOutcome::Buffered
        );
        assert_eq!(
            aggregator.record_receipt(receipt.clone()).unwrap(),
            ReceiptRecordOutcome::DuplicateBuffered
        );

        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
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
        let mut aggregator = test_aggregator(write_context, 1);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'b'),
                1,
            ))
            .unwrap();

        let error = aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'c'),
                1,
            ))
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
        let mut aggregator = test_aggregator(expected, 0);

        let error = aggregator
            .record_receipt(ordered_input(actual, 0, cursor_without_token(b'a'), 1))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::OwnershipMismatch {
                sequence_no: 0,
                expected: Box::new(expected),
                actual: Box::new(actual),
            }
        );
    }

    #[test]
    fn checkpoint_scope_mismatch_keeps_pending_for_retry() {
        let write_context = write_context(0x66);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();

        let wrong_scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::new(1).unwrap(),
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
                PageCommitValidationError::CheckpointScopeMismatch { .. }
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
            .expect("retry with the correct scope should succeed");
        assert_eq!(aggregator.next_sequence_no(), 1);
    }

    #[test]
    fn cannot_ack_checkpoint_without_pending_prefix() {
        let mut aggregator = test_aggregator(write_context(0x77), 0);

        let error = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                CommitScope::from_write_context(
                    write_context(0x77),
                    NonZeroU64::new(1).unwrap(),
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
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();

        let error = aggregator
            .record_receipt(repo_input(write_context, 1, cursor_without_token(b'b'), 1))
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
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'b'),
                1,
            ))
            .unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryRegression { sequence_no: 1 }
        );
    }

    #[test]
    fn pending_prefix_does_not_widen_before_acknowledge() {
        let write_context = write_context(0xBC);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        let first_pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();

        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'b'),
                2,
            ))
            .unwrap();
        let repeated_pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();

        assert_eq!(first_pending.first_sequence_no(), 0);
        assert_eq!(first_pending.last_sequence_no(), 0);
        assert_eq!(repeated_pending, first_pending);
        assert_eq!(aggregator.buffered_receipt_count(), 2);

        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                first_pending.scope().clone(),
                LogicalTime::from_raw(10),
            ))
            .unwrap();

        let next_pending = aggregator.prepare_checkpoint().unwrap().unwrap();
        assert_eq!(next_pending.first_sequence_no(), 1);
        assert_eq!(next_pending.last_sequence_no(), 1);
    }

    #[test]
    fn next_sequence_overflow_preserves_pending_prefix() {
        let write_context = write_context(0xCD);
        let mut aggregator = test_aggregator(write_context, u64::MAX);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                u64::MAX,
                cursor_without_token(b'z'),
                1,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();

        let error = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(11),
            ))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::CountOverflow {
                sequence_no: None,
                field: "next_sequence_no",
            }
        );
        assert_eq!(aggregator.pending_checkpoint(), Some(&pending));
        assert_eq!(aggregator.buffered_receipt_count(), 1);
    }

    #[test]
    fn boundary_regression_detected_against_last_checkpointed_key() {
        let write_context = write_context(0xDA);
        let mut aggregator = test_aggregator(write_context, 0);

        // Checkpoint seq 0 with key 'z'.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'z'),
                1,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(1),
            ))
            .unwrap();
        assert_eq!(aggregator.next_sequence_no(), 1);

        // Buffer seq 1 with key 'a', which regresses against the checkpointed
        // key 'z'. The regression is detected during prefix construction because
        // `build_pending_checkpoint` initializes `previous_key` from
        // `last_checkpoint_key`.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryRegression { sequence_no: 1 }
        );
    }

    #[test]
    fn ordered_content_rejects_equal_keys_within_prefix() {
        let write_context = write_context(0xDB);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'a'),
                2,
            ))
            .unwrap();

        // Ordered-content requires strictly increasing keys. Equal keys
        // would cause tokenless resume (strictly-greater-than semantics)
        // to skip items at the duplicated key position.
        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::OrderedContentEqualKey { sequence_no: 1 }
        );
    }

    #[test]
    fn repo_frontier_permits_equal_keys_within_prefix() {
        let write_context = write_context(0xDB);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(repo_input(write_context, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        aggregator
            .record_receipt(repo_input(write_context, 1, cursor_without_token(b'a'), 2))
            .unwrap();

        // Repo-frontier allows equal keys because multiple units can
        // share the same ItemKey.
        let pending = aggregator
            .prepare_checkpoint()
            .expect("equal keys must not be treated as regression for repo-frontier")
            .expect("contiguous prefix should be preparable");

        assert_eq!(pending.first_sequence_no(), 0);
        assert_eq!(pending.last_sequence_no(), 1);
        assert_eq!(pending.committed_units(), 2);
        assert_eq!(
            pending.checkpoint_cursor().last_key(),
            Some(&item_key(b'a'))
        );
    }

    #[test]
    fn ordered_content_rejects_equal_key_across_checkpoint_boundary() {
        let write_context = write_context(0xDB);
        let mut aggregator = test_aggregator(write_context, 0);

        // Checkpoint seq 0 with key 'a'.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(1),
            ))
            .unwrap();

        // Buffer seq 1 with key 'a' — equal to the last checkpointed key.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'a'),
                2,
            ))
            .unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::OrderedContentEqualKey { sequence_no: 1 }
        );
    }

    #[test]
    fn repo_frontier_permits_equal_key_across_checkpoint_boundary() {
        let write_context = write_context(0xDB);
        let mut aggregator = test_aggregator(write_context, 0);

        // Checkpoint seq 0 with key 'a'.
        aggregator
            .record_receipt(repo_input(write_context, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(1),
            ))
            .unwrap();

        // Buffer seq 1 with key 'a' — equal to the last checkpointed key.
        aggregator
            .record_receipt(repo_input(write_context, 1, cursor_without_token(b'a'), 2))
            .unwrap();

        let pending = aggregator
            .prepare_checkpoint()
            .expect("repo-frontier allows equal keys across checkpoint boundaries")
            .expect("contiguous prefix should be preparable");
        assert_eq!(pending.first_sequence_no(), 1);
        assert_eq!(pending.last_sequence_no(), 1);
    }

    #[test]
    fn checkpointed_units_overflow_preserves_pending_prefix() {
        let write_context = write_context(0xDC);

        // Directly construct an aggregator with `checkpointed_units` at the
        // overflow boundary. `next_sequence_no = 0` so the sequence counter
        // itself does not overflow — only `checkpointed_units` does.
        let mut aggregator = PrefixCheckpointAggregator {
            write_context,
            next_sequence_no: 0,
            checkpointed_units: u64::MAX,
            max_buffered: TEST_CAPACITY,
            boundary_kind: None,
            last_checkpoint_key: None,
            receipts: BTreeMap::new(),
            pending: None,
        };

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        let pending = aggregator.prepare_checkpoint().unwrap().unwrap().clone();

        let error = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(20),
            ))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::CountOverflow {
                sequence_no: None,
                field: "checkpointed_units",
            }
        );
        assert_eq!(aggregator.pending_checkpoint(), Some(&pending));
        assert_eq!(aggregator.buffered_receipt_count(), 1);
        assert_eq!(aggregator.next_sequence_no(), 0);
    }

    #[test]
    fn repo_frontier_lifecycle_prepare_and_acknowledge() {
        let write_context = write_context(0xDD);
        let mut aggregator = test_aggregator(write_context, 0);

        // Record two repo-frontier receipts out of sequence order.
        aggregator
            .record_receipt(repo_input(
                write_context,
                1,
                cursor_with_token(b'r', 0xCC),
                3,
            ))
            .unwrap();
        aggregator
            .record_receipt(repo_input(
                write_context,
                0,
                cursor_with_token(b'q', 0xDD),
                1,
            ))
            .unwrap();

        let pending = aggregator
            .prepare_checkpoint()
            .expect("contiguous repo-frontier receipts should prepare")
            .expect("prefix should be checkpointable")
            .clone();

        assert_eq!(pending.first_sequence_no(), 0);
        assert_eq!(pending.last_sequence_no(), 1);
        assert_eq!(pending.committed_units(), 2);
        assert_eq!(
            pending.scope().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
        // Token stripped, last key preserved from the final receipt in
        // sequence order (seq 1 carries key 'r').
        assert_eq!(
            pending.checkpoint_cursor().last_key(),
            Some(&item_key(b'r'))
        );
        assert!(pending.checkpoint_cursor().token().is_none());
        // Aggregated findings: seq 0 (1,2,3) + seq 1 (3,4,5) = (4,6,8).
        assert_eq!(
            pending.item_commit_receipt().findings(),
            FindingsCommitReceipt::new(4, 6, 8)
        );
        // Aggregated done-ledger: seq 0 (1,1,1) + seq 1 (1,1,3) = (2,2,4).
        assert_eq!(
            pending.item_commit_receipt().done_ledger(),
            DoneLedgerCommitReceipt::new(2, 2, 4)
        );

        let page_receipt = aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                pending.scope().clone(),
                LogicalTime::from_raw(50),
            ))
            .expect("acknowledge should succeed");

        assert_eq!(
            page_receipt.item_commit().scope().committed_units().get(),
            2
        );
        assert_eq!(aggregator.next_sequence_no(), 2);
        assert_eq!(aggregator.checkpointed_units(), 2);
        assert_eq!(aggregator.buffered_receipt_count(), 0);
        assert!(aggregator.pending_checkpoint().is_none());
    }

    #[test]
    fn boundary_kind_freeze_is_symmetric() {
        let write_context = write_context(0xDE);
        let mut aggregator = test_aggregator(write_context, 0);

        // Pin RepoFrontier first.
        aggregator
            .record_receipt(repo_input(write_context, 0, cursor_without_token(b'a'), 1))
            .unwrap();

        // Attempting OrderedContent after RepoFrontier is pinned must fail.
        let error = aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'b'),
                1,
            ))
            .unwrap_err();

        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryKindMismatch {
                expected: CheckpointBoundaryKind::RepoFrontier,
                actual: CheckpointBoundaryKind::OrderedContent,
            }
        );
    }

    #[test]
    fn count_overflow_during_aggregation() {
        let write_context = write_context(0xE0);
        let mut aggregator = test_aggregator(write_context, 0);

        // First receipt with finding_count = u64::MAX.
        let r0 = aggregator_input(
            CheckpointBoundaryKind::OrderedContent,
            unit_receipt(
                write_context,
                0,
                CheckpointBoundary::ordered_content(cursor_without_token(b'a')),
                FindingsCommitReceipt::new(u64::MAX, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            ),
        );
        aggregator.record_receipt(r0).unwrap();

        // Second receipt with finding_count = 1 triggers overflow.
        let r1 = aggregator_input(
            CheckpointBoundaryKind::OrderedContent,
            unit_receipt(
                write_context,
                1,
                CheckpointBoundary::ordered_content(cursor_without_token(b'b')),
                FindingsCommitReceipt::new(1, 0, 0),
                DoneLedgerCommitReceipt::new(1, 1, 0),
            ),
        );
        aggregator.record_receipt(r1).unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::CountOverflow {
                sequence_no: Some(1),
                field: "finding_count",
            }
        );
    }

    #[test]
    fn missing_progress_key_rejected() {
        let write_context = write_context(0xE1);
        let mut aggregator = test_aggregator(write_context, 0);

        let boundary = CheckpointBoundary::ordered_content(Cursor::initial());
        let scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::new(1).unwrap(),
            boundary.clone(),
        );
        let durable = PageCommit::new(scope)
            .record_findings(FindingsCommitReceipt::new(1, 1, 1))
            .record_done_ledger(DoneLedgerCommitReceipt::new(1, 1, 1))
            .unwrap()
            .into_item_commit_receipt();
        let receipt = UnitCommitReceipt::new(CompletedUnit::new(0, boundary), durable).unwrap();
        let input = CheckpointAggregatorInput::new(CheckpointBoundaryKind::OrderedContent, receipt)
            .unwrap();

        let error = aggregator.record_receipt(input).unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::MissingProgressKey { sequence_no: 0 }
        );
    }

    #[test]
    fn per_unit_receipt_expected() {
        let write_context = write_context(0xE2);
        let mut aggregator = test_aggregator(write_context, 0);

        let boundary = CheckpointBoundary::ordered_content(cursor_without_token(b'a'));
        let scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::new(2).unwrap(),
            boundary.clone(),
        );
        let durable = PageCommit::new(scope)
            .record_findings(FindingsCommitReceipt::new(1, 1, 1))
            .record_done_ledger(DoneLedgerCommitReceipt::new(2, 2, 1))
            .unwrap()
            .into_item_commit_receipt();
        let receipt = UnitCommitReceipt::new(CompletedUnit::new(0, boundary), durable).unwrap();
        let input = CheckpointAggregatorInput::new(CheckpointBoundaryKind::OrderedContent, receipt)
            .unwrap();

        let error = aggregator.record_receipt(input).unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::PerUnitReceiptExpected {
                sequence_no: 0,
                actual: 2,
            }
        );
    }

    #[test]
    fn prepare_checkpoint_returns_none_when_buffer_is_empty() {
        let write_context = write_context(0xE3);
        let mut aggregator = test_aggregator(write_context, 0);

        assert!(aggregator.prepare_checkpoint().unwrap().is_none());
        assert!(aggregator.pending_checkpoint().is_none());
        assert_eq!(aggregator.buffered_receipt_count(), 0);
    }

    #[test]
    fn multi_round_acknowledge_carries_last_checkpoint_key() {
        let write_context = write_context(0xE4);
        let mut aggregator = test_aggregator(write_context, 0);

        // Round 1: checkpoint key 'a'.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        let p1 = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                p1.scope().clone(),
                LogicalTime::from_raw(1),
            ))
            .unwrap();
        assert_eq!(aggregator.next_sequence_no(), 1);

        // Round 2: checkpoint key 'b'.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'b'),
                2,
            ))
            .unwrap();
        let p2 = aggregator.prepare_checkpoint().unwrap().unwrap().clone();
        assert_eq!(p2.checkpoint_cursor().last_key(), Some(&item_key(b'b')));
        aggregator
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                p2.scope().clone(),
                LogicalTime::from_raw(2),
            ))
            .unwrap();
        assert_eq!(aggregator.next_sequence_no(), 2);
        assert_eq!(aggregator.checkpointed_units(), 2);

        // Round 3: key 'a' regresses against last checkpointed key 'b'.
        aggregator
            .record_receipt(ordered_input(
                write_context,
                2,
                cursor_without_token(b'a'),
                3,
            ))
            .unwrap();
        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryRegression { sequence_no: 2 }
        );
    }

    #[test]
    fn boundary_regression_preserves_aggregator_state() {
        let write_context = write_context(0xE5);
        let mut aggregator = test_aggregator(write_context, 0);

        aggregator
            .record_receipt(ordered_input(
                write_context,
                1,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'b'),
                1,
            ))
            .unwrap();

        let error = aggregator.prepare_checkpoint().unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::BoundaryRegression { sequence_no: 1 }
        );

        // Aggregator state is fully preserved after the error.
        assert!(aggregator.pending_checkpoint().is_none());
        assert_eq!(aggregator.next_sequence_no(), 0);
        assert_eq!(aggregator.checkpointed_units(), 0);
        assert_eq!(aggregator.buffered_receipt_count(), 2);
    }

    #[test]
    fn discard_pending_returns_and_clears_prepared_prefix() {
        let write_context = write_context(0xE6);
        let mut aggregator = test_aggregator(write_context, 0);

        assert!(aggregator.discard_pending().is_none());

        aggregator
            .record_receipt(ordered_input(
                write_context,
                0,
                cursor_without_token(b'a'),
                1,
            ))
            .unwrap();
        aggregator.prepare_checkpoint().unwrap();

        let discarded = aggregator
            .discard_pending()
            .expect("should return the pending prefix");
        assert_eq!(discarded.first_sequence_no(), 0);
        assert_eq!(discarded.last_sequence_no(), 0);
        assert!(aggregator.pending_checkpoint().is_none());
        assert_eq!(aggregator.buffered_receipt_count(), 1);

        // A new prepare should re-build from the still-buffered receipt.
        let reprepared = aggregator.prepare_checkpoint().unwrap().unwrap();
        assert_eq!(reprepared.first_sequence_no(), 0);
    }

    #[test]
    fn replayed_receipt_does_not_set_boundary_kind() {
        let write_context = write_context(0xF0);

        // Simulate a resumed aggregator: `next_sequence_no > 0` but
        // `boundary_kind` is still `None` (the aggregator was freshly
        // constructed with a non-zero starting sequence).
        let mut aggregator = test_aggregator(write_context, 5);
        assert!(aggregator.checkpoint_boundary_kind().is_none());

        // A replayed receipt with sequence_no < next_sequence_no must be
        // ignored idempotently — including no side-effect on boundary_kind.
        let outcome = aggregator
            .record_receipt(ordered_input(
                write_context,
                3,
                cursor_without_token(b'x'),
                1,
            ))
            .expect("replayed receipt should not error");
        assert_eq!(outcome, ReceiptRecordOutcome::AlreadyCheckpointed);

        // The boundary kind must remain unset — the replayed receipt must not
        // lock it.
        assert!(
            aggregator.checkpoint_boundary_kind().is_none(),
            "boundary_kind must not be set by an already-checkpointed receipt"
        );
    }

    #[test]
    fn receipts_beyond_prefix_survive_acknowledge() {
        let wc = write_context(0xF2);
        let mut agg = test_aggregator(wc, 0);

        // Buffer contiguous [0,1] plus non-contiguous [5,6].
        agg.record_receipt(ordered_input(wc, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 1, cursor_without_token(b'b'), 2))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 5, cursor_without_token(b'f'), 3))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 6, cursor_without_token(b'g'), 4))
            .unwrap();
        assert_eq!(agg.buffered_receipt_count(), 4);

        // Prepare and acknowledge prefix [0,1].
        let pending = agg.prepare_checkpoint().unwrap().unwrap().clone();
        assert_eq!(pending.last_sequence_no(), 1);
        agg.acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(1),
        ))
        .unwrap();

        // Receipts 5 and 6 survive the split_off.
        assert_eq!(agg.next_sequence_no(), 2);
        assert_eq!(agg.buffered_receipt_count(), 2);

        // No contiguous prefix yet (gap at 2,3,4).
        assert!(agg.prepare_checkpoint().unwrap().is_none());

        // Close the gap — full prefix [2..6] available.
        agg.record_receipt(ordered_input(wc, 2, cursor_without_token(b'c'), 5))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 3, cursor_without_token(b'd'), 6))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 4, cursor_without_token(b'e'), 7))
            .unwrap();

        let pending2 = agg.prepare_checkpoint().unwrap().unwrap();
        assert_eq!(pending2.first_sequence_no(), 2);
        assert_eq!(pending2.last_sequence_no(), 6);
        assert_eq!(pending2.committed_units(), 5);
    }

    // `ReceiptBoundaryMismatch` is structurally unreachable: `UnitCommitReceipt::new`
    // validates that the completed-unit boundary matches the durable scope boundary
    // before the receipt can be constructed. No public API bypasses this check.

    // `InvalidPreparedCheckpoint` is structurally unreachable through normal
    // construction: every per-unit receipt has record_count == committed_units == 1
    // (enforced by `PageCommit::record_done_ledger`), so the aggregate always
    // satisfies record_count == committed_units.

    // `InternalInconsistency` is structurally unreachable: every per-unit
    // receipt has `committed_units() == 1` (enforced by `validate_receipt`),
    // so `NonZeroU64::new(committed_units)` on the aggregate always succeeds
    // for a non-empty contiguous prefix.

    #[test]
    fn error_display_messages_are_meaningful() {
        let err = PrefixCheckpointError::CountOverflow {
            sequence_no: Some(42),
            field: "finding_count",
        };
        let msg = err.to_string();
        assert!(msg.contains("finding_count"));
        assert!(msg.contains("42"));

        let err_none = PrefixCheckpointError::CountOverflow {
            sequence_no: None,
            field: "next_sequence_no",
        };
        let msg_none = err_none.to_string();
        assert!(msg_none.contains("next_sequence_no"));
    }

    #[test]
    fn error_source_chains_for_wrapped_variants() {
        let wc = write_context(0xF1);
        let mut agg = test_aggregator(wc, 0);
        agg.record_receipt(ordered_input(wc, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        agg.prepare_checkpoint().unwrap();

        let wrong_scope = CommitScope::from_write_context(
            wc,
            NonZeroU64::new(1).unwrap(),
            CheckpointBoundary::ordered_content(cursor_without_token(b'z')),
        );
        let err = agg
            .acknowledge_checkpoint(CheckpointCommitReceipt::new(
                wrong_scope,
                LogicalTime::from_raw(1),
            ))
            .unwrap_err();
        assert!(err.source().is_some());
    }

    // --- Buffer capacity tests ---

    #[test]
    #[should_panic(expected = "max_buffered must be at least 1")]
    fn zero_capacity_panics_at_construction() {
        let _ = PrefixCheckpointAggregator::new(write_context(0xA0), 0, 0);
    }

    #[test]
    fn buffer_full_rejects_new_receipt_at_capacity() {
        let wc = write_context(0xA0);
        let mut agg = PrefixCheckpointAggregator::new(wc, 0, 2);
        assert_eq!(agg.buffer_capacity(), 2);

        agg.record_receipt(ordered_input(wc, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 1, cursor_without_token(b'b'), 2))
            .unwrap();
        assert_eq!(agg.buffered_receipt_count(), 2);

        // Third receipt exceeds capacity.
        let error = agg
            .record_receipt(ordered_input(wc, 2, cursor_without_token(b'c'), 3))
            .unwrap_err();
        assert_eq!(
            error,
            PrefixCheckpointError::BufferFull {
                buffered: 2,
                capacity: 2,
            }
        );
        assert_eq!(agg.buffered_receipt_count(), 2);
    }

    #[test]
    fn acknowledge_drains_buffer_and_re_enables_insertion() {
        let wc = write_context(0xA1);
        let mut agg = PrefixCheckpointAggregator::new(wc, 0, 2);

        agg.record_receipt(ordered_input(wc, 0, cursor_without_token(b'a'), 1))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 1, cursor_without_token(b'b'), 2))
            .unwrap();

        // Buffer is at capacity — acknowledge prefix [0,1] to drain.
        let pending = agg.prepare_checkpoint().unwrap().unwrap().clone();
        agg.acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(1),
        ))
        .unwrap();
        assert_eq!(agg.buffered_receipt_count(), 0);

        // New receipts can now be accepted.
        agg.record_receipt(ordered_input(wc, 2, cursor_without_token(b'c'), 3))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 3, cursor_without_token(b'd'), 4))
            .unwrap();
        assert_eq!(agg.buffered_receipt_count(), 2);
    }

    #[test]
    fn buffer_full_does_not_reject_duplicates_or_already_checkpointed() {
        let wc = write_context(0xA2);
        let mut agg = PrefixCheckpointAggregator::new(wc, 0, 1);

        let receipt = ordered_input(wc, 0, cursor_without_token(b'a'), 1);
        agg.record_receipt(receipt.clone()).unwrap();
        assert_eq!(agg.buffered_receipt_count(), 1);

        // Duplicate of an existing buffered receipt bypasses the capacity check.
        assert_eq!(
            agg.record_receipt(receipt.clone()).unwrap(),
            ReceiptRecordOutcome::DuplicateBuffered,
        );

        // Acknowledge to advance next_sequence_no.
        let pending = agg.prepare_checkpoint().unwrap().unwrap().clone();
        agg.acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(1),
        ))
        .unwrap();

        // Fill the buffer again.
        agg.record_receipt(ordered_input(wc, 1, cursor_without_token(b'b'), 2))
            .unwrap();
        assert_eq!(agg.buffered_receipt_count(), 1);

        // Already-checkpointed receipt bypasses the capacity check.
        assert_eq!(
            agg.record_receipt(receipt).unwrap(),
            ReceiptRecordOutcome::AlreadyCheckpointed,
        );
    }

    #[test]
    fn gap_filler_admitted_at_capacity_enables_progress() {
        let wc = write_context(0xA3);
        // Start at next_sequence_no = 0, capacity = 2.
        let mut agg = PrefixCheckpointAggregator::new(wc, 0, 2);

        // Skip seq 0 (the gap), buffer seq 1 and seq 2.
        agg.record_receipt(ordered_input(wc, 1, cursor_without_token(b'b'), 2))
            .unwrap();
        agg.record_receipt(ordered_input(wc, 2, cursor_without_token(b'c'), 3))
            .unwrap();

        // Buffer full — seq 3 rejected (it does not fill the head gap).
        let error = agg
            .record_receipt(ordered_input(wc, 3, cursor_without_token(b'd'), 4))
            .unwrap_err();
        assert!(matches!(error, PrefixCheckpointError::BufferFull { .. }));

        // No contiguous prefix (gap at seq 0).
        assert!(agg.prepare_checkpoint().unwrap().is_none());

        // The gap-filling receipt (seq 0 == next_sequence_no) is admitted
        // even though the buffer is at capacity, because it fills the head
        // of the contiguous run and enables prefix construction.
        assert_eq!(
            agg.record_receipt(ordered_input(wc, 0, cursor_without_token(b'a'), 1))
                .unwrap(),
            ReceiptRecordOutcome::Buffered,
        );
        // Buffer temporarily exceeds max_buffered by one (the gap-filler).
        assert_eq!(agg.buffered_receipt_count(), 3);

        // A contiguous prefix [0,1,2] is now available.
        let pending = agg
            .prepare_checkpoint()
            .unwrap()
            .expect("contiguous prefix should be preparable after gap-filler admitted");
        assert_eq!(pending.first_sequence_no(), 0);
        assert_eq!(pending.last_sequence_no(), 2);
        assert_eq!(pending.committed_units(), 3);

        // Acknowledge to drain and restore buffer headroom.
        let pending = pending.clone();
        agg.acknowledge_checkpoint(CheckpointCommitReceipt::new(
            pending.scope().clone(),
            LogicalTime::from_raw(1),
        ))
        .unwrap();
        assert_eq!(agg.next_sequence_no(), 3);
        assert_eq!(agg.buffered_receipt_count(), 0);
    }
}
