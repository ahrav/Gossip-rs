//! Durable acknowledgement handles and receipt types for persistence writes.
//!
//! # Purpose
//!
//! Persistence backends in this crate split submission from durability:
//! submitting a batch returns a [`CommitHandle`], and only
//! [`CommitHandle::wait`] proves the write became durable. This two-phase
//! design lets storage implementations batch or defer fsync/replication work
//! without weakening the caller-visible contract, and lets callers overlap
//! computation with I/O by deferring the wait.
//!
//! # Receipt hierarchy
//!
//! Receipts form a compositional hierarchy that mirrors the page-commit
//! protocol (see [`super::page_commit`]):
//!
//! - [`FindingsCommitReceipt`] — proves the three-layer findings data
//!   (findings, occurrences, observations) is durable.
//! - [`DoneLedgerCommitReceipt`] — proves done-ledger deduplication rows
//!   are durable.
//! - [`CheckpointCommitReceipt`] — proves the cursor checkpoint is durable;
//!   carries the full page scope so the typestate machine can validate
//!   receipt-to-scope correspondence.
//! - [`ItemCommitReceipt`] — composite: findings + done-ledger.
//! - [`PageCommitReceipt`] — composite: item-commit + checkpoint (the
//!   terminal proof that the entire page is durable).
//!
//! All receipts are backend-neutral proof objects. They summarize what became
//! durable without exposing backend-specific transaction identifiers or retry
//! machinery.
//!
//! # Design rationale
//!
//! The [`CommitHandle`] trait consumes `self` on [`wait`](CommitHandle::wait)
//! to prevent double-waits: once you observe a receipt (or error), the handle
//! is gone. [`ReadyCommitHandle`] provides a zero-cost adapter for synchronous
//! backends and test doubles that already have the result in hand.

use std::{error::Error, fmt, sync::Arc};

use crate::identity::LogicalTime;

use super::page_commit::PageCommitScope;

/// Marker trait for durable persistence acknowledgements.
///
/// Receipts are the proof objects callers must hold before claiming a write
/// completed durably. The supertrait bounds ensure receipts can be:
/// - cloned into composite receipts ([`ItemCommitReceipt`], [`PageCommitReceipt`]),
/// - debug-formatted in error diagnostics,
/// - sent across threads for downstream processing.
pub trait CommitReceipt: Clone + fmt::Debug + Send + Sync + 'static {}

/// Handle returned by persistence sinks for eventual durable acknowledgement.
///
/// `Ok(handle)` means the backend accepted responsibility for the write.
/// Durability is not established until [`wait`](Self::wait) returns a receipt.
///
/// # Ownership
///
/// `wait` consumes `self`, preventing double-waits and making the
/// single-use nature of durable acknowledgement explicit in the type system.
#[must_use = "durability is not established until wait() returns a receipt"]
pub trait CommitHandle: Send + 'static {
    /// Receipt proving the durable write completed.
    type Receipt: CommitReceipt;
    /// Backend-specific wait error.
    type Error: Error + Send + Sync + 'static;

    /// Block until the write is durable and return a proof receipt.
    ///
    /// Backends may implement this as an immediate return (synchronous write)
    /// or as a blocking wait on internally queued or coalesced work (e.g.
    /// group-commit fsync).
    fn wait(self) -> Result<Self::Receipt, Self::Error>;
}

/// Pre-resolved [`CommitHandle`] for synchronous backends and test doubles.
///
/// Wraps an already-computed `Result<R, E>`, so [`wait`](CommitHandle::wait)
/// returns immediately without blocking. Useful when:
/// - The backend performs synchronous writes (WAL + fsync inline).
/// - Tests need to inject known success/failure outcomes.
#[must_use = "the contained result must be observed via wait()"]
#[derive(Debug)]
pub struct ReadyCommitHandle<R, E>(Result<R, E>);

impl<R, E> ReadyCommitHandle<R, E> {
    /// Construct a ready successful handle.
    #[inline]
    pub fn ok(receipt: R) -> Self {
        Self(Ok(receipt))
    }

    /// Construct a ready failed handle.
    #[inline]
    pub fn err(error: E) -> Self {
        Self(Err(error))
    }

    /// Construct from a pre-existing result.
    #[inline]
    pub fn from_result(result: Result<R, E>) -> Self {
        Self(result)
    }
}

impl<R, E> CommitHandle for ReadyCommitHandle<R, E>
where
    R: CommitReceipt,
    E: Error + Send + Sync + 'static,
{
    type Receipt = R;
    type Error = E;

    #[inline]
    fn wait(self) -> Result<Self::Receipt, Self::Error> {
        self.0
    }
}

/// Durable acknowledgement for a findings upsert.
///
/// Mirrors the three-layer findings data model: counts correspond to
/// [`FindingRecord`](super::FindingRecord),
/// [`OccurrenceRecord`](super::OccurrenceRecord), and
/// [`ObservationRecord`](super::ObservationRecord) rows respectively.
///
/// **Semantics note:** counts reflect the number of distinct records in the
/// submitted batch that the backend has durably acknowledged, *not* the number
/// of newly inserted rows. An idempotent replay of an already-durable batch
/// returns the same counts as the original write. Callers that need to detect
/// "did anything new get written?" should compare probe snapshots (e.g.,
/// [`FindingsConformanceProbe`](super::conformance::FindingsConformanceProbe))
/// or track insertion state externally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsCommitReceipt {
    finding_count: u64,
    occurrence_count: u64,
    observation_count: u64,
}

impl FindingsCommitReceipt {
    /// Construct a findings receipt.
    #[inline]
    #[must_use]
    pub const fn new(finding_count: u64, occurrence_count: u64, observation_count: u64) -> Self {
        Self {
            finding_count,
            occurrence_count,
            observation_count,
        }
    }

    /// Number of distinct finding rows in the batch durably acknowledged.
    ///
    /// Includes rows that already existed in durable state (idempotent replay).
    #[inline]
    #[must_use]
    pub const fn finding_count(self) -> u64 {
        self.finding_count
    }

    /// Number of distinct occurrence rows in the batch durably acknowledged.
    ///
    /// Includes rows that already existed in durable state (idempotent replay).
    #[inline]
    #[must_use]
    pub const fn occurrence_count(self) -> u64 {
        self.occurrence_count
    }

    /// Number of distinct observation rows in the batch durably acknowledged.
    ///
    /// Includes rows that already existed in durable state (idempotent replay).
    #[inline]
    #[must_use]
    pub const fn observation_count(self) -> u64 {
        self.observation_count
    }
}

impl CommitReceipt for FindingsCommitReceipt {}

/// Durable acknowledgement for a done-ledger upsert.
///
/// `record_count` is the number of **distinct keys** in the committed batch
/// (duplicate keys within a single submission are merged before counting).
/// `scanned_count` is the subset whose status reached a terminal scanned
/// state (as defined by [`DoneLedgerStatus`](super::DoneLedgerStatus)).
/// `findings_count` is the aggregate number of findings referenced across
/// all committed rows (after per-key deduplication).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DoneLedgerCommitReceipt {
    record_count: u64,
    scanned_count: u64,
    findings_count: u64,
}

impl DoneLedgerCommitReceipt {
    /// Construct a done-ledger receipt.
    #[inline]
    #[must_use]
    pub const fn new(record_count: u64, scanned_count: u64, findings_count: u64) -> Self {
        Self {
            record_count,
            scanned_count,
            findings_count,
        }
    }

    /// Number of distinct done-ledger keys durably acknowledged by this receipt.
    #[inline]
    #[must_use]
    pub const fn record_count(self) -> u64 {
        self.record_count
    }

    /// Number of rows whose status was one of the durable scanned states.
    #[inline]
    #[must_use]
    pub const fn scanned_count(self) -> u64 {
        self.scanned_count
    }

    /// Aggregate findings count represented by the committed rows.
    #[inline]
    #[must_use]
    pub const fn findings_count(self) -> u64 {
        self.findings_count
    }
}

impl CommitReceipt for DoneLedgerCommitReceipt {}

/// Durable acknowledgement for a cursor checkpoint.
///
/// Embeds the full [`PageCommitScope`] so the [`PageCommit`](super::PageCommit)
/// typestate machine can validate receipt-to-scope correspondence with a single
/// equality check, guarding against receipt mix-ups across concurrent pages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointCommitReceipt {
    scope: PageCommitScope,
    checkpointed_at: LogicalTime,
}

impl CheckpointCommitReceipt {
    /// Construct a checkpoint receipt.
    #[must_use]
    pub fn new(scope: PageCommitScope, checkpointed_at: LogicalTime) -> Self {
        Self {
            scope,
            checkpointed_at,
        }
    }

    /// Page scope covered by this checkpoint receipt.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }

    /// Logical timestamp when the checkpoint became durable.
    #[inline]
    #[must_use]
    pub const fn checkpointed_at(&self) -> LogicalTime {
        self.checkpointed_at
    }
}

impl CommitReceipt for CheckpointCommitReceipt {}

/// Composite receipt proving a page's findings and done-ledger rows are
/// durably committed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemCommitReceipt {
    scope: Arc<PageCommitScope>,
    findings: FindingsCommitReceipt,
    done_ledger: DoneLedgerCommitReceipt,
}

impl ItemCommitReceipt {
    /// Construct an item-commit receipt from its component parts.
    ///
    /// `pub(super)` because only the [`PageCommit`](super::PageCommit)
    /// typestate machine should assemble this after validating ordering.
    #[inline]
    #[must_use]
    pub(super) fn new(
        scope: Arc<PageCommitScope>,
        findings: FindingsCommitReceipt,
        done_ledger: DoneLedgerCommitReceipt,
    ) -> Self {
        Self {
            scope,
            findings,
            done_ledger,
        }
    }

    /// Page scope shared by the durable findings and done-ledger receipts.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }

    /// Findings-layer acknowledgement for this page.
    #[inline]
    #[must_use]
    pub const fn findings(&self) -> FindingsCommitReceipt {
        self.findings
    }

    /// Done-ledger acknowledgement for this page.
    #[inline]
    #[must_use]
    pub const fn done_ledger(&self) -> DoneLedgerCommitReceipt {
        self.done_ledger
    }
}

impl CommitReceipt for ItemCommitReceipt {}

/// Terminal receipt proving a complete page is durable: findings, done-ledger,
/// and checkpoint have all been acknowledged.
///
/// Holding a `PageCommitReceipt` is sufficient proof that the cursor can be
/// safely advanced — no further persistence work is required for this page.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommitReceipt {
    item_commit: ItemCommitReceipt,
    checkpoint: CheckpointCommitReceipt,
}

impl PageCommitReceipt {
    /// Construct a page-commit receipt from item-commit and checkpoint proofs.
    ///
    /// `pub(super)` because only the [`PageCommit`](super::PageCommit)
    /// typestate machine should assemble this after validating the checkpoint
    /// receipt against the page scope.
    #[inline]
    #[must_use]
    pub(super) fn new(item_commit: ItemCommitReceipt, checkpoint: CheckpointCommitReceipt) -> Self {
        Self {
            item_commit,
            checkpoint,
        }
    }

    /// Durable findings plus done-ledger proof for the page.
    #[inline]
    #[must_use]
    pub fn item_commit(&self) -> &ItemCommitReceipt {
        &self.item_commit
    }

    /// Durable checkpoint proof for the page.
    #[inline]
    #[must_use]
    pub fn checkpoint(&self) -> &CheckpointCommitReceipt {
        &self.checkpoint
    }
}

impl CommitReceipt for PageCommitReceipt {}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::test_util::TestWaitError;

    #[test]
    fn ready_commit_handle_wait_returns_receipt() {
        let receipt = FindingsCommitReceipt::new(1, 2, 3);

        assert_eq!(
            ReadyCommitHandle::<FindingsCommitReceipt, TestWaitError>::ok(receipt)
                .wait()
                .unwrap(),
            receipt
        );
        assert_eq!(
            ReadyCommitHandle::from_result(Ok::<_, TestWaitError>(receipt))
                .wait()
                .unwrap(),
            receipt
        );
    }

    #[test]
    fn ready_commit_handle_wait_returns_error() {
        let error = TestWaitError("fsync failed");

        assert_eq!(
            ReadyCommitHandle::<FindingsCommitReceipt, _>::err(error.clone())
                .wait()
                .unwrap_err(),
            error
        );
    }
}
