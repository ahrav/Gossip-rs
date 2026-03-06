//! Typestate machine for persistence commit ordering.
//!
//! # Problem
//!
//! A page's data must become durable in a strict order so that crash
//! recovery never observes a checkpointed cursor without the corresponding
//! findings and done-ledger rows already on disk. Violating this ordering
//! can cause data loss (findings committed after a cursor advance that is
//! already visible to restart logic) or duplicate work (done-ledger rows
//! missing, causing re-scans).
//!
//! # Solution
//!
//! [`PageCommit<S>`] encodes the three mandatory durability stages as
//! type-level states:
//!
//! 1. **Findings** — persist detected-secret rows via the findings sink.
//! 2. **Done-ledger** — persist deduplication records via the done-ledger.
//! 3. **Checkpoint** — advance the shard cursor to mark the page complete.
//!
//! Each transition method is only available on the correct state, so callers
//! cannot skip or reorder stages. Transitions that accept a backend receipt
//! also validate that the receipt matches the page's [`PageCommitScope`],
//! catching receipt mix-ups between concurrent pages at the earliest point.
//!
//! # Transition methods
//!
//! Each stage offers two ways to advance:
//! - `record_*` — caller already holds the receipt (e.g. from a manual wait).
//! - `wait_*` — caller passes a [`CommitHandle`]; the method waits and then
//!   validates.
//!
//! # Design trade-offs
//!
//! - **Typestate vs runtime enum:** typestate makes invalid orderings a
//!   compile error at the cost of being generic over `S`. The alternative —
//!   a runtime state enum with panics — trades compile-time safety for
//!   simpler generics. Given that incorrect ordering is a data-loss bug,
//!   compile-time enforcement is worth the generics cost.
//! - **Full-scope validation on checkpoint:** only the checkpoint stage
//!   validates all scope fields (tenant, run, shard, epoch, cursor, item
//!   count). Findings and done-ledger receipts carry lighter payloads because
//!   they are produced by the same in-process pipeline that constructed the
//!   scope, while checkpoints go through a backend round-trip where mix-ups
//!   are more likely.

use std::{error::Error, fmt};

use crate::{
    connector::Cursor,
    identity::{FenceEpoch, RunId, ShardId, TenantId},
};

use super::commit::{
    CheckpointCommitReceipt, CommitHandle, DoneLedgerCommitReceipt, FindingsCommitReceipt,
    ItemCommitReceipt, PageCommitReceipt,
};

/// Immutable scope for a single page commit.
///
/// A page commit is always scoped to one tenant, run, shard, fence epoch,
/// item count, and cursor advancement boundary. The runtime constructs this
/// once, then drives the page through findings, done-ledger, and checkpoint
/// durability.
///
/// # Invariant
///
/// Once constructed, the scope is treated as a frozen reference: every
/// receipt-validation check compares against these values. If the scope were
/// mutated mid-protocol, the typestate guarantees would be meaningless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommitScope {
    tenant_id: TenantId,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    committed_items: u64,
    checkpoint_cursor: Cursor,
}

impl PageCommitScope {
    /// Construct the page scope.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        committed_items: u64,
        checkpoint_cursor: Cursor,
    ) -> Self {
        Self {
            tenant_id,
            run_id,
            shard_id,
            fence_epoch,
            committed_items,
            checkpoint_cursor,
        }
    }

    /// Tenant isolation boundary for the page.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Run that produced the page.
    #[inline]
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Shard that emitted the page.
    #[inline]
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Fence epoch under which the page was processed.
    #[inline]
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Number of items represented by the page.
    #[inline]
    #[must_use]
    pub const fn committed_items(&self) -> u64 {
        self.committed_items
    }

    /// Cursor boundary the checkpoint must durably acknowledge.
    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        &self.checkpoint_cursor
    }
}

/// Validation failures when advancing a page commit through its durable stages.
///
/// Each variant indicates that a receipt returned by the persistence backend
/// does not match the [`PageCommitScope`] of the page being committed. This
/// is a programming error or a backend mis-routing bug, never a transient
/// failure — callers should treat it as fatal for the affected page.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageCommitValidationError {
    /// The done-ledger receipt covers a different number of items than the page.
    LedgerItemCountMismatch { expected: u64, actual: u64 },
    /// The checkpoint receipt belongs to a different tenant.
    CheckpointTenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
    /// The checkpoint receipt belongs to a different run.
    CheckpointRunMismatch { expected: RunId, actual: RunId },
    /// The checkpoint receipt belongs to a different shard.
    CheckpointShardMismatch { expected: ShardId, actual: ShardId },
    /// The checkpoint receipt belongs to a different fence epoch.
    CheckpointFenceMismatch {
        expected: FenceEpoch,
        actual: FenceEpoch,
    },
    /// The checkpoint receipt covers a different number of items than the page.
    CheckpointItemCountMismatch { expected: u64, actual: u64 },
    /// The checkpoint receipt advanced to a different cursor than expected.
    CheckpointCursorMismatch,
}

impl fmt::Display for PageCommitValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerItemCountMismatch { expected, actual } => write!(
                f,
                "done-ledger receipt item count mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckpointTenantMismatch { .. } => {
                write!(f, "checkpoint receipt tenant does not match page scope")
            }
            Self::CheckpointRunMismatch { .. } => {
                write!(f, "checkpoint receipt run does not match page scope")
            }
            Self::CheckpointShardMismatch { .. } => {
                write!(f, "checkpoint receipt shard does not match page scope")
            }
            Self::CheckpointFenceMismatch { .. } => {
                write!(
                    f,
                    "checkpoint receipt fence epoch does not match page scope"
                )
            }
            Self::CheckpointItemCountMismatch { expected, actual } => write!(
                f,
                "checkpoint receipt item count mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckpointCursorMismatch => {
                write!(f, "checkpoint receipt cursor does not match page scope")
            }
        }
    }
}

impl Error for PageCommitValidationError {}

/// Combined wait or validation error for `wait_*` state transitions.
///
/// `Wait` errors are transient backend failures (disk I/O, replication timeout)
/// that may be retryable. `Validation` errors are deterministic scope mismatches
/// that indicate a bug — retrying will produce the same result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommitAdvanceError<E> {
    /// Waiting for the backend handle failed (possibly transient).
    Wait(E),
    /// The durable receipt did not match the page scope (deterministic bug).
    Validation(PageCommitValidationError),
}

impl<E> fmt::Display for CommitAdvanceError<E>
where
    E: fmt::Display,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Wait(err) => write!(f, "durable wait failed: {err}"),
            Self::Validation(err) => write!(f, "invalid durable receipt: {err}"),
        }
    }
}

impl<E> Error for CommitAdvanceError<E>
where
    E: Error + Send + Sync + 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Wait(err) => Some(err),
            Self::Validation(err) => Some(err),
        }
    }
}

/// Typestate: no durable acknowledgement yet. Entry point of the protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AwaitingFindings;

/// Typestate: findings are durable; done-ledger is the next required step.
///
/// Carries the findings receipt so it can be bundled into the composite
/// [`ItemCommitReceipt`] when the done-ledger stage completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FindingsDurable {
    findings: FindingsCommitReceipt,
}

/// Typestate: findings and done-ledger are durable; checkpoint is the next
/// required step.
///
/// Carries the composite [`ItemCommitReceipt`] so callers can extract it
/// if they only need item-level proof (e.g. for progress reporting before
/// the checkpoint round-trip completes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ItemDurable {
    item_commit: ItemCommitReceipt,
}

/// Typestate: terminal state. All three stages are durable.
///
/// The [`PageCommitReceipt`] inside is sufficient proof that the cursor can
/// be safely advanced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointDurable {
    page_commit: PageCommitReceipt,
}

/// Typestate machine for the page-commit protocol.
///
/// The type parameter `S` is one of [`AwaitingFindings`], [`FindingsDurable`],
/// [`ItemDurable`], or [`CheckpointDurable`]. Each impl block exposes only
/// the transition methods valid for that state, so the compiler rejects
/// out-of-order calls.
///
/// # State transitions
///
/// ```text
/// AwaitingFindings ──record_findings──▸ FindingsDurable
///                                          │
///                              record_done_ledger (validates item count)
///                                          │
///                                          ▾
///                                      ItemDurable
///                                          │
///                              record_checkpoint (validates full scope)
///                                          │
///                                          ▾
///                                   CheckpointDurable
/// ```
///
/// # Compile-time enforcement examples
///
/// Skipping findings and jumping straight to done-ledger is a type error:
///
/// ```compile_fail
/// use gossip_contracts::{
///     connector::Cursor,
///     identity::{FenceEpoch, RunId, ShardId, TenantId},
///     persistence::{DoneLedgerCommitReceipt, PageCommit, PageCommitScope},
/// };
///
/// let page = PageCommit::new(PageCommitScope::new(
///     TenantId::from_bytes([1; 32]),
///     RunId::from_raw(2),
///     ShardId::from_raw(3),
///     FenceEpoch::from_raw(4),
///     1,
///     Cursor::initial(),
/// ));
///
/// let _ = page.record_done_ledger(DoneLedgerCommitReceipt::new(1, 1, 0));
/// ```
///
/// Skipping done-ledger and jumping from findings to checkpoint is also
/// a type error:
///
/// ```compile_fail
/// use gossip_contracts::{
///     connector::Cursor,
///     identity::{FenceEpoch, LogicalTime, RunId, ShardId, TenantId},
///     persistence::{CheckpointCommitReceipt, FindingsCommitReceipt, PageCommit, PageCommitScope},
/// };
///
/// let scope = PageCommitScope::new(
///     TenantId::from_bytes([1; 32]),
///     RunId::from_raw(2),
///     ShardId::from_raw(3),
///     FenceEpoch::from_raw(4),
///     1,
///     Cursor::initial(),
/// );
/// let page = PageCommit::new(scope.clone()).record_findings(FindingsCommitReceipt::new(1, 1, 1));
/// let checkpoint = CheckpointCommitReceipt::new(
///     scope.tenant_id(),
///     scope.run_id(),
///     scope.shard_id(),
///     scope.fence_epoch(),
///     scope.checkpoint_cursor().clone(),
///     scope.committed_items(),
///     LogicalTime::from_raw(5),
/// );
///
/// let _ = page.record_checkpoint(checkpoint);
/// ```
#[must_use = "page commits must be driven to a durable receipt or explicitly dropped"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommit<S> {
    scope: PageCommitScope,
    state: S,
}

impl<S> PageCommit<S> {
    /// Page scope shared across all typestates.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &PageCommitScope {
        &self.scope
    }
}

impl PageCommit<AwaitingFindings> {
    /// Start a new page commit for `scope`.
    #[inline]
    pub fn new(scope: PageCommitScope) -> Self {
        Self {
            scope,
            state: AwaitingFindings,
        }
    }

    /// Advance the page after obtaining a durable findings receipt.
    ///
    /// No validation is performed on the findings receipt because it carries
    /// only aggregate counts, not scope-identifying fields. The findings sink
    /// is driven by the same in-process pipeline that constructed the scope,
    /// so cross-page mix-ups are structurally prevented.
    #[inline]
    pub fn record_findings(self, receipt: FindingsCommitReceipt) -> PageCommit<FindingsDurable> {
        PageCommit {
            scope: self.scope,
            state: FindingsDurable { findings: receipt },
        }
    }

    /// Wait on a findings [`CommitHandle`] and advance on success.
    ///
    /// Combines `handle.wait()` with [`record_findings`](Self::record_findings).
    /// The error is the backend's wait error; there is no validation error for
    /// findings (see `record_findings` for rationale).
    pub fn wait_findings<H>(self, handle: H) -> Result<PageCommit<FindingsDurable>, H::Error>
    where
        H: CommitHandle<Receipt = FindingsCommitReceipt>,
    {
        let receipt = handle.wait()?;
        Ok(self.record_findings(receipt))
    }
}

impl PageCommit<FindingsDurable> {
    /// Durable findings receipt for this page.
    #[inline]
    #[must_use]
    pub const fn findings_receipt(&self) -> FindingsCommitReceipt {
        self.state.findings
    }

    /// Advance the page after obtaining a durable done-ledger receipt.
    ///
    /// # Errors
    ///
    /// Returns [`PageCommitValidationError::LedgerItemCountMismatch`] if the
    /// receipt's `record_count` does not equal `scope.committed_items()`.
    /// This guards against partial or mixed-page done-ledger flushes.
    pub fn record_done_ledger(
        self,
        receipt: DoneLedgerCommitReceipt,
    ) -> Result<PageCommit<ItemDurable>, PageCommitValidationError> {
        let expected = self.scope.committed_items();
        let actual = receipt.record_count();
        if expected != actual {
            return Err(PageCommitValidationError::LedgerItemCountMismatch { expected, actual });
        }

        let item_commit = ItemCommitReceipt::new(self.scope.clone(), self.state.findings, receipt);
        Ok(PageCommit {
            scope: self.scope,
            state: ItemDurable { item_commit },
        })
    }

    /// Wait on a done-ledger [`CommitHandle`] and advance on success.
    ///
    /// Combines `handle.wait()` with [`record_done_ledger`](Self::record_done_ledger).
    /// Returns [`CommitAdvanceError::Wait`] for backend failures or
    /// [`CommitAdvanceError::Validation`] if the receipt's item count
    /// does not match the page scope.
    pub fn wait_done_ledger<H>(
        self,
        handle: H,
    ) -> Result<PageCommit<ItemDurable>, CommitAdvanceError<H::Error>>
    where
        H: CommitHandle<Receipt = DoneLedgerCommitReceipt>,
    {
        let receipt = handle.wait().map_err(CommitAdvanceError::Wait)?;
        self.record_done_ledger(receipt)
            .map_err(CommitAdvanceError::Validation)
    }
}

impl PageCommit<ItemDurable> {
    /// Composite receipt proving durable findings and done-ledger persistence.
    #[inline]
    #[must_use]
    pub fn item_commit_receipt(&self) -> &ItemCommitReceipt {
        &self.state.item_commit
    }

    /// Consume the state into the item-commit receipt.
    #[inline]
    #[must_use]
    pub fn into_item_commit_receipt(self) -> ItemCommitReceipt {
        self.state.item_commit
    }

    /// Advance the page after obtaining a durable checkpoint receipt.
    ///
    /// Performs full scope validation: tenant, run, shard, fence epoch, item
    /// count, and cursor must all match the page's [`PageCommitScope`].
    /// This is the most thorough validation in the protocol because the
    /// checkpoint receipt travels through a backend round-trip where routing
    /// errors between concurrent pages are possible.
    ///
    /// # Errors
    ///
    /// Returns the first mismatched field as a
    /// [`PageCommitValidationError`]. Fields are checked in a fixed order
    /// (tenant → run → shard → epoch → item count → cursor), so only the
    /// first mismatch is reported.
    pub fn record_checkpoint(
        self,
        receipt: CheckpointCommitReceipt,
    ) -> Result<PageCommit<CheckpointDurable>, PageCommitValidationError> {
        if receipt.tenant_id() != self.scope.tenant_id() {
            return Err(PageCommitValidationError::CheckpointTenantMismatch {
                expected: self.scope.tenant_id(),
                actual: receipt.tenant_id(),
            });
        }
        if receipt.run_id() != self.scope.run_id() {
            return Err(PageCommitValidationError::CheckpointRunMismatch {
                expected: self.scope.run_id(),
                actual: receipt.run_id(),
            });
        }
        if receipt.shard_id() != self.scope.shard_id() {
            return Err(PageCommitValidationError::CheckpointShardMismatch {
                expected: self.scope.shard_id(),
                actual: receipt.shard_id(),
            });
        }
        if receipt.fence_epoch() != self.scope.fence_epoch() {
            return Err(PageCommitValidationError::CheckpointFenceMismatch {
                expected: self.scope.fence_epoch(),
                actual: receipt.fence_epoch(),
            });
        }
        if receipt.committed_items() != self.scope.committed_items() {
            return Err(PageCommitValidationError::CheckpointItemCountMismatch {
                expected: self.scope.committed_items(),
                actual: receipt.committed_items(),
            });
        }
        if receipt.cursor() != self.scope.checkpoint_cursor() {
            return Err(PageCommitValidationError::CheckpointCursorMismatch);
        }

        let page_commit = PageCommitReceipt::new(self.state.item_commit, receipt);
        Ok(PageCommit {
            scope: self.scope,
            state: CheckpointDurable { page_commit },
        })
    }

    /// Wait on a checkpoint [`CommitHandle`] and advance on success.
    ///
    /// Combines `handle.wait()` with [`record_checkpoint`](Self::record_checkpoint).
    /// Returns [`CommitAdvanceError::Wait`] for backend failures or
    /// [`CommitAdvanceError::Validation`] if any scope field does not match.
    pub fn wait_checkpoint<H>(
        self,
        handle: H,
    ) -> Result<PageCommit<CheckpointDurable>, CommitAdvanceError<H::Error>>
    where
        H: CommitHandle<Receipt = CheckpointCommitReceipt>,
    {
        let receipt = handle.wait().map_err(CommitAdvanceError::Wait)?;
        self.record_checkpoint(receipt)
            .map_err(CommitAdvanceError::Validation)
    }
}

impl PageCommit<CheckpointDurable> {
    /// Final durable page receipt.
    #[inline]
    #[must_use]
    pub fn page_commit_receipt(&self) -> &PageCommitReceipt {
        &self.state.page_commit
    }

    /// Consume the state into the final durable page receipt.
    #[inline]
    #[must_use]
    pub fn into_page_commit_receipt(self) -> PageCommitReceipt {
        self.state.page_commit
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt;

    use rstest::rstest;

    use crate::{
        connector::ItemKey,
        identity::{LogicalTime, TenantId},
    };

    use super::super::commit::ReadyCommitHandle;

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct TestWaitError(&'static str);

    impl fmt::Display for TestWaitError {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str(self.0)
        }
    }

    impl Error for TestWaitError {}

    fn tenant(seed: u8) -> TenantId {
        TenantId::from_bytes([seed; 32])
    }

    fn sample_cursor(seed: u8) -> Cursor {
        Cursor::with_last_key(ItemKey::try_from_slice(&[seed]).unwrap())
    }

    fn sample_scope() -> PageCommitScope {
        PageCommitScope::new(
            tenant(1),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            2,
            sample_cursor(5),
        )
    }

    fn sample_findings_receipt() -> FindingsCommitReceipt {
        FindingsCommitReceipt::new(2, 3, 4)
    }

    fn sample_done_ledger_receipt(record_count: u64) -> DoneLedgerCommitReceipt {
        DoneLedgerCommitReceipt::new(record_count, record_count, 4)
    }

    fn sample_checkpoint_receipt(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            scope.run_id(),
            scope.shard_id(),
            scope.fence_epoch(),
            scope.checkpoint_cursor().clone(),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    fn sample_item_commit() -> PageCommit<ItemDurable> {
        let scope = sample_scope();
        PageCommit::new(scope.clone())
            .record_findings(sample_findings_receipt())
            .record_done_ledger(sample_done_ledger_receipt(scope.committed_items()))
            .unwrap()
    }

    fn checkpoint_tenant_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            tenant(9),
            scope.run_id(),
            scope.shard_id(),
            scope.fence_epoch(),
            scope.checkpoint_cursor().clone(),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    fn checkpoint_run_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            RunId::from_raw(scope.run_id().as_raw() + 1),
            scope.shard_id(),
            scope.fence_epoch(),
            scope.checkpoint_cursor().clone(),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    fn checkpoint_shard_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            scope.run_id(),
            ShardId::from_raw(scope.shard_id().as_raw() + 1),
            scope.fence_epoch(),
            scope.checkpoint_cursor().clone(),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    fn checkpoint_fence_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            scope.run_id(),
            scope.shard_id(),
            FenceEpoch::from_raw(scope.fence_epoch().as_raw() + 1),
            scope.checkpoint_cursor().clone(),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    fn checkpoint_item_count_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            scope.run_id(),
            scope.shard_id(),
            scope.fence_epoch(),
            scope.checkpoint_cursor().clone(),
            scope.committed_items() + 1,
            LogicalTime::from_raw(99),
        )
    }

    fn checkpoint_cursor_mismatch(scope: &PageCommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(
            scope.tenant_id(),
            scope.run_id(),
            scope.shard_id(),
            scope.fence_epoch(),
            sample_cursor(8),
            scope.committed_items(),
            LogicalTime::from_raw(99),
        )
    }

    #[test]
    fn page_commit_happy_path_produces_full_page_receipt() {
        let scope = sample_scope();
        let page = PageCommit::new(scope.clone())
            .wait_findings(
                ReadyCommitHandle::<FindingsCommitReceipt, TestWaitError>::ok(
                    sample_findings_receipt(),
                ),
            )
            .unwrap()
            .wait_done_ledger(
                ReadyCommitHandle::<DoneLedgerCommitReceipt, TestWaitError>::ok(
                    sample_done_ledger_receipt(scope.committed_items()),
                ),
            )
            .unwrap()
            .wait_checkpoint(
                ReadyCommitHandle::<CheckpointCommitReceipt, TestWaitError>::ok(
                    sample_checkpoint_receipt(&scope),
                ),
            )
            .unwrap();

        let receipt = page.into_page_commit_receipt();
        assert_eq!(receipt.item_commit().scope(), &scope);
        assert_eq!(receipt.item_commit().findings(), sample_findings_receipt());
        assert_eq!(
            receipt.item_commit().done_ledger(),
            sample_done_ledger_receipt(scope.committed_items())
        );
        assert_eq!(receipt.checkpoint(), &sample_checkpoint_receipt(&scope));
    }

    #[test]
    fn record_done_ledger_rejects_mismatched_item_count() {
        let scope = sample_scope();
        let page = PageCommit::new(scope.clone()).record_findings(sample_findings_receipt());

        assert_eq!(
            page.record_done_ledger(sample_done_ledger_receipt(scope.committed_items() + 1))
                .unwrap_err(),
            PageCommitValidationError::LedgerItemCountMismatch {
                expected: scope.committed_items(),
                actual: scope.committed_items() + 1,
            }
        );
    }

    #[test]
    fn wait_done_ledger_wraps_wait_errors() {
        let page = PageCommit::new(sample_scope()).record_findings(sample_findings_receipt());

        assert_eq!(
            page.wait_done_ledger(ReadyCommitHandle::<DoneLedgerCommitReceipt, _>::err(
                TestWaitError("ledger wait failed"),
            ))
            .unwrap_err(),
            CommitAdvanceError::Wait(TestWaitError("ledger wait failed"))
        );
    }

    #[test]
    fn wait_done_ledger_wraps_validation_errors() {
        let scope = sample_scope();
        let page = PageCommit::new(scope.clone()).record_findings(sample_findings_receipt());

        assert_eq!(
            page.wait_done_ledger(
                ReadyCommitHandle::<DoneLedgerCommitReceipt, TestWaitError>::ok(
                    sample_done_ledger_receipt(scope.committed_items() + 1),
                )
            )
            .unwrap_err(),
            CommitAdvanceError::<TestWaitError>::Validation(
                PageCommitValidationError::LedgerItemCountMismatch {
                    expected: scope.committed_items(),
                    actual: scope.committed_items() + 1,
                },
            )
        );
    }

    #[rstest]
    #[case::tenant(
        checkpoint_tenant_mismatch,
        PageCommitValidationError::CheckpointTenantMismatch {
            expected: tenant(1),
            actual: tenant(9),
        },
    )]
    #[case::run(
        checkpoint_run_mismatch,
        PageCommitValidationError::CheckpointRunMismatch {
            expected: RunId::from_raw(2),
            actual: RunId::from_raw(3),
        },
    )]
    #[case::shard(
        checkpoint_shard_mismatch,
        PageCommitValidationError::CheckpointShardMismatch {
            expected: ShardId::from_raw(3),
            actual: ShardId::from_raw(4),
        },
    )]
    #[case::fence(
        checkpoint_fence_mismatch,
        PageCommitValidationError::CheckpointFenceMismatch {
            expected: FenceEpoch::from_raw(4),
            actual: FenceEpoch::from_raw(5),
        },
    )]
    #[case::item_count(
        checkpoint_item_count_mismatch,
        PageCommitValidationError::CheckpointItemCountMismatch {
            expected: 2,
            actual: 3,
        },
    )]
    #[case::cursor(
        checkpoint_cursor_mismatch,
        PageCommitValidationError::CheckpointCursorMismatch
    )]
    fn record_checkpoint_rejects_scope_mismatches(
        #[case] make_receipt: fn(&PageCommitScope) -> CheckpointCommitReceipt,
        #[case] expected: PageCommitValidationError,
    ) {
        let page = sample_item_commit();
        let scope = page.scope().clone();

        assert_eq!(
            page.record_checkpoint(make_receipt(&scope)).unwrap_err(),
            expected
        );
    }

    #[test]
    fn wait_checkpoint_wraps_wait_errors() {
        let page = sample_item_commit();

        assert_eq!(
            page.wait_checkpoint(ReadyCommitHandle::<CheckpointCommitReceipt, _>::err(
                TestWaitError("checkpoint wait failed"),
            ))
            .unwrap_err(),
            CommitAdvanceError::Wait(TestWaitError("checkpoint wait failed"))
        );
    }

    #[test]
    fn wait_checkpoint_wraps_validation_errors() {
        let page = sample_item_commit();
        let scope = page.scope().clone();

        assert_eq!(
            page.wait_checkpoint(
                ReadyCommitHandle::<CheckpointCommitReceipt, TestWaitError>::ok(
                    checkpoint_cursor_mismatch(&scope),
                )
            )
            .unwrap_err(),
            CommitAdvanceError::<TestWaitError>::Validation(
                PageCommitValidationError::CheckpointCursorMismatch,
            )
        );
    }
}
