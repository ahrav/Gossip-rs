//! Typestate machine for persistence commit ordering.
//!
//! # Problem
//!
//! A page's data must become durable in a strict order so that crash
//! recovery never observes a checkpointed frontier boundary without the
//! corresponding findings and done-ledger rows already on disk. Violating
//! this ordering can cause data loss (findings committed after a frontier
//! advance that is already visible to restart logic) or duplicate work
//! (done-ledger rows missing, causing re-scans).
//!
//! # Solution
//!
//! [`PageCommit<S>`] encodes the three mandatory durability stages as
//! type-level states:
//!
//! 1. **Findings** — persist detected-secret rows via the findings sink.
//! 2. **Done-ledger** — persist deduplication records via the done-ledger.
//! 3. **Checkpoint** — advance the family-specific frontier boundary to mark
//!    the page complete.
//!
//! Each transition method is only available on the correct state, so callers
//! cannot skip or reorder stages. Transitions that accept a backend receipt
//! also validate that the receipt matches the page's [`CommitScope`],
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
//! - **Scope validation on checkpoint:** the checkpoint receipt embeds a
//!   full [`CommitScope`], so the typestate machine validates receipt-
//!   to-scope correspondence with a single equality check. Findings and
//!   done-ledger receipts carry lighter payloads because they are produced
//!   by the same in-process pipeline that constructed the scope, while
//!   checkpoints go through a backend round-trip where mix-ups are more
//!   likely.
//!
//! # Error handling
//!
//! `wait_*` methods consume the state machine. If the backend wait fails,
//! the `PageCommit` is gone and the caller must reconstruct a new one from
//! scratch. This is intentional: after a wait failure, the page's I/O state
//! is unknown (the backend may or may not have committed), so the only safe
//! action is to treat the page as abandoned and retry the full page-commit
//! protocol from `AwaitingFindings`.
//!
//! Callers that need finer retry control should use `record_*` methods with
//! a separately managed `handle.wait()` call, keeping the `PageCommit` alive
//! until a receipt is in hand.
//!
//! `record_*` validation failures (e.g. [`PageCommitValidationError`]) are
//! deterministic scope mismatches — retrying will produce the same result.
//! These indicate a programming error, not a transient failure.

use std::{error::Error, fmt, num::NonZeroU64, sync::Arc};

use crate::{
    connector::Cursor,
    identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
};

use super::{
    WriteContext,
    commit::{
        CheckpointCommitReceipt, CommitHandle, DoneLedgerCommitReceipt, FindingsCommitReceipt,
        ItemCommitReceipt, PageCommitReceipt,
    },
};

/// Semantic domain for a durable checkpoint boundary.
///
/// Ordered-content execution advances by item cursor, while repo-native Git
/// execution advances by repo-frontier position. Both are encoded as a
/// monotonic [`Cursor`] at the persistence boundary, but the tag keeps the
/// family semantics explicit so runtime code cannot accidentally mix them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CheckpointBoundaryKind {
    /// Ordered-content item frontier (`last committed item key`, optional token).
    OrderedContent,
    /// Repo-frontier progress (`last committed repo key`, optional token).
    RepoFrontier,
}

/// Family-neutral durable checkpoint boundary.
///
/// The payload stays as a [`Cursor`] because both supported source families
/// (ordered-content and repo-frontier) reduce to a monotonic frontier position
/// plus optional opaque token.
/// The enum tag carries the semantic domain that the runtime must preserve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CheckpointBoundary {
    /// Ordered-content checkpoint boundary.
    OrderedContent(Cursor),
    /// Repo-frontier checkpoint boundary.
    RepoFrontier(Cursor),
}

impl CheckpointBoundary {
    /// Construct an ordered-content checkpoint boundary.
    #[inline]
    #[must_use]
    pub fn ordered_content(cursor: Cursor) -> Self {
        Self::OrderedContent(cursor)
    }

    /// Construct a repo-frontier checkpoint boundary.
    #[inline]
    #[must_use]
    pub fn repo_frontier(cursor: Cursor) -> Self {
        Self::RepoFrontier(cursor)
    }

    /// Semantic domain carried by this checkpoint boundary.
    #[inline]
    #[must_use]
    pub const fn kind(&self) -> CheckpointBoundaryKind {
        match self {
            Self::OrderedContent(_) => CheckpointBoundaryKind::OrderedContent,
            Self::RepoFrontier(_) => CheckpointBoundaryKind::RepoFrontier,
        }
    }

    /// Returns `true` when this is an ordered-content boundary.
    #[inline]
    #[must_use]
    pub const fn is_ordered_content(&self) -> bool {
        matches!(self, Self::OrderedContent(_))
    }

    /// Returns `true` when this is a repo-frontier boundary.
    #[inline]
    #[must_use]
    pub const fn is_repo_frontier(&self) -> bool {
        matches!(self, Self::RepoFrontier(_))
    }

    /// Underlying monotonic frontier position.
    #[inline]
    #[must_use]
    pub fn cursor(&self) -> &Cursor {
        match self {
            Self::OrderedContent(cursor) | Self::RepoFrontier(cursor) => cursor,
        }
    }

    /// Ordered-content cursor view, if this boundary belongs to that family.
    #[inline]
    #[must_use]
    pub fn as_ordered_content(&self) -> Option<&Cursor> {
        match self {
            Self::OrderedContent(cursor) => Some(cursor),
            Self::RepoFrontier(_) => None,
        }
    }

    /// Repo-frontier cursor view, if this boundary belongs to that family.
    #[inline]
    #[must_use]
    pub fn as_repo_frontier(&self) -> Option<&Cursor> {
        match self {
            Self::OrderedContent(_) => None,
            Self::RepoFrontier(cursor) => Some(cursor),
        }
    }
}

impl fmt::Display for CheckpointBoundary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrderedContent(cursor) => write!(f, "OrderedContent({cursor:?})"),
            Self::RepoFrontier(cursor) => write!(f, "RepoFrontier({cursor:?})"),
        }
    }
}

/// Immutable scope for one durable commit boundary.
///
/// A commit scope is always bound to one tenant, policy, run, shard, fence
/// epoch, committed-prefix length, and checkpoint boundary. The runtime freezes
/// this scope once, then drives the work through findings, done-ledger, and
/// checkpoint durability.
///
/// `policy_hash` is carried for scope-identity completeness — checkpoint receipt
/// validation compares the full scope — even though checkpoint routing itself is
/// policy-independent.
///
/// # Invariant
///
/// Once constructed, the scope is treated as a frozen reference: every
/// receipt-validation check compares against these values. If the scope were
/// mutated mid-protocol, the typestate guarantees would be meaningless.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommitScope {
    tenant_id: TenantId,
    policy_hash: PolicyHash,
    run_id: RunId,
    shard_id: ShardId,
    fence_epoch: FenceEpoch,
    committed_units: NonZeroU64,
    checkpoint_boundary: CheckpointBoundary,
}

impl CommitScope {
    /// Construct the commit scope.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        policy_hash: PolicyHash,
        run_id: RunId,
        shard_id: ShardId,
        fence_epoch: FenceEpoch,
        committed_units: NonZeroU64,
        checkpoint_boundary: CheckpointBoundary,
    ) -> Self {
        Self {
            tenant_id,
            policy_hash,
            run_id,
            shard_id,
            fence_epoch,
            committed_units,
            checkpoint_boundary,
        }
    }

    /// Construct a commit scope from a shared write context.
    ///
    /// Extracts tenant, policy, run, shard, and fence epoch from the
    /// [`WriteContext`]; the caller supplies the remaining commit-specific
    /// fields.
    #[must_use]
    pub fn from_write_context(
        wc: WriteContext,
        committed_units: NonZeroU64,
        checkpoint_boundary: CheckpointBoundary,
    ) -> Self {
        Self::new(
            wc.tenant_id(),
            wc.policy_hash(),
            wc.run_id(),
            wc.shard_id(),
            wc.fence_epoch(),
            committed_units,
            checkpoint_boundary,
        )
    }

    /// Tenant isolation boundary for this scope.
    #[inline]
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Detection-policy version under which the scope was produced.
    #[inline]
    #[must_use]
    pub const fn policy_hash(&self) -> PolicyHash {
        self.policy_hash
    }

    /// Run that produced this scope.
    #[inline]
    #[must_use]
    pub const fn run_id(&self) -> RunId {
        self.run_id
    }

    /// Shard that emitted this scope.
    #[inline]
    #[must_use]
    pub const fn shard_id(&self) -> ShardId {
        self.shard_id
    }

    /// Fence epoch under which the scope was processed.
    #[inline]
    #[must_use]
    pub const fn fence_epoch(&self) -> FenceEpoch {
        self.fence_epoch
    }

    /// Number of committed units represented by this scope.
    #[inline]
    #[must_use]
    pub const fn committed_units(&self) -> NonZeroU64 {
        self.committed_units
    }

    /// Family-neutral checkpoint boundary the receipt must durably acknowledge.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary(&self) -> &CheckpointBoundary {
        &self.checkpoint_boundary
    }

    /// Semantic domain for the checkpoint boundary.
    #[inline]
    #[must_use]
    pub fn checkpoint_boundary_kind(&self) -> CheckpointBoundaryKind {
        self.checkpoint_boundary.kind()
    }

    /// Underlying frontier position shared by ordered-content and repo-frontier
    /// checkpoints.
    #[inline]
    #[must_use]
    pub fn checkpoint_cursor(&self) -> &Cursor {
        self.checkpoint_boundary.cursor()
    }

    /// Reconstruct the shared write context from this scope's routing and
    /// fencing fields.
    #[inline]
    #[must_use]
    pub const fn write_context(&self) -> WriteContext {
        WriteContext::new(
            self.tenant_id,
            self.policy_hash,
            self.run_id,
            self.shard_id,
            self.fence_epoch,
        )
    }
}

/// Validation failures when advancing a page commit through its durable stages.
///
/// Each variant indicates that a receipt returned by the persistence backend
/// does not match the [`CommitScope`] of the page being committed. This
/// is a programming error or a backend mis-routing bug, never a transient
/// failure — callers should treat it as fatal for the affected page.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PageCommitValidationError {
    /// The done-ledger receipt covers a different number of units than the page.
    LedgerUnitCountMismatch { expected: u64, actual: u64 },
    /// The checkpoint receipt's scope does not match the page scope.
    CheckpointScopeMismatch {
        expected: Box<CommitScope>,
        actual: Box<CommitScope>,
    },
}

impl fmt::Display for PageCommitValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LedgerUnitCountMismatch { expected, actual } => write!(
                f,
                "done-ledger receipt unit count mismatch: expected {expected}, got {actual}"
            ),
            Self::CheckpointScopeMismatch { expected, actual } => write!(
                f,
                "checkpoint receipt scope does not match page scope \
                 (expected tenant={:?}, policy={:?}, shard={:?}, run={:?}, epoch={:?}, \
                 units={}, boundary={}; \
                 actual tenant={:?}, policy={:?}, shard={:?}, run={:?}, epoch={:?}, \
                 units={}, boundary={})",
                expected.tenant_id(),
                expected.policy_hash(),
                expected.shard_id(),
                expected.run_id(),
                expected.fence_epoch(),
                expected.committed_units(),
                expected.checkpoint_boundary(),
                actual.tenant_id(),
                actual.policy_hash(),
                actual.shard_id(),
                actual.run_id(),
                actual.fence_epoch(),
                actual.committed_units(),
                actual.checkpoint_boundary(),
            ),
        }
    }
}

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
/// The [`PageCommitReceipt`] inside is proof that the frontier boundary has
/// been durably checkpointed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointDurable {
    page_commit: PageCommitReceipt,
}

// Compile-time proof that page-commit types can move across threads.
const _: fn() = || {
    fn assert_impl<T: Send + Sync>() {}
    assert_impl::<CheckpointBoundaryKind>();
    assert_impl::<CheckpointBoundary>();
    assert_impl::<CommitScope>();
};

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
/// use std::num::NonZeroU64;
/// use gossip_contracts::{
///     connector::Cursor,
///     identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
///     persistence::{CheckpointBoundary, CommitScope, DoneLedgerCommitReceipt, PageCommit},
/// };
///
/// let page = PageCommit::new(CommitScope::new(
///     TenantId::from_bytes([1; 32]),
///     PolicyHash::from_bytes([2; 32]),
///     RunId::from_raw(3),
///     ShardId::from_raw(4),
///     FenceEpoch::from_raw(5),
///     NonZeroU64::new(1).unwrap(),
///     CheckpointBoundary::ordered_content(Cursor::initial()),
/// ));
///
/// let _ = page.record_done_ledger(DoneLedgerCommitReceipt::new(1, 1, 0));
/// ```
///
/// Skipping done-ledger and jumping from findings to checkpoint is also
/// a type error:
///
/// ```compile_fail
/// use std::num::NonZeroU64;
/// use gossip_contracts::{
///     connector::Cursor,
///     identity::{FenceEpoch, LogicalTime, PolicyHash, RunId, ShardId, TenantId},
///     persistence::{
///         CheckpointBoundary, CheckpointCommitReceipt, CommitScope, FindingsCommitReceipt,
///         PageCommit,
///     },
/// };
///
/// let scope = CommitScope::new(
///     TenantId::from_bytes([1; 32]),
///     PolicyHash::from_bytes([2; 32]),
///     RunId::from_raw(3),
///     ShardId::from_raw(4),
///     FenceEpoch::from_raw(5),
///     NonZeroU64::new(1).unwrap(),
///     CheckpointBoundary::ordered_content(Cursor::initial()),
/// );
/// let page = PageCommit::new(scope.clone()).record_findings(FindingsCommitReceipt::new(1, 1, 1));
/// let checkpoint = CheckpointCommitReceipt::new(scope.clone(), LogicalTime::from_raw(5));
///
/// let _ = page.record_checkpoint(checkpoint);
/// ```
#[must_use = "page commits must be driven to a durable receipt or explicitly dropped"]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageCommit<S> {
    /// `Arc` because the scope is shared between the state machine and the
    /// [`ItemCommitReceipt`] produced during the done-ledger transition.
    scope: Arc<CommitScope>,
    state: S,
}

impl<S> PageCommit<S> {
    /// Page scope shared across all typestates.
    #[inline]
    #[must_use]
    pub fn scope(&self) -> &CommitScope {
        &self.scope
    }
}

impl PageCommit<AwaitingFindings> {
    /// Start a new page commit for `scope`.
    #[inline]
    pub fn new(scope: CommitScope) -> Self {
        Self {
            scope: Arc::new(scope),
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
    /// Returns [`PageCommitValidationError::LedgerUnitCountMismatch`] if the
    /// receipt's `record_count` does not equal `scope.committed_units()`.
    /// This guards against partial or mixed-page done-ledger flushes.
    pub fn record_done_ledger(
        self,
        receipt: DoneLedgerCommitReceipt,
    ) -> Result<PageCommit<ItemDurable>, PageCommitValidationError> {
        let expected = self.scope.committed_units().get();
        let actual = receipt.record_count();
        if expected != actual {
            return Err(PageCommitValidationError::LedgerUnitCountMismatch { expected, actual });
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
    /// Validates that the receipt's embedded [`CommitScope`] matches this
    /// page's scope exactly. This guards against receipt mix-ups between
    /// concurrent pages at the earliest possible point.
    ///
    /// # Errors
    ///
    /// Returns [`PageCommitValidationError::CheckpointScopeMismatch`] if the
    /// receipt's scope differs from the page's scope in any field.
    pub fn record_checkpoint(
        self,
        receipt: CheckpointCommitReceipt,
    ) -> Result<PageCommit<CheckpointDurable>, PageCommitValidationError> {
        if receipt.scope() != self.scope() {
            return Err(PageCommitValidationError::CheckpointScopeMismatch {
                expected: Box::new(self.scope().clone()),
                actual: Box::new(receipt.scope().clone()),
            });
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

#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<CheckpointBoundary>() == 72);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(core::mem::size_of::<CommitScope>() == 168);

#[cfg(test)]
mod tests {
    use super::*;

    use std::num::NonZeroU64;

    use crate::{
        connector::ItemKey,
        identity::{LogicalTime, PolicyHash},
        test_util::{TestWaitError, tenant},
    };

    use super::super::commit::ReadyCommitHandle;

    fn sample_cursor(seed: u8) -> Cursor {
        Cursor::with_last_key(ItemKey::try_from_slice(&[seed]).unwrap())
    }

    fn sample_scope() -> CommitScope {
        CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(2).unwrap(),
            CheckpointBoundary::ordered_content(sample_cursor(5)),
        )
    }

    fn sample_findings_receipt() -> FindingsCommitReceipt {
        FindingsCommitReceipt::new(2, 3, 4)
    }

    fn sample_done_ledger_receipt(record_count: u64) -> DoneLedgerCommitReceipt {
        DoneLedgerCommitReceipt::new(record_count, record_count, 4)
    }

    fn sample_checkpoint_receipt(scope: &CommitScope) -> CheckpointCommitReceipt {
        CheckpointCommitReceipt::new(scope.clone(), LogicalTime::from_raw(99))
    }

    fn sample_item_commit() -> PageCommit<ItemDurable> {
        let scope = sample_scope();
        PageCommit::new(scope.clone())
            .record_findings(sample_findings_receipt())
            .record_done_ledger(sample_done_ledger_receipt(scope.committed_units().get()))
            .unwrap()
    }

    /// Construct a checkpoint receipt with a scope that differs from the given
    /// scope (different tenant), so scope equality will fail.
    fn checkpoint_with_wrong_scope(scope: &CommitScope) -> CheckpointCommitReceipt {
        let wrong_scope = CommitScope::new(
            tenant(99),
            scope.policy_hash(),
            scope.run_id(),
            scope.shard_id(),
            scope.fence_epoch(),
            scope.committed_units(),
            scope.checkpoint_boundary().clone(),
        );
        CheckpointCommitReceipt::new(wrong_scope, LogicalTime::from_raw(99))
    }

    #[test]
    fn checkpoint_boundary_tags_distinguish_equal_cursors() {
        let cursor = sample_cursor(0x42);

        assert_ne!(
            CheckpointBoundary::ordered_content(cursor.clone()),
            CheckpointBoundary::repo_frontier(cursor)
        );
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
                    sample_done_ledger_receipt(scope.committed_units().get()),
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
            sample_done_ledger_receipt(scope.committed_units().get())
        );
        assert_eq!(receipt.checkpoint(), &sample_checkpoint_receipt(&scope));
    }

    #[test]
    fn wait_findings_returns_wait_error() {
        let page = PageCommit::new(sample_scope());
        assert_eq!(
            page.wait_findings(ReadyCommitHandle::<FindingsCommitReceipt, _>::err(
                TestWaitError("findings wait failed"),
            ))
            .unwrap_err(),
            TestWaitError("findings wait failed")
        );
    }

    #[test]
    fn record_done_ledger_rejects_mismatched_item_count() {
        let scope = sample_scope();
        let page = PageCommit::new(scope.clone()).record_findings(sample_findings_receipt());

        assert_eq!(
            page.record_done_ledger(sample_done_ledger_receipt(
                scope.committed_units().get() + 1
            ))
            .unwrap_err(),
            PageCommitValidationError::LedgerUnitCountMismatch {
                expected: scope.committed_units().get(),
                actual: scope.committed_units().get() + 1,
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
                    sample_done_ledger_receipt(scope.committed_units().get() + 1),
                )
            )
            .unwrap_err(),
            CommitAdvanceError::<TestWaitError>::Validation(
                PageCommitValidationError::LedgerUnitCountMismatch {
                    expected: scope.committed_units().get(),
                    actual: scope.committed_units().get() + 1,
                },
            )
        );
    }

    #[test]
    fn record_checkpoint_rejects_scope_mismatch() {
        let page = sample_item_commit();
        let scope = page.scope().clone();

        assert!(matches!(
            page.record_checkpoint(checkpoint_with_wrong_scope(&scope))
                .unwrap_err(),
            PageCommitValidationError::CheckpointScopeMismatch { .. }
        ));
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

        assert!(matches!(
            page.wait_checkpoint(
                ReadyCommitHandle::<CheckpointCommitReceipt, TestWaitError>::ok(
                    checkpoint_with_wrong_scope(&scope),
                )
            )
            .unwrap_err(),
            CommitAdvanceError::<TestWaitError>::Validation(
                PageCommitValidationError::CheckpointScopeMismatch { .. },
            )
        ));
    }

    #[test]
    fn done_ledger_validates_count_not_scope_by_design() {
        // Two pages with different scopes but the same committed_units count.
        let scope_a = sample_scope(); // committed_units = 2
        let scope_b = CommitScope::new(
            tenant(9),                          // different tenant
            PolicyHash::from_bytes([0xBB; 32]), // different policy
            RunId::from_raw(99),                // different run
            ShardId::from_raw(88),              // different shard
            FenceEpoch::from_raw(77),           // different epoch
            NonZeroU64::new(2).unwrap(),        // same committed_units
            CheckpointBoundary::repo_frontier(sample_cursor(6)),
        );
        assert_eq!(scope_a.committed_units(), scope_b.committed_units());
        assert_ne!(scope_a.tenant_id(), scope_b.tenant_id());

        // Page A accepts a done-ledger receipt matching page B's count.
        // This is the documented behavior (module docs lines 40-45):
        // done-ledger receipts carry only aggregate counts because they
        // are produced by the same in-process pipeline.
        let page_a = PageCommit::new(scope_a)
            .record_findings(sample_findings_receipt())
            .record_done_ledger(sample_done_ledger_receipt(scope_b.committed_units().get()))
            .expect("done-ledger stage validates count, not scope — by design");

        // The checkpoint stage is where full scope validation occurs.
        // A checkpoint receipt scoped to page B is rejected.
        let wrong_checkpoint = sample_checkpoint_receipt(&scope_b);
        assert!(matches!(
            page_a.record_checkpoint(wrong_checkpoint).unwrap_err(),
            PageCommitValidationError::CheckpointScopeMismatch { .. }
        ));
    }

    #[test]
    fn page_commit_happy_path_with_repo_frontier_boundary() {
        let scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(2).unwrap(),
            CheckpointBoundary::repo_frontier(sample_cursor(5)),
        );
        let page = PageCommit::new(scope.clone())
            .record_findings(sample_findings_receipt())
            .record_done_ledger(sample_done_ledger_receipt(scope.committed_units().get()))
            .unwrap()
            .record_checkpoint(sample_checkpoint_receipt(&scope))
            .unwrap();
        let receipt = page.into_page_commit_receipt();
        assert_eq!(receipt.item_commit().scope(), &scope);
        assert!(scope.checkpoint_boundary().is_repo_frontier());
    }

    #[test]
    fn record_checkpoint_rejects_boundary_family_mismatch() {
        let cursor = sample_cursor(5);
        let scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(2).unwrap(),
            CheckpointBoundary::ordered_content(cursor.clone()),
        );
        let page = PageCommit::new(scope)
            .record_findings(sample_findings_receipt())
            .record_done_ledger(sample_done_ledger_receipt(2))
            .unwrap();

        // Same cursor, same scalars, but RepoFrontier instead of OrderedContent.
        let wrong_scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(2).unwrap(),
            CheckpointBoundary::repo_frontier(cursor),
        );
        let wrong_receipt = CheckpointCommitReceipt::new(wrong_scope, LogicalTime::from_raw(99));
        assert!(matches!(
            page.record_checkpoint(wrong_receipt).unwrap_err(),
            PageCommitValidationError::CheckpointScopeMismatch { .. }
        ));
    }

    #[test]
    fn checkpoint_boundary_ordered_content_accessors() {
        let cursor = sample_cursor(0xAA);
        let boundary = CheckpointBoundary::ordered_content(cursor.clone());
        assert_eq!(boundary.kind(), CheckpointBoundaryKind::OrderedContent);
        assert!(boundary.is_ordered_content());
        assert!(!boundary.is_repo_frontier());
        assert_eq!(boundary.cursor(), &cursor);
        assert_eq!(boundary.as_ordered_content(), Some(&cursor));
        assert_eq!(boundary.as_repo_frontier(), None);
    }

    #[test]
    fn checkpoint_boundary_repo_frontier_accessors() {
        let cursor = sample_cursor(0xBB);
        let boundary = CheckpointBoundary::repo_frontier(cursor.clone());
        assert_eq!(boundary.kind(), CheckpointBoundaryKind::RepoFrontier);
        assert!(!boundary.is_ordered_content());
        assert!(boundary.is_repo_frontier());
        assert_eq!(boundary.cursor(), &cursor);
        assert_eq!(boundary.as_ordered_content(), None);
        assert_eq!(boundary.as_repo_frontier(), Some(&cursor));
    }

    /// When two commit scopes differ only in policy_hash, the Display output
    /// must show distinct values so operators can diagnose the root cause.
    #[test]
    fn scope_mismatch_display_distinguishes_policy_hash_only_difference() {
        let expected_scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(10).unwrap(),
            CheckpointBoundary::ordered_content(sample_cursor(5)),
        );
        let actual_scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xBB; 32]), // only field that differs
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(10).unwrap(),
            CheckpointBoundary::ordered_content(sample_cursor(5)),
        );

        // Scopes must differ (policy_hash is different).
        assert_ne!(expected_scope, actual_scope);

        let err = PageCommitValidationError::CheckpointScopeMismatch {
            expected: Box::new(expected_scope),
            actual: Box::new(actual_scope),
        };

        let msg = err.to_string();

        // The formatted message must contain both distinct policy hashes so
        // operators can see which field actually differs.
        let halves: Vec<&str> = msg.splitn(2, ';').collect();
        assert_eq!(halves.len(), 2, "Display must have expected;actual halves");

        // Extract policy= values from each half.
        let expected_policy = halves[0]
            .split("policy=")
            .nth(1)
            .expect("expected half must contain policy=");
        let actual_policy = halves[1]
            .split("policy=")
            .nth(1)
            .expect("actual half must contain policy=");

        assert_ne!(
            expected_policy, actual_policy,
            "policy-hash-only mismatch must produce distinct values in \
             the formatted output:\n  {msg}"
        );
    }

    #[test]
    fn commit_scope_from_write_context_preserves_shared_fields() {
        use super::WriteContext;

        let wc = WriteContext::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
        );
        let committed_units = NonZeroU64::new(5).unwrap();
        let boundary = CheckpointBoundary::ordered_content(sample_cursor(6));

        let scope = CommitScope::from_write_context(wc, committed_units, boundary.clone());

        assert_eq!(scope.tenant_id(), wc.tenant_id());
        assert_eq!(scope.policy_hash(), wc.policy_hash());
        assert_eq!(scope.run_id(), wc.run_id());
        assert_eq!(scope.shard_id(), wc.shard_id());
        assert_eq!(scope.fence_epoch(), wc.fence_epoch());
        assert_eq!(scope.committed_units(), committed_units);
        assert_eq!(scope.checkpoint_boundary(), &boundary);
    }

    /// Cursor-only mismatches must be visible in the formatted error message.
    ///
    /// When two commit scopes differ only in their checkpoint cursor (same
    /// boundary kind, same scalars), the Display output must show distinct
    /// values for expected vs actual so operators can diagnose the root cause.
    #[test]
    fn scope_mismatch_display_distinguishes_cursor_only_difference() {
        let expected_scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(10).unwrap(),
            CheckpointBoundary::ordered_content(sample_cursor(0xAA)),
        );
        let actual_scope = CommitScope::new(
            tenant(1),
            PolicyHash::from_bytes([0xAA; 32]),
            RunId::from_raw(2),
            ShardId::from_raw(3),
            FenceEpoch::from_raw(4),
            NonZeroU64::new(10).unwrap(),
            CheckpointBoundary::ordered_content(sample_cursor(0xBB)),
        );

        // Scopes must differ (cursor is different).
        assert_ne!(expected_scope, actual_scope);

        let err = PageCommitValidationError::CheckpointScopeMismatch {
            expected: Box::new(expected_scope),
            actual: Box::new(actual_scope),
        };

        let msg = err.to_string();

        // Split at the semicolon to isolate expected vs actual field values.
        let halves: Vec<&str> = msg.splitn(2, ';').collect();
        assert_eq!(halves.len(), 2, "Display must have expected;actual halves");

        // Extract the boundary= value from each half — this is the only field
        // that differs between the two scopes.
        let expected_boundary = halves[0]
            .rsplit_once("boundary=")
            .map(|(_, v)| v)
            .expect("expected half must contain boundary=");
        let actual_boundary = halves[1]
            .rsplit_once("boundary=")
            .map(|(_, v)| v)
            .expect("actual half must contain boundary=");

        assert_ne!(
            expected_boundary, actual_boundary,
            "cursor-only mismatch must produce distinct boundary values in \
             the formatted output:\n  {msg}"
        );
    }
}
