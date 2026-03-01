//! Connector scan loop for advancing a single acquired shard session.
//!
//! ## Overview
//!
//! The scan loop drives one shard from its current cursor to completion (or a
//! terminal error) by repeatedly requesting pages from a connector and recording
//! progress through the coordination backend. Before entering the page loop the
//! function bridges coordination-domain types into connector-domain types (shard
//! spec materialization and cursor conversion); bridging failures are treated as
//! poisoned state.
//!
//! ## Control flow
//!
//! ```text
//!     ┌──────────────────────────────────────┐
//!     │  pre-loop: bridge spec + cursor       │
//!     │  baseline_now = now_fn()              │
//!     │  lease already expired? ──yes──► LeaseLost(0)
//!     └────────┬─────────────────────────────┘
//!              │ no
//!              ▼
//!     ┌───────────────────────────────┐
//!     │  enumerate_page(spec, cursor) │
//!     └────────┬──────────────────────┘
//!              │
//!         Ok(page)──────────── Err(retryable) ──► retry / park TooManyErrors
//!              │                Err(permanent) ──► park (heuristic reason)
//!              ▼
//!     ┌────────────────────┐
//!     │   validate_page    │── Err ──► park Poisoned
//!     └────────┬───────────┘
//!              │ Ok
//!              ▼
//!        ┌──────────┐       ┌────────────────────────────────────┐
//!        │  empty?  │──yes──►  deadline guard (now)              │
//!        └────┬─────┘       │   ├── expired ──► LeaseLost       │
//!             │ no          │   └── ok ──► complete ──► Done     │
//!                           └────────────────────────────────────┘
//!             ▼
//!     ┌────────────────────────┐
//!     │  deadline guard (now)  │── expired ──► LeaseLost
//!     └────────┬───────────────┘
//!              │ ok
//!              ▼
//!     ┌──────────────────┐
//!     │  checkpoint(cur) │── Err ──► Error(Checkpoint)
//!     └────────┬─────────┘
//!              │ Ok
//!              ▼
//!     ┌──────────────────────┐
//!     │  should_renew(now)?  │── yes ──► renew ── Err ──► LeaseLost
//!     └────────┬─────────────┘                 ── Ok ──► recalibrate
//!              │ no
//!              ▼
//!         advance cursor, loop
//! ```
//!
//! ## Scan-loop invariants
//!
//! These invariants are enforced by the loop implementation and verified by
//! the test suite. The labels (SL1–SL7) are stable identifiers used for
//! cross-referencing in tests and design documents.
//!
//! - **SL1 — Validate-before-persist:** A page is always validated before any
//!   checkpoint or complete call. Malformed connector output never becomes
//!   durable cursor state.
//! - **SL2 — Consecutive retry accounting:** The transient-failure streak
//!   counter resets to zero after every successful `enumerate_page` call, so
//!   intermittent errors do not accumulate across otherwise-healthy pages.
//! - **SL3 — Poisoned state never retried:** Invalid spec bytes, unconvertible
//!   cursors, and failed page validations are parked `Poisoned` immediately
//!   without consuming any retry budget.
//! - **SL4 — Park-failure preserves trigger:** When a park call fails, the
//!   original trigger error is preserved in [`ScanLoopError::Park::trigger`]
//!   so callers can distinguish "connector broke" from "coordinator broke
//!   while handling connector breakage."
//! - **SL5 — Terminal outcome exhaustiveness:** Every `run_scan_loop` call
//!   returns exactly one of `Completed`, `Parked`, `LeaseLost`, or `Error`.
//!   No silent drops, no unobservable exits.
//! - **SL6 — Empty-page terminal safety:** Empty pages are treated as terminal
//!   (triggering `complete`). This is safe because SL1 guarantees
//!   `validate_page` runs first, and validation rejects
//!   `EmptyPageCursorAdvanced` — so any empty page that reaches the
//!   terminal check has an unchanged `last_key` and cannot skip items.
//! - **SL7 — Renewal-after-checkpoint ordering:** Lease renewal is attempted
//!   only after a successful checkpoint. A renewal failure therefore never
//!   rolls back already-persisted progress, preserving forward-progress
//!   guarantees even when lease loss is detected.
//!
//! ## Design trade-offs
//!
//! - The loop is synchronous and deterministic (no sleeps, backoff, or jitter).
//!   Logical time is injected via `now_fn` so callers control time progression,
//!   enabling fully reproducible simulation tests.
//! - Lease renewal is checked synchronously between pages (no background task
//!   or async runtime).
//! - Retry-after-error is composed externally (callers re-acquire and re-enter
//!   the loop), while lease renewal is internal. The asymmetry is intentional:
//!   renewal requires access to the live session and lease metadata, so it must
//!   happen inside the loop. Retry orchestration (backoff, jitter, scheduling)
//!   is policy-heavy and session-independent, so it belongs in the caller.
//! - `LeaseLost` is emitted only on explicit abandon paths: deadline elapsed
//!   before `checkpoint`/`complete`, or failed `renew`. Backend rejections from
//!   attempted `checkpoint`/`complete`/`park` mutations - including lease-expired
//!   cases - are returned as `Error`. `renew` is the intentional exception:
//!   renewal failure maps to `LeaseLost` so callers can re-acquire cleanly.
//! - Permanent error classification is message-heuristic based because the
//!   connector contract only surfaces a binary retryability class plus free-form
//!   error text. The heuristic is conservative: unrecognized messages fall through
//!   to [`ParkReason::Other`] rather than guessing a more specific category.
//! - The loop does not process page items for detection. It only advances
//!   coordination cursor state. Detection fan-out is composed externally.

use std::fmt;

use gossip_contracts::connector::{
    Budgets, ConnectorInputError, Cursor, EnumerateError, EnumerationConnector,
    PageValidationError, ScanItem, validate_page,
};
use gossip_contracts::coordination::{ShardSpec, ShardSpecInputError};
use gossip_contracts::identity::{LogicalTime, OpId};
use gossip_coordination::{
    CheckpointError, CompleteError, CoordinationBackend, ParkError, ParkReason, RenewError,
    WorkerSession,
};

/// Default number of consecutive retryable errors tolerated before parking.
///
/// A value of 3 means up to 3 consecutive retryable failures are tolerated
/// before the shard is parked with [`ParkReason::TooManyErrors`].
pub const DEFAULT_MAX_TRANSIENT_RETRIES: usize = 3;

/// Default lease-renew trigger: renew near half-life using ceil-threshold logic.
///
/// The threshold uses `ceil(duration * fraction)` plus a minimum-threshold
/// guard for positive fractions.
pub const DEFAULT_RENEW_AT_FRACTION: f64 = 0.5;

/// Lease-renew scheduling policy for [`run_scan_loop_with_policy`].
///
/// The loop evaluates this policy after each successful checkpoint. If the
/// remaining lease window is at or below the configured fraction of the last
/// observed lease duration, it attempts `session.renew(now)`.
///
/// The raw fraction is accessed via [`Self::renew_at_fraction`] and the
/// clamped/fallback-safe value via [`Self::effective_fraction`].
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RenewalPolicy {
    /// Raw renew-at fraction. Use [`Self::effective_fraction`] for the
    /// clamped, non-finite-safe value used by the renewal decision.
    renew_at_fraction: f64,
}

impl RenewalPolicy {
    /// Construct a policy with an explicit renew-at fraction.
    #[must_use]
    pub const fn new(renew_at_fraction: f64) -> Self {
        Self { renew_at_fraction }
    }

    /// Return the raw fraction value as configured.
    #[must_use]
    pub fn renew_at_fraction(&self) -> f64 {
        self.renew_at_fraction
    }

    /// Return the effective fraction used for renewal decisions.
    ///
    /// Finite values are clamped to `[0.0, 1.0]`. Non-finite values (NaN,
    /// ±Infinity) fall back to [`DEFAULT_RENEW_AT_FRACTION`] so renewal
    /// behavior remains deterministic and fail-safe.
    #[must_use]
    pub fn effective_fraction(&self) -> f64 {
        if self.renew_at_fraction.is_finite() {
            self.renew_at_fraction.clamp(0.0, 1.0)
        } else {
            debug_assert!(
                false,
                "RenewalPolicy::renew_at_fraction is non-finite ({:?}), \
                 falling back to DEFAULT_RENEW_AT_FRACTION",
                self.renew_at_fraction,
            );
            DEFAULT_RENEW_AT_FRACTION
        }
    }
}

impl Default for RenewalPolicy {
    fn default() -> Self {
        Self {
            renew_at_fraction: DEFAULT_RENEW_AT_FRACTION,
        }
    }
}

/// Diagnostic cause for [`ScanLoopOutcome::LeaseLost`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LeaseLossCause {
    /// Lease renewal failed after at least one successful checkpoint.
    ///
    /// The loop stops immediately and does not attempt `park` or `complete`,
    /// so the shard remains resumable from its last persisted checkpoint.
    RenewFailed(RenewError),
    /// Lease deadline elapsed before a checkpoint/complete could be attempted.
    ///
    /// This can happen at loop entry (before any page fetch) or after
    /// enumeration when deadline guards run before `checkpoint`/`complete`.
    /// `pages_completed` still reflects only durable checkpoint progress.
    DeadlineElapsed {
        now: LogicalTime,
        deadline: LogicalTime,
    },
}

impl fmt::Display for LeaseLossCause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RenewFailed(e) => write!(f, "lease renewal failed: {e}"),
            Self::DeadlineElapsed { now, deadline } => {
                write!(f, "deadline elapsed (now={now:?}, deadline={deadline:?})")
            }
        }
    }
}

/// Terminal outcome from [`run_scan_loop`].
///
/// Every call returns exactly one of these four variants. `Completed` and
/// `Parked` indicate that the coordination backend accepted a terminal state
/// transition (the session is consumed). `LeaseLost` means the worker detected
/// lease loss and aborted without attempting a terminal operation. `Error`
/// means the loop exited before a successful terminal transition after an
/// attempted coordination mutation failed (including lease-expired rejections
/// from those attempted mutations).
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "ignoring a ScanLoopOutcome silently discards Error, Parked, and LeaseLost states"]
pub enum ScanLoopOutcome {
    /// The connector returned a terminal empty page and the coordination
    /// backend accepted the `complete` transition. The shard is now `Done`.
    Completed,
    /// The shard was parked due to a non-recoverable scan failure.
    ///
    /// This includes connector/validation failures and pre-loop poisoned-input
    /// failures (invalid shard spec or cursor bridging).
    /// The `reason` categorizes the failure for operational triage.
    ///
    /// `retry_after_ms` carries the connector-supplied backoff advisory from
    /// the final [`EnumerateError`], if one was present. The scan loop itself
    /// is synchronous and does not enforce delays; callers that schedule
    /// re-acquisition should use this hint to pace retries.
    Parked {
        reason: ParkReason,
        retry_after_ms: Option<u64>,
    },
    /// Lease was lost while scanning, so the loop aborted without issuing
    /// terminal transitions (`park`/`complete`).
    ///
    /// This variant is produced by deadline guards (both pre-checkpoint and
    /// pre-complete) and by failed `renew` calls.
    ///
    /// `pages_completed` counts successful checkpoints already persisted in
    /// this session before lease loss was detected.
    LeaseLost {
        pages_completed: u64,
        cause: LeaseLossCause,
    },
    /// The loop failed before a successful terminal transition could be
    /// recorded. This includes coordination-level failures (checkpoint,
    /// complete) as well as compound park-on-error failures where the park
    /// call itself failed.
    Error(ScanLoopError),
}

/// Failure modes that can occur during the scan loop.
///
/// Variants are ordered roughly by where they occur in the loop lifecycle:
/// pre-loop bridging (`InvalidShardSpec`, `CursorBridge`), per-page connector
/// interaction (`PageValidation`, `Enumerate`), and coordination state
/// transitions (`Checkpoint`, `Complete`, `Park`).
///
/// The `Park` variant deserves special attention: it represents a *compound*
/// failure where the loop tried to park the shard in response to some trigger
/// error, but the park call itself failed. The original trigger is preserved
/// in `Park::trigger` so diagnostic tooling can distinguish "connector broke"
/// from "coordinator broke while handling connector breakage."
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScanLoopError {
    /// Acquired shard spec bytes could not be materialized into an owned
    /// [`ShardSpec`]. Indicates corrupted coordinator state; the loop
    /// attempts to park the shard as `Poisoned`.
    InvalidShardSpec(ShardSpecInputError),
    /// Session cursor could not be converted into the connector's [`Cursor`]
    /// form. Indicates a type/size mismatch between coordination and connector
    /// cursor domains; the loop attempts to park the shard as `Poisoned`.
    CursorBridge(ConnectorInputError),
    /// Connector returned a page that failed ordering, membership, or cursor
    /// invariant checks. The loop attempts to park the shard as `Poisoned`
    /// because malformed pages must never become durable cursor state.
    PageValidation(PageValidationError),
    /// Connector enumeration call failed. Retryable errors may have been
    /// retried up to `max_transient_retries` times before reaching this point.
    /// Permanent errors are classified by message heuristic; the loop
    /// attempts to park with the corresponding [`ParkReason`].
    Enumerate(EnumerateError),
    /// Coordination checkpoint transition failed (e.g., lease expired, cursor
    /// monotonicity violation). The shard remains `Active` from the
    /// coordinator's perspective.
    Checkpoint(CheckpointError),
    /// Coordination complete transition failed. The shard remains `Active`.
    Complete(CompleteError),
    /// Park transition failed while handling another trigger error.
    ///
    /// This is the worst-case compound failure: the connector or validator
    /// produced an error that warranted parking, but the coordination backend
    /// rejected the park call. The original trigger is boxed to avoid
    /// infinite-size enum recursion.
    Park {
        /// The [`ParkReason`] the loop intended to record.
        reason: ParkReason,
        /// Error returned by the coordination backend's park call.
        source: ParkError,
        /// The original error that triggered the park attempt.
        trigger: Box<ScanLoopError>,
    },
}

impl fmt::Display for ScanLoopError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidShardSpec(e) => write!(f, "invalid shard spec: {e}"),
            Self::CursorBridge(e) => write!(f, "cursor bridge failed: {e}"),
            Self::PageValidation(e) => write!(f, "page validation failed: {e}"),
            Self::Enumerate(e) => write!(f, "enumerate error: {e}"),
            Self::Checkpoint(e) => write!(f, "checkpoint failed: {e}"),
            Self::Complete(e) => write!(f, "complete failed: {e}"),
            Self::Park {
                reason, trigger, ..
            } => write!(f, "park ({reason}) failed while handling: {trigger}"),
        }
    }
}

impl std::error::Error for ScanLoopError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidShardSpec(e) => Some(e),
            Self::CursorBridge(e) => Some(e),
            Self::PageValidation(e) => Some(e),
            Self::Enumerate(e) => Some(e),
            Self::Checkpoint(e) => Some(e),
            Self::Complete(e) => Some(e),
            Self::Park { trigger, .. } => Some(trigger.as_ref()),
        }
    }
}

/// Redacted `Cursor` formatter for tracing fields.
///
/// Uses `Display` on toxic fields (`ItemKey`, `TokenBytes`) so output is
/// hash-only and never includes raw bytes.
struct RedactedCursor<'a>(&'a Cursor);

impl fmt::Display for RedactedCursor<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let cursor = self.0;
        f.write_str("Cursor(last_key=")?;
        match cursor.last_key() {
            Some(last_key) => write!(f, "{last_key}")?,
            None => f.write_str("None")?,
        }
        f.write_str(", token=")?;
        match cursor.token() {
            Some(token) => write!(f, "Some({token})")?,
            None => f.write_str("None")?,
        }
        f.write_str(")")
    }
}

/// Compact redacted summary of first/last items in an enumerated page.
///
/// Keeps per-page tracing useful without logging the full item list.
struct RedactedPageSample<'a> {
    first: Option<&'a ScanItem>,
    last: Option<&'a ScanItem>,
}

impl<'a> RedactedPageSample<'a> {
    #[inline]
    fn from_items(items: &'a [ScanItem]) -> Self {
        Self {
            first: items.first(),
            last: items.last(),
        }
    }
}

impl fmt::Display for RedactedPageSample<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PageSample(first_key=")?;
        match self.first {
            Some(first) => write!(f, "Some({})", first.item_key())?,
            None => f.write_str("None")?,
        }
        f.write_str(", first_ref=")?;
        match self.first {
            Some(first) => write!(f, "Some({})", first.item_ref())?,
            None => f.write_str("None")?,
        }
        f.write_str(", last_key=")?;
        match self.last {
            Some(last) => write!(f, "Some({})", last.item_key())?,
            None => f.write_str("None")?,
        }
        f.write_str(", last_ref=")?;
        match self.last {
            Some(last) => write!(f, "Some({})", last.item_ref())?,
            None => f.write_str("None")?,
        }
        f.write_str(")")
    }
}

/// Run the connector enumeration loop with the default lease-renew policy.
///
/// This is a convenience wrapper around [`run_scan_loop_with_policy`] using
/// [`RenewalPolicy::default`] (renew at half-life).
#[tracing::instrument(
    skip(session, connector, budgets, op_id_fn, now_fn),
    fields(
        shard_key = %session.shard_key(),
        tenant = %session.tenant(),
        worker = %session.worker(),
    )
)]
pub fn run_scan_loop<B, C, N>(
    session: WorkerSession<'_, B>,
    connector: &mut C,
    budgets: Budgets,
    max_transient_retries: usize,
    op_id_fn: impl FnMut() -> OpId,
    now_fn: N,
) -> ScanLoopOutcome
where
    B: CoordinationBackend,
    C: EnumerationConnector,
    N: FnMut() -> LogicalTime,
{
    run_scan_loop_with_policy(
        session,
        connector,
        budgets,
        RenewalPolicy::default(),
        max_transient_retries,
        op_id_fn,
        now_fn,
    )
}

/// Run the connector enumeration loop for one acquired shard session.
///
/// ## Lifecycle
///
/// The function takes ownership of `session` and always returns a
/// [`ScanLoopOutcome`]. `Completed` and `Parked` consume the session via
/// terminal transitions. `LeaseLost` reports lease loss without terminal
/// mutation attempts. `Error` reports failed coordination mutations.
///
/// ## Time injection contract
///
/// `now_fn` must return monotonically non-decreasing [`LogicalTime`] values.
/// The loop calls `now_fn` multiple times per page iteration (deadline guard,
/// checkpoint timestamp, renewal evaluation). Non-monotonic values would
/// invalidate deadline comparisons and renewal threshold calculations.
///
/// ## Operation-ID contract
///
/// `op_id_fn` must yield fresh IDs for each coordination mutation attempted by
/// this invocation (`checkpoint`, `complete`, `park`). Reusing an `OpId` with a
/// different payload surfaces as backend idempotency conflicts.
///
/// ## Retry-budget semantics
///
/// `max_transient_retries` counts **consecutive** retryable enumerate failures.
/// The streak resets after every successful page. `0` means "park on the first
/// retryable error."
///
/// ## Lease renewal model
///
/// Renewal remains synchronous and deterministic: after each successful
/// checkpoint, the loop evaluates `renewal_policy` and may call
/// `session.renew(now)`. Any renewal failure is treated as immediate lease
/// loss, and the loop exits with `ScanLoopOutcome::LeaseLost`.
///
/// The renew threshold is derived from the most recently observed lease window
/// (`deadline - now`), then recalibrated after each successful renewal. This
/// keeps renewal timing stable even if time has already elapsed between acquire
/// and entering the loop.
///
/// ## Lease-loss boundary
///
/// `LeaseLost` is intentionally narrow: it is returned only when the loop can
/// detect lease loss before issuing a coordination mutation (`checkpoint` or
/// `complete`) or when `renew` itself fails. If `checkpoint`, `complete`, or `park` is
/// attempted and rejected by the backend (including lease-expired cases), the
/// outcome remains `Error`.
///
/// ## Error-to-action mapping
///
/// | Failure class | Action |
/// |---|---|
/// | Invalid shard spec (pre-loop) | Park `Poisoned` |
/// | Cursor bridge failure (pre-loop) | Park `Poisoned` |
/// | Already-expired lease at loop entry | Return `LeaseLost` |
/// | Page validation error | Park `Poisoned` |
/// | Retryable enumerate error (streak < limit) | Retry immediately |
/// | Retryable enumerate error (streak >= limit) | Park `TooManyErrors` |
/// | Permanent enumerate error | Park via message heuristic |
/// | Deadline elapsed before checkpoint or complete | Return `LeaseLost` |
/// | Lease renewal failure | Return `LeaseLost` |
/// | Coordination checkpoint/complete failure | Return `Error` directly |
/// | Park call failure | Return compound `Error::Park` |
///
/// Note: `LeaseLost { pages_completed: 0 }` can occur from the pre-loop entry
/// check, from the pre-checkpoint deadline guard firing on the first non-empty
/// page, or from the pre-complete deadline guard on an initial empty page.
pub fn run_scan_loop_with_policy<B, C, N>(
    mut session: WorkerSession<'_, B>,
    connector: &mut C,
    budgets: Budgets,
    renewal_policy: RenewalPolicy,
    max_transient_retries: usize,
    mut op_id_fn: impl FnMut() -> OpId,
    mut now_fn: N,
) -> ScanLoopOutcome
where
    B: CoordinationBackend,
    C: EnumerationConnector,
    N: FnMut() -> LogicalTime,
{
    // -- Pre-loop bridging: coordination domain -> connector domain ----------
    // Both conversions are fallible because the session exposes borrowed byte
    // slices whose shape is only validated structurally here. Failure means
    // the coordinator handed us bytes that don't form a valid spec or cursor,
    // which is unrecoverable -- park Poisoned.
    let spec = match ShardSpec::try_from_ref(session.spec()) {
        Ok(spec) => spec,
        Err(error) => {
            tracing::error!(error = %error, "contract violation, parking shard");
            return park_and_return(
                session,
                now_fn(),
                op_id_fn(),
                ParkReason::Poisoned,
                ScanLoopError::InvalidShardSpec(error),
                None,
            );
        }
    };

    let mut connector_cursor = match Cursor::try_from_update(session.cursor()) {
        Ok(cursor) => cursor,
        Err(error) => {
            tracing::error!(error = %error, "contract violation, parking shard");
            return park_and_return(
                session,
                now_fn(),
                op_id_fn(),
                ParkReason::Poisoned,
                ScanLoopError::CursorBridge(error),
                None,
            );
        }
    };

    // Seed the renew threshold from the lease time still remaining when the
    // loop actually starts, not from the run's configured lease duration.
    let baseline_now = now_fn();
    // Early exit: if the lease is already expired at loop entry, there is no
    // point issuing a connector call that will produce work we cannot persist.
    if baseline_now >= session.lease().deadline() {
        return lease_lost_outcome(
            0,
            LeaseLossCause::DeadlineElapsed {
                now: baseline_now,
                deadline: session.lease().deadline(),
            },
        );
    }
    // observed_lease_duration can be 0 only when deadline == baseline_now;
    // the guard above exits before renewal logic is reached in that case.
    let mut observed_lease_duration = session
        .lease()
        .deadline()
        .as_raw()
        .saturating_sub(baseline_now.as_raw());
    let mut transient_failures = 0usize;
    let mut pages_completed = 0u64;
    let mut page_num = 0u64;

    loop {
        let page = match connector.enumerate_page(&spec, &connector_cursor, budgets) {
            Ok(page) => {
                // Retry budget applies to consecutive errors only.
                transient_failures = 0;
                page_num = page_num.saturating_add(1);
                tracing::debug!(
                    page_num,
                    items_count = page.items().len(),
                    page_sample = %RedactedPageSample::from_items(page.items()),
                    next_cursor = %RedactedCursor(page.next_cursor()),
                    "page enumerated",
                );
                page
            }
            Err(error) => {
                if error.class().is_retryable() {
                    if transient_failures < max_transient_retries {
                        transient_failures += 1;
                        tracing::debug!(
                            page_num,
                            transient_failures,
                            max_transient_retries,
                            error = %error,
                            "retryable enumerate error, retrying",
                        );
                        continue;
                    }

                    let hint = error.retry_after_ms();
                    tracing::warn!(
                        page_num,
                        transient_failures,
                        retry_after_ms = ?hint,
                        error = %error,
                        "retry budget exhausted, parking shard",
                    );
                    return park_and_return(
                        session,
                        now_fn(),
                        op_id_fn(),
                        ParkReason::TooManyErrors,
                        ScanLoopError::Enumerate(error),
                        hint,
                    );
                }

                let hint = error.retry_after_ms();
                let reason = classify_permanent_enumerate_error(&error);
                if reason == ParkReason::PermissionDenied {
                    tracing::error!(
                        page_num,
                        retry_after_ms = ?hint,
                        error = %error,
                        "connector auth error, parking shard",
                    );
                } else {
                    tracing::warn!(
                        page_num,
                        reason = %reason,
                        retry_after_ms = ?hint,
                        error = %error,
                        "connector error, parking shard",
                    );
                }
                return park_and_return(
                    session,
                    now_fn(),
                    op_id_fn(),
                    reason,
                    ScanLoopError::Enumerate(error),
                    hint,
                );
            }
        };

        // Validate before checkpoint: this ordering is load-bearing. A
        // malformed page must never advance durable cursor state.
        if let Err(error) =
            validate_page(&spec, &connector_cursor, page.items(), page.next_cursor())
        {
            tracing::error!(
                page_num,
                validation_error = %error,
                page_sample = %RedactedPageSample::from_items(page.items()),
                next_cursor = %RedactedCursor(page.next_cursor()),
                "contract violation, parking shard",
            );
            return park_and_return(
                session,
                now_fn(),
                op_id_fn(),
                ParkReason::Poisoned,
                ScanLoopError::PageValidation(error),
                None,
            );
        }
        tracing::debug!(page_num, "page validated");

        // Check emptiness by reference before consuming the page for its
        // cursor, avoiding a clone of heap-allocated key and token fields.
        let is_terminal = page.items().is_empty();
        let next_cursor = page.into_next_cursor();

        // Empty page: complete the shard with the page's cursor as the terminal
        // position. This is safe because `validate_page` (run above) rejects
        // `EmptyPageCursorAdvanced` -- any empty page reaching this point has
        // an unchanged `last_key`, so completing here never skips items.
        //
        // EnumerationPage distinguishes empty+initial (scan complete) from
        // empty+non-initial (gap at cursor position), but the scan loop treats
        // both as terminal -- gap handling is composed externally if needed.
        //
        // Deadline guard before complete: if the lease expired between
        // `enumerate_page` and this point, surface `LeaseLost` rather than
        // attempting a `complete` mutation that would be rejected with
        // `LeaseExpired`. This keeps the LeaseLost contract consistent:
        // all detectable lease expiry is reported as LeaseLost, regardless
        // of whether the page was empty or non-empty.
        if is_terminal {
            let complete_now = now_fn();
            let deadline = session.lease().deadline();
            if complete_now >= deadline {
                return lease_lost_outcome(
                    pages_completed,
                    LeaseLossCause::DeadlineElapsed {
                        now: complete_now,
                        deadline,
                    },
                );
            }
            let final_cursor = next_cursor.as_update();
            return match session.complete(complete_now, &final_cursor, op_id_fn()) {
                Ok(_) => {
                    tracing::info!(
                        page_num,
                        pages_completed,
                        final_cursor = %RedactedCursor(&next_cursor),
                        "scan completed",
                    );
                    ScanLoopOutcome::Completed
                }
                Err(error) => ScanLoopOutcome::Error(ScanLoopError::Complete(error)),
            };
        }

        // Two separate `now_fn()` samples bracket the checkpoint:
        //
        //   checkpoint_now  — sampled here, before the checkpoint mutation.
        //                     Used for the deadline guard and the checkpoint
        //                     timestamp itself.
        //   renew_now       — sampled after `session.checkpoint()` returns
        //                     (see below). Used for the renewal decision so
        //                     the remaining-time calculation accounts for
        //                     work performed during the checkpoint.
        //
        // This split is intentional: a single sample would under-count
        // elapsed time when the checkpoint involves I/O (network round-trip,
        // WAL fsync, etc.), causing the renewal check to believe more lease
        // time remains than actually does.
        let checkpoint_now = now_fn();
        let deadline = session.lease().deadline();
        // Guard before checkpoint so we surface lease loss explicitly instead
        // of issuing a mutation that is already stale.
        if checkpoint_now >= deadline {
            return lease_lost_outcome(
                pages_completed,
                LeaseLossCause::DeadlineElapsed {
                    now: checkpoint_now,
                    deadline,
                },
            );
        }

        let checkpoint_cursor = next_cursor.as_update();
        match session.checkpoint(checkpoint_now, &checkpoint_cursor, op_id_fn()) {
            Ok(_) => {
                // Only cursor state is advanced here. Detection-engine
                // processing of page items is composed externally by the
                // caller, not handled inside the scan loop.
                connector_cursor = next_cursor;
                pages_completed += 1;
                tracing::debug!(
                    page_num,
                    pages_completed,
                    checkpoint_cursor = %RedactedCursor(&connector_cursor),
                    "checkpoint persisted",
                );
            }
            Err(error) => return ScanLoopOutcome::Error(ScanLoopError::Checkpoint(error)),
        }

        // Second time sample — see the "two-sample" comment above
        // `checkpoint_now` for why this is a separate call.
        let renew_now = now_fn();
        if should_renew(
            renew_now,
            session.lease().deadline(),
            observed_lease_duration,
            renewal_policy,
        ) {
            match session.renew(renew_now) {
                Ok(_) => {
                    observed_lease_duration = session
                        .lease()
                        .deadline()
                        .as_raw()
                        .saturating_sub(renew_now.as_raw());
                    debug_assert!(
                        observed_lease_duration > 0,
                        "renewed lease deadline must be strictly after renew time"
                    );
                    tracing::info!(
                        page_num,
                        pages_completed,
                        new_deadline = session.lease().deadline().as_raw(),
                        "lease renewed",
                    );
                }
                Err(error) => {
                    debug_assert!(
                        pages_completed >= 1,
                        "renewal runs only after checkpoint, so pages_completed must be >= 1"
                    );
                    // Renewal failure is treated as lease loss, not a generic
                    // mutation error: we abandon the session immediately.
                    return lease_lost_outcome(pages_completed, LeaseLossCause::RenewFailed(error));
                }
            }
        }
    }
}

/// Emit a standardized lease-loss warning and build the terminal outcome.
#[inline]
fn lease_lost_outcome(pages_completed: u64, cause: LeaseLossCause) -> ScanLoopOutcome {
    tracing::warn!(pages_completed, cause = %cause, "lease lost");
    ScanLoopOutcome::LeaseLost {
        pages_completed,
        cause,
    }
}

/// Decide whether a renewal attempt should run at this checkpoint boundary.
///
/// The trigger compares remaining lease time to a fraction of the most recently
/// observed lease duration. If `now` is already at/past the deadline, this
/// returns `true` to force an immediate renewal attempt (which will surface a
/// precise [`RenewError`] if the lease is already invalid).
///
/// **Reachability note:** The pre-checkpoint deadline guard in the scan loop
/// uses a separate, earlier `now_fn()` sample (`checkpoint_now`). This function
/// receives `renew_now`, a *later* sample taken after the checkpoint completes.
/// Time elapsed during the checkpoint can push `renew_now` past the deadline
/// even though `checkpoint_now` was still within bounds, making the
/// `now >= deadline` early-return reachable in practice.
///
/// Non-finite policy values fall back to [`DEFAULT_RENEW_AT_FRACTION`], and
/// finite values are clamped into `[0.0, 1.0]` — both via
/// [`RenewalPolicy::effective_fraction`].
fn should_renew(
    now: LogicalTime,
    deadline: LogicalTime,
    observed_lease_duration: u64,
    policy: RenewalPolicy,
) -> bool {
    if now >= deadline {
        return true;
    }

    let remaining = deadline.as_raw().saturating_sub(now.as_raw());
    let fraction = policy.effective_fraction();
    let mut renew_threshold = ((observed_lease_duration as f64) * fraction).ceil() as u64;
    if renew_threshold == 0 && fraction > 0.0 {
        renew_threshold = 1;
    }

    remaining <= renew_threshold
}

/// Attempt to park the shard and return the appropriate [`ScanLoopOutcome`].
///
/// On success, returns `Parked { reason, retry_after_ms }`. On failure, wraps
/// the park error and the original `trigger` into [`ScanLoopError::Park`] so
/// callers can distinguish "connector failed" from "coordinator failed while
/// parking a connector failure." The `trigger` is boxed inside the `Park`
/// variant to break the recursive enum size.
///
/// `retry_after_ms` is the connector-supplied backoff advisory from the error
/// that triggered the park. Pass `None` for non-enumerate triggers (e.g.,
/// validation, spec bridging) that carry no backoff hint.
fn park_and_return<B: CoordinationBackend>(
    session: WorkerSession<'_, B>,
    now: LogicalTime,
    op_id: OpId,
    reason: ParkReason,
    trigger: ScanLoopError,
    retry_after_ms: Option<u64>,
) -> ScanLoopOutcome {
    match session.park(now, reason, op_id) {
        Ok(_) => ScanLoopOutcome::Parked {
            reason,
            retry_after_ms,
        },
        Err(source) => ScanLoopOutcome::Error(ScanLoopError::Park {
            reason,
            source,
            trigger: Box::new(trigger),
        }),
    }
}

/// Map a non-retryable [`EnumerateError`] to a coarse [`ParkReason`].
///
/// The classification is keyword-based with case-insensitive matching against
/// the error message.
/// This is deliberately loose coupling: the scan loop does not depend on
/// connector-specific error enums, and connectors can influence park-reason
/// triage simply by including recognized keywords in their error text.
///
/// Evaluation order matters -- the first matching category wins:
/// 1. Permission/auth keywords -> `PermissionDenied` (note: the "auth"
///    substring is deliberately broad — matches "author", "authority", etc. —
///    as a conservative bet: false positives park as `PermissionDenied` rather
///    than the less-actionable `Other`. Connectors control the message text
///    and can avoid false matches by omitting the substring.)
/// 2. Not-found keywords -> `NotFound`
/// 3. Contract/invariant keywords -> `Poisoned`
/// 4. Everything else -> `Other`
///
/// # Panics
///
/// Panics if the error is retryable. Calling this on a retryable error
/// is a logic bug in the scan loop.
fn classify_permanent_enumerate_error(error: &EnumerateError) -> ParkReason {
    assert!(
        !error.class().is_retryable(),
        "permanent classification called for retryable error"
    );

    let msg = error.message();

    // Permission/auth keywords (401/403, EACCES).
    if contains_ascii_ci(msg, "auth")
        || contains_ascii_ci(msg, "permission")
        || contains_ascii_ci(msg, "forbidden")
        || contains_ascii_ci(msg, "unauthorized")
    {
        ParkReason::PermissionDenied
    // Not-found keywords (404, ENOENT).
    } else if contains_ascii_ci(msg, "not found")
        || contains_ascii_ci(msg, "404")
        || contains_ascii_ci(msg, "missing")
    {
        ParkReason::NotFound
    // Contract/invariant keywords — connector bug, not environmental.
    } else if contains_ascii_ci(msg, "contract")
        || contains_ascii_ci(msg, "invariant")
        || contains_ascii_ci(msg, "validation")
    {
        ParkReason::Poisoned
    } else {
        ParkReason::Other
    }
}

/// Case-insensitive ASCII substring search without heap allocation.
///
/// All keyword needles in this module are pure ASCII, so byte-level comparison
/// with [`u8::eq_ignore_ascii_case`] is sufficient and avoids the `String`
/// allocation that [`str::to_ascii_lowercase`] would require.
#[inline]
fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    if n.is_empty() {
        return true;
    }
    h.windows(n.len())
        .any(|w| w.iter().zip(n).all(|(a, b)| a.eq_ignore_ascii_case(b)))
}

#[cfg(test)]
#[path = "scan_loop_test.rs"]
mod tests;
