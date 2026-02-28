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
//! ## Per-page control flow
//!
//! ```text
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
//!        ┌──────────┐       ┌────────────────────────────────┐
//!        │  empty?  │──yes──►  complete(final_cursor) ──► Done
//!        └────┬─────┘       └────────────────────────────────┘
//!             │ no
//!             ▼
//!     ┌──────────────────┐
//!     │  checkpoint(cur) │── Err ──► Error(Checkpoint)
//!     └────────┬─────────┘
//!              │ Ok
//!              ▼
//!         advance cursor, loop
//! ```
//!
//! ## Scan-loop invariants
//!
//! These invariants are enforced by the loop implementation and verified by
//! the test suite. The labels (SL1–SL6) are stable identifiers used for
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
//!   returns exactly one of `Completed`, `Parked`, or `Error`. No silent
//!   drops, no unobservable exits.
//! - **SL6 — Empty-page terminal safety:** Empty pages are treated as terminal
//!   (triggering `complete`). This is safe because SL1 guarantees
//!   `validate_page` runs first, and validation rejects
//!   `EmptyPageCursorAdvanced` — so any empty page that reaches the
//!   terminal check has an unchanged `last_key` and cannot skip items.
//!
//! ## Design trade-offs
//!
//! - The loop is synchronous and deterministic (no sleeps, backoff, or jitter).
//!   Logical time is injected via `now_fn` so callers control time progression,
//!   enabling fully reproducible simulation tests.
//! - Permanent error classification is message-heuristic based because the
//!   connector contract only surfaces a binary retryability class plus free-form
//!   error text. The heuristic is conservative: unrecognized messages fall through
//!   to [`ParkReason::Other`] rather than guessing a more specific category.
//! - The loop does not process page items for detection. It only advances
//!   coordination cursor state. Detection fan-out is composed externally.

use std::fmt;

use gossip_contracts::connector::{
    Budgets, ConnectorInputError, Cursor, EnumerateError, EnumerationConnector,
    PageValidationError, validate_page,
};
use gossip_contracts::coordination::{ShardSpec, ShardSpecInputError};
use gossip_contracts::identity::{LogicalTime, OpId};
use gossip_coordination::{
    CheckpointError, CompleteError, CoordinationBackend, ParkError, ParkReason, WorkerSession,
};

/// Default number of consecutive retryable errors tolerated before parking.
///
/// A value of 3 means up to 3 consecutive retryable failures are tolerated
/// before the shard is parked with [`ParkReason::TooManyErrors`].
pub const DEFAULT_MAX_TRANSIENT_RETRIES: usize = 3;

/// Terminal outcome from [`run_scan_loop`].
///
/// Every call returns exactly one of these three variants. `Completed` and
/// `Parked` indicate that the coordination backend accepted a terminal state
/// transition (the session is consumed). `Error` means the loop exited before
/// reaching a successful terminal transition -- the shard may still be
/// `Active` from the coordinator's perspective, and its lease will eventually
/// expire.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use = "ignoring a ScanLoopOutcome silently discards Error and Parked states"]
pub enum ScanLoopOutcome {
    /// The connector returned a terminal empty page and the coordination
    /// backend accepted the `complete` transition. The shard is now `Done`.
    Completed,
    /// The shard was parked due to a connector or validation failure.
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

/// Run the connector enumeration loop for one acquired shard session.
///
/// ## Lifecycle
///
/// The function takes ownership of `session` and always returns a
/// [`ScanLoopOutcome`]. On `Completed` or `Parked` the session has been
/// consumed by a terminal coordination transition. On `Error` the session
/// was consumed by a failed terminal call, or was dropped without reaching
/// a terminal state (the lease will expire naturally).
///
/// ## Pre-loop bridging
///
/// Before entering the page loop, the session's borrowed spec and cursor
/// bytes are converted into owned connector-domain types ([`ShardSpec`],
/// [`Cursor`]). If either conversion fails the shard is parked `Poisoned`
/// immediately -- these failures indicate corrupted coordinator state that
/// no amount of retrying can fix.
///
/// ## Error-to-action mapping
///
/// | Failure class | Action |
/// |---|---|
/// | Page validation error | Park `Poisoned` |
/// | Retryable enumerate error (streak < limit) | Retry immediately |
/// | Retryable enumerate error (streak >= limit) | Park `TooManyErrors` |
/// | Permanent enumerate error | Park via message heuristic |
/// | Coordination checkpoint/complete failure | Return `Error` directly |
/// | Park call failure | Return compound `Error::Park` |
///
/// ## Parameters
///
/// - `session` -- acquired [`WorkerSession`] for the shard to scan. Consumed.
/// - `connector` -- the [`EnumerationConnector`] that produces pages.
/// - `budgets` -- per-page item/byte budgets forwarded to the connector.
/// - `max_transient_retries` -- maximum consecutive retryable enumeration
///   failures before parking with [`ParkReason::TooManyErrors`].
/// - `op_id_fn` -- called once per checkpoint/complete/park to obtain a
///   unique operation ID for idempotent coordination calls.
/// - `now_fn` -- called before each coordination mutation to obtain the
///   current logical timestamp. Must be monotonic within a session.
pub fn run_scan_loop<B, C, N>(
    mut session: WorkerSession<'_, B>,
    connector: &mut C,
    budgets: Budgets,
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

    let mut transient_failures = 0usize;

    loop {
        let page = match connector.enumerate_page(&spec, &connector_cursor, budgets) {
            Ok(page) => {
                // Retry budget applies to consecutive errors only.
                transient_failures = 0;
                page
            }
            Err(error) => {
                if error.class().is_retryable() {
                    if transient_failures < max_transient_retries {
                        transient_failures += 1;
                        continue;
                    }

                    let hint = error.retry_after_ms();
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
            return park_and_return(
                session,
                now_fn(),
                op_id_fn(),
                ParkReason::Poisoned,
                ScanLoopError::PageValidation(error),
                None,
            );
        }

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
        if is_terminal {
            let final_cursor = next_cursor.as_update();
            return match session.complete(now_fn(), &final_cursor, op_id_fn()) {
                Ok(_) => ScanLoopOutcome::Completed,
                Err(error) => ScanLoopOutcome::Error(ScanLoopError::Complete(error)),
            };
        }

        let checkpoint_cursor = next_cursor.as_update();
        match session.checkpoint(now_fn(), &checkpoint_cursor, op_id_fn()) {
            Ok(_) => {
                // Only cursor state is advanced here. Detection-engine
                // processing of page items is composed externally by the
                // caller, not handled inside the scan loop.
                connector_cursor = next_cursor;
            }
            Err(error) => return ScanLoopOutcome::Error(ScanLoopError::Checkpoint(error)),
        }
    }
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
mod tests {
    use super::*;
    use gossip_connectors::{InMemoryDeterministicConnector, MemItem};
    use gossip_contracts::connector::{
        ConnectorCapabilities, EnumerationPage, ItemKey, ItemRef, ScanItem, VersionId,
    };
    use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, InitialShardInput};
    use gossip_contracts::identity::{
        ConnectorTag, ObjectVersionId, RunId, ShardId, StableItemId, TenantId, WorkerId,
    };
    use gossip_coordination::{
        InMemoryCoordinator, RunConfig, RunManagement, ShardFilter, ShardKey, ShardStatus,
        ShardSummary,
    };
    use rstest::rstest;

    const TAG: ConnectorTag = ConnectorTag::from_ascii(b"scanloop");

    fn counter_op_ids(start: u64) -> impl FnMut() -> OpId {
        let mut next = start;
        move || {
            let raw = next;
            next += 1;
            OpId::from_raw(raw)
        }
    }

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x21; 32])
    }

    fn run_id() -> RunId {
        RunId::from_raw(7)
    }

    fn shard_id() -> ShardId {
        ShardId::from_raw(3)
    }

    fn shard_key() -> ShardKey {
        ShardKey::new(run_id(), shard_id())
    }

    fn worker(id: u64) -> WorkerId {
        WorkerId::from_raw(id)
    }

    fn now(tick: u64) -> LogicalTime {
        LogicalTime::from_raw(tick)
    }

    fn make_key(bytes: &[u8]) -> ItemKey {
        ItemKey::try_from_slice(bytes).expect("test key")
    }

    fn make_mem_item(key: &[u8], bytes: &[u8]) -> MemItem {
        MemItem::new(make_key(key), bytes.to_vec())
    }

    fn make_scan_item(key: &[u8]) -> ScanItem {
        let item_key = make_key(key);
        let item_ref = ItemRef::try_from_slice(key).expect("item ref");
        let mut stable = [0u8; 32];
        let copy_len = key.len().min(stable.len());
        stable[..copy_len].copy_from_slice(&key[..copy_len]);
        ScanItem::new(
            item_key,
            item_ref,
            StableItemId::from_bytes(stable),
            VersionId::Strong(ObjectVersionId::from_version_bytes(key)),
        )
    }

    fn budgets(max_items: usize) -> Budgets {
        Budgets::try_new(max_items, u64::MAX, None).expect("budgets")
    }

    fn seeded_coordinator(
        lease_duration: u64,
        initial_cursor: CursorUpdate<'_>,
    ) -> InMemoryCoordinator {
        let mut coord = InMemoryCoordinator::new(lease_duration);
        let config = RunConfig::try_new(CursorSemantics::Completed, lease_duration, Some(5))
            .expect("config");
        coord
            .create_run(now(1), tenant(), run_id(), config)
            .expect("create run");

        let spec = ShardSpec::with_range(b"a", b"z");
        let shards = [InitialShardInput::new(
            shard_id(),
            spec.as_ref(),
            initial_cursor,
        )];
        let _ = coord
            .register_shards(now(2), tenant(), run_id(), &shards, OpId::from_raw(1))
            .expect("register shard");
        coord
    }

    fn acquire_session<'a>(
        coord: &'a mut InMemoryCoordinator,
        at: u64,
        worker_id: u64,
    ) -> WorkerSession<'a, InMemoryCoordinator> {
        WorkerSession::new(coord, now(at), tenant(), shard_key(), worker(worker_id))
            .expect("acquire session")
    }

    fn shard_summary(coord: &InMemoryCoordinator, at: u64) -> ShardSummary {
        let mut out = Vec::new();
        coord
            .list_shards_into(now(at), tenant(), run_id(), ShardFilter::all(), &mut out)
            .expect("list shards");
        assert_eq!(out.len(), 1, "expected exactly one shard");
        out.remove(0)
    }

    #[derive(Clone)]
    struct ScriptedConnector {
        responses: Vec<Result<EnumerationPage, EnumerateError>>,
        calls: usize,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<Result<EnumerationPage, EnumerateError>>) -> Self {
            Self {
                responses,
                calls: 0,
            }
        }
    }

    impl EnumerationConnector for ScriptedConnector {
        fn caps(&self) -> ConnectorCapabilities {
            ConnectorCapabilities {
                seek_by_key: true,
                token_resume: false,
                range_read: false,
                split_hints: false,
            }
        }

        fn enumerate_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<EnumerationPage, EnumerateError> {
            let response = self.responses.get(self.calls).cloned().unwrap_or_else(|| {
                panic!(
                    "ScriptedConnector: unexpected call #{} ({} responses scripted)",
                    self.calls + 1,
                    self.responses.len(),
                )
            });
            self.calls += 1;
            response
        }
    }

    #[test]
    fn happy_path_completes_and_records_final_cursor() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let mut connector = InMemoryDeterministicConnector::new(
            TAG,
            vec![
                make_mem_item(b"a", b"one"),
                make_mem_item(b"b", b"two"),
                make_mem_item(b"c", b"three"),
            ],
        );

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(100);
        let mut tick = 4u64;
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(2),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || {
                let out = now(tick);
                tick += 1;
                out
            },
        );

        assert_eq!(outcome, ScanLoopOutcome::Completed);
        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Done);
        assert_eq!(summary.last_key(), Some(&b"c"[..]));
    }

    #[test]
    fn page_validation_failure_parks_poisoned() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let bad_page = EnumerationPage::new(
            vec![make_scan_item(b"b"), make_scan_item(b"a")],
            Cursor::with_last_key(make_key(b"a")),
        );
        let mut connector = ScriptedConnector::new(vec![Ok(bad_page)]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(200);
        let mut tick = 4u64;
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || {
                let out = now(tick);
                tick += 1;
                out
            },
        );

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::Poisoned,
                retry_after_ms: None,
            }
        );
        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Parked);
        assert_eq!(summary.park_reason(), Some(ParkReason::Poisoned));
    }

    #[test]
    fn permanent_auth_error_parks_permission_denied() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let mut connector =
            ScriptedConnector::new(vec![Err(EnumerateError::permanent("auth denied"))]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(300);
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(4),
        );

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::PermissionDenied,
                retry_after_ms: None,
            }
        );
        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Parked);
        assert_eq!(summary.park_reason(), Some(ParkReason::PermissionDenied));
    }

    #[test]
    fn retryable_error_exhaustion_parks_too_many_errors() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let mut connector = ScriptedConnector::new(vec![
            Err(EnumerateError::retryable("timeout 1")),
            Err(EnumerateError::retryable("timeout 2")),
        ]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(400);
        let outcome = run_scan_loop(session, &mut connector, budgets(10), 1, &mut op_ids, || {
            now(4)
        });

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::TooManyErrors,
                retry_after_ms: None,
            }
        );
        assert_eq!(connector.calls, 2, "expected one retry then park");
        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Parked);
        assert_eq!(summary.park_reason(), Some(ParkReason::TooManyErrors));
    }

    #[test]
    fn resume_from_checkpoint_after_failure_completes_remaining_work() {
        let mut coord = seeded_coordinator(8, CursorUpdate::initial());
        let mut first_connector = InMemoryDeterministicConnector::new(
            TAG,
            vec![
                make_mem_item(b"a", b"one"),
                make_mem_item(b"b", b"two"),
                make_mem_item(b"c", b"three"),
            ],
        );
        let session = acquire_session(&mut coord, 3, 1);

        let mut op_ids = counter_op_ids(500);
        let mut times = vec![4u64, 5u64, 12u64].into_iter();
        let first_outcome = run_scan_loop(
            session,
            &mut first_connector,
            budgets(1),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(times.next().expect("time script exhausted")),
        );

        match first_outcome {
            ScanLoopOutcome::Error(ScanLoopError::Checkpoint(CheckpointError::LeaseExpired {
                ..
            })) => {}
            other => panic!("expected checkpoint lease-expired error, got {other:?}"),
        }

        let mid = shard_summary(&coord, 13);
        assert_eq!(mid.status(), ShardStatus::Active);
        assert_eq!(mid.last_key(), Some(&b"b"[..]));

        let mut second_connector = InMemoryDeterministicConnector::new(
            TAG,
            vec![
                make_mem_item(b"a", b"one"),
                make_mem_item(b"b", b"two"),
                make_mem_item(b"c", b"three"),
            ],
        );
        let second_session = acquire_session(&mut coord, 30, 2);
        let mut second_op_ids = counter_op_ids(600);
        let mut tick = 31u64;
        let second_outcome = run_scan_loop(
            second_session,
            &mut second_connector,
            budgets(1),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut second_op_ids,
            || {
                let out = now(tick);
                tick += 1;
                out
            },
        );

        assert_eq!(second_outcome, ScanLoopOutcome::Completed);
        let final_summary = shard_summary(&coord, 80);
        assert_eq!(final_summary.status(), ShardStatus::Done);
        assert_eq!(final_summary.last_key(), Some(&b"c"[..]));
    }

    // -- rstest parameterized classifier tests -----------------------------------

    #[rstest]
    #[case("auth denied", ParkReason::PermissionDenied)]
    #[case("permission error", ParkReason::PermissionDenied)]
    #[case("403 forbidden", ParkReason::PermissionDenied)]
    #[case("request unauthorized", ParkReason::PermissionDenied)]
    #[case("resource not found", ParkReason::NotFound)]
    #[case("HTTP 404 response", ParkReason::NotFound)]
    #[case("bucket missing", ParkReason::NotFound)]
    #[case("contract violation", ParkReason::Poisoned)]
    #[case("invariant broken", ParkReason::Poisoned)]
    #[case("data validation failed", ParkReason::Poisoned)]
    #[case("something went wrong", ParkReason::Other)]
    #[case("", ParkReason::Other)]
    // Case insensitivity.
    #[case("AUTH DENIED", ParkReason::PermissionDenied)]
    #[case("NOT FOUND", ParkReason::NotFound)]
    #[case("Contract Violation", ParkReason::Poisoned)]
    // Priority: auth keywords win over not-found keywords.
    #[case("auth not found", ParkReason::PermissionDenied)]
    #[case("missing auth token", ParkReason::PermissionDenied)]
    fn classify_permanent_error_maps_keywords_to_park_reason(
        #[case] message: &str,
        #[case] expected: ParkReason,
    ) {
        let error = EnumerateError::permanent(message);
        let reason = classify_permanent_enumerate_error(&error);
        assert_eq!(reason, expected, "message: {message:?}");
    }

    // -- unit tests for loop logic gaps ------------------------------------------

    /// A1: Retry streak resets after a successful page.
    ///
    /// Script: `[Err(retryable), Ok(page "b"), Err(retryable), Err(retryable)]`
    /// with `max_transient_retries: 1`. If the streak reset regresses, the loop
    /// would park after 3 calls (accumulated streak) instead of 4.
    #[test]
    fn retry_streak_resets_after_successful_page() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());

        let page_b = EnumerationPage::new(
            vec![make_scan_item(b"b")],
            Cursor::with_last_key(make_key(b"b")),
        );
        let mut connector = ScriptedConnector::new(vec![
            Err(EnumerateError::retryable("timeout 1")),
            Ok(page_b),
            Err(EnumerateError::retryable("timeout 2")),
            Err(EnumerateError::retryable("timeout 3")),
        ]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(500);
        let mut tick = 4u64;
        let outcome = run_scan_loop(session, &mut connector, budgets(10), 1, &mut op_ids, || {
            let out = now(tick);
            tick += 1;
            out
        });

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::TooManyErrors,
                retry_after_ms: None,
            }
        );
        // All 4 scripted responses consumed: retry, success, retry, park.
        assert_eq!(connector.calls, 4, "streak must reset after success");

        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Parked);
        // Checkpoint at "b" was recorded before the second retry streak.
        assert_eq!(summary.last_key(), Some(&b"b"[..]));
    }

    /// A2: Empty first page completes immediately without any checkpoint.
    ///
    /// When resumed from a prior cursor position, the connector may return an
    /// empty page echoing the same cursor. The loop validates (cursor did not
    /// advance — allowed for empty pages), then completes with that cursor.
    #[test]
    fn empty_first_page_completes_immediately() {
        let mut coord = seeded_coordinator(40, CursorUpdate::with_last_key(b"a"));

        let empty_page = EnumerationPage::new(Vec::new(), Cursor::with_last_key(make_key(b"a")));
        let mut connector = ScriptedConnector::new(vec![Ok(empty_page)]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(600);
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(4),
        );

        assert_eq!(outcome, ScanLoopOutcome::Completed);
        assert_eq!(connector.calls, 1, "single page fetch expected");

        let summary = shard_summary(&coord, 60);
        assert_eq!(summary.status(), ShardStatus::Done);
    }

    /// A3: `max_transient_retries = 0` parks on the first retryable error.
    #[test]
    fn zero_retries_parks_on_first_retryable_error() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let mut connector = ScriptedConnector::new(vec![Err(EnumerateError::retryable("timeout"))]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(700);
        let outcome = run_scan_loop(session, &mut connector, budgets(10), 0, &mut op_ids, || {
            now(4)
        });

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::TooManyErrors,
                retry_after_ms: None,
            }
        );
        assert_eq!(connector.calls, 1, "no retries with limit 0");
    }

    /// A5: `rate_limited` error surfaces `retry_after_ms` hint in `Parked` outcome.
    ///
    /// Script: two consecutive `rate_limited(5000)` errors with `max_transient_retries: 1`.
    /// The scan loop parks with `TooManyErrors` and the outcome carries the
    /// backoff hint from the final error so callers can pace re-acquisition.
    #[test]
    fn rate_limited_error_surfaces_retry_after_hint() {
        let mut coord = seeded_coordinator(40, CursorUpdate::initial());
        let mut connector = ScriptedConnector::new(vec![
            Err(EnumerateError::rate_limited("429 too many requests", 5000)),
            Err(EnumerateError::rate_limited("429 too many requests", 5000)),
        ]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(750);
        let outcome = run_scan_loop(session, &mut connector, budgets(10), 1, &mut op_ids, || {
            now(4)
        });

        assert_eq!(
            outcome,
            ScanLoopOutcome::Parked {
                reason: ParkReason::TooManyErrors,
                retry_after_ms: Some(5000),
            }
        );
        assert_eq!(connector.calls, 2);
    }

    /// B1: Park failure preserves the trigger context in a compound error.
    ///
    /// Connector returns a permanent auth error, but by the time the loop
    /// calls `session.park()` the lease has expired, so the park call fails.
    #[test]
    fn park_failure_preserves_trigger_context() {
        // Lease duration = 8, acquired at t=3, so deadline = 11.
        let mut coord = seeded_coordinator(8, CursorUpdate::initial());
        let mut connector =
            ScriptedConnector::new(vec![Err(EnumerateError::permanent("auth denied"))]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(800);

        // now_fn returns t=20 which is past the lease deadline of 11.
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(20),
        );

        match outcome {
            ScanLoopOutcome::Error(ScanLoopError::Park {
                reason,
                source,
                trigger,
            }) => {
                assert_eq!(reason, ParkReason::PermissionDenied);
                assert!(
                    matches!(source, ParkError::LeaseExpired { .. }),
                    "expected LeaseExpired, got {source:?}"
                );
                assert!(
                    matches!(*trigger, ScanLoopError::Enumerate(_)),
                    "expected Enumerate trigger, got {trigger:?}"
                );
            }
            other => panic!("expected Error(Park {{ .. }}), got {other:?}"),
        }
    }

    /// A4: `session.complete()` failure returns `Error(Complete(..))`.
    ///
    /// Two pages: first page checkpoints successfully (time within lease),
    /// second page is empty (terminal) but complete fails due to lease expiry.
    #[test]
    fn complete_failure_returns_error() {
        // Lease duration = 8, acquired at t=3, so deadline = 11.
        let mut coord = seeded_coordinator(8, CursorUpdate::initial());

        let page_b = EnumerationPage::new(
            vec![make_scan_item(b"b")],
            Cursor::with_last_key(make_key(b"b")),
        );
        let empty_terminal =
            EnumerationPage::new(Vec::new(), Cursor::with_last_key(make_key(b"b")));
        let mut connector = ScriptedConnector::new(vec![Ok(page_b), Ok(empty_terminal)]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(900);

        // First now_fn call (checkpoint) at t=4 (within lease).
        // Second now_fn call (complete) at t=20 (past lease deadline of 11).
        let mut times = [4u64, 20].into_iter();
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(times.next().expect("time script exhausted")),
        );

        match outcome {
            ScanLoopOutcome::Error(ScanLoopError::Complete(CompleteError::LeaseExpired {
                ..
            })) => {} // expected
            other => panic!("expected Error(Complete(LeaseExpired)), got {other:?}"),
        }

        // Checkpoint at "b" was durable before the complete failure.
        let summary = shard_summary(&coord, 21);
        assert_eq!(summary.status(), ShardStatus::Active);
        assert_eq!(summary.last_key(), Some(&b"b"[..]));
    }

    /// Checkpoint failure (lease expiry) returns `Error(Checkpoint(..))`.
    ///
    /// A single non-empty page is fetched successfully, but by the time the
    /// loop calls `session.checkpoint()` the lease has expired. The shard
    /// remains `Active` because no terminal transition succeeded.
    #[test]
    fn checkpoint_failure_returns_error() {
        // Lease duration = 8, acquired at t=3, so deadline = 11.
        let mut coord = seeded_coordinator(8, CursorUpdate::initial());

        let page_b = EnumerationPage::new(
            vec![make_scan_item(b"b")],
            Cursor::with_last_key(make_key(b"b")),
        );
        let mut connector = ScriptedConnector::new(vec![Ok(page_b)]);

        let session = acquire_session(&mut coord, 3, 1);
        let mut op_ids = counter_op_ids(950);

        // now_fn returns t=20 which is past the lease deadline of 11.
        // The first (and only) now_fn call is for the checkpoint.
        let outcome = run_scan_loop(
            session,
            &mut connector,
            budgets(10),
            DEFAULT_MAX_TRANSIENT_RETRIES,
            &mut op_ids,
            || now(20),
        );

        match outcome {
            ScanLoopOutcome::Error(ScanLoopError::Checkpoint(CheckpointError::LeaseExpired {
                ..
            })) => {} // expected
            other => panic!("expected Error(Checkpoint(LeaseExpired)), got {other:?}"),
        }

        // No checkpoint was durable — shard is still Active at initial cursor.
        let summary = shard_summary(&coord, 21);
        assert_eq!(summary.status(), ShardStatus::Active);
        assert_eq!(summary.last_key(), None);
    }

    // -- proptest classification properties --------------------------------------

    mod prop_tests {
        use super::*;
        use proptest::prelude::*;

        proptest! {
            /// The classifier is total: every permanent error maps to exactly
            /// one `ParkReason` variant, never panics, never returns an
            /// undocumented value.
            #[test]
            fn classify_is_total(message in "\\PC{0,200}") {
                let error = EnumerateError::permanent(&message);
                let reason = classify_permanent_enumerate_error(&error);
                prop_assert!(matches!(
                    reason,
                    ParkReason::PermissionDenied
                        | ParkReason::NotFound
                        | ParkReason::Poisoned
                        | ParkReason::Other
                ));
            }

            /// Classification is case insensitive: uppercased and lowercased
            /// versions of the same message always produce the same reason.
            #[test]
            fn classify_is_case_insensitive(message in "[a-zA-Z0-9 ]{0,100}") {
                let lower = EnumerateError::permanent(message.to_lowercase());
                let upper = EnumerateError::permanent(message.to_uppercase());
                prop_assert_eq!(
                    classify_permanent_enumerate_error(&lower),
                    classify_permanent_enumerate_error(&upper),
                );
            }
        }
    }
}
