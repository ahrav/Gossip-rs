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
    AcquireError, AcquireResultView, AcquireScratch, IdempotentOutcome, InMemoryCoordinator, Lease,
    RenewResult, RunConfig, RunManagement, ShardFilter, ShardKey, ShardStatus, ShardSummary,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult,
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
    let config =
        RunConfig::try_new(CursorSemantics::Completed, lease_duration, Some(5)).expect("config");
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

fn acquire_session<'a, B: CoordinationBackend>(
    coord: &'a mut B,
    at: u64,
    worker_id: u64,
) -> WorkerSession<'a, B> {
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

/// Test-only backend wrapper that steals a shard lease on demand to force
/// a stale-fence renewal path through the real in-memory coordinator.
struct FenceStealingBackend {
    inner: InMemoryCoordinator,
    steal_on_or_after: LogicalTime,
    stolen: bool,
    thief_worker: WorkerId,
}

impl FenceStealingBackend {
    fn new(
        inner: InMemoryCoordinator,
        steal_on_or_after: LogicalTime,
        thief_worker: WorkerId,
    ) -> Self {
        Self {
            inner,
            steal_on_or_after,
            stolen: false,
            thief_worker,
        }
    }
}

impl CoordinationBackend for FenceStealingBackend {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        self.inner
            .acquire_and_restore_into(now, tenant, key, worker, out)
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        if !self.stolen && now >= self.steal_on_or_after {
            let mut scratch = AcquireScratch::default();
            let _ = self
                .inner
                .acquire_and_restore_into(
                    now,
                    tenant,
                    lease.shard_key(),
                    self.thief_worker,
                    &mut scratch,
                )
                .expect("test setup: thief must acquire before stale-fence renew");
            self.stolen = true;
        }
        self.inner.renew(now, tenant, lease)
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.inner.checkpoint(now, tenant, lease, new_cursor, op_id)
    }

    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.inner.complete(now, tenant, lease, final_cursor, op_id)
    }

    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.inner.park_shard(now, tenant, lease, reason, op_id)
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.inner.split_replace(now, tenant, lease, plan, op_id)
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        self.inner.split_residual(now, tenant, lease, plan, op_id)
    }
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
    let mut connector = ScriptedConnector::new(vec![Err(EnumerateError::permanent("auth denied"))]);

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
    let mut times = vec![4u64, 5u64, 6u64, 12u64].into_iter();
    let first_outcome = run_scan_loop(
        session,
        &mut first_connector,
        budgets(1),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || now(times.next().expect("time script exhausted")),
    );

    match first_outcome {
        ScanLoopOutcome::LeaseLost {
            pages_completed,
            cause:
                LeaseLossCause::DeadlineElapsed {
                    now: lease_lost_now,
                    deadline,
                },
        } => {
            assert_eq!(pages_completed, 1);
            assert_eq!(lease_lost_now, now(12));
            assert_eq!(deadline, now(11));
        }
        other => panic!("expected LeaseLost(DeadlineElapsed), got {other:?}"),
    }

    let mid = shard_summary(&coord, 13);
    assert_eq!(mid.status(), ShardStatus::Active);
    assert_eq!(mid.last_key(), Some(&b"a"[..]));

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

#[test]
fn renewal_extends_deadline_and_scan_continues() {
    let mut coord = seeded_coordinator(20, CursorUpdate::initial());
    let mut connector = InMemoryDeterministicConnector::new(
        TAG,
        vec![make_mem_item(b"a", b"one"), make_mem_item(b"b", b"two")],
    );

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(650);
    let mut times = vec![4u64, 5u64, 6u64, 20u64, 21u64, 30u64].into_iter();
    let outcome = run_scan_loop_with_policy(
        session,
        &mut connector,
        budgets(1),
        RenewalPolicy::new(0.5),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || now(times.next().expect("time script exhausted")),
    );

    assert_eq!(outcome, ScanLoopOutcome::Completed);
    let summary = shard_summary(&coord, 80);
    assert_eq!(summary.status(), ShardStatus::Done);
    assert_eq!(summary.last_key(), Some(&b"b"[..]));
}

#[test]
fn stale_fence_during_renew_returns_lease_lost() {
    let base = seeded_coordinator(8, CursorUpdate::initial());
    let mut coord = FenceStealingBackend::new(base, now(20), worker(99));
    let mut connector = InMemoryDeterministicConnector::new(
        TAG,
        vec![make_mem_item(b"a", b"one"), make_mem_item(b"b", b"two")],
    );

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(680);
    let mut times = vec![4u64, 5u64, 6u64, 7u64, 20u64].into_iter();
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(1),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || now(times.next().expect("time script exhausted")),
    );

    match outcome {
        ScanLoopOutcome::LeaseLost {
            pages_completed,
            cause: LeaseLossCause::RenewFailed(RenewError::StaleFence { .. }),
        } => {
            assert_eq!(pages_completed, 2);
        }
        other => panic!("expected LeaseLost(RenewFailed(StaleFence)), got {other:?}"),
    }

    assert!(
        coord.stolen,
        "test hook should have forced a competing acquire"
    );
    let summary = shard_summary(&coord.inner, 25);
    assert_eq!(summary.status(), ShardStatus::Active);
    assert_eq!(summary.last_key(), Some(&b"b"[..]));
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
    let mut connector = ScriptedConnector::new(vec![Err(EnumerateError::permanent("auth denied"))]);

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
    let empty_terminal = EnumerationPage::new(Vec::new(), Cursor::with_last_key(make_key(b"b")));
    let mut connector = ScriptedConnector::new(vec![Ok(page_b), Ok(empty_terminal)]);

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(900);

    // baseline=4, checkpoint=5, renew-check=6 (no renew), complete=20.
    let mut times = [4u64, 5, 6, 20].into_iter();
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(10),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || now(times.next().expect("time script exhausted")),
    );

    match outcome {
        ScanLoopOutcome::Error(ScanLoopError::Complete(CompleteError::LeaseExpired { .. })) => {} // expected
        other => panic!("expected Error(Complete(LeaseExpired)), got {other:?}"),
    }

    // Checkpoint at "b" was durable before the complete failure.
    let summary = shard_summary(&coord, 21);
    assert_eq!(summary.status(), ShardStatus::Active);
    assert_eq!(summary.last_key(), Some(&b"b"[..]));
}

/// Lease expiry detected before checkpoint returns `LeaseLost`.
///
/// A single non-empty page is fetched successfully, but by the time the
/// loop is ready to checkpoint, the deadline has passed. The shard
/// remains `Active` because no terminal transition succeeded.
#[test]
fn checkpoint_deadline_elapsed_returns_lease_lost() {
    // Lease duration = 8, acquired at t=3, so deadline = 11.
    let mut coord = seeded_coordinator(8, CursorUpdate::initial());

    let page_b = EnumerationPage::new(
        vec![make_scan_item(b"b")],
        Cursor::with_last_key(make_key(b"b")),
    );
    let mut connector = ScriptedConnector::new(vec![Ok(page_b)]);

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(950);

    // baseline=4, checkpoint-attempt=20 (past deadline=11).
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
        ScanLoopOutcome::LeaseLost {
            pages_completed,
            cause:
                LeaseLossCause::DeadlineElapsed {
                    now: lease_lost_now,
                    deadline,
                },
        } => {
            assert_eq!(pages_completed, 0);
            assert_eq!(lease_lost_now, now(20));
            assert_eq!(deadline, now(11));
        }
        other => panic!("expected LeaseLost(DeadlineElapsed), got {other:?}"),
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
