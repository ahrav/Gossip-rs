use std::cell::Cell;

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

/// Test-only backend wrapper that injects a `CheckpointError` on a specific
/// checkpoint call, delegating everything else to the real coordinator.
struct CheckpointFailingBackend {
    inner: InMemoryCoordinator,
    /// 1-indexed: fail on the Nth checkpoint call.
    fail_on_call: usize,
    calls: usize,
}

impl CheckpointFailingBackend {
    fn new(inner: InMemoryCoordinator, fail_on_call: usize) -> Self {
        Self {
            inner,
            fail_on_call,
            calls: 0,
        }
    }
}

impl CoordinationBackend for CheckpointFailingBackend {
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
        self.calls += 1;
        if self.calls == self.fail_on_call {
            return Err(CheckpointError::CheckpointMissingKey);
        }
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

/// Test-only backend wrapper that panics if `renew()` is ever called.
/// Used to verify that the scan loop does NOT attempt renewal when ample
/// lease time remains.
struct NoRenewBackend {
    inner: InMemoryCoordinator,
}

impl NoRenewBackend {
    fn new(inner: InMemoryCoordinator) -> Self {
        Self { inner }
    }
}

impl CoordinationBackend for NoRenewBackend {
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
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        panic!("renew called unexpectedly — should_renew should have returned false");
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
    let first_script: &[u64] = &[4, 5, 6, 12];
    let first_idx = Cell::new(0usize);
    let first_outcome = run_scan_loop(
        session,
        &mut first_connector,
        budgets(1),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = first_idx.get();
            first_idx.set(i + 1);
            now(first_script[i])
        },
    );
    assert_eq!(
        first_idx.get(),
        first_script.len(),
        "time script not fully consumed"
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
    let renew_script: &[u64] = &[4, 5, 6, 20, 21, 30];
    let renew_idx = Cell::new(0usize);
    let outcome = run_scan_loop_with_policy(
        session,
        &mut connector,
        budgets(1),
        RenewalPolicy::new(0.5),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = renew_idx.get();
            renew_idx.set(i + 1);
            now(renew_script[i])
        },
    );
    assert_eq!(
        renew_idx.get(),
        renew_script.len(),
        "time script not fully consumed"
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
    let fence_script: &[u64] = &[4, 5, 6, 7, 20];
    let fence_idx = Cell::new(0usize);
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(1),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = fence_idx.get();
            fence_idx.set(i + 1);
            now(fence_script[i])
        },
    );
    assert_eq!(
        fence_idx.get(),
        fence_script.len(),
        "time script not fully consumed"
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

    // baseline_now = 4 (valid, passes early lease check), then t=20 for
    // the park_and_return call (past deadline=11, so park fails).
    let park_script: &[u64] = &[4, 20];
    let park_idx = Cell::new(0usize);
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(10),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = park_idx.get();
            park_idx.set(i + 1);
            now(park_script[i])
        },
    );
    assert_eq!(
        park_idx.get(),
        park_script.len(),
        "time script not fully consumed"
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

/// A4: Expired lease on empty-page path returns `LeaseLost`, not
/// `Error(Complete(..))`.
///
/// Two pages: first page checkpoints successfully (time within lease),
/// second page is empty (terminal) but the deadline has elapsed. The
/// pre-complete deadline guard catches this and returns `LeaseLost`
/// with `pages_completed: 1` (one successful checkpoint already persisted).
#[test]
fn expired_lease_on_empty_page_after_checkpoint_returns_lease_lost() {
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
    let complete_script: &[u64] = &[4, 5, 6, 20];
    let complete_idx = Cell::new(0usize);
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(10),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = complete_idx.get();
            complete_idx.set(i + 1);
            now(complete_script[i])
        },
    );
    assert_eq!(
        complete_idx.get(),
        complete_script.len(),
        "time script not fully consumed"
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
            assert_eq!(pages_completed, 1);
            assert_eq!(lease_lost_now, now(20));
            assert_eq!(deadline, now(11));
        }
        other => panic!("expected LeaseLost(DeadlineElapsed), got {other:?}"),
    }

    // Checkpoint at "b" was durable before lease loss was detected.
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
    let deadline_script: &[u64] = &[4, 20];
    let deadline_idx = Cell::new(0usize);
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(10),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = deadline_idx.get();
            deadline_idx.set(i + 1);
            now(deadline_script[i])
        },
    );
    assert_eq!(
        deadline_idx.get(),
        deadline_script.len(),
        "time script not fully consumed"
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

/// Edge-case verification for should_renew with very small lease durations.
///
/// Confirms that ceil() rounding produces conservative (earlier) renewal for
/// small durations, and the zero-threshold guard fires when fraction > 0 would
/// otherwise compute a threshold of 0.
#[test]
fn should_renew_small_duration_edge_cases() {
    let policy_half = RenewalPolicy::new(0.5);

    // duration=1, fraction=0.5 → ceil(0.5) = 1 → renew when remaining <= 1
    assert!(should_renew(now(9), now(10), 1, policy_half)); // remaining=1
    assert!(!should_renew(now(8), now(10), 1, policy_half)); // remaining=2

    // duration=2, fraction=0.5 → ceil(1.0) = 1 → renew when remaining <= 1
    assert!(should_renew(now(9), now(10), 2, policy_half)); // remaining=1
    assert!(!should_renew(now(8), now(10), 2, policy_half)); // remaining=2

    // duration=0, fraction=0.5 → ceil(0.0) = 0, but fraction > 0 → threshold = 1
    assert!(should_renew(now(9), now(10), 0, policy_half)); // remaining=1

    // duration=1, fraction=0.0 → ceil(0.0) = 0, fraction=0 → threshold stays 0
    let policy_zero = RenewalPolicy::new(0.0);
    // Only renews when now >= deadline (the early return), not via threshold.
    assert!(!should_renew(now(9), now(10), 1, policy_zero)); // remaining=1
    assert!(should_renew(now(10), now(10), 1, policy_zero)); // now == deadline
}

/// Empty page with expired lease returns `LeaseLost(DeadlineElapsed)`.
///
/// When the connector returns an empty page (terminal), the loop must check the
/// deadline before calling `session.complete()`. If the lease has expired, the
/// loop should return `LeaseLost` rather than attempting `complete` (which would
/// fail with `LeaseExpired` and surface as `Error(Complete(..))`).
#[test]
fn empty_page_with_expired_lease_returns_lease_lost() {
    // Lease duration = 8, acquired at t=3, so deadline = 11.
    let mut coord = seeded_coordinator(8, CursorUpdate::with_last_key(b"a"));

    let empty_page = EnumerationPage::new(Vec::new(), Cursor::with_last_key(make_key(b"a")));
    let mut connector = ScriptedConnector::new(vec![Ok(empty_page)]);

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(1050);

    // baseline_now = 4 (within lease), then complete_now = 20 (past deadline=11).
    let script: &[u64] = &[4, 20];
    let idx = Cell::new(0usize);
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(10),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = idx.get();
            idx.set(i + 1);
            now(script[i])
        },
    );
    assert_eq!(idx.get(), script.len(), "time script not fully consumed");

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

    // No terminal transition succeeded — shard stays Active.
    let summary = shard_summary(&coord, 21);
    assert_eq!(summary.status(), ShardStatus::Active);
}

// -- F2: parameterized should_renew coverage ---------------------------------

#[rstest]
// Branch A: now >= deadline (early true)
#[case(now(10), now(10), 20, RenewalPolicy::new(0.5), true)] // at deadline
#[case(now(15), now(10), 20, RenewalPolicy::new(0.5), true)] // past deadline
// Branch B: normal threshold calculation
#[case(now(2), now(20), 20, RenewalPolicy::new(0.5), false)] // plenty of time (remaining=18 > threshold=10)
#[case(now(10), now(20), 20, RenewalPolicy::new(0.5), true)] // at threshold (remaining=10 <= threshold=10)
#[case(now(11), now(20), 20, RenewalPolicy::new(0.5), true)] // below threshold
// Branch B edge: clamping
#[case(now(15), now(20), 20, RenewalPolicy::new(2.0), true)] // >1.0 clamped to 1.0, threshold=20
#[case(now(15), now(20), 20, RenewalPolicy::new(-1.0), false)] // <0.0 clamped to 0.0, threshold=0
// Fraction=0.0: never proactively renew (only at deadline)
#[case(now(9), now(10), 20, RenewalPolicy::new(0.0), false)] // threshold=0, remaining=1
#[case(now(10), now(10), 20, RenewalPolicy::new(0.0), true)] // at deadline, early return
// Fraction=1.0: always renew
#[case(now(1), now(20), 20, RenewalPolicy::new(1.0), true)]
// threshold=20, remaining=19
// Branch D: zero-duration with positive fraction (guard sets threshold=1)
#[case(now(5), now(10), 0, RenewalPolicy::new(0.5), false)] // threshold=1, remaining=5
#[case(now(9), now(10), 0, RenewalPolicy::new(0.5), true)] // threshold=1, remaining=1
// Branch E: zero-duration with zero fraction (threshold stays 0)
#[case(now(5), now(10), 0, RenewalPolicy::new(0.0), false)] // threshold=0, remaining=5
#[case(now(9), now(10), 0, RenewalPolicy::new(0.0), false)] // threshold=0, remaining=1
fn should_renew_parameterized(
    #[case] at: LogicalTime,
    #[case] deadline: LogicalTime,
    #[case] duration: u64,
    #[case] policy: RenewalPolicy,
    #[case] expected: bool,
) {
    assert_eq!(should_renew(at, deadline, duration, policy), expected);
}

// -- F9: RenewalPolicy::default() value test ---------------------------------

#[test]
fn renewal_policy_default_is_half_life() {
    let policy = RenewalPolicy::default();
    assert_eq!(policy.renew_at_fraction(), DEFAULT_RENEW_AT_FRACTION);
    assert_eq!(DEFAULT_RENEW_AT_FRACTION, 0.5);
}

// -- effective_fraction debug/release behavior for non-finite values ----------

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "non-finite")]
fn effective_fraction_panics_on_nan_in_debug() {
    let _ = RenewalPolicy::new(f64::NAN).effective_fraction();
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "non-finite")]
fn effective_fraction_panics_on_infinity_in_debug() {
    let _ = RenewalPolicy::new(f64::INFINITY).effective_fraction();
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "non-finite")]
fn effective_fraction_panics_on_neg_infinity_in_debug() {
    let _ = RenewalPolicy::new(f64::NEG_INFINITY).effective_fraction();
}

/// In release mode, non-finite fractions fall back to DEFAULT (0.5) inside
/// `should_renew` via `effective_fraction`. Verify the end-to-end path.
#[cfg(not(debug_assertions))]
#[rstest]
#[case(f64::NAN, now(10), now(20), 20, true)] // falls back to 0.5, threshold=10, remaining=10 → true
#[case(f64::NAN, now(2), now(20), 20, false)] // falls back to 0.5, threshold=10, remaining=18 → false
#[case(f64::INFINITY, now(10), now(20), 20, true)] // falls back to 0.5, threshold=10, remaining=10 → true
#[case(f64::NEG_INFINITY, now(10), now(20), 20, true)] // falls back to 0.5
fn should_renew_non_finite_falls_back_in_release(
    #[case] fraction: f64,
    #[case] at: LogicalTime,
    #[case] deadline: LogicalTime,
    #[case] duration: u64,
    #[case] expected: bool,
) {
    assert_eq!(
        should_renew(at, deadline, duration, RenewalPolicy::new(fraction)),
        expected,
    );
}

#[cfg(not(debug_assertions))]
#[test]
fn effective_fraction_falls_back_on_non_finite_in_release() {
    assert_eq!(
        RenewalPolicy::new(f64::NAN).effective_fraction(),
        DEFAULT_RENEW_AT_FRACTION,
    );
    assert_eq!(
        RenewalPolicy::new(f64::INFINITY).effective_fraction(),
        DEFAULT_RENEW_AT_FRACTION,
    );
    assert_eq!(
        RenewalPolicy::new(f64::NEG_INFINITY).effective_fraction(),
        DEFAULT_RENEW_AT_FRACTION,
    );
}

// -- F5: CheckpointError path ------------------------------------------------

/// Checkpoint failure returns `Error(Checkpoint(..))`.
///
/// One non-empty page is fetched and validated. The injected backend
/// returns `CheckpointMissingKey` on the first checkpoint call.
/// The scan loop must surface it as `Error(Checkpoint(CheckpointMissingKey))`.
#[test]
fn checkpoint_missing_key_returns_error() {
    let base = seeded_coordinator(40, CursorUpdate::initial());
    let mut coord = CheckpointFailingBackend::new(base, 1);

    let page_b = EnumerationPage::new(
        vec![make_scan_item(b"b")],
        Cursor::with_last_key(make_key(b"b")),
    );
    let mut connector = ScriptedConnector::new(vec![Ok(page_b)]);

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(1000);
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

    match outcome {
        ScanLoopOutcome::Error(ScanLoopError::Checkpoint(
            CheckpointError::CheckpointMissingKey,
        )) => {} // expected
        other => panic!("expected Error(Checkpoint(CheckpointMissingKey)), got {other:?}"),
    }
}

// -- F10: Multi-renewal recalibration ----------------------------------------

/// Two renewals across a 3-page scan verify threshold recalibration.
///
/// Lease duration = 20, acquired at t=3, deadline = 23.
/// Time script crafted so:
/// - Page 1 checkpoint: renew_now=15, remaining=8 <= threshold=10 → renew
///   (new deadline=35, recalibrated observed_duration=20)
/// - Page 2 checkpoint: renew_now=18, remaining=17 > threshold=10 → skip
/// - Page 3 checkpoint: renew_now=28, remaining=7 <= threshold=10 → renew
///   (new deadline=48)
/// - Page 4 (empty): complete at t=30 → Done
#[test]
fn multi_renewal_recalibrates_threshold() {
    let mut coord = seeded_coordinator(20, CursorUpdate::initial());
    let mut connector = InMemoryDeterministicConnector::new(
        TAG,
        vec![
            make_mem_item(b"a", b"one"),
            make_mem_item(b"b", b"two"),
            make_mem_item(b"c", b"three"),
        ],
    );

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(1100);
    // now_fn calls: baseline=4, ckpt1=5, renew1=15, ckpt2=17, renew2=18,
    //              ckpt3=20, renew3=28, complete=30
    let multi_script: &[u64] = &[4, 5, 15, 17, 18, 20, 28, 30];
    let multi_idx = Cell::new(0usize);
    let outcome = run_scan_loop_with_policy(
        session,
        &mut connector,
        budgets(1),
        RenewalPolicy::new(0.5),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let i = multi_idx.get();
            multi_idx.set(i + 1);
            now(multi_script[i])
        },
    );
    assert_eq!(
        multi_idx.get(),
        multi_script.len(),
        "time script not fully consumed"
    );

    assert_eq!(outcome, ScanLoopOutcome::Completed);
    let summary = shard_summary(&coord, 80);
    assert_eq!(summary.status(), ShardStatus::Done);
    assert_eq!(summary.last_key(), Some(&b"c"[..]));
}

// -- F11: Negative test — no renewal when ample time -------------------------

/// With a long lease (1000), should_renew never triggers, so the
/// `NoRenewBackend` (which panics on renew) must not fire.
#[test]
fn no_renewal_when_ample_lease_time() {
    let base = seeded_coordinator(1000, CursorUpdate::initial());
    let mut coord = NoRenewBackend::new(base);
    let mut connector = InMemoryDeterministicConnector::new(
        TAG,
        vec![make_mem_item(b"a", b"one"), make_mem_item(b"b", b"two")],
    );

    let session = acquire_session(&mut coord, 3, 1);
    let mut op_ids = counter_op_ids(1200);
    let mut tick = 4u64;
    let outcome = run_scan_loop(
        session,
        &mut connector,
        budgets(1),
        DEFAULT_MAX_TRANSIENT_RETRIES,
        &mut op_ids,
        || {
            let out = now(tick);
            tick += 1;
            out
        },
    );

    assert_eq!(outcome, ScanLoopOutcome::Completed);
    let summary = shard_summary(&coord.inner, 1100);
    assert_eq!(summary.status(), ShardStatus::Done);
    assert_eq!(summary.last_key(), Some(&b"b"[..]));
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
