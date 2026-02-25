//! Tests for [`WorkerSession`], the RAII handle that binds a worker to a shard.
//!
//! `WorkerSession` wraps an acquired lease and a cached `ShardSnapshot`, then
//! delegates every operation (checkpoint, complete, park, split, renew) to the
//! backend while keeping the cached snapshot consistent. This module verifies
//! that the session wrapper faithfully threads operations through to the backend
//! and maintains its internal state correctly, including after errors.
//!
//! # Coverage Areas
//!
//! - **Happy-path operations**: session creation, checkpoint, complete, park,
//!   split_replace, split_residual, renew. Each verifies the operation succeeds
//!   and that the session's observable state (lease, spec, cursor, capacity) is
//!   consistent afterward.
//!
//! - **Ownership semantics**: `complete`, `park`, and `split_replace` consume
//!   the session (move semantics), while `split_residual`, `checkpoint`, and
//!   `renew` borrow mutably and keep the session usable.
//!
//! - **Error propagation**: `LeaseExpired`, `AlreadyLeased`, and `StaleFence`
//!   errors from the backend surface through the session API without wrapping.
//!
//! - **Snapshot integrity**: checkpoint does not update the cached snapshot;
//!   failed `split_residual` does not corrupt it; replayed `split_residual`
//!   does not double-rebuild it; successive splits accumulate spawned entries
//!   correctly.
//!
//! - **Idempotency**: replayed checkpoint returns `Replayed`; replayed
//!   complete returns `Replayed` (tested via raw backend after consume).
//!   Op-log eviction fallback for split_residual also returns `Replayed`.
//!
//! - **Crash recovery**: dropping a session without a terminal op, then
//!   re-acquiring after lease expiry, restores the checkpointed cursor.
//!
//! - **Lease renewal invariants**: renew advances the deadline without changing
//!   the fence epoch; duplicate same-tick renewals are harmless.
//!
//! - **Capacity hints**: session reports correct available/saturated counts
//!   after acquisition and after renewal.
//!
//! - **Property test**: random Renew/Checkpoint/SplitResidual sequences
//!   preserve identity invariants (tenant, worker, shard_key never change)
//!   and terminate cleanly with complete.

use super::*;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::run::{InitialShardInput, RunConfig, RunManagement};
use crate::coordination::shard_spec::CursorSemantics;
use crate::identity::{RunId, ShardId};
use crate::test_util::miri_proptest_config;
use proptest::prelude::*;

fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

fn test_run() -> RunId {
    RunId::from_raw(1)
}

fn test_worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

fn now(t: u64) -> LogicalTime {
    LogicalTime::from_raw(t)
}

/// Returns a run config with `CursorSemantics::Completed`, a 30-tick
/// lease duration, and a max-workers-per-run of 5.
fn test_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
}

/// Set up a coordinator with a single run containing `shard_count` shards.
///
/// Each shard covers a wide range: shard i covers `[i*0x40, (i+1)*0x40)`.
/// This gives enough room for cursor values and split operations.
/// The lease duration is 30 ticks (from `test_run_config`), so acquiring
/// at `now(2)` yields a deadline of 32.
fn setup_coordinator(shard_count: usize) -> (InMemoryCoordinator, Vec<ShardKey>) {
    let mut coord = InMemoryCoordinator::new(30);
    let tenant = test_tenant();
    let run = test_run();
    let config = test_run_config();

    coord.create_run(now(1), tenant, run, config).unwrap();

    let shards: Vec<InitialShardInput> = (0..shard_count)
        .map(|i| {
            let start = vec![(i as u8) * 0x40];
            let end = vec![((i + 1) as u8) * 0x40];
            InitialShardInput::new(
                ShardId::from_raw(i as u64),
                crate::coordination::shard_spec::ShardSpec::with_range(start, end),
                Cursor::initial(),
            )
        })
        .collect();

    let _ = coord
        .register_shards(now(1), tenant, run, &shards, OpId::from_raw(100))
        .unwrap();

    let keys: Vec<ShardKey> = (0..shard_count)
        .map(|i| ShardKey::new(run, ShardId::from_raw(i as u64)))
        .collect();

    (coord, keys)
}

// ============================================================================
// Happy-path operations
//
// Each test exercises one session method and verifies success plus the
// session's observable state afterward.
// ============================================================================

/// Session creation acquires the shard and populates identity fields
/// (tenant, worker, shard_key) and the initial snapshot (spec, cursor).
#[test]
fn new_ok() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    assert_eq!(session.tenant(), test_tenant());
    assert_eq!(session.worker(), test_worker(1));
    assert_eq!(session.shard_key(), keys[0]);
    assert_eq!(session.lease().shard(), ShardId::from_raw(0));
    assert_eq!(
        session.initial_snapshot().spec().key_range_start(),
        [0x00u8]
    );
}

/// `complete` consumes the session by move; the shard transitions to Done.
/// After this call, the session variable is no longer usable (enforced by
/// Rust's ownership system).
#[test]
fn complete_consumes() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Cursor must be within shard range [0x00, 0x40).
    let cursor = CursorUpdate::new(&[0x10]);
    let result = session.complete(now(3), &cursor, OpId::from_raw(200));
    assert!(result.is_ok());
}

/// `split_residual` borrows the session mutably and keeps it usable.
/// After the split, the session's spec reflects the narrowed parent range,
/// and further operations (checkpoint) work within the new bounds.
#[test]
fn split_residual_keeps_session() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Shard 0 covers [0x00, 0x40). Split into [0x00, 0x20) + residual [0x20, 0x40).
    let parent_new_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let residual_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
    let plan = SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec).unwrap();

    let result = session.split_residual(now(3), plan, OpId::from_raw(300));
    assert!(result.is_ok());

    // Session is still usable — checkpoint should work.
    // Cursor must be within narrowed range [0x00, 0x20).
    let cursor = CursorUpdate::new(&[0x10]);
    let cp_result = session.checkpoint(now(4), &cursor, OpId::from_raw(301));
    assert!(cp_result.is_ok());

    // Snapshot spec should reflect the narrowed range.
    assert_eq!(session.spec().key_range_end(), &[0x20]);
}

/// `renew` extends the lease deadline without creating a new session.
/// The internal lease handle is updated so subsequent operations see the
/// new deadline.
#[test]
fn renew_updates_internal_deadline() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let old_deadline = session.lease().deadline();
    let _result = session.renew(now(10)).unwrap();
    let new_deadline = session.lease().deadline();

    // Deadline must have advanced.
    assert!(new_deadline > old_deadline);
}

/// `park` consumes the session by move, transitioning the shard to Parked.
#[test]
fn park_consumes_session() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let result = session.park(now(3), ParkReason::Other, OpId::from_raw(400));
    assert!(result.is_ok());
}

/// `split_replace` consumes the session by move. The parent transitions to
/// Split, and the returned outcome contains the newly created child shard IDs.
#[test]
fn split_replace_consumes_session() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Shard 0 covers [0x00, 0x40). Split into children [0x00, 0x20) + [0x20, 0x40).
    let child1_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let child2_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);

    use crate::coordination::split::SplitReplaceChild;
    let plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(child1_spec, Cursor::initial()),
        SplitReplaceChild::new(child2_spec, Cursor::initial()),
    ])
    .unwrap();

    let result = session.split_replace(now(3), plan, OpId::from_raw(500));
    assert!(result.is_ok());
    if let Ok(outcome) = result {
        let inner = outcome.into_inner();
        assert_eq!(inner.children.len(), 2);
    }
}

/// Checkpoint through the session returns `Executed` on first call and
/// delegates successfully to the backend.
#[test]
fn checkpoint_advances_cursor_via_session() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let cursor = CursorUpdate::new(&[0x10]);
    let result = session.checkpoint(now(3), &cursor, OpId::from_raw(600));
    assert!(result.is_ok());
    assert!(result.unwrap().is_executed());
}

// -- Error-path & edge-case tests ------------------------------------

/// Replaying the same `split_residual` OpId must NOT rebuild the
/// cached snapshot. The `is_executed()` guard in `split_residual`
/// is the only thing preventing double-rebuild, which would corrupt
/// the spawned list by appending the residual ID twice.
#[test]
fn split_residual_replayed_does_not_rebuild_snapshot() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let parent_new_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let residual_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);

    // First call: Executed — snapshot is rebuilt with narrowed range.
    let plan1 = SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec.clone()).unwrap();
    let op = OpId::from_raw(700);
    let r1 = session.split_residual(now(3), plan1, op).unwrap();
    assert!(r1.is_executed());

    let spec_after_first = session.spec().clone();
    let spawned_after_first: Vec<_> = session.initial_snapshot().spawned().to_vec();
    assert_eq!(spawned_after_first.len(), 1);

    // Second call with same OpId: Replayed — snapshot must NOT change.
    let plan2 = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
    let r2 = session.split_residual(now(4), plan2, op).unwrap();
    assert!(r2.is_replay());

    assert_eq!(session.spec(), &spec_after_first);
    assert_eq!(session.initial_snapshot().spawned(), &spawned_after_first);
}

/// After op-log eviction (16+ subsequent ops), the backend falls
/// back to a spawned-probe to detect the residual. This test
/// verifies that the fallback returns `Replayed` even though the
/// original op-log entry has been evicted.
#[test]
fn split_residual_replayed_after_oplog_eviction() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Shard 0 covers [0x00, 0x40). Split into [0x00, 0x20) + residual [0x20, 0x40).
    let parent_new_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let residual_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
    let split_op = OpId::from_raw(700);
    let plan = SplitResidualPlan::try_new(parent_new_spec.clone(), residual_spec.clone()).unwrap();
    let r = session.split_residual(now(3), plan, split_op).unwrap();
    assert!(r.is_executed(), "first call must be Executed");

    // Execute 17 checkpoints to evict the split op-log entry.
    // OP_LOG_CAP = 16, so 17 pushes guarantee eviction.
    let mut t = 10u64;
    for i in 0..17u64 {
        // Cursor bytes 0x01..=0x11, all within narrowed range [0x00, 0x20).
        let key = [(i + 1) as u8];
        let cursor = CursorUpdate::new(&key);
        let _ = session
            .checkpoint(now(t), &cursor, OpId::from_raw(801 + i))
            .unwrap();
        t += 1;
    }

    // Retry split_residual with the same OpId — op-log entry is
    // evicted, but the spawned-probe fallback detects the residual.
    let plan2 = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
    let r2 = session.split_residual(now(t), plan2, split_op).unwrap();
    assert!(
        r2.is_replay(),
        "must return Replayed via spawned-probe fallback after op-log eviction"
    );
}

/// Renewing a lease must not change the fence epoch — renewal is a
/// deadline extension, not an ownership transfer.
#[test]
fn renew_postconditions_fence_stable() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let fence_before = session.lease().fence();

    // First renewal.
    let _ = session.renew(now(10)).unwrap();
    assert_eq!(
        session.lease().fence(),
        fence_before,
        "fence must not change after first renewal"
    );

    // Second renewal.
    let _ = session.renew(now(20)).unwrap();
    assert_eq!(
        session.lease().fence(),
        fence_before,
        "fence must not change after second renewal"
    );
}

/// Two renew calls at the same logical time produce the same deadline
/// (`now + lease_duration`). The second call must not panic — the trait
/// contract only requires `new_deadline > now`, and duplicate renewals
/// are documented as harmless.
#[test]
fn duplicate_same_tick_renew_does_not_panic() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // First renew at now=10 → deadline = 10 + 30 = 40.
    let r1 = session.renew(now(10)).unwrap();
    assert_eq!(r1.new_deadline, now(40));

    // Second renew at the same now=10 → backend computes the same deadline.
    // This must not panic; duplicate renewals are documented as harmless.
    let r2 = session.renew(now(10)).unwrap();
    assert_eq!(r2.new_deadline, now(40));
}

/// After `split_residual` narrows `[0x00, 0x40)` → `[0x00, 0x20)`,
/// a checkpoint within the narrowed range succeeds but a cursor
/// outside it is rejected with `CursorOutOfBounds`.
#[test]
fn checkpoint_after_split_validates_narrowed_bounds() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Narrow to [0x00, 0x20).
    let parent_new_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let residual_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
    let plan = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
    let _ = session
        .split_residual(now(3), plan, OpId::from_raw(800))
        .unwrap();

    // Within narrowed range — succeeds.
    let ok_cursor = CursorUpdate::new(&[0x10]);
    assert!(
        session
            .checkpoint(now(4), &ok_cursor, OpId::from_raw(801))
            .is_ok()
    );

    // Outside narrowed range — rejected.
    let bad_cursor = CursorUpdate::new(&[0x30]);
    let err = session
        .checkpoint(now(5), &bad_cursor, OpId::from_raw(802))
        .unwrap_err();
    assert!(
        matches!(err, CheckpointError::CursorOutOfBounds(_)),
        "expected CursorOutOfBounds, got {err:?}"
    );
}

/// Advancing time past the lease deadline causes both `renew` and
/// `checkpoint` to return their respective `LeaseExpired` errors.
/// Verifies session correctly threads `now` and `lease` to the backend.
#[test]
fn expired_lease_rejected_through_session() {
    let (mut coord, keys) = setup_coordinator(1);
    // Acquire at now(2) with lease_duration=30 → deadline=32.
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    // Renew past deadline.
    let renew_err = session.renew(now(50)).unwrap_err();
    assert!(
        matches!(renew_err, RenewError::LeaseExpired { .. }),
        "expected LeaseExpired, got {renew_err:?}"
    );

    // Checkpoint past deadline.
    let cp_err = session
        .checkpoint(now(50), &CursorUpdate::new(&[0x10]), OpId::from_raw(900))
        .unwrap_err();
    assert!(
        matches!(cp_err, CheckpointError::LeaseExpired { .. }),
        "expected LeaseExpired, got {cp_err:?}"
    );
}

/// When another worker holds a live lease, `WorkerSession::new`
/// surfaces `AlreadyLeased` without wrapping or translating the error.
#[test]
fn already_leased_rejected_through_session() {
    let (mut coord, keys) = setup_coordinator(1);

    // Worker 1 acquires via raw backend call (borrow released on return).
    let _w1 = coord
        .acquire_and_restore(now(2), test_tenant(), keys[0], test_worker(1))
        .unwrap();

    // Worker 2 tries to create a session on the same shard.
    match WorkerSession::new(&mut coord, now(3), test_tenant(), keys[0], test_worker(2)) {
        Err(AcquireError::AlreadyLeased { .. }) => {} // expected
        Err(other) => panic!("expected AlreadyLeased, got {other:?}"),
        Ok(_) => panic!("expected AlreadyLeased, but session was created"),
    }
}

// -- Stale-fence & crash-recovery tests ------------------------------

/// A stale lease (from a previous session whose fence was superseded)
/// is rejected with `StaleFence` when presented for a checkpoint.
/// Tests the fencing protocol through the coordination backend after
/// two successive session acquisitions on the same shard.
#[test]
fn stale_fence_rejected_through_session() {
    let (mut coord, keys) = setup_coordinator(1);
    // Worker 1 acquires at t=2, deadline=32.
    let session_w1 =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
    let stale_lease = *session_w1.lease();
    // Drop session (release borrow), expire the lease, then worker 2 acquires.
    drop(session_w1);
    let _session_w2 =
        WorkerSession::new(&mut coord, now(50), test_tenant(), keys[0], test_worker(2)).unwrap();
    drop(_session_w2);
    // Use raw backend with stale_lease to verify StaleFence.
    let cp_err = coord
        .checkpoint(
            now(51),
            test_tenant(),
            &stale_lease,
            &CursorUpdate::new(&[0x10]),
            OpId::from_raw(950),
        )
        .unwrap_err();
    assert!(
        matches!(cp_err, CheckpointError::StaleFence { .. }),
        "expected StaleFence, got {cp_err:?}"
    );
}

/// Simulates a crash by dropping session 1 without a terminal op, then
/// re-acquiring. The checkpoint written by session 1 must be restored
/// in session 2's initial cursor.
#[test]
fn crash_recovery_restores_cursor() {
    let (mut coord, keys) = setup_coordinator(1);
    // Session 1: acquire and checkpoint to 0x15.
    {
        let mut s1 =
            WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
        let cursor = CursorUpdate::new(&[0x15]);
        let _ = s1
            .checkpoint(now(3), &cursor, OpId::from_raw(1000))
            .unwrap();
        // Session dropped (simulated crash) without terminal op.
    }
    // Session 2: re-acquire after lease expiry, verify restored cursor.
    let s2 =
        WorkerSession::new(&mut coord, now(50), test_tenant(), keys[0], test_worker(2)).unwrap();
    assert_eq!(s2.cursor().last_key(), Some(&[0x15u8][..]));
}

// -- Idempotency tests ------------------------------------------------

/// Replaying a checkpoint with the same OpId and identical cursor
/// returns `Replayed` rather than `Executed`.
#[test]
fn checkpoint_replayed_returns_replayed() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let cursor = CursorUpdate::new(&[0x10]);
    let op = OpId::from_raw(1100);
    let first = session.checkpoint(now(3), &cursor, op).unwrap();
    assert!(first.is_executed());

    let second = session.checkpoint(now(4), &cursor, op).unwrap();
    assert!(second.is_replay());
}

/// Replaying a complete with the same OpId returns `Replayed`.
/// Since `complete` consumes the session, the replay is tested via
/// a raw backend call with the same lease.
#[test]
fn complete_replayed_returns_replayed() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
    let lease = *session.lease();

    let cursor = CursorUpdate::new(&[0x10]);
    let op = OpId::from_raw(1200);
    let first = session.complete(now(3), &cursor, op).unwrap();
    assert!(first.is_executed());

    // Replay via raw backend — the shard is now Done, but the backend
    // recognizes the idempotent replay by matching the OpId.
    let second = coord
        .complete(now(4), test_tenant(), &lease, &cursor, op)
        .unwrap();
    assert!(second.is_replay());
}

// -- Snapshot staleness tests ----------------------------------------

/// Checkpoint does NOT update the session's cached snapshot.
/// The cursor returned by `session.cursor()` should still reflect
/// the acquisition-time cursor, not the checkpoint value.
#[test]
fn checkpoint_does_not_update_cached_snapshot() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let initial_cursor = session.cursor().clone();

    let checkpoint_cursor = CursorUpdate::new(&[0x10]);
    let result = session.checkpoint(now(3), &checkpoint_cursor, OpId::from_raw(600));
    assert!(result.is_ok());

    // Session's cached cursor must still be the acquisition-time value.
    assert_eq!(
        session.cursor(),
        &initial_cursor,
        "checkpoint must not update cached snapshot cursor"
    );
    assert_eq!(
        checkpoint_cursor.last_key(),
        Some(&[0x10][..]),
        "checkpoint cursor update must preserve the requested key"
    );
}

/// A failed `split_residual` must not corrupt the session's cached
/// snapshot. We trigger a `LeaseExpired` error by advancing time
/// past the deadline.
#[test]
fn split_residual_error_does_not_corrupt_snapshot() {
    let (mut coord, keys) = setup_coordinator(1);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();

    let spec_before = session.spec().clone();
    let cursor_before = session.cursor().clone();
    let spawned_before: Vec<_> = session.initial_snapshot().spawned().to_vec();

    // Attempt split_residual with expired lease (deadline=32, now=50).
    let parent_new_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]);
    let residual_spec =
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]);
    let plan = SplitResidualPlan::try_new(parent_new_spec, residual_spec).unwrap();
    let err = session.split_residual(now(50), plan, OpId::from_raw(900));
    assert!(
        err.is_err(),
        "split_residual should fail with expired lease"
    );

    // Snapshot must be unchanged after the error.
    assert_eq!(session.spec(), &spec_before);
    assert_eq!(session.cursor(), &cursor_before);
    assert_eq!(session.initial_snapshot().spawned(), &spawned_before);
}

// -- Successive split_residual test ------------------------------------

/// Two successive `split_residual` calls accumulate spawned entries and
/// correctly narrow the shard's key range at each step.
/// Shard starts as [0x00, 0x60). First split -> [0x00, 0x40) + residual
/// [0x40, 0x60). Second split -> [0x00, 0x20) + residual [0x20, 0x40).
#[test]
fn successive_split_residual_accumulates_spawned() {
    // Use a shard with range [0x00, 0x60) for room.
    let mut coord = InMemoryCoordinator::new(30);
    let tenant = test_tenant();
    let run = test_run();
    let config = test_run_config();
    coord.create_run(now(1), tenant, run, config).unwrap();

    let shard_spec = crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x60]);
    let shard = InitialShardInput::new(ShardId::from_raw(0), shard_spec, Cursor::initial());
    let _ = coord
        .register_shards(now(1), tenant, run, &[shard], OpId::from_raw(100))
        .unwrap();
    let key = ShardKey::new(run, ShardId::from_raw(0));

    let mut session = WorkerSession::new(&mut coord, now(2), tenant, key, test_worker(1)).unwrap();

    // First split: [0x00, 0x60) -> [0x00, 0x40) + residual [0x40, 0x60).
    let plan1 = SplitResidualPlan::try_new(
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x40]),
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x40], vec![0x60]),
    )
    .unwrap();
    let r1 = session
        .split_residual(now(3), plan1, OpId::from_raw(300))
        .unwrap();
    assert!(r1.is_executed());
    assert_eq!(session.spec().key_range_end(), &[0x40]);
    assert_eq!(session.initial_snapshot().spawned().len(), 1);

    // Second split: [0x00, 0x40) -> [0x00, 0x20) + residual [0x20, 0x40).
    let plan2 = SplitResidualPlan::try_new(
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x00], vec![0x20]),
        crate::coordination::shard_spec::ShardSpec::with_range(vec![0x20], vec![0x40]),
    )
    .unwrap();
    let r2 = session
        .split_residual(now(4), plan2, OpId::from_raw(301))
        .unwrap();
    assert!(r2.is_executed());
    assert_eq!(session.spec().key_range_end(), &[0x20]);
    assert_eq!(session.initial_snapshot().spawned().len(), 2);

    // Checkpoint within the twice-narrowed range succeeds.
    let cursor = CursorUpdate::new(&[0x10]);
    let cp = session
        .checkpoint(now(5), &cursor, OpId::from_raw(302))
        .unwrap();
    assert!(cp.is_executed());
}

// -- Property tests --------------------------------------------------

/// Operation kinds for the property test.
///
/// Generated up front by proptest and then interpreted against
/// runtime state (current key range, last cursor position).
/// Operations that are invalid in the current state (e.g., a
/// checkpoint with a cursor that would regress, or a split on
/// a range too narrow to subdivide) are skipped rather than
/// rejected, keeping the shrinking behavior stable.
#[derive(Debug, Clone)]
enum PropOp {
    Renew,
    Checkpoint(u8),
    SplitResidual,
}

// Random operation sequences — including split_residual — preserve
// identity invariants throughout the session lifecycle.
//
// Generates random Renew / Checkpoint(byte) / SplitResidual sequences
// and verifies that:
// - `tenant()`, `worker()`, and `shard_key()` never change (identity stability)
// - All valid operations succeed (no spurious errors)
// - `complete()` succeeds at the end (session terminates cleanly)
//
// The weight distribution (2:5:1) biases toward checkpoints (the
// most common real-world operation) while still exercising renew
// and the tricky split_residual path.
proptest! {
    #![proptest_config(miri_proptest_config())]

    #[test]
    fn prop_session_lifecycle_invariants(
        ops in proptest::collection::vec(
            prop_oneof![
                2 => Just(PropOp::Renew),
                5 => (0x01u8..=0x3Eu8).prop_map(PropOp::Checkpoint),
                1 => Just(PropOp::SplitResidual),
            ],
            0..10,
        ),
    ) {
        let (mut coord, keys) = setup_coordinator(1);
        // Acquire at t=2, deadline=32. All ops use times in [3, 30].
        let mut session = WorkerSession::new(
            &mut coord, now(2), test_tenant(), keys[0], test_worker(1),
        ).unwrap();

        let expected_tenant = session.tenant();
        let expected_worker = session.worker();
        let expected_key = session.shard_key();

        let mut t = 3u64;
        let mut last_cursor_byte: u8 = 0;
        let mut op_counter = 1000u64;
        // Track current key range (single-byte boundaries).
        let range_start: u8 = 0x00;
        let mut range_end: u8 = 0x40;

        for op in &ops {
            // Identity invariants hold before every operation.
            prop_assert_eq!(session.tenant(), expected_tenant);
            prop_assert_eq!(session.worker(), expected_worker);
            prop_assert_eq!(session.shard_key(), expected_key);

            match op {
                PropOp::Renew => {
                    let _ = session.renew(now(t)).map_err(|e| {
                        TestCaseError::Fail(format!("renew failed at t={t}: {e:?}").into())
                    })?;
                }
                PropOp::Checkpoint(byte) => {
                    // Skip if out of narrowed range or would regress cursor.
                    if *byte <= last_cursor_byte
                        || *byte < range_start
                        || *byte >= range_end
                    {
                        continue;
                    }
                    let key = [*byte];
                    let cursor = CursorUpdate::new(&key);
                    let _ = session
                        .checkpoint(now(t), &cursor, OpId::from_raw(op_counter))
                        .map_err(|e| {
                            TestCaseError::Fail(
                                format!("checkpoint({byte:#04x}) failed at t={t}: {e:?}")
                                    .into(),
                            )
                        })?;
                    last_cursor_byte = *byte;
                    op_counter += 1;
                }
                PropOp::SplitResidual => {
                    // Need at least 4 bytes of range to split meaningfully.
                    if range_end.saturating_sub(range_start) < 4 {
                        continue;
                    }
                    let mid = range_start + (range_end - range_start) / 2;
                    // Split point must leave the cursor inside the new
                    // parent range [range_start, mid).
                    if mid <= last_cursor_byte {
                        continue;
                    }
                    let parent_new =
                        crate::coordination::shard_spec::ShardSpec::with_range(
                            vec![range_start],
                            vec![mid],
                        );
                    let residual =
                        crate::coordination::shard_spec::ShardSpec::with_range(
                            vec![mid],
                            vec![range_end],
                        );
                    let plan =
                        SplitResidualPlan::try_new(parent_new, residual).unwrap();
                    let result = session
                        .split_residual(now(t), plan, OpId::from_raw(op_counter))
                        .map_err(|e| {
                            TestCaseError::Fail(
                                format!("split_residual at t={t}: {e:?}").into(),
                            )
                        })?;
                    prop_assert!(result.is_executed());
                    prop_assert_eq!(session.spec().key_range_end(), &[mid]);
                    range_end = mid;
                    op_counter += 1;
                }
            }
            t += 1;
        }

        // Terminal operation — cursor must be in [range_start, range_end).
        let final_byte = last_cursor_byte.max(range_start + 1);
        if final_byte < range_end {
            let key = [final_byte];
            let final_cursor = CursorUpdate::new(&key);
            let _ = session.complete(now(t), &final_cursor, OpId::from_raw(op_counter)).map_err(|e| {
                TestCaseError::Fail(format!("complete failed: {e:?}").into())
            })?;
        }
        // If range too narrow for any valid cursor, session is dropped.
    }
}

// -- Capacity hint tests -----------------------------------------------
//
// The capacity hint tells a worker how many shards remain available in the
// run, enabling back-pressure and scheduling decisions.

/// After acquiring one of two shards, the session's capacity hint
/// shows the remaining shard as available.
#[test]
fn session_capacity_updated_on_renew() {
    let (mut coord, keys) = setup_coordinator(2);
    let mut session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
    // 2 shards total, 1 just acquired ⇒ 1 available.
    assert_eq!(session.capacity().available_count, 1);
    assert!(!session.capacity().is_saturated());

    // Renew — capacity hint is refreshed.
    let _ = session.renew(now(10)).unwrap();
    assert_eq!(session.capacity().available_count, 1);
}

/// With a single shard, after acquiring it the session sees 0 available.
#[test]
fn session_capacity_zero_when_all_leased() {
    let (mut coord, keys) = setup_coordinator(1);
    let session =
        WorkerSession::new(&mut coord, now(2), test_tenant(), keys[0], test_worker(1)).unwrap();
    assert_eq!(session.capacity().available_count, 0);
    assert!(session.capacity().is_saturated());
    assert!(session.capacity().earliest_deadline.is_some());
}
