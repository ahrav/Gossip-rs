//! Tests for the [`RunManagement`] trait as implemented by
//! [`InMemoryCoordinator`].
//!
//! # Scope
//!
//! This module exercises run-level operations: `create_run`,
//! `register_shards`, `complete_run`, `fail_run`, `cancel_run`,
//! `unpark_shard`, `list_shards_into`, `get_run_progress`, and the
//! convenience combo `create_run_with_shards`. It does **not** test
//! shard-level operations (acquire, checkpoint, etc.) except as setup
//! steps for run-level assertions.
//!
//! # Key invariants verified
//!
//! - **Run state machine**: Initializing -> Active (via register_shards)
//!   -> Done | Failed | Cancelled. Transitions out of terminal states are
//!   rejected.
//! - **Split-index consistency**: Child shards created by split operations
//!   appear in `list_shards_into` and `get_run_progress` immediately.
//! - **Watermark correctness**: `get_run_progress().watermark()` equals
//!   the lexicographic minimum of cursor keys across *Active* shards
//!   only, excluding Done/Split/Parked.
//! - **Shard-count limits**: `register_shards` rejects the entire batch
//!   when per-tenant or global limits would be exceeded.
//! - **Idempotent replay**: Same `(OpId, payload)` returns `Replayed`;
//!   same `OpId` with different payload returns `OpIdConflict`.
//! - **Unpark lifecycle**: Parked -> Active with fence bump, cursor
//!   preservation, and rejection when the run is terminal.
//!
//! # Section organization
//!
//! Tests are grouped by the operation or contract they exercise. Each
//! group starts with a section comment naming the operation and
//! summarizing what it covers. Parameterized tests use `rstest` to
//! avoid repeating identical structure for complete/fail/cancel.

use super::*;
use crate::coordination::cursor::CursorUpdate;
use crate::coordination::run::{
    InitialShardInput, RunConfig, RunManagement, RunStatus, ShardFilter, ShardSummary,
};
use crate::coordination::shard_spec::{CursorSemantics, ShardLimitScope, ShardSpec};
use crate::coordination::test_fixtures::{
    LEASE_DURATION, acquire_result, coordinator_with_run_and_lease, do_split_replace, now,
    short_lease_run_config, test_run, test_split_residual_plan, test_tenant, test_worker,
};
use crate::identity::{FenceEpoch, OpId, RunId, ShardId, ShardKey};
use crate::sim::backend::SimIntrospection;
use rstest::rstest;

fn list_shards_for_run(
    coord: &InMemoryCoordinator,
    at: LogicalTime,
    filter: ShardFilter,
    out: &mut Vec<ShardSummary>,
) {
    // Optional pre-sizing for deterministic test allocations.
    // `list_shards_into` itself can grow `out` if needed.
    let required = coord
        .run_shards
        .get(&(test_tenant(), test_run()))
        .map_or(0, |ids| ids.len());
    if out.capacity() < required {
        out.reserve(required - out.capacity());
    }
    coord
        .list_shards_into(at, test_tenant(), test_run(), filter, out)
        .unwrap();
}

// -- Split index consistency tests --
//
// After a split, child shards must be visible through the run-level
// APIs (get_run_progress, list_shards_into). These tests verify the
// coordinator's split index is updated atomically with the split.

#[test]
fn split_replace_children_visible_in_run_progress() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    let progress = coord
        .get_run_progress(now(5), test_tenant(), test_run())
        .unwrap();
    assert!(
        progress.total() == 3,
        "expected total == 3 (parent + 2 children), got {}",
        progress.total(),
    );
    assert_eq!(progress.split(), 1, "parent should be Split");
    assert_eq!(progress.active(), 2, "two children should be Active");
}

#[test]
fn split_replace_children_visible_in_list_shards() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);

    let mut all = Vec::new();
    list_shards_for_run(&coord, now(5), ShardFilter::all(), &mut all);
    assert!(
        all.len() == 3,
        "expected 3 shards in listing (parent + 2 children), got {}",
        all.len(),
    );

    let starts: Vec<&[u8]> = all.iter().map(|s| s.key_range_start()).collect();
    assert!(
        starts.contains(&b"a".as_slice()) && starts.contains(&b"m".as_slice()),
        "children [a,m) and [m,z) should be in listing; starts = {starts:?}",
    );
}

#[test]
fn split_residual_child_visible_in_list_shards() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // Checkpoint to set cursor within new parent range.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();

    // Split residual: parent shrinks to [a,m), residual gets [m,z).
    let plan = test_split_residual_plan();
    let _ = coord
        .split_residual(now(5), test_tenant(), &lease, plan, OpId::from_raw(2))
        .unwrap();

    let mut all = Vec::new();
    list_shards_for_run(&coord, now(6), ShardFilter::all(), &mut all);
    assert!(
        all.len() == 2,
        "expected 2 shards (parent + residual), got {}",
        all.len(),
    );

    let has_residual = all
        .iter()
        .any(|s| s.key_range_start() == b"m" && s.key_range_end() == b"z");
    assert!(has_residual, "residual [m,z) should be in listing");
}

// -- get_run_progress watermark tests -----------------------------------------
//
// The watermark is the lexicographic minimum of `cursor.last_key` across all
// Active shards in a run. It approximates "how far has the run processed?"
// and is used for progress reporting and backpressure decisions.
//
// Correctness requirements:
// - Only Active shards contribute; Done, Split, and Parked are excluded.
// - `None` when no Active shard has a non-initial cursor.
// - The watermark advances when the lagging shard's cursor advances.
// - Shards registered with non-initial cursors (resume) are included.
// - Unpark reintroduces the shard's cursor into the watermark pool.

/// Acquire `shard` and write a checkpoint key at a controlled logical time.
fn checkpoint_shard_last_key(
    coord: &mut InMemoryCoordinator,
    shard: ShardId,
    worker_id: u64,
    acquire_t: u64,
    checkpoint_t: u64,
    op_id: u64,
    last_key: &[u8],
) {
    let lease = acquire_result(
        coord,
        now(acquire_t),
        test_tenant(),
        ShardKey::new(test_run(), shard),
        test_worker(worker_id),
    )
    .unwrap()
    .lease;
    let _ = coord
        .checkpoint(
            now(checkpoint_t),
            test_tenant(),
            &lease,
            &CursorUpdate::new(last_key),
            OpId::from_raw(op_id),
        )
        .unwrap();
}

/// Acquire `shard` and complete it with a controlled terminal cursor key.
fn complete_shard_with_key(
    coord: &mut InMemoryCoordinator,
    shard: ShardId,
    worker_id: u64,
    acquire_t: u64,
    complete_t: u64,
    op_id: u64,
    last_key: &[u8],
) {
    let lease = acquire_result(
        coord,
        now(acquire_t),
        test_tenant(),
        ShardKey::new(test_run(), shard),
        test_worker(worker_id),
    )
    .unwrap()
    .lease;
    let _ = coord
        .complete(
            now(complete_t),
            test_tenant(),
            &lease,
            &CursorUpdate::new(last_key),
            OpId::from_raw(op_id),
        )
        .unwrap();
}

/// Parameters for the acquire-checkpoint-park helper.
///
/// Bundles the logical timestamps, operation IDs, and cursor key needed
/// to drive a shard through acquire -> checkpoint -> park in a single
/// call to [`park_shard_after_checkpoint`].
struct ParkAfterCheckpointStep<'a> {
    worker_id: u64,
    acquire_t: u64,
    checkpoint_t: u64,
    checkpoint_op_id: u64,
    checkpoint_key: &'a [u8],
    park_t: u64,
    park_op_id: u64,
}

/// Drive a shard through acquire -> checkpoint -> park in one call.
///
/// Used by watermark tests that need a shard in Parked state with a known
/// cursor position.
fn park_shard_after_checkpoint(
    coord: &mut InMemoryCoordinator,
    shard: ShardId,
    step: ParkAfterCheckpointStep<'_>,
) {
    let lease = acquire_result(
        coord,
        now(step.acquire_t),
        test_tenant(),
        ShardKey::new(test_run(), shard),
        test_worker(step.worker_id),
    )
    .unwrap()
    .lease;
    let _ = coord
        .checkpoint(
            now(step.checkpoint_t),
            test_tenant(),
            &lease,
            &CursorUpdate::new(step.checkpoint_key),
            OpId::from_raw(step.checkpoint_op_id),
        )
        .unwrap();
    let _ = coord
        .park_shard(
            now(step.park_t),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(step.park_op_id),
        )
        .unwrap();
}

/// Build a split-replace topology and return children to drive watermark tests:
/// one child later completed, one parked, one left active.
fn coordinator_with_split_children_for_watermark()
-> (InMemoryCoordinator, ShardId, ShardId, ShardId) {
    let (mut coord, root_lease) = coordinator_with_run_and_lease();

    // Make the parent carry a small cursor key before split.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &root_lease,
            &CursorUpdate::new(b"b"),
            OpId::from_raw(10),
        )
        .unwrap();

    let spec_a = ShardSpec::with_range(b"a", b"m");
    let spec_b = ShardSpec::with_range(b"m", b"t");
    let spec_c = ShardSpec::with_range(b"t", b"z");
    let cursor_a = CursorUpdate::initial();
    let cursor_b = CursorUpdate::initial();
    let cursor_c = CursorUpdate::initial();
    let split_plan = SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(spec_a.as_ref(), cursor_a),
        SplitReplaceChild::new(spec_b.as_ref(), cursor_b),
        SplitReplaceChild::new(spec_c.as_ref(), cursor_c),
    ])
    .unwrap();
    let _ = coord
        .split_replace(
            now(5),
            test_tenant(),
            &root_lease,
            split_plan,
            OpId::from_raw(11),
        )
        .unwrap();

    let mut active_children = Vec::new();
    list_shards_for_run(&coord, now(6), ShardFilter::active(), &mut active_children);
    assert_eq!(active_children.len(), 3);

    let child_done = active_children
        .iter()
        .find(|s| s.key_range_start() == b"a")
        .unwrap()
        .shard();
    let child_parked = active_children
        .iter()
        .find(|s| s.key_range_start() == b"m")
        .unwrap()
        .shard();
    let child_active = active_children
        .iter()
        .find(|s| s.key_range_start() == b"t")
        .unwrap()
        .shard();

    (coord, child_done, child_parked, child_active)
}

/// After a 3-way split, completing one child, parking another, and
/// checkpointing the third must leave the watermark at the active child's
/// cursor key. Done, Split, and Parked shards are excluded.
#[test]
fn done_split_parked_excluded_from_watermark() {
    let (mut coord, child_done, child_parked, child_active) =
        coordinator_with_split_children_for_watermark();
    complete_shard_with_key(&mut coord, child_done, 2, 7, 8, 12, b"d");
    park_shard_after_checkpoint(
        &mut coord,
        child_parked,
        ParkAfterCheckpointStep {
            worker_id: 3,
            acquire_t: 9,
            checkpoint_t: 10,
            checkpoint_op_id: 13,
            checkpoint_key: b"n",
            park_t: 11,
            park_op_id: 14,
        },
    );
    checkpoint_shard_last_key(&mut coord, child_active, 4, 12, 13, 15, b"x");

    let progress = coord
        .get_run_progress(now(14), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.total(), 4);
    assert_eq!(progress.split(), 1);
    assert_eq!(progress.done(), 1);
    assert_eq!(progress.parked(), 1);
    assert_eq!(progress.active(), 1);
    assert_eq!(
        progress.watermark(),
        Some(b"x".as_slice()),
        "watermark must ignore Done/Split/Parked cursor keys",
    );
}

/// When every shard is terminal (no Active shards remain), the watermark
/// must be `None` regardless of cursor positions.
#[test]
fn all_shards_terminal_watermark_none() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // Checkpoint then complete the only shard.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(5),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"y"),
            OpId::from_raw(11),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(6), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.active(), 0, "no active shards remain");
    assert_eq!(
        progress.watermark(),
        None,
        "watermark must be None when zero active shards",
    );
}

/// The watermark tracks the *minimum* active cursor key and advances when
/// the lagging shard checkpoints forward.
#[test]
fn watermark_advances_when_min_shard_checkpoints() {
    // Setup: 2-shard run with ranges [a,m) and [m,z).
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    // Checkpoint shard 10 at "c" and shard 11 at "p".
    checkpoint_shard_last_key(&mut coord, ShardId::from_raw(10), 1, 3, 4, 10, b"c");
    checkpoint_shard_last_key(&mut coord, ShardId::from_raw(11), 2, 5, 6, 11, b"p");

    let progress = coord
        .get_run_progress(now(7), test_tenant(), test_run())
        .unwrap();
    assert_eq!(
        progress.watermark(),
        Some(b"c".as_slice()),
        "watermark should be min of 'c' and 'p'",
    );

    // Advance shard 10: "c" -> "k" (still within [a,m), still below "p").
    checkpoint_shard_last_key(&mut coord, ShardId::from_raw(10), 1, 104, 105, 12, b"k");

    let progress = coord
        .get_run_progress(now(106), test_tenant(), test_run())
        .unwrap();
    assert_eq!(
        progress.watermark(),
        Some(b"k".as_slice()),
        "watermark should advance to 'k' (min of 'k' and 'p')",
    );
}

/// With a single active shard, the watermark equals that shard's cursor key.
#[test]
fn single_active_shard_watermark_equals_its_key() {
    let (mut coord, lease) = coordinator_with_run_and_lease();

    // Checkpoint the only shard to "f".
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(5), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.active(), 1);
    assert_eq!(
        progress.watermark(),
        Some(b"f".as_slice()),
        "single active shard's key must be the watermark",
    );
}

/// Shards registered with a non-initial cursor (resume case) contribute
/// to the watermark immediately, without needing a checkpoint first.
#[test]
fn watermark_includes_shards_registered_with_non_initial_cursors() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    // Register two shards: one with a resume cursor, one with initial.
    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::with_last_key(b"d");
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    // Without any checkpoint, the resume cursor should contribute to watermark.
    let progress = coord
        .get_run_progress(now(3), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.active(), 2);
    assert_eq!(
        progress.watermark(),
        Some(b"d".as_slice()),
        "resume cursor from registration must be included in watermark",
    );
}

// -- Shard count limit tests for register_shards --
//
// register_shards is subject to the same per-tenant and global shard
// count limits as split operations. These tests verify that bulk
// registration rejects the entire batch when limits would be breached.

#[test]
fn register_shards_exceeds_per_tenant_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 3, 1_000_000);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let shard_entries: Vec<_> = (0..4)
        .map(|i| {
            let start = vec![b'a' + (i * 5) as u8];
            let end = vec![b'a' + (i * 5 + 4) as u8];
            (
                ShardId::from_raw(i),
                ShardSpec::with_range(start, end),
                CursorUpdate::initial(),
            )
        })
        .collect();
    let shards: Vec<InitialShardInput<'_>> = shard_entries
        .iter()
        .map(|(shard, spec, cursor)| InitialShardInput::new(*shard, spec.as_ref(), *cursor))
        .collect();

    let err = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::PerTenant,
                ..
            }
        ),
        "expected ShardLimitExceeded(PerTenant), got: {err:?}",
    );
}

#[test]
fn register_shards_exceeds_global_limit() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 1000, 3);

    // Seed 2 existing shards from a different tenant.
    let other = TenantId::from_bytes([0x02; 32]);
    let spec1 = ShardSpec::with_range(b"a", b"m");
    let sr1 = ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(90),
        spec1.as_ref(),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(sr1);
    let spec2 = ShardSpec::with_range(b"m", b"z");
    let sr2 = ShardRecord::new_active(
        other,
        RunId::from_raw(99),
        ShardId::from_raw(91),
        spec2.as_ref(),
        CursorSemantics::Completed,
        coord.slab_mut(),
    )
    .unwrap();
    coord.seed_shard(sr2);

    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];

    let err = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::ShardLimitExceeded {
                scope: ShardLimitScope::Global,
                ..
            }
        ),
        "expected ShardLimitExceeded(Global), got: {err:?}",
    );
}

#[test]
fn register_shards_within_limits_succeeds() {
    let mut coord = InMemoryCoordinator::with_limits(LEASE_DURATION, 10, 100);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];

    let result = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(result.is_executed());
}

// -- register_shards cursor preservation (regression guard) --
//
// Shards can be registered with a non-initial cursor (e.g., resuming a
// previous run). The coordinator must preserve the cursor as-is rather
// than resetting it to initial.

#[test]
fn register_shards_preserves_non_initial_cursors() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::with_last_key(b"f");
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    let key = ShardKey::new(test_run(), ShardId::from_raw(10));
    let result = acquire_result(&mut coord, now(3), test_tenant(), key, test_worker(1)).unwrap();
    assert_eq!(
        result.snapshot().cursor().last_key(),
        Some(b"f".as_slice()),
        "non-initial cursor must be preserved after register_shards",
    );
}

// -- Run terminal operation tests (complete_run / fail_run / cancel_run) ------
//
// All three terminal transitions share identical structure: happy path,
// wrong-status rejection, terminal irreversibility, and idempotent
// replay. A small dispatch enum + helper avoids repeating each scenario
// three times. `cancel_run_from_initializing` and `complete_run_not_found`
// remain individual tests because they have no parallel in other ops.

/// Creates a coordinator with a run in Active state (one shard registered).
///
/// Performs: `create_run` -> `register_shards`. Unlike
/// [`coordinator_with_run_and_lease`], this does **not** acquire a lease,
/// making it suitable for run-level operation tests (complete_run,
/// fail_run, cancel_run) that do not need a shard lease. Time advances
/// through t=1..2; callers should start at t=3.
fn active_run_coordinator() -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    coord
}

/// Discriminant for the three run-terminal operations so parameterized
/// tests can dispatch without repeating the match logic.
#[derive(Debug, Clone, Copy)]
enum TerminalOp {
    Complete,
    Fail,
    Cancel,
}

impl TerminalOp {
    fn expected_status(self) -> RunStatus {
        match self {
            Self::Complete => RunStatus::Done,
            Self::Fail => RunStatus::Failed,
            Self::Cancel => RunStatus::Cancelled,
        }
    }
}

/// Dispatch a terminal run operation by discriminant.
///
/// Centralizes the `match` so parameterized tests only need to pass
/// `TerminalOp` without knowing the underlying method signatures.
fn apply_terminal_op(
    coord: &mut InMemoryCoordinator,
    op: TerminalOp,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    op_id: OpId,
) -> Result<IdempotentOutcome<()>, RunTransitionError> {
    match op {
        TerminalOp::Complete => coord.complete_run(now, tenant, run, op_id),
        TerminalOp::Fail => coord.fail_run(now, tenant, run, op_id),
        TerminalOp::Cancel => coord.cancel_run(now, tenant, run, op_id),
    }
}

#[rstest]
#[case::complete(TerminalOp::Complete)]
#[case::fail(TerminalOp::Fail)]
#[case::cancel(TerminalOp::Cancel)]
fn terminal_op_happy_path(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let result = apply_terminal_op(
        &mut coord,
        op,
        now(3),
        test_tenant(),
        test_run(),
        OpId::from_raw(2),
    )
    .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), op.expected_status());
    assert_eq!(record.completed_at(), Some(now(3)));
}

#[rstest]
#[case::complete(TerminalOp::Complete, RunStatus::Done)]
#[case::fail(TerminalOp::Fail, RunStatus::Failed)]
fn terminal_op_wrong_status_initializing(#[case] op: TerminalOp, #[case] target: RunStatus) {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = apply_terminal_op(
        &mut coord,
        op,
        now(2),
        test_tenant(),
        test_run(),
        OpId::from_raw(1),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::WrongStatus {
                status: RunStatus::Initializing,
                target: t,
            } if t == target
        ),
        "expected WrongStatus(Initializing -> {target:?}), got: {err:?}",
    );
}

#[rstest]
#[case::complete_after_done(TerminalOp::Complete)]
#[case::fail_after_done(TerminalOp::Fail)]
#[case::cancel_after_done(TerminalOp::Cancel)]
fn terminal_op_rejected_when_already_terminal(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let _ = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(2))
        .unwrap();

    let err = apply_terminal_op(
        &mut coord,
        op,
        now(4),
        test_tenant(),
        test_run(),
        OpId::from_raw(3),
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal {
                status: RunStatus::Done
            }
        ),
        "expected RunTerminal(Done), got: {err:?}",
    );
}

#[rstest]
#[case::complete(TerminalOp::Complete)]
#[case::fail(TerminalOp::Fail)]
#[case::cancel(TerminalOp::Cancel)]
fn terminal_op_idempotent_replay(#[case] op: TerminalOp) {
    let mut coord = active_run_coordinator();
    let op_id = OpId::from_raw(2);
    let first =
        apply_terminal_op(&mut coord, op, now(3), test_tenant(), test_run(), op_id).unwrap();
    assert!(first.is_executed());

    let second =
        apply_terminal_op(&mut coord, op, now(4), test_tenant(), test_run(), op_id).unwrap();
    assert!(second.is_replay());
}

#[test]
fn cancel_run_from_initializing() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let result = coord
        .cancel_run(now(2), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap();
    assert!(result.is_executed());

    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Cancelled);
    assert_eq!(record.completed_at(), Some(now(2)));
}

#[test]
fn complete_run_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let err = coord
        .complete_run(now(1), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, RunTransitionError::RunNotFound));
}

// -- OpIdConflict across run operations ---------------------------------------
//
// Run-level operations share a single per-run op-log. An OpId used by
// register_shards cannot be reused by complete_run (different payload
// hash), even though they are different operation types.

#[test]
fn run_op_id_conflict_across_ops() {
    let mut coord = active_run_coordinator();
    // register_shards used op_id=1. Now complete_run with same op_id=1 but
    // different payload hash -> OpIdConflict.
    let err = coord
        .complete_run(now(3), test_tenant(), test_run(), OpId::from_raw(1))
        .unwrap_err();
    assert!(
        matches!(err, RunTransitionError::OpIdConflict(_)),
        "expected OpIdConflict when reusing register_shards op_id for complete_run, got: {err:?}",
    );
}

// -- unpark_shard tests -------------------------------------------------------
//
// unpark_shard is an admin operation that transitions Parked -> Active,
// bumps the fence epoch (invalidating any stale leases), clears the
// park_reason, and preserves the cursor. Tests cover: happy path,
// fence bump verification, cursor preservation, idempotent replay,
// not-parked rejection, not-found error, full park->unpark->reacquire
// workflow, and rejection when the owning run is terminal.

#[test]
fn unpark_shard_happy_path() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Park the shard.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Unpark.
    let result = coord
        .unpark_shard(now(5), test_tenant(), key, OpId::from_raw(11))
        .unwrap();
    assert!(result.is_executed());

    // Verify shard is Active again.
    let record = coord.shard_lookup(&test_tenant(), &key).unwrap();
    assert_eq!(record.status, ShardStatus::Active);
    assert!(record.park_reason.is_none());
    assert!(record.lease.is_none());
}

#[test]
fn unpark_shard_fence_epoch_bumped() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    let before_park = coord
        .shard_lookup(&test_tenant(), &key)
        .unwrap()
        .fence_epoch;

    // Park.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Unpark.
    let _ = coord
        .unpark_shard(now(5), test_tenant(), key, OpId::from_raw(11))
        .unwrap();

    let after_unpark = coord
        .shard_lookup(&test_tenant(), &key)
        .unwrap()
        .fence_epoch;
    assert!(
        after_unpark > before_park,
        "fence_epoch must increase after unpark: {before_park:?} vs {after_unpark:?}",
    );
}

#[test]
fn unpark_shard_cursor_preserved() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Checkpoint to set cursor.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();

    // Park.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(11),
        )
        .unwrap();

    // Unpark.
    let _ = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap();

    let record = coord.shard_lookup(&test_tenant(), &key).unwrap();
    assert_eq!(
        record.cursor.last_key(coord.slab()),
        Some(b"f".as_slice()),
        "cursor must be preserved through park->unpark",
    );
}

#[test]
fn unpark_shard_idempotent_replay() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    let op = OpId::from_raw(11);
    let first = coord.unpark_shard(now(5), test_tenant(), key, op).unwrap();
    assert!(first.is_executed());

    let second = coord.unpark_shard(now(6), test_tenant(), key, op).unwrap();
    assert!(second.is_replay());
}

#[test]
fn unpark_shard_not_parked() {
    let (mut coord, _lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Shard is Active, not Parked.
    let err = coord
        .unpark_shard(now(4), test_tenant(), key, OpId::from_raw(10))
        .unwrap_err();
    assert!(
        matches!(err, UnparkError::NotParked { .. }),
        "expected NotParked, got: {err:?}",
    );
}

#[test]
fn unpark_shard_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let key = ShardKey::new(test_run(), ShardId::from_raw(99));
    let err = coord
        .unpark_shard(now(1), test_tenant(), key, OpId::from_raw(1))
        .unwrap_err();
    assert!(matches!(err, UnparkError::ShardNotFound));
}

#[test]
fn unpark_then_reacquire_and_checkpoint() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Checkpoint -> Park -> Unpark -> Re-acquire -> Checkpoint works.
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"d"),
            OpId::from_raw(10),
        )
        .unwrap();
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(11),
        )
        .unwrap();
    let _ = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap();

    // Re-acquire with a new worker.
    let new_result =
        acquire_result(&mut coord, now(7), test_tenant(), key, test_worker(2)).unwrap();
    let new_lease = new_result.lease;
    assert_eq!(
        new_result.snapshot().cursor().last_key(),
        Some(b"d".as_slice()),
        "cursor must survive park->unpark->reacquire",
    );

    // Checkpoint from the resumed position.
    let cp = coord
        .checkpoint(
            now(8),
            test_tenant(),
            &new_lease,
            &CursorUpdate::new(b"g"),
            OpId::from_raw(13),
        )
        .unwrap();
    assert!(cp.is_executed());
}

/// Unparking a shard reintroduces its old cursor into the watermark pool.
///
/// Demonstrates that the watermark can move *backward* after unpark if the
/// unparked shard's cursor is behind the remaining active shards.
#[test]
fn unpark_shard_reintroduces_cursor_into_watermark() {
    // Setup: 2-shard run with ranges [a,m) and [m,z).
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    // Acquire shard 10, checkpoint at "c", keep the lease for parking.
    let lease10 = acquire_result(
        &mut coord,
        now(3),
        test_tenant(),
        ShardKey::new(test_run(), ShardId::from_raw(10)),
        test_worker(1),
    )
    .unwrap()
    .lease;
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease10,
            &CursorUpdate::new(b"c"),
            OpId::from_raw(10),
        )
        .unwrap();

    // Checkpoint shard 11 at "p".
    checkpoint_shard_last_key(&mut coord, ShardId::from_raw(11), 2, 5, 6, 11, b"p");

    let progress = coord
        .get_run_progress(now(7), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.watermark(), Some(b"c".as_slice()), "min of both");

    // Park shard 10 using the lease from the acquire above.
    let _ = coord
        .park_shard(
            now(8),
            test_tenant(),
            &lease10,
            ParkReason::TooManyErrors,
            OpId::from_raw(12),
        )
        .unwrap();

    let progress = coord
        .get_run_progress(now(9), test_tenant(), test_run())
        .unwrap();
    assert_eq!(
        progress.watermark(),
        Some(b"p".as_slice()),
        "only shard 11 active after park"
    );

    // Unpark shard 10 — its old cursor "c" re-enters the watermark pool.
    let key10 = ShardKey::new(test_run(), ShardId::from_raw(10));
    let _ = coord
        .unpark_shard(now(10), test_tenant(), key10, OpId::from_raw(13))
        .unwrap();

    let progress = coord
        .get_run_progress(now(11), test_tenant(), test_run())
        .unwrap();
    assert_eq!(
        progress.watermark(),
        Some(b"c".as_slice()),
        "shard 10 cursor re-enters, watermark moves backward"
    );
}

// -- unpark_shard run-status check tests -----------------------------------
//
// Unparking must be blocked when the owning run has reached a terminal
// state (Cancelled or Done). Reactivating a shard in a dead run would
// violate the run lifecycle contract.

#[rstest]
#[case::run_cancelled(TerminalOp::Cancel, RunStatus::Cancelled)]
#[case::run_done(TerminalOp::Complete, RunStatus::Done)]
fn unpark_shard_rejected_when_run_terminal(
    #[case] op: TerminalOp,
    #[case] expected_status: RunStatus,
) {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));

    // Park the shard.
    let _ = coord
        .park_shard(
            now(4),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    // Terminate the run.
    let _ = apply_terminal_op(
        &mut coord,
        op,
        now(5),
        test_tenant(),
        test_run(),
        OpId::from_raw(11),
    )
    .unwrap();

    // Attempt unpark -> should fail with RunTerminal.
    let err = coord
        .unpark_shard(now(6), test_tenant(), key, OpId::from_raw(12))
        .unwrap_err();
    assert!(
        matches!(
            err,
            UnparkError::RunTerminal { status } if status == expected_status
        ),
        "expected RunTerminal({expected_status:?}), got: {err:?}",
    );
}

// -- register_shards error path tests -----------------------------------------
//
// Covers register_shards edge cases: idempotent replay (same OpId +
// payload returns Replayed with identical shard IDs), OpIdConflict
// (same OpId + different shard list), wrong-status rejection (run
// already Active), not-found error, and staged-build rollback on
// allocation failure (no partial inserts).

#[test]
fn register_shards_idempotent_replay() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let op = OpId::from_raw(1);

    let first = coord
        .register_shards(now(2), test_tenant(), test_run(), &shards, op)
        .unwrap();
    assert!(first.is_executed());
    let first_ids = first.into_inner();

    let second = coord
        .register_shards(now(3), test_tenant(), test_run(), &shards, op)
        .unwrap();
    assert!(second.is_replay());
    assert_eq!(second.into_inner(), first_ids);
}

#[test]
fn register_shards_op_id_conflict() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec_a = ShardSpec::with_range(b"a", b"z");
    let cursor_a = CursorUpdate::initial();
    let shards_a = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec_a.as_ref(),
        cursor_a,
    )];
    let op = OpId::from_raw(1);
    let _ = coord
        .register_shards(now(2), test_tenant(), test_run(), &shards_a, op)
        .unwrap();

    // Same op_id, different payload (different shard IDs).
    let spec_b = ShardSpec::with_range(b"a", b"z");
    let cursor_b = CursorUpdate::initial();
    let shards_b = vec![InitialShardInput::new(
        ShardId::from_raw(20),
        spec_b.as_ref(),
        cursor_b,
    )];
    let err = coord
        .register_shards(now(3), test_tenant(), test_run(), &shards_b, op)
        .unwrap_err();
    assert!(
        matches!(err, RegisterShardsError::OpIdConflict(_)),
        "expected OpIdConflict, got: {err:?}",
    );
}

#[test]
fn register_shards_wrong_status_active() {
    let mut coord = active_run_coordinator();
    // Run is already Active.
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(20),
        spec.as_ref(),
        cursor,
    )];
    let err = coord
        .register_shards(
            now(3),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(99),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::WrongStatus {
                status: RunStatus::Active
            }
        ),
        "expected WrongStatus(Active), got: {err:?}",
    );
}

#[test]
fn register_shards_run_not_found() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let err = coord
        .register_shards(
            now(1),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(matches!(err, RegisterShardsError::RunNotFound));
}

#[test]
fn register_shards_resource_exhausted_returns_error_without_partial_inserts() {
    // Two shards with bounded ranges need 4 non-empty spec slots total.
    // With 16-byte minimum block size, that is 64 bytes. A 32-byte slab can
    // allocate at most one shard spec before surfacing
    // `RegisterShardsError::ResourceExhausted { resource: "shard_slab" }`.
    // The coordinator stages record builds, so this should roll back to zero
    // inserted shards instead of leaving a partially registered run.
    let mut runtime = CoordinatorRuntimeConfig::with_limits(LEASE_DURATION, 10, 10);
    runtime.slab_capacity = 32;
    let mut coord = InMemoryCoordinator::with_runtime_config(runtime);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];
    let err = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap_err();
    assert!(
        matches!(
            err,
            RegisterShardsError::ResourceExhausted {
                resource: "shard_slab"
            }
        ),
        "expected ResourceExhausted, got: {err:?}"
    );

    // Run must stay Initializing with no registered roots on failure.
    let run = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(run.status(), RunStatus::Initializing);
    assert!(run.root_shards().is_empty());

    // No shards should have been inserted.
    let mut summaries = Vec::new();
    list_shards_for_run(&coord, now(3), ShardFilter::all(), &mut summaries);
    assert!(summaries.is_empty(), "failed registration inserted shards");
    assert_eq!(
        coord.shard_count(),
        0,
        "failed registration changed shard count"
    );
}

// -- create_run_with_shards tests ---------------------------------------------
//
// Atomic create+register convenience method. Covers: fresh creation
// (run lands in Active immediately), idempotent retry with same config
// and OpId, and config mismatch detection on retry with different
// RunConfig.

#[test]
fn create_run_with_shards_fresh() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let result = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            short_lease_run_config(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(result.is_executed());
    let record = result.into_inner();
    assert_eq!(record.status(), RunStatus::Active);
}

#[test]
fn create_run_with_shards_retry_same_config() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let op = OpId::from_raw(1);

    // First call.
    let _ = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            short_lease_run_config(),
            &shards,
            op,
        )
        .unwrap();

    // Retry with same config and op_id -> replayed.
    let second = coord
        .create_run_with_shards(
            now(2),
            test_tenant(),
            test_run(),
            short_lease_run_config(),
            &shards,
            op,
        )
        .unwrap();
    assert!(second.is_replay());
}

#[test]
fn create_run_with_shards_config_mismatch() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];

    let _ = coord
        .create_run_with_shards(
            now(1),
            test_tenant(),
            test_run(),
            short_lease_run_config(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();

    // Retry with different config.
    let different_config = RunConfig::try_new(CursorSemantics::Completed, 60, Some(10)).unwrap();
    let err = coord
        .create_run_with_shards(
            now(2),
            test_tenant(),
            test_run(),
            different_config,
            &shards,
            OpId::from_raw(2),
        )
        .unwrap_err();
    assert!(
        matches!(err, CreateRunError::ConfigMismatch { .. }),
        "expected ConfigMismatch, got: {err:?}",
    );
}

// -- create_run duplicate rejection -------------------------------------------
//
// create_run is not idempotent -- calling it twice with the same RunId
// must return RunAlreadyExists, not silently succeed.

#[test]
fn create_run_duplicate_rejected() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();

    let err = coord
        .create_run(now(2), test_tenant(), test_run(), short_lease_run_config())
        .unwrap_err();
    assert!(
        matches!(err, CreateRunError::RunAlreadyExists { .. }),
        "duplicate create_run must return RunAlreadyExists, got: {err:?}"
    );
}

// -- Full run lifecycle end-to-end test ----------------------------------------
//
// Exercises the complete run lifecycle: create_run -> register_shards ->
// acquire -> checkpoint -> complete (per shard) -> verify progress ->
// complete_run. Verifies that all state transitions compose correctly
// and that run progress reflects shard completion accurately.

#[test]
fn full_run_lifecycle_create_register_process_complete() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);

    // Step 1: Create run.
    let _ = coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Initializing);

    // Step 2: Register two shards [a,m) and [m,z).
    let spec_10 = ShardSpec::with_range(b"a", b"m");
    let spec_11 = ShardSpec::with_range(b"m", b"z");
    let cursor_10 = CursorUpdate::initial();
    let cursor_11 = CursorUpdate::initial();
    let shards = vec![
        InitialShardInput::new(ShardId::from_raw(10), spec_10.as_ref(), cursor_10),
        InitialShardInput::new(ShardId::from_raw(11), spec_11.as_ref(), cursor_11),
    ];
    let reg_result = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    assert!(reg_result.is_executed());
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Active);
    assert_eq!(record.root_shards().len(), 2);

    // Step 3: Acquire + checkpoint + complete shard 10.
    let key_10 = ShardKey::new(test_run(), ShardId::from_raw(10));
    let lease_10 = acquire_result(&mut coord, now(3), test_tenant(), key_10, test_worker(1))
        .unwrap()
        .lease;
    let _ = coord
        .checkpoint(
            now(4),
            test_tenant(),
            &lease_10,
            &CursorUpdate::new(b"f"),
            OpId::from_raw(10),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(5),
            test_tenant(),
            &lease_10,
            &CursorUpdate::new(b"l"),
            OpId::from_raw(11),
        )
        .unwrap();

    // Step 4: Acquire + complete shard 11.
    let key_11 = ShardKey::new(test_run(), ShardId::from_raw(11));
    let lease_11 = acquire_result(&mut coord, now(6), test_tenant(), key_11, test_worker(2))
        .unwrap()
        .lease;
    let _ = coord
        .complete(
            now(7),
            test_tenant(),
            &lease_11,
            &CursorUpdate::new(b"y"),
            OpId::from_raw(12),
        )
        .unwrap();

    // Step 5: Verify progress -- all done.
    let progress = coord
        .get_run_progress(now(8), test_tenant(), test_run())
        .unwrap();
    assert_eq!(progress.total(), 2);
    assert_eq!(progress.done(), 2);
    assert_eq!(progress.active(), 0);
    assert!(progress.is_success());

    // Step 6: Complete the run.
    let run_result = coord
        .complete_run(now(9), test_tenant(), test_run(), OpId::from_raw(20))
        .unwrap();
    assert!(run_result.is_executed());
    let record = coord.get_run(test_tenant(), test_run()).unwrap();
    assert_eq!(record.status(), RunStatus::Done);
    assert_eq!(record.completed_at(), Some(now(9)));
}

// ============================================================================
// Property-based watermark tests
// ============================================================================
//
// Fuzz-generates arbitrary shard configurations (random statuses and cursor
// keys) and verifies three properties:
//
// 1. `watermark == min(key | status == Active && key.is_some())`
// 2. `watermark <= every Active cursor key` (lower bound)
// 3. `watermark == None` when no Active shard has a cursor key
//
// These properties are hard to violate with hand-picked cases but easy to
// violate when the implementation accidentally includes a terminal shard's
// cursor or uses the wrong comparison direction.

mod prop_progress_watermark {
    use super::*;
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;

    fn arb_shard_snapshot() -> impl Strategy<Value = (ShardStatus, Option<Vec<u8>>)> {
        let status = prop_oneof![
            Just(ShardStatus::Active),
            Just(ShardStatus::Done),
            Just(ShardStatus::Split),
            Just(ShardStatus::Parked),
        ];
        let key = proptest::option::of(proptest::collection::vec(0u8..=254u8, 1..16));
        (status, key)
    }

    fn arb_shard_snapshots() -> impl Strategy<Value = Vec<(ShardStatus, Option<Vec<u8>>)>> {
        proptest::collection::vec(arb_shard_snapshot(), 1..32)
    }

    proptest! {
        #![proptest_config(miri_proptest_config())]

        #[test]
        fn watermark_bounds_and_none_condition(
            snapshots in arb_shard_snapshots(),
        ) {
            let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
            let shard_ids: Vec<ShardId> = (0..snapshots.len())
                .map(|i| ShardId::from_raw((i as u64) + 1))
                .collect();
            coord.seed_run(test_tenant(), test_run(), shard_ids.clone(), LEASE_DURATION);

            for (shard_id, (status, key)) in shard_ids.into_iter().zip(snapshots.iter()) {
                let cursor = key
                    .as_ref()
                    .map_or_else(CursorUpdate::initial, |k| CursorUpdate::with_last_key(k));
                let park_reason = if *status == ShardStatus::Parked {
                    Some(ParkReason::TooManyErrors)
                } else {
                    None
                };
                // Split shards need non-empty spawned list.
                let spawned = if *status == ShardStatus::Split {
                    let mut s = gossip_stdx::InlineVec::new();
                    s.push(ShardId::from_raw(1u64 << 63));
                    s
                } else {
                    gossip_stdx::InlineVec::new()
                };
                let record = ShardRecord::from_raw_parts(
                    test_tenant(),
                    test_run(),
                    shard_id,
                    *status,
                    park_reason,
                    &ShardSpec::with_range(vec![0x00], vec![0xFF]),
                    cursor,
                    CursorSemantics::Completed,
                    None,
                    FenceEpoch::INITIAL,
                    None,
                    spawned,
                    RingBuffer::new(),
                    coord.slab_mut(),
                );
                coord.seed_shard(record);
            }

            let progress = coord
                .get_run_progress(now(10), test_tenant(), test_run())
                .unwrap();

            // Expected watermark: min of keys where status==Active && key.is_some().
            let expected_min: Option<&[u8]> = snapshots
                .iter()
                .filter(|(s, _)| *s == ShardStatus::Active)
                .filter_map(|(_, k)| k.as_deref())
                .min();

            prop_assert_eq!(
                progress.watermark(),
                expected_min,
                "watermark must equal the minimum active cursor key",
            );

            // Verify watermark <= all active keys (lower bound property).
            if let Some(actual) = progress.watermark() {
                for (status, key) in &snapshots {
                    if *status == ShardStatus::Active
                        && let Some(k) = key.as_deref()
                    {
                        prop_assert!(actual <= k);
                    }
                }
            }

            // Verify watermark ignores non-Active shards.
            let has_active_with_key = snapshots
                .iter()
                .any(|(s, k)| *s == ShardStatus::Active && k.is_some());
            if !has_active_with_key {
                prop_assert_eq!(
                    progress.watermark(),
                    None,
                    "watermark must be None when no active shard has a key",
                );
            }
        }
    }
}
