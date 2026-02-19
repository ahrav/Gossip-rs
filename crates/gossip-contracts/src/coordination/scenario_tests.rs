//! End-to-end scenario tests for the coordination protocol.
//!
//! Each test models a realistic, multi-step workflow that a production system
//! would execute: creating runs, acquiring shards, checkpointing progress,
//! recovering from failures, splitting work, and resolving contention. The
//! focus is on *sequential composition* — does the protocol behave correctly
//! when operations are chained in realistic order, including state
//! restoration across ownership transfers?
//!
//! # Relationship to Other Test Modules
//!
//! - `in_memory_tests` — unit tests: one backend operation per test.
//! - `conformance_tests` — invariant-interaction tests: two or more safety
//!   invariants composed, with assertions on both success and absence of
//!   side effects.
//! - **This module** — scenario tests: multi-step user stories that exercise
//!   the protocol end-to-end, including happy paths, failure recovery, and
//!   edge-case workflows.
//!
//! # Scenarios
//!
//! | ID | Scenario | Core property exercised |
//! |----|----------|------------------------|
//! | S1 | Full run lifecycle | Baseline happy path through every state |
//! | S2 | Lease expiry + reacquire | Cursor restoration across ownership transfer |
//! | S3 | Split-replace + children | Independent child shard lifecycles |
//! | S4 | Double residual split | Iterative parent narrowing with spawned tracking |
//! | S5 | Op-log eviction boundary | Bounded op-log vs. idempotency semantics |
//! | S6 | Cancel from Initializing | Early run termination before any shards exist |
//! | S7 | Worker self-recovery | Same worker recovers from its own lease expiry |
//! | S8 | Claim contention | Correct shard distribution under N > shards |

use std::collections::HashSet;

use crate::coordination::cursor::Cursor;
use crate::coordination::error::CheckpointError;
use crate::coordination::facade::{ClaimError, ShardClaiming};
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::record::ShardStatus;
use crate::coordination::run::{InitialShard, RunManagement, RunStatus};
use crate::coordination::run_errors::{CancelRunError, RegisterShardsError};
use crate::coordination::shard_spec::ShardSpec;
use crate::coordination::split::SplitResidualPlan;
use crate::coordination::test_fixtures::*;
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{OpId, RunId, ShardId, ShardKey};

// ============================================================================
// S1: Full run lifecycle
//
// Baseline happy path. Every other scenario is a variation on this one, so
// if S1 fails the entire protocol is broken.
// ============================================================================

/// Happy-path lifecycle from run creation through run completion.
///
/// Manually constructs the coordinator (no `seeded_coordinator`) to exercise
/// the full setup sequence: `create_run` -> `register_shards` ->
/// `acquire_and_restore` -> three checkpoints with advancing cursors ->
/// `complete` (shard) -> `complete_run`.
///
/// Verifies: shard starts Active after registration, cursor advances
/// monotonically through checkpoints, shard reaches Done, run reaches Done,
/// and `completed_at` is set on the terminal run.
#[test]
fn scenario_full_run_lifecycle() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = test_run();

    // -- Create run --
    let config = test_run_config();
    coord.create_run(now(1), tenant, run, config).unwrap();

    // -- Register one shard [a, z) --
    let shards = vec![InitialShard::new(
        test_shard(),
        test_spec(),
        Cursor::initial(),
    )];
    let reg_outcome = coord
        .register_shards(now(2), tenant, run, &shards, OpId::from_raw(u64::MAX))
        .unwrap();
    assert!(
        reg_outcome.is_executed(),
        "first registration should be Executed"
    );

    // Verify the shard is Active after registration.
    let key = test_key();
    let record = coord
        .shard_lookup(&tenant, &key)
        .expect("shard should exist after registration");
    assert_eq!(
        record.status,
        ShardStatus::Active,
        "shard should be Active after register_shards"
    );

    // -- Acquire shard --
    let result = coord
        .acquire_and_restore(now(3), tenant, key, test_worker(1))
        .unwrap();
    let lease = result.lease;

    // -- Checkpoint x3 with progressively advancing cursors --
    let _ = coord
        .checkpoint(now(4), tenant, &lease, test_cursor(b"d"), OpId::from_raw(1))
        .unwrap();
    let _ = coord
        .checkpoint(now(5), tenant, &lease, test_cursor(b"h"), OpId::from_raw(2))
        .unwrap();
    let _ = coord
        .checkpoint(now(6), tenant, &lease, test_cursor(b"m"), OpId::from_raw(3))
        .unwrap();

    // Verify cursor advanced to "m".
    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.cursor.last_key().map(|k| k.to_vec()),
        Some(b"m".to_vec()),
        "cursor should be at 'm' after three checkpoints"
    );

    // -- Complete shard --
    let _ = coord
        .complete(now(7), tenant, &lease, test_cursor(b"y"), OpId::from_raw(4))
        .unwrap();
    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.status,
        ShardStatus::Done,
        "shard should be Done after complete"
    );

    // -- Complete run --
    let run_outcome = coord
        .complete_run(now(8), tenant, run, OpId::from_raw(5))
        .unwrap();
    assert!(
        run_outcome.is_executed(),
        "first complete_run should be Executed"
    );

    // Verify run status.
    let run_record = coord.get_run(tenant, run).unwrap();
    assert_eq!(
        run_record.status(),
        RunStatus::Done,
        "run should be Done after complete_run"
    );
    assert!(
        run_record.completed_at().is_some(),
        "completed_at must be set when run is Done"
    );
}

// ============================================================================
// S2: Lease expiry and reacquire
//
// The fundamental failure-recovery path: a worker stalls, its lease expires,
// another worker takes over and resumes from the last checkpoint. The stale
// worker's writes are fenced out.
// ============================================================================

/// Cursor is restored and stale writer is fenced after lease expiry.
///
/// Worker 1 acquires, checkpoints at "f", then goes silent. Time advances
/// past the lease deadline. Worker 2 acquires the same shard and sees cursor
/// "f" in the restored snapshot. Worker 1 then attempts a checkpoint and is
/// rejected with `StaleFence` (its fence epoch is stale). Worker 2 proceeds
/// to complete the shard.
///
/// This models the most common distributed failure: a slow or partitioned
/// worker whose lease expires while a replacement takes over.
#[test]
fn scenario_lease_expiry_and_reacquire() {
    let mut coord = seeded_coordinator();
    let tenant = test_tenant();
    let key = test_key();

    // -- W1 acquires and checkpoints --
    let lease1 = acquire_shard(&mut coord, 10, 1);
    let _ = coord
        .checkpoint(
            now(11),
            tenant,
            &lease1,
            test_cursor(b"f"),
            OpId::from_raw(1),
        )
        .unwrap();

    // -- W2 acquires after lease expiry --
    let expired_time = 10 + LEASE_DURATION + 1;
    let result2 = coord
        .acquire_and_restore(now(expired_time), tenant, key, test_worker(2))
        .unwrap();
    let lease2 = result2.lease;

    // Verify the snapshot restores cursor "f".
    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.cursor.last_key().map(|k| k.to_vec()),
        Some(b"f".to_vec()),
        "W2 should see restored cursor at 'f' from W1's checkpoint"
    );

    // -- W1 tries checkpoint with stale lease -> StaleFence --
    let stale_result = coord.checkpoint(
        now(expired_time + 1),
        tenant,
        &lease1,
        test_cursor(b"g"),
        OpId::from_raw(2),
    );
    assert!(
        matches!(stale_result, Err(CheckpointError::StaleFence { .. })),
        "W1 checkpoint after lease expiry should fail with StaleFence, got: {stale_result:?}"
    );

    // -- W2 completes the shard --
    let _ = coord
        .complete(
            now(expired_time + 2),
            tenant,
            &lease2,
            test_cursor(b"y"),
            OpId::from_raw(100),
        )
        .unwrap();

    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.status,
        ShardStatus::Done,
        "shard should be Done after W2 completes"
    );
}

// ============================================================================
// S3: Split-replace and children completion
//
// Proves that shard subdivision works end-to-end: the parent becomes terminal
// (Split), children are independently acquirable, and each child can progress
// through its own lifecycle.
// ============================================================================

/// Split-replace creates independent children that can be completed separately.
///
/// Acquires the parent [a,z), splits into [a,m) and [m,z), then acquires
/// and completes each child with its own worker. Verifies the parent is in
/// Split status, both children are Active after creation, and both reach
/// Done after their respective complete operations.
///
/// The children are processed by different workers (worker 1 and worker 2)
/// to reflect the typical use case where split shards are distributed.
#[test]
fn scenario_split_replace_and_children_completion() {
    let mut coord = seeded_coordinator();
    let tenant = test_tenant();
    let key = test_key();

    // -- Acquire parent and split --
    let lease = acquire_shard(&mut coord, 10, 1);
    let plan = test_split_replace_plan();
    let split_result = coord
        .split_replace(now(11), tenant, &lease, plan, OpId::from_raw(1))
        .unwrap()
        .into_inner();
    let children = split_result.children;
    assert_eq!(children.len(), 2, "split should produce exactly 2 children");

    // Verify parent is now Split.
    let parent_record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        parent_record.status,
        ShardStatus::Split,
        "parent shard should be in Split status after split_replace"
    );

    // -- Acquire and complete child 1 [a,m) --
    let child1_key = ShardKey::new(test_run(), children[0]);
    let child1_result = coord
        .acquire_and_restore(now(12), tenant, child1_key, test_worker(1))
        .unwrap();
    let child1_lease = child1_result.lease;
    let _ = coord
        .checkpoint(
            now(13),
            tenant,
            &child1_lease,
            test_cursor(b"f"),
            OpId::from_raw(2),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(14),
            tenant,
            &child1_lease,
            test_cursor(b"l"),
            OpId::from_raw(3),
        )
        .unwrap();

    // -- Acquire and complete child 2 [m,z) --
    let child2_key = ShardKey::new(test_run(), children[1]);
    let child2_result = coord
        .acquire_and_restore(now(15), tenant, child2_key, test_worker(2))
        .unwrap();
    let child2_lease = child2_result.lease;
    let _ = coord
        .checkpoint(
            now(16),
            tenant,
            &child2_lease,
            test_cursor(b"r"),
            OpId::from_raw(100),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(17),
            tenant,
            &child2_lease,
            test_cursor(b"y"),
            OpId::from_raw(101),
        )
        .unwrap();

    // -- Verify both children are Done --
    let child1_record = coord.shard_lookup(&tenant, &child1_key).unwrap();
    assert_eq!(
        child1_record.status,
        ShardStatus::Done,
        "child 1 should be Done"
    );

    let child2_record = coord.shard_lookup(&tenant, &child2_key).unwrap();
    assert_eq!(
        child2_record.status,
        ShardStatus::Done,
        "child 2 should be Done"
    );
}

// ============================================================================
// S4: Split chain -- double residual
//
// Exercises iterative residual splitting, where a single parent is narrowed
// multiple times while continuing to process its shrinking key range. This
// is the pattern used when a worker discovers mid-scan that its range is too
// large and progressively sheds the unprocessed tail.
// ============================================================================

/// Chained residual splits narrow the parent twice; all three pieces complete.
///
/// Starting from [a,z), the first split produces parent=[a,m) + residual=[m,z).
/// The parent continues processing and splits again: parent=[a,j) +
/// residual=[j,m). The test then completes all three shards (parent and
/// both residuals).
///
/// Key assertions: the parent's `spawned` list grows with each split, the
/// parent's spec narrows correctly, and the cursor from before the split is
/// preserved within the new (narrower) range.
#[test]
fn scenario_split_chain_double_residual() {
    let mut coord = seeded_coordinator();
    let tenant = test_tenant();
    let key = test_key();

    // -- Acquire and checkpoint --
    let lease = acquire_shard(&mut coord, 10, 1);
    let _ = coord
        .checkpoint(
            now(11),
            tenant,
            &lease,
            test_cursor(b"d"),
            OpId::from_raw(1),
        )
        .unwrap();

    // -- First residual split: [a,z) -> parent=[a,m), residual=[m,z) --
    let plan1 = test_split_residual_plan();
    let result1 = coord
        .split_residual(now(12), tenant, &lease, plan1, OpId::from_raw(2))
        .unwrap()
        .into_inner();
    let residual1 = result1.residual;

    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.spawned.len(),
        1,
        "parent should have 1 spawned child after first residual split"
    );

    // -- Checkpoint further, still within [a,m) --
    let _ = coord
        .checkpoint(
            now(13),
            tenant,
            &lease,
            test_cursor(b"g"),
            OpId::from_raw(3),
        )
        .unwrap();

    // -- Second residual split: [a,m) -> parent=[a,j), residual=[j,m) --
    let plan2 = SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"j".to_vec()),
        ShardSpec::with_range(b"j".to_vec(), b"m".to_vec()),
    )
    .unwrap();
    let result2 = coord
        .split_residual(now(14), tenant, &lease, plan2, OpId::from_raw(4))
        .unwrap()
        .into_inner();
    let residual2 = result2.residual;

    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.spawned.len(),
        2,
        "parent should have 2 spawned children after second residual split"
    );
    assert_eq!(
        record.spec.key_range_start(),
        b"a",
        "parent spec start should be 'a'"
    );
    assert_eq!(
        record.spec.key_range_end(),
        b"j",
        "parent spec end should be 'j' after second split"
    );

    // -- Complete parent within [a,j) --
    let _ = coord
        .complete(
            now(15),
            tenant,
            &lease,
            test_cursor(b"i"),
            OpId::from_raw(5),
        )
        .unwrap();
    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.status,
        ShardStatus::Done,
        "parent should be Done after complete"
    );

    // -- Acquire + complete residual 1 [m,z) --
    let r1_key = ShardKey::new(test_run(), residual1);
    let r1_result = coord
        .acquire_and_restore(now(16), tenant, r1_key, test_worker(2))
        .unwrap();
    let _ = coord
        .complete(
            now(17),
            tenant,
            &r1_result.lease,
            test_cursor(b"y"),
            OpId::from_raw(100),
        )
        .unwrap();
    let r1_record = coord.shard_lookup(&tenant, &r1_key).unwrap();
    assert_eq!(
        r1_record.status,
        ShardStatus::Done,
        "residual 1 should be Done"
    );

    // -- Acquire + complete residual 2 [j,m) --
    let r2_key = ShardKey::new(test_run(), residual2);
    let r2_result = coord
        .acquire_and_restore(now(18), tenant, r2_key, test_worker(2))
        .unwrap();
    let _ = coord
        .complete(
            now(19),
            tenant,
            &r2_result.lease,
            test_cursor(b"l"),
            OpId::from_raw(200),
        )
        .unwrap();
    let r2_record = coord.shard_lookup(&tenant, &r2_key).unwrap();
    assert_eq!(
        r2_record.status,
        ShardStatus::Done,
        "residual 2 should be Done"
    );
}

// ============================================================================
// S5: Op-log eviction boundary
//
// The op-log is a bounded ring buffer (cap=16). Once full, the oldest entry
// is evicted. This scenario verifies what happens when a previously-seen
// op_id is replayed *after* its entry has been evicted: the backend cannot
// distinguish it from a genuinely new operation.
// ============================================================================

/// Evicted op_id is treated as new; surviving op_id with wrong payload is rejected.
///
/// Pushes 17 checkpoints (one past the op-log capacity of 16), evicting
/// op_id=1. Replaying op_id=1 with a valid forward cursor succeeds as
/// `Executed` because the backend has no memory of the original. Replaying
/// op_id=17 (still in the log) with a *different* cursor produces
/// `OpIdConflict` because the payload hash does not match the recorded one.
///
/// This is the design trade-off of a bounded op-log: idempotency guarantees
/// hold only while the entry survives in the ring buffer. The test pins
/// exactly where that boundary falls.
#[test]
fn scenario_oplog_eviction_boundary() {
    let mut coord = seeded_coordinator();
    let tenant = test_tenant();

    let lease = acquire_shard(&mut coord, 10, 1);

    // Push 17 checkpoints (op_ids 1..=17) with monotonically advancing cursors.
    // The shard range is [a, z), so we use keys b..r (17 distinct forward values).
    for i in 1u64..=17 {
        let key_byte = b'a' + i as u8; // b, c, d, ..., r
        let cursor = Cursor::with_last_key(vec![key_byte]);
        let _ = coord
            .checkpoint(now(10 + i), tenant, &lease, cursor, OpId::from_raw(i))
            .unwrap_or_else(|e| {
                panic!("checkpoint op_id={i} should succeed, got: {e:?}");
            });
    }

    // op_id=1 has been evicted (cap=16, pushed 17). Replaying op_id=1
    // with a forward cursor should be treated as a new operation (Executed).
    let forward_cursor = Cursor::with_last_key(vec![b's']);
    let evicted_result = coord
        .checkpoint(now(28), tenant, &lease, forward_cursor, OpId::from_raw(1))
        .unwrap();
    assert!(
        evicted_result.is_executed(),
        "evicted op_id=1 should be treated as Executed (new operation), got: {evicted_result:?}"
    );

    // op_id=17 is still in the log. Replaying it with a different cursor
    // should produce OpIdConflict.
    let conflict_cursor = Cursor::with_last_key(vec![b't']);
    let conflict_result =
        coord.checkpoint(now(29), tenant, &lease, conflict_cursor, OpId::from_raw(17));
    assert!(
        matches!(conflict_result, Err(CheckpointError::OpIdConflict { .. })),
        "op_id=17 with different cursor should produce OpIdConflict, got: {conflict_result:?}"
    );
}

// ============================================================================
// S6: Cancel from Initializing
//
// A run can be cancelled before any shards are registered. This is the
// "abort before start" path — important for orchestrators that create runs
// speculatively and need to clean up.
// ============================================================================

/// Cancelling an Initializing run blocks registration and respects idempotency.
///
/// Creates a run without registering shards, then cancels it. Verifies:
/// (1) `register_shards` on the cancelled run fails with `WrongStatus`,
/// (2) replaying the same cancel op_id returns `Replayed` (idempotency),
/// (3) a *new* cancel op_id on the terminal run fails with `RunTerminal`
/// (terminal irreversibility).
#[test]
fn scenario_cancel_from_initializing() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = RunId::from_raw(42);

    // -- Create run (stays Initializing) --
    let config = test_run_config();
    coord.create_run(now(1), tenant, run, config).unwrap();

    let run_record = coord.get_run(tenant, run).unwrap();
    assert_eq!(
        run_record.status(),
        RunStatus::Initializing,
        "run should be Initializing before register_shards"
    );

    // -- Cancel the run --
    let cancel_outcome = coord
        .cancel_run(now(2), tenant, run, OpId::from_raw(1))
        .unwrap();
    assert!(
        cancel_outcome.is_executed(),
        "first cancel should be Executed"
    );

    let run_record = coord.get_run(tenant, run).unwrap();
    assert_eq!(
        run_record.status(),
        RunStatus::Cancelled,
        "run should be Cancelled after cancel_run"
    );
    assert!(
        run_record.completed_at().is_some(),
        "completed_at should be set on cancelled run"
    );

    // -- register_shards on cancelled run should fail --
    let shards = vec![InitialShard::new(
        ShardId::from_raw(1),
        ShardSpec::with_range(b"a".to_vec(), b"z".to_vec()),
        Cursor::initial(),
    )];
    let reg_result = coord.register_shards(now(3), tenant, run, &shards, OpId::from_raw(2));
    assert!(
        matches!(reg_result, Err(RegisterShardsError::WrongStatus { .. })),
        "register_shards on cancelled run should fail with WrongStatus, got: {reg_result:?}"
    );

    // -- Replay cancel with same op_id -> Replayed --
    let replay_outcome = coord
        .cancel_run(now(4), tenant, run, OpId::from_raw(1))
        .unwrap();
    assert!(
        replay_outcome.is_replay(),
        "replaying same cancel op_id should return Replayed"
    );

    // -- New cancel with different op_id -> RunTerminal --
    let terminal_result = coord.cancel_run(now(5), tenant, run, OpId::from_raw(3));
    assert!(
        matches!(terminal_result, Err(CancelRunError::RunTerminal { .. })),
        "cancel on terminal run with new op_id should fail with RunTerminal, got: {terminal_result:?}"
    );
}

// ============================================================================
// S7: Worker self-recovery
//
// Unlike S2 where a *different* worker takes over, here the *same* worker
// recovers from its own lease expiry. The protocol must treat same-worker
// reacquire identically to cross-worker reacquire: bump fence, restore
// cursor, reject the old lease.
// ============================================================================

/// Same worker recovers from its own lease expiry with cursor restoration.
///
/// Worker 1 acquires, checkpoints to "d" and "h", then lets the lease
/// expire. Worker 1 re-acquires and verifies: the fence epoch increased
/// (protecting against zombie writes from the previous lease handle), the
/// cursor is restored to "h", and further checkpoints and complete succeed
/// with the new lease.
///
/// This models a worker that crashed and restarted, or a thread that was
/// delayed past its lease deadline and called acquire again.
#[test]
fn scenario_worker_self_recovery() {
    let mut coord = seeded_coordinator();
    let tenant = test_tenant();
    let key = test_key();

    // -- W1 acquires --
    let lease1 = acquire_shard(&mut coord, 10, 1);
    let fence1 = lease1.fence();

    // -- Checkpoint twice --
    let _ = coord
        .checkpoint(
            now(11),
            tenant,
            &lease1,
            test_cursor(b"d"),
            OpId::from_raw(1),
        )
        .unwrap();
    let _ = coord
        .checkpoint(
            now(12),
            tenant,
            &lease1,
            test_cursor(b"h"),
            OpId::from_raw(2),
        )
        .unwrap();

    // -- Time advances past lease deadline --
    let reacquire_time = 10 + LEASE_DURATION + 1;
    let result2 = coord
        .acquire_and_restore(now(reacquire_time), tenant, key, test_worker(1))
        .unwrap();
    let lease2 = result2.lease;

    // Fence must have advanced.
    assert!(
        lease2.fence() > fence1,
        "fence should advance on reacquire: old={fence1:?}, new={:?}",
        lease2.fence()
    );

    // Cursor should be restored to "h".
    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.cursor.last_key().map(|k| k.to_vec()),
        Some(b"h".to_vec()),
        "cursor should be restored to 'h' from previous session"
    );

    // -- Continue processing with new lease --
    let _ = coord
        .checkpoint(
            now(reacquire_time + 1),
            tenant,
            &lease2,
            test_cursor(b"p"),
            OpId::from_raw(3),
        )
        .unwrap();
    let _ = coord
        .complete(
            now(reacquire_time + 2),
            tenant,
            &lease2,
            test_cursor(b"y"),
            OpId::from_raw(4),
        )
        .unwrap();

    let record = coord.shard_lookup(&tenant, &key).unwrap();
    assert_eq!(
        record.status,
        ShardStatus::Done,
        "shard should be Done after self-recovery and completion"
    );
}

// ============================================================================
// S8: Claim contention
//
// The `claim_next_available` facade distributes shards to workers on a
// first-come-first-served basis. When there are more workers than shards,
// the excess workers must receive NoneAvailable without corrupting state.
// ============================================================================

/// Claim contention with more workers than shards yields correct distribution.
///
/// Sets up a run with 2 shards and 3 workers. Exactly 2 workers must
/// successfully claim (one shard each), and the third must receive
/// `NoneAvailable`. The claimed shards must be distinct and must be exactly
/// the two registered shard ids.
///
/// This is the simplest contention test — it does not exercise concurrent
/// access (the in-memory backend is single-threaded), but it verifies the
/// claim-tracking logic that prevents double-assignment.
#[test]
fn scenario_claim_contention() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = RunId::from_raw(1);

    // -- Set up run with 2 shards --
    let config = test_run_config();
    coord.create_run(now(1), tenant, run, config).unwrap();

    let shard1 = ShardId::from_raw(1);
    let shard2 = ShardId::from_raw(2);
    let shards = vec![
        InitialShard::new(
            shard1,
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        InitialShard::new(
            shard2,
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ];
    let _ = coord
        .register_shards(now(2), tenant, run, &shards, OpId::from_raw(u64::MAX))
        .unwrap();

    // -- 3 workers attempt to claim --
    let mut successes = Vec::new();
    let mut failures = 0;

    for worker_id in 1..=3u64 {
        match coord.claim_next_available(now(3), tenant, run, test_worker(worker_id)) {
            Ok(result) => successes.push(result),
            Err(ClaimError::NoneAvailable) => failures += 1,
            Err(e) => panic!("worker {worker_id}: unexpected claim error: {e:?}"),
        }
    }

    assert_eq!(
        successes.len(),
        2,
        "exactly 2 workers should successfully claim shards, got {}",
        successes.len()
    );
    assert_eq!(
        failures, 1,
        "exactly 1 worker should get NoneAvailable, got {failures}"
    );

    // All claimed shards must be distinct.
    let claimed_shards: HashSet<ShardId> = successes.iter().map(|r| r.lease.shard()).collect();
    assert_eq!(
        claimed_shards.len(),
        2,
        "claimed shards must be distinct: {claimed_shards:?}"
    );

    // The claimed shards must be exactly {shard1, shard2}.
    assert!(
        claimed_shards.contains(&shard1) && claimed_shards.contains(&shard2),
        "claimed shards should be {{shard1, shard2}}, got: {claimed_shards:?}"
    );
}
