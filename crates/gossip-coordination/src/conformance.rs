//! Backend-agnostic coordination conformance harness.
//!
//! This module lifts the coordination conformance suite out of the
//! in-memory backend test module so any [`SimulationBackend`]
//! implementation can execute the same protocol checks.
//!
//! The harness stays intentionally strict about the surface it uses:
//! shard-level mutations and run-level mutations go through the protocol
//! traits ([`CoordinationBackend`](crate::traits::CoordinationBackend) and
//! [`RunManagement`](crate::run::RunManagement)), while shard-level
//! observations go through
//! [`SimIntrospection`](crate::sim::SimIntrospection) and run-level
//! observations go through
//! [`RunManagement::get_run`](crate::run::RunManagement::get_run).
//! That keeps the suite backend-agnostic and avoids reaching into
//! allocator-specific internals such as `ByteSlab`.

use crate::error::{CheckpointError, IdempotentOutcome};
use crate::lease::Lease;
use crate::record::{ParkReason, ShardRecord, ShardStatus};
use crate::run::RunStatus;
use crate::run_errors::{RunTransitionError, UnparkError};
use crate::sim::SimulationBackend;
use crate::test_fixtures::{
    LEASE_DURATION, acquire_shard, checkpoint_ok, complete_ok, now, park_ok, test_cursor, test_key,
    test_run, test_run_config, test_shard, test_split_replace_plan, test_split_residual_plan,
    test_tenant, test_worker,
};
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
use gossip_contracts::identity::{OpId, RunId, ShardId, ShardKey};

/// Assert that `complete_run`, `fail_run`, and `cancel_run` all reject
/// with `RunTerminal` on a run that has already reached `expected_status`.
///
/// Uses timestamps 13–15 and OpIds 101–103 to avoid collisions with the
/// setup operations in each calling block.
fn assert_all_run_transitions_rejected<B: SimulationBackend>(
    coord: &mut B,
    expected_status: RunStatus,
) {
    let err = coord
        .complete_run(now(13), test_tenant(), test_run(), OpId::from_raw(101))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "complete_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );

    let err = coord
        .fail_run(now(14), test_tenant(), test_run(), OpId::from_raw(102))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "fail_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );

    let err = coord
        .cancel_run(now(15), test_tenant(), test_run(), OpId::from_raw(103))
        .unwrap_err();
    assert!(
        matches!(
            err,
            RunTransitionError::RunTerminal { status } if status == expected_status
        ),
        "cancel_run on {expected_status:?} run must return RunTerminal, got: {err:?}"
    );
}

/// Run the coordination conformance suite against a simulation backend.
///
/// The factory must return a fresh seeded backend for each case. Most cases
/// use [`CursorSemantics::Completed`]; the dispatched-routing case requests
/// [`CursorSemantics::Dispatched`] explicitly.
pub fn run_coordination_conformance<B, F>(factory: F)
where
    B: SimulationBackend,
    F: Fn(CursorSemantics) -> B,
{
    // =====================================================================
    // Group A: Cross-Cutting Invariant Interactions
    // =====================================================================

    {
        eprintln!("  conformance: fence_monotonicity_across_full_lifecycle");
        let mut coord = factory(CursorSemantics::Completed);

        let lease1 = acquire_shard(&mut coord, 10, 1);
        let f1 = lease1.fence();

        checkpoint_ok(&mut coord, 11, &lease1, b"d", 1);

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.fence_epoch, f1, "checkpoint must not change fence");
        assert_eq!(rec.status, ShardStatus::Active);

        let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 2);
        let f2 = lease2.fence();
        assert!(f2 > f1, "re-acquire fence must exceed worker 1's fence");

        checkpoint_ok(&mut coord, LEASE_DURATION + 12, &lease2, b"p", 3);

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.fence_epoch, f2, "checkpoint must not change fence");

        complete_ok(&mut coord, LEASE_DURATION + 13, &lease2, b"y", 4);

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.fence_epoch, f2, "complete must not change fence");
        assert_eq!(rec.status, ShardStatus::Done);
    }

    {
        eprintln!("  conformance: cursor_monotonicity_combined_with_split_residual");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);

        checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

        let plan = test_split_residual_plan();
        let result = coord
            .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
            .unwrap();
        assert!(result.is_executed(), "split_residual must be Executed");

        {
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert_eq!(coord.cursor_last_key(rec), Some(b"d".as_slice()));
            let (start, end) = coord.spec_bounds(rec);
            assert_eq!(start, b"a");
            assert_eq!(end, b"m");
        }

        let ck_ok = coord.checkpoint(
            now(13),
            test_tenant(),
            &lease,
            &test_cursor(b"f"),
            OpId::from_raw(3),
        );
        assert!(ck_ok.is_ok(), "checkpoint at 'f' must succeed within [a,m)");

        let ck_err = coord.checkpoint(
            now(14),
            test_tenant(),
            &lease,
            &test_cursor(b"n"),
            OpId::from_raw(4),
        );
        assert!(
            matches!(ck_err, Err(CheckpointError::CursorOutOfBounds(_))),
            "checkpoint at 'n' must fail with CursorOutOfBounds, got: {ck_err:?}"
        );
    }

    {
        eprintln!("  conformance: idempotency_before_terminal_state_rejection");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);

        checkpoint_ok(&mut coord, 11, &lease, b"d", 1);
        let complete_cursor = test_cursor(b"m");
        let complete_op = OpId::from_raw(2);
        let outcome = coord
            .complete(
                now(12),
                test_tenant(),
                &lease,
                &complete_cursor,
                complete_op,
            )
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time complete must be Executed"
        );

        let replay = coord.complete(
            now(13),
            test_tenant(),
            &lease,
            &complete_cursor,
            complete_op,
        );
        assert!(
            matches!(replay, Ok(IdempotentOutcome::Replayed(()))),
            "replay on terminal shard must return Replayed, got: {replay:?}"
        );

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(
            rec.status,
            ShardStatus::Done,
            "replay must not change terminal status"
        );
        assert_eq!(
            coord.cursor_last_key(rec),
            Some(b"m".as_slice()),
            "replay must not mutate cursor"
        );
    }

    {
        eprintln!("  conformance: split_residual_preserved_through_park_unpark");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        let f0 = lease.fence();

        checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

        let plan = test_split_residual_plan();
        let result = coord
            .split_residual(now(12), test_tenant(), &lease, plan, OpId::from_raw(2))
            .unwrap();
        assert!(result.is_executed(), "split_residual must be Executed");

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.fence_epoch, f0, "split_residual must not change fence");

        park_ok(&mut coord, 13, &lease, ParkReason::TooManyErrors, 3);

        {
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert_eq!(rec.status, ShardStatus::Parked);
            assert_eq!(rec.fence_epoch, f0, "park must not change fence");
            assert_eq!(
                coord.cursor_last_key(rec),
                Some(b"d".as_slice()),
                "park must preserve cursor"
            );
            let (start, end) = coord.spec_bounds(rec);
            assert_eq!(start, b"a", "park must preserve narrowed range start");
            assert_eq!(end, b"m", "park must preserve narrowed range end");
        }

        let outcome = coord
            .unpark_shard(now(14), test_tenant(), test_key(), OpId::from_raw(4))
            .unwrap();
        assert!(outcome.is_executed(), "first-time unpark must be Executed");

        let fence_after_unpark = {
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert_eq!(rec.status, ShardStatus::Active);
            assert!(
                rec.fence_epoch > f0,
                "unpark must bump fence above pre-park value"
            );
            assert_eq!(
                coord.cursor_last_key(rec),
                Some(b"d".as_slice()),
                "unpark must preserve cursor through park round-trip"
            );
            let (start, end) = coord.spec_bounds(rec);
            assert_eq!(start, b"a", "unpark must preserve narrowed range start");
            assert_eq!(end, b"m", "unpark must preserve narrowed range end");
            rec.fence_epoch
        };

        let lease2 = acquire_shard(&mut coord, 15, 2);
        assert!(
            lease2.fence() > fence_after_unpark,
            "re-acquire must bump fence again"
        );

        checkpoint_ok(&mut coord, 16, &lease2, b"f", 5);
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(coord.cursor_last_key(rec), Some(b"f".as_slice()));
    }

    {
        eprintln!("  conformance: owner_divergence_with_matching_fence");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        let fence = lease.fence();

        let forged = Lease::new(
            test_tenant(),
            test_run(),
            test_shard(),
            test_worker(99),
            fence,
            lease.deadline(),
        );

        let err = coord
            .checkpoint(
                now(11),
                test_tenant(),
                &forged,
                &test_cursor(b"d"),
                OpId::from_raw(1),
            )
            .unwrap_err();
        assert!(
            matches!(err, CheckpointError::StaleFence { .. }),
            "wrong owner with matching fence must produce StaleFence, got: {err:?}"
        );

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(
            rec.fence_epoch, fence,
            "rejected checkpoint must not change fence"
        );
        assert_eq!(
            coord.cursor_last_key(rec),
            None,
            "rejected checkpoint must not advance cursor"
        );
        assert_eq!(
            rec.status,
            ShardStatus::Active,
            "rejected checkpoint must not change status"
        );
    }

    {
        eprintln!("  conformance: terminal_clears_lease");

        {
            let mut coord = factory(CursorSemantics::Completed);
            let lease = acquire_shard(&mut coord, 10, 1);
            let fence = lease.fence();
            complete_ok(&mut coord, 11, &lease, b"m", 1);
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert!(
                rec.lease_owner().is_none(),
                "complete must clear lease owner"
            );
            assert!(
                rec.lease_deadline().is_none(),
                "complete must clear lease deadline"
            );
            assert_eq!(rec.fence_epoch, fence, "complete must not change fence");
            assert_eq!(rec.status, ShardStatus::Done);
        }

        {
            let mut coord = factory(CursorSemantics::Completed);
            let lease = acquire_shard(&mut coord, 10, 1);
            let fence = lease.fence();
            park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert!(rec.lease_owner().is_none(), "park must clear lease owner");
            assert!(
                rec.lease_deadline().is_none(),
                "park must clear lease deadline"
            );
            assert_eq!(rec.fence_epoch, fence, "park must not change fence");
            assert_eq!(rec.status, ShardStatus::Parked);
        }

        {
            let mut coord = factory(CursorSemantics::Completed);
            let lease = acquire_shard(&mut coord, 10, 1);
            let fence = lease.fence();
            let plan = test_split_replace_plan();
            let outcome = coord
                .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
                .unwrap();
            assert!(
                outcome.is_executed(),
                "first-time split_replace must be Executed"
            );
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert!(
                rec.lease_owner().is_none(),
                "split_replace must clear lease owner"
            );
            assert!(
                rec.lease_deadline().is_none(),
                "split_replace must clear lease deadline"
            );
            assert_eq!(
                rec.fence_epoch, fence,
                "split_replace must not change fence"
            );
            assert_eq!(rec.status, ShardStatus::Split);
        }
    }

    // =====================================================================
    // Group B: Boundary Conditions and Variant Coverage
    // =====================================================================

    {
        eprintln!("  conformance: cursor_semantics_dispatched_through_coordinator");
        let mut coord = factory(CursorSemantics::Dispatched);

        let mut scratch = crate::AcquireScratch::new();
        let result = coord
            .acquire_and_restore_into(
                now(10),
                test_tenant(),
                test_key(),
                test_worker(1),
                &mut scratch,
            )
            .unwrap();
        assert_eq!(
            result.snapshot.cursor_semantics(),
            CursorSemantics::Dispatched,
            "snapshot must reflect Dispatched semantics"
        );

        let lease = result.lease;

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.cursor_semantics, CursorSemantics::Dispatched);

        checkpoint_ok(&mut coord, 11, &lease, b"d", 1);
        complete_ok(&mut coord, 12, &lease, b"m", 2);

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.status, ShardStatus::Done);
        assert_eq!(rec.cursor_semantics, CursorSemantics::Dispatched);
    }

    {
        eprintln!("  conformance: lease_deadline_at_exact_boundary");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        let deadline = 10 + LEASE_DURATION;
        assert_eq!(lease.deadline(), now(deadline));

        let ok = coord.checkpoint(
            now(deadline - 1),
            test_tenant(),
            &lease,
            &test_cursor(b"d"),
            OpId::from_raw(1),
        );
        assert!(ok.is_ok(), "checkpoint at deadline-1 must succeed");

        let err = coord.checkpoint(
            now(deadline),
            test_tenant(),
            &lease,
            &test_cursor(b"e"),
            OpId::from_raw(2),
        );
        assert!(
            matches!(err, Err(CheckpointError::LeaseExpired { .. })),
            "checkpoint at exact deadline must fail with LeaseExpired, got: {err:?}"
        );
    }

    {
        eprintln!("  conformance: split_coverage_key_range_partition");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        let plan = test_split_replace_plan();

        let result = coord
            .split_replace(now(11), test_tenant(), &lease, plan, OpId::from_raw(1))
            .unwrap();
        let children = result.into_inner().children;
        assert_eq!(children.len(), 2, "must produce exactly 2 children");
        let children = children.as_slice();
        let child_a = children[0];
        let child_b = children[1];

        let key_a = ShardKey::new(test_run(), child_a);
        let key_b = ShardKey::new(test_run(), child_b);

        {
            let rec_a = coord.shard_lookup(&test_tenant(), &key_a).unwrap();
            let rec_b = coord.shard_lookup(&test_tenant(), &key_b).unwrap();
            let (a_start, a_end) = coord.spec_bounds(rec_a);
            let (b_start, b_end) = coord.spec_bounds(rec_b);
            assert_eq!(a_start, b"a");
            assert_eq!(a_end, b"m");
            assert_eq!(b_start, b"m");
            assert_eq!(b_end, b"z");
            assert_eq!(a_end, b_start);
            assert_eq!(rec_a.status, ShardStatus::Active);
            assert_eq!(rec_b.status, ShardStatus::Active);
        }

        let mut scratch = crate::AcquireScratch::new();
        let child_lease = coord
            .acquire_and_restore_into(now(12), test_tenant(), key_a, test_worker(1), &mut scratch)
            .expect("child acquire must succeed")
            .lease;
        let outcome = coord
            .checkpoint(
                now(13),
                test_tenant(),
                &child_lease,
                &test_cursor(b"f"),
                OpId::from_raw(2),
            )
            .expect("child checkpoint must succeed");
        assert!(
            outcome.is_executed(),
            "first-time child checkpoint must be Executed"
        );
        let rec_a = coord.shard_lookup(&test_tenant(), &key_a).unwrap();
        assert_eq!(
            coord.cursor_last_key(rec_a),
            Some(b"f".as_slice()),
            "child checkpoint must advance cursor"
        );
    }

    {
        eprintln!("  conformance: oplog_eviction_then_replay");
        let mut coord = factory(CursorSemantics::Completed);
        let lease = acquire_shard(&mut coord, 10, 1);

        // Fill the ring buffer to capacity (OP_LOG_CAP entries).
        for i in 1..=ShardRecord::OP_LOG_CAP as u64 {
            let key = vec![b'a' + i as u8];
            let update = CursorUpdate::new(key.as_slice());
            let outcome = coord
                .checkpoint(
                    now(10 + i),
                    test_tenant(),
                    &lease,
                    &update,
                    OpId::from_raw(i),
                )
                .unwrap();
            assert!(
                outcome.is_executed(),
                "first-time checkpoint must be Executed"
            );
        }

        // One more checkpoint evicts op 1 from the ring buffer.
        let cap = ShardRecord::OP_LOG_CAP as u64;
        checkpoint_ok(&mut coord, 27, &lease, b"s", cap + 1);

        // Surviving op: still in the ring buffer → Replayed.
        let replay_surviving = coord.checkpoint(
            now(28),
            test_tenant(),
            &lease,
            &CursorUpdate::new(&[b'a' + cap as u8]),
            OpId::from_raw(cap),
        );
        assert!(
            matches!(replay_surviving, Ok(IdempotentOutcome::Replayed(()))),
            "surviving op in ring buffer must return Replayed, got: {replay_surviving:?}"
        );

        // Evicted op on the still-ACTIVE shard: the ring buffer no longer
        // has an idempotency record for op 1, so the backend treats it as
        // a fresh operation. A forward cursor satisfies monotonicity and
        // the checkpoint succeeds as Executed.
        let evicted_replay = coord.checkpoint(
            now(29),
            test_tenant(),
            &lease,
            &CursorUpdate::new(b"t"),
            OpId::from_raw(1),
        );
        assert!(
            matches!(evicted_replay, Ok(IdempotentOutcome::Executed(()))),
            "evicted op replayed with forward cursor on active shard must be Executed, \
             got: {evicted_replay:?}"
        );

        // Complete the shard, then verify terminal rejection.
        complete_ok(&mut coord, 30, &lease, b"y", cap + 2);

        let replay_on_terminal = coord.complete(
            now(31),
            test_tenant(),
            &lease,
            &test_cursor(b"y"),
            OpId::from_raw(cap + 2),
        );
        assert!(
            matches!(replay_on_terminal, Ok(IdempotentOutcome::Replayed(()))),
            "surviving op on terminal shard must return Replayed, got: {replay_on_terminal:?}"
        );
    }

    {
        eprintln!("  conformance: unpark_lifecycle_fence_and_cursor_preserved");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        let f_before_park = lease.fence();
        checkpoint_ok(&mut coord, 11, &lease, b"d", 1);

        park_ok(&mut coord, 12, &lease, ParkReason::TooManyErrors, 2);

        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(rec.status, ShardStatus::Parked);

        let outcome = coord
            .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(3))
            .unwrap();
        assert!(outcome.is_executed(), "first-time unpark must be Executed");

        let fence_after_unpark = {
            let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
            assert_eq!(rec.status, ShardStatus::Active);
            assert!(rec.fence_epoch > f_before_park, "unpark must bump fence");
            assert_eq!(
                coord.cursor_last_key(rec),
                Some(b"d".as_slice()),
                "unpark must preserve cursor"
            );
            rec.fence_epoch
        };

        let lease2 = acquire_shard(&mut coord, 14, 2);
        assert!(
            lease2.fence() > fence_after_unpark,
            "acquire after unpark must bump fence again"
        );

        checkpoint_ok(&mut coord, 15, &lease2, b"f", 4);
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(coord.cursor_last_key(rec), Some(b"f".as_slice()));
    }

    {
        eprintln!("  conformance: same_worker_reacquire_bumps_fence");
        let mut coord = factory(CursorSemantics::Completed);

        let lease1 = acquire_shard(&mut coord, 10, 1);
        let f1 = lease1.fence();

        let lease2 = acquire_shard(&mut coord, LEASE_DURATION + 11, 1);
        let f2 = lease2.fence();

        assert_eq!(f2, f1.increment(), "re-acquire must bump fence by 1");
        assert!(f2 > f1, "new fence must exceed old fence");

        let err = coord
            .checkpoint(
                now(LEASE_DURATION + 12),
                test_tenant(),
                &lease1,
                &test_cursor(b"d"),
                OpId::from_raw(1),
            )
            .unwrap_err();
        assert!(
            matches!(err, CheckpointError::StaleFence { .. }),
            "old lease must produce StaleFence, got: {err:?}"
        );

        let ok = coord.checkpoint(
            now(LEASE_DURATION + 12),
            test_tenant(),
            &lease2,
            &test_cursor(b"d"),
            OpId::from_raw(2),
        );
        assert!(ok.is_ok(), "new lease checkpoint must succeed");
    }

    // =====================================================================
    // Group C: Run-Level Conformance
    // =====================================================================

    {
        eprintln!("  conformance: run_terminal_irreversibility [Done]");
        let expected_status = RunStatus::Done;
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        complete_ok(&mut coord, 11, &lease, b"y", 1);
        let outcome = coord
            .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time complete_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), expected_status);

        assert_all_run_transitions_rejected(&mut coord, expected_status);
    }

    {
        eprintln!("  conformance: run_terminal_irreversibility [Cancelled]");
        let expected_status = RunStatus::Cancelled;
        let mut coord = factory(CursorSemantics::Completed);

        // Acquire a shard so the run has an active lease when cancelled.
        // cancel_run must succeed regardless of outstanding leases.
        let _lease = acquire_shard(&mut coord, 10, 1);
        let rec = coord.shard_lookup(&test_tenant(), &test_key()).unwrap();
        assert_eq!(
            rec.status,
            ShardStatus::Active,
            "shard must be leased before cancel"
        );

        let outcome = coord
            .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time cancel_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), expected_status);

        assert_all_run_transitions_rejected(&mut coord, expected_status);
    }

    {
        eprintln!("  conformance: run_terminal_irreversibility [Failed]");
        let expected_status = RunStatus::Failed;
        let mut coord = factory(CursorSemantics::Completed);

        // fail_run requires Active status — the seeded backend already
        // creates the run in Active state with registered shards.
        let outcome = coord
            .fail_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time fail_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), expected_status);

        assert_all_run_transitions_rejected(&mut coord, expected_status);
    }

    {
        eprintln!("  conformance: register_shards_on_non_initializing_rejected");
        let mut coord = factory(CursorSemantics::Completed);

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), RunStatus::Active);

        let spec = ShardSpec::with_range(b"aa", b"bb");
        let cursor = CursorUpdate::initial();
        let shards = vec![InitialShardInput::new(
            ShardId::from_raw(999),
            spec.as_ref(),
            cursor,
        )];
        let err = coord
            .register_shards(
                now(10),
                test_tenant(),
                test_run(),
                &shards,
                OpId::from_raw(200),
            )
            .unwrap_err();
        assert!(
            matches!(
                err,
                crate::run_errors::RegisterShardsError::WrongStatus { .. }
            ),
            "register_shards on Active run must return WrongStatus, got: {err:?}"
        );
    }

    {
        eprintln!("  conformance: run_completed_at_consistency");
        let mut coord = factory(CursorSemantics::Completed);

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), RunStatus::Active);
        assert!(
            rec.completed_at().is_none(),
            "Active run must have completed_at == None"
        );

        let lease = acquire_shard(&mut coord, 10, 1);
        complete_ok(&mut coord, 11, &lease, b"y", 1);
        let outcome = coord
            .complete_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time complete_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), RunStatus::Done);
        assert!(
            rec.completed_at().is_some(),
            "Done run must have completed_at"
        );

        let run2 = RunId::from_raw(2);
        let config = test_run_config();
        coord
            .create_run(now(20), test_tenant(), run2, config)
            .unwrap();

        let rec = coord.get_run(test_tenant(), run2).unwrap();
        assert!(
            rec.completed_at().is_none(),
            "Initializing run must have completed_at == None"
        );

        let outcome = coord
            .cancel_run(now(21), test_tenant(), run2, OpId::from_raw(200))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time cancel_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), run2).unwrap();
        assert_eq!(rec.status(), RunStatus::Cancelled);
        assert!(
            rec.completed_at().is_some(),
            "Cancelled run must have completed_at"
        );
    }

    {
        eprintln!("  conformance: unpark_after_run_terminal_rejected");
        let mut coord = factory(CursorSemantics::Completed);

        let lease = acquire_shard(&mut coord, 10, 1);
        park_ok(&mut coord, 11, &lease, ParkReason::TooManyErrors, 1);

        let outcome = coord
            .cancel_run(now(12), test_tenant(), test_run(), OpId::from_raw(100))
            .unwrap();
        assert!(
            outcome.is_executed(),
            "first-time cancel_run must be Executed"
        );

        let rec = coord.get_run(test_tenant(), test_run()).unwrap();
        assert_eq!(rec.status(), RunStatus::Cancelled);

        let err = coord
            .unpark_shard(now(13), test_tenant(), test_key(), OpId::from_raw(2))
            .unwrap_err();
        assert!(
            matches!(err, UnparkError::RunTerminal { .. }),
            "unpark on terminal run must return RunTerminal, got: {err:?}"
        );
    }
}
