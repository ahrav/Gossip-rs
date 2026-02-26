//! Tests for [`ShardFilter`] predicates applied through
//! [`RunManagement::list_shards_into`].
//!
//! `list_shards_into` accepts a [`ShardFilter`] that narrows the returned set by
//! status, lease state, and parentage. Getting these predicates wrong causes
//! workers to receive invisible shards (missed work) or stale shards
//! (wasted retries), so each filter variant has its own focused test.
//!
//! # Coverage
//!
//! | Filter | What the test proves |
//! |--------|----------------------|
//! | `active()` | Includes leased Active shards, excludes Parked |
//! | `available()` | Excludes leased shards, includes expired-lease shards |
//! | `parked()` | Excludes Active, includes Parked |
//! | `root_only` | Excludes split children (shards with a parent) |
//!
//! A property-based section follows the deterministic tests: random
//! operation sequences must preserve shard-record invariants and the
//! filter/capacity-hint contracts.

use super::*;
use crate::run::{RunManagement, ShardFilter, ShardSummary};
use crate::sim::backend::SimIntrospection;
use crate::test_fixtures::{
    LEASE_DURATION, acquire_result, acquire_shard, coordinator_with_run_and_lease,
    do_split_replace, now, test_run, test_tenant, test_worker,
};
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::manifest::InitialShardInput;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
use gossip_contracts::identity::{FenceEpoch, LogicalTime, OpId, ShardId, ShardKey, WorkerId};

fn list_shards_with_filter(
    coord: &InMemoryCoordinator,
    at: LogicalTime,
    filter: ShardFilter,
    out: &mut Vec<ShardSummary>,
) {
    coord
        .list_shards_into(at, test_tenant(), test_run(), filter, out)
        .unwrap();
}

// -- Deterministic filter tests -----------------------------------------------
//
// Each test sets up a coordinator with one shard in a known state, applies a
// single filter predicate, and asserts exact inclusion/exclusion. The fixture
// `coordinator_with_run_and_lease` provides an Active+leased shard; tests
// transition it to Parked or Split as needed.

/// Active filter includes leased Active shards and excludes Parked ones.
#[test]
fn list_shards_filter_active() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let mut summaries = Vec::new();

    // Shard is Active + leased.
    list_shards_with_filter(&coord, now(4), ShardFilter::active(), &mut summaries);
    assert_eq!(
        summaries.len(),
        1,
        "active filter should include leased Active shard"
    );

    // Park it.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    list_shards_with_filter(&coord, now(6), ShardFilter::active(), &mut summaries);
    assert!(
        summaries.is_empty(),
        "active filter should exclude Parked shard",
    );
}

/// Available filter excludes leased shards but includes them once the lease expires.
#[test]
fn list_shards_filter_available() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let mut summaries = Vec::new();

    // Shard is Active + leased -> available() requires is_leased=false.
    list_shards_with_filter(&coord, now(4), ShardFilter::available(), &mut summaries);
    assert!(
        summaries.is_empty(),
        "available filter should exclude leased Active shard",
    );

    // After lease expiry, shard becomes available.
    list_shards_with_filter(
        &coord,
        now(LEASE_DURATION + 10),
        ShardFilter::available(),
        &mut summaries,
    );
    assert_eq!(
        summaries.len(),
        1,
        "shard should be available after lease expiry"
    );
}

/// Parked filter returns only Parked shards, empty when none are parked.
#[test]
fn list_shards_filter_parked() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    let mut summaries = Vec::new();

    // No parked shards initially.
    list_shards_with_filter(&coord, now(4), ShardFilter::parked(), &mut summaries);
    assert!(summaries.is_empty());

    // Park the shard.
    let _ = coord
        .park_shard(
            now(5),
            test_tenant(),
            &lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(10),
        )
        .unwrap();

    list_shards_with_filter(&coord, now(6), ShardFilter::parked(), &mut summaries);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Parked);
}

/// `root_only` excludes split children (shards whose `parent` is `Some`).
///
/// After a split-replace, the parent becomes Split (root) and two children
/// are created with `parent.is_some()`. The root_only filter must return
/// only the parent; the `all()` filter returns parent + children.
#[test]
fn list_shards_filter_root_only() {
    let (mut coord, lease) = coordinator_with_run_and_lease();
    do_split_replace(&mut coord, &lease);
    let mut summaries = Vec::new();

    // root_only should exclude split children.
    let root_filter = ShardFilter {
        root_only: true,
        ..ShardFilter::default()
    };
    list_shards_with_filter(&coord, now(5), root_filter, &mut summaries);
    // The parent (root) is Split, children are derived (have parent).
    // root_only excludes shards with parent.is_some().
    for s in &summaries {
        assert!(
            s.parent().is_none(),
            "root_only filter should exclude children; found shard with parent: {:?}",
            s.parent(),
        );
    }

    // Without root_only, we get all (parent + children).
    let root_count = summaries.len();
    list_shards_with_filter(&coord, now(5), ShardFilter::all(), &mut summaries);
    assert!(
        summaries.len() > root_count,
        "all filter should include more shards than root_only: all={} vs roots={}",
        summaries.len(),
        root_count,
    );
}

/// list_shards_into grows an undersized caller buffer instead of panicking.
#[test]
fn list_shards_grows_undersized_output_buffer() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let mut out = Vec::new();
    assert_eq!(out.capacity(), 0, "test precondition");

    coord
        .list_shards_into(
            now(4),
            test_tenant(),
            test_run(),
            ShardFilter::all(),
            &mut out,
        )
        .unwrap();

    assert_eq!(out.len(), 1);
    assert!(
        out.capacity() >= 1,
        "buffer should grow to hold at least one summary"
    );
}

/// `list_shards_into` should produce stable results and allow
/// output-buffer reuse across repeated queries.
#[test]
fn list_shards_into_reuses_buffer_on_repeated_query() {
    let (coord, _lease) = coordinator_with_run_and_lease();

    let mut out = Vec::with_capacity(8);
    coord
        .list_shards_into(
            now(4),
            test_tenant(),
            test_run(),
            ShardFilter::active(),
            &mut out,
        )
        .unwrap();
    let expected = out.clone();

    let capacity_after_first = out.capacity();
    coord
        .list_shards_into(
            now(4),
            test_tenant(),
            test_run(),
            ShardFilter::active(),
            &mut out,
        )
        .unwrap();
    assert_eq!(out, expected);
    assert_eq!(
        out.capacity(),
        capacity_after_first,
        "reused output buffer should not reallocate on identical repeated query",
    );
}

// ============================================================================
// Property tests
// ============================================================================
//
// These tests use proptest to generate random operation sequences and verify
// that structural invariants hold after every step. They complement the
// deterministic unit tests above by exploring operation orderings and
// parameter combinations that a human would not enumerate by hand.

use crate::split::SplitReplacePlan;
use crate::test_fixtures::{seeded_coordinator, test_key};
use gossip_contracts::test_util::miri_proptest_config;
use proptest::prelude::*;

/// The universe of operations that can be applied to a coordinator in the
/// property tests. Each variant maps to one `CoordinationBackend` or
/// `RunManagement` method. `TimeAdvance` simulates the passage of logical
/// time (enabling lease expiry between operations).
#[derive(Debug, Clone)]
enum Op {
    Acquire {
        worker: u8,
    },
    Checkpoint {
        cursor_key: u8,
    },
    Complete {
        cursor_key: u8,
    },
    Park,
    Renew,
    SplitReplace,
    SplitResidual,
    TimeAdvance {
        ticks: u64,
    },
    /// Run-level: complete the run (Active -> Done).
    CompleteRun,
    /// Run-level: fail the run (Active -> Failed).
    FailRun,
    /// Run-level: cancel the run (any non-terminal -> Cancelled).
    CancelRun,
    /// Run-level: unpark a parked shard.
    UnparkShard,
}

/// Proptest strategy that generates random coordinator operations.
///
/// Weights are tuned to produce realistic mixes: Checkpoint is most
/// common (4x) because it is the most frequent production operation;
/// Acquire (3x), Complete (2x), and Renew/TimeAdvance (2x each) ensure
/// frequent lease and lifecycle churn; Park, split, and run-level
/// terminal operations are rare (1x each) to avoid sequences that
/// immediately deadlock on a terminal shard.
fn arb_op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0u8..4).prop_map(|w| Op::Acquire { worker: w }),
        4 => (b'a'..b'y').prop_map(|k| Op::Checkpoint { cursor_key: k }),
        2 => (b'a'..b'y').prop_map(|k| Op::Complete { cursor_key: k }),
        1 => Just(Op::Park),
        2 => Just(Op::Renew),
        1 => Just(Op::SplitReplace),
        1 => Just(Op::SplitResidual),
        2 => (1u64..200).prop_map(|t| Op::TimeAdvance { ticks: t }),
        1 => Just(Op::CompleteRun),
        1 => Just(Op::FailRun),
        1 => Just(Op::CancelRun),
        1 => Just(Op::UnparkShard),
    ]
}

/// Applies a single [`Op`] to the coordinator, threading time and op counter.
///
/// Returns `(new_time, new_op_counter)`. Operations that are dispatched
/// with an OpId always increment the counter (even if the coordinator
/// rejects the operation). Operations that cannot be dispatched (no
/// lease available, invalid cursor) or that do not use an OpId (Acquire,
/// Renew, TimeAdvance) leave the counter unchanged. All errors are
/// silently discarded because the property tests assert invariants
/// *after* each op, not individual success/failure outcomes.
fn apply_op(
    coord: &mut InMemoryCoordinator,
    op: &Op,
    time: u64,
    oc: u64,
    last_lease: &mut Option<Lease>,
) -> (u64, u64) {
    let now = LogicalTime::from_raw(time);
    let ten = test_tenant();
    match op {
        Op::Acquire { worker } => {
            if let Ok(r) = acquire_result(
                coord,
                now,
                ten,
                test_key(),
                WorkerId::from_raw(*worker as u64),
            ) {
                *last_lease = Some(r.lease);
            }
            (time, oc)
        }
        Op::Checkpoint { cursor_key } => {
            if let Some(lease) = last_lease.as_ref()
                && let Ok(update) = CursorUpdate::try_with_last_key(&[*cursor_key])
            {
                let _ = coord.checkpoint(now, ten, lease, &update, OpId::from_raw(oc));
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Complete { cursor_key } => {
            if let Some(lease) = last_lease.as_ref()
                && let Ok(update) = CursorUpdate::try_with_last_key(&[*cursor_key])
            {
                let _ = coord.complete(now, ten, lease, &update, OpId::from_raw(oc));
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Park => {
            if let Some(lease) = last_lease.as_ref() {
                let _ = coord.park_shard(
                    now,
                    ten,
                    lease,
                    ParkReason::TooManyErrors,
                    OpId::from_raw(oc),
                );
                return (time, oc + 1);
            }
            (time, oc)
        }
        Op::Renew => {
            if let Some(lease) = last_lease.as_ref() {
                let _ = coord.renew(now, ten, lease);
            }
            (time, oc)
        }
        Op::SplitReplace => {
            if let Some(lease) = last_lease.as_ref() {
                let spec_a = ShardSpec::with_range(b"a", b"m");
                let spec_b = ShardSpec::with_range(b"m", b"z");
                let cursor_a = CursorUpdate::initial();
                let cursor_b = CursorUpdate::initial();
                let child_a = SplitReplaceChild::new(spec_a.as_ref(), cursor_a);
                let child_b = SplitReplaceChild::new(spec_b.as_ref(), cursor_b);
                if let Ok(plan) = SplitReplacePlan::try_new(vec![child_a, child_b]) {
                    let _ = coord.split_replace(now, ten, lease, plan, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
            }
            (time, oc)
        }
        Op::SplitResidual => {
            if let Some(lease) = last_lease.as_ref() {
                let new_parent = ShardSpec::with_range(b"a", b"m");
                let residual = ShardSpec::with_range(b"m", b"z");
                if let Ok(plan) = SplitResidualPlan::try_new(new_parent.as_ref(), residual.as_ref())
                {
                    let _ = coord.split_residual(now, ten, lease, plan, OpId::from_raw(oc));
                    return (time, oc + 1);
                }
            }
            (time, oc)
        }
        Op::TimeAdvance { ticks } => (time.saturating_add(*ticks), oc),
        Op::CompleteRun => {
            let _ = coord.complete_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::FailRun => {
            let _ = coord.fail_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::CancelRun => {
            let _ = coord.cancel_run(now, ten, test_run(), OpId::from_raw(oc));
            (time, oc + 1)
        }
        Op::UnparkShard => {
            let _ = coord.unpark_shard(now, ten, test_key(), OpId::from_raw(oc));
            (time, oc + 1)
        }
    }
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// Fuzz test: random operation sequences must preserve shard record invariants.
    ///
    /// Generates 1..100 random operations and applies them to a seeded
    /// coordinator. After *every* operation (whether it succeeds or fails),
    /// every shard record's `assert_invariants()` must pass. This catches
    /// state-machine corruption that only manifests under unusual operation
    /// orderings.
    #[test]
    fn random_ops_preserve_invariants(ops in proptest::collection::vec(arb_op(), 1..100)) {
        let mut coord = seeded_coordinator();
        // Start time after seeded_coordinator setup (which uses t=1, t=2).
        let mut time = 3u64;
        let mut op_counter = 1u64;
        let mut last_lease: Option<Lease> = None;

        for op in ops {
            (time, op_counter) = apply_op(&mut coord, &op, time, op_counter, &mut last_lease);

            // After every op, all records must satisfy invariants.
            for (_, record) in coord.shards() {
                record.assert_invariants(coord.slab());
            }
        }
    }

    /// Fence epoch strictly increases across successive acquisitions.
    ///
    /// Generates 2..20 worker IDs, each acquiring the shard after the
    /// previous lease expires. The fence epoch must be strictly greater
    /// than the previous maximum after every successful acquisition.
    #[test]
    fn fence_monotonicity_property(
        worker_ids in proptest::collection::vec(0u8..4, 2..20),
    ) {
        let mut coord = seeded_coordinator();
        let mut time = 1u64;
        let mut max_fence = FenceEpoch::INITIAL;

        for worker in worker_ids {
            time += LEASE_DURATION + 1; // ensure lease expired
            if let Ok(result) = acquire_result(&mut coord,
                LogicalTime::from_raw(time),
                test_tenant(),
                test_key(),
                WorkerId::from_raw(worker as u64),
            ) {
                let fence = result.lease.fence();
                prop_assert!(
                    fence > max_fence,
                    "fence must strictly increase: {fence:?} <= {max_fence:?}",
                );
                max_fence = fence;
            }
        }
    }

    /// Idempotent replay: any mutating operation (checkpoint, complete, park),
    /// when replayed with the same OpId and identical payload, returns
    /// `Replayed` rather than executing a second time or returning an error.
    ///
    /// Parameterized over random cursor keys, OpId values, and operation
    /// kinds to exercise the replay path with diverse inputs.
    #[test]
    fn idempotent_replay_across_operations(
        cursor_key in b'b'..b'y',
        op_raw in 1u64..1000,
        op_kind in 0u8..3,
    ) {
        let mut coord = seeded_coordinator();
        let ten = test_tenant();
        // seeded_coordinator() consumes t=1 (create_run) and t=2 (register_shards),
        // so user operations must start at t=3 to preserve logical time ordering.
        let lease = acquire_result(&mut coord,
                LogicalTime::from_raw(3),
                ten,
                test_key(),
                WorkerId::from_raw(1),
            )
            .unwrap()
            .lease;
        let op = OpId::from_raw(op_raw);
        let key = [cursor_key];
        let cursor = CursorUpdate::new(&key);

        match op_kind {
            0 => {
                let first = coord
                    .checkpoint(LogicalTime::from_raw(4), ten, &lease, &cursor, op)
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .checkpoint(LogicalTime::from_raw(5), ten, &lease, &cursor, op)
                    .unwrap();
                prop_assert!(second.is_replay());
            }
            1 => {
                let first = coord
                    .complete(LogicalTime::from_raw(4), ten, &lease, &cursor, op)
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .complete(LogicalTime::from_raw(5), ten, &lease, &cursor, op)
                    .unwrap();
                prop_assert!(second.is_replay());
            }
            _ => {
                let first = coord
                    .park_shard(
                        LogicalTime::from_raw(4),
                        ten,
                        &lease,
                        ParkReason::TooManyErrors,
                        op,
                    )
                    .unwrap();
                prop_assert!(first.is_executed());
                let second = coord
                    .park_shard(
                        LogicalTime::from_raw(5),
                        ten,
                        &lease,
                        ParkReason::TooManyErrors,
                        op,
                    )
                    .unwrap();
                prop_assert!(second.is_replay());
            }
        }
    }

    /// Cursor monotonicity: within a single lease, checkpoint succeeds only
    /// when the cursor advances (or stays equal), and is rejected with
    /// `CursorRegression` when it would move backwards.
    ///
    /// Generates 2..20 random key bytes and attempts checkpoints in order.
    /// Verifies that success implies `key >= max_seen` and regression
    /// rejection implies `key < max_seen`.
    #[test]
    fn cursor_monotonicity_property(
        keys in proptest::collection::vec(b'a'..b'y', 2..20),
    ) {
        let mut coord = seeded_coordinator();
        // seeded_coordinator() consumes t=1 (create_run) and t=2 (register_shards),
        // so user operations must start at t=3 to preserve logical time ordering.
        let lease = acquire_result(&mut coord,
                LogicalTime::from_raw(3),
                test_tenant(),
                test_key(),
                WorkerId::from_raw(1),
            )
            .unwrap()
            .lease;

        let mut max_key: Option<u8> = None;
        let mut op_counter = 3u64;

        for &key_byte in &keys {
            let key = [key_byte];
            let cursor = CursorUpdate::new(&key);
            let result = coord.checkpoint(
                LogicalTime::from_raw(op_counter + 1),
                test_tenant(),
                &lease,
                &cursor,
                OpId::from_raw(op_counter),
            );
            op_counter += 1;

            match result {
                Ok(_) => {
                    // Checkpoint succeeded -- key must be >= max_key.
                    if let Some(prev) = max_key {
                        prop_assert!(key_byte >= prev);
                    }
                    max_key = Some(key_byte);
                }
                Err(CheckpointError::CursorRegression { .. }) => {
                    // Expected: key_byte < max_key, regression rejected.
                    if let Some(prev) = max_key {
                        prop_assert!(key_byte < prev);
                    }
                }
                Err(other) => {
                    prop_assert!(
                        false,
                        "unexpected checkpoint error: {other:?}",
                    );
                }
            }
        }
    }
}

// ============================================================================
// Capacity hint tests
// ============================================================================
//
// CapacityHint is returned by acquire and renew to inform callers how many
// shards remain available in the run. These tests verify:
//
// - `available_count` decrements with each successful acquisition.
// - `earliest_deadline` tracks the minimum lease deadline across all
//   leased shards, giving callers a backoff target when saturated.
// - Terminal shards (Done, Parked) are excluded from the count.
// - The half-open deadline boundary (`now < deadline`) is respected.

/// Helper: create a coordinator with `n` shards in a single run.
fn multi_shard_coordinator(n: usize) -> InMemoryCoordinator {
    use crate::test_fixtures::test_run_config as run_config;
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = test_run();
    coord.create_run(now(1), tenant, run, run_config()).unwrap();
    let shard_entries: Vec<_> = (0..n)
        .map(|i| {
            let start = vec![i as u8];
            let end = vec![(i + 1) as u8];
            (
                ShardId::from_raw(i as u64),
                ShardSpec::with_range(start, end),
                CursorUpdate::initial(),
            )
        })
        .collect();
    let shards: Vec<InitialShardInput<'_>> = shard_entries
        .iter()
        .map(|(shard, spec, cursor)| InitialShardInput::new(*shard, spec.as_ref(), *cursor))
        .collect();
    let _ = coord
        .register_shards(now(1), tenant, run, &shards, OpId::from_raw(100))
        .unwrap();
    coord
}

/// Acquire 3 shards sequentially; capacity hint decrements each time.
#[test]
fn acquire_capacity_hint_reflects_remaining() {
    let mut coord = multi_shard_coordinator(3);
    let tenant = test_tenant();
    let run = test_run();

    let r0 = acquire_result(
        &mut coord,
        now(2),
        tenant,
        ShardKey::new(run, ShardId::from_raw(0)),
        test_worker(1),
    )
    .unwrap();
    assert_eq!(r0.capacity.available_count, 2);
    assert!(!r0.capacity.is_saturated());
    assert!(r0.capacity.earliest_deadline.is_some());

    let r1 = acquire_result(
        &mut coord,
        now(2),
        tenant,
        ShardKey::new(run, ShardId::from_raw(1)),
        test_worker(2),
    )
    .unwrap();
    assert_eq!(r1.capacity.available_count, 1);

    let r2 = acquire_result(
        &mut coord,
        now(2),
        tenant,
        ShardKey::new(run, ShardId::from_raw(2)),
        test_worker(3),
    )
    .unwrap();
    assert_eq!(r2.capacity.available_count, 0);
    assert!(r2.capacity.is_saturated());
    // All leases granted at now(2) with LEASE_DURATION -- earliest deadline
    // is now(2 + LEASE_DURATION).
    assert_eq!(r2.capacity.earliest_deadline, Some(now(2 + LEASE_DURATION)),);
}

/// Acquires shards at different times; earliest_deadline tracks the minimum.
#[test]
fn capacity_hint_earliest_deadline_is_minimum() {
    let mut coord = multi_shard_coordinator(3);
    let tenant = test_tenant();
    let run = test_run();

    // Acquire shard 0 at now(5) -> deadline = 5 + LEASE_DURATION.
    let r0 = acquire_result(
        &mut coord,
        now(5),
        tenant,
        ShardKey::new(run, ShardId::from_raw(0)),
        test_worker(1),
    )
    .unwrap();
    // Only shard 0 is leased; its deadline is the earliest (and only).
    assert_eq!(r0.capacity.earliest_deadline, Some(now(5 + LEASE_DURATION)),);

    // Acquire shard 1 at now(10) -> deadline = 10 + LEASE_DURATION.
    // Shard 0's deadline (105) < shard 1's deadline (110) -- min is 105.
    let r1 = acquire_result(
        &mut coord,
        now(10),
        tenant,
        ShardKey::new(run, ShardId::from_raw(1)),
        test_worker(2),
    )
    .unwrap();
    assert_eq!(
        r1.capacity.earliest_deadline,
        Some(now(5 + LEASE_DURATION)),
        "earliest_deadline should be the minimum across all leased shards",
    );

    // Acquire shard 2 at now(2) -> deadline = 2 + LEASE_DURATION.
    // Now shard 2's deadline (102) < shard 0's (105) < shard 1's (110).
    let r2 = acquire_result(
        &mut coord,
        now(2),
        tenant,
        ShardKey::new(run, ShardId::from_raw(2)),
        test_worker(3),
    )
    .unwrap();
    assert_eq!(
        r2.capacity.earliest_deadline,
        Some(now(2 + LEASE_DURATION)),
        "earliest_deadline should update to the new minimum",
    );
    assert_eq!(r2.capacity.available_count, 0);
}

/// Renew returns a capacity hint reflecting current state.
#[test]
fn renew_capacity_hint_basic() {
    let mut coord = seeded_coordinator();
    let lease = acquire_shard(&mut coord, 3, 1);

    let result = coord.renew(now(50), test_tenant(), &lease).unwrap();
    assert_eq!(result.capacity.available_count, 0);
    // After renewal the deadline is now(50) + LEASE_DURATION.
    assert_eq!(
        result.capacity.earliest_deadline,
        Some(now(50 + LEASE_DURATION)),
    );
}

/// After a lease expires, re-acquiring sees the freed shard.
#[test]
fn capacity_hint_after_lease_expiry() {
    let mut coord = seeded_coordinator();
    let _lease = acquire_shard(&mut coord, 3, 1);

    // Lease deadline = 3 + 100 = 103. At now(104), lease expired.
    let r = acquire_result(
        &mut coord,
        now(104),
        test_tenant(),
        test_key(),
        test_worker(2),
    )
    .unwrap();
    // Just acquired the only shard -- 0 available remain.
    assert_eq!(r.capacity.available_count, 0);
}

/// Terminal (completed) shards are excluded from the capacity count.
#[test]
fn capacity_hint_excludes_terminal_shards() {
    let mut coord = multi_shard_coordinator(2);
    let tenant = test_tenant();
    let run = test_run();

    // Acquire shard 0 and complete it.
    let key0 = ShardKey::new(run, ShardId::from_raw(0));
    let r0 = acquire_result(&mut coord, now(2), tenant, key0, test_worker(1)).unwrap();
    let _ = coord
        .complete(
            now(3),
            tenant,
            &r0.lease,
            &CursorUpdate::new(&[0]),
            OpId::from_raw(200),
        )
        .unwrap();

    // Acquire shard 1 -- shard 0 is terminal and not counted.
    let key1 = ShardKey::new(run, ShardId::from_raw(1));
    let r1 = acquire_result(&mut coord, now(4), tenant, key1, test_worker(2)).unwrap();
    assert_eq!(r1.capacity.available_count, 0);
    assert!(r1.capacity.earliest_deadline.is_some());
}

/// Parked shards are terminal and excluded from the available capacity count.
#[test]
fn capacity_hint_excludes_parked_shards() {
    let mut coord = multi_shard_coordinator(2);
    let tenant = test_tenant();
    let run = test_run();

    // Acquire shard 0 and park it.
    let key0 = ShardKey::new(run, ShardId::from_raw(0));
    let r0 = acquire_result(&mut coord, now(2), tenant, key0, test_worker(1)).unwrap();
    let _ = coord
        .park_shard(
            now(3),
            tenant,
            &r0.lease,
            ParkReason::TooManyErrors,
            OpId::from_raw(100),
        )
        .unwrap();

    // Acquire shard 1 -- shard 0 is Parked (terminal), so the only active
    // shard is shard 1 which we just acquired. Available count = 0.
    let key1 = ShardKey::new(run, ShardId::from_raw(1));
    let r1 = acquire_result(&mut coord, now(4), tenant, key1, test_worker(2)).unwrap();
    assert_eq!(r1.capacity.available_count, 0);
    assert!(r1.capacity.is_saturated());
    // Shard 0 is parked, shard 1 is leased -- earliest deadline reflects shard 1.
    assert!(r1.capacity.earliest_deadline.is_some());
}

/// Capacity hint at the exact deadline boundary (half-open interval).
#[test]
fn capacity_hint_at_deadline_boundary() {
    let mut coord = seeded_coordinator();
    let _lease = acquire_shard(&mut coord, 3, 1);

    // Lease deadline = 3 + 100 = 103.
    // At now(103): now < deadline is false => lease expired.
    let r = acquire_result(
        &mut coord,
        now(103),
        test_tenant(),
        test_key(),
        test_worker(2),
    )
    .unwrap();
    assert_eq!(r.capacity.available_count, 0);
}

/// CapacityHint helper methods work correctly.
#[test]
fn capacity_hint_helpers() {
    use crate::error::CapacityHint;

    let saturated = CapacityHint {
        available_count: 0,
        earliest_deadline: Some(now(100)),
    };
    assert!(saturated.is_saturated());

    let available = CapacityHint {
        available_count: 3,
        earliest_deadline: None,
    };
    assert!(!available.is_saturated());

    assert_eq!(CapacityHint::ZERO.available_count, 0);
    assert_eq!(CapacityHint::ZERO.earliest_deadline, None);
    assert!(CapacityHint::ZERO.is_saturated());
}

// ============================================================================
// Constructor equivalence tests
// ============================================================================
//
// `InMemoryCoordinator` offers multiple constructor entry points
// (`new`, `with_limits`, `with_cooldown`, `with_runtime_config`).
// These tests verify that constructors producing the same logical
// configuration yield bit-identical internal state so callers can
// migrate between constructors without behavioral drift.

/// Asserts constructor wrappers are behaviorally equivalent at initialization.
///
/// This guards the runtime-config migration: legacy constructor entry points
/// must preserve both limits/cooldown semantics and initial capacity policy.
fn assert_constructor_equivalent(lhs: &InMemoryCoordinator, rhs: &InMemoryCoordinator) {
    assert_eq!(lhs.default_lease_duration, rhs.default_lease_duration);
    assert_eq!(lhs.max_shards_per_tenant, rhs.max_shards_per_tenant);
    assert_eq!(lhs.max_total_shards, rhs.max_total_shards);
    assert_eq!(lhs.claim_cooldown_interval, rhs.claim_cooldown_interval);
    assert_eq!(lhs.slab().capacity(), rhs.slab().capacity());
    assert_eq!(lhs.shards.capacity(), rhs.shards.capacity());
    assert_eq!(lhs.runs.capacity(), rhs.runs.capacity());
    assert_eq!(lhs.run_shards.capacity(), rhs.run_shards.capacity());
    assert_eq!(
        lhs.claim_cooldowns.capacity(),
        rhs.claim_cooldowns.capacity()
    );
    assert_eq!(lhs.total_shard_count, rhs.total_shard_count);
    assert_eq!(lhs.total_shard_count, 0);
    assert!(lhs.shards.is_empty());
    assert!(lhs.runs.is_empty());
    assert!(lhs.run_shards.is_empty());
    assert!(lhs.claim_cooldowns.is_empty());
}

#[test]
fn runtime_constructor_matches_new_defaults() {
    let runtime = InMemoryCoordinator::with_runtime_config(CoordinatorRuntimeConfig::with_limits(
        LEASE_DURATION,
        DEFAULT_MAX_SHARDS_PER_TENANT,
        DEFAULT_MAX_TOTAL_SHARDS,
    ));
    let legacy = InMemoryCoordinator::new(LEASE_DURATION);
    assert_constructor_equivalent(&runtime, &legacy);
}

#[test]
fn runtime_constructor_matches_with_limits() {
    let runtime = InMemoryCoordinator::with_runtime_config(CoordinatorRuntimeConfig::with_limits(
        LEASE_DURATION,
        123,
        456,
    ));
    let legacy = InMemoryCoordinator::with_limits(LEASE_DURATION, 123, 456);
    assert_constructor_equivalent(&runtime, &legacy);
}

#[test]
fn runtime_constructor_matches_with_cooldown() {
    let runtime = InMemoryCoordinator::with_runtime_config(CoordinatorRuntimeConfig::new(
        LEASE_DURATION,
        123,
        456,
        9,
    ));
    let legacy = InMemoryCoordinator::with_cooldown(LEASE_DURATION, 123, 456, 9);
    assert_constructor_equivalent(&runtime, &legacy);
}

#[test]
fn runtime_constructor_caps_auto_slab_capacity() {
    // `new()` uses runtime defaults (1_000_000 max shards). Auto sizing would
    // exceed the configured startup cap, so capacity must clamp to the cap.
    let coord = InMemoryCoordinator::new(LEASE_DURATION);
    assert_eq!(coord.slab().capacity(), DEFAULT_MAX_AUTO_SLAB_CAPACITY);
}

#[test]
fn runtime_constructor_respects_explicit_slab_capacity() {
    // Explicit slab capacity bypasses auto-sizing and preserves valid values.
    let mut config = CoordinatorRuntimeConfig::with_limits(LEASE_DURATION, 123, 456);
    config.slab_capacity = 8 * 1024;
    let coord = InMemoryCoordinator::with_runtime_config(config);
    assert_eq!(coord.slab().capacity(), 8 * 1024);
}

#[test]
fn runtime_constructor_clamps_explicit_slab_capacity_to_backend_max() {
    // ByteSlab uses a u32-addressed backing store, so oversized explicit
    // requests must clamp rather than panic or wrap.
    let mut config = CoordinatorRuntimeConfig::with_limits(LEASE_DURATION, 123, 456);
    config.slab_capacity = usize::MAX;
    let coord = InMemoryCoordinator::with_runtime_config(config);
    assert_eq!(coord.slab().capacity(), u32::MAX as usize);
}

// -- CoordinatorConfig memory budget smoke tests ------------------------------
//
// `CoordinatorConfig::memory_budget()` estimates heap consumption to let
// operators right-size container memory limits. These tests pin the
// estimate within a plausible range for dev and prod profiles, verify
// rounding behavior, and confirm that the planning constants embedded in
// the formula match actual `size_of::<ShardRecord>()` / `size_of::<RunRecord>()`
// on this platform. If struct layouts change, the constant-match test
// fails and the formula must be updated in lockstep.

#[test]
fn coordinator_config_dev_defaults_budget() {
    let cfg = super::CoordinatorConfig::dev_defaults();
    let mb = cfg.memory_budget_mb();
    // Dev defaults: ~6.6 MiB. Allow 1-100 MiB range for formula drift.
    assert!(
        (1..=100).contains(&mb),
        "dev_defaults budget {mb} MB outside expected 1-100 MB range"
    );
}

#[test]
fn coordinator_config_prod_defaults_budget() {
    let cfg = super::CoordinatorConfig::prod_defaults();
    let mb = cfg.memory_budget_mb();
    // Prod defaults: 1M shards x ~25 KiB each = ~24.4 GiB. Allow 5-30 GB range.
    assert!(
        (5_000..=30_000).contains(&mb),
        "prod_defaults budget {mb} MB outside expected 5000-30000 MB range"
    );
}

#[test]
fn coordinator_config_memory_budget_mb_rounds_up() {
    // A config that produces a non-MiB-aligned byte count should round up.
    let cfg = super::CoordinatorConfig::new(1, 1, 1, 1, 1, 1);
    let bytes = cfg.memory_budget();
    let mb = cfg.memory_budget_mb();
    let expected_mb = bytes.div_ceil(1 << 20);
    assert_eq!(mb, expected_mb);
}

#[test]
#[should_panic(expected = "CoordinatorConfig::memory_budget overflow: shard contribution")]
fn coordinator_config_memory_budget_overflow_panics_deterministically() {
    let cfg = super::CoordinatorConfig::new(usize::MAX, 1, 1, 1, 0, 0);
    let _ = cfg.memory_budget();
}

#[test]
#[should_panic(expected = "CoordinatorConfig::memory_budget overflow: per-shard base")]
fn coordinator_config_memory_budget_per_shard_add_overflow_panics_deterministically() {
    let cfg = super::CoordinatorConfig::new(1, 1, 1, 1, usize::MAX, 0);
    let _ = cfg.memory_budget();
}

#[test]
#[should_panic(expected = "CoordinatorConfig::memory_budget overflow: shard contribution")]
fn coordinator_config_memory_budget_mb_overflow_panics_deterministically() {
    let cfg = super::CoordinatorConfig::new(usize::MAX, 1, 1, 1, 0, 0);
    let _ = cfg.memory_budget_mb();
}

/// Validates that the planning constants in `memory_budget()` match
/// actual struct sizes on this platform. If this test fails, the
/// constants in `CoordinatorConfig::memory_budget()` need updating.
#[test]
fn memory_budget_constants_match_struct_sizes() {
    use super::ShardRecord;
    use crate::run::RunRecord;
    use std::mem::size_of;

    let shard_size = size_of::<ShardRecord>();
    let run_size = size_of::<RunRecord>();

    // The planning formula uses constants from in_memory.rs; keep them in
    // lockstep with the actual target layout.
    // Keep this test in lockstep with the implementation and docs.
    assert_eq!(
        shard_size,
        super::SHARD_RECORD_PLANNING_BYTES,
        "ShardRecord size changed from {} to {shard_size}; \
         update SHARD_RECORD_PLANNING_BYTES in CoordinatorConfig::memory_budget()",
        super::SHARD_RECORD_PLANNING_BYTES,
    );
    assert_eq!(
        run_size,
        super::RUN_RECORD_PLANNING_BYTES,
        "RunRecord size changed from {} to {run_size}; \
         update RUN_RECORD_PLANNING_BYTES in CoordinatorConfig::memory_budget()",
        super::RUN_RECORD_PLANNING_BYTES,
    );
}

// ============================================================================
// collect_claim_candidates_into tests
//
// These tests exercise the lightweight candidate collection method that the
// default claim path uses instead of list_shards_into.  It returns only
// ShardId values and the earliest lease deadline, avoiding ShardSummary
// construction and slab byte copies.
// ============================================================================

/// An Initializing run (no shards registered yet) returns empty candidates
/// and no deadline.
#[test]
fn collect_candidates_no_shards_registered() {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = test_run();
    let config =
        crate::run::RunConfig::try_new(CursorSemantics::Completed, LEASE_DURATION, None).unwrap();
    coord.create_run(now(1), tenant, run, config).unwrap();

    // Run exists but has zero shards (still Initializing).
    let mut candidates = Vec::new();
    let deadline = coord
        .collect_claim_candidates_into(now(2), tenant, run, &mut candidates)
        .unwrap();
    assert!(candidates.is_empty());
    assert_eq!(deadline, None);
}

/// Mixed states: available + leased + terminal. Only available IDs appear
/// in candidates; the earliest lease deadline is from the leased shard.
#[test]
fn collect_candidates_mixed_states() {
    use crate::run::RunConfig;
    use gossip_contracts::coordination::manifest::InitialShardInput;

    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let tenant = test_tenant();
    let run = test_run();
    let config = RunConfig::try_new(CursorSemantics::Completed, LEASE_DURATION, None).unwrap();
    coord.create_run(now(1), tenant, run, config).unwrap();

    // Register 3 shards.
    let specs: Vec<_> = (0u8..3)
        .map(|i| {
            (
                ShardId::from_raw(i as u64),
                gossip_contracts::coordination::shard_spec::ShardSpec::with_range(
                    vec![i * 10],
                    vec![i * 10 + 9],
                ),
                CursorUpdate::initial(),
            )
        })
        .collect();
    let shards: Vec<InitialShardInput<'_>> = specs
        .iter()
        .map(|(id, spec, cursor)| InitialShardInput::new(*id, spec.as_ref(), *cursor))
        .collect();
    let _ = coord
        .register_shards(now(1), tenant, run, &shards, OpId::from_raw(1))
        .unwrap();

    // Shard 0: acquire and complete (terminal Done).
    let key0 = ShardKey::new(run, ShardId::from_raw(0));
    let mut scratch = crate::error::AcquireScratch::new();
    let lease0 = coord
        .acquire_and_restore_into(now(2), tenant, key0, test_worker(1), &mut scratch)
        .unwrap()
        .lease;
    let _ = coord
        .complete(
            now(3),
            tenant,
            &lease0,
            &CursorUpdate::new(&[0x00]),
            OpId::from_raw(10),
        )
        .unwrap();

    // Shard 1: acquire (Active + leased at now(4), deadline = 4 + LEASE_DURATION).
    let key1 = ShardKey::new(run, ShardId::from_raw(1));
    let _ = coord
        .acquire_and_restore_into(now(4), tenant, key1, test_worker(2), &mut scratch)
        .unwrap();

    // Shard 2: remains Active + unleased.

    let shard_count = coord
        .run_shards
        .get(&(tenant, run))
        .map_or(0, |ids| ids.len());
    let mut candidates = Vec::with_capacity(shard_count);
    let deadline = coord
        .collect_claim_candidates_into(now(5), tenant, run, &mut candidates)
        .unwrap();

    // Only shard 2 should appear (Active + unleased).
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0], ShardId::from_raw(2));

    // Deadline should reflect shard 1's lease.
    assert_eq!(deadline, Some(now(4 + LEASE_DURATION)));

    // Terminal shard 0 must not appear.
    assert!(!candidates.contains(&ShardId::from_raw(0)));
    // Leased shard 1 must not appear as candidate.
    assert!(!candidates.contains(&ShardId::from_raw(1)));
}

/// All shards leased: empty candidates, earliest deadline populated.
#[test]
fn collect_candidates_all_leased() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let tenant = test_tenant();
    let run = test_run();

    // The fixture has shard 0, Active + leased at now(3) with duration=30 → deadline=33.
    let shard_count = coord
        .run_shards
        .get(&(tenant, run))
        .map_or(0, |ids| ids.len());
    let mut candidates = Vec::with_capacity(shard_count);
    let deadline = coord
        .collect_claim_candidates_into(now(4), tenant, run, &mut candidates)
        .unwrap();

    assert!(candidates.is_empty(), "all leased → no candidates");
    assert_eq!(
        deadline,
        Some(now(3 + LEASE_DURATION)),
        "should report the lease deadline"
    );
}

/// Buffer reuse: capacity is preserved across calls.
#[test]
fn collect_candidates_buffer_reuse() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let tenant = test_tenant();
    let run = test_run();

    let shard_count = coord
        .run_shards
        .get(&(tenant, run))
        .map_or(0, |ids| ids.len());
    let mut candidates = Vec::with_capacity(shard_count + 10);
    let initial_capacity = candidates.capacity();

    // Call once (all leased at now(4), deadline = 3 + LEASE_DURATION).
    let _ = coord
        .collect_claim_candidates_into(now(4), tenant, run, &mut candidates)
        .unwrap();
    assert_eq!(
        candidates.capacity(),
        initial_capacity,
        "capacity must not change"
    );

    // Call again after lease expiry.
    let after_expiry = 3 + LEASE_DURATION + 1;
    let _ = coord
        .collect_claim_candidates_into(now(after_expiry), tenant, run, &mut candidates)
        .unwrap();
    assert_eq!(
        candidates.capacity(),
        initial_capacity,
        "capacity must not change on second call"
    );
    assert_eq!(
        candidates.len(),
        1,
        "shard should be available after expiry"
    );
}

/// collect_claim_candidates_into grows an undersized caller buffer instead of panicking.
#[test]
fn collect_candidates_grow_undersized_buffer() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let tenant = test_tenant();
    let run = test_run();

    let mut candidates = Vec::new();
    assert_eq!(candidates.capacity(), 0, "test precondition");

    let _deadline = coord
        .collect_claim_candidates_into(now(LEASE_DURATION + 10), tenant, run, &mut candidates)
        .unwrap();

    assert_eq!(candidates.len(), 1);
    assert!(
        candidates.capacity() >= 1,
        "buffer should grow to hold at least one candidate"
    );
}

/// RunNotFound error for nonexistent run.
#[test]
fn collect_candidates_run_not_found() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let mut candidates = Vec::new();
    let result = coord.collect_claim_candidates_into(
        now(2),
        test_tenant(),
        gossip_contracts::identity::RunId::from_raw(999),
        &mut candidates,
    );
    assert!(matches!(
        result,
        Err(crate::run_errors::GetRunError::RunNotFound)
    ));
}

/// TenantMismatch error for wrong tenant.
#[test]
fn collect_candidates_tenant_mismatch() {
    let (coord, _lease) = coordinator_with_run_and_lease();
    let wrong_tenant = gossip_contracts::identity::TenantId::from_bytes([0xFF; 32]);
    let mut candidates = Vec::new();
    let result =
        coord.collect_claim_candidates_into(now(2), wrong_tenant, test_run(), &mut candidates);
    // InMemoryCoordinator keys by (tenant, run), so wrong tenant → RunNotFound.
    assert!(matches!(
        result,
        Err(crate::run_errors::GetRunError::RunNotFound)
    ));
}
