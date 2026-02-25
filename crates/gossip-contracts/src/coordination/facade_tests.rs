//! Tests for the [`CoordinationFacade`] super-trait, the [`ShardClaiming`]
//! trait, and the [`default_claim_next_available`] free function.
//!
//! The claim algorithm uses a two-step scan-then-acquire pattern: it collects
//! available (active, unleased) shard IDs from the backend, then tries to
//! acquire each candidate sequentially. Because the fencing protocol in
//! `acquire_and_restore_into` guarantees at-most-one winner per shard, the TOCTOU
//! gap between scan and acquire is safe — losers advance to the next
//! candidate.
//!
//! # Coverage Areas
//!
//! - **Happy path**: single claim, sequential exhaustion, claim after lease
//!   expiry, skipping terminal and already-leased shards.
//! - **Error mapping**: `ClaimError::from(GetRunError)` conversions,
//!   `RunNotFound`, `TenantMismatch`, `NoneAvailable` with
//!   `earliest_deadline` reporting.
//! - **Cooldown enforcement**: per-worker throttling across runs, boundary
//!   timing, isolation between workers, priority over downstream errors,
//!   overflow saturation, and the deliberate bypass on direct
//!   `acquire_and_restore_into`.
//! - **Property tests**: random shard/lease mixes, mixed terminal/leased
//!   states, expired lease reclamation, and cooldown invariant validation
//!   across random timestamp sequences.
//! - **Trait wiring**: compile-time proof that `InMemoryCoordinator`
//!   satisfies `CoordinationFacade`.

use super::*;
use crate::coordination::cursor::CursorUpdate;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::run::{InitialShardInput, RunConfig, RunManagement};
use crate::coordination::shard_spec::CursorSemantics;
use crate::coordination::test_fixtures::{now, test_run, test_tenant, test_worker};
use crate::identity::{OpId, ShardId};
use crate::test_util::miri_proptest_config;
use proptest::prelude::*;
use rstest::rstest;

fn test_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
}

fn claim_lease(
    coord: &mut InMemoryCoordinator,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
) -> Result<crate::coordination::Lease, ClaimError> {
    let mut scratch = crate::coordination::AcquireScratch::new();
    coord
        .claim_next_available(now, tenant, run, worker, &mut scratch)
        .map(|result| result.lease)
}

fn acquire_lease(
    coord: &mut InMemoryCoordinator,
    now: LogicalTime,
    tenant: TenantId,
    key: ShardKey,
    worker: WorkerId,
) -> Result<crate::coordination::Lease, crate::coordination::AcquireError> {
    let mut scratch = crate::coordination::AcquireScratch::new();
    coord
        .acquire_and_restore_into(now, tenant, key, worker, &mut scratch)
        .map(|result| result.lease)
}

/// Populate the coordinator with a run and `shard_count` shards.
///
/// Each shard covers a single-byte range `[i, i+1)`. The run uses a 30-tick
/// lease duration and `CursorSemantics::Completed`.
fn populate_run(coord: &mut InMemoryCoordinator, shard_count: usize) {
    let tenant = test_tenant();
    let run = test_run();
    let config = test_run_config();

    coord.create_run(now(1), tenant, run, config).unwrap();

    let shard_entries: Vec<_> = (0..shard_count)
        .map(|i| {
            let start = vec![i as u8];
            let end = vec![(i + 1) as u8];
            (
                ShardId::from_raw(i as u64),
                crate::coordination::shard_spec::ShardSpec::with_range(start, end),
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
}

/// Set up a coordinator with a run containing `shard_count` shards.
///
/// Returns the coordinator ready for claim operations. Shards are registered
/// at `now(1)`, so claim operations should use `now(2)` or later.
fn setup_coordinator(shard_count: usize) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(30);
    populate_run(&mut coord, shard_count);
    coord
}

// ============================================================================
// Basic claim operations
//
// Each test verifies one aspect of the claim algorithm: success, exhaustion,
// skipping occupied shards, nonexistent runs, sequential claiming, and
// reclamation after lease expiry.
// ============================================================================

/// Claiming on a run with available shards succeeds and returns a lease
/// scoped to the correct run.
#[test]
fn claim_next_available_ok() {
    let mut coord = setup_coordinator(2);
    let result = claim_lease(
        &mut coord,
        now(2),
        test_tenant(),
        test_run(),
        test_worker(1),
    );
    assert!(result.is_ok());
    let acquire = result.unwrap();
    assert_eq!(acquire.run(), test_run());
}

/// When the only shard is already leased, `claim_next_available` returns
/// `NoneAvailable` rather than blocking or returning a stale result.
#[test]
fn claim_none_available() {
    let mut coord = setup_coordinator(1);
    // Manually acquire the only shard.
    let key = ShardKey::new(test_run(), ShardId::from_raw(0));
    let _ = acquire_lease(&mut coord, now(2), test_tenant(), key, test_worker(1)).unwrap();

    let result = claim_lease(
        &mut coord,
        now(3),
        test_tenant(),
        test_run(),
        test_worker(2),
    );
    assert!(matches!(result, Err(ClaimError::NoneAvailable { .. })));
}

/// The claim algorithm iterates candidates sequentially; if shard 0 is
/// already leased, shard 1 is returned instead. This verifies the
/// list-then-acquire loop correctly advances past occupied shards.
#[test]
fn claim_skips_already_leased() {
    let mut coord = setup_coordinator(2);
    // Acquire shard 0 manually.
    let key0 = ShardKey::new(test_run(), ShardId::from_raw(0));
    let _ = acquire_lease(&mut coord, now(2), test_tenant(), key0, test_worker(1)).unwrap();

    // claim_next_available should skip shard 0 and get shard 1.
    let result = claim_lease(
        &mut coord,
        now(3),
        test_tenant(),
        test_run(),
        test_worker(2),
    );
    assert!(result.is_ok());
    let acquire = result.unwrap();
    assert_eq!(acquire.shard(), ShardId::from_raw(1));
}

/// Claiming against a nonexistent run surfaces `RunNotFound` immediately
/// rather than attempting any shard-level operations.
#[test]
fn claim_run_not_found() {
    let mut coord = InMemoryCoordinator::new(30);
    let result = claim_lease(
        &mut coord,
        now(1),
        test_tenant(),
        RunId::from_raw(999),
        test_worker(1),
    );
    assert_eq!(result, Err(ClaimError::RunNotFound));
}

/// Three sequential claims on a 3-shard run produce three distinct leases;
/// a fourth claim returns `NoneAvailable`. Verifies the claim algorithm
/// tracks which shards have been assigned and exhausts them correctly.
#[test]
fn claim_all_sequential() {
    let mut coord = setup_coordinator(3);
    let tenant = test_tenant();
    let run = test_run();

    let r1 = claim_lease(&mut coord, now(2), tenant, run, test_worker(1)).unwrap();
    let r2 = claim_lease(&mut coord, now(3), tenant, run, test_worker(2)).unwrap();
    let r3 = claim_lease(&mut coord, now(4), tenant, run, test_worker(3)).unwrap();

    // All three claims must produce distinct shards.
    let mut shards = vec![r1.shard(), r2.shard(), r3.shard()];
    shards.sort();
    shards.dedup();
    assert_eq!(shards.len(), 3);

    // Fourth claim fails.
    let r4 = claim_lease(&mut coord, now(5), tenant, run, test_worker(4));
    assert!(matches!(r4, Err(ClaimError::NoneAvailable { .. })));
}

/// Compile-time proof that `InMemoryCoordinator` satisfies the
/// `CoordinationFacade` super-trait bound (backend + run mgmt + claiming).
#[test]
fn facade_trait_compiles() {
    fn requires_facade<B: CoordinationFacade>(_: &mut B) {}
    let mut coord = InMemoryCoordinator::new(30);
    requires_facade(&mut coord);
}

/// After a lease expires, the shard becomes available again. A new worker
/// can claim it and receives a fresh lease with its own identity. This is
/// the fundamental liveness property: stalled workers do not permanently
/// block shards.
#[test]
fn claim_after_lease_expiry() {
    let mut coord = setup_coordinator(1);
    let tenant = test_tenant();
    let run = test_run();

    // Claim the only shard.
    let _ = claim_lease(&mut coord, now(2), tenant, run, test_worker(1)).unwrap();

    // Advance time past the lease deadline (lease_duration=30).
    // now=2 + 30 = deadline at 32. At now=33, lease is expired.
    let result = claim_lease(&mut coord, now(33), tenant, run, test_worker(2));
    assert!(result.is_ok());
    let acquire = result.unwrap();
    assert_eq!(acquire.owner(), test_worker(2));
}

/// Completed (Done) shards are terminal and must not be returned by the
/// claim algorithm. After completing shard 0, claiming should skip it
/// and return shard 1.
#[test]
fn claim_skips_terminal() {
    let mut coord = setup_coordinator(2);
    let tenant = test_tenant();
    let run = test_run();

    // Acquire shard 0 and complete it (terminal).
    let key0 = ShardKey::new(run, ShardId::from_raw(0));
    let acquire = acquire_lease(&mut coord, now(2), tenant, key0, test_worker(1)).unwrap();
    let cursor = CursorUpdate::new(&[0x00]);
    let _ = coord
        .complete(now(3), tenant, &acquire, &cursor, OpId::from_raw(200))
        .unwrap();

    // claim_next_available should skip the completed shard and get shard 1.
    let result = claim_lease(&mut coord, now(4), tenant, run, test_worker(2));
    assert!(result.is_ok());
    let r = result.unwrap();
    assert_eq!(r.shard(), ShardId::from_raw(1));
}

/// When all shards are leased, `earliest_deadline` should be populated
/// so callers can schedule a retry near the soonest lease expiry.
#[test]
fn claim_all_leased_reports_earliest_deadline() {
    let mut coord = setup_coordinator(2);
    let tenant = test_tenant();
    let run = test_run();

    // Lease both shards at now=10 (lease_duration=30 → deadline=40).
    let key0 = ShardKey::new(run, ShardId::from_raw(0));
    let _ = acquire_lease(&mut coord, now(10), tenant, key0, test_worker(1)).unwrap();

    // Lease second shard at now=15 (deadline=45).
    let key1 = ShardKey::new(run, ShardId::from_raw(1));
    let _ = acquire_lease(&mut coord, now(15), tenant, key1, test_worker(2)).unwrap();

    // All shards leased — claim should fail with earliest_deadline = Some(40).
    let result = claim_lease(&mut coord, now(20), tenant, run, test_worker(3));
    match result {
        Err(ClaimError::NoneAvailable { earliest_deadline }) => {
            assert_eq!(
                earliest_deadline,
                Some(now(40)),
                "should report earliest lease deadline so callers can schedule retry"
            );
        }
        other => panic!("expected NoneAvailable, got {other:?}"),
    }
}

// -- TenantMismatch test -----------------------------------------------

/// Claiming with a wrong tenant is rejected immediately.
///
/// The in-memory coordinator keys runs by `(TenantId, RunId)`, so
/// a wrong tenant surfaces as `RunNotFound` (the run does not
/// exist under that tenant). Backends that key by `RunId` alone
/// would return `TenantMismatch` instead — both prevent
/// cross-tenant shard access.
#[test]
fn claim_wrong_tenant_rejected() {
    let mut coord = setup_coordinator(2);
    let wrong_tenant = TenantId::from_bytes([0x02; 32]);

    let result = claim_lease(&mut coord, now(2), wrong_tenant, test_run(), test_worker(1));
    assert!(result.is_err(), "cross-tenant claim must not succeed");
    // InMemoryCoordinator keys runs by (tenant, run) — wrong
    // tenant means the run is not found under that tenant.
    assert_eq!(result, Err(ClaimError::RunNotFound));
}

// -- From<GetRunError> conversion tests --------------------------------

#[rstest]
#[case::tenant_mismatch(
    GetRunError::TenantMismatch { expected: test_tenant() },
    ClaimError::TenantMismatch { expected: test_tenant() },
)]
#[case::run_not_found(GetRunError::RunNotFound, ClaimError::RunNotFound)]
fn claim_error_from_get_run_error(#[case] input: GetRunError, #[case] expected: ClaimError) {
    let result: ClaimError = input.into();
    assert_eq!(result, expected);
}

// -- Property tests --------------------------------------------------

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// Claiming only returns shards that are available; once all shards
    /// are leased, claiming returns `NoneAvailable`.
    #[test]
    fn claim_never_returns_unavailable_shard(
        shard_count in 1_usize..=8,
        num_leased in 0_usize..=8,
    ) {
        let num_leased = num_leased.min(shard_count);
        let mut coord = setup_coordinator(shard_count);
        let tenant = test_tenant();
        let run = test_run();

        // Lease the first `num_leased` shards.
        for i in 0..num_leased {
            let key = ShardKey::new(run, ShardId::from_raw(i as u64));
            let _ = acquire_lease(&mut coord, now(2), tenant, key, test_worker(100 + i as u64))
                .unwrap();
        }

        let result = claim_lease(&mut coord, now(3), tenant, run, test_worker(999));

        if num_leased == shard_count {
            let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
            prop_assert!(is_none_available, "expected NoneAvailable");
        } else {
            let acq = result.unwrap();
            let claimed = acq.shard().as_raw();
            // Must not be one of the leased shards.
            prop_assert!(claimed >= num_leased as u64);
        }
    }

    /// Mixed shard states: Done + leased + available.
    /// Claim must skip Done and leased shards and return an available one,
    /// or `NoneAvailable` if none remain.
    #[test]
    fn claim_skips_terminal_and_leased_shards(
        shard_count in 2_usize..=8,
        num_done in 0_usize..=4,
        num_leased in 0_usize..=4,
    ) {
        let num_done = num_done.min(shard_count);
        let num_leased = num_leased.min(shard_count - num_done);
        let mut coord = setup_coordinator(shard_count);
        let tenant = test_tenant();
        let run = test_run();

        // Complete first `num_done` shards (Done/terminal).
        for i in 0..num_done {
            let key = ShardKey::new(run, ShardId::from_raw(i as u64));
            let acq = acquire_lease(&mut coord, now(2), tenant, key, test_worker(200 + i as u64))
                .unwrap();
            let key = [i as u8];
            let cursor = CursorUpdate::new(&key);
            let _ = coord
                .complete(now(3), tenant, &acq, &cursor, OpId::from_raw(300 + i as u64))
                .unwrap();
        }

        // Lease the next `num_leased` shards (Active + leased).
        for i in 0..num_leased {
            let idx = num_done + i;
            let key = ShardKey::new(run, ShardId::from_raw(idx as u64));
            let _ = acquire_lease(&mut coord, now(4), tenant, key, test_worker(400 + i as u64))
                .unwrap();
        }

        let available = shard_count - num_done - num_leased;
        let result = claim_lease(&mut coord, now(5), tenant, run, test_worker(999));

        if available == 0 {
            let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
            prop_assert!(is_none_available, "expected NoneAvailable");
        } else {
            let acq = result.unwrap();
            let claimed = acq.shard().as_raw() as usize;
            // Must be one of the available (unleased, non-terminal) shards.
            prop_assert!(claimed >= num_done + num_leased);
            prop_assert!(claimed < shard_count);
        }
    }

    /// Expired leases free shards for re-claiming.
    #[test]
    fn claim_reclaims_expired_leases(
        shard_count in 1_usize..=4,
    ) {
        let mut coord = setup_coordinator(shard_count);
        let tenant = test_tenant();
        let run = test_run();

        // Lease all shards at now=2 (lease_duration=30).
        for i in 0..shard_count {
            let key = ShardKey::new(run, ShardId::from_raw(i as u64));
            let _ = acquire_lease(&mut coord, now(2), tenant, key, test_worker(100 + i as u64))
                .unwrap();
        }

        // At now=3, all leased — claim fails.
        let result = claim_lease(&mut coord, now(3), tenant, run, test_worker(999));
        let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
        prop_assert!(is_none_available, "expected NoneAvailable");

        // Advance past lease expiry (lease_duration=30, so deadline=32).
        // At now=33, all leases expired — claim succeeds.
        let result = claim_lease(&mut coord, now(33), tenant, run, test_worker(888));
        prop_assert!(result.is_ok(), "claim should succeed after lease expiry");
        let acq = result.unwrap();
        prop_assert_eq!(acq.owner(), test_worker(888));
    }
}

// ============================================================================
// Claim cooldown tests
//
// Cooldown is a per-worker rate limiter on `claim_next_available`. After a
// successful claim, the same worker is blocked from claiming again until
// `now >= last_success + cooldown_interval`. The gate fires before run
// lookup or candidate scanning, giving `Throttled` priority over
// `RunNotFound` and `NoneAvailable`. Failed claims do not trigger cooldown.
// ============================================================================

/// Helper: set up a coordinator with cooldown enabled and `shard_count` shards.
fn setup_coordinator_with_cooldown(
    shard_count: usize,
    cooldown_interval: u64,
) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::with_cooldown(30, 100_000, 1_000_000, cooldown_interval);
    populate_run(&mut coord, shard_count);
    coord
}

/// Single-worker cooldown timing: after a successful claim at `first_t`,
/// a second claim at `second_t` is either throttled or succeeds depending
/// on whether `second_t >= first_t + cooldown`.
///
/// `expect_throttled_until` is `Some(deadline)` when the second claim should
/// return `Throttled { retry_after: deadline }`, or `None` when it should
/// succeed.
#[rstest]
#[case::throttled_within_window(5, 3, 10, 11, Some(15))]
#[case::succeeds_at_boundary(5, 3, 10, 15, None)]
#[case::disabled_with_zero(0, 3, 10, 10, None)]
#[case::retry_after_tracks_interval(7, 3, 20, 25, Some(27))]
fn claim_cooldown_single_worker(
    #[case] cooldown: u64,
    #[case] shard_count: usize,
    #[case] first_t: u64,
    #[case] second_t: u64,
    #[case] expect_throttled_until: Option<u64>,
) {
    let mut coord = setup_coordinator_with_cooldown(shard_count, cooldown);
    let tenant = test_tenant();
    let run = test_run();
    let worker = test_worker(1);

    let r1 = claim_lease(&mut coord, now(first_t), tenant, run, worker);
    assert!(r1.is_ok(), "first claim should succeed: {r1:?}");

    let r2 = claim_lease(&mut coord, now(second_t), tenant, run, worker);
    match expect_throttled_until {
        Some(deadline) => {
            assert!(
                matches!(r2, Err(ClaimError::Throttled { retry_after }) if retry_after == now(deadline)),
                "expected Throttled with retry_after={deadline}, got {r2:?}"
            );
        }
        None => {
            assert!(r2.is_ok(), "expected success, got {r2:?}");
        }
    }
}

/// Failed claims (NoneAvailable) must not start a cooldown timer. Worker 2
/// gets NoneAvailable twice in a row without being throttled, proving that
/// only *successful* claims trigger cooldown.
#[test]
fn claim_cooldown_not_triggered_on_failure() {
    let mut coord = setup_coordinator_with_cooldown(1, 5);
    let tenant = test_tenant();
    let run = test_run();

    // Worker 1 claims the only shard at now=10.
    assert!(claim_lease(&mut coord, now(10), tenant, run, test_worker(1)).is_ok());

    // Worker 2 tries at now=10 — fails with NoneAvailable (not Throttled).
    let r1 = claim_lease(&mut coord, now(10), tenant, run, test_worker(2));
    assert!(
        matches!(r1, Err(ClaimError::NoneAvailable { .. })),
        "expected NoneAvailable, got {r1:?}"
    );

    // Worker 2 retries immediately at now=11 — still NoneAvailable, not Throttled.
    let r2 = claim_lease(&mut coord, now(11), tenant, run, test_worker(2));
    assert!(
        matches!(r2, Err(ClaimError::NoneAvailable { .. })),
        "failed claims should not trigger cooldown, got {r2:?}"
    );
}

/// Cooldown timers are per-worker: worker 2 can claim immediately after
/// worker 1, even though worker 1 is in cooldown. Worker 1's subsequent
/// attempt is correctly throttled while worker 2 is unaffected.
#[test]
fn claim_cooldown_per_worker_isolation() {
    let mut coord = setup_coordinator_with_cooldown(3, 5);
    let tenant = test_tenant();
    let run = test_run();

    // Worker 1 claims at now=10.
    assert!(claim_lease(&mut coord, now(10), tenant, run, test_worker(1)).is_ok());

    // Worker 2 claims at now=11 — succeeds (not affected by worker 1's cooldown).
    let r2 = claim_lease(&mut coord, now(11), tenant, run, test_worker(2));
    assert!(
        r2.is_ok(),
        "worker 2 should not be affected by worker 1's cooldown, got {r2:?}"
    );

    // Worker 1 tries at now=12 — throttled.
    let r3 = claim_lease(&mut coord, now(12), tenant, run, test_worker(1));
    assert!(
        matches!(r3, Err(ClaimError::Throttled { .. })),
        "worker 1 should be throttled, got {r3:?}"
    );
}

/// Cooldown spans across runs: a successful claim in run A puts the worker
/// in cooldown for run B too. This prevents a worker from flooding the
/// coordinator by rapidly cycling through runs.
#[test]
fn claim_cooldown_spans_runs() {
    // Cooldown is per-worker, not per-run: a successful claim in run A
    // puts the worker in cooldown for run B too.
    let mut coord = InMemoryCoordinator::with_cooldown(30, 100_000, 1_000_000, 5);
    let tenant = test_tenant();
    let run_a = RunId::from_raw(1);
    let run_b = RunId::from_raw(2);
    let config = test_run_config();

    // Create run A with one shard.
    coord.create_run(now(1), tenant, run_a, config).unwrap();
    let spec_a = crate::coordination::shard_spec::ShardSpec::with_range(vec![0], vec![1]);
    let cursor_a = CursorUpdate::initial();
    let shards_a = vec![InitialShardInput::new(
        ShardId::from_raw(0),
        spec_a.as_ref(),
        cursor_a,
    )];
    let _ = coord
        .register_shards(now(1), tenant, run_a, &shards_a, OpId::from_raw(100))
        .unwrap();

    // Create run B with one shard (different shard ID).
    coord.create_run(now(1), tenant, run_b, config).unwrap();
    let spec_b = crate::coordination::shard_spec::ShardSpec::with_range(vec![10], vec![11]);
    let cursor_b = CursorUpdate::initial();
    let shards_b = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec_b.as_ref(),
        cursor_b,
    )];
    let _ = coord
        .register_shards(now(1), tenant, run_b, &shards_b, OpId::from_raw(101))
        .unwrap();

    // Worker claims in run A at t=10.
    assert!(
        claim_lease(&mut coord, now(10), tenant, run_a, test_worker(1)).is_ok(),
        "initial claim in run A should succeed"
    );

    // Same worker tries run B at t=12 (within cooldown window of 5) — Throttled.
    let r = claim_lease(&mut coord, now(12), tenant, run_b, test_worker(1));
    assert!(
        matches!(r, Err(ClaimError::Throttled { .. })),
        "cooldown should span runs, got {r:?}"
    );

    // After cooldown elapses (t=15), run B claim succeeds.
    let r2 = claim_lease(&mut coord, now(15), tenant, run_b, test_worker(1));
    assert!(
        r2.is_ok(),
        "after cooldown elapses, cross-run claim should succeed, got {r2:?}"
    );
}

/// The `Display` impl for `Throttled` includes both the "throttled" keyword
/// and the numeric retry-after value, so log messages are actionable.
#[test]
fn claim_error_throttled_display() {
    let err = ClaimError::Throttled {
        retry_after: LogicalTime::from_raw(42),
    };
    let display = err.to_string();
    assert!(
        display.contains("throttled"),
        "Display should mention 'throttled', got: {display}"
    );
    assert!(
        display.contains("42"),
        "Display should mention retry_after value, got: {display}"
    );
}

proptest! {
    #![proptest_config(miri_proptest_config())]

    /// Across random claim sequences, no successful claim occurs within
    /// the cooldown window of the previous success for the same worker.
    #[test]
    fn claim_cooldown_invariant_holds(
        cooldown_interval in 1u64..=20,
        shard_count in 2usize..=6,
        timestamps in proptest::collection::vec(1u64..=100, 2..15),
    ) {
        let mut coord = setup_coordinator_with_cooldown(shard_count, cooldown_interval);
        let tenant = test_tenant();
        let run = test_run();
        let worker = test_worker(1);
        let mut last_success: Option<u64> = None;

        for &t in &timestamps {
            let result = claim_lease(&mut coord, now(t), tenant, run, worker);
            match result {
                Ok(_) => {
                    if let Some(prev) = last_success {
                        prop_assert!(
                            t >= prev + cooldown_interval,
                            "successful claim at t={t} within cooldown of prev={prev} + interval={cooldown_interval}"
                        );
                    }
                    last_success = Some(t);
                }
                Err(ClaimError::Throttled { retry_after }) => {
                    if let Some(prev) = last_success {
                        prop_assert_eq!(
                            retry_after,
                            now(prev + cooldown_interval),
                            "retry_after should be last_success + interval"
                        );
                    }
                }
                Err(ClaimError::NoneAvailable { .. }) => {
                    // Exhausted shards — not a cooldown issue.
                }
                Err(other) => {
                    prop_assert!(false, "unexpected error: {other:?}");
                }
            }
        }
    }
}

/// Cooldown gate fires before the run lookup, so `Throttled` takes
/// priority over `RunNotFound` when a worker is in cooldown and
/// targets a nonexistent run.
#[test]
fn claim_cooldown_takes_priority_over_run_not_found() {
    let mut coord = setup_coordinator_with_cooldown(3, 5);
    let tenant = test_tenant();
    let run = test_run();

    // Claim successfully at t=10 to start cooldown.
    assert!(claim_lease(&mut coord, now(10), tenant, run, test_worker(1)).is_ok());

    // Try to claim from a nonexistent run while in cooldown.
    let bogus_run = RunId::from_raw(999);
    let r = claim_lease(&mut coord, now(11), tenant, bogus_run, test_worker(1));
    assert!(
        matches!(r, Err(ClaimError::Throttled { .. })),
        "cooldown gate should reject before run lookup, got {r:?}"
    );
}

/// Cooldown gate fires before the candidate scan, so `Throttled` takes
/// priority over `NoneAvailable` when a worker is in cooldown and all
/// shards are already leased.
#[test]
fn claim_cooldown_takes_priority_over_none_available() {
    let mut coord = setup_coordinator_with_cooldown(1, 5);
    let tenant = test_tenant();
    let run = test_run();

    // Worker 1 claims the only shard at t=10.
    assert!(claim_lease(&mut coord, now(10), tenant, run, test_worker(1)).is_ok());

    // Worker 1 retries at t=11: in cooldown (10+5=15 > 11) AND no shards
    // available (the only shard is leased). Cooldown fires first -> Throttled.
    let r = claim_lease(&mut coord, now(11), tenant, run, test_worker(1));
    assert!(
        matches!(r, Err(ClaimError::Throttled { retry_after }) if retry_after == now(15)),
        "cooldown should take priority over NoneAvailable, got {r:?}"
    );
}

/// When the cooldown interval is `u64::MAX`, `checked_add` overflows
/// and the implementation saturates the deadline to `u64::MAX`,
/// effectively creating a permanent cooldown. This test pins the
/// saturation behavior at the boundary.
#[test]
fn claim_cooldown_overflow_saturates_to_permanent() {
    // With cooldown = u64::MAX, checked_add(10, u64::MAX) overflows
    // and saturates to u64::MAX (effectively permanent cooldown).
    //
    // Construct manually because the `setup_coordinator_with_cooldown`
    // helper uses `default_lease_duration=30`, and the debug_assert in
    // `with_cooldown` requires `cooldown <= lease_duration`.
    let mut coord = InMemoryCoordinator::with_cooldown(u64::MAX, 100_000, 1_000_000, u64::MAX);
    let tenant = test_tenant();
    let run = test_run();
    let config = test_run_config();

    coord.create_run(now(1), tenant, run, config).unwrap();

    let shard_entries: Vec<_> = (0..3)
        .map(|i| {
            let start = vec![i as u8];
            let end = vec![(i + 1) as u8];
            (
                ShardId::from_raw(i as u64),
                crate::coordination::shard_spec::ShardSpec::with_range(start, end),
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

    // First claim succeeds at t=10.
    assert!(claim_lease(&mut coord, now(10), tenant, run, test_worker(1)).is_ok());

    // At any time < u64::MAX, worker is throttled (saturated deadline).
    let r = claim_lease(
        &mut coord,
        LogicalTime::from_raw(u64::MAX - 1),
        tenant,
        run,
        test_worker(1),
    );
    assert!(
        matches!(r, Err(ClaimError::Throttled { .. })),
        "with saturated deadline, times < u64::MAX should be throttled, got {r:?}"
    );

    // At exactly now == u64::MAX == retry_after, boundary convention
    // says cooldown elapsed (now >= deadline), so worker passes through.
    let r2 = claim_lease(
        &mut coord,
        LogicalTime::from_raw(u64::MAX),
        tenant,
        run,
        test_worker(1),
    );
    assert!(
        r2.is_ok() || matches!(r2, Err(ClaimError::NoneAvailable { .. })),
        "at now=u64::MAX with saturated deadline, worker should pass cooldown gate, got {r2:?}"
    );
}

/// Cooldown is enforced only in `claim_next_available`, not in direct
/// `acquire_and_restore_into` calls. This is intentional: cooldown gates the
/// high-level claiming facade, while direct acquire targets a known shard.
#[test]
fn cooldown_not_enforced_on_direct_acquire() {
    let mut coord = setup_coordinator_with_cooldown(3, 10);
    let tenant = test_tenant();
    let run = test_run();
    let worker = test_worker(1);

    // Claim via facade at t=10 — puts worker in cooldown until t=20.
    let _ = claim_lease(&mut coord, now(10), tenant, run, worker).expect("first claim succeeds");

    // Verify cooldown is active for the facade path.
    assert!(
        matches!(
            claim_lease(&mut coord, now(12), tenant, run, worker),
            Err(ClaimError::Throttled { .. })
        ),
        "facade path should be throttled"
    );

    // Direct acquire_and_restore_into on a different shard is NOT gated by cooldown.
    // We created 3 shards (IDs 0..3); target shard 1 which wasn't claimed above.
    let other_shard = ShardKey::new(run, ShardId::from_raw(1));
    let direct = acquire_lease(&mut coord, now(12), tenant, other_shard, worker);
    // Should succeed or fail for shard-state reasons, never for cooldown.
    assert!(
        !matches!(direct, Err(ref e) if format!("{e:?}").contains("Throttled")),
        "direct acquire must not enforce cooldown, got {direct:?}"
    );
}
