//! Shard claiming and the [`CoordinationFacade`] super-trait.
//!
//! The orchestrator needs a single type bound that grants access to
//! shard lifecycle (`CoordinationBackend`), run management
//! (`RunManagement`), **and** shard assignment (`ShardClaiming`).
//! This module provides that bound as `CoordinationFacade`, plus a
//! default shard-claiming algorithm that any backend gets for free.
//!
//! ## Trait Hierarchy
//!
//! ```text
//! CoordinationFacade
//!   ├── CoordinationBackend  (traits.rs: shard lifecycle)
//!   ├── RunManagement        (run.rs: run lifecycle + admin)
//!   └── ShardClaiming        (this file: shard assignment)
//! ```
//!
//! `ShardClaiming` has a blanket impl for any `T: CoordinationBackend
//! + RunManagement`. Its sole method, [`ShardClaiming::claim_next_available`],
//! has a default body that composes `list_shards(available)` with
//! `acquire_and_restore` in a retry loop.
//!
//! The blanket impl means individual backends cannot provide their own
//! `ShardClaiming` impl (Rust coherence). To supply a custom claim
//! strategy, the orchestration layer can call the free function
//! `default_claim_next_available` and add optimized logic around it.
//!
//! ## Design Rationale
//!
//! The default claim algorithm deliberately uses a two-step
//! list-then-acquire pattern rather than requiring an atomic
//! "claim next" primitive from every backend. This keeps the
//! `CoordinationBackend` trait minimal (no claim-specific method)
//! while still being correct under concurrency -- the fencing
//! protocol in `acquire_and_restore` ensures at most one worker
//! succeeds for any given shard, so the TOCTOU gap between list
//! and acquire is safe (losers simply retry the next candidate).
//!
//! The default logic is also exposed as the free function
//! [`default_claim_next_available`] so orchestration layers that
//! implement a custom claim path can delegate to it as a fallback.

use std::fmt;

use crate::coordination::error::{AcquireError, AcquireResult};
use crate::coordination::run::{RunManagement, ShardFilter};
use crate::coordination::run_errors::GetRunError;
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{LogicalTime, RunId, ShardKey, TenantId, WorkerId};

// ============================================================================
// ClaimError
// ============================================================================

/// Error returned by [`ShardClaiming::claim_next_available`].
///
/// `ClaimError` is intentionally coarser than [`AcquireError`]: transient
/// race conditions (`AlreadyLeased`, `ShardTerminal`, `ShardNotFound`)
/// are absorbed by the retry loop and surface as `NoneAvailable` only
/// when *every* candidate has been exhausted. This keeps callers from
/// needing to distinguish between "no shards exist" and "all shards
/// were grabbed by other workers" -- both mean "try again later."
///
/// ## Error mapping
///
/// The [`From<GetRunError>`] impl maps run-lookup failures 1:1 into
/// claim errors. The impl enumerates variants explicitly (no wildcard
/// `_` arm) so that adding a new `GetRunError` variant forces a
/// compile-time decision about how it maps at the claim level.
///
/// ## Security
///
/// `TenantMismatch` only exposes `expected` -- the caller's own tenant.
/// The actual tenant stored on the run record is deliberately omitted
/// to prevent cross-tenant enumeration.
///
/// [`AcquireError`]: crate::coordination::error::AcquireError
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ClaimError {
    /// No available (active, unleased) shards exist for this run, or
    /// all candidates were claimed by concurrent workers before this
    /// caller could acquire one.
    NoneAvailable,
    /// The run does not exist in the coordination store.
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed to
    /// prevent cross-tenant information leakage.
    TenantMismatch { expected: TenantId },
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoneAvailable => f.write_str("no available shards for this run"),
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
        }
    }
}

impl std::error::Error for ClaimError {}

/// Maps run-lookup errors into claim errors.
///
/// `list_shards` returns `GetRunError`, which we translate 1:1 since
/// both `RunNotFound` and `TenantMismatch` apply identically at the
/// claim level. The match is exhaustive (no wildcard) so adding a new
/// `GetRunError` variant produces a compile error here.
impl From<GetRunError> for ClaimError {
    fn from(e: GetRunError) -> Self {
        match e {
            GetRunError::RunNotFound => Self::RunNotFound,
            GetRunError::TenantMismatch { expected } => Self::TenantMismatch { expected },
        }
    }
}

// Compile-time size guard: keeps `ClaimError` small so the error path of
// `Result<_, ClaimError>` is lightweight.
const _: () = assert!(std::mem::size_of::<ClaimError>() <= 48);

// ============================================================================
// Free function: default claim logic
// ============================================================================

/// Default implementation of [`ShardClaiming::claim_next_available`].
///
/// Exposed as a free function so orchestration layers that implement
/// a custom claim path can delegate to it as a fallback.
///
/// ## Algorithm
///
/// 1. Fetch the candidate list via
///    `list_shards(ShardFilter::available())` -- active, unleased shards.
/// 2. If the list is empty, return `NoneAvailable` immediately.
/// 3. Start iteration at offset `worker.as_raw() % len` so that
///    different workers begin at different candidates, reducing
///    contention on the first shard. The offset is deterministic
///    (no RNG) — the same worker always starts at the same position.
///    For each candidate, attempt `acquire_and_restore`.
/// 4. On success, return the `AcquireResult` (lease + snapshot).
/// 5. On a transient race error (`AlreadyLeased`, `ShardTerminal`,
///    `ShardNotFound`), skip that candidate and try the next.
/// 6. On `TenantMismatch`, fail immediately -- this indicates a
///    logic bug, not a race.
/// 7. If all candidates fail, return `NoneAvailable`.
///
/// ## Concurrency
///
/// There is an intentional TOCTOU gap between the `list_shards`
/// snapshot and the per-shard `acquire_and_restore` calls. This is
/// safe because the fencing protocol in `acquire_and_restore`
/// guarantees at-most-one winner per shard. Workers that lose the
/// race simply advance to the next candidate. The worst case for a
/// single worker is O(S) failed acquire attempts where S is the
/// shard count, since it tries each candidate at most once.
///
/// ## Parameters
///
/// - `now`: logical timestamp threaded into both `list_shards` and
///   `acquire_and_restore`. The coordinator never reads a wall clock;
///   passing time explicitly is required for deterministic simulation.
/// - `tenant` / `run`: scope the candidate set and enforce isolation.
/// - `worker`: identity recorded on the new lease if acquire succeeds.
///
/// ## Errors
///
/// - [`ClaimError::NoneAvailable`] -- no shards to claim (empty list
///   or all candidates lost to races).
/// - [`ClaimError::RunNotFound`] -- the run does not exist.
/// - [`ClaimError::TenantMismatch`] -- tenant isolation violation.
pub fn default_claim_next_available<B: CoordinationBackend + RunManagement>(
    backend: &mut B,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
) -> Result<AcquireResult, ClaimError> {
    let summaries = backend
        .list_shards(now, tenant, run, ShardFilter::available())
        .map_err(ClaimError::from)?;

    if summaries.is_empty() {
        return Err(ClaimError::NoneAvailable);
    }

    let len = summaries.len();
    let offset = worker.as_raw() as usize % len;
    let mut inconsistency_count = 0usize;
    for i in 0..len {
        let summary = &summaries[(offset + i) % len];
        let key = ShardKey::new(run, summary.shard());
        match backend.acquire_and_restore(now, tenant, key, worker) {
            Ok(result) => return Ok(result),
            Err(AcquireError::AlreadyLeased { .. }) => {
                // Race — another worker claimed it. Try next.
                continue;
            }
            Err(AcquireError::ShardTerminal { .. }) => {
                // Shard became terminal between list and acquire.
                continue;
            }
            Err(AcquireError::ShardNotFound { .. }) => {
                // list_shards returned this shard but acquire_and_restore
                // says it doesn't exist — signals a data inconsistency.
                // Crashes in debug builds to catch backend bugs early;
                // continues in release where production logging handles this.
                debug_assert!(
                    false,
                    "claim_next_available: list_shards returned shard {key:?} \
                     but acquire_and_restore reports ShardNotFound"
                );
                inconsistency_count += 1;
                continue;
            }
            Err(AcquireError::TenantMismatch { expected }) => {
                return Err(ClaimError::TenantMismatch { expected });
            }
        }
    }

    // If every candidate failed with ShardNotFound, the backend's index
    // is inconsistent with its primary shard map — this is data corruption,
    // not a legitimate race condition.
    debug_assert!(
        inconsistency_count < summaries.len(),
        "all {} candidates returned ShardNotFound — backend index vs shard map inconsistency",
        summaries.len(),
    );

    // All candidates were claimed by other workers (or disappeared).
    Err(ClaimError::NoneAvailable)
}

// ============================================================================
// ShardClaiming trait
// ============================================================================

/// Extension trait: shard claiming for backends that implement both
/// `CoordinationBackend` and `RunManagement`.
///
/// This trait exists to bridge a gap in the base traits: `CoordinationBackend`
/// operates on individual shards (by `ShardKey`), and `RunManagement`
/// can list shards for a run, but neither provides a "give me the next
/// shard to work on" operation. `ShardClaiming` composes the two into
/// that higher-level primitive.
///
/// ## Blanket implementation
///
/// A blanket `impl<T: CoordinationBackend + RunManagement> ShardClaiming for T`
/// means backends never implement this trait directly. Rust coherence
/// rules prevent a concrete type from overriding the blanket impl.
/// To supply a custom claim strategy, the orchestration layer should
/// call [`default_claim_next_available`] as a fallback and add
/// optimized logic (e.g. SQL `SKIP LOCKED`) around it.
///
/// ## Default vs Override
///
/// The default [`claim_next_available`](Self::claim_next_available)
/// calls `list_shards(available)` then tries `acquire_and_restore` on
/// each candidate sequentially. This is correct but not optimal under
/// high contention -- it may attempt O(N) acquires before succeeding
/// or giving up.
///
/// Production deployments should consider wrapping the call with:
/// - **Atomic claim**: `SELECT ... FOR UPDATE SKIP LOCKED` (SQL) or
///   a single FoundationDB transaction that atomically picks and
///   leases a shard.
/// - **Randomized offset**: start iteration at
///   `worker.as_raw() % len` to spread contention deterministically
///   across the candidate list.
/// - **Locality-aware**: prefer shards whose key range is near the
///   worker's previously held shard, reducing cache churn.
///
/// All of these are **performance optimizations** -- they do not
/// affect correctness. Any available shard is a valid choice.
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for `run`.
    ///
    /// On success, returns an [`AcquireResult`] containing the lease
    /// (proof of ownership with fencing token) and the shard snapshot
    /// (status, spec, cursor, cursor_semantics, lineage) so the
    /// worker knows where to resume.
    ///
    /// The `Self: Sized` bound is required because the default body
    /// passes `self` to the free function
    /// [`default_claim_next_available`], which takes `&mut B` by
    /// generic parameter.
    fn claim_next_available(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
    ) -> Result<AcquireResult, ClaimError>
    where
        Self: Sized,
    {
        default_claim_next_available(self, now, tenant, run, worker)
    }
}

// Blanket impl: every `T: CoordinationBackend + RunManagement`
// automatically satisfies `ShardClaiming` with the default method.
// This means backends only need to implement the two base traits to
// get claiming behaviour.
impl<T: CoordinationBackend + RunManagement> ShardClaiming for T {}

// ============================================================================
// CoordinationFacade — combined super-trait
// ============================================================================

/// The complete coordination contract: shard lifecycle + run management
/// + shard claiming, unified into a single bound.
///
/// Callers that need the full coordination surface (typically the
/// orchestrator and scheduler layers) constrain on this trait
/// instead of listing three separate bounds. Because `ShardClaiming`
/// and `CoordinationFacade` both have blanket impls, any concrete
/// backend that implements `CoordinationBackend` and `RunManagement`
/// automatically satisfies `CoordinationFacade` -- no additional
/// code required.
///
/// ## Object safety
///
/// `CoordinationFacade` is **not usable** as a trait object because
/// [`ShardClaiming::claim_next_available`] carries a `where Self: Sized`
/// bound (excluded from the vtable). Use `B: CoordinationFacade` as a
/// generic bound, not `dyn CoordinationFacade`.
///
/// ## Typical lifecycle
///
/// ```rust,ignore
/// fn run_orchestrator<B: CoordinationFacade>(backend: &mut B) {
///     // 1. Create the run and register its shards.
///     backend.create_run(now, tenant, run_id, config)?;
///     backend.register_shards(now, tenant, run_id, shards, op_id)?;
///
///     // 2. Workers claim shards and process them.
///     let result = backend.claim_next_available(now, tenant, run_id, worker)?;
///     backend.checkpoint(now, tenant, &result.lease, cursor, op_id)?;
///     backend.complete(now, tenant, &result.lease, final_cursor, op_id)?;
///
///     // 3. Once all shards are done, finalize the run.
///     backend.complete_run(now, tenant, run_id, op_id)?;
/// }
/// ```
pub trait CoordinationFacade: CoordinationBackend + RunManagement + ShardClaiming {}

// Blanket impl: the three component traits compose automatically.
impl<T: CoordinationBackend + RunManagement + ShardClaiming> CoordinationFacade for T {}

// ============================================================================
// Tests
// ============================================================================

/// Tests verify the default claim algorithm against `InMemoryCoordinator`:
/// - Happy path: claim succeeds and returns a valid lease.
/// - Exhaustion: all shards leased -> `NoneAvailable`.
/// - Race skip: already-leased shards are skipped, next candidate returned.
/// - Run not found: missing run -> `RunNotFound`.
/// - Sequential drain: N claims exhaust N shards; (N+1)th fails.
/// - Lease expiry: expired leases free shards for re-claiming.
/// - Terminal skip: completed shards are filtered by `ShardFilter::available`.
/// - Trait composition: `InMemoryCoordinator` satisfies `CoordinationFacade`.
/// - Error conversion: `From<GetRunError>` maps both variants correctly.
/// - Mixed states: Done + leased + available shards (property test).
/// - Expired leases: re-claiming after lease timeout (property test).
#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::run::{InitialShard, RunConfig, RunManagement};
    use crate::coordination::shard_spec::CursorSemantics;
    use crate::identity::{OpId, ShardId};
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

    fn test_run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
    }

    /// Set up a coordinator with a run containing `shard_count` shards.
    fn setup_coordinator(shard_count: usize) -> InMemoryCoordinator {
        let mut coord = InMemoryCoordinator::new(30);
        let tenant = test_tenant();
        let run = test_run();
        let config = test_run_config();

        coord.create_run(now(1), tenant, run, config).unwrap();

        let shards: Vec<InitialShard> = (0..shard_count)
            .map(|i| {
                let start = vec![i as u8];
                let end = vec![(i + 1) as u8];
                InitialShard::new(
                    ShardId::from_raw(i as u64),
                    crate::coordination::shard_spec::ShardSpec::with_range(start, end),
                    Cursor::initial(),
                )
            })
            .collect();

        let _ = coord
            .register_shards(now(1), tenant, run, &shards, OpId::from_raw(100))
            .unwrap();

        coord
    }

    #[test]
    fn claim_next_available_ok() {
        let mut coord = setup_coordinator(2);
        let result = coord.claim_next_available(now(2), test_tenant(), test_run(), test_worker(1));
        assert!(result.is_ok());
        let acquire = result.unwrap();
        assert_eq!(acquire.lease.run(), test_run());
    }

    #[test]
    fn claim_none_available() {
        let mut coord = setup_coordinator(1);
        // Manually acquire the only shard.
        let key = ShardKey::new(test_run(), ShardId::from_raw(0));
        let _ = coord
            .acquire_and_restore(now(2), test_tenant(), key, test_worker(1))
            .unwrap();

        let result = coord.claim_next_available(now(3), test_tenant(), test_run(), test_worker(2));
        assert_eq!(result, Err(ClaimError::NoneAvailable));
    }

    #[test]
    fn claim_skips_already_leased() {
        let mut coord = setup_coordinator(2);
        // Acquire shard 0 manually.
        let key0 = ShardKey::new(test_run(), ShardId::from_raw(0));
        let _ = coord
            .acquire_and_restore(now(2), test_tenant(), key0, test_worker(1))
            .unwrap();

        // claim_next_available should skip shard 0 and get shard 1.
        let result = coord.claim_next_available(now(3), test_tenant(), test_run(), test_worker(2));
        assert!(result.is_ok());
        let acquire = result.unwrap();
        assert_eq!(acquire.lease.shard(), ShardId::from_raw(1));
    }

    #[test]
    fn claim_run_not_found() {
        let mut coord = InMemoryCoordinator::new(30);
        let result =
            coord.claim_next_available(now(1), test_tenant(), RunId::from_raw(999), test_worker(1));
        assert_eq!(result, Err(ClaimError::RunNotFound));
    }

    #[test]
    fn claim_all_sequential() {
        let mut coord = setup_coordinator(3);
        let tenant = test_tenant();
        let run = test_run();

        let r1 = coord
            .claim_next_available(now(2), tenant, run, test_worker(1))
            .unwrap();
        let r2 = coord
            .claim_next_available(now(3), tenant, run, test_worker(2))
            .unwrap();
        let r3 = coord
            .claim_next_available(now(4), tenant, run, test_worker(3))
            .unwrap();

        // All three claims must produce distinct shards.
        let mut shards = vec![r1.lease.shard(), r2.lease.shard(), r3.lease.shard()];
        shards.sort();
        shards.dedup();
        assert_eq!(shards.len(), 3);

        // Fourth claim fails.
        let r4 = coord.claim_next_available(now(5), tenant, run, test_worker(4));
        assert_eq!(r4, Err(ClaimError::NoneAvailable));
    }

    #[test]
    fn facade_trait_compiles() {
        fn requires_facade<B: CoordinationFacade>(_: &mut B) {}
        let mut coord = InMemoryCoordinator::new(30);
        requires_facade(&mut coord);
    }

    #[test]
    fn claim_after_lease_expiry() {
        let mut coord = setup_coordinator(1);
        let tenant = test_tenant();
        let run = test_run();

        // Claim the only shard.
        let _ = coord
            .claim_next_available(now(2), tenant, run, test_worker(1))
            .unwrap();

        // Advance time past the lease deadline (lease_duration=30).
        // now=2 + 30 = deadline at 32. At now=33, lease is expired.
        let result = coord.claim_next_available(now(33), tenant, run, test_worker(2));
        assert!(result.is_ok());
        let acquire = result.unwrap();
        assert_eq!(acquire.lease.owner(), test_worker(2));
    }

    #[test]
    fn claim_skips_terminal() {
        let mut coord = setup_coordinator(2);
        let tenant = test_tenant();
        let run = test_run();

        // Acquire shard 0 and complete it (terminal).
        let key0 = ShardKey::new(run, ShardId::from_raw(0));
        let acquire = coord
            .acquire_and_restore(now(2), tenant, key0, test_worker(1))
            .unwrap();
        let cursor = Cursor::with_last_key(vec![0x00]);
        let _ = coord
            .complete(now(3), tenant, &acquire.lease, cursor, OpId::from_raw(200))
            .unwrap();

        // claim_next_available should skip the completed shard and get shard 1.
        let result = coord.claim_next_available(now(4), tenant, run, test_worker(2));
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.lease.shard(), ShardId::from_raw(1));
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

        let result = coord.claim_next_available(now(2), wrong_tenant, test_run(), test_worker(1));
        assert!(result.is_err(), "cross-tenant claim must not succeed");
        // InMemoryCoordinator keys runs by (tenant, run) — wrong
        // tenant means the run is not found under that tenant.
        assert_eq!(result, Err(ClaimError::RunNotFound));
    }

    // -- From<GetRunError> conversion tests --------------------------------

    #[test]
    fn claim_error_from_get_run_error_tenant_mismatch() {
        let err = GetRunError::TenantMismatch {
            expected: test_tenant(),
        };
        let claim_err: ClaimError = err.into();
        assert_eq!(
            claim_err,
            ClaimError::TenantMismatch {
                expected: test_tenant()
            }
        );
    }

    #[test]
    fn claim_error_from_get_run_error_run_not_found() {
        let err = GetRunError::RunNotFound;
        let claim_err: ClaimError = err.into();
        assert_eq!(claim_err, ClaimError::RunNotFound);
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
                let _ = coord
                    .acquire_and_restore(now(2), tenant, key, test_worker(100 + i as u64))
                    .unwrap();
            }

            let result = coord.claim_next_available(now(3), tenant, run, test_worker(999));

            if num_leased == shard_count {
                prop_assert_eq!(result, Err(ClaimError::NoneAvailable));
            } else {
                let acq = result.unwrap();
                let claimed = acq.lease.shard().as_raw();
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
                let acq = coord
                    .acquire_and_restore(now(2), tenant, key, test_worker(200 + i as u64))
                    .unwrap();
                let cursor = Cursor::with_last_key(vec![i as u8]);
                let _ = coord
                    .complete(now(3), tenant, &acq.lease, cursor, OpId::from_raw(300 + i as u64))
                    .unwrap();
            }

            // Lease the next `num_leased` shards (Active + leased).
            for i in 0..num_leased {
                let idx = num_done + i;
                let key = ShardKey::new(run, ShardId::from_raw(idx as u64));
                let _ = coord
                    .acquire_and_restore(now(4), tenant, key, test_worker(400 + i as u64))
                    .unwrap();
            }

            let available = shard_count - num_done - num_leased;
            let result = coord.claim_next_available(now(5), tenant, run, test_worker(999));

            if available == 0 {
                prop_assert_eq!(result, Err(ClaimError::NoneAvailable));
            } else {
                let acq = result.unwrap();
                let claimed = acq.lease.shard().as_raw() as usize;
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
                let _ = coord
                    .acquire_and_restore(now(2), tenant, key, test_worker(100 + i as u64))
                    .unwrap();
            }

            // At now=3, all leased — claim fails.
            let result = coord.claim_next_available(now(3), tenant, run, test_worker(999));
            prop_assert_eq!(result, Err(ClaimError::NoneAvailable));

            // Advance past lease expiry (lease_duration=30, so deadline=32).
            // At now=33, all leases expired — claim succeeds.
            let result = coord.claim_next_available(now(33), tenant, run, test_worker(888));
            prop_assert!(result.is_ok(), "claim should succeed after lease expiry");
            let acq = result.unwrap();
            prop_assert_eq!(acq.lease.owner(), test_worker(888));
        }
    }
}
