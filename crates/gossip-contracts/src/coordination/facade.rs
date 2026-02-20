//! Shard claiming and the [`CoordinationFacade`] super-trait.
//!
//! The orchestrator needs a single type bound that grants access to
//! shard lifecycle (`CoordinationBackend`), run management
//! (`RunManagement`), **and** shard assignment (`ShardClaiming`).
//! This module provides that bound as `CoordinationFacade`, plus a
//! default shard-claiming algorithm available to all backends.
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
//! Backends must implement `ShardClaiming` explicitly. The trait
//! provides a default method body that delegates to the free function
//! [`default_claim_next_available`], so a one-line empty impl is
//! sufficient for backends that need no custom claim logic:
//!
//! ```rust,ignore
//! impl ShardClaiming for MyBackend {}
//! ```
//!
//! Backends that need custom behavior (e.g., per-worker claim
//! cooldown) override `claim_next_available` and may delegate to
//! `default_claim_next_available` internally.
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
//! [`default_claim_next_available`] so backends that override
//! `claim_next_available` can delegate to it as a building block.

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
/// The enum is `#[non_exhaustive]` so that future claim strategies can
/// introduce additional error variants without requiring callers to
/// update exhaustive `match` arms.
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
    ///
    /// `earliest_deadline` is the soonest lease expiry observed during
    /// the claiming scan. Workers should use it to schedule their next
    /// claim attempt (sleeping until roughly this time avoids busy-
    /// spinning on a fully-leased run). `None` when no leased shards
    /// were encountered -- meaning all shards are terminal or the run
    /// has no shards at all, so retrying is unlikely to help.
    NoneAvailable {
        earliest_deadline: Option<LogicalTime>,
    },
    /// The run does not exist in the coordination store.
    RunNotFound,
    /// Tenant isolation violation. Only `expected` is exposed to
    /// prevent cross-tenant information leakage.
    TenantMismatch { expected: TenantId },
    /// The worker's claim cooldown has not elapsed since its last
    /// successful acquisition. `retry_after` is the earliest logical
    /// time at which the worker may next attempt a claim.
    ///
    /// Cooldown is per-worker (not per-run) to prevent a single worker
    /// from flooding the coordinator across multiple runs. Only
    /// successful claims trigger cooldown; failed claims do not.
    Throttled { retry_after: LogicalTime },
}

impl fmt::Display for ClaimError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoneAvailable {
                earliest_deadline: Some(deadline),
            } => write!(
                f,
                "no available shards for this run (earliest lease expiry: {deadline:?})"
            ),
            Self::NoneAvailable {
                earliest_deadline: None,
            } => f.write_str("no available shards for this run (no active leases)"),
            Self::RunNotFound => f.write_str("run not found"),
            Self::TenantMismatch { expected } => {
                write!(f, "tenant mismatch (expected {expected:?})")
            }
            Self::Throttled { retry_after } => {
                write!(
                    f,
                    "claim throttled: worker in cooldown (retry after {retry_after:?})"
                )
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
/// 2. If the list is empty, query `active()` shards to find the earliest
///    lease deadline, then return `NoneAvailable` with that deadline.
/// 3. Start iteration at offset `worker.as_raw() % len` so that
///    different workers begin at different candidates, reducing
///    contention on the first shard. The offset is deterministic
///    (no RNG) — for a given candidate list length, the same worker
///    always starts at the same position.
///    For each candidate, attempt `acquire_and_restore`.
/// 4. On success, return the `AcquireResult` (lease, snapshot, capacity hint).
/// 5. On a transient race error (`AlreadyLeased`, `ShardTerminal`,
///    `ShardNotFound`), skip that candidate and try the next.
/// 6. On `TenantMismatch`, fail immediately -- this indicates a
///    logic bug, not a race.
/// 7. If all candidates fail, return `NoneAvailable`. (If every
///    candidate returned `ShardNotFound`, this indicates index
///    corruption and the function panics instead.)
///
/// ## Concurrency
///
/// There is an intentional TOCTOU gap between the `list_shards`
/// snapshot and the per-shard `acquire_and_restore` calls. This is
/// safe because the fencing protocol in `acquire_and_restore`
/// guarantees at-most-one winner per shard. Workers that lose the
/// race simply advance to the next candidate. The worst case for a
/// single worker is O(S) failed acquire attempts where S is the
/// number of available shards, since it tries each candidate at
/// most once.
///
/// ## Parameters
///
/// - `backend`: mutable reference to the coordination backend. The
///   `&mut B` bound means exactly one claim attempt is in flight per
///   backend instance at a time -- concurrent claiming requires
///   separate backend instances (one per worker thread/task).
/// - `now`: logical timestamp threaded into both `list_shards` and
///   `acquire_and_restore`. The coordinator never reads a wall clock;
///   passing time explicitly is required for deterministic simulation.
/// - `tenant` / `run`: scope the candidate set and enforce isolation.
/// - `worker`: identity recorded on the new lease if acquire succeeds.
///
/// ## Complexity
///
/// O(S) where S is the number of available shards. Each shard is
/// attempted at most once. The `list_shards` call is O(S log S) in the
/// in-memory backend (linear scan + sort over the run's shard map).
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
        // No unleased shards.  Query active shards (including leased) to
        // surface the earliest lease deadline so callers can schedule a
        // retry near the soonest expiry instead of busy-spinning.
        let earliest_deadline = backend
            .list_shards(now, tenant, run, ShardFilter::active())
            .unwrap_or_default()
            .iter()
            .filter_map(|s| s.lease_deadline())
            .min();
        return Err(ClaimError::NoneAvailable { earliest_deadline });
    }

    let len = summaries.len();
    let offset = worker.as_raw() as usize % len;
    let mut inconsistency_count = 0usize;
    let mut earliest_deadline: Option<LogicalTime> = None;
    for i in 0..len {
        let summary = &summaries[(offset + i) % len];
        let key = ShardKey::new(run, summary.shard());
        match backend.acquire_and_restore(now, tenant, key, worker) {
            Ok(result) => return Ok(result),
            Err(AcquireError::AlreadyLeased { lease_deadline, .. }) => {
                // Race -- another worker claimed it.  Track the deadline
                // so callers can schedule their next attempt near the
                // soonest lease expiry.  Only AlreadyLeased carries a
                // deadline; terminal and not-found shards have none.
                earliest_deadline = Some(match earliest_deadline {
                    Some(prev) => core::cmp::min(prev, lease_deadline),
                    None => lease_deadline,
                });
                continue;
            }
            Err(AcquireError::ShardTerminal { .. }) => {
                // Shard became terminal between list and acquire.
                continue;
            }
            Err(AcquireError::ShardNotFound { .. }) => {
                // list_shards returned this shard but acquire_and_restore
                // says it doesn't exist.  This is a backend data
                // inconsistency (the index disagrees with the shard map).
                // Isolated occurrences are tolerable in release builds
                // (a concurrent split_replace could theoretically cause
                // a transient gap); all-not-found is data corruption and
                // is caught by the post-loop assert.
                debug_assert!(
                    false,
                    "claim_next_available: list_shards returned shard {key:?} \
                     but acquire_and_restore reports ShardNotFound"
                );
                inconsistency_count += 1;
                continue;
            }
            Err(AcquireError::TenantMismatch { expected }) => {
                // Not a race -- this is a logic bug (wrong tenant
                // threaded into the call). Fail immediately; retrying
                // other candidates would hit the same mismatch.
                return Err(ClaimError::TenantMismatch { expected });
            }
        }
    }

    // Partial ShardNotFound is tolerable (concurrent mutations).
    // All-not-found means the backend's shard index is fundamentally
    // inconsistent with the shard map — unconditional panic (data corruption).
    assert!(
        inconsistency_count < summaries.len(),
        "all {} candidates returned ShardNotFound — backend index vs shard map inconsistency",
        summaries.len(),
    );

    // All candidates were claimed by other workers, became terminal,
    // or disappeared.  Surface the earliest deadline (if any) so
    // callers can schedule a retry without busy-spinning.
    Err(ClaimError::NoneAvailable { earliest_deadline })
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
/// ## Implementation
///
/// Backends must implement this trait explicitly. The default method
/// body delegates to [`default_claim_next_available`], so a minimal
/// impl needs no method bodies:
///
/// ```rust,ignore
/// impl ShardClaiming for MyBackend {}
/// ```
///
/// Backends that need custom claim behavior (e.g., per-worker cooldown,
/// SQL `SKIP LOCKED`, locality-aware selection) override
/// [`claim_next_available`](Self::claim_next_available) and may
/// delegate to [`default_claim_next_available`] internally.
///
/// ## Default Algorithm
///
/// The default [`claim_next_available`](Self::claim_next_available)
/// calls `list_shards(available)` then tries `acquire_and_restore` on
/// each candidate sequentially. This is correct but not optimal under
/// high contention -- it may attempt O(N) acquires before succeeding
/// or giving up.
///
/// The default already spreads contention by starting iteration at
/// `worker.as_raw() % len` (deterministic per-worker offset).
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for `run`.
    ///
    /// On success, returns an [`AcquireResult`] containing the lease
    /// (proof of ownership with fencing token), the shard snapshot
    /// (status, spec, cursor, cursor_semantics, lineage), and a
    /// [`CapacityHint`](crate::coordination::error::CapacityHint)
    /// indicating how many shards remain available.
    ///
    /// ## Errors
    ///
    /// - [`ClaimError::NoneAvailable`] -- no shards to claim.
    /// - [`ClaimError::RunNotFound`] -- the run does not exist.
    /// - [`ClaimError::TenantMismatch`] -- tenant isolation violation.
    /// - [`ClaimError::Throttled`] -- the worker's claim cooldown has
    ///   not elapsed. Only returned by backends with per-worker rate
    ///   limiting (e.g., [`InMemoryCoordinator`] with a non-zero
    ///   cooldown interval). The default implementation never returns
    ///   `Throttled`; backends that add rate limiting must override
    ///   this method to enforce it before delegating.
    ///
    /// [`InMemoryCoordinator`]: crate::coordination::in_memory::InMemoryCoordinator
    ///
    /// ## `Self: Sized` bound
    ///
    /// Required because the default body passes `self` to the free
    /// function [`default_claim_next_available`], which takes `&mut B`
    /// by generic parameter. This means `claim_next_available` is
    /// excluded from the vtable and cannot be called on `dyn
    /// ShardClaiming`.
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

// No blanket impl: backends must implement `ShardClaiming` explicitly.
// The trait provides a default method body that delegates to
// `default_claim_next_available`, so a one-line empty impl suffices
// for backends with no custom claim logic. Backends that need custom
// behavior (e.g., per-worker cooldown) override the method directly.

// ============================================================================
// CoordinationFacade — combined super-trait
// ============================================================================

/// The complete coordination contract: shard lifecycle + run management
/// + shard claiming, unified into a single bound.
///
/// Callers that need the full coordination surface (typically the
/// orchestrator and scheduler layers) constrain on this trait
/// instead of listing three separate bounds. `CoordinationFacade`
/// has a blanket impl, so any backend that implements all three
/// component traits automatically satisfies it.
///
/// ## Object safety
///
/// `CoordinationFacade` is technically object-safe, but `dyn
/// CoordinationFacade` loses access to
/// [`ShardClaiming::claim_next_available`] because it carries a
/// `where Self: Sized` bound (excluded from the vtable). Since
/// claiming is the primary value of the facade, prefer
/// `B: CoordinationFacade` as a generic bound over `dyn
/// CoordinationFacade`.
///
/// ## Typical lifecycle
///
/// ```rust,ignore
/// fn run_orchestrator<B: CoordinationFacade>(backend: &mut B) {
///     // Phase 1: Setup -- create run and register its shard manifest.
///     // The run transitions Initializing -> Active on register_shards.
///     backend.create_run(now, tenant, run_id, config)?;
///     backend.register_shards(now, tenant, run_id, shards, op_id)?;
///
///     // Phase 2: Processing -- each worker claims a shard, processes
///     // it with periodic checkpoints, and marks it complete.
///     let result = backend.claim_next_available(now, tenant, run_id, worker)?;
///     backend.checkpoint(now, tenant, &result.lease, cursor, op_id)?;
///     backend.complete(now, tenant, &result.lease, final_cursor, op_id)?;
///
///     // Phase 3: Finalization -- once all shards are Done, the
///     // orchestrator marks the run as Done (terminal).
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
///
/// ## Core claim behavior
/// - Happy path: claim succeeds and returns a valid lease.
/// - Exhaustion: all shards leased -> `NoneAvailable`.
/// - Race skip: already-leased shards are skipped, next candidate returned.
/// - Run not found: missing run -> `RunNotFound`.
/// - Sequential drain: N claims exhaust N shards; (N+1)th fails.
/// - Lease expiry: expired leases free shards for re-claiming.
/// - Terminal skip: completed shards are filtered by `ShardFilter::available`.
/// - Earliest deadline: `NoneAvailable` reports soonest lease expiry.
/// - Wrong tenant: cross-tenant claim rejected.
///
/// ## Trait composition and error conversion
/// - Trait composition: `InMemoryCoordinator` satisfies `CoordinationFacade`.
/// - Error conversion: `From<GetRunError>` maps both variants correctly.
///
/// ## Property tests
/// - Mixed states: Done + leased + available shards.
/// - Expired leases: re-claiming after lease timeout.
///
/// ## Claim cooldown
/// - Single-worker timing (parameterized): throttled within window,
///   succeeds at boundary, disabled with zero, retry_after value.
/// - Failed claims do not trigger cooldown.
/// - Cooldown is per-worker (not global).
/// - `Throttled` display format.
/// - Property: no successful claim within cooldown of previous success.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::coordination::cursor::Cursor;
    use crate::coordination::in_memory::InMemoryCoordinator;
    use crate::coordination::run::{InitialShard, RunConfig, RunManagement};
    use crate::coordination::shard_spec::CursorSemantics;
    use crate::coordination::test_fixtures::{now, test_run, test_tenant, test_worker};
    use crate::identity::{OpId, ShardId};
    use crate::test_util::miri_proptest_config;
    use proptest::prelude::*;
    use rstest::rstest;

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
        assert!(matches!(result, Err(ClaimError::NoneAvailable { .. })));
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
        assert!(matches!(r4, Err(ClaimError::NoneAvailable { .. })));
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

    /// When all shards are leased, `earliest_deadline` should be populated
    /// so callers can schedule a retry near the soonest lease expiry.
    #[test]
    fn claim_all_leased_reports_earliest_deadline() {
        let mut coord = setup_coordinator(2);
        let tenant = test_tenant();
        let run = test_run();

        // Lease both shards at now=10 (lease_duration=30 → deadline=40).
        let key0 = ShardKey::new(run, ShardId::from_raw(0));
        let _ = coord
            .acquire_and_restore(now(10), tenant, key0, test_worker(1))
            .unwrap();

        // Lease second shard at now=15 (deadline=45).
        let key1 = ShardKey::new(run, ShardId::from_raw(1));
        let _ = coord
            .acquire_and_restore(now(15), tenant, key1, test_worker(2))
            .unwrap();

        // All shards leased — claim should fail with earliest_deadline = Some(40).
        let result = coord.claim_next_available(now(20), tenant, run, test_worker(3));
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
                let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
                prop_assert!(is_none_available, "expected NoneAvailable");
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
                let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
                prop_assert!(is_none_available, "expected NoneAvailable");
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
            let is_none_available = matches!(result, Err(ClaimError::NoneAvailable { .. }));
            prop_assert!(is_none_available, "expected NoneAvailable");

            // Advance past lease expiry (lease_duration=30, so deadline=32).
            // At now=33, all leases expired — claim succeeds.
            let result = coord.claim_next_available(now(33), tenant, run, test_worker(888));
            prop_assert!(result.is_ok(), "claim should succeed after lease expiry");
            let acq = result.unwrap();
            prop_assert_eq!(acq.lease.owner(), test_worker(888));
        }
    }

    // ========================================================================
    // Claim cooldown tests
    // ========================================================================

    /// Helper: set up a coordinator with cooldown enabled and `shard_count` shards.
    fn setup_coordinator_with_cooldown(
        shard_count: usize,
        cooldown_interval: u64,
    ) -> InMemoryCoordinator {
        let mut coord =
            InMemoryCoordinator::with_cooldown(30, 100_000, 1_000_000, cooldown_interval);
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
        let mut coord = if cooldown > 0 {
            setup_coordinator_with_cooldown(shard_count, cooldown)
        } else {
            setup_coordinator(shard_count)
        };
        let tenant = test_tenant();
        let run = test_run();
        let worker = test_worker(1);

        let r1 = coord.claim_next_available(now(first_t), tenant, run, worker);
        assert!(r1.is_ok(), "first claim should succeed: {r1:?}");

        let r2 = coord.claim_next_available(now(second_t), tenant, run, worker);
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

    #[test]
    fn claim_cooldown_not_triggered_on_failure() {
        let mut coord = setup_coordinator_with_cooldown(1, 5);
        let tenant = test_tenant();
        let run = test_run();

        // Worker 1 claims the only shard at now=10.
        assert!(
            coord
                .claim_next_available(now(10), tenant, run, test_worker(1))
                .is_ok()
        );

        // Worker 2 tries at now=10 — fails with NoneAvailable (not Throttled).
        let r1 = coord.claim_next_available(now(10), tenant, run, test_worker(2));
        assert!(
            matches!(r1, Err(ClaimError::NoneAvailable { .. })),
            "expected NoneAvailable, got {r1:?}"
        );

        // Worker 2 retries immediately at now=11 — still NoneAvailable, not Throttled.
        let r2 = coord.claim_next_available(now(11), tenant, run, test_worker(2));
        assert!(
            matches!(r2, Err(ClaimError::NoneAvailable { .. })),
            "failed claims should not trigger cooldown, got {r2:?}"
        );
    }

    #[test]
    fn claim_cooldown_per_worker_isolation() {
        let mut coord = setup_coordinator_with_cooldown(3, 5);
        let tenant = test_tenant();
        let run = test_run();

        // Worker 1 claims at now=10.
        assert!(
            coord
                .claim_next_available(now(10), tenant, run, test_worker(1))
                .is_ok()
        );

        // Worker 2 claims at now=11 — succeeds (not affected by worker 1's cooldown).
        let r2 = coord.claim_next_available(now(11), tenant, run, test_worker(2));
        assert!(
            r2.is_ok(),
            "worker 2 should not be affected by worker 1's cooldown, got {r2:?}"
        );

        // Worker 1 tries at now=12 — throttled.
        let r3 = coord.claim_next_available(now(12), tenant, run, test_worker(1));
        assert!(
            matches!(r3, Err(ClaimError::Throttled { .. })),
            "worker 1 should be throttled, got {r3:?}"
        );
    }

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
                let result = coord.claim_next_available(now(t), tenant, run, worker);
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
}
