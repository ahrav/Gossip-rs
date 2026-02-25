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
//! protocol in `acquire_and_restore_into` ensures at most one worker
//! succeeds for any given shard, so the TOCTOU gap between list
//! and acquire is safe (losers simply retry the next candidate).
//!
//! The default logic is also exposed as the free function
//! [`default_claim_next_available`] so backends that override
//! `claim_next_available` can delegate to it as a building block.

use std::fmt;

use crate::coordination::error::{AcquireError, AcquireResultView, AcquireScratch};
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
/// The default implementation panics instead of returning `NoneAvailable`
/// when *every* candidate yields `ShardNotFound`, because that indicates
/// backend index corruption rather than normal contention.
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
///    For each candidate, attempt `acquire_and_restore_into`.
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
/// snapshot and the per-shard `acquire_and_restore_into` calls. This is
/// safe because the fencing protocol in `acquire_and_restore_into`
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
///   `acquire_and_restore_into`. The coordinator never reads a wall clock;
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
pub fn default_claim_next_available<'a, B: CoordinationBackend + RunManagement>(
    backend: &mut B,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
    out: &'a mut AcquireScratch,
) -> Result<AcquireResultView<'a>, ClaimError> {
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
    let mut i = 0usize;
    let acquired = loop {
        if i == len {
            break None;
        }
        let summary = &summaries[(offset + i) % len];
        let key = ShardKey::new(run, summary.shard());
        match backend.acquire_and_restore_into(now, tenant, key, worker, out) {
            Ok(result) => {
                let snapshot = result.snapshot;
                break Some((
                    result.lease,
                    snapshot.status(),
                    snapshot.cursor_semantics(),
                    snapshot.parent(),
                    result.capacity,
                ));
            }
            Err(AcquireError::AlreadyLeased { lease_deadline, .. }) => {
                // Race -- another worker claimed it.  Track the deadline
                // so callers can schedule their next attempt near the
                // soonest lease expiry.  Only AlreadyLeased carries a
                // deadline; terminal and not-found shards have none.
                earliest_deadline = Some(match earliest_deadline {
                    Some(prev) => core::cmp::min(prev, lease_deadline),
                    None => lease_deadline,
                });
                i += 1;
                continue;
            }
            Err(AcquireError::ShardTerminal { .. }) => {
                // Shard became terminal between list and acquire.
                i += 1;
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
                     but acquire_and_restore_into reports ShardNotFound"
                );
                inconsistency_count += 1;
                i += 1;
                continue;
            }
            Err(AcquireError::TenantMismatch { expected }) => {
                // Not a race -- this is a logic bug (wrong tenant
                // threaded into the call). Fail immediately; retrying
                // other candidates would hit the same mismatch.
                return Err(ClaimError::TenantMismatch { expected });
            }
        }
    };

    if let Some((lease, status, cursor_semantics, parent, capacity)) = acquired {
        return Ok(AcquireResultView {
            lease,
            snapshot: out.view(status, cursor_semantics, parent),
            capacity,
        });
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
/// calls `list_shards(available)` then tries `acquire_and_restore_into` on
/// each candidate sequentially. This is correct but not optimal under
/// high contention -- it may attempt O(N) acquires before succeeding
/// or giving up.
///
/// The default already spreads contention by starting iteration at
/// `worker.as_raw() % len` (deterministic per-worker offset).
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for `run`.
    ///
    /// On success, returns an [`AcquireResultView`] containing the lease
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
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError>
    where
        Self: Sized,
    {
        default_claim_next_available(self, now, tenant, run, worker, out)
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

#[cfg(test)]
#[path = "facade_tests.rs"]
mod tests;
