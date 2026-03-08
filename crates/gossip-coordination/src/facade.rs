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
//! Backends implement `ShardClaiming` explicitly. Implementations that
//! want the shared scan-then-acquire behavior can delegate to
//! [`default_claim_next_available`] while reusing a caller-owned
//! candidate buffer (`Vec<ShardId>`).
//!
//! ## Design Rationale
//!
//! The default claim algorithm deliberately uses a two-step
//! scan-then-acquire pattern rather than requiring an atomic
//! "claim next" primitive from every backend. This keeps the
//! `CoordinationBackend` trait minimal (no claim-specific method)
//! while still being correct under concurrency — the fencing
//! protocol in `acquire_and_restore_into` ensures at most one worker
//! succeeds for any given shard, so the TOCTOU gap between scan
//! and acquire is safe (losers simply retry the next candidate).
//!
//! The default logic is also exposed as the free function
//! [`default_claim_next_available`] so backends that override
//! `claim_next_available` can delegate to it as a building block.

use std::fmt;

use crate::error::{AcquireError, AcquireResultView, AcquireScratch, InfraError};
use crate::run::RunManagement;
use crate::run_errors::GetRunError;
use crate::traits::CoordinationBackend;
use gossip_contracts::identity::{LogicalTime, RunId, ShardId, ShardKey, TenantId, WorkerId};

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
/// [`AcquireError`]: crate::error::AcquireError
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
    /// The coordination backend encountered an infrastructure error.
    /// See [`InfraError`] for transient vs. corruption classification.
    BackendError(InfraError),
}

/// Human-readable formatting for logging and error display chains.
///
/// Includes the `earliest_deadline` for `NoneAvailable` and the
/// `retry_after` for `Throttled` so operators can diagnose scheduling
/// delays without inspecting the error value programmatically.
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
            Self::BackendError(infra) => {
                write!(f, "coordination backend error: {infra}")
            }
        }
    }
}

impl std::error::Error for ClaimError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::BackendError(infra) => Some(infra),
            _ => None,
        }
    }
}

/// Maps run-lookup errors into claim errors.
///
/// `collect_claim_candidates_into` returns `GetRunError`, which we translate
/// 1:1 since both `RunNotFound` and `TenantMismatch` apply identically at
/// the claim level. The match is exhaustive (no wildcard) so adding a new
/// `GetRunError` variant produces a compile error here.
impl From<GetRunError> for ClaimError {
    fn from(e: GetRunError) -> Self {
        match e {
            GetRunError::RunNotFound => Self::RunNotFound,
            GetRunError::TenantMismatch { expected } => Self::TenantMismatch { expected },
            GetRunError::BackendError(infra) => Self::BackendError(infra),
        }
    }
}

// Compile-time size guard: keeps `ClaimError` small so the error path of
// `Result<_, ClaimError>` is lightweight.
const _: () = assert!(std::mem::size_of::<ClaimError>() <= 56);

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
/// 1. Collect candidates via
///    [`collect_claim_candidates_into`](RunManagement::collect_claim_candidates_into)
///    — a single pass over the run's shard set that returns Active, unleased
///    shard IDs plus the earliest lease deadline among Active-but-leased
///    shards. Backends may sort candidates for deterministic ordering.
///    No [`ShardSummary`](crate::run::ShardSummary) objects are
///    constructed.
/// 2. If the candidate list is empty, return `NoneAvailable` with the
///    earliest deadline from the scan (so callers can schedule a retry
///    near the soonest lease expiry instead of busy-spinning).
/// 3. Start iteration at offset `worker.as_raw() % len` so that
///    different workers begin at different candidates, reducing
///    contention on the first shard. The offset is deterministic
///    (no RNG) — for a given candidate list length, the same worker
///    always starts at the same position.
///    For each candidate, attempt `acquire_and_restore_into`.
/// 4. On success, return the `AcquireResultView` (lease, snapshot, capacity hint).
/// 5. On a transient race error (`AlreadyLeased`, `ShardTerminal`,
///    `ShardNotFound`), skip that candidate and try the next.
/// 6. On `TenantMismatch`, fail immediately — this indicates a
///    logic bug, not a race.
/// 7. If all candidates fail, return `NoneAvailable`. (If every
///    candidate returned `ShardNotFound`, this indicates index
///    corruption and the function panics instead.)
///
/// ## Concurrency
///
/// There is an intentional TOCTOU gap between the candidate scan and the
/// per-shard `acquire_and_restore_into` calls. This is safe because the
/// fencing protocol in `acquire_and_restore_into` guarantees at-most-one
/// winner per shard. Workers that lose the race simply advance to the next
/// candidate. The worst case for a single worker is O(C) failed acquire
/// attempts where C is the number of candidates, since it tries each
/// candidate at most once.
///
/// ## Parameters
///
/// - `backend`: mutable reference to the coordination backend. The
///   `&mut B` bound means exactly one claim attempt is in flight per
///   backend instance at a time — concurrent claiming requires
///   separate backend instances (one per worker thread/task).
/// - `now`: logical timestamp threaded into both
///   `collect_claim_candidates_into` and `acquire_and_restore_into`.
///   The coordinator never reads a wall clock; passing time explicitly
///   is required for deterministic simulation.
/// - `tenant` / `run`: scope the candidate set and enforce isolation.
/// - `worker`: identity recorded on the new lease if acquire succeeds.
/// - `out`: caller-owned scratch space for the shard snapshot returned on
///   success. Reused across calls — no allocation in steady state.
/// - `candidates`: caller-owned buffer for shard IDs. Cleared and reused
///   per call; implementations may grow it when needed.
///
/// ## Complexity
///
/// O(S + C log C) where S is the number of shards in the run and C is the
/// number of claimable candidates (if the backend sorts candidates).
///
/// ## Errors
///
/// - [`ClaimError::NoneAvailable`] — no shards to claim (empty list
///   or all candidates lost to races).
/// - [`ClaimError::RunNotFound`] — the run does not exist.
/// - [`ClaimError::TenantMismatch`] — tenant isolation violation.
pub fn default_claim_next_available<'a, B: CoordinationBackend + RunManagement>(
    backend: &mut B,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
    out: &'a mut AcquireScratch,
    candidates: &mut Vec<ShardId>,
) -> Result<AcquireResultView<'a>, ClaimError> {
    let scan_deadline = backend
        .collect_claim_candidates_into(now, tenant, run, candidates)
        .map_err(ClaimError::from)?;

    if candidates.is_empty() {
        return Err(ClaimError::NoneAvailable {
            earliest_deadline: scan_deadline,
        });
    }

    let len = candidates.len();
    let offset = worker.as_raw() as usize % len;
    let mut inconsistency_count = 0usize;
    // Merge the scan-phase earliest deadline with any tighter deadlines
    // discovered during per-shard acquire attempts (AlreadyLeased errors).
    let mut earliest_deadline: Option<LogicalTime> = scan_deadline;
    let mut i = 0usize;
    let acquired = loop {
        if i == len {
            break None;
        }
        let shard_id = candidates[(offset + i) % len];
        let key = ShardKey::new(run, shard_id);
        match backend.acquire_and_restore_into(now, tenant, key, worker, out) {
            Ok(result) => {
                // Destructure into owned values before breaking out of the loop.
                // `result.snapshot` borrows `out`, and the loop needs to yield
                // ownership back to the caller — extracting the fields here
                // drops the borrow so `out.view()` can be called after the loop.
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
                // Race — another worker claimed it.  Track the deadline
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
                // Shard became terminal between scan and acquire.
                i += 1;
                continue;
            }
            Err(AcquireError::ShardNotFound { .. }) => {
                // collect_claim_candidates_into returned this shard but
                // acquire_and_restore says it doesn't exist.  Isolated
                // occurrences are tolerable (a concurrent split_replace
                // could cause a transient gap); all-not-found is data
                // corruption and is caught by the post-loop assert.
                debug_assert!(
                    false,
                    "claim_next_available: candidate shard {key:?} \
                     not found during acquire_and_restore_into"
                );
                inconsistency_count += 1;
                i += 1;
                continue;
            }
            Err(AcquireError::TenantMismatch { expected }) => {
                // Not a race — this is a logic bug (wrong tenant
                // threaded into the call). Fail immediately; retrying
                // other candidates would hit the same mismatch.
                return Err(ClaimError::TenantMismatch { expected });
            }
            Err(AcquireError::BackendError(infra)) => {
                // Infrastructure error — fail immediately; retrying
                // other candidates is unlikely to succeed.
                return Err(ClaimError::BackendError(infra));
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
        inconsistency_count < candidates.len(),
        "all {} candidates returned ShardNotFound — backend index vs shard map inconsistency",
        candidates.len(),
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
/// Backends implement [`claim_next_available`](Self::claim_next_available)
/// explicitly. Implementations can delegate to
/// [`default_claim_next_available`] as a building block:
///
/// ```rust,ignore
/// impl ShardClaiming for MyBackend {
///     fn claim_next_available<'a>(
///         &mut self,
///         now: LogicalTime,
///         tenant: TenantId,
///         run: RunId,
///         worker: WorkerId,
///         out: &'a mut AcquireScratch,
///     ) -> Result<AcquireResultView<'a>, ClaimError> {
///         // Temporarily take the scratch buffer to avoid simultaneous
///         // `&mut self` and `&mut self.claim_candidates_scratch`.
///         let mut candidates = std::mem::take(&mut self.claim_candidates_scratch);
///         let result = default_claim_next_available(
///             self, now, tenant, run, worker, out, &mut candidates,
///         );
///         self.claim_candidates_scratch = candidates;
///         result
///     }
/// }
/// ```
///
/// Backends that need custom claim behavior (e.g., per-worker cooldown,
/// SQL `SKIP LOCKED`, locality-aware selection) can implement their own
/// candidate selection/acquire loop.
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for `run`.
    ///
    /// On success, returns an [`AcquireResultView`] containing the lease
    /// (proof of ownership with fencing token), the shard snapshot
    /// (status, spec, cursor, cursor_semantics, lineage), and a
    /// [`CapacityHint`](crate::error::CapacityHint)
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
    ///   cooldown interval).
    ///
    /// [`InMemoryCoordinator`]: crate::in_memory::InMemoryCoordinator
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError>;
}

// No blanket impl: backends must implement `ShardClaiming` explicitly.

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
/// ## Typical lifecycle
///
/// ```rust,ignore
/// fn run_orchestrator<B: CoordinationFacade>(backend: &mut B) {
///     // Setup: create run and register its shard manifest.
///     // The run transitions Initializing -> Active on register_shards.
///     backend.create_run(now, tenant, run_id, config)?;
///     backend.register_shards(now, tenant, run_id, shards, op_id)?;
///
///     // Processing: each worker claims a shard, processes
///     // it with periodic checkpoints, and marks it complete.
///     let result = backend.claim_next_available(now, tenant, run_id, worker)?;
///     backend.checkpoint(now, tenant, &result.lease, cursor, op_id)?;
///     backend.complete(now, tenant, &result.lease, final_cursor, op_id)?;
///
///     // Finalization: once all shards are Done, the
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
