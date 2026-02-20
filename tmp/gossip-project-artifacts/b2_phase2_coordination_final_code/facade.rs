//! Shard claiming and the `CoordinationFacade` super-trait.
//!
//! This module composes the three coordination traits into a single
//! type constraint for the orchestrator and scheduler layers.
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
//! `ShardClaiming` has a blanket implementation for any type that
//! implements both `CoordinationBackend` and `RunManagement`. The
//! default `claim_next_available` composes `list_shards(available)`
//! with `acquire_and_restore`. Backends MAY override for efficiency
//! (e.g., `SELECT ... FOR UPDATE SKIP LOCKED` in SQL backends).

use crate::identity::{
    LogicalTime, RunId, ShardKey, TenantId, WorkerId,
};
use crate::coordination::error::{AcquireError, AcquireResult};
use crate::coordination::run::{
    GetRunError, RunManagement, ShardFilter,
};
use crate::coordination::traits::CoordinationBackend;

// ============================================================================
// § ClaimError
// ============================================================================

/// Error from `claim_next_available`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClaimError {
    /// No available (active, unleased) shards exist for this run.
    NoneAvailable { run: RunId },
    /// The run does not exist.
    RunNotFound { run: RunId },
    /// Tenant isolation violation.
    TenantMismatch {
        expected: TenantId,
        actual: TenantId,
    },
}

// ============================================================================
// § ShardClaiming trait
// ============================================================================

/// Extension trait for shard claiming on backends that also implement
/// `RunManagement` (for `list_shards`).
///
/// Composes `list_shards(available)` + `acquire_and_restore` into a
/// single logical operation. Backends MAY override the default for
/// efficiency (e.g., single FDB transaction, SQL `SKIP LOCKED`).
///
/// ## Shard Selection Policy
///
/// The default iterates available shards in key-range order and tries
/// to acquire the first one. If acquisition fails (race), tries next.
///
/// Backends may implement more sophisticated policies:
/// - **Locality-aware**: prefer shards near the worker's previous shard
/// - **Load-balanced**: prefer shards with lower acquire_count
/// - **Priority-ordered**: prefer shards with specific labels
///
/// These are optimizations and do NOT affect correctness — any
/// available shard is a valid choice.
///
/// Reference: §2.2 — "work-stealing for dynamic load balancing";
///            Blumofe & Leiserson, JACM 1999.
pub trait ShardClaiming: CoordinationBackend + RunManagement {
    /// Attempt to claim the next available shard for this run.
    ///
    /// Returns an `AcquireResult` on success, or `ClaimError` if
    /// no shards are available.
    ///
    /// ## Default Implementation
    ///
    /// 1. `list_shards(filter: available)` — find active, unleased shards.
    /// 2. For each candidate, try `acquire_and_restore`.
    /// 3. Return the first successful acquisition.
    /// 4. If all fail (races), return `NoneAvailable`.
    ///
    /// ## Concurrency
    ///
    /// Multiple workers may race to claim the same shard. The fencing
    /// protocol ensures at most one succeeds. Losing workers retry with
    /// different candidates. Safe because `acquire_and_restore` is
    /// atomic (backend serializes concurrent acquisitions).
    fn claim_next_available(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
    ) -> Result<AcquireResult, ClaimError> {
        let summaries = self
            .list_shards(now, tenant, run, ShardFilter::available())
            .map_err(|e| match e {
                GetRunError::RunNotFound { run } => {
                    ClaimError::RunNotFound { run }
                }
                GetRunError::TenantMismatch { expected, actual } => {
                    ClaimError::TenantMismatch { expected, actual }
                }
            })?;

        if summaries.is_empty() {
            return Err(ClaimError::NoneAvailable { run });
        }

        for summary in &summaries {
            let key = ShardKey {
                run,
                shard: summary.shard,
            };
            match self.acquire_and_restore(now, tenant, key, worker) {
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
                    // Shouldn't happen — just listed. Defensive: skip.
                    continue;
                }
                Err(AcquireError::TenantMismatch {
                    expected, actual,
                }) => {
                    return Err(ClaimError::TenantMismatch {
                        expected,
                        actual,
                    });
                }
            }
        }

        // All candidates were claimed by other workers.
        Err(ClaimError::NoneAvailable { run })
    }
}

// Blanket implementation: any type implementing both traits gets claiming.
impl<T: CoordinationBackend + RunManagement> ShardClaiming for T {}

// ============================================================================
// § CoordinationFacade — combined super-trait
// ============================================================================

/// The complete coordination contract: shard operations + run management
/// + shard claiming.
///
/// This is the type constraint used by the orchestrator and scheduler.
///
/// ```rust,ignore
/// fn run_orchestrator<B: CoordinationFacade>(backend: &mut B) {
///     let run = backend.create_run(now, tenant, run_id, config)?;
///     backend.register_shards(now, tenant, run_id, shards, op_id)?;
///     let result = backend.claim_next_available(now, tenant, run_id, worker)?;
///     backend.checkpoint(now, tenant, &result.lease, cursor, op_id)?;
///     backend.complete(now, tenant, &result.lease, final_cursor, op_id)?;
/// }
/// ```
pub trait CoordinationFacade:
    CoordinationBackend + RunManagement + ShardClaiming
{
}

// Blanket implementation.
impl<T: CoordinationBackend + RunManagement + ShardClaiming>
    CoordinationFacade for T
{
}

// ============================================================================
// § Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Static assertion: InMemoryCoordinator implements CoordinationFacade.
    // This is a compile-time check — if it compiles, the blanket impl works.
    #[cfg(feature = "test-support")]
    fn _assert_facade_impl(
        _b: &mut crate::coordination::in_memory::InMemoryCoordinator,
    ) {
        fn requires_facade<B: CoordinationFacade>(_: &mut B) {}
        // requires_facade(_b);  // Uncomment when full impl is wired
    }

    // TODO: test claim_next_available_ok
    //   - Create run with 3 shards
    //   - claim_next_available → acquires first available shard
    //   - Verify: result.lease is valid, snapshot has correct spec

    // TODO: test claim_next_available_none
    //   - Create run with 1 shard, acquire it manually
    //   - claim_next_available → Err(NoneAvailable)

    // TODO: test claim_next_available_skips_leased
    //   - Create run with 2 shards, acquire first manually
    //   - claim_next_available → acquires second shard

    // TODO: test claim_next_available_skips_terminal
    //   - Create run with 2 shards, complete first
    //   - claim_next_available → acquires second shard

    // TODO: test claim_next_available_run_not_found
    //   - claim_next_available on nonexistent run → Err(RunNotFound)

    // TODO: test claim_next_available_all_workers_claim
    //   - Create run with 3 shards
    //   - 3 sequential claims → each gets different shard
    //   - 4th claim → Err(NoneAvailable)

    // TODO: test claim_next_available_after_lease_expiry
    //   - Create run, claim shard, let lease expire
    //   - claim_next_available with new worker → acquires same shard
    //   - (shard appears available after lease expiry)

    // TODO: test facade_trait_constraint
    //   - Function with `B: CoordinationFacade` compiles
    //   - InMemoryCoordinator satisfies the constraint
}
