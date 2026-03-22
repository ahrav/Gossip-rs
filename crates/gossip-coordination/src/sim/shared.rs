//! Shared simulation utilities used by both [`super::harness::CoordinationSim`]
//! and [`super::composition::CompositionSim`].
//!
//! Extracted to eliminate duplication — every item here was previously defined
//! identically in both harness modules.

use std::collections::BTreeMap;

use rand::Rng;
use rand_chacha::ChaCha8Rng;

use gossip_contracts::coordination::cursor::MAX_KEY_SIZE;
use gossip_contracts::identity::{OpId, ShardKey, WorkerId};

use crate::Lease;

use super::worker::SimWorker;
use super::{RejectionKind, SimEvent};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default shard lease duration (in logical ticks) for the simulated coordinator.
///
/// Balances two competing needs:
/// - **Long enough** that warmup operations can acquire, checkpoint,
///   and renew before expiry, even with small time advances (1–50 ticks each).
/// - **Short enough** that a single Stormy time-jump (50–200 ticks) or two
///   Radioactive time-jumps (100–500 ticks) can expire a lease mid-flight,
///   creating the stale-lease and zombie-worker scenarios the simulation
///   is designed to stress-test.
pub(super) const DEFAULT_LEASE_DURATION: u64 = 100;

/// Maximum number of stale leases retained for zombie checkpoint injection.
///
/// Capped to prevent unbounded growth in long-running simulations. When
/// the limit is exceeded, random entries are evicted via `swap_remove`.
pub(super) const MAX_STALE_LEASES: usize = 64;

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

/// Per-(worker, run, shard) checkpoint history for replay/conflict testing.
///
/// Key is `(worker_raw, run_raw, shard_raw)` because the key includes a
/// `WorkerId` dimension that `ShardKey` does not carry. Value stores the
/// last successful checkpoint's `(OpId, last_key_bytes, WorkerId, ShardKey)`.
pub(super) type CheckpointOpMap = BTreeMap<(u64, u64, u64), (OpId, Vec<u8>, WorkerId, ShardKey)>;

/// Stack-owned copy of a shard's spec bounds: `(start_buf, start_len, end_buf, end_len)`.
///
/// Fixed-capacity arrays avoid holding immutable borrows into the coordinator
/// while building split plans that require mutable coordinator access.
pub(super) type SplitBoundsBuf = ([u8; MAX_KEY_SIZE], usize, [u8; MAX_KEY_SIZE], usize);

/// Split input snapshot: spec bounds plus the optional first cursor byte.
///
/// The cursor byte is used by split-residual to place the split point after
/// already-scanned data.
pub(super) type SplitInputCopy = (SplitBoundsBuf, Option<u8>);

// ---------------------------------------------------------------------------
// SessionTerminalAction
// ---------------------------------------------------------------------------

/// Terminal action selection for session lifecycle.
#[derive(Debug, Clone, Copy)]
pub(super) enum SessionTerminalAction {
    Complete,
    Park,
    SplitReplace,
    SplitResidualThenComplete,
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Validate worker preconditions and consume the next op-ID in one shot.
///
/// Checks that `worker` exists and is not paused (both conditions return
/// `WorkerPaused` — the harness registers all workers at init, so a missing
/// worker is a harness bug, not an expected rejection), holds a lease on `key`,
/// and advances its op-ID counter. Returns the lease and fresh op-ID on
/// success, or a `Rejected` event on failure.
///
/// This is a free function (not `&mut self`) to enable borrow splitting:
/// callers can pass `&mut self.workers` while retaining mutable access to
/// `self.coordinator`, `self.context`, and other fields.
pub(super) fn require_lease_and_op(
    workers: &mut BTreeMap<WorkerId, SimWorker>,
    worker: WorkerId,
    key: &ShardKey,
) -> Result<(Lease, OpId), SimEvent> {
    let w = workers
        .get_mut(&worker)
        .filter(|w| !w.is_paused())
        .ok_or(SimEvent::Rejected {
            kind: RejectionKind::WorkerPaused,
        })?;
    let lease = *w.lease_for(key).ok_or(SimEvent::Rejected {
        kind: RejectionKind::NotLeased,
    })?;
    let op_id = w.next_op_id();
    Ok((lease, op_id))
}

/// Compute a random split midpoint in the half-open interval `[lo, hi)`.
///
/// Returns `None` when the interval is empty (`lo >= hi`).
/// Used by split-plan precomputation and standalone split ops to eliminate
/// the duplicated range-check + sample pattern.
pub(super) fn random_midpoint(rng: &mut ChaCha8Rng, lo: u8, hi: u8) -> Option<u8> {
    if lo >= hi {
        return None;
    }
    Some(rng.random_range(lo..hi))
}
