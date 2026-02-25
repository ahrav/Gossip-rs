//! In-memory reference implementation of the [`CoordinationBackend`] trait.
//!
//! # Purpose
//!
//! This backend is the **executable specification** for the shard coordination
//! protocol. Every protocol rule (fencing, leases, idempotency, cursor
//! monotonicity, split coverage) is enforced here first; production backends
//! (Postgres, DynamoDB, etc.) must produce identical observable behavior.
//!
//! # Design choices
//!
//! - **Single-threaded** — `&mut self` serializes all operations, eliminating
//!   concurrency concerns so invariants can be verified in-line.
//! - **Purely in-memory** — two-level `AHashMap<TenantId, AHashMap<ShardKey, ShardRecord>>`.
//!   No I/O, no transactions, no retries.
//! - **No event emission wiring yet** — operation sites contain
//!   `TODO(events)` markers where `EventCollector` hooks can be added later.
//! - **Tiger-style invariant enforcement** — mutation paths that can affect
//!   multi-field shard invariants call [`ShardRecord::assert_invariants()`]
//!   before returning. Simpler paths (for example lease refresh/acquire
//!   updates) mutate a constrained field subset and rely on targeted guards.
//!   A violated invariant panics immediately (crash-to-prevent-corruption).
//!
//! # Protocol foundations
//!
//! - **Fencing tokens** (Kleppmann 2016): each `acquire_and_restore_into` bumps a
//!   monotonic `fence_epoch`. Stale workers are rejected by epoch comparison.
//! - **Leases** (Gray & Cheriton 1989): time-bounded ownership via
//!   `LeaseHolder { owner, deadline }`. Expiry makes shards re-acquirable.
//! - **Bounded idempotency** (Stripe pattern): shard-level mutations use a
//!   16-entry FIFO op-log for `(OpId, payload_hash)` replay detection.
//!   Run-level lifecycle operations use a separate run op-log
//!   ([`RunRecord::OP_LOG_CAP`], currently 8 entries). Replays return cached
//!   results; hash mismatches yield `OpIdConflict`.
//!
//! # Shard state machine
//!
//! ```text
//!        ┌──────────────┐
//!        │    Active     │
//!        └──┬───┬────┬──┘
//!           │   │    │
//!  complete │   │    │ park_shard
//!    ┌──────┘   │    └───────┐
//!    ▼    split_replace      ▼
//! ┌──────┐      │       ┌────────┐
//! │ Done │      ▼       │ Parked │
//! └──────┘  ┌───────┐   └───┬────┘
//!           │ Split  │       │ unpark_shard
//!           └───────┘       │ (admin, bumps fence)
//!                           ▼
//!                      back to Active
//! ```
//!
//! All transitions originate from `Active`. `Done` and `Split` are permanently
//! terminal. `Parked` has one escape: `unpark_shard` ([`RunManagement`], not
//! [`CoordinationBackend`]) transitions Parked → Active, bumping the fence
//! epoch. All other terminal-state mutations are rejected.
//!
//! `split_residual` is special: it shrinks the parent's range and spawns a
//! residual child, but the parent stays `Active`.
//!
//! # Allocation-failure policy
//!
//! Hot-path functions use a **two-strategy** approach to allocation failures:
//!
//! 1. **Pre-reservation (recoverable).**  Before entering a mutation sequence,
//!    a dedicated `reserve_*` or `check_*` method calls `try_reserve` and
//!    returns a typed error (e.g. `CapacityExceeded`, `SlabFull`) if the
//!    allocator cannot satisfy the request.  Callers can propagate this error
//!    without any state corruption because no mutation has begun.
//!
//! 2. **Defense-in-depth panics (unreachable after pre-reservation).**  During
//!    the subsequent commit phase, individual insertions may still call
//!    `try_reserve(…).unwrap_or_else(|_| panic!(…))`.  These panics exist as a
//!    safety net: if the pre-reservation protocol was followed correctly, the
//!    capacity is already available and the panic never fires.  If it *does*
//!    fire, it indicates a bug in the reservation logic, and crashing is
//!    preferable to silent data corruption.
//!
//! Examples:
//! - `reserve_register_shard_capacity` + `reserve_register_index_capacity`
//!   run before `register_shards` commits shard records and index entries.
//! - `ensure_claim_cooldown_capacity` runs before `claim_next_available`
//!   inserts a cooldown entry.
//! - `index_shard` panics on `try_reserve` are defense-in-depth; callers
//!   (`split_replace`, `split_residual`) have already passed shard-count
//!   validation and the run's index entry exists from `register_shards`.
//!
//! # Split operation memory-safety pattern
//!
//! Both split operations temporarily **remove** the parent record from the map,
//! mutate it inside a closure, then **restore** it on both success and failure
//! paths. This avoids holding a `&mut ShardRecord` (from `get_mut`) while also
//! inserting new child entries into the same `HashMap`. If the closure panics
//! (invariant violation),
//! the parent is intentionally *not* restored — an invariant panic indicates
//! irrecoverable corruption.
//!
//! # Performance note
//!
//! `claim_next_available` (via `ShardClaiming`) scans the run index and sorts
//! available candidates by key range in-place. The resulting worst case is
//! O(S log S) where S is the run's shard count. Acceptable here; production
//! backends need a secondary available-shards index.

use std::collections::{HashMap, HashSet};

use crate::coordination::cursor::CursorUpdate;
use crate::coordination::error::{
    AcquireError, AcquireResultView, AcquireScratch, CapacityHint, CheckpointError, CompleteError,
    IdempotentOutcome, ParkError, RenewError, RenewResult, SplitReplaceError, SplitResidualError,
};
use crate::coordination::facade::{ClaimError, ShardClaiming};
use crate::coordination::lease::{Lease, LeaseHolder, OpKind, OpLogEntry, OpResult};
use crate::coordination::record::{ParkReason, ShardRecord, ShardStatus};
use crate::coordination::run::{
    InitialShardInput, RunConfig, RunManagement, RunOpKind, RunOpLogEntry, RunOpResult,
    RunProgress, RunRecord, RunStatus, ShardFilter, ShardSummary, hash_cancel_run_payload,
    hash_complete_run_payload, hash_fail_run_payload, hash_register_shards_payload,
    hash_unpark_payload, validate_manifest,
};
use crate::coordination::run_errors::{
    CreateRunError, GetRunError, RegisterShardsError, RunTransitionError, UnparkError,
};
use crate::coordination::shard_spec::{
    ShardLimitScope, ShardSpec, ShardSpecRef, SplitValidationError, validate_residual_split_bounds,
};
use crate::coordination::split::{
    DerivedShardKind, MAX_SPAWNED_PER_SHARD, MAX_SPLIT_CHILDREN, SplitReplaceChild,
    SplitReplacePlan, SplitReplaceResult, SplitResidualPlan, SplitResidualResult,
    derive_split_shard_id, hash_checkpoint_payload, hash_complete_payload, hash_park_payload,
    hash_split_replace_payload, hash_split_residual_payload,
};
use crate::coordination::traits::CoordinationBackend;
use crate::coordination::validation::{
    check_op_idempotency, validate_cursor_update_pooled, validate_lease,
};
use crate::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};
use gossip_stdx::{ByteSlab, RingBuffer};

/// aHash-backed `HashMap` — faster hashing than the std default
/// (`DefaultHasher`, which uses SipHash-1-3) for point lookups. aHash
/// provides hash-flooding resistance via per-instance random keys
/// (uses AES-NI where available).
type AHashMap<K, V> = HashMap<K, V, ahash::RandomState>;

// Initial map/set capacity policy.
//
// These values are intentionally conservative. They reduce eager allocation
// compared with the previous fixed-capacity (64/16) policy while keeping
// behavior identical as structures grow.
const TOP_LEVEL_SHARDS_MAP_MIN_INITIAL_CAPACITY: usize = 4;
const TOP_LEVEL_SHARDS_MAP_MAX_INITIAL_CAPACITY: usize = 16;
const TOP_LEVEL_RUNS_MAP_INITIAL_CAPACITY: usize = 8;
const TOP_LEVEL_RUN_SHARDS_MAP_INITIAL_CAPACITY: usize = 8;
const TOP_LEVEL_CLAIM_COOLDOWNS_MAP_INITIAL_CAPACITY: usize = 8;
const TENANT_SHARDS_MAP_MIN_INITIAL_CAPACITY: usize = 4;
const TENANT_SHARDS_MAP_MAX_INITIAL_CAPACITY: usize = 32;
const RUN_SHARD_SET_INITIAL_CAPACITY: usize = 8;
const DEFAULT_MAX_SHARDS_PER_TENANT: usize = 100_000;
const DEFAULT_MAX_TOTAL_SHARDS: usize = 1_000_000;
const SHARD_RECORD_PLANNING_BYTES: usize = 728;
const RUN_RECORD_PLANNING_BYTES: usize = 512;
const SHARD_ENTRY_OVERHEAD_BYTES: usize = 72;
const RUN_ENTRY_OVERHEAD_BYTES: usize = 80;
const WORKER_COOLDOWN_ENTRY_BYTES: usize = 16;
const COORDINATOR_BASE_BYTES: usize = 4096;

#[inline]
fn ahash_map_with_capacity<K, V>(capacity: usize) -> AHashMap<K, V> {
    AHashMap::with_capacity_and_hasher(capacity, ahash::RandomState::default())
}

#[inline]
fn ahash_set_with_capacity<T>(capacity: usize) -> HashSet<T, ahash::RandomState> {
    HashSet::with_capacity_and_hasher(capacity, ahash::RandomState::default())
}

#[inline]
fn top_level_shards_map_initial_capacity(
    max_total_shards: usize,
    max_shards_per_tenant: usize,
) -> usize {
    // Estimate tenant cardinality from shard limits, then clamp to a small
    // startup range so tiny deployments do not pre-allocate aggressively.
    let tenant_limit = max_shards_per_tenant.max(1);
    let estimated_tenants = max_total_shards.div_ceil(tenant_limit);
    estimated_tenants.clamp(
        TOP_LEVEL_SHARDS_MAP_MIN_INITIAL_CAPACITY,
        TOP_LEVEL_SHARDS_MAP_MAX_INITIAL_CAPACITY,
    )
}

#[inline]
fn tenant_shards_map_initial_capacity(max_shards_per_tenant: usize) -> usize {
    max_shards_per_tenant.clamp(
        TENANT_SHARDS_MAP_MIN_INITIAL_CAPACITY,
        TENANT_SHARDS_MAP_MAX_INITIAL_CAPACITY,
    )
}

/// Runtime constructor configuration for [`InMemoryCoordinator`].
///
/// This type drives operational constructor behavior:
/// lease duration, shard limits, and optional claim cooldown.
/// It intentionally excludes planning-only budget knobs from
/// [`CoordinatorConfig`] so runtime enforcement and capacity estimation can
/// evolve independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorRuntimeConfig {
    /// Duration (in logical time units) applied to every new lease.
    pub default_lease_duration: u64,
    /// Maximum number of shards a single tenant may own.
    pub max_shards_per_tenant: usize,
    /// Maximum total shards across all tenants.
    pub max_total_shards: usize,
    /// Minimum logical time units between successful claims by the same worker.
    /// Zero disables cooldown.
    pub claim_cooldown_interval: u64,
    /// Byte slab capacity for arena-pooled shard fields (spec + cursor).
    /// Zero uses an auto-sized default:
    /// `min(max_total_shards * DEFAULT_PER_SHARD_SLAB_BUDGET,
    /// DEFAULT_MAX_AUTO_SLAB_CAPACITY)`. Any explicit value above
    /// `MAX_SLAB_CAPACITY` is clamped to that backend limit.
    /// The caps avoid pathological eager allocation and keep construction
    /// compatible with `ByteSlab`'s `u32`-addressed backing store.
    pub slab_capacity: usize,
}

/// Default per-shard byte budget for slab sizing.
///
/// Each shard stores up to 5 variable-length fields: 3 in spec
/// (key_range_start, key_range_end, metadata) and 2 in cursor
/// (last_key, token). With power-of-2 rounding, typical shards
/// use 1-4 KiB. 4 KiB is a conservative default covering most
/// workloads; ES scroll tokens (10 KiB) and large metadata
/// require a higher budget.
const DEFAULT_PER_SHARD_SLAB_BUDGET: usize = 4_096;
/// Upper bound for auto-sized slab capacity.
///
/// Without this cap, deriving from `max_total_shards` can over-allocate
/// at startup (e.g., default limits imply ~4 GiB).
const DEFAULT_MAX_AUTO_SLAB_CAPACITY: usize = 64 * 1024 * 1024;
/// Maximum capacity accepted by `ByteSlab` (`u32`-addressed backing store).
const MAX_SLAB_CAPACITY: usize = u32::MAX as usize;

impl CoordinatorRuntimeConfig {
    /// Create a runtime config with explicit parameters.
    #[must_use]
    pub const fn new(
        default_lease_duration: u64,
        max_shards_per_tenant: usize,
        max_total_shards: usize,
        claim_cooldown_interval: u64,
    ) -> Self {
        Self {
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
            claim_cooldown_interval,
            slab_capacity: 0, // use default
        }
    }

    /// Create a runtime config with explicit shard limits and no cooldown.
    #[must_use]
    pub const fn with_limits(
        default_lease_duration: u64,
        max_shards_per_tenant: usize,
        max_total_shards: usize,
    ) -> Self {
        Self::new(
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
            0,
        )
    }

    /// Derive slab capacity from config, using the explicit value if set
    /// or computing the capped default formula from `max_total_shards`.
    ///
    /// Explicit capacities are clamped to [`MAX_SLAB_CAPACITY`]. Auto-sized
    /// capacities are clamped to both startup budget
    /// ([`DEFAULT_MAX_AUTO_SLAB_CAPACITY`]) and backend addressability.
    const fn effective_slab_capacity(&self) -> usize {
        if self.slab_capacity > 0 {
            if self.slab_capacity > MAX_SLAB_CAPACITY {
                MAX_SLAB_CAPACITY
            } else {
                self.slab_capacity
            }
        } else {
            // Saturate to avoid overflow on pathological configs.
            let derived = match self
                .max_total_shards
                .checked_mul(DEFAULT_PER_SHARD_SLAB_BUDGET)
            {
                Some(v) => v,
                None => usize::MAX,
            };
            if derived > DEFAULT_MAX_AUTO_SLAB_CAPACITY {
                DEFAULT_MAX_AUTO_SLAB_CAPACITY
            } else if derived > MAX_SLAB_CAPACITY {
                MAX_SLAB_CAPACITY
            } else {
                derived
            }
        }
    }
}

/// Planning-only configuration for memory budget estimation.
///
/// Models expected memory needs from deployment-level parameters using a
/// static formula. See `docs/memory-budget-audit.md`.
///
/// This configuration does not configure runtime behavior and is not
/// runtime-enforced. Coordinator construction uses
/// [`CoordinatorRuntimeConfig`] (via
/// [`InMemoryCoordinator::with_runtime_config`]); this type remains for
/// capacity planning and memory-budget estimation only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CoordinatorConfig {
    /// Global shard cap.
    pub max_total_shards: usize,
    /// Per-tenant shard cap.
    pub max_shards_per_tenant: usize,
    /// Maximum concurrent runs.
    pub max_runs: usize,
    /// Maximum distinct workers.
    pub max_workers: usize,
    /// Per-shard byte budget for variable-length fields (keys, metadata, token, spawned).
    pub per_shard_budget: usize,
    /// Per-run byte budget for root_shards + op results.
    pub per_run_budget: usize,
}

impl CoordinatorConfig {
    /// Create a config with explicit parameters.
    #[must_use]
    pub const fn new(
        max_total_shards: usize,
        max_shards_per_tenant: usize,
        max_runs: usize,
        max_workers: usize,
        per_shard_budget: usize,
        per_run_budget: usize,
    ) -> Self {
        Self {
            max_total_shards,
            max_shards_per_tenant,
            max_runs,
            max_workers,
            per_shard_budget,
            per_run_budget,
        }
    }

    /// Defaults for local development and unit tests.
    ///
    /// ~6.6 MiB: 512 shards, 64 runs, 16 workers.
    #[must_use]
    pub const fn dev_defaults() -> Self {
        Self {
            max_total_shards: 512,
            max_shards_per_tenant: 256,
            max_runs: 64,
            max_workers: 16,
            per_shard_budget: 4_096,
            per_run_budget: 2_048,
        }
    }

    /// Defaults for staging / integration tests.
    ///
    /// ~168 MiB: 10 K shards, 1 K runs, 256 workers.
    #[must_use]
    pub const fn staging_defaults() -> Self {
        Self {
            max_total_shards: 10_000,
            max_shards_per_tenant: 2_000,
            max_runs: 1_000,
            max_workers: 256,
            per_shard_budget: 8_192,
            per_run_budget: 4_096,
        }
    }

    /// Defaults for production deployments.
    ///
    /// ~24.4 GiB: 1 M shards, 100 K runs, 10 K workers.
    #[must_use]
    pub const fn prod_defaults() -> Self {
        Self {
            max_total_shards: 1_000_000,
            max_shards_per_tenant: 100_000,
            max_runs: 100_000,
            max_workers: 10_000,
            per_shard_budget: 16_384,
            per_run_budget: 8_192,
        }
    }

    /// Estimate planning memory budget in bytes.
    ///
    /// Formula:
    /// `M = S * (SR + B_s + SO) + R * (RR + B_r + RO) + W * WC + CB`
    ///
    /// Where:
    /// - `S` = `max_total_shards`, `B_s` = `per_shard_budget`
    /// - `R` = `max_runs`, `B_r` = `per_run_budget`
    /// - `W` = `max_workers`
    /// - `SR` = [`SHARD_RECORD_PLANNING_BYTES`]
    /// - `SO` = [`SHARD_ENTRY_OVERHEAD_BYTES`]
    /// - `RR` = [`RUN_RECORD_PLANNING_BYTES`]
    /// - `RO` = [`RUN_ENTRY_OVERHEAD_BYTES`]
    /// - `WC` = [`WORKER_COOLDOWN_ENTRY_BYTES`]
    /// - `CB` = [`COORDINATOR_BASE_BYTES`]
    ///
    /// Assumptions:
    /// - Struct-size constants (`SR`, `RR`) match this target's layout
    ///   (validated by `memory_budget_constants_match_struct_sizes`).
    /// - HashMap overhead terms (`72`, `80`, `16`) are modeling estimates
    ///   for current key/bucket metadata behavior.
    /// - One cooldown entry exists per distinct worker.
    /// - Allocator fragmentation, transient resize peaks, and runtime
    ///   implementation variance are excluded.
    ///
    /// Planning-only contract: this estimate is not a hard runtime bound and
    /// is not consulted by allocation paths.
    ///
    /// # Panics
    ///
    /// Panics with a deterministic message if any intermediate arithmetic
    /// overflows `usize`.
    #[must_use]
    pub const fn memory_budget(&self) -> usize {
        let per_shard_base = match SHARD_RECORD_PLANNING_BYTES.checked_add(self.per_shard_budget) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: per-shard base"),
        };
        let per_shard = match per_shard_base.checked_add(SHARD_ENTRY_OVERHEAD_BYTES) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: per-shard overhead"),
        };

        let per_run_base = match RUN_RECORD_PLANNING_BYTES.checked_add(self.per_run_budget) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: per-run base"),
        };
        let per_run = match per_run_base.checked_add(RUN_ENTRY_OVERHEAD_BYTES) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: per-run overhead"),
        };

        let shard_bytes = match self.max_total_shards.checked_mul(per_shard) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: shard contribution"),
        };
        let run_bytes = match self.max_runs.checked_mul(per_run) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: run contribution"),
        };
        let worker_bytes = match self.max_workers.checked_mul(WORKER_COOLDOWN_ENTRY_BYTES) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: worker contribution"),
        };

        let with_runs = match shard_bytes.checked_add(run_bytes) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: shard+run total"),
        };
        let with_workers = match with_runs.checked_add(worker_bytes) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: shard+run+worker total"),
        };
        match with_workers.checked_add(COORDINATOR_BASE_BYTES) {
            Some(value) => value,
            None => panic!("CoordinatorConfig::memory_budget overflow: final total"),
        }
    }

    /// Estimate planning memory budget in mebibytes (rounded up).
    ///
    /// # Panics
    ///
    /// Propagates any overflow panic from [`memory_budget`](Self::memory_budget).
    #[must_use]
    pub const fn memory_budget_mb(&self) -> usize {
        self.memory_budget().div_ceil(1 << 20)
    }
}

/// In-memory coordinator for shard-level operations.
///
/// # Keying strategy
///
/// Shards use a two-level map: `AHashMap<TenantId, AHashMap<ShardKey, ShardRecord>>`.
/// The outer level provides O(1) tenant isolation — a wrong-tenant lookup misses
/// at the outer map without scanning any shard records. The inner level reduces
/// hash input from 48 bytes (composite key) to 16 bytes (`ShardKey` only).
///
/// `total_shard_count` is maintained inline (incremented on insert, decremented
/// on remove) so that global limit checks remain O(1) instead of O(T) where
/// T = number of tenants.
///
/// # Lease duration
///
/// `default_lease_duration` is stored on the coordinator (not per-record)
/// because lease length is an operational parameter of the deployment, not
/// an intrinsic property of a shard. All shards served by this coordinator
/// share the same duration.
pub struct InMemoryCoordinator {
    /// Two-level shard map: tenant → (shard_key → record).
    ///
    /// Per-tenant shard count is `inner.len()` — O(1) instead of the
    /// previous O(N) full-map scan in `check_shard_limits`.
    shards: AHashMap<TenantId, AHashMap<ShardKey, ShardRecord>>,
    /// Global shard count, maintained inline on insert/remove.
    ///
    /// Invariant: `total_shard_count == self.shards.values().map(|m| m.len()).sum::<usize>()`.
    /// Verified via `assert!` after mutations.
    total_shard_count: usize,
    /// Run records keyed by `(tenant, run)`.
    ///
    /// A run groups a set of shards that collectively cover a single scan
    /// target. The run record tracks lifecycle status (Initializing, Active,
    /// terminal) and the root shard manifest.
    runs: AHashMap<(TenantId, RunId), RunRecord>,
    /// Secondary index: run → shard IDs (root + split children).
    ///
    /// Uses `HashSet` for O(1) dedup in `index_shard`.
    /// Iteration order doesn't matter — `list_shards_into`
    /// sorts results by `key_range_start` afterward.
    run_shards: AHashMap<(TenantId, RunId), HashSet<ShardId, ahash::RandomState>>,
    /// Duration (in logical time units) applied to every new lease.
    ///
    /// Stored on the coordinator rather than per-shard because lease
    /// length is a deployment-level parameter shared across all shards.
    default_lease_duration: u64,
    /// Maximum number of shards a single tenant may have across all runs.
    ///
    /// Prevents a single tenant from monopolizing coordinator resources.
    /// Checked on shard creation (register, split).
    max_shards_per_tenant: usize,
    /// Maximum total shards across all tenants.
    ///
    /// Hard upper bound to prevent unbounded memory growth from
    /// split-flooding (CWE-400). Checked alongside `max_shards_per_tenant`.
    max_total_shards: usize,
    /// Per-worker claim cooldown: worker -> last successful claim time.
    ///
    /// Only accessed via point lookups (`get`/`insert`). Grows at most one
    /// entry per distinct `WorkerId` that successfully claims a shard.
    ///
    /// Entries are never evicted: once a worker claims, its timestamp
    /// remains for the coordinator's lifetime. This is acceptable
    /// because bounded worker population is an operational assumption
    /// of the deployment, not local enforcement in this coordinator.
    /// Adding periodic eviction here would turn the average O(1)
    /// `check_cooldown` path into O(N). Production backends should use
    /// TTL-based eviction at the storage layer.
    claim_cooldowns: AHashMap<WorkerId, LogicalTime>,
    /// Minimum logical time units between successive successful claims
    /// by the same worker. Zero disables cooldown entirely.
    ///
    /// Like `default_lease_duration`, this is a deployment-level
    /// operational parameter, not a per-shard or per-run property.
    claim_cooldown_interval: u64,
    /// Arena allocator for pooled `ShardRecord` fields (spec key ranges,
    /// cursor keys/tokens). Shared by all records in `self.shards`.
    slab: ByteSlab,
    /// Reusable scratch for `register_shards` shard ID staging.
    ///
    /// Grows to the largest observed manifest and is then cleared/reused so
    /// repeated registrations avoid fresh `Vec` allocation.
    register_shard_ids_scratch: Vec<ShardId>,
    /// Reusable scratch for `register_shards` staged record construction.
    ///
    /// Holds `(ShardKey, ShardRecord)` pairs during collect-then-insert, then
    /// is returned to this field for reuse on the next call.
    register_stage_scratch: Vec<(ShardKey, ShardRecord)>,
    /// Reusable shard-id candidate buffer for claim hot path.
    ///
    /// Cleared and reused across calls to keep `claim_next_available`
    /// allocation-silent after warmup.
    claim_candidates_scratch: Vec<ShardId>,
}

impl std::fmt::Debug for InMemoryCoordinator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InMemoryCoordinator")
            .field("total_shard_count", &self.total_shard_count)
            .field("runs", &self.runs.len())
            .field("default_lease_duration", &self.default_lease_duration)
            .field("max_shards_per_tenant", &self.max_shards_per_tenant)
            .field("max_total_shards", &self.max_total_shards)
            .field("claim_cooldown_interval", &self.claim_cooldown_interval)
            .finish_non_exhaustive()
    }
}

impl InMemoryCoordinator {
    /// Create a new coordinator with the given default lease duration
    /// and generous default shard limits.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0.
    pub fn new(default_lease_duration: u64) -> Self {
        Self::with_runtime_config(CoordinatorRuntimeConfig::with_limits(
            default_lease_duration,
            DEFAULT_MAX_SHARDS_PER_TENANT,
            DEFAULT_MAX_TOTAL_SHARDS,
        ))
    }

    /// Create a coordinator from explicit runtime constructor config.
    ///
    /// `new`, `with_limits`, and `with_cooldown` all delegate here so
    /// constructor behavior stays aligned while preserving existing call sites.
    /// The config also seeds conservative initial map/set capacities; shard
    /// limits are enforced by runtime checks, not by those initial capacities.
    /// Explicit slab capacity requests are sanitized through
    /// `effective_slab_capacity()` so constructor callers cannot exceed
    /// `ByteSlab`'s representable maximum.
    /// In debug builds, `claim_cooldown_interval > default_lease_duration`
    /// triggers a `debug_assert!` because it is usually a misconfiguration.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0 or if either shard limit is 0.
    pub fn with_runtime_config(config: CoordinatorRuntimeConfig) -> Self {
        let CoordinatorRuntimeConfig {
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
            claim_cooldown_interval,
            slab_capacity: _,
        } = config;

        assert!(default_lease_duration > 0, "lease duration must be > 0");
        assert!(
            max_shards_per_tenant > 0,
            "max_shards_per_tenant must be > 0"
        );
        assert!(max_total_shards > 0, "max_total_shards must be > 0");
        debug_assert!(
            claim_cooldown_interval == 0 || claim_cooldown_interval <= default_lease_duration,
            "claim_cooldown_interval ({claim_cooldown_interval}) exceeds \
             default_lease_duration ({default_lease_duration}); a worker cannot \
             claim a second shard within one lease period"
        );

        let top_level_shards_capacity =
            top_level_shards_map_initial_capacity(max_total_shards, max_shards_per_tenant);
        Self {
            shards: ahash_map_with_capacity(top_level_shards_capacity),
            total_shard_count: 0,
            runs: ahash_map_with_capacity(TOP_LEVEL_RUNS_MAP_INITIAL_CAPACITY),
            run_shards: ahash_map_with_capacity(TOP_LEVEL_RUN_SHARDS_MAP_INITIAL_CAPACITY),
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
            claim_cooldowns: ahash_map_with_capacity(
                TOP_LEVEL_CLAIM_COOLDOWNS_MAP_INITIAL_CAPACITY,
            ),
            claim_cooldown_interval,
            slab: ByteSlab::with_capacity(config.effective_slab_capacity()),
            register_shard_ids_scratch: Vec::with_capacity(RUN_SHARD_SET_INITIAL_CAPACITY),
            register_stage_scratch: Vec::with_capacity(RUN_SHARD_SET_INITIAL_CAPACITY),
            claim_candidates_scratch: Vec::with_capacity(RUN_SHARD_SET_INITIAL_CAPACITY),
        }
    }

    /// Create a coordinator with explicit shard count limits.
    ///
    /// Compatibility wrapper for call sites that do not need claim cooldown.
    ///
    /// # Panics
    ///
    /// Panics if `default_lease_duration` is 0 or if either limit is 0.
    pub fn with_limits(
        default_lease_duration: u64,
        max_shards_per_tenant: usize,
        max_total_shards: usize,
    ) -> Self {
        Self::with_runtime_config(CoordinatorRuntimeConfig::with_limits(
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
        ))
    }

    /// Create a coordinator with explicit shard limits and claim cooldown.
    ///
    /// Compatibility wrapper for call sites that set cooldown explicitly.
    ///
    /// # Parameters
    ///
    /// - `default_lease_duration` -- duration (in logical time units)
    ///   applied to every new lease. Must be > 0.
    /// - `max_shards_per_tenant` -- upper bound on shards a single
    ///   tenant may hold across all runs. Must be > 0.
    /// - `max_total_shards` -- hard cap on total shards across all
    ///   tenants. Must be > 0.
    /// - `claim_cooldown_interval` -- minimum logical time units between
    ///   successive successful claims by the same worker. Zero disables
    ///   cooldown entirely.
    ///
    /// # Panics
    ///
    /// Same as [`with_limits`](Self::with_limits).
    pub fn with_cooldown(
        default_lease_duration: u64,
        max_shards_per_tenant: usize,
        max_total_shards: usize,
        claim_cooldown_interval: u64,
    ) -> Self {
        Self::with_runtime_config(CoordinatorRuntimeConfig::new(
            default_lease_duration,
            max_shards_per_tenant,
            max_total_shards,
            claim_cooldown_interval,
        ))
    }

    /// Mutable reference to the coordinator's slab (test/fixture helper).
    ///
    /// Exposes the slab so tests can create `ShardRecord` values that
    /// allocate into the same arena as production paths.
    #[cfg(any(test, feature = "test-support"))]
    pub fn slab_mut(&mut self) -> &mut ByteSlab {
        &mut self.slab
    }

    /// Shared reference to the coordinator's slab (test/fixture helper).
    #[cfg(any(test, feature = "test-support"))]
    pub fn slab(&self) -> &ByteSlab {
        &self.slab
    }

    /// Seed a shard record directly (test/fixture helper).
    ///
    /// Does not enforce shard count limits — this is a test helper for
    /// constructing specific states. Also updates the `run_shards` index
    /// so that `list_shards_into` can discover seeded shards (required by
    /// `claim_next_available`).
    ///
    /// # Panics
    ///
    /// Panics if `record` violates any [`ShardRecord`] invariant.
    /// This catches malformed test fixtures early rather than letting them
    /// propagate to confusing failures later.
    ///
    /// In production paths, shards are created through `register_shards`
    /// (root shards) or split operations (derived children), both of
    /// which construct records with correct invariants by construction.
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_shard(&mut self, record: ShardRecord) {
        record.assert_invariants(&self.slab);
        let key = ShardKey::new(record.run, record.shard);
        self.index_shard(record.tenant, record.run, record.shard);
        self.shard_insert(record.tenant, key, record);
    }

    /// Seed a shard record **without** calling `assert_invariants()`.
    ///
    /// Only available in test builds — allows inserting intentionally
    /// invalid records for testing external invariant checkers.
    #[cfg(test)]
    pub fn seed_shard_unchecked(&mut self, record: ShardRecord) {
        let key = ShardKey::new(record.run, record.shard);
        self.index_shard(record.tenant, record.run, record.shard);
        self.shard_insert(record.tenant, key, record);
    }

    /// Seed a run record directly (test/fixture helper).
    ///
    /// Creates an `Active` run with `shard_ids` as root shards, bypassing
    /// the two-phase `create_run` → `register_shards` flow. Paired with
    /// [`seed_shard`](Self::seed_shard) for constructing specific states.
    ///
    /// No-op if the run already exists (idempotent for multi-shard setups).
    #[cfg(any(test, feature = "test-support"))]
    pub fn seed_run(
        &mut self,
        tenant: TenantId,
        run: RunId,
        shard_ids: Vec<ShardId>,
        lease_duration: u64,
    ) {
        use crate::coordination::shard_spec::CursorSemantics;

        if self.runs.contains_key(&(tenant, run)) {
            return;
        }
        let config = RunConfig::try_new(CursorSemantics::Completed, lease_duration, Some(5))
            .expect("seed_run: invalid lease_duration");
        let record = RunRecord {
            tenant,
            run,
            config,
            status: RunStatus::Active,
            created_at: LogicalTime::from_raw(1),
            completed_at: None,
            root_shards: shard_ids,
            op_log: RingBuffer::new(),
        };
        record.assert_invariants();
        self.runs.insert((tenant, run), record);
    }

    // `shards()`, `shard_count()`, and `shard_lookup()` are provided via
    // the `SimIntrospection` trait impl below. Simulation is first-class
    // verification (FoundationDB model), not unit testing — no cfg gates.

    // -- Internal two-level map helpers --

    /// Look up a shard record by tenant and key.
    fn shard_get(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        self.shards.get(tenant).and_then(|m| m.get(key))
    }

    /// Look up a mutable shard record by tenant and key.
    fn shard_get_mut(&mut self, tenant: &TenantId, key: &ShardKey) -> Option<&mut ShardRecord> {
        self.shards.get_mut(tenant).and_then(|m| m.get_mut(key))
    }

    /// Insert a shard record, maintaining `total_shard_count`.
    ///
    /// If a record already exists at `(tenant, key)`, it is replaced and
    /// the count is unchanged (upsert semantics).  This is intentional:
    /// the remove-mutate-restore pattern in split operations removes a
    /// parent, then re-inserts the mutated parent at the same key.
    fn shard_insert(&mut self, tenant: TenantId, key: ShardKey, record: ShardRecord) {
        let inner_initial_capacity = tenant_shards_map_initial_capacity(self.max_shards_per_tenant);
        let inner = self
            .shards
            .entry(tenant)
            .or_insert_with(|| ahash_map_with_capacity(inner_initial_capacity));
        if let Some(mut old) = inner.insert(key, record) {
            old.deallocate_fields(&mut self.slab);
        } else {
            self.total_shard_count += 1;
        }
        self.assert_shard_count();
    }

    /// Remove a shard record, maintaining `total_shard_count`.
    ///
    /// Returns the removed record, or `None` if the key was not present.
    /// Uses `checked_sub` for the decrement — an underflow would indicate
    /// the counter drifted from the map contents, which is always a bug.
    fn shard_remove(&mut self, tenant: &TenantId, key: &ShardKey) -> Option<ShardRecord> {
        let inner = self.shards.get_mut(tenant)?;
        let removed = inner.remove(key);
        if removed.is_some() {
            self.total_shard_count = self
                .total_shard_count
                .checked_sub(1)
                .expect("total_shard_count underflow");
        }
        self.assert_shard_count();
        removed
    }

    /// Check whether a shard key exists for the given tenant.
    fn shard_contains(&self, tenant: &TenantId, key: &ShardKey) -> bool {
        self.shards.get(tenant).is_some_and(|m| m.contains_key(key))
    }

    /// Assert `total_shard_count` invariant.
    ///
    /// A desynchronized counter means silent data
    /// corruption (wrong shard-limit decisions), which
    /// must crash immediately per the project's crash-to-prevent-corruption
    /// philosophy.
    fn assert_shard_count(&self) {
        assert_eq!(
            self.total_shard_count,
            self.shards.values().map(|m| m.len()).sum::<usize>(),
            "total_shard_count drift detected"
        );
    }

    /// Check that adding `additional` shards for `tenant` stays within limits.
    ///
    /// `temporarily_removed` accounts for records that have been removed
    /// from the map for the remove-mutate-restore pattern (split ops) but
    /// will be restored. These must be counted toward both per-tenant and
    /// global totals.
    fn check_shard_limits(
        &self,
        tenant: TenantId,
        additional: usize,
        temporarily_removed: usize,
    ) -> Result<(), SplitValidationError> {
        // Per-tenant limit: O(1) via inner map len().
        let tenant_count = self
            .shards
            .get(&tenant)
            .map_or(0, |m| m.len())
            .saturating_add(temporarily_removed);
        if tenant_count.saturating_add(additional) > self.max_shards_per_tenant {
            return Err(SplitValidationError::ShardLimitExceeded {
                current: tenant_count,
                additional,
                max: self.max_shards_per_tenant,
                scope: ShardLimitScope::PerTenant,
            });
        }

        // Global limit: O(1) via maintained counter.
        let total_count = self.total_shard_count.saturating_add(temporarily_removed);
        if total_count.saturating_add(additional) > self.max_total_shards {
            return Err(SplitValidationError::ShardLimitExceeded {
                current: total_count,
                additional,
                max: self.max_total_shards,
                scope: ShardLimitScope::Global,
            });
        }

        Ok(())
    }

    /// Ensure tenant shard map capacity for an upcoming `register_shards` batch.
    ///
    /// This makes growth explicit up front so per-shard inserts in the hot
    /// loop do not trigger implicit rehash/allocation.
    fn reserve_register_shard_capacity(
        &mut self,
        tenant: TenantId,
        additional: usize,
    ) -> Result<(), RegisterShardsError> {
        if additional == 0 {
            return Ok(());
        }

        if !self.shards.contains_key(&tenant) {
            self.shards
                .try_reserve(1)
                .map_err(|_| RegisterShardsError::CapacityExceeded {
                    resource: "tenant_shards_index",
                })?;
            let initial =
                tenant_shards_map_initial_capacity(self.max_shards_per_tenant).max(additional);
            let mut inner: AHashMap<ShardKey, ShardRecord> = ahash_map_with_capacity(0);
            inner
                .try_reserve(initial)
                .map_err(|_| RegisterShardsError::CapacityExceeded {
                    resource: "tenant_shards",
                })?;
            return Ok(());
        }

        self.shards
            .get_mut(&tenant)
            .expect("tenant map must exist after contains_key check")
            .try_reserve(additional)
            .map_err(|_| RegisterShardsError::CapacityExceeded {
                resource: "tenant_shards",
            })?;
        Ok(())
    }

    /// Ensure run-shard index map/set capacity for an upcoming `register_shards` batch.
    fn reserve_register_index_capacity(
        &mut self,
        tenant: TenantId,
        run: RunId,
        shard_ids: &[ShardId],
    ) -> Result<(), RegisterShardsError> {
        let run_key = (tenant, run);
        if let Some(existing) = self.run_shards.get_mut(&run_key) {
            let additional_unique = shard_ids.iter().filter(|id| !existing.contains(id)).count();
            if additional_unique > 0 {
                existing.try_reserve(additional_unique).map_err(|_| {
                    RegisterShardsError::CapacityExceeded {
                        resource: "run_shards_set",
                    }
                })?;
            }
            return Ok(());
        }

        self.run_shards
            .try_reserve(1)
            .map_err(|_| RegisterShardsError::CapacityExceeded {
                resource: "run_shards_index",
            })?;
        let mut shard_set: HashSet<ShardId, ahash::RandomState> = ahash_set_with_capacity(0);
        shard_set
            .try_reserve(shard_ids.len().max(RUN_SHARD_SET_INITIAL_CAPACITY))
            .map_err(|_| RegisterShardsError::CapacityExceeded {
                resource: "run_shards_set",
            })?;
        Ok(())
    }

    /// Ensure claim cooldown map can absorb a new worker entry, if needed.
    fn ensure_claim_cooldown_capacity(&mut self, worker: WorkerId) {
        if self.claim_cooldown_interval == 0 || self.claim_cooldowns.contains_key(&worker) {
            return;
        }
        self.claim_cooldowns.try_reserve(1).unwrap_or_else(|_| {
            panic!(
                "claim_cooldowns capacity exhausted while preparing worker claim state \
                 for {worker:?}"
            )
        });
    }
}

/// Release all slab-backed shard fields before the slab itself is dropped.
///
/// Two strategies, chosen by build profile:
///
/// - **Debug builds**: iterate every record and call `deallocate_fields`
///   (`spec`, `cursor`, and spawned lineage storage). This decrements
///   `live_count` for each slot individually, so `ByteSlab::Drop` can assert
///   `live_count == 0` -- a leak detector that catches bugs where a record
///   is removed from the map but its slab slots are never released.
///
/// - **Release builds**: call `slab.clear()` for O(1) bulk reset. This
///   skips the per-record iteration (irrelevant in production where the
///   coordinator is typically long-lived and dropped only at shutdown).
impl Drop for InMemoryCoordinator {
    fn drop(&mut self) {
        #[cfg(debug_assertions)]
        {
            for (_tenant, tenant_map) in self.shards.drain() {
                for (_key, mut record) in tenant_map {
                    record.deallocate_fields(&mut self.slab);
                }
            }
            // ByteSlab::Drop will assert live_count == 0
        }
        #[cfg(not(debug_assertions))]
        self.slab.clear();
    }
}

// ============================================================================
// Shard-level protocol (CoordinationBackend)
// ============================================================================

impl CoordinationBackend for InMemoryCoordinator {
    /// Attempt to acquire exclusive ownership of a shard and return its last
    /// checkpointed state so the worker can resume processing.
    ///
    /// The two-level map (`TenantId → ShardKey → ShardRecord`) structurally
    /// provides tenant isolation: a lookup with the wrong tenant misses at
    /// the outer map and returns `ShardNotFound` without revealing any
    /// internal state. After the record is found, the following checks are
    /// performed in order:
    ///   1. **Tenant isolation (defense-in-depth)** — `record.tenant` must
    ///      match the request's tenant. This catches internal consistency
    ///      bugs where the record's tenant field disagrees with its map key.
    ///   2. **Shard liveness** — only `Active` shards can be acquired;
    ///      non-Active states (Done, Split, Parked) return `ShardTerminal`.
    ///      Note: `Parked` shards can be resumed via [`RunManagement::unpark_shard`] but
    ///      are not acquirable until unparked.
    ///   3. **At-most-once lease** — if another worker still holds a valid
    ///      lease the call fails rather than preempting, preserving the
    ///      at-most-once processing guarantee within a lease window.
    ///   4. **Fencing** — the fence epoch is bumped (Kleppmann fencing token)
    ///      so any stale holder from a prior epoch is rejected on its next
    ///      mutation attempt.
    ///   5. **Lease grant** — a new lease with a fresh deadline is written.
    ///   6. **Snapshot** — a read-only snapshot of the shard record is
    ///      returned alongside the lease so the caller can resume from the
    ///      last checkpointed cursor.
    ///
    /// The returned snapshot borrows from `out`; callers must consume/copy it
    /// before reusing that scratch buffer on a later acquire call.
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        let lease_duration = self.default_lease_duration;
        // Inline HashMap lookup for borrow splitting: `&mut record` + `&self.slab`.
        let record = self
            .shards
            .get_mut(&tenant)
            .and_then(|m| m.get_mut(&key))
            .ok_or(AcquireError::ShardNotFound { shard: key })?;

        // 1) Tenant isolation.
        if record.tenant != tenant {
            return Err(AcquireError::TenantMismatch { expected: tenant });
        }

        // 2) Terminal shards cannot be acquired.
        if record.status != ShardStatus::Active {
            return Err(AcquireError::ShardTerminal {
                shard: key,
                status: record.status,
            });
        }

        // 3) Active lease — must wait for expiry rather than preempt.
        if record.is_leased_at(now) {
            let (owner, deadline) = record
                .lease
                .as_ref()
                .map(|h| (h.owner(), h.deadline()))
                .expect("lease must exist when is_leased_at returns true");
            return Err(AcquireError::AlreadyLeased {
                current_owner: owner,
                lease_deadline: deadline,
            });
        }

        // 4) Bump fence epoch.
        let new_fence = record.advance_fence();

        // 5) Grant a new lease with a fresh deadline.
        // Saturate rather than panicking: a very-long lease is safe — it will
        // still expire eventually or be superseded by a fence bump.
        let deadline = now
            .checked_add(lease_duration)
            .unwrap_or(LogicalTime::from_raw(u64::MAX));
        record.lease = Some(LeaseHolder::new(worker, deadline));

        // 6) Return the fencing lease + shard snapshot + capacity hint.
        let lease = Lease::new(tenant, key.run(), key.shard(), worker, new_fence, deadline);
        out.reset();
        out.write_spec(
            record.spec.key_range_start(&self.slab),
            record.spec.key_range_end(&self.slab),
            record.spec.metadata(&self.slab),
        );
        out.write_cursor(
            record.cursor.last_key(&self.slab),
            record.cursor.token(&self.slab),
        );
        out.write_spawned_iter(record.spawned.iter(&self.slab));
        let snapshot = out.view(record.status, record.cursor_semantics, record.parent);
        let capacity = self.count_available_for_run(now, tenant, key.run());
        // TODO(events): emit ShardAcquired
        Ok(AcquireResultView {
            lease,
            snapshot,
            capacity,
        })
    }

    /// Extend an existing lease by resetting its deadline.
    ///
    /// Validates tenant isolation, fence epoch, and lease ownership via
    /// [`validate_lease`], then writes a fresh deadline. Returns the new
    /// deadline on success.
    ///
    /// **Complexity**: Computing the capacity hint adds an O(S) scan over the
    /// run's shards, where S is the run's shard count. Production backends
    /// should maintain a running counter for O(1) capacity hints.
    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        let lease_duration = self.default_lease_duration;
        let deadline = {
            let record = self
                .shard_get_mut(&tenant, &key)
                .ok_or(RenewError::ShardNotFound { shard: key })?;

            validate_lease(now, tenant, lease, record)?;

            // Saturate rather than panicking: a very-long lease is safe — it will
            // still expire eventually or be superseded by a fence bump.
            let deadline = now
                .checked_add(lease_duration)
                .unwrap_or(LogicalTime::from_raw(u64::MAX));
            record.lease = Some(LeaseHolder::new(lease.owner(), deadline));
            deadline
        };
        self.shard_get(&tenant, &key)
            .expect("renewed shard must exist")
            .assert_invariants(&self.slab);
        let capacity = self.count_available_for_run(now, tenant, key.run());
        Ok(RenewResult {
            new_deadline: deadline,
            capacity,
        })
    }

    /// Persist a new cursor position for the shard (idempotent).
    ///
    /// Idempotency is checked *before* lease validation so that replays
    /// succeed even after the shard becomes terminal or the lease expires.
    /// On a fresh execution the lease and cursor-monotonicity invariants
    /// are validated, the cursor is advanced, and an op-log entry is
    /// recorded. Cursor/spec validation runs on borrowed pooled bytes
    /// (`validate_cursor_update_pooled`) to avoid per-call materialization.
    ///
    /// `new_cursor` is borrowed input only: bytes are copied into the
    /// shard's pooled cursor storage and references are never retained.
    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        // Inline HashMap lookup for borrow splitting: `&mut record` + `&mut self.slab`.
        let record = self
            .shards
            .get_mut(&tenant)
            .and_then(|m| m.get_mut(&key))
            .ok_or(CheckpointError::ShardNotFound { shard: key })?;

        // Idempotency before lease — replays succeed even after terminal/expiry.
        let payload_hash = hash_checkpoint_payload(new_cursor);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;

        validate_cursor_update_pooled(
            new_cursor,
            record.cursor.last_key(&self.slab),
            record.spec.key_range_start(&self.slab),
            record.spec.key_range_end(&self.slab),
        )?;

        record.cursor.update_from_ref(new_cursor, &mut self.slab)?;
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Checkpoint,
            OpResult::Completed,
            payload_hash,
            now,
        ));

        // TODO(events): emit ShardCheckpointed
        record.assert_invariants(&self.slab);
        Ok(IdempotentOutcome::Executed(()))
    }

    /// Mark a shard as fully processed and release its lease (idempotent).
    ///
    /// Transitions the shard to [`ShardStatus::Done`] (terminal) after
    /// validating idempotency, lease ownership, and cursor monotonicity.
    /// The lease is cleared so no further mutations can occur under this
    /// shard. The final cursor is persisted for audit/resume purposes.
    /// Validation stays on borrowed pooled bytes to avoid extra heap work.
    /// `final_cursor` references are not retained after the call.
    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        let key = lease.shard_key();
        // Inline HashMap lookup for borrow splitting: `&mut record` + `&mut self.slab`.
        let record = self
            .shards
            .get_mut(&tenant)
            .and_then(|m| m.get_mut(&key))
            .ok_or(CompleteError::ShardNotFound { shard: key })?;

        let payload_hash = hash_complete_payload(final_cursor);
        if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        validate_lease(now, tenant, lease, record)?;

        validate_cursor_update_pooled(
            final_cursor,
            record.cursor.last_key(&self.slab),
            record.spec.key_range_start(&self.slab),
            record.spec.key_range_end(&self.slab),
        )?;

        record
            .cursor
            .update_from_ref(final_cursor, &mut self.slab)?;
        record.assert_transition_legal(ShardStatus::Done);
        record.status = ShardStatus::Done;
        record.lease = None;
        record.op_log_push(OpLogEntry::new(
            op_id,
            OpKind::Complete,
            OpResult::Completed,
            payload_hash,
            now,
        ));

        // TODO(events): emit ShardCompleted
        record.assert_invariants(&self.slab);
        Ok(IdempotentOutcome::Executed(()))
    }

    /// Suspend a shard so it is no longer eligible for acquisition
    /// (idempotent).
    ///
    /// Transitions the shard to [`ShardStatus::Parked`], records the
    /// [`ParkReason`], and releases the lease. A parked shard can only
    /// be resumed through the admin `RunManagement` interface (unpark).
    /// Idempotency and lease validation follow the same order as
    /// [`checkpoint`](Self::checkpoint).
    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        let key = lease.shard_key();
        {
            let record = self
                .shard_get_mut(&tenant, &key)
                .ok_or(ParkError::ShardNotFound { shard: key })?;

            let payload_hash = hash_park_payload(reason);
            if check_op_idempotency(record, op_id, payload_hash)?.is_some() {
                return Ok(IdempotentOutcome::Replayed(()));
            }

            validate_lease(now, tenant, lease, record)?;

            record.assert_transition_legal(ShardStatus::Parked);
            record.status = ShardStatus::Parked;
            record.park_reason = Some(reason);
            record.lease = None;
            record.op_log_push(OpLogEntry::new(
                op_id,
                OpKind::Park,
                OpResult::Completed,
                payload_hash,
                now,
            ));
        }
        self.shard_get(&tenant, &key)
            .expect("parked shard must exist")
            .assert_invariants(&self.slab);
        // TODO(events): emit ShardParked
        Ok(IdempotentOutcome::Executed(()))
    }

    /// Replace a parent shard with N child shards whose key-ranges
    /// collectively cover the parent's range (idempotent).
    ///
    /// Executes in three phases:
    ///   1. **Validate** — idempotency, lease, and full-coverage checks.
    ///   2. **Build+Insert** — derive child IDs, build child records, and
    ///      insert each child with rollback on any mid-build failure.
    ///   3. **Apply** — transition the parent to [`ShardStatus::Split`]
    ///      (terminal) and update indexes.
    ///
    /// Uses the *remove-mutate-restore* pattern: the parent record is
    /// temporarily removed from `self.shards` so that both `&mut parent`
    /// and `&mut self.shards` (for child insertion) can coexist. The
    /// parent is re-inserted at the end on both success and failure
    /// paths (see module-level docs for the panic exception). A
    /// shard-count limit guard prevents split-flooding (CWE-400).
    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        self.with_removed_parent(
            tenant,
            key,
            SplitReplaceError::ShardNotFound { shard: key },
            |coordinator, parent| {
                // Phase 1: Validate preconditions.
                let payload_hash = hash_split_replace_payload(&plan);
                if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
                    // Op-log eviction cannot affect replays: parent is terminal
                    // (Split) so no further ops can push entries.
                    let children = split_replace_replay_child_ids(parent, &plan, op_id);
                    return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
                }

                validate_lease(now, tenant, lease, parent)?;
                let sorted =
                    split_replace_validate_preconditions(parent, &plan, &coordinator.slab)?;

                // Shard count limit guard (temporarily_removed=1 for parent).
                coordinator
                    .check_shard_limits(tenant, sorted.len(), 1)
                    .map_err(SplitReplaceError::SplitInvalid)?;

                // Phase 2: Build + insert children (may allocate into slab).
                let child_ids = split_replace_insert_children(
                    coordinator,
                    parent,
                    &plan,
                    &sorted,
                    tenant,
                    op_id,
                )?;

                // Phase 3: Apply parent mutation + index updates.
                if let Err(e) = split_replace_apply_parent(
                    parent,
                    child_ids.as_slice(),
                    op_id,
                    payload_hash,
                    now,
                    &mut coordinator.slab,
                ) {
                    split_replace_rollback_inserted_children(
                        coordinator,
                        tenant,
                        parent.run,
                        child_ids.as_slice(),
                    );
                    return Err(e);
                }

                for &child_id in &child_ids {
                    coordinator.index_shard(tenant, parent.run, child_id);
                }

                // TODO(events): emit ShardSplit
                Ok(IdempotentOutcome::Executed(SplitReplaceResult {
                    children: child_ids,
                }))
            },
        )
    }

    /// Split off a *residual* child shard from the parent without
    /// retiring the parent (idempotent).
    ///
    /// Unlike [`split_replace`](Self::split_replace), the parent remains
    /// `Active` with an updated spec while a single new residual shard is
    /// created to handle the carved-out key range. The same three-phase
    /// structure applies:
    ///   1. **Validate** — idempotency, lease, and plan preconditions.
    ///   2. **Build** — derive the residual shard ID (BLAKE3 with domain
    ///      separation) and construct its record (pure).
    ///   3. **Apply** — update the parent's spec and spawned list, insert
    ///      the residual into the map, and update indexes. If parent update
    ///      fails after build, staged residual allocations are explicitly
    ///      deallocated before returning the error.
    ///
    /// Uses the same remove-mutate-restore pattern and shard-count limit
    /// guard as `split_replace`.
    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        self.with_removed_parent(
            tenant,
            key,
            SplitResidualError::ShardNotFound { shard: key },
            |coordinator, parent| {
                // Phase 1: Validate preconditions.
                let payload_hash = hash_split_residual_payload(&plan);

                // Derive residual ID (index = spawned.len() before push).
                let residual_id = derive_split_shard_id(
                    parent.run,
                    parent.shard,
                    op_id,
                    DerivedShardKind::Residual,
                    parent.spawned.len() as u32,
                );

                if let Some(replay) =
                    split_residual_check_replay(parent, op_id, payload_hash, &coordinator.slab)?
                {
                    return Ok(replay);
                }
                split_residual_validate_preconditions(
                    now,
                    tenant,
                    lease,
                    parent,
                    &plan,
                    &coordinator.slab,
                )?;

                // Shard count limit guard (temporarily_removed=1 for parent).
                coordinator
                    .check_shard_limits(tenant, 1, 1)
                    .map_err(SplitResidualError::SplitInvalid)?;

                // Phase 2: Build residual record (allocates into slab).
                let mut residual_record = split_residual_build_record(
                    parent,
                    &plan,
                    tenant,
                    residual_id,
                    &mut coordinator.slab,
                )?;

                // Phase 3: Apply mutations.
                let residual_key = ShardKey::new(parent.run, residual_id);
                if coordinator.shard_contains(&tenant, &residual_key) {
                    // Deallocate the just-built residual before returning error.
                    residual_record.deallocate_fields(&mut coordinator.slab);
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::DerivedIdCollision {
                            derived_id: residual_id,
                        },
                    ));
                }

                if let Err(e) = split_residual_apply_parent(
                    parent,
                    plan.parent_new_spec(),
                    residual_id,
                    op_id,
                    payload_hash,
                    now,
                    &mut coordinator.slab,
                ) {
                    // Parent update failed after we built the residual record.
                    // Roll back staged residual slab allocations before returning.
                    residual_record.deallocate_fields(&mut coordinator.slab);
                    return Err(e);
                }

                coordinator.shard_insert(tenant, residual_key, residual_record);
                coordinator.index_shard(tenant, parent.run, residual_id);

                // TODO(events): emit ShardResidualCreated
                Ok(IdempotentOutcome::Executed(SplitResidualResult {
                    residual: residual_id,
                }))
            },
        )
    }
}

// ============================================================================
// split_replace helpers
// ============================================================================
//
// These are extracted as free functions (not methods on `InMemoryCoordinator`)
// for two reasons:
//
// 1. **Borrow splitting** — `split_replace` temporarily removes the parent
//    from `self.shards` and passes `&mut parent` into a closure.  Free
//    functions that take `&ShardRecord` / `&mut ShardRecord` avoid borrowing
//    `self`, which would conflict with the closure's `&mut self` captures
//    (needed for `shard_insert`, `index_shard`, etc.).
//
// 2. **Purity** — validation and record construction are pure computations
//    over their arguments.  Keeping them free of `self` makes this explicit
//    and simplifies unit testing (no coordinator setup required).

/// Fixed-capacity child-id scratch used by split-replace helpers.
type SplitChildIds = gossip_stdx::InlineVec<ShardId, { MAX_SPLIT_CHILDREN }>;

const _: () = assert!(MAX_SPLIT_CHILDREN <= u16::MAX as usize);

/// Fixed-capacity sorted index scratch for `SplitReplacePlan::children()`.
///
/// Stores child indices sorted by `key_range_start` without allocating.
#[derive(Clone, Copy)]
struct SplitChildOrder {
    len: usize,
    indices: [u16; MAX_SPLIT_CHILDREN],
}

impl SplitChildOrder {
    fn from_plan(plan: &SplitReplacePlan<'_>) -> Self {
        let len = plan.children().len();
        let mut indices = [0u16; MAX_SPLIT_CHILDREN];
        for (i, slot) in indices.iter_mut().take(len).enumerate() {
            *slot = u16::try_from(i).expect("split child index exceeds u16");
        }
        indices[..len].sort_by(|a, b| {
            plan.children()[usize::from(*a)]
                .spec()
                .key_range_start()
                .cmp(plan.children()[usize::from(*b)].spec().key_range_start())
        });
        // Defense-in-depth: `SplitReplacePlan::try_new` already enforces >= 2
        // children at construction time, but this assertion guards against
        // future refactors that might bypass the constructor.
        assert!(len >= 2, "split_replace requires >= 2 children");
        Self { len, indices }
    }

    #[inline]
    fn len(&self) -> usize {
        self.len
    }

    #[inline]
    fn child<'a>(
        &self,
        plan: &'a SplitReplacePlan<'a>,
        sorted_idx: usize,
    ) -> &'a SplitReplaceChild<'a> {
        &plan.children()[usize::from(self.indices[sorted_idx])]
    }
}

fn split_replace_validate_coverage_sorted(
    parent_start: &[u8],
    parent_end: &[u8],
    plan: &SplitReplacePlan<'_>,
    sorted: &SplitChildOrder,
) -> Result<(), SplitValidationError> {
    if sorted.len() == 0 {
        return Err(SplitValidationError::NoChildren);
    }
    if sorted.len() == 1 {
        return Err(SplitValidationError::SingleChild);
    }

    let first = sorted.child(plan, 0).spec();
    if first.key_range_start() != parent_start {
        return Err(SplitValidationError::StartMismatch {
            parent_start: parent_start.len(),
            first_child_start: first.key_range_start().len(),
        });
    }

    let last = sorted.child(plan, sorted.len() - 1).spec();
    if last.key_range_end() != parent_end {
        return Err(SplitValidationError::EndMismatch {
            parent_end: parent_end.len(),
            last_child_end: last.key_range_end().len(),
        });
    }

    for i in 0..sorted.len() - 1 {
        let child = sorted.child(plan, i).spec();
        let next = sorted.child(plan, i + 1).spec();
        if child.key_range_end() != next.key_range_start() {
            return Err(SplitValidationError::BoundaryMismatch {
                child_index: i,
                next_child_index: i + 1,
                child_end: child.key_range_end().len(),
                next_child_start: next.key_range_start().len(),
            });
        }
        if child.key_range_end().is_empty() {
            return Err(SplitValidationError::OverlappingChild {
                child_index: i,
                next_child_index: i + 1,
            });
        }
    }

    for i in 0..sorted.len() {
        let child = sorted.child(plan, i).spec();
        if !child.key_range_start().is_empty()
            && !child.key_range_end().is_empty()
            && child.key_range_start() >= child.key_range_end()
        {
            return Err(SplitValidationError::InvertedChild { child_index: i });
        }
    }

    Ok(())
}

/// Validate split_replace preconditions: coverage and spawn-cap.
///
/// Sorts children, validates that they partition the parent's range, and
/// checks the spawn-cap limit. Parent bounds are borrowed directly from the
/// pooled parent spec, avoiding `to_spec()` materialization in this hot path.
/// Returns sorted child-order scratch on success.
fn split_replace_validate_preconditions<'a>(
    parent: &ShardRecord,
    plan: &'a SplitReplacePlan<'a>,
    slab: &ByteSlab,
) -> Result<SplitChildOrder, SplitReplaceError> {
    let sorted = split_replace_sort_children(plan);

    // Validate per-spec size limits before coverage checks. ShardSpecRef is
    // intentionally unvalidated at construction; this gate prevents oversized
    // specs from reaching AcquireScratch::write_spec's panicking asserts.
    for i in 0..sorted.len() {
        let child = sorted.child(plan, i);
        if ShardSpec::validate_ref(child.spec()).is_err() {
            return Err(SplitReplaceError::SplitInvalid(
                SplitValidationError::InvalidChildSpec { child_index: i },
            ));
        }
    }

    split_replace_validate_coverage_sorted(
        parent.spec.key_range_start(slab),
        parent.spec.key_range_end(slab),
        plan,
        &sorted,
    )
    .map_err(SplitReplaceError::SplitInvalid)?;

    // Spawn-cap guard: check BEFORE mutating parent.spawned.
    if !parent.can_spawn(sorted.len()) {
        return Err(SplitReplaceError::SplitInvalid(
            SplitValidationError::SpawnLimitExceeded {
                current: parent.spawned.len(),
                additional: sorted.len(),
                max: MAX_SPAWNED_PER_SHARD,
            },
        ));
    }
    Ok(sorted)
}

/// Sort plan children by `key_range_start` for deterministic ordering.
///
/// Callers may submit children in any order. Sorting ensures that the
/// derived child IDs (which depend on index) are stable regardless of
/// submission order, and that `split_replace_validate_coverage_sorted`
/// sees children in the contiguous sequence it expects.
fn split_replace_sort_children<'a>(plan: &'a SplitReplacePlan<'a>) -> SplitChildOrder {
    SplitChildOrder::from_plan(plan)
}

/// Recompute child IDs for an idempotent replay.
///
/// On replay, the op_log entry exists but the children are already in
/// `parent.spawned`. Since `split_replace` transitions the parent to
/// terminal `Split` status, no further operations can modify `spawned`.
/// The original base index was `spawned.len() - children_count`.
fn split_replace_replay_child_ids(
    parent: &ShardRecord,
    plan: &SplitReplacePlan<'_>,
    op_id: OpId,
) -> SplitChildIds {
    let sorted = split_replace_sort_children(plan);
    let n = sorted.len();
    // Parent is terminal (Split) after first execution, so spawned is
    // frozen. The children were the last N entries appended.
    let base_index = parent
        .spawned
        .len()
        .checked_sub(n)
        .expect("split_replace replay: parent.spawned.len() < child count; state corruption");
    let mut ids = SplitChildIds::new();
    for i in 0..n {
        ids.push(derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Child,
            (base_index + i) as u32,
        ));
    }
    ids
}

/// Remove and deallocate any children inserted during split-replace staging.
///
/// Called when a mid-loop failure occurs after one or more children were
/// already inserted (allocation failure for a later child, or a derived-ID
/// collision discovered later in the sorted sequence).
/// # Panic safety
///
/// This runs inside [`with_removed_parent`], which temporarily removes the
/// parent from the shard map before re-inserting it. If this function panics
/// (e.g., slab `deallocate` hits metadata exhaustion or a double-free
/// assertion), the parent record is lost because `with_removed_parent`
/// never reaches the re-insertion line. In practice, `deallocate_fields`
/// only panics on slab invariant violations that indicate data corruption,
/// at which point losing the parent is the least of our problems.
fn split_replace_rollback_inserted_children(
    coordinator: &mut InMemoryCoordinator,
    tenant: TenantId,
    run: RunId,
    inserted: &[ShardId],
) {
    for &child_id in inserted.iter().rev() {
        let child_key = ShardKey::new(run, child_id);
        if let Some(mut record) = coordinator.shard_remove(&tenant, &child_key) {
            record.deallocate_fields(&mut coordinator.slab);
        }
    }
}

/// Derive child IDs, build child records, and insert each child with rollback.
///
/// Each child ID is derived via BLAKE3 from `(run, parent_shard, op_id,
/// kind=Child, index)`. The index starts at `parent.spawned.len()` so IDs
/// are unique across successive splits of the same parent. If any child build
/// fails, previously inserted children are removed and deallocated so the
/// operation remains all-or-nothing before parent mutation.
fn split_replace_insert_children(
    coordinator: &mut InMemoryCoordinator,
    parent: &ShardRecord,
    plan: &SplitReplacePlan<'_>,
    sorted: &SplitChildOrder,
    tenant: TenantId,
    op_id: OpId,
) -> Result<SplitChildIds, SplitReplaceError> {
    let mut child_ids = SplitChildIds::new();

    for i in 0..sorted.len() {
        let child = sorted.child(plan, i);
        let idx = (parent.spawned.len() + i) as u32;
        let child_id = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Child,
            idx,
        );
        assert!(child_id.is_derived(), "derived child must have bit 63 set");

        let child_key = ShardKey::new(parent.run, child_id);
        if coordinator.shard_contains(&tenant, &child_key) {
            split_replace_rollback_inserted_children(
                coordinator,
                tenant,
                parent.run,
                child_ids.as_slice(),
            );
            return Err(SplitReplaceError::SplitInvalid(
                SplitValidationError::DerivedIdCollision {
                    derived_id: child_id,
                },
            ));
        }

        let record = match ShardRecord::new_split_child(
            tenant,
            parent.run,
            child_id,
            child.spec(),
            child.cursor(),
            parent.cursor_semantics,
            parent.shard,
            &mut coordinator.slab,
        ) {
            Ok(record) => record,
            Err(err) => {
                split_replace_rollback_inserted_children(
                    coordinator,
                    tenant,
                    parent.run,
                    child_ids.as_slice(),
                );
                return Err(SplitReplaceError::from(err));
            }
        };

        coordinator.shard_insert(tenant, child_key, record);
        child_ids.push(child_id);
    }

    assert_eq!(
        child_ids.len(),
        sorted.len(),
        "child count mismatch after build",
    );
    Ok(child_ids)
}

/// Transition parent to terminal `Split` status.
///
/// The parent's lease is released (no worker owns a terminal shard) and
/// child IDs are recorded in `spawned` for lineage tracking. Once in
/// `Split` status, no further operations can push op-log entries, so the
/// split_replace entry is **never evicted** — guaranteeing idempotent
/// replay detection.
fn split_replace_apply_parent(
    parent: &mut ShardRecord,
    child_ids: &[ShardId],
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
    slab: &mut ByteSlab,
) -> Result<(), SplitReplaceError> {
    assert!(!child_ids.is_empty(), "split_replace requires children");
    debug_assert!(
        parent.can_spawn(child_ids.len()),
        "split_replace precondition violated: append would exceed spawn cap"
    );

    let (spawned_slot, spawned_len) = parent.spawned.allocate_appended_slot(child_ids, slab)?;
    parent.assert_transition_legal(ShardStatus::Split);
    parent.spawned.install_slot(spawned_slot, spawned_len, slab);
    parent.status = ShardStatus::Split;
    parent.lease = None;
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitReplace,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants(slab);
    Ok(())
}

// ============================================================================
// split_residual helpers
// ============================================================================
//
// Extracted as free functions for the same borrow-splitting and purity
// reasons as the split_replace helpers above.  Additionally,
// `split_residual_check_replay` encapsulates the two-tier replay
// detection logic (op-log + spawned probe) which is specific to
// residual splits and would clutter the main method body.

/// Search `parent.spawned` for a residual derived from the given `op_id`.
///
/// `spawned` is append-only: each derived split ID is pushed at the same
/// index used in its derivation. This lets us probe replay candidates in a
/// single pass without building a temporary set: for each current index `i`,
/// derive `Residual(op_id, i)` and compare against `spawned[i]`.
///
/// Complexity: O(S·D) where S = `spawned.len()` and D = BLAKE3 hash cost
/// (constant). At `MAX_SPAWNED_PER_SHARD` (1024), worst case is ~1024
/// hash+compare steps and zero heap allocation.
///
/// Returns `None` if no match, meaning this is genuinely a new operation.
fn find_replayed_residual(parent: &ShardRecord, op_id: OpId, slab: &ByteSlab) -> Option<ShardId> {
    assert!(
        parent.spawned.len() <= MAX_SPAWNED_PER_SHARD,
        "spawned count {} exceeds bound {}",
        parent.spawned.len(),
        MAX_SPAWNED_PER_SHARD,
    );
    for (idx, spawned) in parent.spawned.iter(slab).enumerate() {
        let candidate = derive_split_shard_id(
            parent.run,
            parent.shard,
            op_id,
            DerivedShardKind::Residual,
            idx as u32,
        );
        if spawned == candidate {
            return Some(candidate);
        }
    }
    None
}

/// Two-tier replay detection for `split_residual`.
///
/// Unlike `split_replace` (which makes the parent terminal, freezing its
/// op-log), `split_residual` keeps the parent `Active`. Subsequent
/// checkpoints can evict the split_residual op-log entry. To handle this:
///
/// 1. **Op-log check** (primary): if the entry is still present and the
///    payload hash matches, return `Replayed`. If the hash differs, return
///    `OpIdConflict`.
/// 2. **Spawned probe** (defense-in-depth): if the op-log entry was evicted,
///    scan `parent.spawned` for a residual derived from this `op_id`. The
///    `spawned` vec is permanent (never evicted, bounded by
///    `MAX_SPAWNED_PER_SHARD`).
///
/// The spawned check comes *after* the op-log check so that `OpIdConflict`
/// (same op_id, different payload) is not masked.
///
/// Returns `Some(Replayed(..))` if replay detected, `None` to proceed.
fn split_residual_check_replay(
    parent: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
    slab: &ByteSlab,
) -> Result<Option<IdempotentOutcome<SplitResidualResult>>, SplitResidualError> {
    if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
        // Op-log hit. The residual is already in spawned; find it.
        // An op-log hit means `split_residual_apply_parent` completed — the
        // residual was pushed to `parent.spawned` before the op-log entry was
        // written. If `find_replayed_residual` fails here, it indicates a
        // logic bug (spawned was mutated without recording the residual).
        let replayed = find_replayed_residual(parent, op_id, slab).expect(
            "op-log hit for split_residual implies residual exists in parent.spawned; \
             missing entry indicates a coordinator bug",
        );
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: replayed,
        })));
    }

    // Defense-in-depth: if op_log entry was evicted but residual was
    // already created, detect via parent.spawned (permanent, never
    // evicted). This check comes AFTER op-log miss to avoid masking
    // OpIdConflict. MAX_SPAWNED_PER_SHARD bounds the search.
    //
    // NOTE(limitation): The spawned-probe tier cannot verify payload hash
    // after op-log eviction. If a client replays op_id=X with a *different*
    // plan after the op-log entry is evicted, this path returns Replayed
    // (matching the original residual) instead of OpIdConflict. This is
    // acceptable because: (1) eviction requires 16+ intervening ops,
    // meaning the original execution is far in the past, (2) op_ids are
    // CSPRNG-generated so accidental reuse is astronomically unlikely,
    // (3) this is a reference implementation — production backends with
    // durable op-logs don't have this window.
    if let Some(existing) = find_replayed_residual(parent, op_id, slab) {
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: existing,
        })));
    }

    Ok(None)
}

/// Validate all preconditions for a fresh `split_residual` execution.
///
/// Checks, in order: lease validity (tenant, fence, expiry), split
/// coverage (new parent + residual must partition old parent's range),
/// cursor bounds (parent's cursor must remain within the shrunk range),
/// and spawn-cap (parent has not exceeded [`MAX_SPAWNED_PER_SHARD`]).
/// Split coverage consumes borrowed parent bounds from the pooled parent
/// record to keep validation allocation-free.
fn split_residual_validate_preconditions(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    slab: &ByteSlab,
) -> Result<(), SplitResidualError> {
    validate_lease(now, tenant, lease, parent)?;

    // Validate per-spec size limits for both the new parent and residual specs.
    if ShardSpec::validate_ref(plan.parent_new_spec()).is_err() {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::InvalidChildSpec { child_index: 0 },
        ));
    }
    if ShardSpec::validate_ref(plan.residual_spec()).is_err() {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::InvalidChildSpec { child_index: 1 },
        ));
    }

    validate_residual_split_bounds(
        parent.spec.key_range_start(slab),
        parent.spec.key_range_end(slab),
        plan.parent_new_spec(),
        plan.residual_spec(),
    )
    .map_err(SplitResidualError::SplitInvalid)?;
    // Safety: shrinking the parent must not strand its existing cursor.
    split_residual_validate_cursor_bounds(parent, plan, slab)?;
    // Spawn-cap guard: check BEFORE mutating parent.spawned.
    if !parent.can_spawn(1) {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::SpawnLimitExceeded {
                current: parent.spawned.len(),
                additional: 1,
                max: MAX_SPAWNED_PER_SHARD,
            },
        ));
    }
    Ok(())
}

/// Verify the parent's cursor remains within the shrunk key range.
///
/// After a residual split, the parent keeps a subset of the original
/// keyspace (typically a prefix, but the validation is position-agnostic).
/// If the cursor's `last_key` falls outside the new range,
/// the parent would violate cursor-bounds invariants (INV: `last_key ∈
/// [spec.start, spec.end)`). This would strand progress — the worker
/// could never advance past a key that's no longer in its range.
fn split_residual_validate_cursor_bounds(
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    slab: &ByteSlab,
) -> Result<(), SplitResidualError> {
    // Borrow pooled last_key directly and check against the proposed parent.
    if let Some(k) = parent.cursor.last_key(slab)
        && !plan.parent_new_spec().contains_key(k)
    {
        return Err(SplitResidualError::SplitInvalid(
            crate::coordination::shard_spec::SplitValidationError::ParentCursorOutOfBounds {
                cursor: k.len(),
                new_parent_start: plan.parent_new_spec().key_range_start().len(),
                new_parent_end: plan.parent_new_spec().key_range_end().len(),
            },
        ));
    }
    Ok(())
}

/// Build the residual shard record (pure — no map mutation).
///
/// The residual starts with `CursorUpdate::initial()` because no work has been
/// done in the residual's key range yet. It inherits `cursor_semantics`
/// from the parent (run-level property) and records `parent.shard` as its
/// lineage parent.
fn split_residual_build_record(
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    tenant: TenantId,
    residual_id: ShardId,
    slab: &mut ByteSlab,
) -> Result<ShardRecord, SplitResidualError> {
    assert!(residual_id.is_derived(), "residual must be derived");
    ShardRecord::new_split_child(
        tenant,
        parent.run,
        residual_id,
        plan.residual_spec(),
        CursorUpdate::initial(),
        parent.cursor_semantics,
        parent.shard,
        slab,
    )
    .map_err(SplitResidualError::from)
}

/// Shrink parent's key range and record the residual in `spawned`.
///
/// Unlike `split_replace_apply_parent`, the parent **keeps its lease** —
/// the worker continues processing the (now smaller) parent shard. The
/// parent stays `Active`, which means subsequent ops can evict this
/// op-log entry. That's acceptable because `find_replayed_residual`
/// provides a secondary replay detection path via `spawned`.
fn split_residual_apply_parent(
    parent: &mut ShardRecord,
    new_spec: ShardSpecRef<'_>,
    residual_id: ShardId,
    op_id: OpId,
    payload_hash: u64,
    now: LogicalTime,
    slab: &mut ByteSlab,
) -> Result<(), SplitResidualError> {
    assert!(residual_id.is_derived(), "residual must be derived");
    debug_assert!(
        parent.can_spawn(1),
        "split_residual precondition violated: append would exceed spawn cap"
    );

    let (spawned_slot, spawned_len) = parent
        .spawned
        .allocate_appended_slot(core::slice::from_ref(&residual_id), slab)?;
    if let Err(err) = parent.spec.update_from_ref(new_spec, slab) {
        slab.deallocate(spawned_slot);
        return Err(SplitResidualError::from(err));
    }
    parent.spawned.install_slot(spawned_slot, spawned_len, slab);
    parent.op_log_push(OpLogEntry::new(
        op_id,
        OpKind::SplitResidual,
        OpResult::Completed,
        payload_hash,
        now,
    ));
    parent.assert_invariants(slab);
    Ok(())
}

// ============================================================================
// Run-level helpers
// ============================================================================
//
// Shared infrastructure for run lifecycle operations (create, register,
// complete, fail, cancel) and the run→shard secondary index.  These are
// methods on `InMemoryCoordinator` (not free functions) because they need
// access to `self.runs`, `self.run_shards`, and `self.shards`.

impl InMemoryCoordinator {
    /// Register a shard in the run-to-shards secondary index.
    ///
    /// This index enables `list_shards_into` and `get_run_progress` to enumerate
    /// a run's shards without scanning the entire tenant shard map.
    /// Idempotent — `HashSet::insert` is a no-op if the shard is already
    /// indexed, so calling this on both register and split paths is safe.
    ///
    /// # Pre-reservation contract
    ///
    /// Callers are expected to ensure the run already has an entry in
    /// `run_shards` (created by `register_shards` during run initialization).
    /// For `register_shards`, [`reserve_register_index_capacity`] explicitly
    /// pre-reserves both the outer map slot and inner set capacity.  For
    /// `split_replace` and `split_residual`, the run's index entry already
    /// exists (the parent shard was registered earlier), so the outer map
    /// insertion is a no-op and only inner-set growth is needed.
    ///
    /// # Panics
    ///
    /// Panics if `try_reserve` fails on either the outer `run_shards` map or
    /// the inner shard-ID set.  These are defense-in-depth: under correct
    /// pre-reservation they are unreachable (see module-level
    /// "Allocation-failure policy").
    fn index_shard(&mut self, tenant: TenantId, run: RunId, shard: ShardId) {
        let run_key = (tenant, run);
        if !self.run_shards.contains_key(&run_key) {
            self.run_shards.try_reserve(1).unwrap_or_else(|_| {
                panic!(
                    "run_shards index capacity exhausted while indexing run {run:?} \
                     for tenant {tenant:?}"
                )
            });
        }
        let shard_ids = self
            .run_shards
            .entry(run_key)
            .or_insert_with(|| ahash_set_with_capacity(RUN_SHARD_SET_INITIAL_CAPACITY));
        if !shard_ids.contains(&shard) {
            shard_ids.try_reserve(1).unwrap_or_else(|_| {
                panic!(
                    "run_shards set capacity exhausted while indexing shard {shard:?} \
                     for run {run:?}"
                )
            });
        }
        shard_ids.insert(shard);
    }

    /// Cross-validate the `run_shards` index against the primary `shards` map.
    ///
    /// Every shard ID in the index must exist in the primary map. Called after
    /// split operations and `register_shards` to catch index desynchronization
    /// (e.g., a shard inserted into the index but not into the primary map).
    /// Compiled out in release builds (`#[cfg(debug_assertions)]`).
    #[cfg(debug_assertions)]
    fn debug_assert_run_shards_consistent(&self, tenant: TenantId, run: RunId) {
        if let Some(shard_ids) = self.run_shards.get(&(tenant, run)) {
            for &shard_id in shard_ids {
                let key = ShardKey::new(run, shard_id);
                debug_assert!(
                    self.shard_get(&tenant, &key).is_some(),
                    "run_shards index contains {:?} for run {:?} but primary map has no record",
                    shard_id,
                    run,
                );
            }
        }
    }

    #[cfg(not(debug_assertions))]
    fn debug_assert_run_shards_consistent(&self, _tenant: TenantId, _run: RunId) {}

    /// Apply the terminal mutation shared by `complete_run`, `fail_run`, and `cancel_run`.
    ///
    /// Sets the target status, records `completed_at`, pushes an op-log entry,
    /// and verifies invariants. Callers are responsible for all precondition
    /// checks (lookup, tenant, idempotency, terminal, wrong-status) before
    /// calling this helper.
    ///
    /// This is an associated function (takes `&mut RunRecord`, not `&mut self`)
    /// because the caller already holds a mutable borrow from `self.runs.get_mut`.
    /// An `&mut self` method would conflict with that outstanding borrow.
    fn apply_terminal_run_transition(
        record: &mut RunRecord,
        now: LogicalTime,
        op_id: OpId,
        payload_hash: u64,
        target_status: RunStatus,
        op_kind: RunOpKind,
    ) {
        record.assert_transition_legal(target_status);
        record.status = target_status;
        record.completed_at = Some(now);
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            op_kind,
            payload_hash,
            now,
            RunOpResult::Ack,
        ));
        record.assert_invariants();
    }

    /// Count available shards and find the earliest lease deadline for a run.
    ///
    /// O(S) where S = shards in run.  The reference in-memory backend
    /// accepts this cost because [`list_shards_into`](Self::list_shards_into) and the
    /// claiming loop already perform O(S) scans.  Production backends should
    /// maintain a secondary counter or compute this from an index.
    ///
    /// The result is order-independent — iteration order of the `run_shards`
    /// `HashSet` does not affect the output (sum and min are commutative).
    ///
    /// See also [`get_run_progress`](Self::get_run_progress) which performs a
    /// similar iteration for run-level status reporting (different consumer,
    /// different output shape).
    pub(crate) fn count_available_for_run(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> CapacityHint {
        // A missing index entry means the run has no registered shards yet
        // (e.g., still in `Initializing` status).  Return ZERO rather than
        // panicking — the caller already validated the run exists via
        // `lookup_run` or shard-level lookup.
        let shard_ids = match self.run_shards.get(&(tenant, run)) {
            Some(ids) => ids,
            None => return CapacityHint::ZERO,
        };

        debug_assert!(
            shard_ids.len() <= self.max_total_shards,
            "run_shards index size {} exceeds max_total_shards {}",
            shard_ids.len(),
            self.max_total_shards,
        );

        let mut available_count: u32 = 0;
        let mut earliest_deadline: Option<LogicalTime> = None;

        for &shard_id in shard_ids {
            let key = ShardKey::new(run, shard_id);
            let record = self.shard_get(&tenant, &key).unwrap_or_else(|| {
                panic!(
                    "run_shards index contains shard {:?} for run {:?} \
                     but no record exists in the primary shard map — \
                     index desynchronization",
                    shard_id, run,
                )
            });

            if record.status != ShardStatus::Active {
                continue;
            }

            if record.is_leased_at(now) {
                let deadline = record
                    .lease()
                    .expect("is_leased_at returned true but lease is None")
                    .deadline();
                earliest_deadline = Some(match earliest_deadline {
                    Some(prev) => core::cmp::min(prev, deadline),
                    None => deadline,
                });
            } else {
                available_count = available_count
                    .checked_add(1)
                    .expect("available_count overflow: more active unleased shards than u32::MAX");
            }
        }

        CapacityHint {
            available_count,
            earliest_deadline,
        }
    }

    /// Look up a run record with tenant isolation enforcement.
    ///
    /// Shared precondition helper for read-only run queries (`get_run`,
    /// `get_run_progress`, `list_shards_into`). Callers that need `&mut` must
    /// look up the record directly via `self.runs.get_mut`.
    fn lookup_run(&self, tenant: TenantId, run: RunId) -> Result<&RunRecord, GetRunError> {
        let record = self
            .runs
            .get(&(tenant, run))
            .ok_or(GetRunError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(GetRunError::TenantMismatch { expected: tenant });
        }
        Ok(record)
    }
}

// ============================================================================
// RunManagement implementation
// ============================================================================
//
// Run lifecycle follows a two-phase pattern: `create_run` (Initializing) →
// `register_shards` (Active) → terminal (`complete_run`, `fail_run`, or
// `cancel_run`).  The three terminal transitions share a common validation
// sequence (lookup → tenant → idempotency → terminal check → status check)
// and delegate to `apply_terminal_run_transition` for the actual mutation.
//
// Idempotency is checked before status in every idempotent path so that
// replays succeed even after the run has since transitioned (e.g., a
// `register_shards` replay after the run is already Active).

impl RunManagement for InMemoryCoordinator {
    /// Create a new run in `Initializing` status with no shards.
    ///
    /// The config is validated eagerly via `RunConfig::assert_valid`.
    /// Duplicate run IDs within the same tenant are rejected. The run
    /// must subsequently receive a [`register_shards`](Self::register_shards)
    /// call to transition to `Active`.
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        config.assert_valid();

        if self.runs.contains_key(&(tenant, run)) {
            return Err(CreateRunError::RunAlreadyExists { run });
        }

        let record = RunRecord {
            tenant,
            run,
            config,
            status: RunStatus::Initializing,
            created_at: now,
            completed_at: None,
            root_shards: Vec::new(),
            op_log: RingBuffer::new(),
        };
        record.assert_invariants();

        self.runs.insert((tenant, run), record.clone());
        Ok(record)
    }

    /// Populate an `Initializing` run with its initial shard manifest and
    /// transition it to `Active` (idempotent).
    ///
    /// Validation order:
    ///   1. Tenant isolation + run lookup.
    ///   2. Idempotency (checked before status so replays survive later
    ///      state changes).
    ///   3. Status — must be `Initializing`.
    ///   4. Manifest validation (uniqueness, non-empty, etc.).
    ///   5. Shard-count limit guard.
    ///   6. Stage shard record creation with rollback on allocation failure.
    ///   7. Insert staged records, update index, transition run to `Active`.
    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        let payload_hash = hash_register_shards_payload(shards);

        // 1. Lookup + tenant isolation.
        let record = self
            .runs
            .get(&(tenant, run))
            .ok_or(RegisterShardsError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(RegisterShardsError::TenantMismatch { expected: tenant });
        }

        // 2. Idempotency (before status).
        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            assert_eq!(
                entry.kind(),
                RunOpKind::RegisterShards,
                "idempotent replay kind mismatch: expected RegisterShards, got {:?}",
                entry.kind(),
            );
            match entry.result() {
                RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                }
                RunOpResult::Ack => {
                    panic!(
                        "Run {:?}: RegisterShards op-log entry has Ack result \
                         (expected RegisteredShards) — data corruption",
                        run,
                    );
                }
            }
        }

        // 3. Status check.
        if record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                status: record.status,
            });
        }

        // 4. Manifest validation.
        validate_manifest(shards).map_err(RegisterShardsError::ManifestInvalid)?;

        // 5. Shard count limit.
        self.check_shard_limits(tenant, shards.len(), 0)
            .map_err(|e| match e {
                SplitValidationError::ShardLimitExceeded {
                    current,
                    additional,
                    max,
                    scope,
                } => RegisterShardsError::ShardLimitExceeded {
                    current,
                    additional,
                    max,
                    scope,
                },
                _ => unreachable!("check_shard_limits only returns ShardLimitExceeded"),
            })?;

        // 6. Build shard records, then insert.
        //
        // Build first so recoverable allocation failures (`SlabFull`) return
        // an error without partially mutating shard maps. Any staged records
        // are deallocated before returning so this path stays all-or-nothing.
        // Borrowed manifest inputs are copied into slab-owned record fields.
        let cursor_semantics = record.config.cursor_semantics();
        let mut shard_ids = std::mem::take(&mut self.register_shard_ids_scratch);
        shard_ids.clear();
        shard_ids.extend(shards.iter().map(InitialShardInput::shard));

        let mut to_insert = std::mem::take(&mut self.register_stage_scratch);
        to_insert.clear();

        if let Err(err) = self
            .reserve_register_shard_capacity(tenant, shard_ids.len())
            .and_then(|_| self.reserve_register_index_capacity(tenant, run, &shard_ids))
        {
            self.register_shard_ids_scratch = shard_ids;
            self.register_stage_scratch = to_insert;
            return Err(err);
        }

        for s in shards {
            let key = ShardKey::new(run, s.shard());
            assert!(
                !self.shard_contains(&tenant, &key),
                "register_shards: ShardKey collision for {key:?} — \
                 manifest validation should prevent this"
            );
            let sr = match ShardRecord::new_active_with_cursor(
                tenant,
                run,
                s.shard(),
                s.spec(),
                s.cursor(),
                cursor_semantics,
                &mut self.slab,
            ) {
                Ok(record) => record,
                Err(err) => {
                    // Roll back staged records allocated so far.
                    for (_, mut staged) in to_insert.drain(..) {
                        staged.deallocate_fields(&mut self.slab);
                    }
                    self.register_shard_ids_scratch = shard_ids;
                    self.register_stage_scratch = to_insert;
                    return Err(err.into());
                }
            };
            sr.assert_invariants(&self.slab);
            to_insert.push((key, sr));
        }

        if !self.shards.contains_key(&tenant) {
            self.shards.insert(
                tenant,
                ahash_map_with_capacity(
                    tenant_shards_map_initial_capacity(self.max_shards_per_tenant)
                        .max(shard_ids.len()),
                ),
            );
        }

        for (key, record) in to_insert.drain(..) {
            self.shard_insert(tenant, key, record);
        }

        // Index finalization: `reserve_register_index_capacity` (step 5) already
        // validated that `run_shards` can absorb these entries.  The panic below
        // is defense-in-depth — it fires only if the reservation logic has a bug.
        let run_key = (tenant, run);
        debug_assert!(
            self.run_shards.contains_key(&run_key)
                || self.run_shards.capacity() > self.run_shards.len(),
            "register_shards: run_shards capacity should have been pre-reserved \
             by reserve_register_index_capacity for run {run:?}"
        );
        let shard_set = self.run_shards.entry(run_key).or_insert_with(|| {
            let mut shard_set = ahash_set_with_capacity(0);
            shard_set
                .try_reserve(shard_ids.len().max(RUN_SHARD_SET_INITIAL_CAPACITY))
                .unwrap_or_else(|_| {
                    panic!(
                        "run_shards set capacity exhausted while finalizing register_shards \
                         for run {run:?}"
                    )
                });
            shard_set
        });
        shard_set.extend(shard_ids.iter().copied());

        // 7. Transition run → Active.
        //
        // Re-borrow mutably: the immutable borrow from step 1 (`self.runs.get`)
        // was dropped before step 6's `self.shard_insert` calls.  We must look
        // up again because `&mut self` was consumed by the intervening inserts.
        let record = self
            .runs
            .get_mut(&(tenant, run))
            .expect("run record must exist: verified by step 1 lookup");
        record.assert_transition_legal(RunStatus::Active);
        record.status = RunStatus::Active;
        let executed_shard_ids = shard_ids.clone();
        record.root_shards = executed_shard_ids.clone();
        record.op_log_push(RunOpLogEntry::new(
            op_id,
            RunOpKind::RegisterShards,
            payload_hash,
            now,
            RunOpResult::RegisteredShards {
                shard_ids: executed_shard_ids.clone().into_boxed_slice(),
            },
        ));
        record.assert_invariants();
        self.debug_assert_run_shards_consistent(tenant, run);

        self.register_shard_ids_scratch = shard_ids;
        self.register_stage_scratch = to_insert;

        Ok(IdempotentOutcome::Executed(executed_shard_ids))
    }

    /// Return a clone of the run record after validating tenant isolation.
    ///
    /// Clones to decouple the caller from the coordinator's internal state,
    /// matching the trait's by-value return signature (production backends
    /// would reconstruct from a database row, not hand out references).
    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        self.lookup_run(tenant, run).cloned()
    }

    /// Compute an aggregate progress snapshot for a run by iterating its
    /// shards and counting statuses and lease states.
    ///
    /// The result is order-independent: status tallies use addition and the
    /// watermark uses lexicographic minimum; both are commutative/associative.
    /// This is important because `run_shards` is a `HashSet` with
    /// non-deterministic iteration order.
    ///
    /// `leased` is evaluated at `now`, so a shard at lease deadline is treated
    /// as unleased (`now >= deadline`).
    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        let _ = self.lookup_run(tenant, run)?;

        let mut progress = RunProgress::default();
        if let Some(shard_ids) = self.run_shards.get(&(tenant, run)) {
            for &shard_id in shard_ids {
                let key = ShardKey::new(run, shard_id);
                let record = self.shard_get(&tenant, &key).unwrap_or_else(|| {
                    panic!(
                        "run_shards index contains shard {:?} for run {:?} \
                         but no record exists in the primary shard map — \
                         index desynchronization",
                        shard_id, run,
                    )
                });
                let is_leased = record.is_leased_at(now);
                progress.observe_shard(
                    record.status,
                    is_leased,
                    record.cursor.last_key(&self.slab),
                );
            }
        }
        Ok(progress)
    }

    /// Write summaries for shards in a run that match `filter` into `out`,
    /// sorted by `key_range_start` for deterministic output.
    ///
    /// Sort tie-breaking: when two shards share the same `key_range_start`
    /// (for example split-replace where the parent and first child start at
    /// the same boundary), the secondary sort key is `shard` ID for stable
    /// ordering.
    ///
    /// Applies `filter.matches_record()` *before* constructing
    /// [`ShardSummary`], which avoids unnecessary summary-byte copies
    /// for shards that will be discarded. This matters when a run has
    /// many terminal shards and the caller only wants active ones.
    ///
    /// # Panics
    ///
    /// Panics if the caller-provided `out` buffer does not have enough
    /// pre-allocated capacity to hold all run shards (allocation contract:
    /// no growth inside this method). Also panics if the `run_shards` index
    /// references a shard ID with no corresponding record in the primary
    /// shard map (index desynchronization — indicates a bug).
    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        let _ = self.lookup_run(tenant, run)?;

        let shard_ids = self.run_shards.get(&(tenant, run));
        out.clear();
        if let Some(shard_ids) = shard_ids {
            // Allocation contract: `list_shards_into` must be allocation-silent
            // after startup. Callers are responsible for pre-sizing `out` to
            // at least the run's shard cardinality.
            assert!(
                out.capacity() >= shard_ids.len(),
                "list_shards_into: summary buffer capacity {} < required {} \
                 for run {run:?}; pre-allocate caller buffer at startup",
                out.capacity(),
                shard_ids.len(),
            );
            for &shard_id in shard_ids {
                let key = ShardKey::new(run, shard_id);
                let record = self.shard_get(&tenant, &key).unwrap_or_else(|| {
                    panic!(
                        "run_shards index contains shard {:?} for run {:?} \
                         but no record exists in the primary shard map — \
                         index desynchronization",
                        shard_id, run,
                    )
                });
                // Pre-filter on record fields before constructing ShardSummary
                // and copying spec/cursor bytes into summary storage.
                if !filter.matches_record(record, now) {
                    continue;
                }
                let summary = ShardSummary::from_record(record, now, &self.slab);
                out.push(summary);
            }
        }

        out.sort_by(|a, b| {
            a.key_range_start()
                .cmp(b.key_range_start())
                .then_with(|| a.shard().cmp(&b.shard()))
        });
        Ok(())
    }

    /// Transition an `Active` run to `Done` (terminal, idempotent).
    ///
    /// Validates tenant isolation, checks idempotency, then verifies the
    /// run is `Active` (not `Initializing` or already terminal) before
    /// writing the terminal status and `completed_at` timestamp.
    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let payload_hash = hash_complete_run_payload();
        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(RunTransitionError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(RunTransitionError::TenantMismatch { expected: tenant });
        }

        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            assert_eq!(entry.kind(), RunOpKind::CompleteRun);
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(RunTransitionError::RunTerminal {
                status: record.status,
            });
        }
        // Must be Active (not Initializing).
        if record.status != RunStatus::Active {
            return Err(RunTransitionError::WrongStatus {
                status: record.status,
                target: RunStatus::Done,
            });
        }
        Self::apply_terminal_run_transition(
            record,
            now,
            op_id,
            payload_hash,
            RunStatus::Done,
            RunOpKind::CompleteRun,
        );
        Ok(IdempotentOutcome::Executed(()))
    }

    /// Transition an `Active` run to `Failed` (terminal, idempotent).
    ///
    /// Only `Active` runs can be failed — `Initializing` runs that have
    /// not yet received their shard manifest must use
    /// [`cancel_run`](Self::cancel_run) instead, which is the only
    /// termination path for pre-manifest runs. Follows the same
    /// idempotency-first, terminal-check, status-check order as
    /// [`complete_run`](Self::complete_run).
    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let payload_hash = hash_fail_run_payload();
        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(RunTransitionError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(RunTransitionError::TenantMismatch { expected: tenant });
        }

        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            assert_eq!(entry.kind(), RunOpKind::FailRun);
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(RunTransitionError::RunTerminal {
                status: record.status,
            });
        }
        // Must be Active — Initializing runs use cancel_run instead.
        if record.status != RunStatus::Active {
            return Err(RunTransitionError::WrongStatus {
                status: record.status,
                target: RunStatus::Failed,
            });
        }
        Self::apply_terminal_run_transition(
            record,
            now,
            op_id,
            payload_hash,
            RunStatus::Failed,
            RunOpKind::FailRun,
        );
        Ok(IdempotentOutcome::Executed(()))
    }

    /// Transition a non-terminal run to `Cancelled` (terminal, idempotent).
    ///
    /// Unlike [`fail_run`](Self::fail_run), cancellation accepts both
    /// `Initializing` and `Active` runs — it is the only way to abandon
    /// a run that has not yet received its shard manifest.
    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let payload_hash = hash_cancel_run_payload();
        let record = self
            .runs
            .get_mut(&(tenant, run))
            .ok_or(RunTransitionError::RunNotFound)?;
        if record.tenant != tenant {
            return Err(RunTransitionError::TenantMismatch { expected: tenant });
        }

        if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
            assert_eq!(entry.kind(), RunOpKind::CancelRun);
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status.is_terminal() {
            return Err(RunTransitionError::RunTerminal {
                status: record.status,
            });
        }
        // Accepts both Initializing and Active (unlike fail_run).
        Self::apply_terminal_run_transition(
            record,
            now,
            op_id,
            payload_hash,
            RunStatus::Cancelled,
            RunOpKind::CancelRun,
        );

        Ok(IdempotentOutcome::Executed(()))
    }

    /// Resume a `Parked` shard back to `Active` so it can be acquired
    /// again (idempotent, admin-only).
    ///
    /// Bumps the fence epoch first to invalidate any zombie workers
    /// from a prior lease, then clears park state and restores `Active`.
    /// Idempotency uses the *shard* op-log (not the run op-log).
    ///
    /// **Limitation:** unlike `split_residual`, unpark has no permanent
    /// marker for defense-in-depth replay detection after op-log
    /// eviction. After 16+ shard-level operations a stale retry is
    /// treated as new — acceptable because op_ids are CSPRNG-generated
    /// and the shard must be re-parked before a stale unpark could
    /// succeed.
    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let payload_hash = hash_unpark_payload(&key);

        let record = self
            .shard_get(&tenant, &key)
            .ok_or(UnparkError::ShardNotFound)?;
        if record.tenant != tenant {
            return Err(UnparkError::TenantMismatch { expected: tenant });
        }

        // Reject unpark if the run is already terminal. Unparking a shard in a
        // Cancelled/Done/Failed run wastes worker effort and can create orphaned
        // Active shards that no run-level operation will ever collect.
        let run_key = (tenant, key.run());
        let run_record = self
            .runs
            .get(&run_key)
            .expect("run record must exist for a registered shard");
        if run_record.status.is_terminal() {
            return Err(UnparkError::RunTerminal {
                status: run_record.status,
            });
        }

        // Idempotency via shard op-log.
        //
        // `unpark_shard` lives on `RunManagement` (not `CoordinationBackend`)
        // and uses `UnparkError` (not a `CoordError`-derived type).  The
        // `map_err` below manually routes `CoordError::OpIdConflict` to
        // `UnparkError::OpIdConflict`.  All other `CoordError` variants are
        // listed exhaustively (no wildcard `_`) so that adding a new variant
        // triggers a compile error here, forcing a conscious routing decision.
        if check_op_idempotency(record, op_id, payload_hash)
            .map_err(|e| match e {
                crate::coordination::error::CoordError::OpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                } => UnparkError::OpIdConflict(crate::coordination::run::RunOpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                }),
                crate::coordination::error::CoordError::ShardNotFound { .. }
                | crate::coordination::error::CoordError::TenantMismatch { .. }
                | crate::coordination::error::CoordError::StaleFence { .. }
                | crate::coordination::error::CoordError::LeaseExpired { .. }
                | crate::coordination::error::CoordError::ShardTerminal { .. }
                | crate::coordination::error::CoordError::CursorRegression { .. }
                | crate::coordination::error::CoordError::CursorOutOfBounds(_)
                | crate::coordination::error::CoordError::CursorKeyTooLarge { .. }
                | crate::coordination::error::CoordError::SplitInvalid(_)
                | crate::coordination::error::CoordError::CheckpointMissingKey => {
                    unreachable!("check_op_idempotency only returns OpIdConflict")
                }
            })?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }

        if record.status != ShardStatus::Parked {
            return Err(UnparkError::NotParked {
                status: record.status,
            });
        }

        {
            let record = self
                .shard_get_mut(&tenant, &key)
                .expect("shard record must exist: verified by read-only check above");

            // Bump fence first — invalidate zombie workers from prior lease.
            record.advance_fence();

            record.park_reason = None;
            record.status = ShardStatus::Active;
            record.lease = None;

            record.op_log_push(OpLogEntry::new(
                op_id,
                OpKind::Unpark,
                OpResult::Completed,
                payload_hash,
                now,
            ));
        }
        self.shard_get(&tenant, &key)
            .expect("unparked shard must exist")
            .assert_invariants(&self.slab);

        Ok(IdempotentOutcome::Executed(()))
    }
}

// ============================================================================
// ShardClaiming — per-worker claim cooldown
// ============================================================================

impl ShardClaiming for InMemoryCoordinator {
    /// Claim the next available shard with per-worker cooldown enforcement.
    ///
    /// Overrides the default [`ShardClaiming`] implementation to add a
    /// cooldown gate: if the worker's last successful claim was less than
    /// `claim_cooldown_interval` logical time units ago, the request is
    /// rejected with [`ClaimError::Throttled`] *before* invoking candidate
    /// selection. Candidate selection scans the run index and sorts shard IDs
    /// by `key_range_start` (O(S log S)) using a reusable caller-owned scratch
    /// buffer to avoid per-claim summary allocations.
    ///
    /// On success, the worker's cooldown timer is reset. Failed
    /// claims (no shards available, run not found) do not trigger cooldown,
    /// so a worker competing for scarce shards is never penalized for losing
    /// a race.
    ///
    /// # Panics
    ///
    /// Panics if the candidate buffer cannot be reserved to hold all active
    /// shards in the run (defense-in-depth; the caller-owned `AcquireScratch`
    /// typically grows to steady-state capacity after the first call).  Also
    /// panics if the `run_shards` index references a shard ID with no
    /// corresponding record in the primary shard map (index desynchronization).
    /// Panics if `ensure_claim_cooldown_capacity` was unable to pre-reserve
    /// a cooldown entry for the worker (called before candidate selection).
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError> {
        // Cooldown gate: average O(1) hash lookup before candidate selection.
        if let Some(retry_after) = self.check_cooldown(worker, now) {
            return Err(ClaimError::Throttled { retry_after });
        }
        let _ = self.lookup_run(tenant, run).map_err(ClaimError::from)?;
        self.ensure_claim_cooldown_capacity(worker);

        let mut candidates = std::mem::take(&mut self.claim_candidates_scratch);
        candidates.clear();

        let claim_result = (|| {
            let mut earliest_deadline: Option<LogicalTime> = None;
            if let Some(shard_ids) = self.run_shards.get(&(tenant, run)) {
                if candidates.capacity() < shard_ids.len() {
                    candidates
                        .try_reserve(shard_ids.len() - candidates.capacity())
                        .unwrap_or_else(|_| {
                            panic!(
                                "claim_next_available: unable to reserve candidate buffer \
                                 for run {run:?} ({} entries)",
                                shard_ids.len()
                            )
                        });
                }
                for &shard_id in shard_ids {
                    let key = ShardKey::new(run, shard_id);
                    let record = self.shard_get(&tenant, &key).unwrap_or_else(|| {
                        panic!(
                            "run_shards index contains shard {:?} for run {:?} \
                             but no record exists in the primary shard map — \
                             index desynchronization",
                            shard_id, run,
                        )
                    });
                    if record.status != ShardStatus::Active {
                        continue;
                    }
                    if record.is_leased_at(now) {
                        if let Some(deadline) = record.lease_deadline() {
                            earliest_deadline = Some(match earliest_deadline {
                                Some(prev) => core::cmp::min(prev, deadline),
                                None => deadline,
                            });
                        }
                        continue;
                    }
                    candidates.push(shard_id);
                }
            }

            if candidates.is_empty() {
                return Err(ClaimError::NoneAvailable { earliest_deadline });
            }

            candidates.sort_by(|a, b| {
                let key_a = ShardKey::new(run, *a);
                let key_b = ShardKey::new(run, *b);
                let record_a = self.shard_get(&tenant, &key_a).unwrap_or_else(|| {
                    panic!(
                        "run_shards index contains shard {:?} for run {:?} \
                         but no record exists in the primary shard map — \
                         index desynchronization",
                        a, run,
                    )
                });
                let record_b = self.shard_get(&tenant, &key_b).unwrap_or_else(|| {
                    panic!(
                        "run_shards index contains shard {:?} for run {:?} \
                         but no record exists in the primary shard map — \
                         index desynchronization",
                        b, run,
                    )
                });
                record_a
                    .spec
                    .key_range_start(&self.slab)
                    .cmp(record_b.spec.key_range_start(&self.slab))
                    .then_with(|| a.cmp(b))
            });

            let len = candidates.len();
            let offset = worker.as_raw() as usize % len;
            let mut inconsistency_count = 0usize;

            for i in 0..len {
                let shard_id = candidates[(offset + i) % len];
                let key = ShardKey::new(run, shard_id);
                match self.acquire_and_restore_into(now, tenant, key, worker, out) {
                    Ok(result) => {
                        let snapshot = result.snapshot;
                        return Ok((
                            result.lease,
                            snapshot.status(),
                            snapshot.cursor_semantics(),
                            snapshot.parent(),
                            result.capacity,
                        ));
                    }
                    Err(AcquireError::AlreadyLeased { lease_deadline, .. }) => {
                        earliest_deadline = Some(match earliest_deadline {
                            Some(prev) => core::cmp::min(prev, lease_deadline),
                            None => lease_deadline,
                        });
                    }
                    Err(AcquireError::ShardTerminal { .. }) => {}
                    Err(AcquireError::ShardNotFound { .. }) => {
                        debug_assert!(
                            false,
                            "claim_next_available: candidate shard {key:?} \
                             disappeared between selection and acquire"
                        );
                        inconsistency_count += 1;
                    }
                    Err(AcquireError::TenantMismatch { expected }) => {
                        return Err(ClaimError::TenantMismatch { expected });
                    }
                }
            }

            assert!(
                inconsistency_count < len,
                "all {} claim candidates returned ShardNotFound — backend index vs shard map inconsistency",
                len,
            );
            Err(ClaimError::NoneAvailable { earliest_deadline })
        })();

        self.claim_candidates_scratch = candidates;
        let (lease, status, cursor_semantics, parent, capacity) = claim_result?;
        self.record_claim(worker, now);
        Ok(AcquireResultView {
            lease,
            snapshot: out.view(status, cursor_semantics, parent),
            capacity,
        })
    }
}

impl InMemoryCoordinator {
    /// Check whether `worker` is still in cooldown at time `now`.
    ///
    /// Returns `Some(retry_after)` if the worker must wait, `None` if
    /// the worker may proceed. The cooldown window is the half-open
    /// interval `[last_claim, last_claim + interval)`: at exactly
    /// `last_claim + interval` the worker is allowed through. This
    /// matches the lease expiry convention where `now >= deadline`
    /// means expired.
    ///
    /// On arithmetic overflow (`last_claim + interval > u64::MAX`), the deadline
    /// saturates to `LogicalTime::MAX`, making the cooldown effectively permanent.
    /// This matches the lease deadline saturation in `acquire_and_restore_into`.
    fn check_cooldown(&self, worker: WorkerId, now: LogicalTime) -> Option<LogicalTime> {
        if self.claim_cooldown_interval == 0 {
            return None;
        }
        let last_claim = self.claim_cooldowns.get(&worker)?;
        let retry_after = last_claim
            .checked_add(self.claim_cooldown_interval)
            .unwrap_or(LogicalTime::from_raw(u64::MAX));
        if now < retry_after {
            Some(retry_after)
        } else {
            None
        }
    }

    /// Record that `worker` successfully claimed a shard at time `now`.
    ///
    /// No-op when cooldown is disabled (`claim_cooldown_interval == 0`),
    /// avoiding unbounded growth of `claim_cooldowns` in deployments
    /// that don't use the feature.
    fn record_claim(&mut self, worker: WorkerId, now: LogicalTime) {
        if self.claim_cooldown_interval > 0 {
            debug_assert!(
                now >= *self
                    .claim_cooldowns
                    .get(&worker)
                    .unwrap_or(&LogicalTime::from_raw(0)),
                "record_claim: time went backward for worker {worker:?}: \
                 now={now:?}, previous={:?}",
                self.claim_cooldowns.get(&worker),
            );
            self.claim_cooldowns.insert(worker, now);
        }
    }

    /// Remove a parent shard record, run `body`, then always restore it.
    ///
    /// This centralizes the *remove-mutate-restore* pattern used by both
    /// split operations (`split_replace` and `split_residual`). The pattern
    /// exists because Rust's borrow checker prevents holding `&mut parent`
    /// (from `HashMap::get_mut`) while simultaneously inserting new child
    /// entries into the same `HashMap`. Removing the parent first releases
    /// the mutable borrow on the map, allowing the closure to call
    /// `shard_insert` for children.
    ///
    /// The parent is reinserted for both `Ok` and `Err` returns from `body`.
    /// On panic (invariant violation), the parent is intentionally *not*
    /// restored -- an invariant panic indicates irrecoverable corruption,
    /// and restoring the parent would mask it.
    ///
    /// After restoration, `debug_assert_run_shards_consistent` verifies that
    /// the run-to-shard secondary index agrees with the primary shard map.
    fn with_removed_parent<R, E, F>(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
        not_found: E,
        body: F,
    ) -> Result<R, E>
    where
        F: FnOnce(&mut Self, &mut ShardRecord) -> Result<R, E>,
    {
        let mut parent = self.shard_remove(&tenant, &key).ok_or(not_found)?;
        let run = parent.run;
        let result = body(self, &mut parent);
        self.shard_insert(tenant, key, parent);
        self.debug_assert_run_shards_consistent(tenant, run);
        result
    }
}

// ============================================================================
// SimIntrospection — read-only observation for simulation
// ============================================================================

/// Read-only observation interface for the deterministic simulation harness.
///
/// Exposes the coordinator's internal shard state without mutation, enabling
/// the simulation invariant checker to verify protocol properties (coverage
/// gaps, lease consistency, cursor bounds) across all shards after each
/// simulated step. Following the FoundationDB model, simulation is treated
/// as first-class verification infrastructure — not gated behind `#[cfg(test)]`
/// alone, but also available via the `test-support` feature for integration
/// harnesses.
///
/// This impl intentionally exposes borrowed accessors (cursor key,
/// range bounds, cleanup hook) instead of raw slab
/// handles so simulation code stays storage-abstraction-safe.
#[cfg(any(test, feature = "test-support"))]
/// Two-level shard iterator used by `SimIntrospection::shards`.
///
/// Traverses tenant maps in outer-hash-map iteration order, then shard maps in
/// per-tenant hash-map iteration order. Both orders are intentionally
/// unspecified.
pub struct InMemoryShardIter<'a> {
    outer: std::collections::hash_map::Iter<'a, TenantId, AHashMap<ShardKey, ShardRecord>>,
    inner: Option<(
        TenantId,
        std::collections::hash_map::Iter<'a, ShardKey, ShardRecord>,
    )>,
}

#[cfg(any(test, feature = "test-support"))]
impl<'a> Iterator for InMemoryShardIter<'a> {
    type Item = ((TenantId, ShardKey), &'a ShardRecord);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some((tenant, inner)) = self.inner.as_mut()
                && let Some((&key, record)) = inner.next()
            {
                return Some(((*tenant, key), record));
            }

            let (&tenant, records) = self.outer.next()?;
            self.inner = Some((tenant, records.iter()));
        }
    }
}

#[cfg(any(test, feature = "test-support"))]
/// Run iterator used by `SimIntrospection::runs`.
///
/// Order follows hash-map iteration and is intentionally unspecified.
pub struct InMemoryRunIter<'a> {
    inner: std::collections::hash_map::Iter<'a, (TenantId, RunId), RunRecord>,
}

#[cfg(any(test, feature = "test-support"))]
impl<'a> Iterator for InMemoryRunIter<'a> {
    type Item = ((TenantId, RunId), &'a RunRecord);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(&(tenant, run), record)| ((tenant, run), record))
    }
}

#[cfg(any(test, feature = "test-support"))]
/// Borrowed iterator over a record's spawned child IDs.
///
/// Wraps `PooledSpawnedIter` so simulation code does not need to reference
/// pooled storage internals directly.
pub struct InMemorySpawnedIter<'a> {
    inner: crate::coordination::pooled::PooledSpawnedIter<'a>,
}

#[cfg(any(test, feature = "test-support"))]
impl<'a> Iterator for InMemorySpawnedIter<'a> {
    type Item = ShardId;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

#[cfg(any(test, feature = "test-support"))]
impl crate::sim::backend::SimIntrospection for InMemoryCoordinator {
    type ShardIter<'a> = InMemoryShardIter<'a>;
    type RunIter<'a> = InMemoryRunIter<'a>;
    type SpawnedIter<'a> = InMemorySpawnedIter<'a>;

    fn shards(&self) -> Self::ShardIter<'_> {
        // Iterator construction is allocation-free: this just captures map iterators.
        InMemoryShardIter {
            outer: self.shards.iter(),
            inner: None,
        }
    }

    fn runs(&self) -> Self::RunIter<'_> {
        // Allocation-free borrowed iterator over run records.
        InMemoryRunIter {
            inner: self.runs.iter(),
        }
    }

    fn shard_count(&self) -> usize {
        self.total_shard_count
    }

    fn shard_lookup(&self, tenant: &TenantId, key: &ShardKey) -> Option<&ShardRecord> {
        self.shard_get(tenant, key)
    }

    fn cursor_last_key<'a>(&'a self, record: &'a ShardRecord) -> Option<&'a [u8]> {
        record.cursor.last_key(&self.slab)
    }

    fn spec_bounds<'a>(&'a self, record: &'a ShardRecord) -> (&'a [u8], &'a [u8]) {
        (
            record.spec.key_range_start(&self.slab),
            record.spec.key_range_end(&self.slab),
        )
    }

    fn validate_record_invariants(&self, record: &ShardRecord) -> Result<(), String> {
        record.validate_invariants(&self.slab)
    }

    fn spawned_children<'a>(&'a self, record: &'a ShardRecord) -> Self::SpawnedIter<'a> {
        // Allocation-free borrowed iterator over pooled lineage storage.
        InMemorySpawnedIter {
            inner: record.spawned.iter(&self.slab),
        }
    }

    fn release_record_fields(&mut self, record: &mut ShardRecord) {
        record.deallocate_fields(&mut self.slab);
    }
}

#[cfg(test)]
#[path = "in_memory_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "in_memory_run_tests.rs"]
mod run_tests;

#[cfg(test)]
#[path = "in_memory_filter_tests.rs"]
mod filter_tests;
