//! Shared test fixtures for the coordination module.
//!
//! Promotes commonly duplicated test helpers (tenant, run, shard factories,
//! seeded coordinator setup) to a single `pub(crate)` location. Consumed by
//! `in_memory_tests`, `conformance_tests`, `scenario_tests`, and any future
//! coordination test modules.
//!
//! # Design rationale
//!
//! Every coordination test needs the same boilerplate: a `TenantId`, a
//! `RunId`, a `ShardId`, and a coordinator seeded with at least one run and
//! shard. Duplicating that setup per test module invites copy-paste drift
//! (different tenant bytes, inconsistent shard ranges). Centralizing here
//! keeps the canonical identities stable and lets test modules focus on the
//! behavior under test.
//!
//! # Conventions
//!
//! - **Time**: `now(t)` wraps `LogicalTime::from_raw(t)`. Tests advance
//!   time manually; no background clock.
//! - **Identity factories** (`test_tenant`, `test_run`, `test_shard`,
//!   `test_worker`): return deterministic, visually recognizable values.
//! - **Seeded coordinators** (`seeded_coordinator`,
//!   `coordinator_with_run_and_lease`): pre-populate a single run with one
//!   shard and optionally acquire a lease, so tests start from a known
//!   baseline.
//! - **Fire-and-forget helpers** (`checkpoint_ok`, `complete_ok`,
//!   `park_ok`): advance state without inspecting the return value. They
//!   panic on failure, suitable only for setup steps.

use crate::coordination::cursor::CursorUpdate;
use crate::coordination::error::{AcquireError, AcquireScratch, CapacityHint, ShardSnapshotView};
use crate::coordination::facade::{ClaimError, ShardClaiming};
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::lease::Lease;
use crate::coordination::record::{ParkReason, ShardStatus};
use crate::coordination::run::{InitialShardInput, RunConfig, RunManagement};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec, ShardSpecRef};
use crate::coordination::split::{SplitReplaceChild, SplitReplacePlan, SplitResidualPlan};
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};

// ============================================================================
// Constants and identity factories
// ============================================================================

/// Default lease duration in logical time ticks.
///
/// 100 ticks provides enough headroom that most test operations complete
/// within a single lease, while still allowing lease-expiry tests to
/// advance time past the deadline with small offsets.
pub const LEASE_DURATION: u64 = 100;

/// Canonical test tenant (`[0x01; 32]`).
pub fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

/// Canonical test run (ID = 1).
pub fn test_run() -> RunId {
    RunId::from_raw(1)
}

/// Canonical test shard (ID = 10).
pub fn test_shard() -> ShardId {
    ShardId::from_raw(10)
}

/// Canonical test shard spec: half-open range `[a, z)`.
pub fn test_spec() -> ShardSpec {
    ShardSpec::with_range(b"a", b"z")
}

/// Create a worker identity from a numeric ID.
pub fn test_worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

/// Wrap a raw tick count into [`LogicalTime`].
pub fn now(t: u64) -> LogicalTime {
    LogicalTime::from_raw(t)
}

/// Canonical shard key combining [`test_run()`] and [`test_shard()`].
pub fn test_key() -> ShardKey {
    ShardKey::new(test_run(), test_shard())
}

/// Create a derived `ShardId` (bit 63 set), matching the convention
/// used by the split subsystem for child shard IDs.
pub fn derived_shard_id(base: u64) -> ShardId {
    ShardId::from_raw(base | (1u64 << 63))
}

/// Returns a tenant distinct from [`test_tenant()`] for isolation tests.
///
/// Uses `[0x02; 32]` so it is deterministic and visually distinguishable
/// from `test_tenant()` (`[0x01; 32]`).
pub fn other_tenant() -> TenantId {
    TenantId::from_bytes([0x02; 32])
}

/// Wrap a byte slice in a [`CursorUpdate`].
pub fn test_cursor(key: &[u8]) -> CursorUpdate<'_> {
    CursorUpdate::new(key)
}

// ============================================================================
// Seeded coordinator factories
// ============================================================================

/// Create a coordinator with a single run containing one shard `[a, z)`.
///
/// The run uses `CursorSemantics::Completed` and the default lease duration.
/// The register-shards op uses `OpId::MAX` to avoid collisions with test ops.
pub fn seeded_coordinator() -> InMemoryCoordinator {
    seeded_coordinator_with_semantics(CursorSemantics::Completed)
}

/// Like [`seeded_coordinator`] but allows choosing cursor semantics.
pub fn seeded_coordinator_with_semantics(semantics: CursorSemantics) -> InMemoryCoordinator {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    let config = RunConfig::try_new(semantics, LEASE_DURATION, Some(5)).unwrap();
    coord
        .create_run(now(1), test_tenant(), test_run(), config)
        .unwrap();
    let spec = test_spec();
    let shards = vec![InitialShardInput::new(
        test_shard(),
        spec.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(u64::MAX),
        )
        .unwrap();
    coord
}

/// Standard [`RunConfig`] with default lease duration (100 ticks).
pub fn test_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, LEASE_DURATION, Some(5)).unwrap()
}

/// Allocation-free test acquire result wrapper that owns scratch storage.
///
/// This keeps borrowed snapshot views usable after helper return without any
/// heap-backed cursor/spec materialization.
#[derive(Debug)]
pub struct AcquireFixture {
    pub lease: Lease,
    pub capacity: CapacityHint,
    status: ShardStatus,
    cursor_semantics: CursorSemantics,
    parent: Option<ShardId>,
    scratch: AcquireScratch,
}

impl AcquireFixture {
    pub fn snapshot(&self) -> ShardSnapshotView<'_> {
        self.scratch
            .view(self.status, self.cursor_semantics, self.parent)
    }
}

/// Acquire + restore using allocation-free snapshot storage.
pub fn acquire_result<B: CoordinationBackend>(
    backend: &mut B,
    now: LogicalTime,
    tenant: TenantId,
    key: ShardKey,
    worker: WorkerId,
) -> Result<AcquireFixture, AcquireError> {
    let mut scratch = AcquireScratch::new();
    let (lease, capacity, status, cursor_semantics, parent) = {
        let view = backend.acquire_and_restore_into(now, tenant, key, worker, &mut scratch)?;
        (
            view.lease,
            view.capacity,
            view.snapshot.status(),
            view.snapshot.cursor_semantics(),
            view.snapshot.parent(),
        )
    };
    Ok(AcquireFixture {
        lease,
        capacity,
        status,
        cursor_semantics,
        parent,
        scratch,
    })
}

/// Claim next available using allocation-free snapshot storage.
pub fn claim_result<B: ShardClaiming + Sized>(
    backend: &mut B,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
) -> Result<AcquireFixture, ClaimError> {
    let mut scratch = AcquireScratch::new();
    let (lease, capacity, status, cursor_semantics, parent) = {
        let view = backend.claim_next_available(now, tenant, run, worker, &mut scratch)?;
        (
            view.lease,
            view.capacity,
            view.snapshot.status(),
            view.snapshot.cursor_semantics(),
            view.snapshot.parent(),
        )
    };
    Ok(AcquireFixture {
        lease,
        capacity,
        status,
        cursor_semantics,
        parent,
        scratch,
    })
}

// ============================================================================
// Split plan factories
// ============================================================================

/// The canonical `[a,m) + [m,z)` replace plan used by most split tests.
pub fn test_split_replace_plan() -> SplitReplacePlan<'static> {
    SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(ShardSpecRef::new(b"a", b"m", b""), CursorUpdate::initial()),
        SplitReplaceChild::new(ShardSpecRef::new(b"m", b"z", b""), CursorUpdate::initial()),
    ])
    .unwrap()
}

/// The canonical `[a,m)` parent + `[m,z)` residual plan.
pub fn test_split_residual_plan() -> SplitResidualPlan<'static> {
    SplitResidualPlan::try_new(
        ShardSpecRef::new(b"a", b"m", b""),
        ShardSpecRef::new(b"m", b"z", b""),
    )
    .unwrap()
}

// ============================================================================
// Fire-and-forget operation helpers
// ============================================================================
//
// Each helper performs one coordinator operation and panics on failure.
// Use these only for *setup* steps where the return value is not the
// subject of the test's assertions. For assertions on outcomes, call
// the coordinator method directly.

/// Acquire the default test shard with the given worker at the given time.
pub fn acquire_shard(coord: &mut InMemoryCoordinator, t: u64, worker_id: u64) -> Lease {
    let mut scratch = crate::coordination::error::AcquireScratch::new();
    let result = coord
        .acquire_and_restore_into(
            now(t),
            test_tenant(),
            test_key(),
            test_worker(worker_id),
            &mut scratch,
        )
        .expect("acquire should succeed");
    result.lease
}

/// Checkpoint the default test shard, discarding the result.
///
/// Panics on failure. Use this only for fire-and-forget checkpoints where
/// the return value is not needed (e.g. setting up state for a later assertion).
pub fn checkpoint_ok(
    coord: &mut InMemoryCoordinator,
    t: u64,
    lease: &Lease,
    cursor_key: &[u8],
    op_id: u64,
) {
    let cursor = test_cursor(cursor_key);
    let _ = coord
        .checkpoint(now(t), test_tenant(), lease, &cursor, OpId::from_raw(op_id))
        .expect("checkpoint should succeed");
}

/// Complete the default test shard, discarding the result.
///
/// Panics on failure. Use this only for fire-and-forget completes where
/// the return value is not needed.
pub fn complete_ok(
    coord: &mut InMemoryCoordinator,
    t: u64,
    lease: &Lease,
    cursor_key: &[u8],
    op_id: u64,
) {
    let cursor = test_cursor(cursor_key);
    let _ = coord
        .complete(now(t), test_tenant(), lease, &cursor, OpId::from_raw(op_id))
        .expect("complete should succeed");
}

/// Park the default test shard, discarding the result.
///
/// Panics on failure. Use this only for fire-and-forget parks where
/// the return value is not needed.
pub fn park_ok(
    coord: &mut InMemoryCoordinator,
    t: u64,
    lease: &Lease,
    reason: ParkReason,
    op_id: u64,
) {
    let _ = coord
        .park_shard(now(t), test_tenant(), lease, reason, OpId::from_raw(op_id))
        .expect("park should succeed");
}

/// Standard [`RunConfig`] for run-management tests.
///
/// Uses `CursorSemantics::Completed`, a 30-tick lease duration,
/// and max shard retries of 5. Named "short lease" to distinguish from
/// [`test_run_config`] which uses [`LEASE_DURATION`] (100).
pub fn short_lease_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, 30, Some(5)).unwrap()
}

/// Creates a coordinator with a fully initialized run and an acquired lease.
///
/// Performs: `create_run` -> `register_shards` (one shard `[a,z)`) ->
/// `acquire_and_restore_into`. Returns `(coordinator, lease)` ready for
/// split, park, or completion tests. Time advances through t=1..3;
/// callers should start at t=4.
///
/// Uses [`short_lease_run_config`] (30-tick lease) for run creation.
pub fn coordinator_with_run_and_lease() -> (InMemoryCoordinator, Lease) {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let spec = ShardSpec::with_range(b"a", b"z");
    let cursor = CursorUpdate::initial();
    let shards = vec![InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        cursor,
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &shards,
            OpId::from_raw(1),
        )
        .unwrap();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));
    let mut scratch = crate::coordination::error::AcquireScratch::new();
    let lease = coord
        .acquire_and_restore_into(now(3), test_tenant(), key, test_worker(1), &mut scratch)
        .unwrap()
        .lease;
    (coord, lease)
}

/// Performs the canonical `split_replace` on `[a,z)` into `[a,m)` and `[m,z)`.
///
/// Uses t=4 and OpId=2. Panics on failure. Intended to be called after
/// [`coordinator_with_run_and_lease`] to set up a post-split state for
/// index-consistency and filter tests.
pub fn do_split_replace(coord: &mut InMemoryCoordinator, lease: &Lease) {
    let plan = test_split_replace_plan();
    let _ = coord
        .split_replace(now(4), test_tenant(), lease, plan, OpId::from_raw(2))
        .unwrap();
}
