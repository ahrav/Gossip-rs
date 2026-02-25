//! Shared test fixtures for the coordination module.
//!
//! Promotes commonly duplicated test helpers (tenant, run, shard factories,
//! seeded coordinator setup) to a single `pub(crate)` location. Consumed by
//! `in_memory_tests`, `conformance_tests`, `scenario_tests`, and any future
//! coordination test modules.

use crate::coordination::cursor::{Cursor, CursorUpdate};
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::lease::Lease;
use crate::coordination::record::ParkReason;
use crate::coordination::run::{InitialShardInput, RunConfig, RunManagement};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec, ShardSpecRef};
use crate::coordination::split::{SplitReplaceChild, SplitReplacePlan, SplitResidualPlan};
use crate::coordination::traits::CoordinationBackend;
use crate::identity::{LogicalTime, OpId, RunId, ShardId, ShardKey, TenantId, WorkerId};

/// Default lease duration in logical time ticks.
pub const LEASE_DURATION: u64 = 100;

pub fn test_tenant() -> TenantId {
    TenantId::from_bytes([0x01; 32])
}

pub fn test_run() -> RunId {
    RunId::from_raw(1)
}

pub fn test_shard() -> ShardId {
    ShardId::from_raw(10)
}

pub fn test_spec() -> ShardSpec {
    ShardSpec::with_range(b"a".to_vec(), b"z".to_vec())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialShard<'a> {
    shard: ShardId,
    spec: ShardSpecRef<'a>,
    cursor: CursorUpdate<'a>,
}

impl<'a> InitialShard<'a> {
    pub fn new(shard: ShardId, spec: ShardSpecRef<'a>, cursor: CursorUpdate<'a>) -> Self {
        Self {
            shard,
            spec,
            cursor,
        }
    }
}

pub fn manifest_inputs<'a>(shards: &[InitialShard<'a>]) -> Vec<InitialShardInput<'a>> {
    shards
        .iter()
        .map(|shard| InitialShardInput::new(shard.shard, shard.spec, shard.cursor))
        .collect()
}

pub fn test_worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

pub fn now(t: u64) -> LogicalTime {
    LogicalTime::from_raw(t)
}

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

pub fn test_cursor(key: &[u8]) -> CursorUpdate<'_> {
    CursorUpdate::new(key)
}

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
    let inputs = [InitialShardInput::new(
        test_shard(),
        spec.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &inputs,
            OpId::from_raw(u64::MAX),
        )
        .unwrap();
    coord
}

pub fn test_run_config() -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, LEASE_DURATION, Some(5)).unwrap()
}

/// The canonical `[a,m) + [m,z)` replace plan used by most split tests.
pub fn test_split_replace_plan() -> SplitReplacePlan {
    SplitReplacePlan::try_new(vec![
        SplitReplaceChild::new(
            ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
            Cursor::initial(),
        ),
        SplitReplaceChild::new(
            ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
            Cursor::initial(),
        ),
    ])
    .unwrap()
}

/// The canonical `[a,m)` parent + `[m,z)` residual plan.
pub fn test_split_residual_plan() -> SplitResidualPlan {
    SplitResidualPlan::try_new(
        ShardSpec::with_range(b"a".to_vec(), b"m".to_vec()),
        ShardSpec::with_range(b"m".to_vec(), b"z".to_vec()),
    )
    .unwrap()
}

/// Acquire the default test shard with the given worker at the given time.
pub fn acquire_shard(coord: &mut InMemoryCoordinator, t: u64, worker_id: u64) -> Lease {
    let result = coord
        .acquire_and_restore(now(t), test_tenant(), test_key(), test_worker(worker_id))
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
/// `acquire_and_restore`. Returns `(coordinator, lease)` ready for
/// split, park, or completion tests. Time advances through t=1..3;
/// callers should start at t=4.
///
/// Uses [`short_lease_run_config`] (30-tick lease) for run creation.
pub fn coordinator_with_run_and_lease() -> (InMemoryCoordinator, Lease) {
    let mut coord = InMemoryCoordinator::new(LEASE_DURATION);
    coord
        .create_run(now(1), test_tenant(), test_run(), short_lease_run_config())
        .unwrap();
    let spec = ShardSpec::with_range(b"a".to_vec(), b"z".to_vec());
    let inputs = [InitialShardInput::new(
        ShardId::from_raw(10),
        spec.as_ref(),
        CursorUpdate::initial(),
    )];
    let _ = coord
        .register_shards(
            now(2),
            test_tenant(),
            test_run(),
            &inputs,
            OpId::from_raw(1),
        )
        .unwrap();
    let key = ShardKey::new(test_run(), ShardId::from_raw(10));
    let lease = coord
        .acquire_and_restore(now(3), test_tenant(), key, test_worker(1))
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
