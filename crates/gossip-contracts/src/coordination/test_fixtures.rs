//! Shared test fixtures for the coordination module.
//!
//! Promotes commonly duplicated test helpers (tenant, run, shard factories,
//! seeded coordinator setup) to a single `pub(crate)` location. Consumed by
//! `in_memory_tests`, `conformance_tests`, `scenario_tests`, and any future
//! coordination test modules.

use crate::coordination::cursor::Cursor;
use crate::coordination::in_memory::InMemoryCoordinator;
use crate::coordination::lease::Lease;
use crate::coordination::run::{InitialShard, RunConfig, RunManagement};
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
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

pub fn test_worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

pub fn now(t: u64) -> LogicalTime {
    LogicalTime::from_raw(t)
}

pub fn test_key() -> ShardKey {
    ShardKey::new(test_run(), test_shard())
}

pub fn test_cursor(key: &[u8]) -> Cursor {
    Cursor::with_last_key(key.to_vec())
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
    let shards = vec![InitialShard::new(
        test_shard(),
        test_spec(),
        Cursor::initial(),
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

/// Acquire the default test shard with the given worker at the given time.
pub fn acquire_shard(coord: &mut InMemoryCoordinator, t: u64, worker_id: u64) -> Lease {
    let result = coord
        .acquire_and_restore(now(t), test_tenant(), test_key(), test_worker(worker_id))
        .expect("acquire should succeed");
    result.lease
}
