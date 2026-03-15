//! In-memory coordinator binding for the shared coordination conformance harness.

use crate::conformance::run_coordination_conformance;
use crate::test_fixtures::{LEASE_DURATION, seeded_coordinator_with_semantics};
use crate::{MAX_SPAWNED_PER_SHARD, ShardRecord};

// Guard against silent constant changes that would invalidate test assumptions.

const _: () = assert!(ShardRecord::OP_LOG_CAP == 16);
const _: () = assert!(MAX_SPAWNED_PER_SHARD == 1024);
const _: () = assert!(LEASE_DURATION == 100);

// Production-only allocation-contract guards.
//
// These pin the hot-path API surface to borrowed inputs and caller-owned
// scratch/output forms in default-feature (production-like) builds.
// `test-support` builds intentionally skip these guards so simulation paths
// can remain allocation-friendly.
#[cfg(not(feature = "test-support"))]
const _: for<'a> fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    gossip_contracts::identity::ShardKey,
    gossip_contracts::identity::WorkerId,
    &'a mut crate::AcquireScratch,
) -> Result<crate::AcquireResultView<'a>, crate::AcquireError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::acquire_and_restore_into;

#[cfg(not(feature = "test-support"))]
const _: fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    &crate::Lease,
    &crate::CursorUpdate<'_>,
    gossip_contracts::identity::OpId,
) -> Result<crate::IdempotentOutcome<()>, crate::CheckpointError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::checkpoint;

#[cfg(not(feature = "test-support"))]
const _: fn(
    &mut crate::InMemoryCoordinator,
    gossip_contracts::identity::LogicalTime,
    gossip_contracts::identity::TenantId,
    &crate::Lease,
    &crate::CursorUpdate<'_>,
    gossip_contracts::identity::OpId,
) -> Result<crate::IdempotentOutcome<()>, crate::CompleteError> =
    <crate::InMemoryCoordinator as crate::CoordinationBackend>::complete;

#[test]
fn in_memory_coordination_conformance() {
    run_coordination_conformance(seeded_coordinator_with_semantics);
}
