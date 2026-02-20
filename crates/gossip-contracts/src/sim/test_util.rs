//! Shared test utilities for the simulation module.

use crate::coordination::cursor::Cursor;
use crate::coordination::lease::LeaseHolder;
use crate::coordination::record::ShardRecord;
use crate::coordination::record::ShardStatus;
use crate::coordination::shard_spec::{CursorSemantics, ShardSpec};
use crate::identity::{FenceEpoch, RunId, ShardId, ShardKey, TenantId};
use gossip_stdx::RingBuffer;

/// Standard test tenant used across simulation test modules.
pub(crate) const TENANT: TenantId = TenantId::from_bytes([0x01; 32]);

/// Standard lease duration used across simulation test modules.
pub(crate) const LEASE_DUR: u64 = 100;

/// Convenience constructor for `ShardKey` from raw integer IDs.
pub(crate) fn make_key(run: u64, shard: u64) -> ShardKey {
    ShardKey::new(RunId::from_raw(run), ShardId::from_raw(shard))
}

/// Fluent builder for [`ShardRecord`] in tests.
///
/// Provides sensible defaults for every field so tests only specify the
/// fields relevant to the invariant being tested, replacing verbose
/// 13-argument `from_raw_parts` calls.
pub(crate) struct TestRecordBuilder {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
    status: ShardStatus,
    park_reason: Option<crate::coordination::record::ParkReason>,
    spec: ShardSpec,
    cursor: Cursor,
    cursor_semantics: CursorSemantics,
    lease: Option<LeaseHolder>,
    fence_epoch: FenceEpoch,
    parent: Option<ShardId>,
    spawned: Vec<ShardId>,
}

impl TestRecordBuilder {
    /// Start building a record with the three identity fields that vary
    /// across tests. All other fields get sensible defaults.
    pub fn new(tenant: TenantId, run: RunId, shard: ShardId) -> Self {
        Self {
            tenant,
            run,
            shard,
            status: ShardStatus::Active,
            park_reason: None,
            spec: ShardSpec::with_range(vec![b'a'], vec![b'z']),
            cursor: Cursor::initial(),
            cursor_semantics: CursorSemantics::Completed,
            lease: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: None,
            spawned: vec![],
        }
    }

    pub fn status(mut self, status: ShardStatus) -> Self {
        self.status = status;
        self
    }

    pub fn park_reason(mut self, reason: crate::coordination::record::ParkReason) -> Self {
        self.park_reason = Some(reason);
        self
    }

    pub fn spec(mut self, spec: ShardSpec) -> Self {
        self.spec = spec;
        self
    }

    pub fn cursor(mut self, cursor: Cursor) -> Self {
        self.cursor = cursor;
        self
    }

    pub fn lease(mut self, lease: LeaseHolder) -> Self {
        self.lease = Some(lease);
        self
    }

    pub fn fence_epoch(mut self, epoch: FenceEpoch) -> Self {
        self.fence_epoch = epoch;
        self
    }

    pub fn parent(mut self, parent: ShardId) -> Self {
        self.parent = Some(parent);
        self
    }

    pub fn spawned(mut self, spawned: Vec<ShardId>) -> Self {
        self.spawned = spawned;
        self
    }

    /// Consume the builder and produce a [`ShardRecord`].
    ///
    /// Delegates to `from_raw_parts`, bypassing invariant validation so
    /// tests can construct intentionally invalid records.
    pub fn build(self) -> ShardRecord {
        ShardRecord::from_raw_parts(
            self.tenant,
            self.run,
            self.shard,
            self.status,
            self.park_reason,
            self.spec,
            self.cursor,
            self.cursor_semantics,
            self.lease,
            self.fence_epoch,
            self.parent,
            self.spawned,
            RingBuffer::new(),
        )
    }
}
