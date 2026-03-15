//! Shared test utilities for the simulation module.
//!
//! Centralizes proptest strategies, canonical constants, and a fluent builder
//! so that simulation test modules (`proptest_state_machine_tests`),
//! harness property tests, and subsystem tests (`invariants`,
//! `fault_injector`) share one source of truth for test data construction.
//!
//! # Contents
//!
//! - **[`arb_fault_level`] / [`arb_sim_op`]** — proptest strategies for
//!   generating fault levels and simulation operations. Strategies are
//!   stateless (no tracking of held leases or paused workers) so proptest
//!   can shrink by freely removing any element from a generated sequence.
//! - **[`TENANT`] / [`LEASE_DUR`] / [`make_key`]** — canonical constants and
//!   a convenience constructor, preventing magic literals from scattering
//!   across test files.
//! - **[`TestRecordBuilder`]** — fluent builder for [`ShardRecord`] that
//!   provides sensible defaults, replacing verbose 13-argument
//!   `from_raw_parts` calls with intent-revealing chains like
//!   `TestRecordBuilder::new(…).status(Done).build()`.

use proptest::prelude::*;
use std::borrow::Borrow;

use crate::lease::LeaseHolder;
use crate::record::ShardRecord;
use crate::record::ShardStatus;
use crate::sim::FaultLevel;
use crate::sim::harness::{RunTerminalKind, SimOp};
use gossip_contracts::coordination::cursor::CursorUpdate;
use gossip_contracts::coordination::shard_spec::{CursorSemantics, ShardSpec};
use gossip_contracts::identity::{FenceEpoch, RunId, ShardId, ShardKey, TenantId, WorkerId};
use gossip_stdx::{ByteSlab, RingBuffer};

/// Proptest strategy producing a uniform choice among the three [`FaultLevel`] variants.
///
/// Each level has equal weight (`1:1:1`). Used by
/// `prop_safety_across_fault_levels` and harness-level property tests to
/// sweep all severity tiers in a single proptest run.
pub fn arb_fault_level() -> impl Strategy<Value = FaultLevel> {
    prop_oneof![
        Just(FaultLevel::SunnyDay),
        Just(FaultLevel::Stormy),
        Just(FaultLevel::Radioactive),
    ]
}

/// Proptest strategy producing a single [`SimOp`].
///
/// # Parameter space
///
/// - Workers: `1..=n_workers` (mapped to [`WorkerId`]).
/// - Shard keys: `(run=1, shard=1..=n_shards)` — all keys share a single
///   run, matching the single-run assumption of `CoordinationSim`.
///
/// # Weight distribution
///
/// Total weight across the 18 strategy arms (17 variants; `AdvanceTime` appears twice with different ranges) is **40**. Weights bias
/// toward ops that drive forward progress (Acquire=6, AdvanceTime=5,
/// Checkpoint=5, Complete=4) while exotic variants (Split*, Replay/Conflict
/// Checkpoint, ZombieCheckpoint) appear at weight 1 to exercise rejection
/// paths without drowning out productive state transitions.
///
/// `ZombieCheckpoint` is included at low weight despite always producing
/// `NoStaleLease` rejections when generated externally (stale leases are
/// harness-internal state). The cost is small (1/40 of ops) and ensures
/// the variant appears in all property test suites.
///
/// A fixed-150-tick `AdvanceTime` variant (weight 1) exceeds
/// `DEFAULT_LEASE_DURATION` (100), enabling lease-expiry coverage in
/// property tests. The main `AdvanceTime` (weight 5) stays at 1..=50 to
/// avoid expiring all leases every step.
pub fn arb_sim_op(n_workers: u64, n_shards: u64) -> impl Strategy<Value = SimOp> {
    let worker = (1..=n_workers).prop_map(WorkerId::from_raw);
    let key = (1..=n_shards).prop_map(|s| ShardKey::new(RunId::from_raw(1), ShardId::from_raw(s)));

    let w = worker.clone();
    let k = key.clone();
    prop_oneof![
        6 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::Acquire { worker, key }),
        // Tick range 1..=50 stays below DEFAULT_LEASE_DURATION (100) to prevent
        // a single advance from expiring all leases at once.
        5 => (1u64..=50).prop_map(|ticks| SimOp::AdvanceTime { ticks }),
        5 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::Checkpoint { worker, key }),
        4 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::Complete { worker, key }),
        3 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::Renew { worker, key }),
        2 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::SessionLifecycle { worker, key }),
        2 => w.clone().prop_map(|worker| SimOp::ClaimNext { worker }),
        2 => w.clone().prop_map(|worker| SimOp::PauseWorker { worker }),
        2 => w.clone().prop_map(|worker| SimOp::ResumeWorker { worker }),
        // Exceeds DEFAULT_LEASE_DURATION (100) to trigger lease expiry.
        1 => Just(SimOp::AdvanceTime { ticks: 150 }),
        1 => Just(SimOp::ZombieCheckpoint),
        1 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::Park { worker, key }),
        1 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::SplitReplace { worker, key }),
        1 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::SplitResidual { worker, key }),
        1 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::ReplayCheckpoint { worker, key }),
        1 => (w.clone(), k.clone()).prop_map(|(worker, key)| SimOp::ConflictCheckpoint { worker, key }),
        1 => k.clone().prop_map(|key| SimOp::Unpark { key }),
        1 => prop_oneof![
            Just(RunTerminalKind::Complete),
            Just(RunTerminalKind::Fail),
            Just(RunTerminalKind::Cancel),
        ].prop_map(|kind| SimOp::TerminateRun {
            run: RunId::from_raw(1),
            kind,
        }),
    ]
}

/// Standard test tenant used across simulation test modules.
///
/// A fixed 32-byte value (`[0x01; 32]`) chosen to be visually distinct in
/// debug output. All sim tests that need a tenant should use this constant
/// rather than constructing ad-hoc values.
pub const TENANT: TenantId = TenantId::from_bytes([0x01; 32]);

/// Standard lease duration used across simulation test modules.
///
/// Matches `DEFAULT_LEASE_DURATION` in `harness.rs` (both are 100 ticks).
/// The primary `AdvanceTime` arm in `arb_sim_op` caps ticks at 50 — half
/// this value — so that most time advances cannot expire a freshly acquired
/// lease. A secondary arm at 150 ticks exists specifically to trigger expiry.
pub const LEASE_DUR: u64 = 100;

/// Convenience constructor for [`ShardKey`] from raw integer IDs.
///
/// Wraps the three-step `RunId::from_raw` + `ShardId::from_raw` + `ShardKey::new`
/// dance into a single call, keeping test setup concise.
pub fn make_key(run: u64, shard: u64) -> ShardKey {
    ShardKey::new(RunId::from_raw(run), ShardId::from_raw(shard))
}

/// Fluent builder for [`ShardRecord`] in tests.
///
/// `ShardRecord::from_raw_parts` takes 13 positional arguments, making test
/// construction noisy and obscuring which fields matter for a given
/// assertion. This builder provides sensible defaults for every field so
/// tests only specify the fields relevant to the invariant under test:
///
/// ```rust,ignore
/// // Only status matters for this test — everything else is defaulted.
/// TestRecordBuilder::new(TENANT, run, shard)
///     .status(ShardStatus::Done)
///     .build()
/// ```
///
/// # Defaults
///
/// | Field | Default value |
/// |-------|--------------|
/// | `status` | `ShardStatus::Active` |
/// | `park_reason` | `None` |
/// | `spec` | Range `[b'a', b'z']` |
/// | `cursor` | `CursorUpdate::initial()` |
/// | `cursor_semantics` | `CursorSemantics::Completed` |
/// | `lease` | `None` (unleased) |
/// | `fence_epoch` | `FenceEpoch::INITIAL` |
/// | `parent` | `None` |
/// | `spawned` | empty spawned-child list |
/// | `op_log` | empty `RingBuffer` (always — no setter) |
///
/// # Validation bypass
///
/// [`build`](Self::build) delegates to `ShardRecord::from_raw_parts`, which
/// skips `assert_invariants()`. This is intentional: some tests construct
/// records that violate internal invariants to verify that the invariant
/// checker detects them.
///
/// # Missing setters
///
/// `cursor_semantics` and `op_log` have no setter methods. `cursor_semantics`
/// defaults to `Completed` which is correct for the vast majority of tests.
/// `op_log` is always empty because test scenarios that need specific op-log
/// entries construct records directly via `from_raw_parts`.
pub struct TestRecordBuilder {
    tenant: TenantId,
    run: RunId,
    shard: ShardId,
    status: ShardStatus,
    park_reason: Option<crate::record::ParkReason>,
    spec: ShardSpec,
    cursor_last_key: Option<Vec<u8>>,
    cursor_token: Option<Vec<u8>>,
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
            cursor_last_key: None,
            cursor_token: None,
            cursor_semantics: CursorSemantics::Completed,
            lease: None,
            fence_epoch: FenceEpoch::INITIAL,
            parent: None,
            spawned: Vec::new(),
        }
    }

    /// Override the shard status (default: `Active`).
    pub fn status(mut self, status: ShardStatus) -> Self {
        self.status = status;
        self
    }

    /// Set the park reason, wrapping the value in `Some`.
    ///
    /// Only meaningful when `status` is `Parked`; calling this with an
    /// `Active` status produces an intentionally invalid record (useful
    /// for invariant-violation tests).
    pub fn park_reason(mut self, reason: crate::record::ParkReason) -> Self {
        self.park_reason = Some(reason);
        self
    }

    /// Override the shard spec (default: range `[b'a', b'z']`).
    pub fn spec(mut self, spec: ShardSpec) -> Self {
        self.spec = spec;
        self
    }

    /// Override the cursor position (default: `CursorUpdate::initial()`).
    pub fn cursor(mut self, cursor: CursorUpdate<'_>) -> Self {
        self.cursor_last_key = cursor.last_key().map(ToOwned::to_owned);
        self.cursor_token = cursor.token().map(ToOwned::to_owned);
        self
    }

    /// Attach a lease holder, wrapping the value in `Some`.
    ///
    /// By default the record is unleased (`None`). Attaching a lease to a
    /// terminal-status record produces an intentionally invalid record.
    pub fn lease(mut self, lease: LeaseHolder) -> Self {
        self.lease = Some(lease);
        self
    }

    /// Override the fence epoch (default: `FenceEpoch::INITIAL`).
    pub fn fence_epoch(mut self, epoch: FenceEpoch) -> Self {
        self.fence_epoch = epoch;
        self
    }

    /// Set the parent shard, wrapping the value in `Some`.
    pub fn parent(mut self, parent: ShardId) -> Self {
        self.parent = Some(parent);
        self
    }

    /// Set the spawned children list (default: empty).
    ///
    /// Accepts any iterator over `ShardId` values or references so test code
    /// does not depend on the production spawned-list storage type.
    pub fn spawned<I, S>(mut self, spawned: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Borrow<ShardId>,
    {
        self.spawned = spawned.into_iter().map(|id| *id.borrow()).collect();
        self
    }

    /// Consume the builder and produce a [`ShardRecord`].
    ///
    /// Delegates to `from_raw_parts`, bypassing invariant validation so
    /// tests can construct intentionally invalid records.
    pub fn build(self, slab: &mut ByteSlab) -> ShardRecord {
        let cursor = match (
            self.cursor_last_key.as_deref(),
            self.cursor_token.as_deref(),
        ) {
            (None, _) => CursorUpdate::initial(),
            (Some(last_key), None) => CursorUpdate::with_last_key(last_key),
            (Some(last_key), Some(token)) => CursorUpdate::with_token(last_key, token),
        };
        ShardRecord::from_raw_parts(
            self.tenant,
            self.run,
            self.shard,
            self.status,
            self.park_reason,
            &self.spec,
            cursor,
            self.cursor_semantics,
            self.lease,
            self.fence_epoch,
            self.parent,
            self.spawned.into_iter().collect(),
            RingBuffer::new(),
            slab,
        )
    }
}
