use std::fmt;

use crate::config::{DEFAULT_BOOTSTRAP_LEASE_DURATION, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::runtime::SyncRuntime;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationBackend, CreateRunError, CursorUpdate, GetRunError, IdempotentOutcome,
    InMemoryCoordinator, InitialShardInput, Lease, LogicalTime, OpId, ParkError, ParkReason,
    RegisterShardsError, RenewError, RenewResult, RunConfig, RunId, RunManagement, RunProgress,
    RunRecord, RunTransitionError, ShardClaiming, ShardFilter, ShardId, ShardKey, ShardSummary,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult, TenantId, UnparkError, WorkerId,
};

/// Health snapshot of a single etcd cluster member, returned by the
/// maintenance `Status` RPC.
///
/// Useful for liveness probes, operator dashboards, and diagnosing cluster
/// issues (e.g., a member falling behind on Raft apply, or a leader change
/// during a network partition).
///
/// # Fields
///
/// | Field | Meaning |
/// |---|---|
/// | `version` | etcd server version string (e.g. `"3.5.12"`). |
/// | `db_size` | Total on-disk size of the member's backend store (bytes). |
/// | `raft_used_db_size` | Portion of `db_size` actually in use by the backend store (defrag reclaims the gap). |
/// | `leader` | Member ID of the current Raft leader (`0` if no leader is elected). |
/// | `raft_index` | Latest Raft log index the member is aware of. |
/// | `raft_term` | Current Raft election term. |
/// | `raft_applied_index` | Highest Raft log index the member has applied to its state machine. A gap between `raft_index` and `raft_applied_index` indicates the member is catching up. |
/// | `errors` | Alarm strings reported by this member (e.g. `NOSPACE`). Empty when healthy. |
/// | `is_learner` | Whether this member is a non-voting learner (cannot become leader). |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EtcdEndpointStatus {
    pub version: String,
    pub db_size: i64,
    pub raft_used_db_size: i64,
    pub leader: u64,
    pub raft_index: u64,
    pub raft_term: u64,
    pub raft_applied_index: u64,
    pub errors: Vec<String>,
    pub is_learner: bool,
}

impl From<etcd_client::StatusResponse> for EtcdEndpointStatus {
    fn from(value: etcd_client::StatusResponse) -> Self {
        Self {
            version: value.version().to_owned(),
            db_size: value.db_size(),
            raft_used_db_size: value.raft_used_db_size(),
            leader: value.leader(),
            raft_index: value.raft_index(),
            raft_term: value.raft_term(),
            raft_applied_index: value.raft_applied_index(),
            errors: value.errors().to_vec(),
            is_learner: value.is_learner(),
        }
    }
}

/// etcd-backed coordination backend.
///
/// Implements [`CoordinationBackend`], [`RunManagement`], and
/// [`ShardClaiming`] against a live etcd cluster connection.
///
/// # Delegation architecture
///
/// All protocol semantics (shard lifecycle, run lifecycle, idempotency,
/// lease fencing) are currently **delegated** to an embedded
/// [`InMemoryCoordinator`]. The etcd connection is established and
/// health-checked at construction time, but shard and run state lives
/// entirely in process memory.
///
/// **Implication:** state is lost on process restart. This is intentional —
/// the delegation model lets the etcd integration crate ship a correct,
/// test-covered trait surface immediately while the etcd keyspace layout,
/// record codecs, and transactional write protocol are developed
/// separately. Once those land, each trait method will be replaced with
/// real etcd transactions; the `protocol_delegate` field will be removed.
///
/// # Threading and async
///
/// The coordination traits are synchronous. The upstream `etcd-client`
/// crate is async (tonic/gRPC). A private `SyncRuntime` bridges the
/// gap via a current-thread Tokio runtime that drives async RPCs from
/// sync trait methods. Callers must not invoke trait methods from within
/// an existing Tokio async context (nested `block_on` panics).
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    runtime: SyncRuntime,
    /// Live gRPC connection to the etcd cluster. Currently used only for
    /// health-check (`status()`); will carry all coordination traffic once
    /// the transactional protocol is implemented.
    client: etcd_client::Client,
    /// Holds all shard/run state in memory. Every trait method forwards
    /// here today; will be replaced by etcd read/write transactions.
    protocol_delegate: InMemoryCoordinator,
}

impl EtcdCoordinator {
    /// Connect to etcd and return a ready-to-use backend.
    ///
    /// Performs a three-phase fail-fast initialization:
    ///
    /// 1. **Config validation** — rejects empty endpoints, malformed namespace
    ///    prefixes, etc. before any I/O.
    /// 2. **gRPC connect** — establishes a channel to the etcd cluster.
    /// 3. **Status probe** — round-trips a maintenance `Status` RPC to
    ///    confirm the cluster is reachable and responsive.
    ///
    /// On success the caller is guaranteed a validated config, a live etcd
    /// connection, and a fully initialized in-memory protocol delegate
    /// (bootstrapped with the default lease duration).
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError::Config`] for invalid configuration,
    /// [`EtcdCoordinatorError::RuntimeBuild`] if the Tokio runtime cannot
    /// be created, or [`EtcdCoordinatorError::Etcd`] if the connect or
    /// status probe fails.
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;

        let runtime = SyncRuntime::new()?;
        let endpoints = config.endpoints().to_vec();
        let mut client = runtime
            .block_on(etcd_client::Client::connect(endpoints, None))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Connect,
                source,
            })?;

        runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })?;

        Ok(Self {
            config,
            runtime,
            client,
            protocol_delegate: InMemoryCoordinator::new(DEFAULT_BOOTSTRAP_LEASE_DURATION),
        })
    }

    /// Return the validated configuration used to construct this backend.
    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    /// Return the configured etcd endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        self.config.endpoints()
    }

    /// Return the namespace prefix used as the etcd keyspace root.
    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        self.config.namespace_prefix()
    }

    /// Round-trip a maintenance `Status` RPC against the etcd cluster.
    ///
    /// Returns a point-in-time health snapshot of the connected member.
    /// Useful as a liveness probe or for operator-facing diagnostics.
    ///
    /// # Client clone
    ///
    /// `etcd_client::Client::status()` takes `&mut self` (it mutates
    /// internal gRPC state). To keep this method callable through `&self`,
    /// we clone the `Client` handle — which is cheap because `Client`
    /// wraps tonic `Channel` handles that share the underlying HTTP/2
    /// connection.
    pub fn status(&self) -> Result<EtcdEndpointStatus, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        let response = self.runtime.block_on(client.status()).map_err(|source| {
            EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            }
        })?;
        Ok(response.into())
    }
}

/// Custom [`Debug`] output. Omits the etcd `Client` (which does not
/// implement `Debug`) and the `SyncRuntime` (internal plumbing). Shows
/// the config fields and a note about the current delegation storage mode.
impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoints", &self.config.endpoints())
            .field("namespace_prefix", &self.config.namespace_prefix())
            .field(
                "coordination_storage_mode",
                &"delegated to InMemoryCoordinator until etcd keyspace/codec lands",
            )
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Trait delegation — shard lifecycle
// ---------------------------------------------------------------------------
//
// Every method below is a direct forwarding call to `self.protocol_delegate`
// (an `InMemoryCoordinator`). All protocol semantics — lease granting,
// fencing, idempotency dedup, cursor persistence, split logic — are defined
// and tested in `gossip-coordination`. This impl adds no additional behavior.
//
// When the etcd transactional write protocol lands, each method will be
// replaced with: (1) read current shard state from etcd, (2) apply the
// protocol logic, (3) write back via an etcd `Txn` with a compare guard.
// The method signatures and error types will remain unchanged.

impl CoordinationBackend for EtcdCoordinator {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, AcquireError> {
        self.protocol_delegate
            .acquire_and_restore_into(now, tenant, key, worker, out)
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        self.protocol_delegate.renew(now, tenant, lease)
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        self.protocol_delegate
            .checkpoint(now, tenant, lease, new_cursor, op_id)
    }

    fn complete(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        final_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.protocol_delegate
            .complete(now, tenant, lease, final_cursor, op_id)
    }

    fn park_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        reason: ParkReason,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.protocol_delegate
            .park_shard(now, tenant, lease, reason, op_id)
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.protocol_delegate
            .split_replace(now, tenant, lease, plan, op_id)
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        self.protocol_delegate
            .split_residual(now, tenant, lease, plan, op_id)
    }
}

// ---------------------------------------------------------------------------
// Trait delegation — run lifecycle
// ---------------------------------------------------------------------------
//
// Same delegation pattern as `CoordinationBackend` above: every method
// forwards to `InMemoryCoordinator`. Run creation, shard registration,
// progress queries, and terminal transitions (complete/fail/cancel) all
// carry their full semantics from the reference implementation. Most
// mutating methods accept `OpId` for idempotency (`create_run` is the
// exception — it is inherently non-idempotent); the in-memory delegate
// enforces dedup via a bounded op-log on each `RunRecord`.

impl RunManagement for EtcdCoordinator {
    fn create_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        config: RunConfig,
    ) -> Result<RunRecord, CreateRunError> {
        self.protocol_delegate.create_run(now, tenant, run, config)
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        self.protocol_delegate
            .register_shards(now, tenant, run, shards, op_id)
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        self.protocol_delegate.get_run(tenant, run)
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        self.protocol_delegate.get_run_progress(now, tenant, run)
    }

    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        self.protocol_delegate
            .list_shards_into(now, tenant, run, filter, out)
    }

    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        self.protocol_delegate
            .collect_claim_candidates_into(now, tenant, run, candidates)
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.protocol_delegate.complete_run(now, tenant, run, op_id)
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.protocol_delegate.fail_run(now, tenant, run, op_id)
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.protocol_delegate.cancel_run(now, tenant, run, op_id)
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        self.protocol_delegate.unpark_shard(now, tenant, key, op_id)
    }
}

// ---------------------------------------------------------------------------
// Trait delegation — shard claiming
// ---------------------------------------------------------------------------
//
// `ShardClaiming` extends `CoordinationBackend + RunManagement` (they are
// its supertraits). `claim_next_available` queries run state for claimable
// shards, then acquires one — both steps delegated to the in-memory
// coordinator.

impl ShardClaiming for EtcdCoordinator {
    fn claim_next_available<'a>(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        out: &'a mut AcquireScratch,
    ) -> Result<AcquireResultView<'a>, ClaimError> {
        self.protocol_delegate
            .claim_next_available(now, tenant, run, worker, out)
    }
}
