use std::fmt;

use crate::config::{
    DEFAULT_BOOTSTRAP_LEASE_DURATION, DEFAULT_CONNECT_TIMEOUT, EtcdCoordinatorConfig,
};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationBackend, CreateRunError, CursorUpdate, GetRunError, IdempotentOutcome,
    InMemoryCoordinator, InitialShardInput, Lease, LogicalTime, OpId, ParkError, ParkReason,
    RegisterShardsError, RenewError, RenewResult, RunConfig, RunId, RunManagement, RunProgress,
    RunRecord, RunTransitionError, ShardClaiming, ShardFilter, ShardId, ShardKey, ShardSummary,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError, SplitResidualPlan,
    SplitResidualResult, TenantId, UnparkError, WorkerId,
};

/// etcd-backed coordination backend.
///
/// Implements [`CoordinationBackend`], [`RunManagement`], and
/// [`ShardClaiming`] against a live etcd cluster connection.
///
/// # Security
///
/// TLS and authentication are not yet wired into the connection path.
/// All traffic is plaintext gRPC over TCP. **Do not deploy this backend
/// against non-localhost etcd endpoints** until TLS certificate paths
/// and auth credentials are plumbed through [`EtcdCoordinatorConfig`]
/// into [`etcd_client::ConnectOptions`].
///
/// # Delegation architecture
///
/// All protocol semantics (shard lifecycle, run lifecycle, idempotency,
/// lease fencing) are **delegated** to an embedded
/// [`InMemoryCoordinator`]. The etcd connection is established and
/// health-checked at construction time, but shard and run state lives
/// entirely in process memory.
///
/// **Implication:** state is lost on process restart. The delegation model
/// provides a correct, test-covered trait surface while the etcd keyspace
/// layout, record codecs, and transactional write protocol are developed
/// in parallel.
///
/// # Threading and async
///
/// The coordination traits are synchronous. The upstream `etcd-client`
/// crate is async (tonic/gRPC). A private current-thread Tokio runtime
/// bridges the gap by driving async RPCs from sync trait methods. Callers
/// must not invoke trait methods from within an existing Tokio async
/// context (nested `block_on` panics).
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    /// Current-thread Tokio runtime that bridges the sync coordination
    /// traits to the async etcd client. See [struct-level docs](Self)
    /// for threading constraints.
    runtime: tokio::runtime::Runtime,
    /// Live gRPC connection to the etcd cluster. Used for health-check
    /// (`status()`). Coordination traffic uses the in-memory delegate.
    client: etcd_client::Client,
    /// Holds all shard/run state in memory. Every trait method delegates here.
    protocol_delegate: InMemoryCoordinator,
}

impl EtcdCoordinator {
    /// Connect to etcd and return a ready-to-use backend.
    ///
    /// Performs a two-phase fail-fast initialization:
    ///
    /// 1. **gRPC connect** — establishes a channel to the etcd cluster with a
    ///    5-second connect timeout.
    /// 2. **Status probe** — round-trips a maintenance `Status` RPC to
    ///    confirm the cluster is reachable and responsive.
    ///
    /// Config validation is performed by the [`EtcdCoordinatorConfig`]
    /// constructors (`new`, `from_endpoints_csv`, `localhost`), so the
    /// `config` argument is guaranteed valid on entry.
    ///
    /// On success the caller is guaranteed a validated config, a live etcd
    /// connection, and a fully initialized in-memory protocol delegate
    /// (bootstrapped with the default lease duration).
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError::RuntimeBuild`] if the Tokio runtime
    /// cannot be created, or [`EtcdCoordinatorError::Etcd`] if the connect
    /// or status probe fails (including connect timeout).
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;

        let endpoints = config.endpoints().to_vec();
        let connect_opts =
            etcd_client::ConnectOptions::new().with_connect_timeout(DEFAULT_CONNECT_TIMEOUT);

        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "connect() must not be called from within an active Tokio runtime"
        );

        let mut client = runtime
            .block_on(etcd_client::Client::connect(endpoints, Some(connect_opts)))
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

    /// Round-trip a maintenance `Status` RPC against the etcd cluster.
    ///
    /// Returns the upstream [`etcd_client::StatusResponse`] as a
    /// point-in-time health snapshot of the connected member.
    /// Useful as a liveness probe or for operator-facing diagnostics.
    ///
    /// # Client clone
    ///
    /// `etcd_client::Client::status()` takes `&mut self` (it mutates
    /// internal gRPC state). To keep this method callable through `&self`,
    /// we clone the `Client` handle — which is cheap because `Client`
    /// wraps tonic `Channel` handles that share the underlying HTTP/2
    /// connection.
    ///
    /// # Panics
    ///
    /// Panics (in debug builds) if called from within an active Tokio
    /// async context (nested `block_on` is not supported by Tokio). This
    /// method — and all coordination trait methods — must be called from
    /// synchronous code only. See the [struct-level docs](Self) for
    /// details.
    pub fn status(&self) -> Result<etcd_client::StatusResponse, EtcdCoordinatorError> {
        debug_assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "status() must not be called from within an active Tokio runtime"
        );
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })
    }
}

/// Custom [`Debug`] output. Omits the etcd `Client` (which does not
/// implement `Debug`) and the Tokio runtime (internal plumbing). Shows
/// endpoint count (not raw URIs — they may contain credentials), the
/// namespace prefix, and a note about the current delegation storage mode.
impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.config.namespace_prefix())
            .field(
                "coordination_storage_mode",
                &"delegated to InMemoryCoordinator",
            )
            .finish()
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
// Once delegation is replaced by real etcd RPCs, every method here will go
// through `self.runtime.block_on()`, adding network round-trip latency.
// Callers on hot paths should account for that cost.

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
