use std::fmt;

use crate::config::{DEFAULT_BOOTSTRAP_LEASE_DURATION, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use crate::runtime::SyncRuntime;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CheckpointError, CompleteError,
    CoordinationBackend, CreateRunError, CursorUpdate, GetRunError, IdempotentOutcome,
    InMemoryCoordinator, InitialShardInput, Lease, LogicalTime, OpId, ParkError, ParkReason,
    RegisterShardsError, RenewError, RenewResult, RunConfig, RunId, RunManagement, RunProgress,
    RunRecord, RunTransitionError, ShardFilter, ShardId, ShardKey, ShardSummary,
    SplitReplaceError, SplitReplacePlan, SplitReplaceResult, SplitResidualError,
    SplitResidualPlan, SplitResidualResult, TenantId, UnparkError, WorkerId,
};

/// A single-member status snapshot returned by `etcd status`.
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

/// etcd coordination backend scaffold.
///
/// B0/B1 responsibilities:
/// - own a real etcd client connection,
/// - expose the final backend type and trait impl surface,
/// - define the deterministic keyspace and record codecs.
///
/// Actual persistence-backed coordination protocol semantics are deferred to
/// later Epic B items. Until then, the trait implementation delegates to the
/// executable reference backend (`InMemoryCoordinator`) so the crate can build,
/// wire into tests, and adopt the final types without lying about durability.
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    keyspace: EtcdKeyspace,
    runtime: SyncRuntime,
    client: etcd_client::Client,
    protocol_delegate: InMemoryCoordinator,
}

impl EtcdCoordinator {
    /// Connect to etcd, verify connectivity with `status`, and create the
    /// scaffold backend.
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;
        let keyspace = EtcdKeyspace::new(config.namespace_prefix().to_owned())?;

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
            keyspace,
            runtime,
            client,
            protocol_delegate: InMemoryCoordinator::new(DEFAULT_BOOTSTRAP_LEASE_DURATION),
        })
    }

    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        self.config.endpoints()
    }

    #[must_use]
    pub fn namespace_prefix(&self) -> &str {
        self.config.namespace_prefix()
    }

    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    /// Round-trip a maintenance `status` request against etcd.
    pub fn status(&self) -> Result<EtcdEndpointStatus, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        let response = self
            .runtime
            .block_on(async move { client.status().await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })?;
        Ok(response.into())
    }
}

impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoints", &self.config.endpoints())
            .field("namespace_prefix", &self.config.namespace_prefix())
            .field("keyspace", &self.keyspace)
            .field(
                "coordination_storage_mode",
                &"B0/B1 bootstrap: protocol semantics delegated to InMemoryCoordinator until etcd txn backend lands",
            )
            .finish_non_exhaustive()
    }
}

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
