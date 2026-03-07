use std::collections::HashMap;
use std::fmt;

use crate::codec::{
    EtcdCodecError, OwnerLeaseValueV1, decode_owner_value_v1, decode_run_record_v1,
    decode_shard_record_v1, encode_owner_value_v1, encode_run_record_v1, encode_shard_record_v1,
};
use crate::config::EtcdCoordinatorConfig;
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use crate::runtime::SyncRuntime;
use etcd_client::{Compare, CompareOp, DeleteOptions, GetOptions, PutOptions, Txn, TxnOp};
use gossip_contracts::coordination::limits::{MAX_SPLIT_CHILDREN, MAX_SPAWNED_PER_SHARD};
use gossip_contracts::coordination::shard_spec::{
    ShardSpec, SplitValidationError, validate_residual_split_bounds,
};
use gossip_coordination::validation::validate_cursor_update_pooled;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CapacityHint, CheckpointError,
    CompleteError, CoordinationBackend, CreateRunError, CursorUpdate, DerivedShardKind,
    FenceEpoch, GetRunError, IdempotentOutcome, InitialShardInput, Lease, LeaseHolder,
    LogicalTime, OpId, OpKind, OpLogEntry, OpResult, ParkError, ParkReason,
    RegisterShardsError, RenewError, RenewResult, RunConfig, RunId, RunManagement,
    RunOpKind, RunOpLogEntry, RunOpResult, RunProgress, RunRecord, RunStatus,
    RunTransitionError, ShardFilter, ShardId, ShardKey, ShardRecord, ShardStatus,
    ShardSummary, SplitReplaceChild, SplitReplaceError, SplitReplacePlan, SplitReplaceResult,
    SplitResidualError, SplitResidualPlan, SplitResidualResult, TenantId, UnparkError, WorkerId,
    check_op_idempotency, derive_split_shard_id, hash_cancel_run_payload,
    hash_checkpoint_payload, hash_complete_run_payload, hash_fail_run_payload,
    hash_register_shards_payload, hash_split_replace_payload, hash_split_residual_payload,
    hash_unpark_payload, validate_lease, validate_manifest,
};
use gossip_stdx::{ByteSlab, InlineVec, RingBuffer};

const MIN_DECODE_SLAB_CAPACITY: usize = 4 * 1024;
const MAX_DECODE_SLAB_CAPACITY: usize = 256 * 1024;
const DEFAULT_BUILD_SLAB_FLOOR: usize = 1024;


type SplitChildIds = InlineVec<ShardId, { MAX_SPLIT_CHILDREN }>;

const _: () = assert!(MAX_SPLIT_CHILDREN <= u16::MAX as usize);

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

fn split_replace_sort_children<'a>(plan: &'a SplitReplacePlan<'a>) -> SplitChildOrder {
    SplitChildOrder::from_plan(plan)
}

fn split_replace_replay_child_ids(
    parent: &ShardRecord,
    plan: &SplitReplacePlan<'_>,
    op_id: OpId,
) -> SplitChildIds {
    let sorted = split_replace_sort_children(plan);
    let n = sorted.len();
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

fn split_replace_validate_preconditions<'a>(
    parent: &ShardRecord,
    plan: &'a SplitReplacePlan<'a>,
    slab: &ByteSlab,
    max_children_per_op: usize,
) -> Result<SplitChildOrder, SplitReplaceError> {
    let sorted = split_replace_sort_children(plan);

    if sorted.len() > max_children_per_op {
        return Err(SplitReplaceError::SplitInvalid(
            SplitValidationError::BackendChildLimitExceeded {
                count: sorted.len(),
                max: max_children_per_op,
            },
        ));
    }

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

fn split_residual_check_replay(
    parent: &ShardRecord,
    op_id: OpId,
    payload_hash: u64,
    slab: &ByteSlab,
) -> Result<Option<IdempotentOutcome<SplitResidualResult>>, SplitResidualError> {
    if check_op_idempotency(parent, op_id, payload_hash)?.is_some() {
        let replayed = find_replayed_residual(parent, op_id, slab).expect(
            "op-log hit for split_residual implies residual exists in parent.spawned;              missing entry indicates a coordinator bug",
        );
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: replayed,
        })));
    }

    if let Some(existing) = find_replayed_residual(parent, op_id, slab) {
        return Ok(Some(IdempotentOutcome::Replayed(SplitResidualResult {
            residual: existing,
        })));
    }

    Ok(None)
}

fn split_residual_validate_preconditions(
    now: LogicalTime,
    tenant: TenantId,
    lease: &Lease,
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    slab: &ByteSlab,
) -> Result<(), SplitResidualError> {
    validate_lease(now, tenant, lease, parent)?;

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
    split_residual_validate_cursor_bounds(parent, plan, slab)?;
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

fn split_residual_validate_cursor_bounds(
    parent: &ShardRecord,
    plan: &SplitResidualPlan<'_>,
    slab: &ByteSlab,
) -> Result<(), SplitResidualError> {
    if let Some(k) = parent.cursor.last_key(slab)
        && !plan.parent_new_spec().contains_key(k)
    {
        return Err(SplitResidualError::SplitInvalid(
            SplitValidationError::ParentCursorOutOfBounds {
                cursor: k.len(),
                new_parent_start: plan.parent_new_spec().key_range_start().len(),
                new_parent_end: plan.parent_new_spec().key_range_end().len(),
            },
        ));
    }
    Ok(())
}

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

fn split_residual_apply_parent(
    parent: &mut ShardRecord,
    new_spec: gossip_contracts::coordination::ShardSpecRef<'_>,
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

fn parse_direct_run_id_from_key(
    prefix: &str,
    key: &[u8],
) -> Result<Option<RunId>, EtcdCoordinatorError> {
    let key = core::str::from_utf8(key).map_err(|_| EtcdCoordinatorError::Codec {
        operation: EtcdOperation::Get,
        source: EtcdCodecError::InvariantViolation {
            kind: "Keyspace",
            detail: "etcd key is not valid UTF-8",
        },
    })?;

    let Some(rest) = key.strip_prefix(prefix) else {
        return Err(EtcdCoordinatorError::Codec {
            operation: EtcdOperation::Get,
            source: EtcdCodecError::InvariantViolation {
                kind: "Keyspace",
                detail: "prefix scan returned a key outside the requested prefix",
            },
        });
    };
    let Some(rest) = rest.strip_prefix('/') else {
        return Ok(None);
    };
    if rest.contains('/') {
        return Ok(None);
    }
    if rest.len() != 16 {
        return Err(EtcdCoordinatorError::Codec {
            operation: EtcdOperation::Get,
            source: EtcdCodecError::InvariantViolation {
                kind: "Keyspace",
                detail: "direct run key must end in exactly 16 lowercase hex chars",
            },
        });
    }
    let raw = u64::from_str_radix(rest, 16).map_err(|_| EtcdCoordinatorError::Codec {
        operation: EtcdOperation::Get,
        source: EtcdCodecError::InvariantViolation {
            kind: "Keyspace",
            detail: "direct run key suffix is not valid lowercase hex",
        },
    })?;
    Ok(Some(RunId::from_raw(raw)))
}


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

#[derive(Debug)]
struct PersistedRun {
    record: RunRecord,
    mod_revision: i64,
}

#[derive(Clone, Debug)]
struct PersistedOwner {
    binding: OwnerLeaseValueV1,
    lease_id: i64,
    mod_revision: i64,
}

#[derive(Debug)]
struct PersistedShard {
    record: ShardRecord,
    slab: ByteSlab,
    mod_revision: i64,
    owner: Option<PersistedOwner>,
}

impl PersistedShard {
    fn owner_is_live_at(&self, now: LogicalTime) -> bool {
        self.owner.is_some()
            && self
                .record
                .lease_deadline()
                .is_some_and(|deadline| now < deadline)
    }

    fn expected_owner_value(&self) -> Option<Vec<u8>> {
        self.owner
            .as_ref()
            .map(|owner| encode_owner_value_v1(owner.binding.worker, owner.binding.fence))
    }

    fn owner_matches_lease(&self, lease: &Lease) -> bool {
        self.owner.as_ref().is_some_and(|owner| {
            owner.binding.worker == lease.owner() && owner.binding.fence == lease.fence()
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum EtcdTestFault {
    /// Delete the parent shard's ephemeral owner key immediately before the
    /// next `split_replace` txn commits. The etcd txn must then abort and
    /// publish no partial child set.
    DropOwnerBeforeNextSplitReplaceTxn,
    /// Delete the parent shard's ephemeral owner key immediately before the
    /// next `split_residual` txn commits. The etcd txn must then abort and
    /// publish no partial residual shard.
    DropOwnerBeforeNextSplitResidualTxn,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct EtcdTestFaultState {
    drop_owner_before_next_split_replace_txn: bool,
    drop_owner_before_next_split_residual_txn: bool,
}

/// etcd coordination backend.
///
/// B2 scope:
/// - B0/B1 scaffold (connection, keyspace, codecs),
/// - run creation / shard registration and read-side queries required to
///   exercise persisted state,
/// - acquire / renew / checkpoint executed against etcd with storage-layer
///   fencing and owner keys attached to real etcd leases.
///
/// Out-of-scope mutating operations after B3:
/// - `complete`
/// - `park_shard`
/// - run terminal transitions
/// - `unpark_shard`
///
/// Acquire / renew / checkpoint / split_replace / split_residual are persisted
/// in etcd with fenced transactions.
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    keyspace: EtcdKeyspace,
    runtime: SyncRuntime,
    client: etcd_client::Client,
    #[cfg(any(test, feature = "test-support"))]
    test_faults: EtcdTestFaultState,
}

impl EtcdCoordinator {
    /// Connect to etcd, verify connectivity with `status`, and create the backend.
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
            #[cfg(any(test, feature = "test-support"))]
            test_faults: EtcdTestFaultState::default(),
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

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_arm_fault(&mut self, fault: EtcdTestFault) {
        match fault {
            EtcdTestFault::DropOwnerBeforeNextSplitReplaceTxn => {
                self.test_faults.drop_owner_before_next_split_replace_txn = true;
            }
            EtcdTestFault::DropOwnerBeforeNextSplitResidualTxn => {
                self.test_faults.drop_owner_before_next_split_residual_txn = true;
            }
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn maybe_drop_owner_before_split_replace_txn(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<(), EtcdCoordinatorError> {
        if !self.test_faults.drop_owner_before_next_split_replace_txn {
            return Ok(());
        }
        self.test_faults.drop_owner_before_next_split_replace_txn = false;
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        self.etcd_delete(owner_key, None)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    fn maybe_drop_owner_before_split_residual_txn(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<(), EtcdCoordinatorError> {
        if !self.test_faults.drop_owner_before_next_split_residual_txn {
            return Ok(());
        }
        self.test_faults.drop_owner_before_next_split_residual_txn = false;
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        self.etcd_delete(owner_key, None)?;
        Ok(())
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

    fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "EtcdCoordinator {operation} is not implemented in Epic B2; \
             later Epic B items must persist this operation in etcd before it is callable"
        );
    }

    fn fatal_storage_error<T>(&self, context: &'static str, err: impl fmt::Display) -> T {
        panic!("etcd coordination backend {context} failed: {err}");
    }

    fn make_decode_slab(blob_len: usize) -> ByteSlab {
        let cap = blob_len
            .saturating_mul(4)
            .clamp(MIN_DECODE_SLAB_CAPACITY, MAX_DECODE_SLAB_CAPACITY);
        ByteSlab::with_capacity(cap)
    }

    fn build_slab_capacity_for_initial_shard(input: &InitialShardInput<'_>) -> usize {
        Self::build_slab_capacity_for_initial_shard_bytes(input.spec(), input.cursor())
    }

    fn build_slab_capacity_for_initial_shard_bytes(
        spec: gossip_contracts::coordination::ShardSpecRef<'_>,
        cursor: CursorUpdate<'_>,
    ) -> usize {
        let cursor_last = cursor.last_key().map_or(0, |k| k.len());
        let cursor_token = cursor.token().map_or(0, |t| t.len());
        let needed = spec.key_range_start().len()
            + spec.key_range_end().len()
            + spec.metadata().len()
            + cursor_last
            + cursor_token
            + 256;
        needed.max(DEFAULT_BUILD_SLAB_FLOOR)
    }

    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.get(key, options).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Get,
                source,
            })
    }

    fn etcd_put(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        options: Option<PutOptions>,
    ) -> Result<etcd_client::PutResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.put(key, value, options).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Put,
                source,
            })
    }

    fn etcd_delete(
        &self,
        key: Vec<u8>,
        options: Option<DeleteOptions>,
    ) -> Result<etcd_client::DeleteResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.delete(key, options).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Delete,
                source,
            })
    }

    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.txn(txn).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.lease_grant(ttl, None).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move {
                let (mut keeper, _stream) = client.lease_keep_alive(lease_id).await?;
                keeper.keep_alive().await?;
                Ok::<(), etcd_client::Error>(())
            })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })
    }

    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move { client.lease_revoke(lease_id).await })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

    fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(tenant, run).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let record = decode_run_record_v1(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
            operation: EtcdOperation::Get,
            source,
        })?;
        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    fn decode_owner_binding(
        &self,
        operation: EtcdOperation,
        bytes: &[u8],
    ) -> Result<OwnerLeaseValueV1, EtcdCoordinatorError> {
        decode_owner_value_v1(bytes).map_err(|source| EtcdCoordinatorError::Codec {
            operation,
            source,
        })
    }

    fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(shard_record_key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };

        let mut slab = Self::make_decode_slab(kv.value().len());
        let record = decode_shard_record_v1(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;
        let mod_revision = kv.mod_revision();

        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        let owner_response = self.etcd_get(owner_key, None)?;
        let owner = match owner_response.kvs().first() {
            None => None,
            Some(owner_kv) => {
                let binding = self.decode_owner_binding(EtcdOperation::Get, owner_kv.value())?;
                if owner_kv.lease() == 0 {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "OwnerKey",
                            detail: "owner key must be attached to a non-zero etcd lease",
                        },
                    });
                }
                Some(PersistedOwner {
                    binding,
                    lease_id: owner_kv.lease(),
                    mod_revision: owner_kv.mod_revision(),
                })
            }
        };

        if let Some(owner) = &owner {
            let Some(holder) = record.lease() else {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "owner key exists but shard record lease is None",
                    },
                });
            };
            if holder.owner() != owner.binding.worker || record.fence_epoch != owner.binding.fence {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "owner key binding disagrees with shard record lease or fence",
                    },
                });
            }
        }

        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision,
            owner,
        }))
    }

    fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self.keyspace.shard_records_scan_prefix(tenant, run).into_bytes();
        let response = self.etcd_get(prefix, Some(GetOptions::new().with_prefix()))?;

        let mut owner_map = HashMap::<Vec<u8>, PersistedOwner>::new();
        let mut record_kvs = Vec::<(Vec<u8>, Vec<u8>, i64)>::new();

        for kv in response.kvs() {
            if kv.key().ends_with(b"/owner") {
                let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
                if kv.lease() == 0 {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "OwnerKey",
                            detail: "owner key must be attached to a non-zero etcd lease",
                        },
                    });
                }
                owner_map.insert(
                    kv.key().to_vec(),
                    PersistedOwner {
                        binding,
                        lease_id: kv.lease(),
                        mod_revision: kv.mod_revision(),
                    },
                );
            } else {
                record_kvs.push((kv.key().to_vec(), kv.value().to_vec(), kv.mod_revision()));
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = Self::make_decode_slab(value.len());
            let record = decode_shard_record_v1(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;
            let mut owner_key = record_key.clone();
            owner_key.extend_from_slice(b"/owner");
            let owner = owner_map.remove(&owner_key);

            if let Some(owner) = &owner {
                let Some(holder) = record.lease() else {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "ShardRecord",
                            detail: "owner key exists but shard record lease is None",
                        },
                    });
                };
                if holder.owner() != owner.binding.worker
                    || record.fence_epoch != owner.binding.fence
                {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "ShardRecord",
                            detail: "owner key binding disagrees with shard record lease or fence",
                        },
                    });
                }
            }

            out.push(PersistedShard {
                record,
                slab,
                mod_revision,
                owner,
            });
        }

        if !owner_map.is_empty() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "OwnerKey",
                    detail: "owner key exists without a corresponding shard record",
                },
            });
        }

        Ok(out)
    }

    fn visible_record_at(persisted: &PersistedShard, now: LogicalTime) -> ShardRecord {
        let mut record = persisted.record.clone();
        if !persisted.owner_is_live_at(now) {
            record.lease = None;
        }
        record
    }

    fn count_available_for_run(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let shards = self.scan_run_shards(tenant, run)?;
        let mut available_count: u32 = 0;
        let mut earliest_deadline: Option<LogicalTime> = None;

        for shard in &shards {
            if shard.record.status != ShardStatus::Active {
                continue;
            }
            if shard.owner_is_live_at(now) {
                let deadline = shard
                    .record
                    .lease_deadline()
                    .expect("live owner must imply a logical lease deadline");
                earliest_deadline = Some(match earliest_deadline {
                    Some(prev) => core::cmp::min(prev, deadline),
                    None => deadline,
                });
            } else {
                available_count = available_count.saturating_add(1);
            }
        }

        Ok(CapacityHint {
            available_count,
            earliest_deadline,
        })
    }

    fn compare_shard_revision(shard_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(shard_record_key, CompareOp::Equal, mod_revision)
    }

    fn compare_run_revision(run_record_key: String, mod_revision: i64) -> Compare {
        Compare::mod_revision(run_record_key, CompareOp::Equal, mod_revision)
    }

    fn compare_absent(key: String) -> Compare {
        Compare::version(key, CompareOp::Equal, 0)
    }

    fn compare_present(key: String) -> Compare {
        Compare::version(key, CompareOp::Greater, 0)
    }

    fn compare_owner_present(owner_key: String, owner_value: Vec<u8>) -> Vec<Compare> {
        vec![
            Compare::version(owner_key.clone(), CompareOp::Greater, 0),
            Compare::value(owner_key, CompareOp::Equal, owner_value),
        ]
    }

    fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        let _ = self.etcd_lease_revoke(lease_id);
    }

    fn load_run_or_panic(&self, tenant: TenantId, run: RunId) -> PersistedRun {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => run_record,
            Ok(None) => self.fatal_storage_error("load run", format!("run {:?} missing", run)),
            Err(err) => self.fatal_storage_error("load run", err),
        }
    }

    fn load_shard_or_panic(&self, tenant: TenantId, key: ShardKey) -> PersistedShard {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => self.fatal_storage_error("load shard", format!("shard {:?} missing", key)),
            Err(err) => self.fatal_storage_error("load shard", err),
        }
    }

    fn build_root_shard_blob(
        &self,
        tenant: TenantId,
        run: RunId,
        cursor_semantics: gossip_coordination::CursorSemantics,
        input: &InitialShardInput<'_>,
    ) -> Result<Vec<u8>, RegisterShardsError> {
        let mut slab = ByteSlab::with_capacity(Self::build_slab_capacity_for_initial_shard(input));
        let record = ShardRecord::new_active_with_cursor(
            tenant,
            run,
            input.shard(),
            input.spec(),
            input.cursor(),
            cursor_semantics,
            &mut slab,
        )
        .map_err(|_| RegisterShardsError::ResourceExhausted {
            resource: "shard_slab",
        })?;
        Ok(encode_shard_record_v1(&record, &slab))
    }

    fn scan_tenant_runs(&self, tenant: TenantId) -> Result<Vec<PersistedRun>, EtcdCoordinatorError> {
        let prefix = self.keyspace.runs_prefix(tenant);
        let response = self.etcd_get(prefix.clone().into_bytes(), Some(GetOptions::new().with_prefix()))?;
        let mut out = Vec::new();
        for kv in response.kvs() {
            let Some(run_from_key) = parse_direct_run_id_from_key(&prefix, kv.key())? else {
                continue;
            };
            let record = decode_run_record_v1(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            })?;
            if record.tenant != tenant {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record tenant disagrees with keyspace tenant",
                    },
                });
            }
            if record.run != run_from_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "RunRecord",
                        detail: "run record run id disagrees with key suffix",
                    },
                });
            }
            out.push(PersistedRun {
                record,
                mod_revision: kv.mod_revision(),
            });
        }
        out.sort_by_key(|persisted| persisted.record.run.as_raw());
        Ok(out)
    }

    /// List worker-visible runs by scanning only the active-runs index.
    ///
    /// This intentionally does not scan `/runs/...`, so `Initializing` runs and
    /// partial create attempts remain invisible until `register_shards` commits
    /// the authoritative active-run index entry.
    pub fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let prefix = self.keyspace.runs_active_prefix(tenant);
        let response = self.etcd_get(prefix.clone().into_bytes(), Some(GetOptions::new().with_prefix()))?;
        out.clear();
        for kv in response.kvs() {
            if let Some(run) = parse_direct_run_id_from_key(&prefix, kv.key())? {
                out.push(run);
            }
        }
        out.sort_unstable_by_key(|run| run.as_raw());
        Ok(())
    }

    pub fn list_active_runs(&self, tenant: TenantId) -> Result<Vec<RunId>, EtcdCoordinatorError> {
        let mut out = Vec::new();
        self.list_active_runs_into(tenant, &mut out)?;
        Ok(out)
    }

    /// Delete stale `Initializing` runs that never published an active-run index.
    ///
    /// Deletion is fenced by both the run-record revision and `runs_active/<run>`
    /// absence, so a concurrent `register_shards` commit wins cleanly.
    pub fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        created_before_or_at: LogicalTime,
        limit: usize,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        out.clear();
        if limit == 0 {
            return Ok(());
        }

        let mut candidates = self.scan_tenant_runs(tenant)?;
        candidates.retain(|persisted| {
            persisted.record.status == RunStatus::Initializing
                && persisted.record.created_at <= created_before_or_at
        });
        candidates.sort_by(|a, b| {
            a.record
                .created_at
                .cmp(&b.record.created_at)
                .then_with(|| a.record.run.as_raw().cmp(&b.record.run.as_raw()))
        });

        for persisted in candidates.into_iter().take(limit) {
            let run = persisted.record.run;
            let run_key = self.keyspace.run_record_key(tenant, run);
            let active_key = self.keyspace.run_active_index_key(tenant, run);
            let shards_prefix = self.keyspace.run_shards_prefix(tenant, run);
            let active_shards_prefix = self.keyspace.shards_active_prefix(tenant, run);

            let txn = Txn::new()
                .when(vec![
                    Self::compare_run_revision(run_key.clone(), persisted.mod_revision),
                    Self::compare_absent(active_key.clone()),
                ])
                .and_then(vec![
                    TxnOp::delete(run_key.into_bytes(), None),
                    TxnOp::delete(active_key.into_bytes(), None),
                    TxnOp::delete(
                        shards_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                    TxnOp::delete(
                        active_shards_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                ]);
            let response = self.etcd_txn(txn)?;
            if response.succeeded() {
                out.push(run);
            }
        }
        Ok(())
    }

    pub fn gc_stale_initializing_runs(
        &mut self,
        tenant: TenantId,
        created_before_or_at: LogicalTime,
        limit: usize,
    ) -> Result<Vec<RunId>, EtcdCoordinatorError> {
        let mut out = Vec::new();
        self.gc_stale_initializing_runs_into(tenant, created_before_or_at, limit, &mut out)?;
        Ok(out)
    }


    fn transition_run_terminal(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
        payload_hash: u64,
        target_status: RunStatus,
        op_kind: RunOpKind,
        require_active: bool,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_run_record(tenant, run) {
                Ok(Some(run_record)) => run_record,
                Ok(None) => return Err(RunTransitionError::RunNotFound),
                Err(err) => self.fatal_storage_error("run_terminal.load", err),
            };
            let mut record = persisted.record;

            if record.tenant != tenant {
                return Err(RunTransitionError::TenantMismatch { expected: tenant });
            }
            if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
                assert_eq!(entry.kind(), op_kind, "idempotent replay kind mismatch for terminal run op");
                return Ok(IdempotentOutcome::Replayed(()));
            }
            if record.status.is_terminal() {
                return Err(RunTransitionError::RunTerminal { status: record.status });
            }
            if require_active && record.status != RunStatus::Active {
                return Err(RunTransitionError::WrongStatus {
                    status: record.status,
                    target: target_status,
                });
            }

            apply_terminal_run_transition(
                &mut record,
                now,
                op_id,
                payload_hash,
                target_status,
                op_kind,
            );
            let run_blob = encode_run_record_v1(&record);
            let run_key = self.keyspace.run_record_key(tenant, run);
            let active_key = self.keyspace.run_active_index_key(tenant, run);
            let mut compares = vec![Self::compare_run_revision(run_key.clone(), persisted.mod_revision)];
            match persisted.record.status {
                RunStatus::Active => compares.push(Self::compare_present(active_key.clone())),
                RunStatus::Initializing => compares.push(Self::compare_absent(active_key.clone())),
                RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled => {
                    unreachable!("terminal statuses returned earlier")
                }
            }
            let txn = Txn::new().when(compares).and_then(vec![
                TxnOp::put(run_key.into_bytes(), run_blob, None),
                TxnOp::delete(active_key.into_bytes(), None),
            ]);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("run_terminal.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(()));
            }
        }

        let persisted = self.load_run_or_panic(tenant, run);
        if let Some(entry) = persisted.record.check_op_idempotency(op_id, payload_hash)? {
            assert_eq!(entry.kind(), op_kind, "idempotent replay kind mismatch for terminal run op");
            return Ok(IdempotentOutcome::Replayed(()));
        }
        if persisted.record.status.is_terminal() {
            return Err(RunTransitionError::RunTerminal { status: persisted.record.status });
        }
        if require_active && persisted.record.status != RunStatus::Active {
            return Err(RunTransitionError::WrongStatus {
                status: persisted.record.status,
                target: target_status,
            });
        }
        self.fatal_storage_error(
            "run_terminal.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_clear_namespace(&self) -> Result<(), EtcdCoordinatorError> {
        self.etcd_delete(
            self.keyspace.prefix().as_bytes().to_vec(),
            Some(DeleteOptions::new().with_prefix()),
        )?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_run_record(&self, record: &RunRecord) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(record.tenant, record.run).into_bytes();
        let value = encode_run_record_v1(record);
        self.etcd_put(key, value, None)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_shard_record(
        &self,
        record: &ShardRecord,
        slab: &ByteSlab,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self
            .keyspace
            .shard_record_key(record.tenant, record.run, record.shard)
            .into_bytes();
        let value = encode_shard_record_v1(record, slab);
        self.etcd_put(key, value, None)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_run_active_index(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.run_active_index_key(tenant, run).into_bytes();
        self.etcd_put(key, Vec::new(), None)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_active_shard_index(
        &self,
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.active_shard_index_key(tenant, run, shard).into_bytes();
        self.etcd_put(key, Vec::new(), None)?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_owner_binding(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(WorkerId, FenceEpoch, i64)>, EtcdCoordinatorError> {
        let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard()).into_bytes();
        let response = self.etcd_get(owner_key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let binding = self.decode_owner_binding(EtcdOperation::Get, kv.value())?;
        Ok(Some((binding.worker, binding.fence, kv.lease())))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_shard_snapshot(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(ShardRecord, ByteSlab)>, EtcdCoordinatorError> {
        match self.load_shard_record(tenant, key)? {
            None => Ok(None),
            Some(persisted) => Ok(Some((persisted.record, persisted.slab))),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_run_snapshot(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<RunRecord>, EtcdCoordinatorError> {
        Ok(self.load_run_record(tenant, run)?.map(|persisted| persisted.record))
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_active_shard_index_exists(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<bool, EtcdCoordinatorError> {
        let index_key = self
            .keyspace
            .active_shard_index_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(index_key, None)?;
        Ok(!response.kvs().is_empty())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub fn test_run_active_index_exists(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<bool, EtcdCoordinatorError> {
        let index_key = self.keyspace.run_active_index_key(tenant, run).into_bytes();
        let response = self.etcd_get(index_key, None)?;
        Ok(!response.kvs().is_empty())
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
                &"B4: run creation/registration, run lifecycle, acquire/renew/checkpoint/split, active-run index enumeration, and stale-initializing-run GC persisted in etcd; complete/park still pending",
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
        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(AcquireError::ShardNotFound { shard: key }),
                Err(err) => self.fatal_storage_error("acquire.load_shard", err),
            };

            if persisted.record.tenant != tenant {
                return Err(AcquireError::TenantMismatch { expected: tenant });
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(AcquireError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            if persisted.owner_is_live_at(now) {
                let current_owner = persisted
                    .record
                    .lease_owner()
                    .expect("live owner key must match shard record lease");
                let lease_deadline = persisted
                    .record
                    .lease_deadline()
                    .expect("live owner key must match shard record deadline");
                return Err(AcquireError::AlreadyLeased {
                    current_owner,
                    lease_deadline,
                });
            }

            let run_record = self.load_run_or_panic(tenant, key.run());
            let lease_duration = run_record.record.config.lease_duration();
            let new_deadline = now
                .checked_add(lease_duration)
                .unwrap_or(LogicalTime::from_raw(u64::MAX));
            let grant = self
                .etcd_lease_grant(self.config.owner_lease_ttl_secs())
                .unwrap_or_else(|err| self.fatal_storage_error("acquire.lease_grant", err));
            let new_lease_id = grant.id();
            let prior_lease_id = persisted.owner.as_ref().map(|owner| owner.lease_id);

            let mut persisted = persisted;
            let new_fence = persisted.record.advance_fence();
            persisted.record.lease = Some(LeaseHolder::new(worker, new_deadline));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);
            let owner_blob = encode_owner_value_v1(worker, new_fence);

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            if let Some(expected_owner) = persisted.expected_owner_value() {
                compares.extend(Self::compare_owner_present(owner_key.clone(), expected_owner));
            } else {
                compares.push(Self::compare_absent(owner_key.clone()));
            }
            let txn = Txn::new().when(compares).and_then(vec![
                TxnOp::put(shard_record_key.into_bytes(), shard_blob, None),
                TxnOp::put(
                    owner_key.into_bytes(),
                    owner_blob,
                    Some(PutOptions::new().with_lease(new_lease_id)),
                ),
            ]);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("acquire.txn", err));
            if !response.succeeded() {
                self.best_effort_revoke_lease(new_lease_id);
                continue;
            }

            if let Some(old_lease_id) = prior_lease_id {
                self.best_effort_revoke_lease(old_lease_id);
            }

            let capacity = self
                .count_available_for_run(now, tenant, key.run())
                .unwrap_or_else(|err| self.fatal_storage_error("acquire.capacity_hint", err));

            let lease = Lease::new(tenant, key.run(), key.shard(), worker, new_fence, new_deadline);
            out.reset();
            out.write_spec(
                persisted.record.spec.key_range_start(&persisted.slab),
                persisted.record.spec.key_range_end(&persisted.slab),
                persisted.record.spec.metadata(&persisted.slab),
            );
            out.write_cursor(
                persisted.record.cursor.last_key(&persisted.slab),
                persisted.record.cursor.token(&persisted.slab),
            );
            out.write_spawned_iter(persisted.record.spawned.iter(&persisted.slab));
            let snapshot = out.view(
                persisted.record.status,
                persisted.record.cursor_semantics,
                persisted.record.parent,
            );
            return Ok(AcquireResultView {
                lease,
                snapshot,
                capacity,
            });
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if persisted.record.status != ShardStatus::Active {
            return Err(AcquireError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        if persisted.owner_is_live_at(now) {
            return Err(AcquireError::AlreadyLeased {
                current_owner: persisted
                    .record
                    .lease_owner()
                    .expect("live owner key must match record owner"),
                lease_deadline: persisted
                    .record
                    .lease_deadline()
                    .expect("live owner key must match record deadline"),
            });
        }
        self.fatal_storage_error("acquire.compare_retry_budget", "compare contention did not converge")
    }

    fn renew(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
    ) -> Result<RenewResult, RenewError> {
        let key = lease.shard_key();
        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(RenewError::ShardNotFound { shard: key }),
                Err(err) => self.fatal_storage_error("renew.load_shard", err),
            };
            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(RenewError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let run_record = self.load_run_or_panic(tenant, key.run());
            let lease_duration = run_record.record.config.lease_duration();
            let new_deadline = now
                .checked_add(lease_duration)
                .unwrap_or(LogicalTime::from_raw(u64::MAX));

            let old_lease_id = persisted
                .owner
                .as_ref()
                .map(|owner| owner.lease_id)
                .expect("validated owner must exist");
            self.etcd_lease_keep_alive_once(old_lease_id)
                .unwrap_or_else(|err| self.fatal_storage_error("renew.lease_keep_alive", err));

            let mut persisted = persisted;
            persisted.record.lease = Some(LeaseHolder::new(lease.owner(), new_deadline));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(owner_key, owner_blob));
            let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                shard_record_key.into_bytes(),
                shard_blob,
                None,
            )]);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("renew.txn", err));
            if response.succeeded() {
                let capacity = self
                    .count_available_for_run(now, tenant, key.run())
                    .unwrap_or_else(|err| self.fatal_storage_error("renew.capacity_hint", err));
                return Ok(RenewResult {
                    new_deadline,
                    capacity,
                });
            }
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        validate_lease(now, tenant, lease, &persisted.record)?;
        Err(RenewError::StaleFence {
            presented: lease.fence(),
            current: persisted.record.fence_epoch,
        })
    }

    fn checkpoint(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        new_cursor: &CursorUpdate<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CheckpointError> {
        let key = lease.shard_key();
        let payload_hash = hash_checkpoint_payload(new_cursor);

        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(CheckpointError::ShardNotFound { shard: key }),
                Err(err) => self.fatal_storage_error("checkpoint.load_shard", err),
            };

            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                return Ok(IdempotentOutcome::Replayed(()));
            }
            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(CheckpointError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }
            validate_cursor_update_pooled(
                new_cursor,
                persisted.record.cursor.last_key(&persisted.slab),
                persisted.record.spec.key_range_start(&persisted.slab),
                persisted.record.spec.key_range_end(&persisted.slab),
            )?;

            let mut persisted = persisted;
            persisted
                .record
                .cursor
                .update_from_ref(new_cursor, &mut persisted.slab)
                .map_err(CheckpointError::ResourceExhausted)?;
            persisted.record.op_log_push(OpLogEntry::new(
                op_id,
                OpKind::Checkpoint,
                OpResult::Completed,
                payload_hash,
                now,
            ));
            persisted.record.assert_invariants(&persisted.slab);
            let shard_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(owner_key, owner_blob));
            let txn = Txn::new().when(compares).and_then(vec![TxnOp::put(
                shard_record_key.into_bytes(),
                shard_blob,
                None,
            )]);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("checkpoint.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(()));
            }
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            return Ok(IdempotentOutcome::Replayed(()));
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        Err(CheckpointError::StaleFence {
            presented: lease.fence(),
            current: persisted.record.fence_epoch,
        })
    }

    fn complete(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _final_cursor: &CursorUpdate<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, CompleteError> {
        self.fail_unimplemented("complete")
    }

    fn park_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _reason: ParkReason,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, ParkError> {
        self.fail_unimplemented("park_shard")
    }

    fn split_replace(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitReplacePlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_replace_payload(&plan);

        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(SplitReplaceError::ShardNotFound { shard: key }),
                Err(err) => self.fatal_storage_error("split_replace.load_shard", err),
            };

            if persisted.record.tenant != tenant {
                return Err(SplitReplaceError::TenantMismatch { expected: tenant });
            }
            if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
                let children = split_replace_replay_child_ids(&persisted.record, &plan, op_id);
                return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(SplitReplaceError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            validate_lease(now, tenant, lease, &persisted.record)?;
            if !persisted.owner_matches_lease(lease) {
                return Err(SplitReplaceError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let sorted = split_replace_validate_preconditions(
                &persisted.record,
                &plan,
                &persisted.slab,
                self.config.max_children_per_op(),
            )?;

            let mut child_ids = SplitChildIds::new();
            let mut child_puts = Vec::with_capacity(sorted.len());
            let mut child_index_ops = Vec::with_capacity(sorted.len());
            let mut child_absent_compares = Vec::with_capacity(sorted.len());

            for i in 0..sorted.len() {
                let child = sorted.child(&plan, i);
                let derived_index = (persisted.record.spawned.len() + i) as u32;
                let child_id = derive_split_shard_id(
                    persisted.record.run,
                    persisted.record.shard,
                    op_id,
                    DerivedShardKind::Child,
                    derived_index,
                );
                assert!(child_id.is_derived(), "derived child must have bit 63 set");
                let child_key = ShardKey::new(persisted.record.run, child_id);

                match self.load_shard_record(tenant, child_key) {
                    Ok(Some(_)) => {
                        return Err(SplitReplaceError::SplitInvalid(
                            SplitValidationError::DerivedIdCollision { derived_id: child_id },
                        ));
                    }
                    Ok(None) => {}
                    Err(err) => {
                        self.fatal_storage_error("split_replace.preflight_child_absence", err)
                    }
                }

                let mut child_slab = ByteSlab::with_capacity(
                    Self::build_slab_capacity_for_initial_shard_bytes(
                        child.spec(),
                        child.cursor(),
                    ),
                );
                let child_record = ShardRecord::new_split_child(
                    tenant,
                    persisted.record.run,
                    child_id,
                    child.spec(),
                    child.cursor(),
                    persisted.record.cursor_semantics,
                    persisted.record.shard,
                    &mut child_slab,
                )?;
                child_record.assert_invariants(&child_slab);

                let child_record_key = self
                    .keyspace
                    .shard_record_key(tenant, persisted.record.run, child_id);
                child_absent_compares.push(Self::compare_absent(child_record_key.clone()));
                child_puts.push(TxnOp::put(
                    child_record_key.clone().into_bytes(),
                    encode_shard_record_v1(&child_record, &child_slab),
                    None,
                ));
                child_index_ops.push(TxnOp::put(
                    self.keyspace
                        .active_shard_index_key(tenant, persisted.record.run, child_id)
                        .into_bytes(),
                    Vec::new(),
                    None,
                ));
                child_ids.push(child_id);
            }

            let mut persisted = persisted;
            split_replace_apply_parent(
                &mut persisted.record,
                child_ids.as_slice(),
                op_id,
                payload_hash,
                now,
                &mut persisted.slab,
            )?;
            let parent_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");

            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(owner_key.clone(), owner_blob));
            compares.extend(child_absent_compares);

            let mut ops = Vec::with_capacity(2 + child_puts.len() + child_index_ops.len() + 1);
            ops.push(TxnOp::put(
                shard_record_key.into_bytes(),
                parent_blob,
                None,
            ));
            ops.push(TxnOp::delete(owner_key.into_bytes(), None));
            ops.push(TxnOp::delete(
                self.keyspace
                    .active_shard_index_key(tenant, key.run(), key.shard())
                    .into_bytes(),
                None,
            ));
            ops.extend(child_puts);
            ops.extend(child_index_ops);

            #[cfg(any(test, feature = "test-support"))]
            self.maybe_drop_owner_before_split_replace_txn(tenant, key)
                .unwrap_or_else(|err| self.fatal_storage_error("split_replace.inject_fault", err));

            let txn = Txn::new().when(compares).and_then(ops);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("split_replace.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(SplitReplaceResult { children: child_ids }));
            }
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if check_op_idempotency(&persisted.record, op_id, payload_hash)?.is_some() {
            let children = split_replace_replay_child_ids(&persisted.record, &plan, op_id);
            return Ok(IdempotentOutcome::Replayed(SplitReplaceResult { children }));
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(SplitReplaceError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        Err(SplitReplaceError::StaleFence {
            presented: lease.fence(),
            current: persisted.record.fence_epoch,
        })
    }

    fn split_residual(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        plan: SplitResidualPlan<'_>,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        let key = lease.shard_key();
        let payload_hash = hash_split_residual_payload(&plan);

        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(SplitResidualError::ShardNotFound { shard: key }),
                Err(err) => self.fatal_storage_error("split_residual.load_shard", err),
            };

            if persisted.record.tenant != tenant {
                return Err(SplitResidualError::TenantMismatch { expected: tenant });
            }
            if let Some(replay) =
                split_residual_check_replay(&persisted.record, op_id, payload_hash, &persisted.slab)?
            {
                return Ok(replay);
            }
            if persisted.record.status != ShardStatus::Active {
                return Err(SplitResidualError::ShardTerminal {
                    shard: key,
                    status: persisted.record.status,
                });
            }
            split_residual_validate_preconditions(
                now,
                tenant,
                lease,
                &persisted.record,
                &plan,
                &persisted.slab,
            )?;
            if !persisted.owner_matches_lease(lease) {
                return Err(SplitResidualError::StaleFence {
                    presented: lease.fence(),
                    current: persisted.record.fence_epoch,
                });
            }

            let residual_id = derive_split_shard_id(
                persisted.record.run,
                persisted.record.shard,
                op_id,
                DerivedShardKind::Residual,
                persisted.record.spawned.len() as u32,
            );
            let residual_key = ShardKey::new(persisted.record.run, residual_id);
            match self.load_shard_record(tenant, residual_key) {
                Ok(Some(_)) => {
                    return Err(SplitResidualError::SplitInvalid(
                        SplitValidationError::DerivedIdCollision {
                            derived_id: residual_id,
                        },
                    ));
                }
                Ok(None) => {}
                Err(err) => {
                    self.fatal_storage_error("split_residual.preflight_child_absence", err)
                }
            }

            let mut residual_slab = ByteSlab::with_capacity(
                Self::build_slab_capacity_for_initial_shard_bytes(
                    plan.residual_spec(),
                    CursorUpdate::initial(),
                ),
            );
            let residual_record = split_residual_build_record(
                &persisted.record,
                &plan,
                tenant,
                residual_id,
                &mut residual_slab,
            )?;
            residual_record.assert_invariants(&residual_slab);

            let residual_record_key = self
                .keyspace
                .shard_record_key(tenant, persisted.record.run, residual_id);

            let mut persisted = persisted;
            split_residual_apply_parent(
                &mut persisted.record,
                plan.parent_new_spec(),
                residual_id,
                op_id,
                payload_hash,
                now,
                &mut persisted.slab,
            )?;
            let parent_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let owner_blob = persisted
                .expected_owner_value()
                .expect("validated owner must produce owner value");

            let mut compares = vec![Self::compare_shard_revision(
                shard_record_key.clone(),
                persisted.mod_revision,
            )];
            compares.extend(Self::compare_owner_present(owner_key, owner_blob));
            compares.push(Self::compare_absent(residual_record_key.clone()));

            let ops = vec![
                TxnOp::put(shard_record_key.into_bytes(), parent_blob, None),
                TxnOp::put(
                    residual_record_key.clone().into_bytes(),
                    encode_shard_record_v1(&residual_record, &residual_slab),
                    None,
                ),
                TxnOp::put(
                    self.keyspace
                        .active_shard_index_key(tenant, persisted.record.run, residual_id)
                        .into_bytes(),
                    Vec::new(),
                    None,
                ),
            ];

            #[cfg(any(test, feature = "test-support"))]
            self.maybe_drop_owner_before_split_residual_txn(tenant, key)
                .unwrap_or_else(|err| self.fatal_storage_error("split_residual.inject_fault", err));

            let txn = Txn::new().when(compares).and_then(ops);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("split_residual.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(SplitResidualResult {
                    residual: residual_id,
                }));
            }
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        if let Some(replay) =
            split_residual_check_replay(&persisted.record, op_id, payload_hash, &persisted.slab)?
        {
            return Ok(replay);
        }
        if persisted.record.status != ShardStatus::Active {
            return Err(SplitResidualError::ShardTerminal {
                shard: key,
                status: persisted.record.status,
            });
        }
        validate_lease(now, tenant, lease, &persisted.record)?;
        Err(SplitResidualError::StaleFence {
            presented: lease.fence(),
            current: persisted.record.fence_epoch,
        })
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
        config.assert_valid();

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

        let key = self.keyspace.run_record_key(tenant, run);
        let active_key = self.keyspace.run_active_index_key(tenant, run);
        let blob = encode_run_record_v1(&record);
        let txn = Txn::new()
            .when(vec![
                Self::compare_absent(key.clone()),
                Self::compare_absent(active_key),
            ])
            .and_then(vec![TxnOp::put(key.into_bytes(), blob, None)]);
        let response = self
            .etcd_txn(txn)
            .unwrap_or_else(|err| self.fatal_storage_error("create_run.txn", err));
        if response.succeeded() {
            return Ok(record);
        }

        Err(CreateRunError::RunAlreadyExists { run })
    }

    fn register_shards(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        shards: &[InitialShardInput<'_>],
        op_id: OpId,
    ) -> Result<IdempotentOutcome<Vec<ShardId>>, RegisterShardsError> {
        let payload_hash = hash_register_shards_payload(shards);

        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted_run = match self.load_run_record(tenant, run) {
                Ok(Some(run_record)) => run_record,
                Ok(None) => return Err(RegisterShardsError::RunNotFound),
                Err(err) => self.fatal_storage_error("register_shards.load_run", err),
            };
            let mut run_record = persisted_run.record;

            if run_record.tenant != tenant {
                return Err(RegisterShardsError::TenantMismatch { expected: tenant });
            }
            if let Some(entry) = run_record.check_op_idempotency(op_id, payload_hash)? {
                assert_eq!(
                    entry.kind(),
                    RunOpKind::RegisterShards,
                    "idempotent replay kind mismatch: expected RegisterShards, got {:?}",
                    entry.kind()
                );
                match entry.result() {
                    RunOpResult::RegisteredShards { shard_ids } => {
                        return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                    }
                    RunOpResult::Ack => {
                        panic!(
                            "Run {:?}: RegisterShards op-log entry has Ack result \
                             (expected RegisteredShards) — data corruption",
                            run
                        );
                    }
                }
            }
            if run_record.status != RunStatus::Initializing {
                return Err(RegisterShardsError::WrongStatus {
                    status: run_record.status,
                });
            }

            validate_manifest(shards).map_err(RegisterShardsError::ManifestInvalid)?;

            let cursor_semantics = run_record.config.cursor_semantics();
            let shard_ids: Vec<ShardId> = shards.iter().map(InitialShardInput::shard).collect();

            let mut txn_ops = Vec::with_capacity(1 + (shards.len() * 2) + 1);
            let mut compares = Vec::with_capacity(2 + (shards.len() * 2));
            let run_key = self.keyspace.run_record_key(tenant, run);
            let run_active_key = self.keyspace.run_active_index_key(tenant, run);
            compares.push(Self::compare_run_revision(run_key.clone(), persisted_run.mod_revision));
            compares.push(Self::compare_absent(run_active_key.clone()));

            for shard in shards {
                let shard_key = self.keyspace.shard_record_key(tenant, run, shard.shard());
                let active_index = self.keyspace.active_shard_index_key(tenant, run, shard.shard());
                compares.push(Self::compare_absent(shard_key.clone()));
                compares.push(Self::compare_absent(active_index.clone()));
                let shard_blob =
                    self.build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                txn_ops.push(TxnOp::put(shard_key.into_bytes(), shard_blob, None));
                txn_ops.push(TxnOp::put(active_index.into_bytes(), Vec::<u8>::new(), None));
            }

            run_record.assert_transition_legal(RunStatus::Active);
            run_record.status = RunStatus::Active;
            run_record.root_shards = shard_ids.clone();
            run_record.op_log_push(RunOpLogEntry::new(
                op_id,
                RunOpKind::RegisterShards,
                payload_hash,
                now,
                RunOpResult::RegisteredShards {
                    shard_ids: shard_ids.clone().into_boxed_slice(),
                },
            ));
            run_record.assert_invariants();
            let run_blob = encode_run_record_v1(&run_record);

            txn_ops.insert(0, TxnOp::put(run_key.into_bytes(), run_blob, None));
            let run_active_key = self.keyspace.run_active_index_key(tenant, run);
            txn_ops.push(TxnOp::put(run_active_key.into_bytes(), Vec::<u8>::new(), None));

            let txn = Txn::new().when(compares).and_then(txn_ops);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("register_shards.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(shard_ids));
            }
        }

        let persisted_run = self.load_run_or_panic(tenant, run);
        if let Some(entry) = persisted_run.record.check_op_idempotency(op_id, payload_hash)? {
            match entry.result() {
                RunOpResult::RegisteredShards { shard_ids } => {
                    return Ok(IdempotentOutcome::Replayed(shard_ids.to_vec()));
                }
                RunOpResult::Ack => {
                    panic!(
                        "Run {:?}: RegisterShards op-log entry has Ack result \
                         (expected RegisteredShards) — data corruption",
                        run
                    );
                }
            }
        }
        if persisted_run.record.status != RunStatus::Initializing {
            return Err(RegisterShardsError::WrongStatus {
                status: persisted_run.record.status,
            });
        }
        self.fatal_storage_error(
            "register_shards.compare_retry_budget",
            "compare contention did not converge",
        )
    }

    fn get_run(&self, tenant: TenantId, run: RunId) -> Result<RunRecord, GetRunError> {
        match self.load_run_record(tenant, run) {
            Ok(Some(persisted)) => {
                if persisted.record.tenant != tenant {
                    Err(GetRunError::TenantMismatch { expected: tenant })
                } else {
                    Ok(persisted.record)
                }
            }
            Ok(None) => Err(GetRunError::RunNotFound),
            Err(err) => self.fatal_storage_error("get_run.load", err),
        }
    }

    fn get_run_progress(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
    ) -> Result<RunProgress, GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards = self
            .scan_run_shards(tenant, run)
            .unwrap_or_else(|err| self.fatal_storage_error("get_run_progress.scan", err));

        let mut progress = RunProgress::default();
        for persisted in &shards {
            progress.observe_shard(
                persisted.record.status,
                persisted.owner_is_live_at(now),
                persisted.record.cursor.last_key(&persisted.slab),
            );
        }
        Ok(progress)
    }

    fn list_shards_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        filter: ShardFilter,
        out: &mut Vec<ShardSummary>,
    ) -> Result<(), GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards = self
            .scan_run_shards(tenant, run)
            .unwrap_or_else(|err| self.fatal_storage_error("list_shards_into.scan", err));

        out.clear();
        for persisted in &shards {
            let visible = Self::visible_record_at(persisted, now);
            if !filter.matches_record(&visible, now) {
                continue;
            }
            out.push(ShardSummary::from_record(&visible, now, &persisted.slab));
        }

        out.sort_by(|a, b| {
            a.key_range_start()
                .cmp(b.key_range_start())
                .then_with(|| a.shard().cmp(&b.shard()))
        });
        Ok(())
    }

    fn collect_claim_candidates_into(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<LogicalTime>, GetRunError> {
        let _ = self.get_run(tenant, run)?;
        let shards = self
            .scan_run_shards(tenant, run)
            .unwrap_or_else(|err| self.fatal_storage_error("collect_claim_candidates.scan", err));

        candidates.clear();
        let mut earliest_deadline: Option<LogicalTime> = None;
        for persisted in &shards {
            if persisted.record.status != ShardStatus::Active {
                continue;
            }
            if persisted.owner_is_live_at(now) {
                if let Some(deadline) = persisted.record.lease_deadline() {
                    earliest_deadline = Some(match earliest_deadline {
                        Some(prev) => core::cmp::min(prev, deadline),
                        None => deadline,
                    });
                }
                continue;
            }
            candidates.push(persisted.record.shard);
        }

        candidates.sort_unstable();
        Ok(earliest_deadline)
    }

    fn complete_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(
            now,
            tenant,
            run,
            op_id,
            hash_complete_run_payload(),
            RunStatus::Done,
            RunOpKind::CompleteRun,
            true,
        )
    }

    fn fail_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(
            now,
            tenant,
            run,
            op_id,
            hash_fail_run_payload(),
            RunStatus::Failed,
            RunOpKind::FailRun,
            true,
        )
    }

    fn cancel_run(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.transition_run_terminal(
            now,
            tenant,
            run,
            op_id,
            hash_cancel_run_payload(),
            RunStatus::Cancelled,
            RunOpKind::CancelRun,
            false,
        )
    }

    fn unpark_shard(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        key: ShardKey,
        op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        let payload_hash = hash_unpark_payload(&key);

        for _ in 0..self.config.optimistic_txn_retries() {
            let persisted = match self.load_shard_record(tenant, key) {
                Ok(Some(shard)) => shard,
                Ok(None) => return Err(UnparkError::ShardNotFound),
                Err(err) => self.fatal_storage_error("unpark.load_shard", err),
            };
            if persisted.record.tenant != tenant {
                return Err(UnparkError::TenantMismatch { expected: tenant });
            }

            let run_persisted = self.load_run_or_panic(tenant, key.run());
            if run_persisted.record.status.is_terminal() {
                return Err(UnparkError::RunTerminal {
                    status: run_persisted.record.status,
                });
            }

            if check_op_idempotency(&persisted.record, op_id, payload_hash)
                .map_err(|e| match e {
                    gossip_coordination::CoordError::OpIdConflict {
                        op_id,
                        expected_hash,
                        actual_hash,
                    } => UnparkError::OpIdConflict(gossip_coordination::RunOpIdConflict {
                        op_id,
                        expected_hash,
                        actual_hash,
                    }),
                    gossip_coordination::CoordError::ShardNotFound { .. }
                    | gossip_coordination::CoordError::TenantMismatch { .. }
                    | gossip_coordination::CoordError::StaleFence { .. }
                    | gossip_coordination::CoordError::LeaseExpired { .. }
                    | gossip_coordination::CoordError::ShardTerminal { .. }
                    | gossip_coordination::CoordError::CursorRegression { .. }
                    | gossip_coordination::CoordError::CursorOutOfBounds(_)
                    | gossip_coordination::CoordError::CursorKeyTooLarge { .. }
                    | gossip_coordination::CoordError::CursorTokenTooLarge { .. }
                    | gossip_coordination::CoordError::SplitInvalid(_)
                    | gossip_coordination::CoordError::CheckpointMissingKey => {
                        unreachable!("check_op_idempotency only returns OpIdConflict")
                    }
                })?
                .is_some()
            {
                return Ok(IdempotentOutcome::Replayed(()));
            }

            if persisted.record.status != ShardStatus::Parked {
                return Err(UnparkError::NotParked {
                    status: persisted.record.status,
                });
            }

            let mut persisted = persisted;
            persisted.record.advance_fence();
            persisted.record.park_reason = None;
            persisted.record.status = ShardStatus::Active;
            persisted.record.lease = None;
            persisted.record.op_log_push(OpLogEntry::new(
                op_id,
                OpKind::Unpark,
                OpResult::Completed,
                payload_hash,
                now,
            ));
            persisted.record.assert_invariants(&persisted.slab);

            let shard_record_key = self.keyspace.shard_record_key(tenant, key.run(), key.shard());
            let owner_key = self.keyspace.shard_owner_key(tenant, key.run(), key.shard());
            let active_shard_key = self.keyspace.active_shard_index_key(tenant, key.run(), key.shard());
            let run_key = self.keyspace.run_record_key(tenant, key.run());
            let run_active_key = self.keyspace.run_active_index_key(tenant, key.run());
            let shard_blob = encode_shard_record_v1(&persisted.record, &persisted.slab);

            let txn = Txn::new()
                .when(vec![
                    Self::compare_shard_revision(shard_record_key.clone(), persisted.mod_revision),
                    Self::compare_run_revision(run_key, run_persisted.mod_revision),
                    Self::compare_present(run_active_key),
                    Self::compare_absent(owner_key.clone()),
                ])
                .and_then(vec![
                    TxnOp::put(shard_record_key.into_bytes(), shard_blob, None),
                    TxnOp::delete(owner_key.into_bytes(), None),
                    TxnOp::put(active_shard_key.into_bytes(), Vec::new(), None),
                ]);
            let response = self
                .etcd_txn(txn)
                .unwrap_or_else(|err| self.fatal_storage_error("unpark.txn", err));
            if response.succeeded() {
                return Ok(IdempotentOutcome::Executed(()));
            }
        }

        let persisted = self.load_shard_or_panic(tenant, key);
        let run_persisted = self.load_run_or_panic(tenant, key.run());
        if run_persisted.record.status.is_terminal() {
            return Err(UnparkError::RunTerminal {
                status: run_persisted.record.status,
            });
        }
        if check_op_idempotency(&persisted.record, op_id, payload_hash)
            .map_err(|e| match e {
                gossip_coordination::CoordError::OpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                } => UnparkError::OpIdConflict(gossip_coordination::RunOpIdConflict {
                    op_id,
                    expected_hash,
                    actual_hash,
                }),
                gossip_coordination::CoordError::ShardNotFound { .. }
                | gossip_coordination::CoordError::TenantMismatch { .. }
                | gossip_coordination::CoordError::StaleFence { .. }
                | gossip_coordination::CoordError::LeaseExpired { .. }
                | gossip_coordination::CoordError::ShardTerminal { .. }
                | gossip_coordination::CoordError::CursorRegression { .. }
                | gossip_coordination::CoordError::CursorOutOfBounds(_)
                | gossip_coordination::CoordError::CursorKeyTooLarge { .. }
                | gossip_coordination::CoordError::CursorTokenTooLarge { .. }
                | gossip_coordination::CoordError::SplitInvalid(_)
                | gossip_coordination::CoordError::CheckpointMissingKey => {
                    unreachable!("check_op_idempotency only returns OpIdConflict")
                }
            })?
            .is_some()
        {
            return Ok(IdempotentOutcome::Replayed(()));
        }
        if persisted.record.status != ShardStatus::Parked {
            return Err(UnparkError::NotParked {
                status: persisted.record.status,
            });
        }
        self.fatal_storage_error(
            "unpark.compare_retry_budget",
            "compare contention did not converge",
        )
    }
}
