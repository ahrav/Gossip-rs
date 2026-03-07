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
use gossip_coordination::validation::validate_cursor_update_pooled;
use gossip_coordination::{
    AcquireError, AcquireResultView, AcquireScratch, CapacityHint, CheckpointError,
    CompleteError, CoordinationBackend, CreateRunError, CursorUpdate, FenceEpoch, GetRunError,
    IdempotentOutcome, InitialShardInput, Lease, LeaseHolder, LogicalTime, OpId, OpKind,
    OpLogEntry, OpResult, ParkError, ParkReason, RegisterShardsError, RenewError, RenewResult,
    RunConfig, RunId, RunManagement, RunOpKind, RunOpLogEntry, RunOpResult, RunProgress,
    RunRecord, RunStatus, RunTransitionError, ShardFilter, ShardId, ShardKey, ShardRecord,
    ShardStatus, ShardSummary, SplitReplaceError, SplitReplacePlan, SplitReplaceResult,
    SplitResidualError, SplitResidualPlan, SplitResidualResult, TenantId, UnparkError, WorkerId,
    check_op_idempotency, hash_checkpoint_payload, hash_register_shards_payload,
    validate_lease, validate_manifest,
};
use gossip_stdx::{ByteSlab, RingBuffer};

const MIN_DECODE_SLAB_CAPACITY: usize = 4 * 1024;
const MAX_DECODE_SLAB_CAPACITY: usize = 256 * 1024;
const DEFAULT_BUILD_SLAB_FLOOR: usize = 1024;

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

/// etcd coordination backend.
///
/// B2 scope:
/// - B0/B1 scaffold (connection, keyspace, codecs),
/// - run creation / shard registration and read-side queries required to
///   exercise persisted state,
/// - acquire / renew / checkpoint executed against etcd with storage-layer
///   fencing and owner keys attached to real etcd leases.
///
/// Out-of-scope mutating operations (`complete`, `park_shard`, `split_*`,
/// run terminal transitions, `unpark_shard`) fail closed until later Epic B
/// items land.
pub struct EtcdCoordinator {
    config: EtcdCoordinatorConfig,
    keyspace: EtcdKeyspace,
    runtime: SyncRuntime,
    client: etcd_client::Client,
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
        let spec = input.spec();
        let cursor = input.cursor();
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

    #[cfg(test)]
    pub(crate) fn test_clear_namespace(&self) -> Result<(), EtcdCoordinatorError> {
        self.etcd_delete(
            self.keyspace.prefix().as_bytes().to_vec(),
            Some(DeleteOptions::new().with_prefix()),
        )?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_seed_run_record(&self, record: &RunRecord) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(record.tenant, record.run).into_bytes();
        let value = encode_run_record_v1(record);
        self.etcd_put(key, value, None)?;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_seed_shard_record(
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

    #[cfg(test)]
    pub(crate) fn test_load_owner_binding(
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

    #[cfg(test)]
    pub(crate) fn test_load_shard_snapshot(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(ShardRecord, ByteSlab)>, EtcdCoordinatorError> {
        match self.load_shard_record(tenant, key)? {
            None => Ok(None),
            Some(persisted) => Ok(Some((persisted.record, persisted.slab))),
        }
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
                &"B2: run creation/registration + acquire/renew/checkpoint persisted in etcd; remaining mutating ops fail closed until later Epic B items",
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
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _plan: SplitReplacePlan<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitReplaceResult>, SplitReplaceError> {
        self.fail_unimplemented("split_replace")
    }

    fn split_residual(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _lease: &Lease,
        _plan: SplitResidualPlan<'_>,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<SplitResidualResult>, SplitResidualError> {
        self.fail_unimplemented("split_residual")
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
        let blob = encode_run_record_v1(&record);
        let txn = Txn::new()
            .when(vec![Self::compare_absent(key.clone())])
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
            let mut compares = Vec::with_capacity(1 + shards.len());
            let run_key = self.keyspace.run_record_key(tenant, run);
            compares.push(Self::compare_run_revision(run_key.clone(), persisted_run.mod_revision));

            for shard in shards {
                let shard_key = self.keyspace.shard_record_key(tenant, run, shard.shard());
                compares.push(Self::compare_absent(shard_key.clone()));
                let shard_blob =
                    self.build_root_shard_blob(tenant, run, cursor_semantics, shard)?;
                txn_ops.push(TxnOp::put(shard_key.into_bytes(), shard_blob, None));
                let active_index = self.keyspace.active_shard_index_key(tenant, run, shard.shard());
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
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("complete_run")
    }

    fn fail_run(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("fail_run")
    }

    fn cancel_run(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _run: RunId,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        self.fail_unimplemented("cancel_run")
    }

    fn unpark_shard(
        &mut self,
        _now: LogicalTime,
        _tenant: TenantId,
        _key: ShardKey,
        _op_id: OpId,
    ) -> Result<IdempotentOutcome<()>, UnparkError> {
        self.fail_unimplemented("unpark_shard")
    }
}
