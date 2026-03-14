//! Test-support helpers for the etcd coordination backend.
//!
//! This module keeps seeding, inspection, and deterministic fault-injection
//! surfaces out of the production backend implementation while still sharing
//! the same private storage/runtime helpers.

#[cfg(any(test, feature = "test-support"))]
use super::PersistedShard;
#[cfg(any(test, feature = "test-support"))]
use super::coordinator::SyncEtcdLike;
use super::{AsyncEtcdCoordinator, EtcdCoordinator};
#[cfg(any(test, feature = "test-support"))]
use crate::codec::{encode_run_record, encode_shard_record};
#[cfg(any(test, feature = "test-support"))]
use crate::error::{EtcdCoordinatorError, EtcdOperation};
#[cfg(any(test, feature = "test-support"))]
use etcd_client::DeleteOptions;
#[cfg(any(test, feature = "test-support"))]
use gossip_coordination::{ByteSlab, FenceEpoch, RunId, RunRecord, ShardId, ShardRecord, WorkerId};
use gossip_coordination::{ShardKey, TenantId};

/// One-shot fault injection knobs for etcd integration tests.
///
/// Each fault targets the narrow window after a split operation has computed
/// its parent/child mutations but before the atomic etcd transaction commits.
/// Deleting the owner key at that point simulates lease loss and forces the
/// transaction's ownership compares to fail.
#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtcdTestFault {
    /// Delete the parent owner key immediately before the next
    /// `split_replace` transaction executes.
    DropOwnerBeforeNextSplitReplaceTxn,
    /// Delete the parent owner key immediately before the next
    /// `split_residual` transaction executes.
    DropOwnerBeforeNextSplitResidualTxn,
}

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Debug, Default)]
pub(super) struct EtcdTestFaultState {
    drop_owner_before_next_split_replace_txn: bool,
    drop_owner_before_next_split_residual_txn: bool,
}

/// Read-only shard snapshot used by integration tests and downstream
/// `test-support` harnesses.
///
/// The wrapper keeps the decoded shard record and its backing slab together so
/// cleanup stays automatic when the snapshot drops.
#[cfg(any(test, feature = "test-support"))]
pub struct EtcdTestShardSnapshot {
    inner: PersistedShard,
}

#[cfg(any(test, feature = "test-support"))]
impl EtcdTestShardSnapshot {
    /// Return the backing slab that owns the pooled field storage referenced by
    /// this snapshot.
    #[must_use]
    pub fn slab(&self) -> &ByteSlab {
        &self.inner.slab
    }
}

#[cfg(any(test, feature = "test-support"))]
impl std::ops::Deref for EtcdTestShardSnapshot {
    type Target = ShardRecord;

    fn deref(&self) -> &Self::Target {
        &self.inner.record
    }
}

#[cfg(any(test, feature = "test-support"))]
impl std::ops::DerefMut for EtcdTestShardSnapshot {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner.record
    }
}

impl EtcdCoordinator {
    /// Execute a `put` RPC on the internal single-threaded Tokio runtime.
    #[cfg(any(test, feature = "test-support"))]
    fn etcd_put(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        options: Option<etcd_client::PutOptions>,
    ) -> Result<etcd_client::PutResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.put(key, value, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Put,
                source,
            })
    }

    /// Execute a `delete` RPC on the internal single-threaded Tokio runtime.
    #[cfg(any(test, feature = "test-support"))]
    fn etcd_delete(
        &self,
        key: Vec<u8>,
        options: Option<DeleteOptions>,
    ) -> Result<etcd_client::DeleteResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.delete(key, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Delete,
                source,
            })
    }

    /// Arm a one-shot fault injection hook for the next matching split
    /// operation.
    ///
    /// The flag clears itself whether the next transaction succeeds or fails,
    /// so tests must re-arm it before every independent fault scenario.
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

    /// Delete every key under this coordinator's namespace prefix.
    ///
    /// Appends a trailing `/` to the stored prefix before issuing the
    /// range-delete so that etcd's `with_prefix()` only matches keys
    /// nested under this namespace — without the separator, prefix
    /// `/foo/v1` would also match `/foo/v10/...`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_clear_namespace(&self) -> Result<(), EtcdCoordinatorError> {
        let mut bounded = self.keyspace.prefix().to_owned();
        if !bounded.ends_with('/') {
            bounded.push('/');
        }
        self.etcd_delete(
            bounded.into_bytes(),
            Some(DeleteOptions::new().with_prefix()),
        )?;
        Ok(())
    }

    /// Seed a run record directly into etcd.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_run_record(&self, record: &RunRecord) -> Result<(), EtcdCoordinatorError> {
        let key = self
            .keyspace
            .run_record_key(record.tenant, record.run)
            .into_bytes();
        let value = encode_run_record(record);
        self.etcd_put(key, value, None)?;
        Ok(())
    }

    /// Seed the active-run index marker for `run`.
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

    /// Seed the active-shard index marker for `shard`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_active_shard_index(
        &self,
        tenant: TenantId,
        run: RunId,
        shard: ShardId,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self
            .keyspace
            .shard_active_index_key(tenant, run, shard)
            .into_bytes();
        self.etcd_put(key, Vec::new(), None)?;
        Ok(())
    }

    /// Seed or overwrite the tenant shard counter key.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_seed_tenant_shard_count(
        &self,
        tenant: TenantId,
        count: u64,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.tenant_shard_count_key(tenant).into_bytes();
        self.etcd_put(key, super::encode_tenant_shard_count(count).to_vec(), None)?;
        Ok(())
    }

    /// Delete the tenant shard counter key.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_delete_tenant_shard_count(
        &self,
        tenant: TenantId,
    ) -> Result<(), EtcdCoordinatorError> {
        let key = self.keyspace.tenant_shard_count_key(tenant).into_bytes();
        self.etcd_delete(key, None)?;
        Ok(())
    }

    /// Load the tenant shard counter value.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_tenant_shard_count(
        &self,
        tenant: TenantId,
    ) -> Result<Option<u64>, EtcdCoordinatorError> {
        Ok(self
            .load_tenant_shard_count(tenant)?
            .map(|persisted| persisted.count))
    }

    /// Load the persisted owner binding and its etcd lease ID.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_owner_binding(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<(WorkerId, FenceEpoch, i64)>, EtcdCoordinatorError> {
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(owner_key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let binding = super::decode_owner_binding(EtcdOperation::Get, kv.value())?;
        Ok(Some((binding.worker, binding.fence, kv.lease())))
    }

    /// Load a shard record snapshot for assertion-heavy tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_shard_snapshot(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<EtcdTestShardSnapshot>, EtcdCoordinatorError> {
        Ok(self
            .load_shard_record(tenant, key)?
            .map(|inner| EtcdTestShardSnapshot { inner }))
    }

    /// Overwrite a shard record in etcd, bypassing all CAS guards.
    ///
    /// This allows integration tests to seed states that are not otherwise
    /// reachable yet, such as `Parked` while `park_shard` remains fail-closed.
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
        let value =
            encode_shard_record(record, slab).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Put,
                source,
            })?;
        self.etcd_put(key, value, None)?;
        Ok(())
    }

    /// Load a run record directly from etcd for assertion-heavy tests.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_load_run_snapshot(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<RunRecord>, EtcdCoordinatorError> {
        Ok(self
            .load_run_record(tenant, run)?
            .map(|persisted| persisted.record))
    }

    /// Return `true` when the active-shard index marker exists for `key`.
    #[cfg(any(test, feature = "test-support"))]
    pub fn test_active_shard_index_exists(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<bool, EtcdCoordinatorError> {
        let index_key = self
            .keyspace
            .shard_active_index_key(tenant, key.run(), key.shard())
            .into_bytes();
        let response = self.etcd_get(index_key, None)?;
        Ok(!response.kvs().is_empty())
    }

    /// Return `true` when the active-run index marker exists for `run`.
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

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn inject_split_replace_fault_if_armed(&mut self, tenant: TenantId, key: ShardKey) {
        self.maybe_drop_owner_before_split_replace_txn(tenant, key)
            .expect("test fault injection for split_replace must not fail");
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) fn inject_split_residual_fault_if_armed(&mut self, tenant: TenantId, key: ShardKey) {
        self.maybe_drop_owner_before_split_residual_txn(tenant, key)
            .expect("test fault injection for split_residual must not fail");
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub(super) fn inject_split_replace_fault_if_armed(
        &mut self,
        _tenant: TenantId,
        _key: ShardKey,
    ) {
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub(super) fn inject_split_residual_fault_if_armed(
        &mut self,
        _tenant: TenantId,
        _key: ShardKey,
    ) {
    }
}

impl AsyncEtcdCoordinator {
    /// Arm a one-shot fault injection hook for the next matching split
    /// operation.
    ///
    /// The flag clears itself whether the next transaction succeeds or fails,
    /// so tests must re-arm it before every independent fault scenario.
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
    async fn etcd_delete(
        &self,
        key: Vec<u8>,
        options: Option<etcd_client::DeleteOptions>,
    ) -> Result<etcd_client::DeleteResponse, crate::error::EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client.delete(key, options).await.map_err(|source| {
            crate::error::EtcdCoordinatorError::Etcd {
                operation: crate::error::EtcdOperation::Delete,
                source,
            }
        })
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn maybe_drop_owner_before_split_replace_txn(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<(), crate::error::EtcdCoordinatorError> {
        if !self.test_faults.drop_owner_before_next_split_replace_txn {
            return Ok(());
        }
        self.test_faults.drop_owner_before_next_split_replace_txn = false;
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        self.etcd_delete(owner_key, None).await?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    async fn maybe_drop_owner_before_split_residual_txn(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<(), crate::error::EtcdCoordinatorError> {
        if !self.test_faults.drop_owner_before_next_split_residual_txn {
            return Ok(());
        }
        self.test_faults.drop_owner_before_next_split_residual_txn = false;
        let owner_key = self
            .keyspace
            .shard_owner_key(tenant, key.run(), key.shard())
            .into_bytes();
        self.etcd_delete(owner_key, None).await?;
        Ok(())
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) async fn inject_split_replace_fault_if_armed(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) {
        self.maybe_drop_owner_before_split_replace_txn(tenant, key)
            .await
            .expect("test fault injection for split_replace must not fail");
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) async fn inject_split_residual_fault_if_armed(
        &mut self,
        tenant: TenantId,
        key: ShardKey,
    ) {
        self.maybe_drop_owner_before_split_residual_txn(tenant, key)
            .await
            .expect("test fault injection for split_residual must not fail");
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub(super) async fn inject_split_replace_fault_if_armed(
        &mut self,
        _tenant: TenantId,
        _key: ShardKey,
    ) {
    }

    #[cfg(not(any(test, feature = "test-support")))]
    pub(super) async fn inject_split_residual_fault_if_armed(
        &mut self,
        _tenant: TenantId,
        _key: ShardKey,
    ) {
    }
}
