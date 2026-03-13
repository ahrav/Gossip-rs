//! In-memory model of the etcd KV subset used by the coordination backend.
//!
//! The live backend only depends on linearizable point reads, prefix scans,
//! compare-and-swap transactions, and lease-backed key expiry. This module
//! models that subset in-process so deterministic simulations can exercise
//! the production transaction shapes without a live etcd server.
//!
//! # Fidelity gaps
//!
//! This model is intentionally simplified. Known divergences from real etcd:
//!
//! - **`DuplicateMutation`** — `put(k) → delete(k) → put(k)` in a single
//!   transaction is rejected, whereas real etcd allows it. The coordination
//!   backend never issues such patterns.
//! - **`lease_grant` does not advance revision** — real etcd bumps the global
//!   revision on every lease grant; this model only bumps on KV mutations.
//! - **Global revision starts at 0** — real etcd starts at 1. The first
//!   mutating transaction produces revision 1 in both systems.
//! - **Lease expiry boundary** — a lease with TTL *t* granted at time *T*
//!   expires when `now >= T + t` (i.e., alive for exactly *t* ticks). Real
//!   etcd uses a comparable but not identical heartbeat-based mechanism.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use etcd_client::proto::{
    PbCompare, PbCompareTarget, PbDeleteRequest, PbDeleteResponse, PbKeyValue,
    PbLeaseGrantResponse, PbLeaseRevokeResponse, PbPutRequest, PbPutResponse, PbRangeRequest,
    PbRangeResponse, PbResponseHeader, PbResponseOp, PbTargetUnion, PbTxnOpRequest,
    PbTxnOpResponse, PbTxnRequest, PbTxnResponse,
};
use etcd_client::{CompareOp, GetOptions, LeaseGrantResponse, LeaseRevokeResponse, Txn};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

const PPM_MAX: u32 = 1_000_000;

/// In-memory etcd model for deterministic simulation.
#[derive(Debug, Clone)]
pub struct SimulatedEtcdKV {
    kvs: BTreeMap<Vec<u8>, KvEntry>,
    revision: i64,
    leases: HashMap<i64, LeaseState>,
    next_lease_id: i64,
    now: u64,
    next_expiry: u64,
    fault_config: SimEtcdFaultConfig,
    rng: ChaCha8Rng,
}

impl SimulatedEtcdKV {
    /// Create an empty simulated etcd store with deterministic fault injection.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self::with_fault_config(seed, SimEtcdFaultConfig::default())
    }

    /// Create an empty simulated etcd store with an explicit fault profile.
    #[must_use]
    pub fn with_fault_config(seed: u64, fault_config: SimEtcdFaultConfig) -> Self {
        Self {
            kvs: BTreeMap::new(),
            revision: 0,
            leases: HashMap::new(),
            next_lease_id: 1,
            now: 0,
            next_expiry: u64::MAX,
            fault_config,
            rng: ChaCha8Rng::seed_from_u64(seed),
        }
    }

    /// Current global KV revision.
    #[must_use]
    pub fn revision(&self) -> i64 {
        self.revision
    }

    /// Current logical time used for lease expiry.
    #[must_use]
    pub fn now(&self) -> u64 {
        self.now
    }

    /// Number of live keys in the store (no side effects, no expiry).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.kvs.len()
    }

    /// Number of active leases (no side effects, no expiry).
    #[must_use]
    pub fn lease_count(&self) -> usize {
        self.leases.len()
    }

    /// Whether the store contains the given key (no side effects, no expiry).
    #[must_use]
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.kvs.contains_key(key)
    }

    /// All keys sharing the given prefix, in lexicographic order.
    ///
    /// Pure inspection — does not trigger lease expiry.
    #[must_use]
    pub fn keys_with_prefix(&self, prefix: &[u8]) -> Vec<&[u8]> {
        self.kvs
            .range(prefix.to_vec()..)
            .take_while(|(k, _)| k.starts_with(prefix))
            .map(|(k, _)| k.as_slice())
            .collect()
    }

    /// Summary of a single lease, if it exists.
    ///
    /// Pure inspection — does not trigger lease expiry.
    #[must_use]
    pub fn lease_info(&self, lease_id: i64) -> Option<LeaseInfo> {
        self.leases.get(&lease_id).map(|ls| LeaseInfo {
            ttl: ls.ttl,
            expires_at: ls.expires_at,
            attached_key_count: ls.attached_keys.len(),
        })
    }

    /// Set the logical clock without triggering lease expiry.
    ///
    /// Use [`Self::tick`] for normal time advancement; this method lets
    /// the simulation driver position the clock before an explicit
    /// [`Self::expire_due_leases`] call.
    ///
    /// # Panics
    ///
    /// Panics if `t < self.now` — simulation time must be monotonic.
    pub fn set_time(&mut self, t: u64) {
        assert!(
            t >= self.now,
            "SimulatedEtcdKV time must be monotonic (attempted {t}, current {})",
            self.now
        );
        self.now = t;
    }

    /// Replace the fault configuration mid-simulation.
    pub fn set_fault_config(&mut self, config: SimEtcdFaultConfig) {
        self.fault_config = config;
    }

    /// Linearizable get over the modeled keyspace.
    pub fn get(
        &mut self,
        key: impl Into<Vec<u8>>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, SimEtcdError> {
        self.expire_due_leases();
        if self
            .fault_config
            .should_fail(SimEtcdOperation::Get, &mut self.rng)
        {
            return Err(SimEtcdError::FaultInjected {
                operation: SimEtcdOperation::Get,
            });
        }

        let mut request: PbRangeRequest = options.unwrap_or_default().into();
        request.key = key.into();

        if request.revision > 0 {
            return Err(SimEtcdError::UnsupportedGetOption {
                detail: "historical revisions are not modeled",
            });
        }
        if request.serializable {
            return Err(SimEtcdError::UnsupportedGetOption {
                detail: "serializable reads are not distinct in the simulator",
            });
        }
        if request.sort_order != 0 || request.sort_target != 0 {
            return Err(SimEtcdError::UnsupportedGetOption {
                detail: "custom sort order is not modeled",
            });
        }

        let matched = self.matching_keys(&request.key, &request.range_end)?;
        let filtered: Vec<_> = matched
            .into_iter()
            .filter(|(_, entry)| passes_revision_filters(&request, entry))
            .collect();

        let total_count = i64::try_from(filtered.len()).unwrap_or(i64::MAX);
        if request.count_only {
            return Ok(build_get_response(
                self.revision,
                Vec::new(),
                false,
                total_count,
            ));
        }

        let limit = usize::try_from(request.limit.max(0)).unwrap_or(usize::MAX);
        let more = limit != 0 && filtered.len() > limit;
        let take_count = if limit == 0 {
            filtered.len()
        } else {
            filtered.len().min(limit)
        };

        let kvs = filtered
            .into_iter()
            .take(take_count)
            .map(|(key, entry)| entry.to_pb_key_value(key.clone(), request.keys_only))
            .collect();

        Ok(build_get_response(self.revision, kvs, more, total_count))
    }

    /// Atomic compare-and-swap transaction over the modeled keyspace.
    pub fn txn(&mut self, txn: Txn) -> Result<etcd_client::TxnResponse, SimEtcdError> {
        self.expire_due_leases();
        if self
            .fault_config
            .should_fail(SimEtcdOperation::Txn, &mut self.rng)
        {
            return Err(SimEtcdError::FaultInjected {
                operation: SimEtcdOperation::Txn,
            });
        }

        let request: PbTxnRequest = txn.into();
        if !request.failure.is_empty() {
            return Err(SimEtcdError::UnsupportedTxnOp {
                detail: "failure branches are not modeled",
            });
        }

        let compares_succeeded = request
            .compare
            .iter()
            .try_fold(true, |all_match, compare| {
                if !all_match {
                    return Ok(false);
                }
                self.evaluate_compare(compare)
            })?;
        if !compares_succeeded {
            return Ok(build_txn_response(self.revision, false, Vec::new()));
        }

        let staged = self.stage_success_ops(&request.success)?;
        if staged.ops.is_empty() {
            return Ok(build_txn_response(self.revision, true, Vec::new()));
        }

        let revision = if staged.changed {
            self.bump_revision()
        } else {
            self.revision
        };
        let responses = self.apply_staged_txn(staged, revision);
        Ok(build_txn_response(revision, true, responses))
    }

    /// Grant a new lease with a fixed TTL in simulation ticks.
    pub fn lease_grant(&mut self, ttl: i64) -> Result<LeaseGrantResponse, SimEtcdError> {
        self.expire_due_leases();
        if self
            .fault_config
            .should_fail(SimEtcdOperation::LeaseGrant, &mut self.rng)
        {
            return Err(SimEtcdError::FaultInjected {
                operation: SimEtcdOperation::LeaseGrant,
            });
        }
        if ttl <= 0 {
            return Err(SimEtcdError::InvalidLeaseTtl { ttl });
        }

        let lease_id = self.next_lease_id;
        self.next_lease_id = self
            .next_lease_id
            .checked_add(1)
            .ok_or(SimEtcdError::LeaseIdExhausted)?;

        let ttl_u64 = u64::try_from(ttl).expect("TTL validated positive");
        let expires_at = self
            .now
            .checked_add(ttl_u64)
            .expect("lease expiry overflow");
        self.leases.insert(
            lease_id,
            LeaseState {
                ttl: ttl_u64,
                expires_at,
                attached_keys: BTreeSet::new(),
            },
        );
        self.next_expiry = self.next_expiry.min(expires_at);

        Ok(build_lease_grant_response(self.revision, lease_id, ttl))
    }

    /// Keep an existing lease alive for another full TTL interval.
    pub fn lease_keep_alive_once(&mut self, lease_id: i64) -> Result<(), SimEtcdError> {
        self.expire_due_leases();
        if self
            .fault_config
            .should_fail(SimEtcdOperation::LeaseKeepAlive, &mut self.rng)
        {
            return Err(SimEtcdError::FaultInjected {
                operation: SimEtcdOperation::LeaseKeepAlive,
            });
        }

        let lease = self
            .leases
            .get_mut(&lease_id)
            .ok_or(SimEtcdError::LeaseNotFound { lease_id })?;
        lease.expires_at = self
            .now
            .checked_add(lease.ttl)
            .expect("lease keep-alive overflow");
        self.next_expiry = self.next_expiry.min(lease.expires_at);
        Ok(())
    }

    /// Revoke a lease and delete all keys still attached to it.
    pub fn lease_revoke(&mut self, lease_id: i64) -> Result<LeaseRevokeResponse, SimEtcdError> {
        self.expire_due_leases();
        if self
            .fault_config
            .should_fail(SimEtcdOperation::LeaseRevoke, &mut self.rng)
        {
            return Err(SimEtcdError::FaultInjected {
                operation: SimEtcdOperation::LeaseRevoke,
            });
        }

        let deleted_any = self.remove_lease_and_keys(lease_id)?;
        self.debug_assert_no_stale_lease_keys(lease_id);
        let revision = if deleted_any {
            self.bump_revision()
        } else {
            self.revision
        };

        Ok(build_lease_revoke_response(revision))
    }

    /// Advance logical time and expire any leases that have elapsed.
    pub fn tick(&mut self, dt: u64) {
        self.now = self
            .now
            .checked_add(dt)
            .expect("SimulatedEtcdKV clock overflow");
        self.expire_due_leases();
    }

    fn evaluate_compare(&self, compare: &PbCompare) -> Result<bool, SimEtcdError> {
        if !compare.range_end.is_empty() {
            return Err(SimEtcdError::UnsupportedCompare {
                detail: "range compares are not modeled",
            });
        }

        let entry = self.kvs.get(&compare.key);
        let compare_op =
            CompareOp::try_from(compare.result).map_err(|_| SimEtcdError::UnsupportedCompare {
                detail: "unknown compare operator",
            })?;
        let target = compare
            .target_union
            .as_ref()
            .ok_or(SimEtcdError::MalformedCompare {
                detail: "compare is missing a target value",
            })?;

        let matched = match (compare.target, target) {
            (x, PbTargetUnion::Version(expected)) if x == PbCompareTarget::Version as i32 => {
                compare_i64(actual_version(entry), *expected, compare_op)
            }
            (x, PbTargetUnion::CreateRevision(expected)) if x == PbCompareTarget::Create as i32 => {
                compare_i64(actual_create_revision(entry), *expected, compare_op)
            }
            (x, PbTargetUnion::ModRevision(expected)) if x == PbCompareTarget::Mod as i32 => {
                compare_i64(actual_mod_revision(entry), *expected, compare_op)
            }
            (x, PbTargetUnion::Lease(expected)) if x == PbCompareTarget::Lease as i32 => {
                compare_i64(actual_lease(entry), *expected, compare_op)
            }
            (x, PbTargetUnion::Value(expected)) if x == PbCompareTarget::Value as i32 => {
                compare_bytes(actual_value(entry), expected, compare_op)
            }
            _ => {
                return Err(SimEtcdError::UnsupportedCompare {
                    detail: "compare target does not match its value payload",
                });
            }
        };

        Ok(matched)
    }

    fn stage_success_ops(
        &self,
        ops: &[etcd_client::proto::PbTxnRequestOp],
    ) -> Result<StagedTxn, SimEtcdError> {
        let mut staged = StagedTxn::default();

        for op in ops {
            match op.request.as_ref().ok_or(SimEtcdError::MalformedTxn {
                detail: "transaction op is missing its request payload",
            })? {
                PbTxnOpRequest::RequestPut(request) => self.stage_put(request, &mut staged)?,
                PbTxnOpRequest::RequestDeleteRange(request) => {
                    self.stage_delete(request, &mut staged)?
                }
                PbTxnOpRequest::RequestRange(_) => {
                    return Err(SimEtcdError::UnsupportedTxnOp {
                        detail: "range ops inside transactions are not modeled",
                    });
                }
                PbTxnOpRequest::RequestTxn(_) => {
                    return Err(SimEtcdError::UnsupportedTxnOp {
                        detail: "nested transactions are not modeled",
                    });
                }
            }
        }

        Ok(staged)
    }

    fn stage_put(
        &self,
        request: &PbPutRequest,
        staged: &mut StagedTxn,
    ) -> Result<(), SimEtcdError> {
        if request.ignore_value || request.ignore_lease {
            return Err(SimEtcdError::UnsupportedTxnOp {
                detail: "ignore_value and ignore_lease are not modeled",
            });
        }
        if request.lease != 0 && !self.leases.contains_key(&request.lease) {
            return Err(SimEtcdError::LeaseNotFound {
                lease_id: request.lease,
            });
        }
        if !staged.all_put_keys.insert(request.key.clone()) {
            return Err(SimEtcdError::DuplicateMutation {
                key: request.key.clone(),
            });
        }
        staged.pending_puts.insert(request.key.clone());
        staged.ops.push(StagedOp::Put(StagedPut {
            key: request.key.clone(),
            value: request.value.clone(),
            lease_id: request.lease,
        }));
        staged.changed = true;
        Ok(())
    }

    /// Stage delete operations, resolving against both the pre-transaction
    /// store and any previously staged puts (so that `put(k)` followed by
    /// `delete(k)` in the same txn correctly targets k).
    fn stage_delete(
        &self,
        request: &PbDeleteRequest,
        staged: &mut StagedTxn,
    ) -> Result<(), SimEtcdError> {
        let mut keys_to_delete: BTreeSet<Vec<u8>> = BTreeSet::new();

        // Match against pre-transaction store.
        let matched = self.matching_keys(&request.key, &request.range_end)?;
        for (key, _) in matched {
            keys_to_delete.insert(key.clone());
        }

        // Also match against previously staged puts so that a delete can
        // target a key created by an earlier put in the same transaction.
        if request.range_end.is_empty() {
            // Point delete.
            if staged.pending_puts.contains(&request.key) {
                keys_to_delete.insert(request.key.clone());
            }
        } else if request.range_end == [0] {
            // From-key or all-keys sentinel.
            if request.key.is_empty() {
                keys_to_delete.extend(staged.pending_puts.iter().cloned());
            } else {
                keys_to_delete.extend(staged.pending_puts.range(request.key.clone()..).cloned());
            }
        } else {
            // Explicit half-open range: empty if key >= range_end.
            if request.key < request.range_end {
                keys_to_delete.extend(
                    staged
                        .pending_puts
                        .range(request.key.clone()..request.range_end.clone())
                        .cloned(),
                );
            }
        }

        let keys: Vec<Vec<u8>> = keys_to_delete.into_iter().collect();
        for key in &keys {
            staged.pending_puts.remove(key);
        }
        if !keys.is_empty() {
            staged.changed = true;
        }
        staged.ops.push(StagedOp::DeleteRange(keys));
        Ok(())
    }

    /// Replay staged operations in the order they were recorded, matching
    /// etcd's sequential execution of transaction success ops.
    fn apply_staged_txn(&mut self, staged: StagedTxn, revision: i64) -> Vec<PbResponseOp> {
        let header = Some(response_header(revision));
        let mut responses = Vec::with_capacity(staged.ops.len());
        for op in staged.ops {
            match op {
                StagedOp::Put(put) => {
                    self.put_key(put, revision);
                    responses.push(PbResponseOp {
                        response: Some(PbTxnOpResponse::ResponsePut(PbPutResponse {
                            header,
                            prev_kv: None,
                        })),
                    });
                }
                StagedOp::DeleteRange(keys) => {
                    let mut deleted = 0i64;
                    for key in keys {
                        if self.kvs.contains_key(&key) {
                            deleted += 1;
                        }
                        self.delete_key(&key);
                    }
                    responses.push(PbResponseOp {
                        response: Some(PbTxnOpResponse::ResponseDeleteRange(PbDeleteResponse {
                            header,
                            deleted,
                            prev_kvs: Vec::new(),
                        })),
                    });
                }
            }
        }
        responses
    }

    fn put_key(&mut self, put: StagedPut, revision: i64) {
        self.detach_key_from_lease(&put.key);
        match self.kvs.get_mut(&put.key) {
            Some(entry) => {
                entry.value = put.value;
                entry.mod_revision = revision;
                entry.version = entry.version.saturating_add(1);
                entry.lease_id = put.lease_id;
            }
            None => {
                self.kvs.insert(
                    put.key.clone(),
                    KvEntry {
                        value: put.value,
                        create_revision: revision,
                        mod_revision: revision,
                        version: 1,
                        lease_id: put.lease_id,
                    },
                );
            }
        }

        if put.lease_id != 0 {
            self.leases
                .get_mut(&put.lease_id)
                .expect("validated lease must exist")
                .attached_keys
                .insert(put.key);
        }
    }

    fn delete_key(&mut self, key: &[u8]) {
        self.detach_key_from_lease(key);
        self.kvs.remove(key);
    }

    fn detach_key_from_lease(&mut self, key: &[u8]) {
        let lease_id = self.kvs.get(key).map(|entry| entry.lease_id).unwrap_or(0);
        if lease_id == 0 {
            return;
        }
        if let Some(lease) = self.leases.get_mut(&lease_id) {
            lease.attached_keys.remove(key);
        }
    }

    fn remove_lease_and_keys(&mut self, lease_id: i64) -> Result<bool, SimEtcdError> {
        let lease = self
            .leases
            .remove(&lease_id)
            .ok_or(SimEtcdError::LeaseNotFound { lease_id })?;
        let mut deleted_any = false;
        for key in lease.attached_keys {
            if self
                .kvs
                .get(&key)
                .is_some_and(|entry| entry.lease_id == lease_id)
            {
                self.kvs.remove(&key);
                deleted_any = true;
            }
        }
        Ok(deleted_any)
    }

    fn debug_assert_no_stale_lease_keys(&self, lease_id: i64) {
        debug_assert!(
            !self.kvs.values().any(|e| e.lease_id == lease_id),
            "stale keys referencing revoked lease {lease_id}"
        );
    }

    /// Expire all leases whose TTL has elapsed at the current logical time.
    ///
    /// Called automatically by every mutating operation. Exposed publicly so
    /// the simulation driver can decouple clock advancement ([`Self::set_time`])
    /// from expiry processing.
    pub fn expire_due_leases(&mut self) {
        if self.now < self.next_expiry {
            return;
        }

        let mut expired: Vec<i64> = self
            .leases
            .iter()
            .filter_map(|(lease_id, state)| (state.expires_at <= self.now).then_some(*lease_id))
            .collect();
        expired.sort_unstable();

        for lease_id in expired {
            let deleted_any = match self.remove_lease_and_keys(lease_id) {
                Ok(deleted_any) => deleted_any,
                Err(SimEtcdError::LeaseNotFound { .. }) => false,
                Err(_) => {
                    debug_assert!(false, "unexpected error during lease expiry");
                    continue;
                }
            };
            self.debug_assert_no_stale_lease_keys(lease_id);
            if deleted_any {
                self.bump_revision();
            }
        }

        self.next_expiry = self
            .leases
            .values()
            .map(|ls| ls.expires_at)
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Resolve the set of keys matching an etcd key+range_end pair.
    ///
    /// `range_end` semantics follow the etcd v3 API:
    /// - empty → point lookup on `key`
    /// - `[0]` + empty key → all keys
    /// - `[0]` + non-empty key → all keys >= `key` (from-key scan)
    /// - otherwise → half-open range `[key, range_end)`
    fn matching_keys<'a>(
        &'a self,
        key: &[u8],
        range_end: &[u8],
    ) -> Result<Vec<(&'a Vec<u8>, &'a KvEntry)>, SimEtcdError> {
        if range_end.is_empty() {
            return Ok(self
                .kvs
                .get_key_value(key)
                .into_iter()
                .collect::<Vec<(&Vec<u8>, &KvEntry)>>());
        }

        if range_end == [0] {
            if key.is_empty() {
                return Ok(self.kvs.iter().collect());
            }
            return Ok(self.kvs.range(key.to_vec()..).collect());
        }

        if key >= range_end {
            return Ok(Vec::new());
        }
        Ok(self.kvs.range(key.to_vec()..range_end.to_vec()).collect())
    }

    fn bump_revision(&mut self) -> i64 {
        self.revision = self.revision.checked_add(1).expect("revision overflow");
        self.revision
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KvEntry {
    value: Vec<u8>,
    create_revision: i64,
    mod_revision: i64,
    version: i64,
    lease_id: i64,
}

impl KvEntry {
    fn to_pb_key_value(&self, key: Vec<u8>, keys_only: bool) -> PbKeyValue {
        PbKeyValue {
            key,
            create_revision: self.create_revision,
            mod_revision: self.mod_revision,
            version: self.version,
            value: if keys_only {
                Vec::new()
            } else {
                self.value.clone()
            },
            lease: self.lease_id,
        }
    }
}

/// Read-only snapshot of a single lease's state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseInfo {
    /// TTL in simulation ticks.
    pub ttl: u64,
    /// Absolute tick at which the lease expires.
    pub expires_at: u64,
    /// Number of keys currently attached to this lease.
    pub attached_key_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LeaseState {
    ttl: u64,
    expires_at: u64,
    attached_keys: BTreeSet<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StagedPut {
    key: Vec<u8>,
    value: Vec<u8>,
    lease_id: i64,
}

/// Single staged operation in execution order.
#[derive(Debug)]
enum StagedOp {
    Put(StagedPut),
    /// All keys matched by a single delete-range request, applied as one batch.
    DeleteRange(Vec<Vec<u8>>),
}

/// Accumulated state for a transaction's success branch.
///
/// Operations are recorded in the order they appear in the request so that
/// `apply_staged_txn` can replay them sequentially — matching real etcd's
/// in-order execution of success ops.
///
/// Limitation: `all_put_keys` is never cleared, so `put(k) → delete(k) →
/// put(k)` within a single transaction is rejected with `DuplicateMutation`.
/// Real etcd allows this sequence. The simplification is acceptable because
/// the coordination backend never issues such patterns.
#[derive(Debug, Default)]
struct StagedTxn {
    ops: Vec<StagedOp>,
    /// Keys staged for put that have not yet been cancelled by a later delete.
    /// Used so that `stage_delete` can resolve against previously staged puts
    /// in addition to the pre-transaction store.
    pending_puts: BTreeSet<Vec<u8>>,
    /// Keys already staged for put (including those later deleted).
    /// Guards against two puts to the same key in the same transaction.
    all_put_keys: BTreeSet<Vec<u8>>,
    changed: bool,
}

/// Deterministic simulator fault configuration using integer PPM rates.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SimEtcdFaultConfig {
    get_failure_ppm: u32,
    txn_failure_ppm: u32,
    lease_grant_failure_ppm: u32,
    lease_keep_alive_failure_ppm: u32,
    lease_revoke_failure_ppm: u32,
}

impl SimEtcdFaultConfig {
    /// Override the get-failure rate.
    #[must_use]
    pub fn with_get_failure_ppm(mut self, ppm: u32) -> Self {
        self.get_failure_ppm = validate_ppm(ppm);
        self
    }

    /// Override the transaction-failure rate.
    #[must_use]
    pub fn with_txn_failure_ppm(mut self, ppm: u32) -> Self {
        self.txn_failure_ppm = validate_ppm(ppm);
        self
    }

    /// Override the lease-grant failure rate.
    #[must_use]
    pub fn with_lease_grant_failure_ppm(mut self, ppm: u32) -> Self {
        self.lease_grant_failure_ppm = validate_ppm(ppm);
        self
    }

    /// Override the keep-alive failure rate.
    #[must_use]
    pub fn with_lease_keep_alive_failure_ppm(mut self, ppm: u32) -> Self {
        self.lease_keep_alive_failure_ppm = validate_ppm(ppm);
        self
    }

    /// Override the lease-revoke failure rate.
    #[must_use]
    pub fn with_lease_revoke_failure_ppm(mut self, ppm: u32) -> Self {
        self.lease_revoke_failure_ppm = validate_ppm(ppm);
        self
    }

    fn should_fail(&self, op: SimEtcdOperation, rng: &mut ChaCha8Rng) -> bool {
        let ppm = match op {
            SimEtcdOperation::Get => self.get_failure_ppm,
            SimEtcdOperation::Txn => self.txn_failure_ppm,
            SimEtcdOperation::LeaseGrant => self.lease_grant_failure_ppm,
            SimEtcdOperation::LeaseKeepAlive => self.lease_keep_alive_failure_ppm,
            SimEtcdOperation::LeaseRevoke => self.lease_revoke_failure_ppm,
        };
        should_inject(rng, ppm)
    }
}

/// Operation kind used in deterministic fault errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SimEtcdOperation {
    Get,
    Txn,
    LeaseGrant,
    LeaseKeepAlive,
    LeaseRevoke,
}

/// Errors returned by the in-memory etcd model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimEtcdError {
    FaultInjected { operation: SimEtcdOperation },
    InvalidLeaseTtl { ttl: i64 },
    LeaseNotFound { lease_id: i64 },
    LeaseIdExhausted,
    DuplicateMutation { key: Vec<u8> },
    UnsupportedGetOption { detail: &'static str },
    UnsupportedCompare { detail: &'static str },
    UnsupportedTxnOp { detail: &'static str },
    MalformedCompare { detail: &'static str },
    MalformedTxn { detail: &'static str },
}

impl fmt::Display for SimEtcdError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FaultInjected { operation } => {
                write!(f, "fault injected while handling {:?}", operation)
            }
            Self::InvalidLeaseTtl { ttl } => {
                write!(f, "lease TTL must be positive, got {ttl}")
            }
            Self::LeaseNotFound { lease_id } => write!(f, "lease {lease_id} was not found"),
            Self::LeaseIdExhausted => f.write_str("lease id space exhausted"),
            Self::DuplicateMutation { key } => {
                write!(f, "transaction mutates the same key twice: {:?}", key)
            }
            Self::UnsupportedGetOption { detail }
            | Self::UnsupportedCompare { detail }
            | Self::UnsupportedTxnOp { detail }
            | Self::MalformedCompare { detail }
            | Self::MalformedTxn { detail } => f.write_str(detail),
        }
    }
}

impl std::error::Error for SimEtcdError {}

fn build_get_response(
    revision: i64,
    kvs: Vec<PbKeyValue>,
    more: bool,
    count: i64,
) -> etcd_client::GetResponse {
    etcd_client::GetResponse(PbRangeResponse {
        header: Some(response_header(revision)),
        kvs,
        more,
        count,
    })
}

fn build_txn_response(
    revision: i64,
    succeeded: bool,
    responses: Vec<PbResponseOp>,
) -> etcd_client::TxnResponse {
    etcd_client::TxnResponse(PbTxnResponse {
        header: Some(response_header(revision)),
        succeeded,
        responses,
    })
}

fn build_lease_grant_response(revision: i64, lease_id: i64, ttl: i64) -> LeaseGrantResponse {
    LeaseGrantResponse(PbLeaseGrantResponse {
        header: Some(response_header(revision)),
        id: lease_id,
        ttl,
        error: String::new(),
    })
}

fn build_lease_revoke_response(revision: i64) -> LeaseRevokeResponse {
    LeaseRevokeResponse(PbLeaseRevokeResponse {
        header: Some(response_header(revision)),
    })
}

fn response_header(revision: i64) -> PbResponseHeader {
    PbResponseHeader {
        revision,
        ..Default::default()
    }
}

fn validate_ppm(ppm: u32) -> u32 {
    assert!(ppm <= PPM_MAX, "PPM rate {ppm} exceeds maximum {PPM_MAX}");
    ppm
}

fn should_inject(rng: &mut ChaCha8Rng, ppm: u32) -> bool {
    if ppm == 0 {
        return false;
    }
    rng.random_range(0u32..PPM_MAX) < ppm
}

fn passes_revision_filters(request: &PbRangeRequest, entry: &KvEntry) -> bool {
    if request.min_mod_revision > 0 && entry.mod_revision < request.min_mod_revision {
        return false;
    }
    if request.max_mod_revision > 0 && entry.mod_revision > request.max_mod_revision {
        return false;
    }
    if request.min_create_revision > 0 && entry.create_revision < request.min_create_revision {
        return false;
    }
    if request.max_create_revision > 0 && entry.create_revision > request.max_create_revision {
        return false;
    }
    true
}

fn actual_version(entry: Option<&KvEntry>) -> i64 {
    entry.map_or(0, |entry| entry.version)
}

fn actual_create_revision(entry: Option<&KvEntry>) -> i64 {
    entry.map_or(0, |entry| entry.create_revision)
}

fn actual_mod_revision(entry: Option<&KvEntry>) -> i64 {
    entry.map_or(0, |entry| entry.mod_revision)
}

fn actual_lease(entry: Option<&KvEntry>) -> i64 {
    entry.map_or(0, |entry| entry.lease_id)
}

fn actual_value(entry: Option<&KvEntry>) -> &[u8] {
    entry.map_or(&[], |entry| entry.value.as_slice())
}

fn compare_i64(actual: i64, expected: i64, op: CompareOp) -> bool {
    match op {
        CompareOp::Equal => actual == expected,
        CompareOp::Greater => actual > expected,
        CompareOp::Less => actual < expected,
        CompareOp::NotEqual => actual != expected,
    }
}

fn compare_bytes(actual: &[u8], expected: &[u8], op: CompareOp) -> bool {
    match op {
        CompareOp::Equal => actual == expected,
        CompareOp::Greater => actual > expected,
        CompareOp::Less => actual < expected,
        CompareOp::NotEqual => actual != expected,
    }
}

#[cfg(test)]
mod tests {
    use super::{SimEtcdError, SimEtcdFaultConfig, SimulatedEtcdKV};
    use etcd_client::{Compare, CompareOp, GetOptions, PutOptions, Txn, TxnOp};

    #[test]
    fn prefix_scan_is_lexicographic_and_supports_keys_only_and_count_only() {
        let mut kv = SimulatedEtcdKV::new(1);
        put_absent(&mut kv, b"/runs/2", b"b");
        put_absent(&mut kv, b"/runs/1", b"a");
        put_absent(&mut kv, b"/runs/3", b"c");

        let response = kv
            .get(b"/runs/".to_vec(), Some(GetOptions::new().with_prefix()))
            .expect("prefix scan should succeed");
        let keys: Vec<Vec<u8>> = response.kvs().iter().map(|kv| kv.key().to_vec()).collect();
        assert_eq!(
            keys,
            vec![
                b"/runs/1".to_vec(),
                b"/runs/2".to_vec(),
                b"/runs/3".to_vec()
            ]
        );

        let keys_only = kv
            .get(
                b"/runs/".to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .expect("keys-only prefix scan should succeed");
        assert!(keys_only.kvs().iter().all(|kv| kv.value().is_empty()));

        let count_only = kv
            .get(
                b"/runs/".to_vec(),
                Some(GetOptions::new().with_prefix().with_count_only()),
            )
            .expect("count-only prefix scan should succeed");
        assert!(count_only.kvs().is_empty());
        assert_eq!(count_only.count(), 3);
    }

    #[test]
    fn successful_multi_key_cas_is_atomic_and_failed_compare_keeps_state() {
        let mut kv = SimulatedEtcdKV::new(2);
        put_absent(&mut kv, b"a", b"old-a");
        put_absent(&mut kv, b"b", b"old-b");

        let a_mod = get_exact(&mut kv, b"a").mod_revision();
        let b_mod = get_exact(&mut kv, b"b").mod_revision();

        let txn = Txn::new()
            .when(vec![
                Compare::mod_revision(b"a", CompareOp::Equal, a_mod),
                Compare::mod_revision(b"b", CompareOp::Equal, b_mod),
            ])
            .and_then(vec![
                TxnOp::put(b"a", b"new-a", None),
                TxnOp::put(b"b", b"new-b", None),
            ]);
        let response = kv.txn(txn).expect("CAS should succeed");
        assert!(response.succeeded());

        let a = get_exact(&mut kv, b"a");
        let b = get_exact(&mut kv, b"b");
        assert_eq!(a.value(), b"new-a");
        assert_eq!(b.value(), b"new-b");
        assert_eq!(a.mod_revision(), b.mod_revision());

        let failed = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::mod_revision(b"a", CompareOp::Equal, a_mod)])
                    .and_then(vec![TxnOp::put(b"a", b"never", None)]),
            )
            .expect("stale compare should still return a txn response");
        assert!(!failed.succeeded());
        assert_eq!(get_exact(&mut kv, b"a").value(), b"new-a");
    }

    #[test]
    fn create_revision_resets_after_delete_and_recreate() {
        let mut kv = SimulatedEtcdKV::new(3);
        put_absent(&mut kv, b"alpha", b"v1");
        let first = get_exact(&mut kv, b"alpha");
        assert_eq!(first.create_revision(), 1);
        assert_eq!(first.mod_revision(), 1);
        assert_eq!(first.version(), 1);

        kv.txn(
            Txn::new()
                .when(vec![Compare::mod_revision(
                    b"alpha",
                    CompareOp::Equal,
                    first.mod_revision(),
                )])
                .and_then(vec![TxnOp::put(b"alpha", b"v2", None)]),
        )
        .expect("update should succeed");
        let updated = get_exact(&mut kv, b"alpha");
        assert_eq!(updated.create_revision(), 1);
        assert_eq!(updated.mod_revision(), 2);
        assert_eq!(updated.version(), 2);

        kv.txn(
            Txn::new()
                .when(vec![Compare::mod_revision(
                    b"alpha",
                    CompareOp::Equal,
                    updated.mod_revision(),
                )])
                .and_then(vec![TxnOp::delete(b"alpha", None)]),
        )
        .expect("delete should succeed");
        assert!(
            kv.get(b"alpha".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty()
        );

        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"alpha",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(b"alpha", b"v3", None)]),
        )
        .expect("recreate should succeed");
        let recreated = get_exact(&mut kv, b"alpha");
        assert_eq!(recreated.create_revision(), 4);
        assert_eq!(recreated.mod_revision(), 4);
        assert_eq!(recreated.version(), 1);
    }

    #[test]
    fn keep_alive_extends_lease_and_tick_expires_attached_keys() {
        let mut kv = SimulatedEtcdKV::new(4);
        let lease = kv.lease_grant(5).expect("lease grant should succeed");

        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"owned",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(
                    b"owned",
                    b"value",
                    Some(PutOptions::new().with_lease(lease.id())),
                )]),
        )
        .expect("lease-attached put should succeed");

        kv.tick(4);
        assert_eq!(get_exact(&mut kv, b"owned").value(), b"value");

        kv.lease_keep_alive_once(lease.id())
            .expect("keep alive should succeed");
        kv.tick(4);
        assert_eq!(get_exact(&mut kv, b"owned").value(), b"value");

        kv.tick(1);
        assert!(
            kv.get(b"owned".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty()
        );
    }

    #[test]
    fn revoke_deletes_attached_keys_immediately() {
        let mut kv = SimulatedEtcdKV::new(5);
        let lease = kv.lease_grant(10).expect("lease grant should succeed");
        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"revoked",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(
                    b"revoked",
                    b"value",
                    Some(PutOptions::new().with_lease(lease.id())),
                )]),
        )
        .expect("lease-attached put should succeed");

        kv.lease_revoke(lease.id())
            .expect("lease revoke should succeed");
        assert!(
            kv.get(b"revoked".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty()
        );
    }

    #[test]
    fn fault_config_can_deterministically_fail_operations() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            6,
            SimEtcdFaultConfig::default().with_txn_failure_ppm(1_000_000),
        );
        let err = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"fault",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![TxnOp::put(b"fault", b"value", None)]),
            )
            .expect_err("txn should deterministically fail");
        assert!(matches!(
            err,
            SimEtcdError::FaultInjected {
                operation: super::SimEtcdOperation::Txn
            }
        ));
        assert!(
            kv.get(b"fault".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty()
        );
    }

    fn put_absent(kv: &mut SimulatedEtcdKV, key: &[u8], value: &[u8]) {
        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(key, CompareOp::Equal, 0)])
                .and_then(vec![TxnOp::put(key, value, None)]),
        )
        .expect("initial put should succeed");
    }

    fn get_exact(kv: &mut SimulatedEtcdKV, key: &[u8]) -> etcd_client::KeyValue {
        kv.get(key.to_vec(), None)
            .expect("get should succeed")
            .take_kvs()
            .into_iter()
            .next()
            .expect("key should exist")
    }

    /// `with_from_key()` (range_end=[0]) returns all keys >= the start key,
    /// not just keys sharing the start key's prefix.
    #[test]
    fn from_key_get_returns_all_keys_gte_start() {
        let mut kv = SimulatedEtcdKV::new(101);
        put_absent(&mut kv, b"/a/1", b"a1");
        put_absent(&mut kv, b"/a/2", b"a2");
        put_absent(&mut kv, b"/b/1", b"b1");
        put_absent(&mut kv, b"/c/1", b"c1");

        let resp = kv
            .get(b"/a/".to_vec(), Some(GetOptions::new().with_from_key()))
            .expect("from_key get should succeed");

        let keys: Vec<Vec<u8>> = resp.kvs().iter().map(|kv| kv.key().to_vec()).collect();
        assert_eq!(
            keys,
            vec![
                b"/a/1".to_vec(),
                b"/a/2".to_vec(),
                b"/b/1".to_vec(),
                b"/c/1".to_vec(),
            ],
            "from_key should return ALL keys >= start, not just prefix matches"
        );
    }

    /// put(k) followed by delete(k) in the same txn leaves k absent, matching
    /// etcd's in-order execution of success ops.
    #[test]
    fn txn_put_then_delete_same_absent_key_leaves_key_absent() {
        let mut kv = SimulatedEtcdKV::new(102);

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"ephemeral",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![
                        TxnOp::put(b"ephemeral", b"value", None),
                        TxnOp::delete(b"ephemeral", None),
                    ]),
            )
            .expect("txn should succeed");
        assert!(resp.succeeded());

        let get_resp = kv
            .get(b"ephemeral".to_vec(), None)
            .expect("get should succeed");
        assert!(
            get_resp.kvs().is_empty(),
            "key should be absent after put-then-delete in same txn"
        );
    }

    /// Reversed range bounds (key >= range_end) must not panic; real etcd
    /// returns an empty result set for such queries.
    #[test]
    fn reversed_range_bounds_returns_empty_without_panic() {
        let mut kv = SimulatedEtcdKV::new(105);
        put_absent(&mut kv, b"a", b"v");
        put_absent(&mut kv, b"b", b"v");
        put_absent(&mut kv, b"c", b"v");

        // key="z" > range_end="a" → reversed bounds.
        let resp = kv
            .get(
                b"z".to_vec(),
                Some(GetOptions::new().with_range(b"a".to_vec())),
            )
            .expect("reversed-range get should not panic");
        assert!(
            resp.kvs().is_empty(),
            "reversed range should return empty set"
        );
    }

    /// delete(k) + put(k) in the same txn resets create_revision to the
    /// txn's revision, proving the key is treated as a fresh create.
    #[test]
    fn txn_delete_then_put_same_key_resets_create_revision() {
        let mut kv = SimulatedEtcdKV::new(106);
        put_absent(&mut kv, b"k", b"v1");

        let original = get_exact(&mut kv, b"k");
        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::mod_revision(
                        b"k",
                        CompareOp::Equal,
                        original.mod_revision(),
                    )])
                    .and_then(vec![
                        TxnOp::delete(b"k", None),
                        TxnOp::put(b"k", b"v2", None),
                    ]),
            )
            .expect("delete-then-put txn should succeed");
        assert!(resp.succeeded());

        let recreated = get_exact(&mut kv, b"k");
        assert_eq!(
            recreated.create_revision(),
            resp.header().unwrap().revision(),
            "create_revision should equal the txn revision (fresh create)"
        );
        assert_eq!(recreated.version(), 1);
        assert_eq!(recreated.value(), b"v2");
    }

    /// A txn with empty when/and_then branches is a no-op that does not
    /// advance the global revision.
    #[test]
    fn txn_with_empty_success_branch_does_not_bump_revision() {
        let mut kv = SimulatedEtcdKV::new(107);
        put_absent(&mut kv, b"anchor", b"v");
        let rev_before = kv.revision();

        let resp = kv.txn(Txn::new()).expect("empty txn should succeed");
        assert!(resp.succeeded());
        assert_eq!(
            kv.revision(),
            rev_before,
            "empty txn must not advance revision"
        );
    }

    /// Deleting a key that does not exist is a no-op that does not advance
    /// the global revision.
    #[test]
    fn txn_delete_nonexistent_key_does_not_bump_revision() {
        let mut kv = SimulatedEtcdKV::new(108);
        put_absent(&mut kv, b"anchor", b"v");
        let rev_before = kv.revision();

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"ghost",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![TxnOp::delete(b"ghost", None)]),
            )
            .expect("delete-nonexistent txn should succeed");
        assert!(resp.succeeded());
        assert_eq!(
            kv.revision(),
            rev_before,
            "deleting a nonexistent key must not advance revision"
        );
    }

    /// `Compare::version(key, Greater, 0)` succeeds when the key exists
    /// (version >= 1) and fails for absent keys (version == 0).
    #[test]
    fn compare_version_greater_detects_key_existence() {
        let mut kv = SimulatedEtcdKV::new(200);
        put_absent(&mut kv, b"present", b"val");

        let exists = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::version(b"present", CompareOp::Greater, 0)])
                    .and_then(vec![TxnOp::put(b"present", b"val2", None)]),
            )
            .expect("txn should succeed");
        assert!(exists.succeeded(), "version > 0 should match existing key");

        let absent = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::version(b"missing", CompareOp::Greater, 0)])
                    .and_then(vec![TxnOp::put(b"missing", b"v", None)]),
            )
            .expect("txn should succeed");
        assert!(
            !absent.succeeded(),
            "version > 0 should fail for absent key"
        );
    }

    /// `Compare::value(key, Equal, val)` matches against the stored byte
    /// payload and rejects mismatches.
    #[test]
    fn compare_value_equal_matches_stored_bytes() {
        let mut kv = SimulatedEtcdKV::new(201);
        put_absent(&mut kv, b"k", b"expected");

        let matched = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::value(b"k", CompareOp::Equal, b"expected")])
                    .and_then(vec![TxnOp::put(b"k", b"updated", None)]),
            )
            .expect("txn should succeed");
        assert!(matched.succeeded(), "value compare should match");

        let mismatched = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::value(b"k", CompareOp::Equal, b"wrong")])
                    .and_then(vec![TxnOp::put(b"k", b"never", None)]),
            )
            .expect("txn should succeed");
        assert!(
            !mismatched.succeeded(),
            "value compare should reject mismatch"
        );
    }

    /// `Compare::lease(key, Equal, lease_id)` matches the lease attached to
    /// a key via `PutOptions::with_lease`.
    #[test]
    fn compare_lease_equal_matches_attached_lease() {
        let mut kv = SimulatedEtcdKV::new(202);
        let lease = kv.lease_grant(30).expect("lease grant should succeed");

        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"leased",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(
                    b"leased",
                    b"val",
                    Some(PutOptions::new().with_lease(lease.id())),
                )]),
        )
        .expect("leased put should succeed");

        let matched = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::lease(
                        b"leased",
                        CompareOp::Equal,
                        lease.id(),
                    )])
                    .and_then(vec![TxnOp::put(b"leased", b"val2", None)]),
            )
            .expect("txn should succeed");
        assert!(
            matched.succeeded(),
            "lease compare should match attached lease"
        );

        let wrong_lease = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::lease(b"leased", CompareOp::Equal, 9999)])
                    .and_then(vec![TxnOp::put(b"leased", b"never", None)]),
            )
            .expect("txn should succeed");
        assert!(
            !wrong_lease.succeeded(),
            "lease compare should reject wrong lease id"
        );
    }

    /// A single delete-range request matching N keys must produce exactly one
    /// response entry with `deleted == N`, not N entries with `deleted == 1`.
    #[test]
    fn delete_range_produces_one_response_per_request_op() {
        let mut kv = SimulatedEtcdKV::new(106);
        put_absent(&mut kv, b"/pfx/a", b"1");
        put_absent(&mut kv, b"/pfx/b", b"2");
        put_absent(&mut kv, b"/pfx/c", b"3");

        // Txn: always-true compare, one put, one delete-range matching 3 keys.
        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"sentinel",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![
                        TxnOp::put(b"sentinel", b"v", None),
                        TxnOp::delete(
                            b"/pfx/",
                            Some(etcd_client::DeleteOptions::new().with_prefix()),
                        ),
                    ]),
            )
            .expect("txn should succeed");
        assert!(resp.succeeded());

        // Request had 2 ops → response must have exactly 2 entries.
        let op_responses = resp.op_responses();
        assert_eq!(
            op_responses.len(),
            2,
            "response count must match request op count"
        );
    }

    /// No-op delete (deleting a non-existent key) must still produce a
    /// ResponseDeleteRange with deleted=0 in the per-op responses.
    #[test]
    fn noop_delete_still_produces_response_entry() {
        let mut kv = SimulatedEtcdKV::new(107);

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"ghost",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![TxnOp::delete(b"ghost", None)]),
            )
            .expect("txn should succeed");
        assert!(resp.succeeded());

        // Even though nothing was deleted, the response must contain one
        // entry per request op.
        assert_eq!(
            resp.op_responses().len(),
            1,
            "no-op delete must still emit one response entry"
        );
    }

    /// A multi-op txn must produce one response header per op (i.e., the
    /// header must not be moved-from after the first op).
    #[test]
    fn multi_op_txn_produces_header_per_response() {
        let mut kv = SimulatedEtcdKV::new(108);

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(b"a", CompareOp::Equal, 0)])
                    .and_then(vec![
                        TxnOp::put(b"a", b"1", None),
                        TxnOp::put(b"b", b"2", None),
                        TxnOp::put(b"c", b"3", None),
                    ]),
            )
            .expect("txn should succeed");
        assert!(resp.succeeded());
        assert_eq!(
            resp.op_responses().len(),
            3,
            "3-op txn must produce 3 response entries"
        );
    }
}
