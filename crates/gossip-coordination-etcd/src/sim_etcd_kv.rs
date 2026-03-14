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
//! - **Batch lease expiry revision** — when multiple leases expire at the
//!   same logical time, each lease that deletes keys bumps the global
//!   revision independently. Real etcd coalesces batch expiry into a single
//!   revision increment. CAS correctness is unaffected (no interleaving
//!   within `expire_due_leases`), but revision numbers will be inflated
//!   relative to production.
//! - **Injected faults** — four fault types (CAS compare miss, uncertain
//!   commit, lease-TTL race, retry-exhaustion burst) simulate failure
//!   modes that occur organically only with concurrent writers or network
//!   partitions. The single-threaded simulator cannot produce these
//!   naturally, so they are injected probabilistically via
//!   [`SimEtcdFaultConfig`].

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;

use etcd_client::proto::{
    PbCompare, PbCompareTarget, PbDeleteRequest, PbDeleteResponse, PbKeyValue,
    PbLeaseGrantResponse, PbLeaseRevokeResponse, PbPutRequest, PbPutResponse, PbRangeRequest,
    PbRangeResponse, PbResponseHeader, PbResponseOp, PbTargetUnion, PbTxnOpRequest,
    PbTxnOpResponse, PbTxnRequest, PbTxnResponse,
};
use etcd_client::{CompareOp, GetOptions, LeaseGrantResponse, LeaseRevokeResponse, Txn, TxnOp};
use gossip_coordination::sim::FaultLevel;
use gossip_stdx::{FNV_OFFSET, fnv_mix_byte, fnv_mix_bytes, fnv_mix_u64};
use rand::Rng;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;

use crate::config::DEFAULT_OPTIMISTIC_TXN_RETRIES;

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
    /// Active sustained-contention burst for one logical CAS request.
    active_retry_exhaustion: Option<ActiveRetryExhaustion>,
    /// Suppresses immediate re-arming after a forced retry-exhaustion burst.
    /// Cleared once a different txn fingerprint arrives.
    recent_retry_exhaustion: Option<u64>,
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
        debug_assert!(
            fault_config.retry_exhaustion_ppm == 0 || fault_config.retry_exhaustion_attempts > 0,
            "retry_exhaustion_attempts is 0 but retry_exhaustion_ppm is nonzero ({} PPM); \
             the fault will never fire",
            fault_config.retry_exhaustion_ppm,
        );
        Self {
            kvs: BTreeMap::new(),
            revision: 0,
            leases: HashMap::new(),
            next_lease_id: 1,
            now: 0,
            next_expiry: u64::MAX,
            fault_config,
            active_retry_exhaustion: None,
            recent_retry_exhaustion: None,
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
    ///
    /// Clears any in-progress retry-exhaustion burst so the new config
    /// takes effect from a clean state.
    pub fn set_fault_config(&mut self, config: SimEtcdFaultConfig) {
        debug_assert!(
            config.retry_exhaustion_ppm == 0 || config.retry_exhaustion_attempts > 0,
            "retry_exhaustion_attempts is 0 but retry_exhaustion_ppm is nonzero ({} PPM); \
             the fault will never fire",
            config.retry_exhaustion_ppm,
        );
        self.fault_config = config;
        self.active_retry_exhaustion = None;
        self.recent_retry_exhaustion = None;
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

        let pb_op: PbTxnOpRequest = TxnOp::get(key, options).into();
        let request: PbRangeRequest = match pb_op {
            PbTxnOpRequest::RequestRange(r) => r,
            _ => unreachable!("TxnOp::get produces a range request"),
        };

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
        self.maybe_inject_lease_ttl_race();

        let request: PbTxnRequest = txn.into();
        if !request.failure.is_empty() {
            return Err(SimEtcdError::UnsupportedTxnOp {
                detail: "failure branches are not modeled",
            });
        }

        let retry_exhaustion_possible = self.active_retry_exhaustion.is_some()
            || self.recent_retry_exhaustion.is_some()
            || (self.fault_config.retry_exhaustion_ppm > 0
                && self.fault_config.retry_exhaustion_attempts > 0);

        let fingerprint = if retry_exhaustion_possible {
            let fp = txn_fingerprint(&request);
            self.clear_retry_exhaustion_for_other_txn(fp);
            if self.consume_retry_exhaustion(fp) {
                return Ok(build_txn_response(self.revision, false, Vec::new()));
            }
            Some(fp)
        } else {
            None
        };

        for compare in &request.compare {
            if !self.evaluate_compare(compare)? {
                return Ok(build_txn_response(self.revision, false, Vec::new()));
            }
        }
        if !request.compare.is_empty() && self.fault_config.should_cas_compare_fail(&mut self.rng) {
            return Ok(build_txn_response(self.revision, false, Vec::new()));
        }
        if fingerprint.is_some_and(|fp| self.maybe_arm_retry_exhaustion(&request, fp)) {
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
        if self.fault_config.should_uncertain_commit(&mut self.rng) {
            // State IS committed; the caller will retry. On the next call for
            // the same fingerprint, compares will fail (revision changed), so
            // we return at the compares_succeeded=false early-exit before
            // maybe_arm_retry_exhaustion can fire. The retry-exhaustion state
            // machine is intentionally left unchanged here.
            return Err(SimEtcdError::UncertainCommit);
        }
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
        let expires_at = self.now.saturating_add(ttl_u64);
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
    ///
    /// Note: TTL-race fault injection is intentionally omitted here.
    /// Unlike `txn`, where a lease-boundary race exercises CAS conflict
    /// handling, a race inside keep-alive permanently deletes the lease
    /// and returns `LeaseNotFound` — which `map_etcd_err` classifies as
    /// transient, causing an unrecoverable retry loop.
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
        lease.expires_at = self.now.saturating_add(lease.ttl);
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

        let attached_keys = self
            .leases
            .get(&lease_id)
            .ok_or(SimEtcdError::LeaseNotFound { lease_id })?
            .attached_keys
            .clone();
        let deleted_any = self.remove_lease_and_keys(lease_id)?;
        self.debug_assert_no_stale_lease_keys(&attached_keys);
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

    /// Advance the clock by one tick and expire any newly-due leases.
    ///
    /// Only leases within one tick of expiry are affected. Firings where
    /// no lease is near its deadline are benign no-ops that preserve
    /// clock monotonicity without mutating KV state.
    fn maybe_inject_lease_ttl_race(&mut self) {
        if !self.fault_config.should_lease_ttl_race(&mut self.rng) {
            return;
        }
        self.now = self
            .now
            .checked_add(1)
            .expect("SimulatedEtcdKV clock overflow");
        self.expire_due_leases();
    }

    fn clear_retry_exhaustion_for_other_txn(&mut self, fingerprint: u64) {
        if self
            .active_retry_exhaustion
            .as_ref()
            .is_some_and(|fault| fault.txn_fingerprint != fingerprint)
        {
            self.active_retry_exhaustion = None;
        }
        if self
            .recent_retry_exhaustion
            .is_some_and(|recent| recent != fingerprint)
        {
            self.recent_retry_exhaustion = None;
        }
    }

    fn consume_retry_exhaustion(&mut self, fingerprint: u64) -> bool {
        let Some(fault) = self.active_retry_exhaustion.as_mut() else {
            return false;
        };
        if fault.txn_fingerprint != fingerprint {
            return false;
        }
        if fault.remaining_failures == 0 {
            self.active_retry_exhaustion = None;
            return false;
        }
        fault.remaining_failures -= 1;
        if fault.remaining_failures == 0 {
            self.recent_retry_exhaustion = Some(fingerprint);
            self.active_retry_exhaustion = None;
        }
        true
    }

    fn maybe_arm_retry_exhaustion(&mut self, request: &PbTxnRequest, fingerprint: u64) -> bool {
        if request.compare.is_empty()
            || request.success.is_empty()
            || self.fault_config.retry_exhaustion_attempts == 0
            || self
                .recent_retry_exhaustion
                .is_some_and(|recent| recent == fingerprint)
            || !self.fault_config.should_retry_exhaust(&mut self.rng)
        {
            return false;
        }

        // When `retry_exhaustion_attempts == 1` the arming call itself is the
        // sole failure — remaining_failures is 0, so we transition directly
        // to cooldown without entering the Armed state.
        let remaining_failures = self
            .fault_config
            .retry_exhaustion_attempts
            .saturating_sub(1);
        if remaining_failures == 0 {
            self.recent_retry_exhaustion = Some(fingerprint);
            self.active_retry_exhaustion = None;
        } else {
            self.active_retry_exhaustion = Some(ActiveRetryExhaustion {
                txn_fingerprint: fingerprint,
                remaining_failures,
            });
            self.recent_retry_exhaustion = None;
        }
        true
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
        let key = request.key.clone();
        if !staged.all_put_keys.insert(key.clone()) {
            return Err(SimEtcdError::DuplicateMutation { key });
        }
        staged.pending_puts.insert(key.clone());
        staged.ops.push(StagedOp::Put(StagedPut {
            key,
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

    /// Verify that all keys from a revoked lease have been removed from the store.
    fn debug_assert_no_stale_lease_keys(&self, removed_keys: &BTreeSet<Vec<u8>>) {
        for key in removed_keys {
            debug_assert!(
                !self.kvs.contains_key(key),
                "stale key after lease revoke: {key:?}"
            );
        }
    }

    /// Expire all leases whose TTL has elapsed, deleting their attached keys.
    ///
    /// Called automatically by every mutating operation. Exposed publicly so
    /// the simulation driver can decouple clock advancement ([`Self::set_time`])
    /// from expiry processing.
    ///
    /// Returns the lease IDs that actually expired and deleted at least one
    /// key. Callers can use this to invalidate cached owner bindings.
    pub fn expire_due_leases(&mut self) -> Vec<i64> {
        if self.now < self.next_expiry {
            return Vec::new();
        }

        let mut expired: Vec<i64> = self
            .leases
            .iter()
            .filter_map(|(lease_id, state)| (state.expires_at <= self.now).then_some(*lease_id))
            .collect();
        expired.sort_unstable();

        let mut deleted_lease_ids = Vec::new();
        for lease_id in expired {
            let attached_keys = self
                .leases
                .get(&lease_id)
                .map(|ls| ls.attached_keys.clone())
                .unwrap_or_default();
            let deleted_any = match self.remove_lease_and_keys(lease_id) {
                Ok(deleted_any) => deleted_any,
                Err(SimEtcdError::LeaseNotFound { .. }) => false,
                Err(_) => {
                    debug_assert!(false, "unexpected error during lease expiry");
                    continue;
                }
            };
            self.debug_assert_no_stale_lease_keys(&attached_keys);
            if deleted_any {
                self.bump_revision();
                deleted_lease_ids.push(lease_id);
            }
        }

        self.next_expiry = self
            .leases
            .values()
            .map(|ls| ls.expires_at)
            .min()
            .unwrap_or(u64::MAX);

        deleted_lease_ids
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
            return Ok(match self.kvs.get_key_value(key) {
                Some(pair) => vec![pair],
                None => Vec::new(),
            });
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
        self.revision = self
            .revision
            .checked_add(1)
            .unwrap_or_else(|| panic!("revision overflow: current revision={}", self.revision));
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
struct ActiveRetryExhaustion {
    txn_fingerprint: u64,
    remaining_failures: usize,
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
    cas_compare_failure_ppm: u32,
    uncertain_commit_ppm: u32,
    lease_ttl_race_ppm: u32,
    retry_exhaustion_ppm: u32,
    retry_exhaustion_attempts: usize,
}

impl SimEtcdFaultConfig {
    /// Progressive etcd-layer faults for the given simulation severity.
    ///
    /// The retry-exhaustion window defaults to the coordinator's standard
    /// optimistic retry budget (8 attempts). Callers using a custom retry
    /// budget should override it with [`with_retry_exhaustion_attempts`](Self::with_retry_exhaustion_attempts).
    #[must_use]
    pub fn for_level(level: FaultLevel) -> Self {
        match level {
            FaultLevel::SunnyDay => Self::default(),
            FaultLevel::Stormy => Self {
                cas_compare_failure_ppm: 100_000,
                uncertain_commit_ppm: 20_000,
                lease_ttl_race_ppm: 50_000,
                retry_exhaustion_ppm: 10_000,
                retry_exhaustion_attempts: DEFAULT_OPTIMISTIC_TXN_RETRIES,
                ..Self::default()
            },
            FaultLevel::Radioactive => Self {
                cas_compare_failure_ppm: 300_000,
                uncertain_commit_ppm: 100_000,
                lease_ttl_race_ppm: 150_000,
                retry_exhaustion_ppm: 50_000,
                retry_exhaustion_attempts: DEFAULT_OPTIMISTIC_TXN_RETRIES,
                ..Self::default()
            },
        }
    }

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

    /// Override the simulated CAS-contention rate.
    #[must_use]
    pub fn with_cas_compare_failure_ppm(mut self, ppm: u32) -> Self {
        self.cas_compare_failure_ppm = validate_ppm(ppm);
        self
    }

    /// Override the uncertain-commit rate.
    #[must_use]
    pub fn with_uncertain_commit_ppm(mut self, ppm: u32) -> Self {
        self.uncertain_commit_ppm = validate_ppm(ppm);
        self
    }

    /// Override the lease-expiry race rate.
    #[must_use]
    pub fn with_lease_ttl_race_ppm(mut self, ppm: u32) -> Self {
        self.lease_ttl_race_ppm = validate_ppm(ppm);
        self
    }

    /// Override the sustained CAS-contention rate used to exhaust retries.
    #[must_use]
    pub fn with_retry_exhaustion_ppm(mut self, ppm: u32) -> Self {
        self.retry_exhaustion_ppm = validate_ppm(ppm);
        self
    }

    /// Override the number of compare-fail responses used to exhaust retries.
    #[must_use]
    pub fn with_retry_exhaustion_attempts(mut self, attempts: usize) -> Self {
        self.retry_exhaustion_attempts = attempts;
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

    fn should_cas_compare_fail(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.cas_compare_failure_ppm)
    }

    fn should_uncertain_commit(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.uncertain_commit_ppm)
    }

    fn should_lease_ttl_race(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.lease_ttl_race_ppm)
    }

    fn should_retry_exhaust(&self, rng: &mut ChaCha8Rng) -> bool {
        should_inject(rng, self.retry_exhaustion_ppm)
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
    UncertainCommit,
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
            Self::UncertainCommit => {
                f.write_str("transaction committed but the client observed an uncertain outcome")
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

/// Structural FNV-1a fingerprint for one logical CAS request.
///
/// Hashes only the key set, compare target types, compare operators,
/// and success op-type discriminants. Values, revisions, and boolean
/// flags are deliberately excluded because the coordinator rebuilds
/// transactions from scratch on each retry, re-reading current state,
/// so value-dependent fields can legitimately differ across retries of
/// the same logical operation.
fn txn_fingerprint(request: &PbTxnRequest) -> u64 {
    let mut sig = FNV_OFFSET;
    fnv_mix_u64(&mut sig, request.compare.len() as u64);
    for compare in &request.compare {
        fnv_mix_bytes(&mut sig, &compare.key);
        fnv_mix_byte(&mut sig, compare.result as u8);
        fnv_mix_byte(&mut sig, compare.target as u8);
    }

    fnv_mix_u64(&mut sig, request.success.len() as u64);
    for op in &request.success {
        match op.request.as_ref() {
            Some(PbTxnOpRequest::RequestPut(put)) => {
                fnv_mix_byte(&mut sig, 10);
                fnv_mix_bytes(&mut sig, &put.key);
            }
            Some(PbTxnOpRequest::RequestDeleteRange(delete)) => {
                fnv_mix_byte(&mut sig, 11);
                fnv_mix_bytes(&mut sig, &delete.key);
                fnv_mix_bytes(&mut sig, &delete.range_end);
            }
            Some(PbTxnOpRequest::RequestRange(range)) => {
                fnv_mix_byte(&mut sig, 12);
                fnv_mix_bytes(&mut sig, &range.key);
                fnv_mix_bytes(&mut sig, &range.range_end);
            }
            Some(PbTxnOpRequest::RequestTxn(_)) => fnv_mix_byte(&mut sig, 13),
            None => fnv_mix_byte(&mut sig, 254),
        }
    }
    sig
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
    use crate::config::DEFAULT_OPTIMISTIC_TXN_RETRIES;
    use etcd_client::{Compare, CompareOp, GetOptions, PutOptions, Txn, TxnOp};
    use gossip_coordination::sim::FaultLevel;

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
    fn prefix_scan_with_trailing_slash_excludes_sibling_stems() {
        let mut kv = SimulatedEtcdKV::new(109);
        put_absent(&mut kv, b"/runs/1/shards/0001", b"record");
        put_absent(&mut kv, b"/runs/1/shards_active/0001", b"active");

        let response = kv
            .get(
                b"/runs/1/shards/".to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .expect("prefix scan should succeed");
        let keys: Vec<Vec<u8>> = response.kvs().iter().map(|kv| kv.key().to_vec()).collect();

        assert_eq!(keys, vec![b"/runs/1/shards/0001".to_vec()]);
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

    #[test]
    fn fault_level_profiles_match_progressive_rates() {
        let sunny = SimEtcdFaultConfig::for_level(FaultLevel::SunnyDay);
        assert_eq!(sunny.cas_compare_failure_ppm, 0);
        assert_eq!(sunny.uncertain_commit_ppm, 0);
        assert_eq!(sunny.lease_ttl_race_ppm, 0);
        assert_eq!(sunny.retry_exhaustion_ppm, 0);

        let stormy = SimEtcdFaultConfig::for_level(FaultLevel::Stormy);
        assert_eq!(stormy.cas_compare_failure_ppm, 100_000);
        assert_eq!(stormy.uncertain_commit_ppm, 20_000);
        assert_eq!(stormy.lease_ttl_race_ppm, 50_000);
        assert_eq!(stormy.retry_exhaustion_ppm, 10_000);
        assert_eq!(
            stormy.retry_exhaustion_attempts,
            DEFAULT_OPTIMISTIC_TXN_RETRIES
        );

        let radioactive = SimEtcdFaultConfig::for_level(FaultLevel::Radioactive);
        assert_eq!(radioactive.cas_compare_failure_ppm, 300_000);
        assert_eq!(radioactive.uncertain_commit_ppm, 100_000);
        assert_eq!(radioactive.lease_ttl_race_ppm, 150_000);
        assert_eq!(radioactive.retry_exhaustion_ppm, 50_000);
        assert_eq!(
            radioactive.retry_exhaustion_attempts,
            DEFAULT_OPTIMISTIC_TXN_RETRIES
        );
    }

    #[test]
    fn cas_compare_fault_rejects_without_mutating_state() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            7,
            SimEtcdFaultConfig::default().with_cas_compare_failure_ppm(1_000_000),
        );

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"fault-cas",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![TxnOp::put(b"fault-cas", b"value", None)]),
            )
            .expect("CAS contention fault should surface as a compare miss");

        assert!(!resp.succeeded(), "fault should reject the CAS");
        assert!(
            kv.get(b"fault-cas".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty(),
            "rejected CAS must not mutate store state"
        );
    }

    #[test]
    fn uncertain_commit_applies_state_before_returning_error() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            8,
            SimEtcdFaultConfig::default().with_uncertain_commit_ppm(1_000_000),
        );

        let err = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(
                        b"uncertain",
                        CompareOp::Equal,
                        0,
                    )])
                    .and_then(vec![TxnOp::put(b"uncertain", b"value", None)]),
            )
            .expect_err("uncertain commit should hide the committed response");
        assert!(matches!(err, SimEtcdError::UncertainCommit));
        assert_eq!(
            get_exact(&mut kv, b"uncertain").value(),
            b"value",
            "uncertain commit must still apply the staged mutation"
        );
    }

    #[test]
    fn lease_ttl_race_can_expire_keys_between_read_and_write() {
        let mut kv = SimulatedEtcdKV::new(9);
        let lease = kv.lease_grant(1).expect("lease grant should succeed");
        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(b"racy", CompareOp::Equal, 0)])
                .and_then(vec![TxnOp::put(
                    b"racy",
                    b"value",
                    Some(PutOptions::new().with_lease(lease.id())),
                )]),
        )
        .expect("initial leased put should succeed");
        kv.set_fault_config(SimEtcdFaultConfig::default().with_lease_ttl_race_ppm(1_000_000));

        let resp = kv
            .txn(
                Txn::new()
                    .when(vec![Compare::create_revision(b"racy", CompareOp::Equal, 1)])
                    .and_then(vec![TxnOp::put(b"other", b"value", None)]),
            )
            .expect("lease race should look like a failed CAS");

        assert!(!resp.succeeded(), "expired owner key should break the CAS");
        assert!(
            kv.get(b"racy".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty(),
            "lease-race fault must expire attached keys before txn evaluation"
        );
    }

    #[test]
    fn retry_exhaustion_fault_forces_repeated_compare_failures() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            10,
            SimEtcdFaultConfig::default()
                .with_retry_exhaustion_ppm(1_000_000)
                .with_retry_exhaustion_attempts(3),
        );
        let txn = || {
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"retry",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(b"retry", b"value", None)])
        };

        let first = kv
            .txn(txn())
            .expect("first forced contention should return a txn response");
        let second = kv
            .txn(txn())
            .expect("second forced contention should return a txn response");
        let third = kv
            .txn(txn())
            .expect("third forced contention should return a txn response");
        let fourth = kv
            .txn(txn())
            .expect("fault should clear after configured retries");

        assert!(!first.succeeded());
        assert!(!second.succeeded());
        assert!(!third.succeeded());
        assert!(
            fourth.succeeded(),
            "txn should commit once forced contention clears"
        );
        assert_eq!(get_exact(&mut kv, b"retry").value(), b"value");
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

    #[test]
    fn cas_compare_fault_does_not_reject_compare_free_txn() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            11,
            SimEtcdFaultConfig::default().with_cas_compare_failure_ppm(1_000_000),
        );

        let resp = kv
            .txn(Txn::new().and_then(vec![TxnOp::put(b"no-compare", b"value", None)]))
            .expect("compare-free txn must not be rejected by CAS fault");
        assert!(
            resp.succeeded(),
            "compare-free txn must succeed even with 100% CAS fault rate"
        );
        assert_eq!(
            get_exact(&mut kv, b"no-compare").value(),
            b"value",
            "compare-free txn must write the key"
        );
    }

    #[test]
    fn retry_exhaustion_with_single_attempt_fires_once() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            12,
            SimEtcdFaultConfig::default()
                .with_retry_exhaustion_ppm(1_000_000)
                .with_retry_exhaustion_attempts(1),
        );
        let txn = || {
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"single-retry",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(b"single-retry", b"value", None)])
        };

        let first = kv.txn(txn()).expect("first txn should return response");
        assert!(
            !first.succeeded(),
            "attempts=1 must fail on the arming call"
        );

        let second = kv.txn(txn()).expect("second txn should return response");
        assert!(
            second.succeeded(),
            "recent suppression must prevent re-arming after a 1-attempt burst"
        );
        assert_eq!(get_exact(&mut kv, b"single-retry").value(), b"value");
    }

    /// TTL-race fault injection is excluded from `lease_keep_alive_once`
    /// to prevent an unrecoverable retry loop (the lease expires
    /// permanently but `LeaseNotFound` maps to a transient error).
    /// Keep-alive succeeds even with 100% TTL race configured.
    #[test]
    fn keep_alive_ignores_ttl_race_fault() {
        let mut kv = SimulatedEtcdKV::new(13);
        let lease = kv.lease_grant(1).expect("lease grant should succeed");
        kv.txn(
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"keep-alive-race",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(
                    b"keep-alive-race",
                    b"value",
                    Some(PutOptions::new().with_lease(lease.id())),
                )]),
        )
        .expect("leased put should succeed");

        kv.set_fault_config(SimEtcdFaultConfig::default().with_lease_ttl_race_ppm(1_000_000));

        // TTL race is not injected in keep-alive, so this succeeds.
        kv.lease_keep_alive_once(lease.id())
            .expect("keep-alive should succeed — TTL race not injected here");
        assert!(
            !kv.get(b"keep-alive-race".to_vec(), None)
                .expect("get should succeed")
                .kvs()
                .is_empty(),
            "attached key must still exist after successful keep-alive"
        );
    }

    #[test]
    fn set_fault_config_clears_active_retry_exhaustion() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            14,
            SimEtcdFaultConfig::default()
                .with_retry_exhaustion_ppm(1_000_000)
                .with_retry_exhaustion_attempts(5),
        );
        let txn = || {
            Txn::new()
                .when(vec![Compare::create_revision(
                    b"clear-retry",
                    CompareOp::Equal,
                    0,
                )])
                .and_then(vec![TxnOp::put(b"clear-retry", b"value", None)])
        };

        let first = kv.txn(txn()).expect("first txn should return response");
        let second = kv.txn(txn()).expect("second txn should return response");
        assert!(!first.succeeded());
        assert!(!second.succeeded());

        kv.set_fault_config(SimEtcdFaultConfig::default());

        let after_clear = kv
            .txn(txn())
            .expect("txn after config reset should return response");
        assert!(
            after_clear.succeeded(),
            "set_fault_config must clear active retry-exhaustion state"
        );
        assert_eq!(get_exact(&mut kv, b"clear-retry").value(), b"value");
    }

    #[test]
    fn sunny_day_never_injects_faults() {
        let mut kv = SimulatedEtcdKV::with_fault_config(
            42,
            SimEtcdFaultConfig::for_level(FaultLevel::SunnyDay),
        );

        for i in 0..100u32 {
            let key = format!("sunny-{i}");
            let resp = kv
                .txn(
                    Txn::new()
                        .when(vec![Compare::create_revision(
                            key.as_bytes(),
                            CompareOp::Equal,
                            0,
                        )])
                        .and_then(vec![TxnOp::put(key.as_bytes(), b"v", None)]),
                )
                .unwrap_or_else(|e| panic!("SunnyDay txn #{i} returned error: {e}"));
            assert!(
                resp.succeeded(),
                "SunnyDay txn #{i} failed — no faults should fire at zero PPM"
            );
        }
    }

    // ---- Verification tests for review-identified edge cases ----

    /// TTL-race fault injection is not applied inside `lease_keep_alive_once`
    /// because it would permanently expire the target lease and return
    /// `LeaseNotFound`, which maps to a transient error at the backend
    /// layer — creating an unrecoverable retry loop.
    #[test]
    fn ttl_race_does_not_fire_inside_keep_alive() {
        let fault = SimEtcdFaultConfig::default().with_lease_ttl_race_ppm(1_000_000);
        let mut kv = SimulatedEtcdKV::with_fault_config(100, fault);

        // Grant a lease with TTL=5 ticks.
        let lease = kv.lease_grant(5).expect("lease_grant should succeed");
        let lease_id = lease.id();

        // Position clock at 1 tick before expiry.
        kv.set_time(4);

        // With TTL race excluded from keep-alive, this should succeed
        // rather than expiring the lease.
        let result = kv.lease_keep_alive_once(lease_id);
        assert!(
            result.is_ok(),
            "keep-alive must succeed — TTL race is not injected here, got: {result:?}"
        );

        // Lease must still exist.
        assert!(
            kv.lease_info(lease_id).is_some(),
            "lease must still exist after successful keep-alive"
        );
    }

    /// Constructing a fault config with `retry_exhaustion_ppm > 0` and
    /// `attempts == 0` triggers a debug_assert at construction time,
    /// catching the misconfiguration early rather than silently disabling
    /// the fault.
    #[test]
    #[cfg_attr(
        debug_assertions,
        should_panic(expected = "retry_exhaustion_attempts is 0")
    )]
    fn retry_exhaustion_ppm_without_attempts_panics_in_debug() {
        let fault = SimEtcdFaultConfig::default()
            .with_retry_exhaustion_ppm(1_000_000) // 100% rate
            .with_retry_exhaustion_attempts(0); // but zero burst length
        // In debug builds, this panics at the debug_assert in with_fault_config.
        // In release builds, the fault silently does nothing (no panic).
        let _kv = SimulatedEtcdKV::with_fault_config(200, fault);
    }

    /// A point delete (empty `range_end`) and a range delete (non-empty
    /// `range_end`) on the same key should produce different fingerprints
    /// so the retry-exhaustion state machine does not conflate them.
    #[test]
    fn point_and_range_delete_produce_distinct_fingerprints() {
        use etcd_client::proto::{
            PbCompare, PbDeleteRequest, PbTxnOpRequest, PbTxnRequest, PbTxnRequestOp,
        };

        let compare = PbCompare {
            key: b"prefix/".to_vec(),
            ..Default::default()
        };

        // Point delete: range_end is empty.
        let point_delete = PbTxnRequest {
            compare: vec![compare.clone()],
            success: vec![PbTxnRequestOp {
                request: Some(PbTxnOpRequest::RequestDeleteRange(PbDeleteRequest {
                    key: b"prefix/".to_vec(),
                    range_end: Vec::new(),
                    ..Default::default()
                })),
            }],
            failure: Vec::new(),
        };

        // Range delete: range_end is the prefix-end sentinel.
        let range_delete = PbTxnRequest {
            compare: vec![compare],
            success: vec![PbTxnRequestOp {
                request: Some(PbTxnOpRequest::RequestDeleteRange(PbDeleteRequest {
                    key: b"prefix/".to_vec(),
                    range_end: b"prefix0".to_vec(), // prefix end
                    ..Default::default()
                })),
            }],
            failure: Vec::new(),
        };

        let fp_point = super::txn_fingerprint(&point_delete);
        let fp_range = super::txn_fingerprint(&range_delete);

        // These should differ since range_end changes the semantics.
        assert_ne!(
            fp_point, fp_range,
            "point delete and range delete on the same key must produce different fingerprints"
        );
    }

    // ---- Property-based tests ----

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        /// Generates a random KV operation sequence.
        #[derive(Debug, Clone)]
        enum KvOp {
            Put { key: Vec<u8>, value: Vec<u8> },
            Delete { key: Vec<u8> },
            Get { key: Vec<u8> },
            Tick(u64),
        }

        fn arb_key() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(b'a'..=b'f', 1..=4)
        }

        fn arb_value() -> impl Strategy<Value = Vec<u8>> {
            prop::collection::vec(any::<u8>(), 0..=16)
        }

        fn arb_kv_op() -> impl Strategy<Value = KvOp> {
            prop_oneof![
                4 => (arb_key(), arb_value()).prop_map(|(key, value)| KvOp::Put { key, value }),
                2 => arb_key().prop_map(|key| KvOp::Delete { key }),
                2 => arb_key().prop_map(|key| KvOp::Get { key }),
                1 => (1u64..=5).prop_map(KvOp::Tick),
            ]
        }

        fn arb_kv_ops(
            count: impl Into<prop::collection::SizeRange>,
        ) -> impl Strategy<Value = Vec<KvOp>> {
            prop::collection::vec(arb_kv_op(), count)
        }

        fn arb_fault_config() -> impl Strategy<Value = SimEtcdFaultConfig> {
            (
                0u32..=200_000,
                0u32..=200_000,
                0u32..=200_000,
                0u32..=200_000,
                0usize..=5,
            )
                .prop_map(|(cas, uncertain, lease, retry, attempts)| {
                    // Ensure valid config: if retry ppm is nonzero, attempts
                    // must also be nonzero (otherwise the fault never fires
                    // and a debug_assert catches the misconfiguration).
                    let valid_attempts = if retry > 0 && attempts == 0 {
                        1
                    } else {
                        attempts
                    };
                    SimEtcdFaultConfig::default()
                        .with_cas_compare_failure_ppm(cas)
                        .with_uncertain_commit_ppm(uncertain)
                        .with_lease_ttl_race_ppm(lease)
                        .with_retry_exhaustion_ppm(retry)
                        .with_retry_exhaustion_attempts(valid_attempts)
                })
        }
        proptest! {
            /// Global revision must never decrease across any operation sequence,
            /// even under randomized fault injection.
            #[test]
            fn revision_monotonically_increases(
                ops in arb_kv_ops(1..50),
                seed in any::<u64>(),
                fault_config in arb_fault_config(),
            ) {
                let mut kv = SimulatedEtcdKV::with_fault_config(seed, fault_config);
                let mut prev_rev = kv.revision();

                for op in ops {
                    match op {
                        KvOp::Put { key, value } => {
                            let txn = Txn::new()
                                .when(Vec::new())
                                .and_then(vec![TxnOp::put(key, value, None)]);
                            if let Ok(resp) = kv.txn(txn) {
                                let rev = resp.header().unwrap().revision();
                                prop_assert!(rev >= prev_rev, "revision went backwards: {} -> {}", prev_rev, rev);
                                prev_rev = rev;
                            }
                        }
                        KvOp::Delete { key } => {
                            let txn = Txn::new()
                                .when(Vec::new())
                                .and_then(vec![TxnOp::delete(key, None)]);
                            if let Ok(resp) = kv.txn(txn) {
                                let rev = resp.header().unwrap().revision();
                                prop_assert!(rev >= prev_rev, "revision went backwards: {} -> {}", prev_rev, rev);
                                prev_rev = rev;
                            }
                        }
                        KvOp::Get { key } => {
                            if let Ok(resp) = kv.get(key, None) {
                                let rev = resp.header().unwrap().revision();
                                prop_assert!(rev >= prev_rev, "revision went backwards: {} -> {}", prev_rev, rev);
                                prev_rev = rev;
                            }
                        }
                        KvOp::Tick(dt) => {
                            kv.tick(dt);
                        }
                    }
                }
            }

            /// The key_count accessor must always equal the number of keys
            /// retrievable via a full-range scan, even under fault injection.
            #[test]
            fn key_count_matches_full_range_scan(
                ops in arb_kv_ops(1..30),
                seed in any::<u64>(),
                fault_config in arb_fault_config(),
            ) {
                let mut kv = SimulatedEtcdKV::with_fault_config(seed, fault_config);

                for op in ops {
                    match op {
                        KvOp::Put { key, value } => {
                            let _ = kv.txn(
                                Txn::new()
                                    .when(Vec::new())
                                    .and_then(vec![TxnOp::put(key, value, None)]),
                            );
                        }
                        KvOp::Delete { key } => {
                            let _ = kv.txn(
                                Txn::new()
                                    .when(Vec::new())
                                    .and_then(vec![TxnOp::delete(key, None)]),
                            );
                        }
                        KvOp::Get { .. } => {}
                        KvOp::Tick(dt) => { kv.tick(dt); }
                    }
                }

                // Full-range scan: all keys >= empty key.
                let scan = kv
                    .get(Vec::new(), Some(GetOptions::new().with_from_key()))
                    .expect("full scan should succeed");
                prop_assert_eq!(
                    kv.key_count(),
                    scan.kvs().len(),
                    "key_count must match full-range scan length"
                );
            }

            /// A CAS compare against a stale mod_revision must fail.
            #[test]
            fn cas_with_stale_mod_revision_always_fails(seed in any::<u64>()) {
                let mut kv = SimulatedEtcdKV::new(seed);

                // Create key and record its initial mod_revision.
                let txn = Txn::new()
                    .when(vec![Compare::create_revision(b"k", CompareOp::Equal, 0)])
                    .and_then(vec![TxnOp::put(b"k", b"v1", None)]);
                kv.txn(txn).expect("initial put should succeed");
                let initial_mod = get_exact(&mut kv, b"k").mod_revision();

                // Update to bump mod_revision.
                let txn = Txn::new()
                    .when(vec![Compare::mod_revision(b"k", CompareOp::Equal, initial_mod)])
                    .and_then(vec![TxnOp::put(b"k", b"v2", None)]);
                let resp = kv.txn(txn).expect("update should succeed");
                prop_assert!(resp.succeeded());

                // Stale compare must fail.
                let txn = Txn::new()
                    .when(vec![Compare::mod_revision(b"k", CompareOp::Equal, initial_mod)])
                    .and_then(vec![TxnOp::put(b"k", b"v3", None)]);
                let resp = kv.txn(txn).expect("stale compare txn should return response");
                prop_assert!(!resp.succeeded(), "CAS with stale mod_revision must fail");
            }
        }
    }
}
