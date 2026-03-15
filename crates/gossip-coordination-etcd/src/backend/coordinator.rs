//! Coordinator types, etcd RPC wrappers, and CAS retry infrastructure.
//!
//! This module defines the two coordinator entrypoints:
//!
//! - [`EtcdCoordinator`] — sync wrapper that owns a single-threaded Tokio
//!   runtime and drives all etcd RPCs via `runtime.block_on(...)`.
//! - [`AsyncEtcdCoordinator`] — async core that expects an externally
//!   provided Tokio runtime.
//!
//! Both expose the same core coordination surface (run management, shard hot
//! path, shard lifecycle), differing only in execution model. The sync
//! [`EtcdCoordinator`] additionally implements
//! [`ShardClaiming`](gossip_coordination::ShardClaiming) for claim
//! orchestration. Shared free functions and validation logic live in the
//! parent [`super`] module; trait impls live in [`super::run_management`]
//! and [`super::shard_coordination`].
//!
//! # CAS retry loop
//!
//! [`EtcdCoordinator::cas_retry`] and [`AsyncEtcdCoordinator::cas_retry`]
//! drive the optimistic CAS pattern used by every mutating operation:
//!
//! ```text
//! for attempt in 0..max_retries {
//!     match attempt_fn() {
//!         Committed(val) => return Ok(val),
//!         RetryNeeded    => sleep(jittered_backoff),
//!     }
//! }
//! on_exhaustion()  // re-read and diagnose
//! ```
//!
//! The `on_exhaustion` closure runs without additional backoff and is
//! responsible for re-reading persisted state to return the correct domain
//! error (idempotent replay, terminal status, stale fence, or transient
//! contention error).
//!
//! # Data loading helpers
//!
//! `load_run_record`, `load_shard_record`, `scan_run_shards`, and
//! `scan_tenant_runs` all perform defense-in-depth validation: after
//! decoding a record, they check that its identity fields (tenant, run,
//! shard) match the key path used to retrieve it. This detects silent
//! data corruption at the access layer rather than surfacing it as a
//! logic error later in validation.

use std::collections::HashMap;
use std::fmt;

use etcd_client::{DeleteOptions, GetOptions, Txn, TxnOp};
use gossip_coordination::{
    CapacityHint, IdempotentOutcome, InfraError, Lease, LogicalTime, OpId, RunId, RunOpKind,
    RunStatus, RunTransitionError, ShardId, ShardKey, TenantId, hash_cancel_run_payload,
    hash_complete_run_payload, hash_fail_run_payload,
};

use crate::codec::{EtcdCodecError, decode_run_record, decode_shard_record, encode_run_record};
use crate::config::{DEFAULT_CONNECT_TIMEOUT, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use crate::keyspace::{
    PersistedShardSubtreeKey, RunActiveIndexKey, RunRecordKey, ShardOwnerKey, ShardRecordKey,
};

use super::{
    CasOutcome, PersistedOwner, PersistedRun, PersistedShard, PersistedTenantShardCount,
    TenantShardCountMutation, TxnBuilder, apply_terminal_run_transition, cas_retry_delay,
    compare_absent, compare_present, compare_run_revision, compare_tenant_shard_count_revision,
    decode_owner_kv, decode_tenant_shard_count_kv, encode_tenant_shard_count, make_decode_slab,
    u64_to_usize_saturating, usize_to_u64_saturating, validate_loaded_shard_lease,
    validate_owner_consistency,
};

#[cfg(any(test, feature = "test-support"))]
use super::test_support::EtcdTestFaultState;

/// Abstraction over the sync etcd transport, enabling the same coordination
/// logic to run against both real etcd ([`EtcdCoordinator`]) and the
/// in-process simulation backend ([`SimEtcdCoordinator`]).
///
/// This trait defines the low-level RPC surface (`etcd_get`, `etcd_txn`,
/// lease operations), the CAS retry loop, and all data-loading helpers
/// that coordination operations compose. The actual trait impls for
/// [`CoordinationBackend`](gossip_coordination::CoordinationBackend) and
/// [`RunManagement`](gossip_coordination::RunManagement) are defined in
/// sibling modules and are generic over `SyncEtcdLike` via a macro.
///
/// # Polymorphism via macro
///
/// Rather than object-safe dynamic dispatch, the coordination trait impls
/// are stamped out via `impl_sync_coordination_backend!` and
/// `impl_sync_run_management!` for each concrete type. This preserves
/// monomorphization and inlining across the CAS retry hot path while
/// avoiding the ergonomic overhead of generic bounds on every call site.
///
/// # Default method overrides
///
/// - `cas_retry_backoff` — real backends sleep with jittered exponential
///   backoff; simulation overrides to a no-op (deterministic, no real
///   contention).
/// - `sync_logical_time` — simulation uses this to advance its synthetic
///   clock; real backends ignore it.
/// - `on_gc_run` — simulation uses this to drop cached run state.
#[cfg_attr(not(any(test, feature = "test-support")), allow(dead_code))]
pub(crate) trait SyncEtcdLike: Sized {
    fn config(&self) -> &EtcdCoordinatorConfig;
    fn keyspace(&self) -> &EtcdKeyspace;

    fn sync_logical_time(&self, _now: LogicalTime) {}

    fn refresh_cached_run_state(
        &mut self,
        _tenant: TenantId,
        _run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        Ok(())
    }

    /// Best-effort cache refresh after a committed CAS transaction.
    ///
    /// If the refresh fails (e.g., fault-injected KV error in the sim
    /// backend), the failure is logged but not propagated. The CAS already
    /// committed — the caller must receive the successful result. The
    /// cache will be repopulated on the next mutation or explicit refresh.
    fn best_effort_refresh_cached_run_state(&mut self, tenant: TenantId, run: RunId) {
        if let Err(err) = self.refresh_cached_run_state(tenant, run) {
            tracing::warn!(
                %err,
                %tenant,
                ?run,
                "post-commit cache refresh failed; cache is stale until next mutation",
            );
        }
    }

    /// Backoff strategy between CAS retry attempts.
    /// Default: real sleep with exponential backoff + jitter.
    /// Simulation overrides to no-op (deterministic, no real contention).
    fn cas_retry_backoff(&self, attempt: usize) {
        std::thread::sleep(cas_retry_delay(attempt));
    }

    /// Hook called when GC successfully deletes a run.
    /// Simulation overrides to drop cached run state.
    fn on_gc_run(&mut self, _tenant: TenantId, _run: RunId) {}

    /// Drive an optimistic CAS mutation with bounded retries.
    ///
    /// `attempt` runs the read-validate-CAS cycle and returns
    /// [`CasOutcome::Committed`] on success or [`CasOutcome::RetryNeeded`]
    /// when the etcd transaction's preconditions fail. Non-retryable domain
    /// errors (stale fence, terminal shard, etc.) are returned as `Err`
    /// immediately, short-circuiting the loop.
    ///
    /// After `optimistic_txn_retries` attempts, `on_exhaustion` re-reads
    /// persisted state and returns the appropriate domain error. This final
    /// read distinguishes idempotent replays, stale fences, and genuine
    /// transient contention.
    fn cas_retry<T, E>(
        &mut self,
        mut attempt: impl FnMut(&mut Self, usize) -> Result<CasOutcome<T>, E>,
        on_exhaustion: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let max_retries = self.config().optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            match attempt(self, attempt_num)? {
                CasOutcome::Committed(val) => return Ok(val),
                CasOutcome::RetryNeeded => {
                    if attempt_num + 1 < max_retries {
                        self.cas_retry_backoff(attempt_num);
                    }
                }
            }
        }
        on_exhaustion(self)
    }

    /// Load a shard record, then validate a presented lease against it.
    ///
    /// Combines the shard load with full lease validation (expiry, tenant,
    /// status, and owner binding match) in a single call, reducing
    /// boilerplate at call sites. The three closures map the three
    /// possible error categories into the caller's error type:
    ///
    /// - `map_not_found` — shard key absent in etcd.
    /// - `map_load_error` — etcd RPC or decode failure.
    /// - `map_stale_fence` — owner binding disagrees with the presented
    ///   lease's worker + fence epoch.
    fn load_shard_and_validate_lease<E>(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        map_not_found: impl FnOnce(ShardKey) -> E,
        map_load_error: impl FnOnce(EtcdCoordinatorError) -> E,
        map_stale_fence: impl FnOnce(
            gossip_coordination::FenceEpoch,
            gossip_coordination::FenceEpoch,
        ) -> E,
    ) -> Result<PersistedShard, E>
    where
        E: From<gossip_coordination::CoordError>,
    {
        let key = lease.shard_key();
        let persisted = match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => return Err(map_not_found(key)),
            Err(err) => return Err(map_load_error(err)),
        };
        validate_loaded_shard_lease(now, tenant, lease, &persisted, map_stale_fence)?;
        Ok(persisted)
    }

    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError>;

    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError>;

    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError>;

    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError>;

    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError>;

    /// Load a run record by exact key and validate identity consistency.
    ///
    /// Decodes the stored record and verifies that its `tenant` and `run`
    /// fields match the key path used to retrieve it. This defense-in-depth
    /// check catches silent data corruption (e.g., a misplaced blob or
    /// corrupted write) at the access layer rather than surfacing it as
    /// a subtle logic error during validation.
    ///
    /// Returns `Ok(None)` if the key does not exist in etcd.
    fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace().run_record_key(tenant, run).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };

        let record =
            decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            })?;

        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != run {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record run id disagrees with key-path run id",
                },
            });
        }

        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    /// Load the per-tenant materialized shard counter.
    ///
    /// Returns `Ok(None)` when the counter key does not exist — callers
    /// bootstrap from a full tenant prefix scan in that case.
    fn load_tenant_shard_count(
        &self,
        tenant: TenantId,
    ) -> Result<Option<PersistedTenantShardCount>, EtcdCoordinatorError> {
        let key = self.keyspace().tenant_shard_count_key(tenant).into_bytes();
        let response = self.etcd_get(key, None)?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        Ok(Some(decode_tenant_shard_count_kv(kv)?))
    }

    /// Prepare a CAS-guarded per-tenant shard counter update.
    ///
    /// If the counter key exists, returns its current value with a
    /// revision-based CAS compare. If the key is absent (first shard
    /// creation for this tenant), bootstraps the count from a full
    /// tenant prefix scan and guards creation with `compare_absent`.
    ///
    /// The returned [`TenantShardCountMutation`] contains both the
    /// compare clause (for inclusion in the caller's CAS transaction)
    /// and the `current_count` (for shard-limit preflight checks).
    fn prepare_tenant_shard_count_mutation(
        &self,
        tenant: TenantId,
        additional: usize,
    ) -> Result<TenantShardCountMutation, EtcdCoordinatorError> {
        let counter_key = self.keyspace().tenant_shard_count_key(tenant);
        let delta = usize_to_u64_saturating(additional);
        if let Some(counter) = self.load_tenant_shard_count(tenant)? {
            return Ok(TenantShardCountMutation {
                key: counter_key.clone(),
                current_count: u64_to_usize_saturating(counter.count),
                next_count: counter.count.saturating_add(delta),
                compare: compare_tenant_shard_count_revision(counter_key, counter.mod_revision),
            });
        }

        let scanned =
            self.count_persisted_shards_under_prefix(self.keyspace().tenant_prefix(tenant))?;
        Ok(TenantShardCountMutation {
            key: counter_key.clone(),
            current_count: scanned,
            next_count: usize_to_u64_saturating(scanned).saturating_add(delta),
            compare: compare_absent(counter_key),
        })
    }

    /// Load a shard record and its co-located owner binding in one RPC.
    ///
    /// Uses a prefix-scoped `get` on the shard record key, which returns
    /// both the record itself and its `/owner` child key (if present) in
    /// a single etcd range read. This avoids a second round-trip to
    /// determine ownership status.
    ///
    /// After decoding, validates:
    /// - Record identity (tenant, run, shard) matches the key path.
    /// - If an owner key exists, its binding is consistent with the
    ///   record's lease holder and fence epoch.
    ///
    /// Returns `Ok(None)` if the shard record key does not exist.
    fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace()
            .shard_record_key(tenant, key.run(), key.shard());
        let owner_key = shard_record_key.owner_key();

        let response = self.etcd_get(
            shard_record_key.clone().into_bytes(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut record_kv: Option<&etcd_client::KeyValue> = None;
        let mut owner_kv: Option<&etcd_client::KeyValue> = None;

        for kv in response.kvs() {
            if kv.key() == shard_record_key.as_bytes() {
                record_kv = Some(kv);
            } else if kv.key() == owner_key.as_bytes() {
                owner_kv = Some(kv);
            }
        }

        let Some(kv) = record_kv else {
            return Ok(None);
        };

        let mut slab = make_decode_slab(kv.value().len());
        let record = decode_shard_record(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;

        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != key.run() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record run id disagrees with key-path run id",
                },
            });
        }
        if record.shard != key.shard() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record shard id disagrees with key-path shard id",
                },
            });
        }

        let mod_revision = kv.mod_revision();

        let owner = match owner_kv {
            None => None,
            Some(okv) => Some(decode_owner_kv(okv)?),
        };

        if let Some(owner) = &owner {
            validate_owner_consistency(owner, &record)?;
        }

        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision,
            owner,
        }))
    }

    /// Prefix-scan all shard records and owner bindings under a run.
    ///
    /// Performs a single etcd prefix range read that returns both shard
    /// record keys and owner keys interleaved. The results are classified
    /// and separated into two collections in a first pass, then joined
    /// by the owner key derived from each record key. This two-pass
    /// approach avoids N+1 round-trips for owner lookups.
    ///
    /// # Invariant checks
    ///
    /// - Each record's identity (tenant, run, shard) must match the
    ///   scan prefix and key path.
    /// - Every owner key must have a corresponding shard record (orphan
    ///   owners indicate corruption or incomplete cleanup).
    /// - No unexpected key types may appear under the shard subtree.
    fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self
            .keyspace()
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let response = self.etcd_get(prefix, Some(GetOptions::new().with_prefix()))?;

        let mut owner_map = HashMap::<ShardOwnerKey, PersistedOwner>::new();
        let mut record_kvs =
            Vec::<(ShardRecordKey, Vec<u8>, i64)>::with_capacity(response.kvs().len());

        for kv in response.kvs() {
            match PersistedShardSubtreeKey::classify(kv.key()) {
                Some(PersistedShardSubtreeKey::Owner) => {
                    let owner_key = ShardOwnerKey::from_encoded_key(kv.key()).ok_or_else(|| {
                        EtcdCoordinatorError::Codec {
                            operation: EtcdOperation::Get,
                            source: EtcdCodecError::InvariantViolation {
                                kind: "OwnerKey",
                                detail: "owner key under shard scan prefix is malformed",
                            },
                        }
                    })?;
                    owner_map.insert(owner_key, decode_owner_kv(kv)?);
                }
                Some(PersistedShardSubtreeKey::Record) => {
                    let record_key =
                        ShardRecordKey::from_encoded_key(kv.key()).ok_or_else(|| {
                            EtcdCoordinatorError::Codec {
                                operation: EtcdOperation::Get,
                                source: EtcdCodecError::InvariantViolation {
                                    kind: "ShardRecord",
                                    detail: "shard record key under scan prefix is malformed",
                                },
                            }
                        })?;
                    record_kvs.push((record_key, kv.value().to_vec(), kv.mod_revision()));
                }
                None => {
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "ShardKey",
                            detail: "unexpected key found under shard scan prefix",
                        },
                    });
                }
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = make_decode_slab(value.len());
            let record = decode_shard_record(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;

            if record.tenant != tenant || record.run != run {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record identity disagrees with scan prefix",
                    },
                });
            }
            let expected_key = self.keyspace().shard_record_key(tenant, run, record.shard);
            if record_key != expected_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record shard id disagrees with key path",
                    },
                });
            }

            let owner = owner_map.remove(&record_key.owner_key());

            if let Some(owner) = &owner {
                validate_owner_consistency(owner, &record)?;
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

    /// Prefix-scan all run records under a tenant.
    ///
    /// Returns all runs (including terminal ones) sorted by raw run ID.
    /// Validates that each record's tenant matches and that the record's
    /// run ID matches the key suffix. Keys that do not parse as direct
    /// run IDs are silently skipped (they may be sub-keys like active
    /// index entries).
    fn scan_tenant_runs(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<PersistedRun>, EtcdCoordinatorError> {
        let prefix = self.keyspace().run_records_scan_prefix(tenant);
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut out = Vec::with_capacity(response.kvs().len());
        for kv in response.kvs() {
            let Some(run_from_key) = RunRecordKey::parse_direct_run_id(&prefix, kv.key()) else {
                continue;
            };
            let record =
                decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
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
        out.sort_unstable_by_key(|persisted| persisted.record.run.as_raw());
        Ok(out)
    }

    /// Estimate the number of claimable shards for a run using cheap RPCs.
    ///
    /// Computes `available = total_active - owned` using two lightweight
    /// etcd requests:
    ///
    /// 1. A `count_only` prefix scan on the active-shard index (no values
    ///    transferred) to get `total_active`.
    /// 2. A `keys_only` prefix scan on the shard record subtree, filtering
    ///    for `/owner` keys to get `owned`.
    ///
    /// This is an approximation: the two reads are not atomic, so
    /// concurrent acquires or releases may cause brief overcounting or
    /// undercounting. The trade-off is acceptable because `CapacityHint`
    /// is advisory and only used for scheduling heuristics, not for
    /// correctness-critical decisions.
    ///
    /// `earliest_deadline` is always `None` because computing it would
    /// require loading full shard record blobs.
    fn count_available_lightweight(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let active_prefix = self
            .keyspace()
            .shards_active_prefix(tenant, run)
            .into_bytes();
        let active_response = self.etcd_get(
            active_prefix,
            Some(GetOptions::new().with_prefix().with_count_only()),
        )?;
        let total_active = u32::try_from(active_response.count()).unwrap_or_else(|_| {
            tracing::warn!(
                count = active_response.count(),
                "etcd active count exceeds u32 range; clamping to u32::MAX"
            );
            u32::MAX
        });

        let shards_prefix = self.keyspace().shard_records_scan_prefix(tenant, run);
        let keys_response = self.etcd_get(
            shards_prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        let owned_count = u32::try_from(
            keys_response
                .kvs()
                .iter()
                .filter(|kv| {
                    ShardOwnerKey::parse_owned_shard(shards_prefix.as_bytes(), kv.key()).is_some()
                })
                .count(),
        )
        .unwrap_or(u32::MAX);

        Ok(CapacityHint {
            available_count: total_active.saturating_sub(owned_count),
            earliest_deadline: None,
        })
    }

    /// Count shard records under a keyspace prefix, excluding owner keys.
    ///
    /// Uses a `keys_only` prefix scan and classifies each key via
    /// [`PersistedShardSubtreeKey`] to count only record keys, not
    /// owner keys that share the same prefix. Used for shard-limit
    /// preflight checks.
    fn count_persisted_shards_under_prefix(
        &self,
        prefix: String,
    ) -> Result<usize, EtcdCoordinatorError> {
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        Ok(response
            .kvs()
            .iter()
            .filter(|kv| {
                PersistedShardSubtreeKey::classify(kv.key())
                    == Some(PersistedShardSubtreeKey::Record)
            })
            .count())
    }

    /// List active run IDs by scanning the active-run index.
    ///
    /// Only runs that have completed `register_shards` (and thus have
    /// an active-run index entry) appear here. Results are sorted by
    /// raw run ID for deterministic ordering.
    fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut prefix = self.keyspace().runs_active_prefix(tenant);
        prefix.push('/');
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix().with_keys_only()),
        )?;
        out.clear();
        for kv in response.kvs() {
            if let Some(run) = RunActiveIndexKey::parse_direct_run_id(&prefix, kv.key()) {
                out.push(run);
            }
        }
        out.sort_unstable_by_key(|run| run.as_raw());
        Ok(())
    }

    /// Garbage-collect runs stuck in `Initializing` past a creation-time
    /// cutoff.
    ///
    /// Runs that fail to complete `register_shards` (e.g., the creating
    /// worker crashes) leave behind orphaned `Initializing` records. This
    /// method scans all tenant runs, filters to stale initializing ones,
    /// and attempts to delete each via a CAS transaction guarded by:
    ///
    /// - Run record `mod_revision` (unchanged since the scan).
    /// - Active-run index absent (the run was never activated).
    ///
    /// Each successful deletion also removes the run's shard records,
    /// active-shard index entries, and adjusts the per-tenant shard
    /// counter. Candidates are processed oldest-first to prioritize the
    /// most stale runs.
    ///
    /// Concurrent activation (a late `register_shards` succeeding between
    /// the scan and the GC transaction) causes the CAS to fail, which is
    /// silently skipped.
    fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        cutoff: LogicalTime,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut candidates = self.scan_tenant_runs(tenant)?;
        candidates.retain(|persisted| {
            persisted.record.status == RunStatus::Initializing
                && persisted.record.created_at < cutoff
        });
        candidates.sort_by(|left, right| {
            left.record
                .created_at
                .cmp(&right.record.created_at)
                .then_with(|| left.record.run.as_raw().cmp(&right.record.run.as_raw()))
        });

        out.clear();
        for persisted in candidates {
            let run = persisted.record.run;
            let run_key = self.keyspace().run_record_key(tenant, run);
            let active_key = self.keyspace().run_active_index_key(tenant, run);
            let shard_prefix = self.keyspace().shard_records_scan_prefix(tenant, run);
            let mut active_shard_prefix = self.keyspace().shards_active_prefix(tenant, run);
            active_shard_prefix.push('/');
            let removed_shard_count =
                self.count_persisted_shards_under_prefix(shard_prefix.clone())?;

            let counter_key = self.keyspace().tenant_shard_count_key(tenant);
            let (counter_compare, next_count) = if let Some(counter) =
                self.load_tenant_shard_count(tenant)?
            {
                let removed = usize_to_u64_saturating(removed_shard_count);
                let next = match counter.count.checked_sub(removed) {
                    Some(n) => n,
                    None => {
                        tracing::warn!(
                            tenant = %tenant,
                            persisted_count = counter.count,
                            removed = removed,
                            "tenant shard counter underflow during GC; \
                             rebuilding from scan"
                        );
                        let scanned = self.count_persisted_shards_under_prefix(
                            self.keyspace().tenant_prefix(tenant),
                        )?;
                        usize_to_u64_saturating(scanned).saturating_sub(removed)
                    }
                };
                (
                    compare_tenant_shard_count_revision(counter_key.clone(), counter.mod_revision),
                    next,
                )
            } else {
                let scanned = self
                    .count_persisted_shards_under_prefix(self.keyspace().tenant_prefix(tenant))?;
                let next = usize_to_u64_saturating(scanned)
                    .saturating_sub(usize_to_u64_saturating(removed_shard_count));
                (compare_absent(counter_key.clone()), next)
            };

            let mut txn = TxnBuilder::new();
            txn.compare(compare_run_revision(
                run_key.clone(),
                persisted.mod_revision,
            ))
            .compare(compare_absent(active_key.clone()))
            .delete(run_key.into_bytes())
            .delete(active_key.into_bytes())
            .ops([
                TxnOp::delete(
                    shard_prefix.into_bytes(),
                    Some(DeleteOptions::new().with_prefix()),
                ),
                TxnOp::delete(
                    active_shard_prefix.into_bytes(),
                    Some(DeleteOptions::new().with_prefix()),
                ),
            ]);
            txn.compare(counter_compare).put(
                counter_key.into_bytes(),
                encode_tenant_shard_count(next_count),
            );

            let response = self.etcd_txn(txn.build())?;
            if response.succeeded() {
                self.on_gc_run(tenant, run);
                out.push(run);
            } else {
                tracing::debug!(
                    ?run,
                    "GC: skipped stale run (concurrent activation or revision change)"
                );
            }
        }

        Ok(())
    }

    /// Shared CAS implementation for terminal run transitions
    /// (Done, Failed, Cancelled).
    ///
    /// The CAS transaction adapts its active-run index guard based on
    /// the run's prior status:
    ///
    /// - `Active` runs have an index entry → guard with `compare_present`.
    /// - `Initializing` runs have no index entry → guard with
    ///   `compare_absent`. Only `cancel_run` reaches this path; the
    ///   other two transitions (`complete_run`, `fail_run`) require
    ///   `Active` status.
    ///
    /// In both cases, the index entry is deleted on commit.
    ///
    /// Idempotent via run op-log. Kind-mismatch on replay (same `op_id`
    /// but different `RunOpKind`) is treated as corruption.
    fn transition_run_terminal(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
        op_kind: RunOpKind,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let (target_status, payload_hash, require_active) = match op_kind {
            RunOpKind::CompleteRun => (RunStatus::Done, hash_complete_run_payload(), true),
            RunOpKind::FailRun => (RunStatus::Failed, hash_fail_run_payload(), true),
            RunOpKind::CancelRun => (RunStatus::Cancelled, hash_cancel_run_payload(), false),
            RunOpKind::RegisterShards => {
                unreachable!("transition_run_terminal does not handle RegisterShards")
            }
        };

        self.cas_retry(
            |this, _attempt| {
                let persisted = match this.load_run_record(tenant, run) {
                    Ok(Some(run_record)) => run_record,
                    Ok(None) => return Err(RunTransitionError::RunNotFound),
                    Err(err) => {
                        return Err(RunTransitionError::BackendError(super::map_etcd_err(
                            "run_terminal.load_run",
                            err,
                        )));
                    }
                };
                let prior_status = persisted.record.status;
                let mut record = persisted.record;

                if record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.idempotent_replay",
                            format!(
                                "kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        )));
                    }
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                }
                if record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: record.status,
                    });
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
                    target_status,
                    op_id,
                    op_kind,
                    payload_hash,
                );
                let run_blob = encode_run_record(&record);
                let run_key = this.keyspace().run_record_key(tenant, run);
                let active_key = this.keyspace().run_active_index_key(tenant, run);
                let mut compares = vec![compare_run_revision(
                    run_key.clone(),
                    persisted.mod_revision,
                )];
                match prior_status {
                    RunStatus::Active => {
                        compares.push(compare_present(active_key.clone()));
                    }
                    RunStatus::Initializing => {
                        compares.push(compare_absent(active_key.clone()));
                    }
                    RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled => {
                        unreachable!("terminal statuses return early")
                    }
                }

                let mut txn = TxnBuilder::new();
                txn.compare_all(compares)
                    .put(run_key.into_bytes(), run_blob)
                    .delete(active_key.into_bytes());
                txn.execute(this, IdempotentOutcome::Executed(()))
                    .map_err(|err| {
                        RunTransitionError::BackendError(super::map_etcd_err(
                            "run_terminal.txn",
                            err,
                        ))
                    })
            },
            |this| {
                let persisted = match this.load_run_record(tenant, run) {
                    Ok(Some(r)) => r,
                    Ok(None) if !require_active => return Err(RunTransitionError::RunNotFound),
                    Ok(None) => {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.exhaust.load_run",
                            format!("run {run:?} missing (expected Active)"),
                        )));
                    }
                    Err(err) => {
                        return Err(RunTransitionError::BackendError(super::map_etcd_err(
                            "run_terminal.exhaust.load_run",
                            err,
                        )));
                    }
                };
                if persisted.record.tenant != tenant {
                    return Err(RunTransitionError::TenantMismatch { expected: tenant });
                }
                if let Some(entry) = persisted.record.check_op_idempotency(op_id, payload_hash)? {
                    if entry.kind() != op_kind {
                        return Err(RunTransitionError::BackendError(InfraError::corruption(
                            "run_terminal.idempotent_replay",
                            format!(
                                "kind mismatch: expected {op_kind:?}, got {:?}",
                                entry.kind()
                            ),
                        )));
                    }
                    return Ok(IdempotentOutcome::Replayed(()));
                }
                if persisted.record.status.is_terminal() {
                    return Err(RunTransitionError::RunTerminal {
                        status: persisted.record.status,
                    });
                }
                if require_active && persisted.record.status != RunStatus::Active {
                    return Err(RunTransitionError::WrongStatus {
                        status: persisted.record.status,
                        target: target_status,
                    });
                }

                Err(RunTransitionError::BackendError(InfraError::transient(
                    "run_terminal",
                    "CAS retry budget exhausted",
                )))
            },
        )
    }

    /// Revoke an etcd lease, logging but not propagating failures.
    ///
    /// Called after CAS transactions that either grant a new lease
    /// (revoking the prior one) or release ownership (revoking the
    /// current one). If the revocation fails, the lease will expire
    /// via etcd's TTL mechanism, so correctness is preserved — the
    /// revocation only accelerates cleanup.
    ///
    /// No-ops for non-positive lease IDs (etcd sentinel for "no lease").
    fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        if let Err(err) = self.etcd_lease_revoke(lease_id) {
            tracing::warn!(
                lease_id,
                %err,
                ttl_secs = self.config().owner_lease_ttl_secs(),
                "failed to revoke etcd lease; will expire via TTL",
            );
        }
    }

    /// Load a run record that is expected to exist.
    ///
    /// Returns `InfraError::corruption` if the key is missing — callers
    /// use this in contexts where a missing run indicates data loss or
    /// an invariant violation, not a normal "not found" condition.
    fn load_run_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        run: RunId,
    ) -> Result<PersistedRun, InfraError> {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => Ok(run_record),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("run {run:?} missing"),
            )),
            Err(err) => Err(super::map_etcd_err(context, err)),
        }
    }

    /// Load a shard record that is expected to exist.
    ///
    /// Returns `InfraError::corruption` if the key is missing.
    /// See [`load_run_checked`](Self::load_run_checked) for rationale.
    fn load_shard_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<PersistedShard, InfraError> {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => Ok(shard),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("shard {key:?} missing"),
            )),
            Err(err) => Err(super::map_etcd_err(context, err)),
        }
    }

    #[cfg(any(test, feature = "test-support"))]
    fn inject_split_replace_fault_if_armed(&mut self, _tenant: TenantId, _key: ShardKey) {}

    #[cfg(any(test, feature = "test-support"))]
    fn inject_split_residual_fault_if_armed(&mut self, _tenant: TenantId, _key: ShardKey) {}
}

// ---------------------------------------------------------------------------
// EtcdCoordinator — sync wrapper
// ---------------------------------------------------------------------------

/// etcd-backed coordination backend (sync wrapper).
///
/// Owns a single-threaded Tokio runtime and wraps individual etcd RPCs
/// (`get`, `txn`, `lease_grant`, etc.) in `runtime.block_on(...)`.
/// Implements the full sync trait surface: [`CoordinationBackend`](gossip_coordination::CoordinationBackend),
/// [`RunManagement`](gossip_coordination::RunManagement), and [`ShardClaiming`](gossip_coordination::ShardClaiming).
///
/// [`AsyncEtcdCoordinator`] provides the same operations as native
/// `async fn` methods for callers that already have a Tokio runtime.
/// Both implementations share static helpers and the same validation
/// logic but maintain separate method bodies.
///
/// ## Threading model
///
/// Callers **must not** invoke methods from within an existing Tokio
/// runtime — `block_on` within `block_on` deadlocks. Runtime guards
/// on all `block_on` call sites panic early if this invariant is
/// violated.
///
/// ## Scratch allocation
///
/// `claim_candidates_scratch` is a reusable buffer for
/// [`default_claim_next_available`](gossip_coordination::default_claim_next_available). It is `mem::take`-ed at the start of
/// each claim and restored afterward, avoiding per-claim heap allocation
/// in the common case where the buffer capacity is already sufficient.
pub struct EtcdCoordinator {
    pub(super) config: EtcdCoordinatorConfig,
    pub(super) keyspace: EtcdKeyspace,
    pub(super) runtime: tokio::runtime::Runtime,
    pub(super) client: etcd_client::Client,
    /// Reusable buffer for shard-claim candidate collection, avoiding
    /// per-claim allocation.
    pub(super) claim_candidates_scratch: Vec<ShardId>,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) test_faults: EtcdTestFaultState,
}

impl EtcdCoordinator {
    /// Connect to etcd, verify connectivity with `status`, and create the
    /// backend.
    ///
    /// # Panics
    ///
    /// Asserts that no Tokio runtime is active on the current thread.
    /// The backend owns a single-threaded runtime internally and
    /// `block_on` within an existing runtime would deadlock.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError`] on config validation failure,
    /// Tokio runtime creation failure, connection failure, or if the
    /// initial `status` health check fails.
    pub fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;

        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "EtcdCoordinator::connect() must not be called from within an \
             active Tokio runtime — use AsyncEtcdCoordinator::connect() instead"
        );

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .map_err(EtcdCoordinatorError::RuntimeBuild)?;

        let endpoints = config.endpoints().to_vec();
        let mut connect_opts =
            etcd_client::ConnectOptions::new().with_connect_timeout(DEFAULT_CONNECT_TIMEOUT);
        if let Some((user, password)) = config.auth() {
            connect_opts = connect_opts.with_user(user, password);
        }
        #[cfg(feature = "tls")]
        if let Some(tls) = config.tls().cloned() {
            connect_opts = connect_opts.with_tls(tls);
        }

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

        let keyspace = EtcdKeyspace::new(config.namespace_prefix())?;

        Ok(Self {
            config,
            keyspace,
            runtime,
            client,
            claim_candidates_scratch: Vec::new(),
            #[cfg(any(test, feature = "test-support"))]
            test_faults: EtcdTestFaultState::default(),
        })
    }

    /// The validated configuration used to construct this backend.
    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    /// The keyspace builder used for all etcd key construction.
    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    /// Panics if an active Tokio runtime exists on the current thread.
    ///
    /// All sync methods funnel through `runtime.block_on(...)`, which
    /// deadlocks when called from within an existing runtime. This
    /// guard catches that programming error early.
    pub(super) fn assert_not_in_async_context(&self) {
        assert!(
            tokio::runtime::Handle::try_current().is_err(),
            "EtcdCoordinator sync methods must not be called from within an \
             active Tokio runtime — use AsyncEtcdCoordinator instead"
        );
    }

    /// Round-trip a maintenance `status` request against etcd.
    pub fn status(&self) -> Result<etcd_client::StatusResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();

        let mut client = self.client.clone();
        self.runtime
            .block_on(client.status())
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })
    }

    /// Execute a `get` RPC on the internal single-threaded Tokio runtime.
    pub(super) fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.get(key, options))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Get,
                source,
            })
    }

    /// Execute a `txn` (compare-and-swap) RPC on the internal runtime.
    pub(super) fn etcd_txn(
        &self,
        txn: Txn,
    ) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.txn(txn))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    /// Grant an etcd lease with the given TTL in seconds.
    pub(super) fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_grant(ttl, None))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    /// Send a single keep-alive ping for an existing etcd lease and
    /// consume the server ACK to confirm the renewal succeeded.
    pub(super) fn etcd_lease_keep_alive_once(
        &self,
        lease_id: i64,
    ) -> Result<(), EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(async move {
                let (mut keeper, mut stream) = client.lease_keep_alive(lease_id).await?;
                keeper.keep_alive().await?;
                // The keep_alive() call only sends the request; the server
                // ACK (or error) arrives on the response stream. Read it to
                // confirm the lease was actually renewed.
                match stream.message().await? {
                    Some(resp) if resp.ttl() > 0 => Ok(()),
                    _ => Err(etcd_client::Error::LeaseKeepAliveError(
                        "lease expired or keep-alive rejected by server".into(),
                    )),
                }
            })
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })
    }

    /// Immediately revoke an etcd lease, causing all keys attached to it
    /// to be deleted.
    pub(super) fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        self.assert_not_in_async_context();
        let mut client = self.client.clone();
        self.runtime
            .block_on(client.lease_revoke(lease_id))
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

    /// List runs visible to workers by scanning only the active-run index.
    pub fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        <Self as SyncEtcdLike>::list_active_runs_into(self, tenant, out)
    }

    /// Garbage-collect stale runs that never left `Initializing`.
    pub fn gc_stale_initializing_runs_into(
        &mut self,
        tenant: TenantId,
        cutoff: LogicalTime,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        <Self as SyncEtcdLike>::gc_stale_initializing_runs_into(self, tenant, cutoff, out)
    }
}

impl TxnBuilder {
    /// Execute the assembled transaction through the sync coordinator and
    /// translate etcd success/failure into a CAS retry outcome.
    pub(crate) fn execute<T, C: SyncEtcdLike>(
        self,
        coordinator: &C,
        on_success: T,
    ) -> Result<CasOutcome<T>, EtcdCoordinatorError> {
        let response = coordinator.etcd_txn(self.build())?;
        if response.succeeded() {
            Ok(CasOutcome::Committed(on_success))
        } else {
            Ok(CasOutcome::RetryNeeded)
        }
    }
}

impl SyncEtcdLike for EtcdCoordinator {
    fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    fn etcd_get(
        &self,
        key: Vec<u8>,
        options: Option<GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        EtcdCoordinator::etcd_get(self, key, options)
    }

    fn etcd_txn(&self, txn: Txn) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        EtcdCoordinator::etcd_txn(self, txn)
    }

    fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        EtcdCoordinator::etcd_lease_grant(self, ttl)
    }

    fn etcd_lease_keep_alive_once(&self, lease_id: i64) -> Result<(), EtcdCoordinatorError> {
        EtcdCoordinator::etcd_lease_keep_alive_once(self, lease_id)
    }

    fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        EtcdCoordinator::etcd_lease_revoke(self, lease_id)
    }

    #[cfg(any(test, feature = "test-support"))]
    fn inject_split_replace_fault_if_armed(&mut self, tenant: TenantId, key: ShardKey) {
        EtcdCoordinator::inject_split_replace_fault_if_armed(self, tenant, key);
    }

    #[cfg(any(test, feature = "test-support"))]
    fn inject_split_residual_fault_if_armed(&mut self, tenant: TenantId, key: ShardKey) {
        EtcdCoordinator::inject_split_residual_fault_if_armed(self, tenant, key);
    }
}

impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted shard lifecycle + run lifecycle in etcd",
            )
            .finish()
    }
}

// ---------------------------------------------------------------------------
// AsyncEtcdCoordinator — async core (no runtime)
// ---------------------------------------------------------------------------

/// Async core of the etcd coordination backend.
///
/// Contains all coordination logic and etcd client state. Does not own
/// a Tokio runtime — callers provide their own async execution context.
/// Implements [`AsyncCoordinationBackend`](gossip_coordination::AsyncCoordinationBackend)
/// and [`AsyncRunManagement`](gossip_coordination::AsyncRunManagement).
///
/// Use [`EtcdCoordinator`] for a sync wrapper that owns a single-threaded
/// runtime and delegates via `block_on`.
///
pub struct AsyncEtcdCoordinator {
    pub(super) config: EtcdCoordinatorConfig,
    pub(super) keyspace: EtcdKeyspace,
    pub(super) client: etcd_client::Client,
    #[cfg(any(test, feature = "test-support"))]
    pub(super) test_faults: EtcdTestFaultState,
}

impl AsyncEtcdCoordinator {
    /// Connect to etcd and verify connectivity — for use within an
    /// existing async runtime (e.g., Tokio).
    ///
    /// Validates configuration, establishes the etcd client connection,
    /// runs a `status` health check, and constructs the keyspace builder.
    ///
    /// Unlike [`EtcdCoordinator::connect`], this does not create a Tokio
    /// runtime — it must be called from within one.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError`] on config validation failure,
    /// connection failure, or if the initial `status` health check fails.
    pub async fn connect(config: EtcdCoordinatorConfig) -> Result<Self, EtcdCoordinatorError> {
        config.validate()?;

        let endpoints = config.endpoints().to_vec();
        let mut connect_opts =
            etcd_client::ConnectOptions::new().with_connect_timeout(DEFAULT_CONNECT_TIMEOUT);
        if let Some((user, password)) = config.auth() {
            connect_opts = connect_opts.with_user(user, password);
        }
        #[cfg(feature = "tls")]
        if let Some(tls) = config.tls().cloned() {
            connect_opts = connect_opts.with_tls(tls);
        }

        let mut client = etcd_client::Client::connect(endpoints, Some(connect_opts))
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Connect,
                source,
            })?;

        client
            .status()
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })?;

        let keyspace = EtcdKeyspace::new(config.namespace_prefix())?;

        Ok(Self {
            config,
            keyspace,
            client,
            #[cfg(any(test, feature = "test-support"))]
            test_faults: EtcdTestFaultState::default(),
        })
    }

    /// The validated configuration.
    #[must_use]
    pub fn config(&self) -> &EtcdCoordinatorConfig {
        &self.config
    }

    /// The keyspace builder.
    #[must_use]
    pub fn keyspace(&self) -> &EtcdKeyspace {
        &self.keyspace
    }

    /// Async health check.
    pub async fn status(&self) -> Result<etcd_client::StatusResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client
            .status()
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Status,
                source,
            })
    }

    // -- Low-level async etcd RPC wrappers --
    //
    // Mirror the sync `etcd_*` methods on `EtcdCoordinator`. Each clones the
    // etcd client (cheap Arc bump) and wraps the gRPC error with
    // `EtcdCoordinatorError::Etcd` for uniform error handling.

    /// Execute an async `get` RPC.
    pub(super) async fn etcd_get(
        &self,
        key: impl Into<Vec<u8>>,
        options: Option<etcd_client::GetOptions>,
    ) -> Result<etcd_client::GetResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client
            .get(key, options)
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Get,
                source,
            })
    }

    /// Execute an async CAS `txn` RPC.
    pub(super) async fn etcd_txn(
        &self,
        txn: etcd_client::Txn,
    ) -> Result<etcd_client::TxnResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client
            .txn(txn)
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::Txn,
                source,
            })
    }

    /// Grant an etcd lease with the given TTL (seconds).
    pub(super) async fn etcd_lease_grant(
        &self,
        ttl: i64,
    ) -> Result<etcd_client::LeaseGrantResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client
            .lease_grant(ttl, None)
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseGrant,
                source,
            })
    }

    /// Send a single keep-alive ping for an existing etcd lease and
    /// consume the server ACK to confirm the renewal succeeded.
    pub(super) async fn etcd_lease_keep_alive_once(
        &self,
        lease_id: i64,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut client = self.client.clone();
        let (mut keeper, mut stream) =
            client.lease_keep_alive(lease_id).await.map_err(|source| {
                EtcdCoordinatorError::Etcd {
                    operation: EtcdOperation::LeaseKeepAlive,
                    source,
                }
            })?;
        keeper
            .keep_alive()
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })?;
        match stream
            .message()
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source,
            })? {
            Some(resp) if resp.ttl() > 0 => Ok(()),
            _ => Err(EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseKeepAlive,
                source: etcd_client::Error::LeaseKeepAliveError(
                    "lease expired or keep-alive rejected by server".into(),
                ),
            }),
        }
    }

    /// Immediately revoke an etcd lease (async).
    pub(super) async fn etcd_lease_revoke(
        &self,
        lease_id: i64,
    ) -> Result<etcd_client::LeaseRevokeResponse, EtcdCoordinatorError> {
        let mut client = self.client.clone();
        client
            .lease_revoke(lease_id)
            .await
            .map_err(|source| EtcdCoordinatorError::Etcd {
                operation: EtcdOperation::LeaseRevoke,
                source,
            })
    }

    /// Best-effort lease revocation. Logs the error but does not propagate it.
    pub(super) async fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        if let Err(err) = self.etcd_lease_revoke(lease_id).await {
            tracing::warn!(
                lease_id,
                %err,
                ttl_secs = self.config.owner_lease_ttl_secs(),
                "failed to revoke etcd lease; will expire via TTL",
            );
        }
    }

    async fn refresh_cached_run_state(
        &mut self,
        _tenant: TenantId,
        _run: RunId,
    ) -> Result<(), EtcdCoordinatorError> {
        Ok(())
    }

    /// Best-effort async cache refresh after a run-scoped mutation.
    ///
    /// The async coordinator currently does not maintain a decoded run cache,
    /// so this is a no-op that preserves the same call sites as the sync
    /// surface. If async caching is added later, the refresh logic can land
    /// here without changing mutation semantics.
    pub(super) async fn best_effort_refresh_cached_run_state(
        &mut self,
        tenant: TenantId,
        run: RunId,
    ) {
        if let Err(err) = self.refresh_cached_run_state(tenant, run).await {
            tracing::warn!(
                %err,
                %tenant,
                ?run,
                "post-commit cache refresh failed; cache is stale until next mutation",
            );
        }
    }

    // -- Higher-level data access helpers (async) --
    //
    // These are async mirrors of the sync helpers on `EtcdCoordinator`.
    // They perform the same defense-in-depth identity validation.

    /// Load a single run record by exact key (async).
    ///
    /// See [`EtcdCoordinator::load_run_record`] for validation details.
    pub(super) async fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(tenant, run).into_bytes();
        let response = self.etcd_get(key, None).await?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        let record =
            decode_run_record(kv.value()).map_err(|source| EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            })?;

        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != run {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "RunRecord",
                    detail: "run record run id disagrees with key-path run id",
                },
            });
        }

        Ok(Some(PersistedRun {
            record,
            mod_revision: kv.mod_revision(),
        }))
    }

    /// Load the per-tenant materialized shard counter key (async).
    ///
    /// Returns `Ok(None)` when the counter key does not exist; callers then
    /// bootstrap from a tenant prefix scan.
    pub(super) async fn load_tenant_shard_count(
        &self,
        tenant: TenantId,
    ) -> Result<Option<PersistedTenantShardCount>, EtcdCoordinatorError> {
        let key = self.keyspace.tenant_shard_count_key(tenant).into_bytes();
        let response = self.etcd_get(key, None).await?;
        let Some(kv) = response.kvs().first() else {
            return Ok(None);
        };
        Ok(Some(decode_tenant_shard_count_kv(kv)?))
    }

    /// Prepare a CAS-guarded per-tenant counter update for one mutation.
    ///
    /// If the counter key exists, uses its current value and revision.
    /// If absent, bootstraps from a tenant shard scan and guards creation
    /// with `compare_absent`.
    pub(super) async fn prepare_tenant_shard_count_mutation(
        &self,
        tenant: TenantId,
        additional: usize,
    ) -> Result<TenantShardCountMutation, EtcdCoordinatorError> {
        let counter_key = self.keyspace.tenant_shard_count_key(tenant);
        let delta = usize_to_u64_saturating(additional);
        if let Some(counter) = self.load_tenant_shard_count(tenant).await? {
            return Ok(TenantShardCountMutation {
                key: counter_key.clone(),
                current_count: u64_to_usize_saturating(counter.count),
                next_count: counter.count.saturating_add(delta),
                compare: compare_tenant_shard_count_revision(counter_key, counter.mod_revision),
            });
        }

        let scanned = self
            .count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))
            .await?;
        Ok(TenantShardCountMutation {
            key: counter_key.clone(),
            current_count: scanned,
            next_count: usize_to_u64_saturating(scanned).saturating_add(delta),
            compare: compare_absent(counter_key),
        })
    }

    /// Load a shard record and its owner binding by exact key (async).
    ///
    /// See [`EtcdCoordinator::load_shard_record`] for validation details.
    pub(super) async fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard());
        let owner_key = shard_record_key.owner_key();
        let response = self
            .etcd_get(
                shard_record_key.clone().into_bytes(),
                Some(GetOptions::new().with_prefix()),
            )
            .await?;

        let mut record_kv: Option<&etcd_client::KeyValue> = None;
        let mut owner_kv: Option<&etcd_client::KeyValue> = None;
        for kv in response.kvs() {
            if kv.key() == shard_record_key.as_bytes() {
                record_kv = Some(kv);
            } else if kv.key() == owner_key.as_bytes() {
                owner_kv = Some(kv);
            }
        }

        let Some(kv) = record_kv else {
            return Ok(None);
        };
        let mut slab = make_decode_slab(kv.value().len());
        let record = decode_shard_record(kv.value(), &mut slab).map_err(|source| {
            EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source,
            }
        })?;

        if record.tenant != tenant {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record tenant disagrees with key-path tenant",
                },
            });
        }
        if record.run != key.run() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record run id disagrees with key-path run id",
                },
            });
        }
        if record.shard != key.shard() {
            return Err(EtcdCoordinatorError::Codec {
                operation: EtcdOperation::Get,
                source: EtcdCodecError::InvariantViolation {
                    kind: "ShardRecord",
                    detail: "shard record shard id disagrees with key-path shard id",
                },
            });
        }

        let mod_revision = kv.mod_revision();
        let owner = match owner_kv {
            None => None,
            Some(okv) => Some(decode_owner_kv(okv)?),
        };
        if let Some(owner) = &owner {
            validate_owner_consistency(owner, &record)?;
        }
        Ok(Some(PersistedShard {
            record,
            slab,
            mod_revision,
            owner,
        }))
    }

    /// Prefix-scan all shard records under a run (async).
    ///
    /// See [`EtcdCoordinator::scan_run_shards`] for validation details.
    pub(super) async fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let response = self
            .etcd_get(prefix, Some(GetOptions::new().with_prefix()))
            .await?;

        let mut owner_map = HashMap::<ShardOwnerKey, PersistedOwner>::new();
        let mut record_kvs = Vec::<(ShardRecordKey, Vec<u8>, i64)>::new();
        for kv in response.kvs() {
            match PersistedShardSubtreeKey::classify(kv.key()) {
                Some(PersistedShardSubtreeKey::Owner) => {
                    let owner_key = ShardOwnerKey::from_encoded_key(kv.key()).ok_or_else(|| {
                        EtcdCoordinatorError::Codec {
                            operation: EtcdOperation::Get,
                            source: EtcdCodecError::InvariantViolation {
                                kind: "OwnerKey",
                                detail: "owner key under shard scan prefix is malformed",
                            },
                        }
                    })?;
                    owner_map.insert(owner_key, decode_owner_kv(kv)?);
                }
                Some(PersistedShardSubtreeKey::Record) => {
                    let record_key =
                        ShardRecordKey::from_encoded_key(kv.key()).ok_or_else(|| {
                            EtcdCoordinatorError::Codec {
                                operation: EtcdOperation::Get,
                                source: EtcdCodecError::InvariantViolation {
                                    kind: "ShardRecord",
                                    detail: "shard record key under scan prefix is malformed",
                                },
                            }
                        })?;
                    record_kvs.push((record_key, kv.value().to_vec(), kv.mod_revision()));
                }
                None => {
                    // Fail closed when an unknown key appears inside the
                    // persisted shard subtree: this keyspace is schema-bound
                    // and mixed-version readers must upgrade in lockstep.
                    return Err(EtcdCoordinatorError::Codec {
                        operation: EtcdOperation::Get,
                        source: EtcdCodecError::InvariantViolation {
                            kind: "ShardKey",
                            detail: "unexpected key found under shard scan prefix",
                        },
                    });
                }
            }
        }

        let mut out = Vec::with_capacity(record_kvs.len());
        for (record_key, value, mod_revision) in record_kvs {
            let mut slab = make_decode_slab(value.len());
            let record = decode_shard_record(&value, &mut slab).map_err(|source| {
                EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source,
                }
            })?;
            // Defense-in-depth: verify decoded payload identity matches
            // the scanned key path. The prefix constrains etcd results,
            // but corrupt data can still encode mismatched tenant/run/shard.
            if record.tenant != tenant || record.run != run {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record identity disagrees with scan prefix",
                    },
                });
            }
            let expected_key = self.keyspace.shard_record_key(tenant, run, record.shard);
            if record_key != expected_key {
                return Err(EtcdCoordinatorError::Codec {
                    operation: EtcdOperation::Get,
                    source: EtcdCodecError::InvariantViolation {
                        kind: "ShardRecord",
                        detail: "shard record shard id disagrees with key path",
                    },
                });
            }
            let owner = owner_map.remove(&record_key.owner_key());
            if let Some(owner) = &owner {
                validate_owner_consistency(owner, &record)?;
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

    /// Count persisted shard records under a prefix (async).
    ///
    /// See [`EtcdCoordinator::count_persisted_shards_under_prefix`].
    pub(super) async fn count_persisted_shards_under_prefix(
        &self,
        prefix: String,
    ) -> Result<usize, EtcdCoordinatorError> {
        let response = self
            .etcd_get(
                prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .await?;
        Ok(response
            .kvs()
            .iter()
            // Persisted shard records are nested under `.../runs/{run}/shards/{hex}`.
            // Count only record keys and skip owner keys.
            .filter(|kv| {
                PersistedShardSubtreeKey::classify(kv.key())
                    == Some(PersistedShardSubtreeKey::Record)
            })
            .count())
    }

    /// Load current persisted shard counts for one tenant and globally (async).
    /// Lightweight capacity hint using count-only and keys-only RPCs (async).
    ///
    /// See [`EtcdCoordinator::count_available_lightweight`].
    pub(super) async fn count_available_lightweight(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let active_prefix = self.keyspace.shards_active_prefix(tenant, run).into_bytes();
        let active_response = self
            .etcd_get(
                active_prefix,
                Some(GetOptions::new().with_prefix().with_count_only()),
            )
            .await?;
        let total_active = u32::try_from(active_response.count()).unwrap_or_else(|_| {
            tracing::warn!(
                count = active_response.count(),
                "etcd active count exceeds u32 range; clamping to u32::MAX"
            );
            u32::MAX
        });
        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
        let keys_response = self
            .etcd_get(
                shards_prefix.as_bytes().to_vec(),
                Some(GetOptions::new().with_prefix().with_keys_only()),
            )
            .await?;
        let owned_count = u32::try_from(
            keys_response
                .kvs()
                .iter()
                .filter(|kv| {
                    ShardOwnerKey::parse_owned_shard(shards_prefix.as_bytes(), kv.key()).is_some()
                })
                .count(),
        )
        .unwrap_or(u32::MAX);
        Ok(CapacityHint {
            available_count: total_active.saturating_sub(owned_count),
            earliest_deadline: None,
        })
    }

    /// Load a shard, then validate a presented lease against it (async).
    ///
    /// See [`EtcdCoordinator::load_shard_and_validate_lease`].
    pub(super) async fn load_shard_and_validate_lease<E>(
        &self,
        now: LogicalTime,
        tenant: TenantId,
        lease: &Lease,
        map_not_found: impl FnOnce(ShardKey) -> E,
        map_load_error: impl FnOnce(EtcdCoordinatorError) -> E,
        map_stale_fence: impl FnOnce(
            gossip_coordination::FenceEpoch,
            gossip_coordination::FenceEpoch,
        ) -> E,
    ) -> Result<PersistedShard, E>
    where
        E: From<gossip_coordination::CoordError>,
    {
        let key = lease.shard_key();
        let persisted = match self.load_shard_record(tenant, key).await {
            Ok(Some(shard)) => shard,
            Ok(None) => return Err(map_not_found(key)),
            Err(err) => {
                return Err(map_load_error(err));
            }
        };
        validate_loaded_shard_lease(now, tenant, lease, &persisted, map_stale_fence)?;
        Ok(persisted)
    }

    /// Load a run record that is expected to exist (async).
    ///
    /// Returns `InfraError::corruption` if the key is missing and maps
    /// backend errors via [`map_etcd_err`](super::map_etcd_err).
    ///
    /// `context` identifies the calling operation for diagnostics.
    pub(super) async fn load_run_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        run: RunId,
    ) -> Result<PersistedRun, InfraError> {
        match self.load_run_record(tenant, run).await {
            Ok(Some(run_record)) => Ok(run_record),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("run {run:?} missing"),
            )),
            Err(err) => Err(super::map_etcd_err(context, err)),
        }
    }

    /// Load a shard record that is expected to exist (async).
    ///
    /// Returns `InfraError::corruption` if the key is missing and maps
    /// backend errors via [`map_etcd_err`](super::map_etcd_err).
    ///
    /// `context` identifies the calling operation for diagnostics.
    pub(super) async fn load_shard_checked(
        &self,
        context: &'static str,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<PersistedShard, InfraError> {
        match self.load_shard_record(tenant, key).await {
            Ok(Some(shard)) => Ok(shard),
            Ok(None) => Err(InfraError::corruption(
                context,
                format!("shard {key:?} missing"),
            )),
            Err(err) => Err(super::map_etcd_err(context, err)),
        }
    }

    /// Async CAS retry loop with exponential backoff and jitter.
    ///
    /// Semantically identical to [`EtcdCoordinator::cas_retry`] but
    /// accepts async closures (boxed futures). The boxing is necessary
    /// because the closures borrow `&mut Self` across `.await` points,
    /// which Rust's current async closures cannot express directly.
    pub(super) async fn cas_retry<T, E>(
        &mut self,
        mut attempt: impl FnMut(
            &mut Self,
            usize,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<CasOutcome<T>, E>> + '_>,
        >,
        on_exhaustion: impl FnOnce(
            &mut Self,
        ) -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<T, E>> + '_>,
        >,
    ) -> Result<T, E> {
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            match attempt(self, attempt_num).await? {
                CasOutcome::Committed(val) => return Ok(val),
                CasOutcome::RetryNeeded => {
                    if attempt_num + 1 < max_retries {
                        tokio::time::sleep(cas_retry_delay(attempt_num)).await;
                    }
                }
            }
        }
        on_exhaustion(self).await
    }

    /// Shared optimistic-CAS implementation for terminal run transitions (async).
    ///
    /// See [`EtcdCoordinator::transition_run_terminal`] for the full
    /// algorithm description.
    pub(super) async fn transition_run_terminal(
        &mut self,
        now: LogicalTime,
        tenant: TenantId,
        run: RunId,
        op_id: OpId,
        op_kind: RunOpKind,
    ) -> Result<IdempotentOutcome<()>, RunTransitionError> {
        let (target_status, payload_hash, require_active) = match op_kind {
            RunOpKind::CompleteRun => (RunStatus::Done, hash_complete_run_payload(), true),
            RunOpKind::FailRun => (RunStatus::Failed, hash_fail_run_payload(), true),
            RunOpKind::CancelRun => (RunStatus::Cancelled, hash_cancel_run_payload(), false),
            RunOpKind::RegisterShards => {
                unreachable!("transition_run_terminal does not handle RegisterShards")
            }
        };

        self.cas_retry(
            |this, _attempt| {
                Box::pin(async move {
                    let persisted = match this.load_run_record(tenant, run).await {
                        Ok(Some(r)) => r,
                        Ok(None) => return Err(RunTransitionError::RunNotFound),
                        Err(err) => {
                            return Err(RunTransitionError::BackendError(super::map_etcd_err(
                                "run_terminal.load_run",
                                err,
                            )));
                        }
                    };
                    let prior_status = persisted.record.status;
                    let mut record = persisted.record;

                    if record.tenant != tenant {
                        return Err(RunTransitionError::TenantMismatch { expected: tenant });
                    }
                    if let Some(entry) = record.check_op_idempotency(op_id, payload_hash)? {
                        if entry.kind() != op_kind {
                            return Err(RunTransitionError::BackendError(InfraError::corruption(
                                "run_terminal.idempotent_replay",
                                format!(
                                    "kind mismatch: expected {op_kind:?}, got {:?}",
                                    entry.kind()
                                ),
                            )));
                        }
                        return Ok(CasOutcome::Committed(IdempotentOutcome::Replayed(())));
                    }
                    if record.status.is_terminal() {
                        return Err(RunTransitionError::RunTerminal {
                            status: record.status,
                        });
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
                        target_status,
                        op_id,
                        op_kind,
                        payload_hash,
                    );
                    let run_blob = encode_run_record(&record);
                    let run_key = this.keyspace.run_record_key(tenant, run);
                    let active_key = this.keyspace.run_active_index_key(tenant, run);
                    let mut compares = vec![compare_run_revision(
                        run_key.clone(),
                        persisted.mod_revision,
                    )];
                    match prior_status {
                        RunStatus::Active => {
                            compares.push(compare_present(active_key.clone()));
                        }
                        RunStatus::Initializing => {
                            compares.push(compare_absent(active_key.clone()));
                        }
                        RunStatus::Done | RunStatus::Failed | RunStatus::Cancelled => {
                            unreachable!("terminal statuses return early")
                        }
                    }
                    let mut txn = TxnBuilder::new();
                    txn.compare_all(compares)
                        .put(run_key.into_bytes(), run_blob)
                        .delete(active_key.into_bytes());
                    txn.execute_async(this, IdempotentOutcome::Executed(()))
                        .await
                        .map_err(|err| {
                            RunTransitionError::BackendError(super::map_etcd_err(
                                "run_terminal.txn",
                                err,
                            ))
                        })
                })
            },
            |this| {
                Box::pin(async move {
                    let persisted = match this.load_run_record(tenant, run).await {
                        Ok(Some(r)) => r,
                        Ok(None) if !require_active => return Err(RunTransitionError::RunNotFound),
                        Ok(None) => {
                            return Err(RunTransitionError::BackendError(InfraError::corruption(
                                "run_terminal.exhaust.load_run",
                                format!("run {run:?} missing (expected Active)"),
                            )));
                        }
                        Err(err) => {
                            return Err(RunTransitionError::BackendError(super::map_etcd_err(
                                "run_terminal.exhaust.load_run",
                                err,
                            )));
                        }
                    };
                    if persisted.record.tenant != tenant {
                        return Err(RunTransitionError::TenantMismatch { expected: tenant });
                    }
                    if let Some(entry) =
                        persisted.record.check_op_idempotency(op_id, payload_hash)?
                    {
                        if entry.kind() != op_kind {
                            return Err(RunTransitionError::BackendError(InfraError::corruption(
                                "run_terminal.idempotent_replay",
                                format!(
                                    "kind mismatch: expected {op_kind:?}, got {:?}",
                                    entry.kind()
                                ),
                            )));
                        }
                        return Ok(IdempotentOutcome::Replayed(()));
                    }
                    if persisted.record.status.is_terminal() {
                        return Err(RunTransitionError::RunTerminal {
                            status: persisted.record.status,
                        });
                    }
                    if require_active && persisted.record.status != RunStatus::Active {
                        return Err(RunTransitionError::WrongStatus {
                            status: persisted.record.status,
                            target: target_status,
                        });
                    }
                    Err(RunTransitionError::BackendError(InfraError::transient(
                        "run_terminal",
                        "CAS retry budget exhausted",
                    )))
                })
            },
        )
        .await
    }
}

impl TxnBuilder {
    /// Execute the assembled transaction through the async coordinator and
    /// translate etcd success/failure into a CAS retry outcome.
    pub(super) async fn execute_async<T>(
        self,
        coordinator: &AsyncEtcdCoordinator,
        on_success: T,
    ) -> Result<CasOutcome<T>, EtcdCoordinatorError> {
        let response = coordinator.etcd_txn(self.build()).await?;
        if response.succeeded() {
            Ok(CasOutcome::Committed(on_success))
        } else {
            Ok(CasOutcome::RetryNeeded)
        }
    }
}

impl fmt::Debug for AsyncEtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncEtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted shard lifecycle + run lifecycle in etcd",
            )
            .finish()
    }
}
