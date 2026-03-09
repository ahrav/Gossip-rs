use std::collections::HashMap;
use std::fmt;

use etcd_client::{DeleteOptions, GetOptions, Txn, TxnOp};
use gossip_coordination::{
    CapacityHint, IdempotentOutcome, InfraError, LogicalTime, OpId, RunId, RunOpKind, RunStatus,
    RunTransitionError, ShardId, ShardKey, TenantId, hash_cancel_run_payload,
    hash_complete_run_payload, hash_fail_run_payload,
};

use crate::codec::{EtcdCodecError, decode_run_record, decode_shard_record, encode_run_record};
use crate::config::{DEFAULT_CONNECT_TIMEOUT, EtcdCoordinatorConfig};
use crate::error::{EtcdCoordinatorError, EtcdOperation};
use crate::keyspace::EtcdKeyspace;
use crate::keyspace::{
    PersistedShardSubtreeKey, RunActiveIndexKey, RunRecordKey, ShardActiveIndexKey, ShardOwnerKey,
    ShardRecordKey,
};

use super::{
    CasOutcome, PersistedOwner, PersistedRun, PersistedShard, ShardCountSnapshot,
    apply_terminal_run_transition, cas_retry_delay, compare_absent, compare_present,
    compare_run_revision, decode_owner_kv, fatal_storage_error, make_decode_slab,
    validate_owner_consistency,
};

#[cfg(any(test, feature = "test-support"))]
use super::test_support::EtcdTestFaultState;

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

    /// Panics with a message identifying the unimplemented operation.
    ///
    /// Used as a placeholder for coordination operations whose etcd
    /// persistence logic has not been implemented. Callers should not
    /// catch this panic — it indicates a code path that must not be
    /// reached until the operation is persisted.
    pub(super) fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "EtcdCoordinator::{operation} is not yet persisted to etcd; \
             this operation must be implemented before it is callable"
        );
    }

    /// Execute a CAS retry loop with exponential backoff and jitter.
    ///
    /// Calls `attempt` up to `optimistic_txn_retries` times. On
    /// [`CasOutcome::RetryNeeded`], sleeps with jittered backoff and
    /// retries. On [`CasOutcome::Committed`], returns immediately.
    /// If retries exhaust, calls `on_exhaustion` immediately (no
    /// additional backoff) to re-read state and produce a domain error
    /// or panic. Callers that perform network I/O in `on_exhaustion`
    /// should be aware this executes at peak-contention time.
    pub(super) fn cas_retry<T, E>(
        &mut self,
        mut attempt: impl FnMut(&mut Self, usize) -> Result<CasOutcome<T>, E>,
        on_exhaustion: impl FnOnce(&mut Self) -> Result<T, E>,
    ) -> Result<T, E> {
        let max_retries = self.config.optimistic_txn_retries();
        for attempt_num in 0..max_retries {
            match attempt(self, attempt_num)? {
                CasOutcome::Committed(val) => return Ok(val),
                CasOutcome::RetryNeeded => {
                    if attempt_num + 1 < max_retries {
                        std::thread::sleep(cas_retry_delay(attempt_num));
                    }
                }
            }
        }
        on_exhaustion(self)
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

    /// Load a single run record by exact key. Returns `None` if the key
    /// does not exist in etcd. Cross-validates that the decoded record's
    /// identity fields match the key-path parameters to detect data
    /// corruption at the data-access layer.
    pub(super) fn load_run_record(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Option<PersistedRun>, EtcdCoordinatorError> {
        let key = self.keyspace.run_record_key(tenant, run).into_bytes();
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

    /// Load a single shard record and its owner binding by exact key.
    ///
    /// Uses a single prefix-range GET on the shard record key. Because
    /// shard IDs are fixed-width 16-char hex and the only child key is
    /// `/owner`, the prefix scan returns exactly the record KV and
    /// (optionally) the owner KV — no false matches against other shard
    /// IDs. Cross-validates the owner binding against the shard record's
    /// lease fields and the decoded record's identity fields against the
    /// key-path parameters to detect data corruption. Returns `None` if
    /// the shard record key does not exist.
    ///
    /// # Errors
    ///
    /// Returns [`EtcdCoordinatorError::Codec`] with an invariant violation
    /// if the owner key exists but disagrees with the shard record's
    /// lease holder or fence epoch, or if the decoded record's identity
    /// fields disagree with the key-path parameters.
    pub(super) fn load_shard_record(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> Result<Option<PersistedShard>, EtcdCoordinatorError> {
        let shard_record_key = self
            .keyspace
            .shard_record_key(tenant, key.run(), key.shard());
        let owner_key = shard_record_key.owner_key();

        // Single prefix-range scan fetches both the shard record and its
        // `/owner` child key in one etcd RPC.
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

    /// Prefix-scan all shard records (and their `/owner` keys) under a run.
    ///
    /// Issues a single etcd prefix-range `get` on the `shards/` subtree,
    /// then partitions the response into record KVs and owner KVs.
    /// Owner bindings are matched to their parent shard record by
    /// key suffix convention (`{shard_key}/owner`).
    ///
    /// Cross-validates every owner binding against its shard record and
    /// rejects orphaned owner keys (owner with no matching shard record).
    pub(super) fn scan_run_shards(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<Vec<PersistedShard>, EtcdCoordinatorError> {
        let prefix = self
            .keyspace
            .shard_records_scan_prefix(tenant, run)
            .into_bytes();
        let response = self.etcd_get(prefix, Some(GetOptions::new().with_prefix()))?;

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

    /// Prefix-scan direct run records under a tenant, skipping shard and
    /// active-index descendants.
    ///
    /// Uses [`RunRecordKey::parse_direct_run_id`] to filter the prefix-range
    /// response down to immediate `runs/{hex}` children, ignoring deeper
    /// keys (`runs/{hex}/shards/…`, `runs_active/…`). Cross-validates that
    /// each decoded record's tenant and run ID match the key path. Results
    /// are sorted by raw run ID.
    pub(super) fn scan_tenant_runs(
        &self,
        tenant: TenantId,
    ) -> Result<Vec<PersistedRun>, EtcdCoordinatorError> {
        let prefix = self.keyspace.run_records_scan_prefix(tenant);
        let response = self.etcd_get(
            prefix.as_bytes().to_vec(),
            Some(GetOptions::new().with_prefix()),
        )?;

        let mut out = Vec::new();
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

    /// Lightweight capacity hint using count-only and keys-only RPCs.
    ///
    /// Returns an approximate count of active shards without an owner key,
    /// suitable for `CapacityHint`. Uses two etcd RPCs with minimal data
    /// transfer (no shard record values are decoded):
    ///
    /// 1. `count_only` on the `shards_active/` prefix → total active shards.
    /// 2. `keys_only` on the `shards/` prefix, counting `/owner` suffixes →
    ///    owned shard count.
    ///
    /// The result is approximate because the two RPCs are not transactional:
    /// a concurrent acquire between them may cause a brief undercount or
    /// overcount. This is acceptable for a capacity hint used in claim
    /// scheduling.
    ///
    /// `earliest_deadline` is always `None` because computing it would
    /// require decoding shard record values, defeating the purpose.
    pub(super) fn count_available_lightweight(
        &self,
        tenant: TenantId,
        run: RunId,
    ) -> Result<CapacityHint, EtcdCoordinatorError> {
        let active_prefix = self.keyspace.shards_active_prefix(tenant, run).into_bytes();
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

        let shards_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
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

    /// Count persisted shard records under `prefix` using a keys-only scan.
    ///
    /// The subtree contains run records, owner keys, and active indexes in
    /// addition to shard records, so the caller filters keys structurally.
    ///
    /// This is intentionally an O(N) preflight read. The backend does not yet
    /// maintain dedicated shard-count keys, and these paths are setup/lifecycle
    /// operations where correctness is more important than constant-time reads.
    pub(super) fn count_persisted_shards_under_prefix(
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
            // `parse_direct_shard_id` accepts only direct `{hex}` children.
            // This excludes `/owner` keys and deeper descendants.
            .filter(|kv| ShardActiveIndexKey::parse_direct_shard_id(&prefix, kv.key()).is_some())
            .count())
    }

    /// Load current persisted shard counts for one tenant and for the whole
    /// backend.
    ///
    /// Unlike the in-memory backend's remove-mutate-restore flow, etcd reads
    /// the parent shard directly from storage, so the current counts already
    /// include the parent being split.
    pub(super) fn current_shard_counts(
        &self,
        tenant: TenantId,
    ) -> Result<ShardCountSnapshot, EtcdCoordinatorError> {
        Ok(ShardCountSnapshot {
            tenant: self
                .count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))?,
            total: self.count_persisted_shards_under_prefix(self.keyspace.tenants_prefix())?,
        })
    }

    /// List runs visible to workers by scanning only the active-run index.
    ///
    /// Initializing runs remain invisible until `register_shards` publishes
    /// the corresponding active-run marker.
    pub fn list_active_runs_into(
        &self,
        tenant: TenantId,
        out: &mut Vec<RunId>,
    ) -> Result<(), EtcdCoordinatorError> {
        let mut prefix = self.keyspace.runs_active_prefix(tenant);
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

    /// Garbage-collect stale runs that never left `Initializing`.
    ///
    /// Scans all runs under `tenant`, retains those that are still
    /// `Initializing` with `created_at < cutoff`, and attempts to delete
    /// each one. Each candidate is deleted behind a single CAS transaction
    /// guarded by the run revision and the absence of the active-run marker.
    /// A concurrently activated run simply fails the compare and is skipped.
    ///
    /// Deletion is total: the run record, any shard records, and any
    /// active-shard index entries are removed in a single transaction.
    /// Successfully deleted run IDs are appended to `out`.
    ///
    /// On error, `out` may contain a partial list of the runs that were
    /// successfully deleted before the failure. Callers must not rely on
    /// `out` contents when the return value is `Err`.
    pub fn gc_stale_initializing_runs_into(
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
            let run_key = self.keyspace.run_record_key(tenant, run);
            let active_key = self.keyspace.run_active_index_key(tenant, run);
            let shard_prefix = self.keyspace.shard_records_scan_prefix(tenant, run);
            let mut active_shard_prefix = self.keyspace.shards_active_prefix(tenant, run);
            active_shard_prefix.push('/');

            let txn = Txn::new()
                .when(vec![
                    compare_run_revision(run_key.clone(), persisted.mod_revision),
                    compare_absent(active_key.clone()),
                ])
                .and_then(vec![
                    TxnOp::delete(run_key.into_bytes(), None),
                    TxnOp::delete(active_key.into_bytes(), None),
                    TxnOp::delete(
                        shard_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                    TxnOp::delete(
                        active_shard_prefix.into_bytes(),
                        Some(DeleteOptions::new().with_prefix()),
                    ),
                ]);
            let response = self.etcd_txn(txn)?;
            if response.succeeded() {
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

    /// Shared optimistic-CAS implementation for terminal run transitions
    /// (`complete_run`, `fail_run`, `cancel_run`).
    ///
    /// Each iteration:
    /// 1. Loads the run record and checks idempotent replay.
    /// 2. Validates status preconditions (e.g., `complete_run` requires
    ///    `Active`; `cancel_run` accepts both `Active` and `Initializing`).
    /// 3. Applies the terminal transition locally.
    /// 4. Commits the updated run record and deletes the active-run index
    ///    entry in a single CAS transaction.
    ///
    /// The active-run index guard adapts to the prior status: `Active` runs
    /// require the index entry to exist (`compare_present`), while
    /// `Initializing` runs require it to be absent (`compare_absent`). This
    /// prevents cancelling a run that was concurrently activated between the
    /// read and the write.
    ///
    /// On CAS exhaustion, re-reads the run to return the appropriate domain
    /// error or confirm idempotent replay.
    pub(super) fn transition_run_terminal(
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

                let txn = Txn::new().when(compares).and_then(vec![
                    TxnOp::put(run_key.into_bytes(), run_blob, None),
                    TxnOp::delete(active_key.into_bytes(), None),
                ]);
                let response = match this.etcd_txn(txn) {
                    Ok(r) => r,
                    Err(err) => {
                        return Err(RunTransitionError::BackendError(super::map_etcd_err(
                            "run_terminal.txn",
                            err,
                        )));
                    }
                };
                if response.succeeded() {
                    return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(())));
                }
                Ok(CasOutcome::RetryNeeded)
            },
            |this| {
                let persisted = this.load_run_or_panic(tenant, run);
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

    /// Attempt to revoke an etcd lease, logging on failure.
    ///
    /// Used for cleanup after a CAS failure when the lease is no longer
    /// needed. If the revocation fails (e.g., network error), the lease
    /// will eventually expire via etcd's TTL mechanism. Failures are
    /// logged at `warn` level so operators can detect accumulation of
    /// orphaned leases during etcd instability.
    pub(super) fn best_effort_revoke_lease(&self, lease_id: i64) {
        if lease_id <= 0 {
            return;
        }
        if let Err(err) = self.etcd_lease_revoke(lease_id) {
            tracing::warn!(
                lease_id,
                %err,
                ttl_secs = self.config.owner_lease_ttl_secs(),
                "failed to revoke etcd lease; will expire via TTL",
            );
        }
    }

    /// Load a run record, panicking if the key is missing or unreadable.
    ///
    /// Used in paths where the run is expected to exist (e.g., after
    /// a successful `create_run`).
    pub(super) fn load_run_or_panic(&self, tenant: TenantId, run: RunId) -> PersistedRun {
        match self.load_run_record(tenant, run) {
            Ok(Some(run_record)) => run_record,
            Ok(None) => fatal_storage_error("load run", format!("run {run:?} missing")),
            Err(err) => fatal_storage_error("load run", err),
        }
    }

    /// Load a shard record, panicking if the key is missing or unreadable.
    pub(super) fn load_shard_or_panic(&self, tenant: TenantId, key: ShardKey) -> PersistedShard {
        match self.load_shard_record(tenant, key) {
            Ok(Some(shard)) => shard,
            Ok(None) => fatal_storage_error("load shard", format!("shard {key:?} missing")),
            Err(err) => fatal_storage_error("load shard", err),
        }
    }
}

impl fmt::Debug for EtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted acquire/renew/checkpoint/split/unpark + run lifecycle in etcd",
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

    // -- Higher-level data access helpers (async) --

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
            // `parse_direct_shard_id` accepts only direct `{hex}` children.
            // This excludes `/owner` keys and deeper descendants.
            .filter(|kv| ShardActiveIndexKey::parse_direct_shard_id(&prefix, kv.key()).is_some())
            .count())
    }

    pub(super) async fn current_shard_counts(
        &self,
        tenant: TenantId,
    ) -> Result<ShardCountSnapshot, EtcdCoordinatorError> {
        Ok(ShardCountSnapshot {
            tenant: self
                .count_persisted_shards_under_prefix(self.keyspace.tenant_prefix(tenant))
                .await?,
            total: self
                .count_persisted_shards_under_prefix(self.keyspace.tenants_prefix())
                .await?,
        })
    }

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

    pub(super) async fn load_run_or_panic(&self, tenant: TenantId, run: RunId) -> PersistedRun {
        match self.load_run_record(tenant, run).await {
            Ok(Some(run_record)) => run_record,
            Ok(None) => fatal_storage_error("load run", format!("run {run:?} missing")),
            Err(err) => fatal_storage_error("load run", err),
        }
    }

    pub(super) async fn load_shard_or_panic(
        &self,
        tenant: TenantId,
        key: ShardKey,
    ) -> PersistedShard {
        match self.load_shard_record(tenant, key).await {
            Ok(Some(shard)) => shard,
            Ok(None) => fatal_storage_error("load shard", format!("shard {key:?} missing")),
            Err(err) => fatal_storage_error("load shard", err),
        }
    }

    pub(super) fn fail_unimplemented<T>(&self, operation: &'static str) -> T {
        panic!(
            "AsyncEtcdCoordinator::{operation} is not yet persisted to etcd; \
             this operation must be implemented before it is callable"
        );
    }

    /// Async CAS retry loop. The attempt and exhaustion closures return
    /// boxed futures because async closures with mutable borrows require
    /// explicit lifetime management.
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

    /// Shared optimistic-CAS implementation for terminal run transitions.
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
                    let txn = Txn::new().when(compares).and_then(vec![
                        TxnOp::put(run_key.into_bytes(), run_blob, None),
                        TxnOp::delete(active_key.into_bytes(), None),
                    ]);
                    let response = match this.etcd_txn(txn).await {
                        Ok(r) => r,
                        Err(err) => {
                            return Err(RunTransitionError::BackendError(super::map_etcd_err(
                                "run_terminal.txn",
                                err,
                            )));
                        }
                    };
                    if response.succeeded() {
                        return Ok(CasOutcome::Committed(IdempotentOutcome::Executed(())));
                    }
                    Ok(CasOutcome::RetryNeeded)
                })
            },
            |this| {
                Box::pin(async move {
                    let persisted = this.load_run_or_panic(tenant, run).await;
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

impl fmt::Debug for AsyncEtcdCoordinator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AsyncEtcdCoordinator")
            .field("endpoint_count", &self.config.endpoints().len())
            .field("namespace_prefix", &self.keyspace.prefix())
            .field(
                "coordination_storage_mode",
                &"persisted acquire/renew/checkpoint/split/unpark + run lifecycle in etcd",
            )
            .finish()
    }
}
