//! Adapter that bridges coordination backends into the distributed scanner
//! runtime's [`DistributedCoordinator`] trait.
//!
//! The scanner runtime defines its own coordinator contract
//! ([`DistributedCoordinator`]) expressed in terms of [`ShardLease`] and
//! [`FilesystemAssignment`]. The coordination layer speaks a different
//! language: [`Lease`], [`ShardSpecRef`], [`ClaimError`], and
//! [`AcquireScratch`]. This module translates between the two without
//! either side depending on the other.
//!
//! ## Lifecycle
//!
//! ```text
//! acquire_shard ──► claim_next_available (coordination)
//!                  ├─ OK: map spec → FilesystemAssignment, wrap in ShardLease
//!                  ├─ NoneAvailable + active > 0: sleep, retry
//!                  └─ NoneAvailable + active == 0: return None (no active shards remain)
//!
//! complete_shard ──► complete (coordination) + deterministic OpId
//!
//! release_shard  ──► remove from local tracking map only
//! ```
//!
//! ## Concurrency
//!
//! All mutable coordination state (the backend handle, `AcquireScratch`, and
//! the active-lease map) lives behind a single `Mutex<AdapterState>`. The lock
//! is held for one or two coordination calls per acquisition attempt (claim
//! plus an optional progress check on the retry path) but is always released
//! before the inter-retry sleep. Contention is bounded by the number of
//! concurrent worker threads.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Result, anyhow};
use gossip_contracts::connector::Cursor;
use gossip_contracts::coordination::ShardSpecRef;
use gossip_contracts::identity::{
    CanonicalBytes, FenceEpoch, LogicalTime, OpId, PolicyHash, RunId, ShardKey, TenantId,
    TenantSecretKey, WorkerId, domain_hasher, finalize_64,
};
use gossip_contracts::persistence::WriteContext;
use gossip_coordination::{
    AcquireScratch, ClaimError, CoordinationBackend, Lease, OpKind, RunManagement, ShardClaiming,
};
use gossip_coordination_etcd::EtcdCoordinator;
use gossip_frontier::decode_connector_extra;
use gossip_scanner_runtime::coordination_sink::CoordinationEventRecorder;
use gossip_scanner_runtime::distributed::{DistributedCoordinator, ShardLease};
use gossip_scanner_runtime::{FsScanConfig, ScanReport};

use crate::FilesystemAssignment;

/// Fallback delay when no shard-lease deadline is available to guide retry
/// timing. Kept short to avoid stalling the worker loop when concurrent
/// workers are completing shards rapidly.
const CLAIM_RACE_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Production adapter: the generic adapter core specialized on
/// [`EtcdCoordinator`].
///
/// The generic core exists so tests can substitute
/// [`InMemoryCoordinator`](gossip_coordination::InMemoryCoordinator) without
/// touching production code paths.
pub type EtcdRuntimeAdapter = RuntimeAdapterCore<EtcdCoordinator>;

/// Generic adapter core parameterized over any coordination backend.
///
/// Immutable identity fields (`tenant`, `run`, `worker`, `policy_hash`,
/// `tenant_secret_key`, `scan_template`, `recorder`) are set at construction
/// and shared across all shard operations. Mutable state — the backend handle,
/// claim scratch buffer, and active-lease tracking map — lives behind a single
/// `Mutex` to keep the trait implementation `Send + Sync`.
pub struct RuntimeAdapterCore<C> {
    tenant: TenantId,
    run: RunId,
    worker: WorkerId,
    policy_hash: PolicyHash,
    tenant_secret_key: TenantSecretKey,
    /// Base scan configuration cloned and optionally overridden per-shard
    /// when the shard spec carries a filesystem path in `connector_extra`.
    scan_template: FsScanConfig,
    recorder: Arc<dyn CoordinationEventRecorder>,
    state: Mutex<AdapterState<C>>,
}

/// Mutable state guarded by a single lock.
///
/// The lock is held for at most two coordination calls (claim + progress
/// check in the retry branch), never across blocking sleeps, so contention
/// stays bounded.
struct AdapterState<C> {
    coordinator: C,
    /// Heap-allocated to avoid bloating the state struct (contains multiple
    /// fixed-capacity buffers). Reused across `claim_next_available` calls
    /// to avoid per-claim allocation.
    scratch: Box<AcquireScratch>,
    /// Maps shard-id strings to their coordination-layer [`Lease`] tokens
    /// and the shard spec's inclusive range-start key.
    /// Entries are inserted on acquire and removed on complete or release.
    /// The map lets `complete_shard` and `release_shard` look up the
    /// coordination-layer lease from the runtime-layer `ShardLease`.
    ///
    /// The range-start key is captured at acquire time and used as a
    /// fallback cursor position when completing shards that produced zero
    /// findings (no receipt-derived checkpoint cursor exists).
    active_leases: HashMap<String, TrackedLease>,
}

/// Coordination-layer lease paired with the shard spec's range-start key.
///
/// The range-start is captured at acquire time because the shard spec is
/// only available during the claim call. At completion time, if the
/// runtime provides no checkpoint cursor (zero-finding shards), the
/// adapter uses the range-start as the `last_key` in the cursor update.
/// This satisfies the coordination backend's key-presence requirement
/// under `CursorSemantics::Completed` without implying false progress.
struct TrackedLease {
    lease: Lease,
    /// Inclusive lower bound of the shard's key range, cloned from
    /// `ShardSpecRef::key_range_start()` at acquisition time.
    range_start: Vec<u8>,
}

impl<C> RuntimeAdapterCore<C> {
    /// Construct an adapter for the given coordination backend.
    ///
    /// The `scan_template` is cloned per-shard and may be overridden when the
    /// shard spec carries a filesystem path in its `connector_extra` metadata.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        coordinator: C,
        tenant: TenantId,
        run: RunId,
        worker: WorkerId,
        policy_hash: PolicyHash,
        tenant_secret_key: TenantSecretKey,
        scan_template: FsScanConfig,
        recorder: Arc<dyn CoordinationEventRecorder>,
    ) -> Self {
        Self {
            tenant,
            run,
            worker,
            policy_hash,
            tenant_secret_key,
            scan_template,
            recorder,
            state: Mutex::new(AdapterState {
                coordinator,
                scratch: Box::new(AcquireScratch::new()),
                active_leases: HashMap::new(),
            }),
        }
    }
}

/// [`DistributedCoordinator`] implementation for the generic adapter core.
///
/// `is_shard_done` always returns `false` and `mark_shard_done` is a no-op
/// because shard completion state is tracked by the coordination backend
/// itself (the `complete` call transitions the shard to Done status).
/// Re-scanning after a crash is harmless due to idempotency contracts on
/// `FindingsSink` and `DoneLedger`.
impl<C> DistributedCoordinator<FilesystemAssignment> for RuntimeAdapterCore<C>
where
    C: CoordinationBackend + RunManagement + ShardClaiming + Send,
{
    /// Blocking shard acquisition loop.
    ///
    /// Repeatedly calls `claim_next_available` until either:
    /// - A shard is claimed: translates the coordination-layer lease and spec
    ///   into a runtime-layer [`ShardLease<FilesystemAssignment>`], tracks the
    ///   coordination lease in `active_leases`, and returns `Some(lease)`.
    /// - No active shards remain (`progress.active() == 0`): returns `None`,
    ///   signaling the worker loop to shut down. Parked or terminal shards
    ///   are not retried.
    /// - A non-retryable error occurs: returns `Err`.
    ///
    /// Between retries the thread sleeps until the earliest known lease
    /// deadline, falling back to [`CLAIM_RACE_RETRY_DELAY`] when no deadline
    /// is available. The `Mutex` is released before sleeping so other
    /// threads can complete or release their shards concurrently.
    fn acquire_shard(&self) -> Result<Option<ShardLease<FilesystemAssignment>>> {
        loop {
            let now = wall_clock_now();
            let sleep_for = {
                let mut state = self.state.lock().expect("adapter state lock");
                let AdapterState {
                    coordinator,
                    scratch,
                    active_leases,
                } = &mut *state;
                match coordinator.claim_next_available(
                    now,
                    self.tenant,
                    self.run,
                    self.worker,
                    scratch,
                ) {
                    Ok(acquired) => {
                        let tracked_lease = acquired.lease;
                        let shard_id = tracked_lease.shard().to_string();
                        let spec = acquired.snapshot.spec();
                        let range_start = spec.key_range_start().to_vec();
                        let assignment =
                            assignment_from_spec(spec, self.policy_hash, &self.scan_template)?;
                        let write_context = WriteContext::new(
                            tracked_lease.tenant(),
                            self.policy_hash,
                            tracked_lease.run(),
                            tracked_lease.shard(),
                            tracked_lease.fence(),
                        );
                        let runtime_lease = ShardLease::new(
                            Arc::from(shard_id.clone()),
                            assignment,
                            write_context,
                            self.tenant_secret_key,
                        )
                        .map_err(anyhow::Error::from)?;
                        active_leases.insert(
                            shard_id,
                            TrackedLease {
                                lease: tracked_lease,
                                range_start,
                            },
                        );
                        return Ok(Some(runtime_lease));
                    }
                    Err(ClaimError::NoneAvailable { earliest_deadline }) => {
                        // No shards claimable right now, but the run may still
                        // have active work held by other workers. Check run
                        // progress to decide whether to retry or signal completion.
                        let progress = coordinator
                            .get_run_progress(now, self.tenant, self.run)
                            .map_err(anyhow::Error::from)?;
                        if progress.active() == 0 {
                            return Ok(None);
                        }
                        claim_retry_delay(now, earliest_deadline)
                    }
                    Err(err) => return Err(err.into()),
                }
            };
            std::thread::sleep(sleep_for);
        }
    }

    /// Drop a lease without marking it complete in the coordination backend.
    ///
    /// Only removes the lease from the local tracking map. The coordination
    /// layer will reclaim the shard when the lease's deadline expires, making
    /// it available for another worker.
    ///
    /// Returns an error if `lease` is not tracked by this adapter (double
    /// release or wrong adapter instance).
    fn release_shard(&self, lease: &ShardLease<FilesystemAssignment>) -> Result<()> {
        let mut state = self.state.lock().expect("adapter state lock");
        if state.active_leases.remove(lease.shard_id()).is_none() {
            return Err(anyhow!(
                "runtime lease '{}' is not active on this adapter",
                lease.shard_id()
            ));
        }
        Ok(())
    }

    /// Mark a shard as done in the coordination backend and remove it from
    /// the local tracking map.
    ///
    /// Bridges the runtime-layer cursor checkpoint into a coordination-layer
    /// `CursorUpdate` and issues a fenced `complete` call with a deterministic
    /// [`OpId`]. Deterministic op-ids make the completion idempotent: if the
    /// worker crashes and replays the same completion, the coordinator detects
    /// the duplicate via its per-shard op-log.
    ///
    /// When no checkpoint cursor is provided (zero-finding shards), the
    /// adapter uses the shard's range-start key captured at acquisition time.
    /// This satisfies the coordination backend's key-presence requirement
    /// under `CursorSemantics::Completed` without implying false progress
    /// beyond the initial position.
    fn complete_shard(
        &self,
        lease: &ShardLease<FilesystemAssignment>,
        checkpoint: Option<Cursor>,
        report: ScanReport,
    ) -> Result<()> {
        tracing::debug!(
            shard_id = %lease.shard_id(),
            items_scanned = report.items_scanned,
            bytes_scanned = report.bytes_scanned,
            findings_emitted = report.findings_emitted,
            "shard scan complete",
        );
        let now = wall_clock_now();
        let mut state = self.state.lock().expect("adapter state lock");

        // Copy the coordination lease and range-start out of the tracking map
        // before calling into the coordinator. This avoids holding an immutable
        // borrow on `active_leases` across the mutable `coordinator.complete`
        // call.
        let tracked = state.active_leases.get(lease.shard_id()).ok_or_else(|| {
            anyhow!(
                "runtime lease '{}' is not active on this adapter",
                lease.shard_id()
            )
        })?;
        let coordination_lease = tracked.lease;
        let fallback_key = tracked.range_start.clone();

        let final_cursor = match checkpoint.as_ref() {
            Some(cursor) => cursor.as_update(),
            None => {
                // Zero-finding shards have no receipt-derived checkpoint.
                // Use the shard's range-start key as a "no progress beyond
                // the initial position" marker so the coordination backend
                // accepts the completion under Completed semantics.
                gossip_contracts::coordination::CursorUpdate::new(&fallback_key)
            }
        };
        let op_id = deterministic_op_id(
            coordination_lease.shard_key(),
            coordination_lease.fence(),
            OpKind::Complete,
        );
        let outcome = state
            .coordinator
            .complete(now, self.tenant, &coordination_lease, &final_cursor, op_id)
            .map_err(anyhow::Error::from)?;
        if !outcome.is_executed() {
            tracing::info!(
                shard_id = %lease.shard_id(),
                "completion was an idempotent replay",
            );
        }
        state.active_leases.remove(lease.shard_id());
        Ok(())
    }

    fn is_shard_done(&self, _lease: &ShardLease<FilesystemAssignment>) -> Result<bool> {
        Ok(false)
    }

    fn mark_shard_done(&self, _lease: &ShardLease<FilesystemAssignment>) -> Result<()> {
        Ok(())
    }

    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder> {
        Arc::clone(&self.recorder)
    }
}

/// Build a [`FilesystemAssignment`] from a coordination-layer shard spec.
///
/// Clones `scan_template` and optionally overrides its path if the
/// `connector_extra` payload decoded from the shard spec's metadata contains
/// a non-empty UTF-8 string. This payload is the connector's mechanism for
/// routing individual shards to distinct filesystem subtrees; an empty value
/// means "use the template path as-is".
fn assignment_from_spec(
    spec: ShardSpecRef<'_>,
    policy_hash: PolicyHash,
    scan_template: &FsScanConfig,
) -> Result<FilesystemAssignment> {
    let mut scan_config = scan_template.clone();

    // `connector_extra` carries connector-owned shard-routing data. The
    // filesystem bridge treats a non-empty payload as a UTF-8 path override.
    let connector_extra = decode_connector_extra(spec)
        .map_err(|err| anyhow!("failed to decode shard metadata envelope: {err}"))?;
    if !connector_extra.is_empty() {
        let path = std::str::from_utf8(connector_extra)
            .map_err(|err| anyhow!("filesystem shard metadata path is not valid UTF-8: {err}"))?;
        scan_config.path = PathBuf::from(path);
    }

    Ok(FilesystemAssignment::new(policy_hash, scan_config))
}

/// Convert the current wall-clock time to [`LogicalTime`] (milliseconds since
/// Unix epoch).
///
/// Clamps to a minimum of 1 ms because [`LogicalTime::ZERO`] is reserved as a
/// sentinel in the coordination layer (e.g., "no deadline" or "uninitialized").
/// Falls back to 1 ms if `SystemTime::now()` precedes `UNIX_EPOCH` or the
/// millisecond count exceeds `u64::MAX`.
fn wall_clock_now() -> LogicalTime {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|duration| u64::try_from(duration.as_millis()).ok())
        .unwrap_or(1);
    LogicalTime::from_raw(millis.max(1))
}

/// Compute how long to sleep before retrying a shard claim.
///
/// If the coordination layer reports an `earliest_deadline` (the soonest
/// time a currently-held lease expires), sleep until that instant. Otherwise
/// fall back to [`CLAIM_RACE_RETRY_DELAY`]. The minimum sleep is 1 ms to
/// avoid busy-spinning on stale deadlines.
fn claim_retry_delay(now: LogicalTime, earliest_deadline: Option<LogicalTime>) -> Duration {
    earliest_deadline
        .map(|deadline| deadline.as_raw().saturating_sub(now.as_raw()).max(1))
        .map(Duration::from_millis)
        .unwrap_or(CLAIM_RACE_RETRY_DELAY)
}

/// Derive a deterministic [`OpId`] from shard identity, fence epoch, and
/// operation kind.
///
/// The coordination layer's per-shard op-log uses `OpId` for idempotency
/// detection: if a worker crashes and replays the same `complete` or
/// `checkpoint` call, the matching `OpId` lets the coordinator skip the
/// duplicate. Determinism is achieved by hashing fixed-layout canonical
/// representations of all inputs under a domain-separated hasher.
fn deterministic_op_id(key: ShardKey, fence: FenceEpoch, op_kind: OpKind) -> OpId {
    let mut hasher = domain_hasher("gossip.coordination.bridge.runtime_adapter.op_id");
    key.run().write_canonical(&mut hasher);
    key.shard().write_canonical(&mut hasher);
    fence.write_canonical(&mut hasher);
    op_kind.as_u8().write_canonical(&mut hasher);
    OpId::from_raw(finalize_64(&hasher))
}

#[cfg(test)]
mod tests {
    use super::*;

    use gossip_contracts::connector::ItemKey;
    use gossip_contracts::coordination::{CursorSemantics, CursorUpdate, InitialShardInput};
    use gossip_contracts::identity::{FenceEpoch, ShardId};
    use gossip_coordination::{
        InMemoryCoordinator, RunConfig, RunManagement, ShardFilter, ShardStatus,
    };
    use gossip_frontier::{ShardSpecScratch, range_shard_ref};
    use gossip_scanner_runtime::distributed::ShardLeaseAssignment;
    use tempfile::tempdir;

    #[derive(Default)]
    struct NoopRecorder;

    impl CoordinationEventRecorder for NoopRecorder {
        fn record_core_event(
            &self,
            _shard_id: &str,
            _event: gossip_scanner_runtime::OwnedCoreEvent,
        ) -> Result<()> {
            Ok(())
        }

        fn record_git_event(
            &self,
            _shard_id: &str,
            _event: gossip_scanner_runtime::coordination_sink::StoredGitEvent,
        ) -> Result<()> {
            Ok(())
        }

        fn record_commit_progress(
            &self,
            _shard_id: &str,
            _event: gossip_scanner_runtime::coordination_sink::CommitProgressRecord,
        ) -> Result<()> {
            Ok(())
        }
    }

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn run() -> RunId {
        RunId::from_raw(7)
    }

    fn worker() -> WorkerId {
        WorkerId::from_raw(13)
    }

    fn policy_hash() -> PolicyHash {
        PolicyHash::from_bytes([0x22; 32])
    }

    fn tenant_secret_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0x33; 32])
    }

    fn recorder() -> Arc<dyn CoordinationEventRecorder> {
        Arc::new(NoopRecorder)
    }

    fn base_scan_config() -> FsScanConfig {
        FsScanConfig::new("/fallback")
    }

    fn make_adapter_with_registered_shard(
        path_override: &[u8],
    ) -> RuntimeAdapterCore<InMemoryCoordinator> {
        let mut coordinator = InMemoryCoordinator::new(30_000);
        let now = wall_clock_now();
        let config =
            RunConfig::try_new(CursorSemantics::Completed, 30_000, None).expect("run config");
        coordinator
            .create_run(now, tenant(), run(), config)
            .expect("create run");

        let mut scratch = ShardSpecScratch::new();
        let spec =
            range_shard_ref(b"a", b"z", path_override, &mut scratch).expect("range shard spec");
        let shards = [InitialShardInput::new(
            ShardId::from_raw(1),
            spec,
            CursorUpdate::initial(),
        )];
        let _ = coordinator
            .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
            .expect("register shard");

        RuntimeAdapterCore::new(
            coordinator,
            tenant(),
            run(),
            worker(),
            policy_hash(),
            tenant_secret_key(),
            base_scan_config(),
            recorder(),
        )
    }

    #[test]
    fn filesystem_assignment_exposes_policy_hash_and_scan_config() {
        let config = FsScanConfig::new("/tmp/shard");
        let assignment = FilesystemAssignment::new(policy_hash(), config.clone());

        assert_eq!(assignment.policy_hash(), policy_hash());
        assert_eq!(
            assignment
                .filesystem_scan_config()
                .expect("filesystem config should exist"),
            config
        );
        assert_eq!(assignment.scan_config(), &config);
    }

    #[test]
    fn deterministic_op_id_is_stable_and_input_sensitive() {
        let key = ShardKey::new(run(), ShardId::from_raw(9));
        let fence = FenceEpoch::from_raw(4);

        let baseline = deterministic_op_id(key, fence, OpKind::Complete);

        // Stability: identical inputs produce identical output.
        assert_eq!(baseline, deterministic_op_id(key, fence, OpKind::Complete));

        // Each input dimension changes the output.
        let different_op = deterministic_op_id(key, fence, OpKind::Checkpoint);
        assert_ne!(baseline, different_op, "op-kind must influence the hash");

        let different_shard = ShardKey::new(run(), ShardId::from_raw(10));
        assert_ne!(
            baseline,
            deterministic_op_id(different_shard, fence, OpKind::Complete),
            "shard identity must influence the hash"
        );

        let different_fence = FenceEpoch::from_raw(5);
        assert_ne!(
            baseline,
            deterministic_op_id(key, different_fence, OpKind::Complete),
            "fence epoch must influence the hash"
        );
    }

    #[test]
    fn acquire_shard_maps_claim_errors_into_anyhow_messages() {
        let adapter = RuntimeAdapterCore::new(
            InMemoryCoordinator::new(30_000),
            tenant(),
            run(),
            worker(),
            policy_hash(),
            tenant_secret_key(),
            base_scan_config(),
            recorder(),
        );

        let error = adapter
            .acquire_shard()
            .expect_err("missing run should error");

        assert!(
            error.to_string().contains("run not found"),
            "unexpected acquire error: {error}"
        );
    }

    #[test]
    fn adapter_acquire_and_complete_lifecycle_uses_metadata_path_override() {
        let dir = tempdir().expect("tempdir");
        let path_text = dir.path().to_str().expect("utf-8 tempdir path");
        let adapter = make_adapter_with_registered_shard(path_text.as_bytes());

        let lease = adapter
            .acquire_shard()
            .expect("acquire should succeed")
            .expect("one shard should be available");

        assert_eq!(lease.shard_id(), "ShardId(1)");
        assert_eq!(lease.write_context().tenant_id(), tenant());
        assert_eq!(lease.write_context().run_id(), run());
        assert_eq!(lease.write_context().shard_id(), ShardId::from_raw(1));
        assert_eq!(lease.write_context().policy_hash(), policy_hash());
        // First claim bumps the fence from INITIAL (1) to 2.
        assert_eq!(
            lease.write_context().fence_epoch(),
            FenceEpoch::from_raw(2),
            "first acquire must propagate the post-claim fence epoch"
        );
        assert_eq!(
            lease
                .assignment()
                .filesystem_scan_config()
                .expect("filesystem config")
                .path,
            PathBuf::from(path_text)
        );

        let checkpoint_bytes = b"file:///tmp/checkpoint";
        let checkpoint = Cursor::with_last_key(
            ItemKey::try_from_slice(checkpoint_bytes.as_slice()).expect("item key"),
        );
        adapter
            .complete_shard(&lease, Some(checkpoint), ScanReport::default())
            .expect("complete should succeed");

        {
            let state = adapter.state.lock().expect("adapter state lock");
            let progress = state
                .coordinator
                .get_run_progress(wall_clock_now(), tenant(), run())
                .expect("run progress");
            assert_eq!(progress.active(), 0);
            assert_eq!(progress.done(), 1);
            assert!(
                state.active_leases.is_empty(),
                "completed lease should be removed from the tracking map"
            );

            // Verify the checkpoint cursor was forwarded to the coordination backend.
            let mut summaries = Vec::new();
            state
                .coordinator
                .list_shards_into(
                    wall_clock_now(),
                    tenant(),
                    run(),
                    ShardFilter::all(),
                    &mut summaries,
                )
                .expect("list shards");
            assert_eq!(summaries.len(), 1);
            assert_eq!(summaries[0].status(), ShardStatus::Done);
            assert_eq!(
                summaries[0].last_key(),
                Some(checkpoint_bytes.as_slice()),
                "cursor must be forwarded to the coordination backend on complete"
            );
        }

        assert!(
            adapter
                .acquire_shard()
                .expect("second acquire should succeed")
                .is_none(),
            "settled run should report no more leases"
        );
    }

    #[test]
    fn adapter_falls_back_to_template_path_when_connector_extra_is_empty() {
        let adapter = make_adapter_with_registered_shard(&[]);

        let lease = adapter
            .acquire_shard()
            .expect("acquire should succeed")
            .expect("one shard should be available");

        assert_eq!(
            lease
                .assignment()
                .filesystem_scan_config()
                .expect("filesystem config")
                .path,
            PathBuf::from("/fallback")
        );
    }

    #[test]
    fn release_shard_removes_tracking_entry_and_rejects_double_release() {
        let adapter = make_adapter_with_registered_shard(&[]);

        let lease = adapter
            .acquire_shard()
            .expect("acquire should succeed")
            .expect("one shard should be available");

        // First release succeeds and removes the tracking entry.
        adapter
            .release_shard(&lease)
            .expect("first release should succeed");
        {
            let state = adapter.state.lock().expect("adapter state lock");
            assert!(
                state.active_leases.is_empty(),
                "released lease must be removed from the tracking map"
            );
        }

        // Second release on the same lease is rejected.
        let err = adapter
            .release_shard(&lease)
            .expect_err("double release should error");
        assert!(
            err.to_string().contains("not active on this adapter"),
            "unexpected release error: {err}"
        );
    }

    #[test]
    fn complete_shard_without_checkpoint_uses_range_start_under_completed_semantics() {
        let adapter = make_adapter_with_registered_shard(&[]);

        let lease = adapter
            .acquire_shard()
            .expect("acquire should succeed")
            .expect("one shard should be available");

        // Zero-finding shards complete with `checkpoint = None`. The adapter
        // falls back to the shard's range-start key captured at acquire time,
        // which satisfies the coordination backend's key-presence requirement
        // under CursorSemantics::Completed.
        adapter
            .complete_shard(&lease, None, ScanReport::default())
            .expect("zero-finding shard completion must succeed under Completed semantics");

        let state = adapter.state.lock().expect("adapter state lock");
        let progress = state
            .coordinator
            .get_run_progress(wall_clock_now(), tenant(), run())
            .expect("run progress");
        assert_eq!(progress.active(), 0);
        assert_eq!(progress.done(), 1);
        assert!(
            state.active_leases.is_empty(),
            "completed lease should be removed from the tracking map"
        );
    }

    #[test]
    fn complete_shard_on_unknown_lease_errors() {
        let adapter = make_adapter_with_registered_shard(&[]);

        let lease = adapter
            .acquire_shard()
            .expect("acquire should succeed")
            .expect("one shard should be available");

        // Release the lease so it is no longer tracked.
        adapter
            .release_shard(&lease)
            .expect("release should succeed");

        // Completing a lease that is not in the tracking map must error.
        let err = adapter
            .complete_shard(&lease, None, ScanReport::default())
            .expect_err("complete on unknown lease should error");
        assert!(
            err.to_string().contains("not active on this adapter"),
            "unexpected complete error: {err}"
        );
    }

    #[test]
    fn claim_retry_delay_with_future_deadline() {
        let now = LogicalTime::from_raw(1000);
        let deadline = Some(LogicalTime::from_raw(1050));
        assert_eq!(claim_retry_delay(now, deadline), Duration::from_millis(50));
    }

    #[test]
    fn claim_retry_delay_clamps_stale_deadline_to_one_ms() {
        let now = LogicalTime::from_raw(2000);
        // Deadline already passed — saturating_sub yields 0, clamped to 1 ms.
        let stale = Some(LogicalTime::from_raw(1000));
        assert_eq!(claim_retry_delay(now, stale), Duration::from_millis(1));
    }

    #[test]
    fn claim_retry_delay_falls_back_without_deadline() {
        let now = LogicalTime::from_raw(1000);
        assert_eq!(claim_retry_delay(now, None), CLAIM_RACE_RETRY_DELAY);
    }

    #[test]
    fn acquire_shard_rejects_non_utf8_connector_extra() {
        let adapter = make_adapter_with_registered_shard(&[0xFF, 0xFE]);
        let err = adapter
            .acquire_shard()
            .expect_err("non-UTF-8 connector_extra should fail");
        assert!(
            err.to_string().contains("not valid UTF-8"),
            "unexpected error: {err}"
        );
    }
}
