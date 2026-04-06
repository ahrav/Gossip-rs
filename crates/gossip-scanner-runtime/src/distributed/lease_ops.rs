//! Lease lifecycle operations: claiming, hydration, deadline watchdog, and shard advancement.
//!
//! Covers the full lifecycle of a distributed lease from initial claim through
//! to terminal completion or intermediate checkpoint, including the deadline
//! watchdog thread and the uncertainty signal that protects against stale
//! leases.

use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context as _, Error as AnyError, Result, anyhow};
use gossip_contracts::{
    connector::Cursor,
    coordination::{CursorBoundsCheck, RestoredShardState, ShardSpec, check_cursor_bounds},
    identity::{
        CanonicalBytes, FenceEpoch, LogicalTime, OpId, ShardKey, TenantId, WorkerId, domain_hasher,
        finalize_64,
    },
    persistence::WriteContext,
};
use gossip_coordination::{
    AcquireResultView, AcquireScratch, CheckpointError, ClaimError, CompleteError,
    CoordinationFacade, OpKind,
};
#[cfg(test)]
use gossip_coordination::{ParkError, ParkReason};
use gossip_frontier::decode_connector_extra;
use gossip_orchestrator::{FilesystemPathKind, FilesystemShardPayload, GitShardPayload};

use super::types::{
    DistributedRuntimeError, GitShardLease, GitWorkerIdentity, HydratedFilesystemSource,
    LeaseUncertainty, LeaseView, PageLoopTermination, ShardCompletionOutcome, ShardLease,
    WorkerIdentity, wall_clock_now,
};
use crate::coordination_sink::{
    CoordinationEventSink, LeaseUncertaintyReason, MirrorErrorClass, StageSignal,
};
use crate::{CancellationToken, FsScanConfig, ScanRuntimeError};
use gossip_contracts::connector::ErrorClass;

// ---------------------------------------------------------------------------
// Lease-uncertainty signal
// ---------------------------------------------------------------------------

/// Shared lease-uncertainty signal written by the deadline watcher.
///
/// The signal can be sealed once the receipt drain finishes successfully so a
/// later wall-clock expiry does not retroactively invalidate a completed local
/// durability stage.
///
/// State transitions are one-way:
/// - `Open` -> `Recorded` (deadline watcher fires)
/// - `Open` -> `Closed` (drain completes successfully)
/// - `Recorded` stays `Recorded` (drain success does not restore trust)
#[derive(Clone, Debug, Default)]
enum LeaseUncertaintyState {
    /// No uncertainty observed; the lease is still trusted.
    #[default]
    Open,
    /// The deadline watcher detected an expiry condition. The contained
    /// [`LeaseUncertainty`] describes the specific reason.
    Recorded(LeaseUncertainty),
    /// The local durability stage completed successfully and the signal was
    /// sealed before any deadline expiry. No further uncertainty can be
    /// recorded.
    Closed,
}

/// Shared lease-uncertainty signal written by the deadline watcher and sealed
/// when the local durability stage has finished successfully.
#[derive(Clone, Debug, Default)]
pub(super) struct LeaseUncertaintySignal {
    state: Arc<Mutex<LeaseUncertaintyState>>,
}

impl LeaseUncertaintySignal {
    pub(super) fn note(&self, reason: LeaseUncertainty) -> bool {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match &*guard {
            LeaseUncertaintyState::Open => {
                *guard = LeaseUncertaintyState::Recorded(reason);
                true
            }
            LeaseUncertaintyState::Recorded(_) | LeaseUncertaintyState::Closed => false,
        }
    }

    pub(super) fn close(&self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if matches!(*guard, LeaseUncertaintyState::Open) {
            *guard = LeaseUncertaintyState::Closed;
        }
        // A prior Recorded reason is preserved intentionally: local drain
        // success does not retroactively restore lease trust once the deadline
        // has elapsed. The coordinator's fence epoch is the authoritative
        // backstop.
    }

    pub(super) fn current(&self) -> Option<LeaseUncertainty> {
        match &*self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
        {
            LeaseUncertaintyState::Recorded(reason) => Some(*reason),
            LeaseUncertaintyState::Open | LeaseUncertaintyState::Closed => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Armed lease deadline
// ---------------------------------------------------------------------------

/// Local monotonic view of a coordination lease deadline.
///
/// The deadline is anchored to a wall-clock and monotonic-clock snapshot
/// captured at claim time, so later setup latency (engine build, pipeline
/// start) does not silently extend the watchdog window. Callers can then
/// re-check whether that original monotonic deadline has already elapsed
/// before starting scan or durability work.
#[derive(Clone, Copy, Debug)]
pub(super) struct ArmedLeaseDeadline {
    pub(super) deadline: LogicalTime,
    pub(super) monotonic_deadline: Instant,
}

impl ArmedLeaseDeadline {
    pub(super) fn arm_from(
        deadline: LogicalTime,
        observed: LogicalTime,
        monotonic_observed: Instant,
    ) -> Result<Self, LeaseUncertainty> {
        if observed.as_raw() >= deadline.as_raw() {
            return Err(LeaseUncertainty::DeadlineElapsed { deadline, observed });
        }

        let remaining = Duration::from_millis(deadline.as_raw().saturating_sub(observed.as_raw()));
        let monotonic_deadline = monotonic_observed
            .checked_add(remaining)
            .ok_or(LeaseUncertainty::DeadlineElapsed { deadline, observed })?;

        Ok(Self {
            deadline,
            monotonic_deadline,
        })
    }

    pub(super) fn expiry_reason(&self) -> Option<LeaseUncertainty> {
        (Instant::now() >= self.monotonic_deadline).then(|| LeaseUncertainty::DeadlineElapsed {
            deadline: self.deadline,
            observed: wall_clock_now(),
        })
    }
}

// ---------------------------------------------------------------------------
// Deadline watchdog
// ---------------------------------------------------------------------------

/// Fallback delay when no lease deadline is available to guide retry timing.
///
/// Kept short (25 ms) to avoid stalling the worker loop when concurrent
/// workers are completing shards rapidly.
pub(super) const CLAIM_RACE_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Synthetic cursor key for completing unbounded shards that produced zero
/// items.
///
/// When a shard's `key_range_start` is empty (unbounded lower bound) and no
/// items were committed, we still need a valid `last_key` to satisfy the
/// coordination layer's completion validation. A single null byte is the
/// smallest non-empty byte sequence and passes all bounds checks when the
/// spec start is empty.
pub(super) const EMPTY_RANGE_SENTINEL_KEY: &[u8] = b"\x00";

/// Poll a lease deadline until shard execution finishes or the deadline elapses.
///
/// The watcher uses [`std::thread::park_timeout`] instead of
/// [`std::thread::sleep`] so the caller can wake it immediately via
/// [`std::thread::Thread::unpark`] when shard execution completes before the
/// deadline. The sleep interval is clamped to [`CLAIM_RACE_RETRY_DELAY`] so
/// expiry detection stays responsive without introducing a separate
/// busy-spin interval.
///
/// Deadline comparison uses a monotonic [`Instant`] to avoid false-positive
/// or false-negative detection from `CLOCK_REALTIME` jumps (NTP step
/// corrections, VM live migration, leap seconds). The wall-clock
/// [`LogicalTime`] deadline is retained only for the diagnostic fields in
/// [`LeaseUncertainty::DeadlineElapsed`].
pub(super) fn watch_lease_deadline(
    armed_deadline: ArmedLeaseDeadline,
    cancel: CancellationToken,
    done: Arc<AtomicBool>,
    signal: LeaseUncertaintySignal,
) {
    loop {
        if let Some(reason) = armed_deadline.expiry_reason() {
            if signal.note(reason) {
                cancel.cancel();
            }
            return;
        }

        if done.load(Ordering::Acquire) {
            return;
        }

        let remaining = armed_deadline
            .monotonic_deadline
            .saturating_duration_since(Instant::now())
            .min(CLAIM_RACE_RETRY_DELAY)
            .max(Duration::from_millis(1));
        std::thread::park_timeout(remaining);
    }
}

/// Keep the shard locally trustworthy after receipt drain succeeds.
///
/// The watchdog records deadline expiry through [`LeaseUncertaintySignal`].
/// Once the drain thread closes that signal, later wall-clock ticks must not
/// retroactively invalidate already-durable local progress.
pub(super) fn ensure_post_drain_lease_trust(
    lease_uncertainty: &LeaseUncertaintySignal,
) -> Result<(), DistributedRuntimeError> {
    if let Some(reason) = lease_uncertainty.current() {
        return Err(DistributedRuntimeError::LeaseUncertain(reason));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Error mapping helpers
// ---------------------------------------------------------------------------

/// Maps an [`ErrorClass`] to a [`MirrorErrorClass`] telemetry label.
///
/// The wildcard arm is required because `ErrorClass` is `#[non_exhaustive]`.
/// New variants should be matched explicitly here; the fallback ensures
/// forward compatibility but should not be relied upon silently.
pub(super) const fn mirror_error_class(class: ErrorClass) -> MirrorErrorClass {
    match class {
        ErrorClass::Retryable => MirrorErrorClass::Retryable,
        ErrorClass::Permanent => MirrorErrorClass::Permanent,
        _ => MirrorErrorClass::Other,
    }
}

pub(super) const fn lease_uncertainty_reason(reason: LeaseUncertainty) -> LeaseUncertaintyReason {
    match reason {
        LeaseUncertainty::DeadlineElapsed { .. } => LeaseUncertaintyReason::DeadlineElapsed,
        LeaseUncertainty::AdvanceStaleFence { .. } => LeaseUncertaintyReason::StaleFence,
        LeaseUncertainty::AdvanceLeaseExpired { .. } => LeaseUncertaintyReason::LeaseExpired,
    }
}

pub(super) fn emit_lease_uncertainty(stage_sink: &CoordinationEventSink, reason: LeaseUncertainty) {
    stage_sink.emit_stage_signal(StageSignal::LeaseUncertaintyObserved {
        reason: lease_uncertainty_reason(reason),
    });
}

// ---------------------------------------------------------------------------
// Lease hydration — filesystem
// ---------------------------------------------------------------------------

/// Build hydrated filesystem source state by decoding shard metadata onto a
/// worker-owned scan template.
///
/// The shard's `connector_extra` bytes must contain a typed filesystem payload.
/// Hydration restores the canonical root path, validates it against the
/// payload's explicit source mode, and then overlays that path onto the worker
/// template.
///
/// # Trust boundary
///
/// The `connector_extra` metadata originates from a trusted coordination backend,
/// so no path-containment check is performed here. If the coordination backend
/// ever accepts untrusted shard metadata, apply
/// [`FilesystemRequest::normalize_within`] at submission time to verify the
/// canonical path falls within allowed roots before registration. Downstream,
/// the filesystem runtime still validates the hydrated path and the connector's
/// `openat`/`O_NOFOLLOW` enforcement prevents symlink traversal during reads.
/// Hydration uses `symlink_metadata` to reject symlinks before they reach the
/// connector layer.
///
/// [`FilesystemRequest::normalize_within`]: gossip_orchestrator::FilesystemRequest::normalize_within
pub(super) fn hydrate_filesystem_source_from_spec(
    spec: gossip_coordination::ShardSpecRef<'_>,
    scan_template: &FsScanConfig,
) -> Result<HydratedFilesystemSource> {
    fn validate_payload_path_kind(payload: &FilesystemShardPayload) -> Result<()> {
        let metadata = fs::symlink_metadata(payload.canonical_root())
            .context("failed to inspect filesystem shard payload path")?;
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            anyhow::bail!("filesystem shard payload path is a symlink; expected a canonical path");
        }
        let actual_kind = FilesystemPathKind::from_file_type(&file_type).ok_or_else(|| {
            anyhow!("filesystem shard payload path must be a regular file or directory")
        })?;
        let expected_kind = payload.mode().expected_path_kind();
        if actual_kind != expected_kind {
            return Err(anyhow!(
                "filesystem shard payload mode '{}' requires a {}, but the path is a {}",
                payload.mode(),
                expected_kind,
                actual_kind
            ));
        }
        Ok(())
    }

    let mut scan_config = scan_template.clone();
    let connector_extra = decode_connector_extra(spec)
        .map_err(|err| anyhow!("failed to decode shard metadata envelope: {err}"))?;
    let payload = FilesystemShardPayload::decode(connector_extra)
        .map_err(|err| anyhow!("failed to decode filesystem shard payload: {err}"))?;
    validate_payload_path_kind(&payload)?;
    scan_config.path = payload.canonical_root().to_path_buf();

    Ok(HydratedFilesystemSource::new(scan_config, payload.mode()))
}

/// Convert an acquired coordination lease into the concrete runtime payload.
///
/// Constructs a [`WriteContext`] from the lease's fencing fields and the
/// worker's policy hash, restores an owned [`ShardSpec`] and resume
/// [`Cursor`] from the acquired snapshot, then decodes the shard spec's typed
/// filesystem payload to restore the scan path and source mode.
pub(super) fn build_lease_from_acquire(
    acquired: AcquireResultView<'_>,
    identity: &WorkerIdentity,
    claim_wall_clock: LogicalTime,
    claim_instant: Instant,
) -> Result<ShardLease> {
    let snapshot = acquired.snapshot;
    let spec = snapshot.spec();
    let shard_spec = ShardSpec::try_from_ref(spec).with_context(|| {
        format!(
            "failed to restore shard spec for shard {}",
            acquired.lease.shard()
        )
    })?;
    let resume_cursor = Cursor::try_from_update(snapshot.cursor()).with_context(|| {
        format!(
            "failed to restore cursor for shard {}",
            acquired.lease.shard()
        )
    })?;
    let state = RestoredShardState::new(shard_spec, resume_cursor, snapshot.cursor_semantics());
    let write_context = WriteContext::new(
        acquired.lease.tenant(),
        identity.policy_hash,
        acquired.lease.run(),
        acquired.lease.shard(),
        acquired.lease.fence(),
    );

    Ok(ShardLease::new(
        Arc::from(acquired.lease.shard().to_string()),
        acquired.lease,
        state,
        hydrate_filesystem_source_from_spec(spec, &identity.scan_template)?,
        write_context,
        identity.tenant_secret_key,
        claim_wall_clock,
        claim_instant,
    ))
}

// ---------------------------------------------------------------------------
// Lease hydration — Git
// ---------------------------------------------------------------------------

/// Decode the typed Git repo-frontier payload carried in shard metadata.
fn hydrate_git_payload_from_spec(
    spec: gossip_coordination::ShardSpecRef<'_>,
    tenant: TenantId,
) -> Result<GitShardPayload> {
    let connector_extra = decode_connector_extra(spec)
        .map_err(|err| anyhow!("failed to decode shard metadata envelope: {err}"))?;
    let payload = GitShardPayload::decode(connector_extra)
        .map_err(|err| anyhow!("failed to decode git shard payload: {err}"))?;
    if payload.tenant_id() != tenant {
        return Err(anyhow!(
            "git shard payload tenant {:?} did not match worker tenant {:?}",
            payload.tenant_id(),
            tenant
        ));
    }
    Ok(payload)
}

/// Convert an acquired coordination lease into the concrete Git runtime payload.
pub(super) fn build_git_lease_from_acquire(
    acquired: AcquireResultView<'_>,
    identity: &GitWorkerIdentity,
    claim_wall_clock: LogicalTime,
    claim_instant: Instant,
) -> Result<GitShardLease> {
    let snapshot = acquired.snapshot;
    let spec = snapshot.spec();
    let shard_spec = ShardSpec::try_from_ref(spec).with_context(|| {
        format!(
            "failed to restore shard spec for shard {}",
            acquired.lease.shard()
        )
    })?;
    let resume_cursor = Cursor::try_from_update(snapshot.cursor()).with_context(|| {
        format!(
            "failed to restore cursor for shard {}",
            acquired.lease.shard()
        )
    })?;
    let state = RestoredShardState::new(shard_spec, resume_cursor, snapshot.cursor_semantics());
    let write_context = WriteContext::new(
        acquired.lease.tenant(),
        identity.policy_hash,
        acquired.lease.run(),
        acquired.lease.shard(),
        acquired.lease.fence(),
    );

    Ok(GitShardLease::new(
        Arc::from(acquired.lease.shard().to_string()),
        acquired.lease,
        state,
        hydrate_git_payload_from_spec(spec, identity.tenant)?,
        write_context,
        identity.tenant_secret_key,
        claim_wall_clock,
        claim_instant,
    ))
}

// ---------------------------------------------------------------------------
// Claim retry logic
// ---------------------------------------------------------------------------

/// Compute how long to sleep before retrying a shard claim.
///
/// When the coordinator provides an `earliest_deadline` (the soonest
/// existing lease expiry), the delay equals `deadline - now` (clamped to
/// at least 1 ms). Without a deadline, the fixed [`CLAIM_RACE_RETRY_DELAY`]
/// is used.
pub(super) fn claim_retry_delay(
    now: LogicalTime,
    earliest_deadline: Option<LogicalTime>,
) -> Duration {
    earliest_deadline
        .map(|deadline| deadline.as_raw().saturating_sub(now.as_raw()).max(1))
        .map(Duration::from_millis)
        .unwrap_or(CLAIM_RACE_RETRY_DELAY)
}

/// Claim the next available shard, retrying while the run still has active
/// work or the coordinator is enforcing worker cooldown.
///
/// Returns `Ok(None)` when no shards are available **and** the run has zero
/// active leases (i.e., the run is fully settled). Returns `Ok(Some(lease))`
/// on successful claim. Retries internally on `NoneAvailable` (other
/// workers hold all shards) and `Throttled` (coordinator-imposed cooldown),
/// sleeping until the earliest deadline expires. Terminal errors like
/// `RunNotFound` or `BackendError` propagate immediately.
///
/// `build_lease` converts a raw `AcquireResultView` into the caller's
/// concrete lease type (filesystem or Git) so the retry loop is shared.
fn claim_next<C, L, F>(
    coordinator: &mut C,
    tenant: TenantId,
    run: gossip_contracts::identity::RunId,
    worker: WorkerId,
    scratch: &mut AcquireScratch,
    build_lease: F,
) -> Result<Option<L>, DistributedRuntimeError>
where
    C: CoordinationFacade,
    F: Fn(AcquireResultView<'_>, LogicalTime, Instant) -> Result<L>,
{
    loop {
        let now = wall_clock_now();
        let claim_instant = Instant::now();
        match coordinator.claim_next_available(now, tenant, run, worker, scratch) {
            Ok(acquired) => {
                return build_lease(acquired, now, claim_instant)
                    .map(Some)
                    .map_err(DistributedRuntimeError::Coordinator);
            }
            Err(ClaimError::NoneAvailable { earliest_deadline }) => {
                // Refresh the wall clock after the (potentially slow)
                // coordinator call so retry delay and progress queries
                // use an up-to-date timestamp.
                let now = wall_clock_now();
                let progress = coordinator
                    .get_run_progress(now, tenant, run)
                    .map_err(|error| DistributedRuntimeError::Coordinator(AnyError::new(error)))?;
                if progress.active() == 0 {
                    return Ok(None);
                }
                std::thread::sleep(claim_retry_delay(now, earliest_deadline));
            }
            Err(ClaimError::Throttled { retry_after }) => {
                let now = wall_clock_now();
                std::thread::sleep(claim_retry_delay(now, Some(retry_after)));
            }
            Err(error) => {
                return Err(DistributedRuntimeError::Coordinator(AnyError::new(error)));
            }
        }
    }
}

/// Claim the next available filesystem shard lease.
pub(super) fn claim_next_lease<C>(
    coordinator: &mut C,
    identity: &WorkerIdentity,
    scratch: &mut AcquireScratch,
) -> Result<Option<ShardLease>, DistributedRuntimeError>
where
    C: CoordinationFacade,
{
    claim_next(
        coordinator,
        identity.tenant,
        identity.run,
        identity.worker,
        scratch,
        |acquired, now, instant| build_lease_from_acquire(acquired, identity, now, instant),
    )
}

/// Claim the next available Git repo-frontier shard lease.
pub(super) fn claim_next_git_lease<C>(
    coordinator: &mut C,
    identity: &GitWorkerIdentity,
    scratch: &mut AcquireScratch,
) -> Result<Option<GitShardLease>, DistributedRuntimeError>
where
    C: CoordinationFacade,
{
    claim_next(
        coordinator,
        identity.tenant,
        identity.run,
        identity.worker,
        scratch,
        |acquired, now, instant| build_git_lease_from_acquire(acquired, identity, now, instant),
    )
}

// ---------------------------------------------------------------------------
// Deterministic OpId
// ---------------------------------------------------------------------------

/// Derive a deterministic [`OpId`] from shard identity, fence epoch, and kind.
///
/// Idempotent: the same `(key, fence, op_kind)` triple always produces the
/// same `OpId`. This allows the coordination backend to detect and deduplicate
/// replayed completion calls.
pub(super) fn deterministic_op_id(key: ShardKey, fence: FenceEpoch, op_kind: OpKind) -> OpId {
    // Domain string is part of the identity contract: changing it breaks OpId
    // continuity for in-flight operations and causes deduplication mismatches.
    let mut hasher = domain_hasher("gossip.scanner_runtime.distributed.op_id");
    key.run().write_canonical(&mut hasher);
    key.shard().write_canonical(&mut hasher);
    fence.write_canonical(&mut hasher);
    op_kind.as_u8().write_canonical(&mut hasher);
    OpId::from_raw(finalize_64(&hasher))
}

/// Maps coordinator advance errors (`StaleFence`, `LeaseExpired`) to
/// `DistributedRuntimeError::LeaseUncertain`, falling back to
/// `DistributedRuntimeError::Coordinator` for other variants.
macro_rules! map_advance_error {
    ($error:expr, $error_type:ident) => {
        match $error {
            $error_type::StaleFence { presented, current } => {
                DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceStaleFence {
                    presented,
                    current,
                })
            }
            $error_type::LeaseExpired { deadline, now } => {
                DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceLeaseExpired {
                    deadline,
                    now,
                })
            }
            other => DistributedRuntimeError::Coordinator(AnyError::new(other)),
        }
    };
}

// ---------------------------------------------------------------------------
// Shard advancement
// ---------------------------------------------------------------------------

/// Advance a claimed shard directly against the coordination backend.
///
/// `outcome` makes the coordination action explicit:
/// - [`ShardCompletionOutcome::Complete`] uses the receipt-driven
///   checkpoint cursor and transitions the shard to `Done`.
/// - [`ShardCompletionOutcome::Checkpoint`] uses the receipt-driven
///   checkpoint cursor but keeps the shard active for a later claim.
/// - [`ShardCompletionOutcome::ExhaustedEmpty`] preserves the restored
///   resume cursor when the shard has prior progress (last key present),
///   uses `EMPTY_RANGE_SENTINEL_KEY` for unbounded empty shards, and
///   falls back to `range_start()` for bounded empty shards.
///
/// The chosen cursor is validated with [`check_cursor_bounds`] before the
/// coordinator call so checkpoint and completion updates cannot silently
/// escape the shard's key range.
///
/// The operation uses a deterministic [`OpId`] so replayed calls are
/// idempotent. If the coordination backend reports the update was already
/// applied (idempotent replay), the function logs an info message but
/// succeeds. Coordinator-side lease loss (`StaleFence` / `LeaseExpired`)
/// surfaces as [`DistributedRuntimeError::LeaseUncertain`] for both
/// checkpoint and completion paths.
///
/// The `now` parameter passed to checkpoint/complete uses
/// `wall_clock_now()` (SystemTime). The local monotonic watchdog is a
/// best-effort early-warning mechanism; the coordinator's server-side
/// deadline and fence-epoch checks are authoritative.
pub(super) fn advance_shard<C, L>(
    coordinator: &mut C,
    tenant: TenantId,
    lease: &L,
    outcome: &ShardCompletionOutcome,
) -> Result<(), DistributedRuntimeError>
where
    C: CoordinationFacade,
    L: LeaseView,
{
    if lease.lease().tenant() != tenant {
        return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
            anyhow::anyhow!(
                "advance_shard tenant mismatch: worker tenant {tenant:?}, lease tenant {:?}",
                lease.lease().tenant(),
            ),
        )));
    }

    let (cursor, op_kind, operation_name) = match outcome {
        ShardCompletionOutcome::Checkpoint { checkpoint } => {
            (checkpoint.as_update(), OpKind::Checkpoint, "checkpoint")
        }
        ShardCompletionOutcome::Complete { checkpoint } => {
            (checkpoint.as_update(), OpKind::Complete, "completion")
        }
        ShardCompletionOutcome::ExhaustedEmpty if lease.resume_cursor().last_key().is_some() => (
            lease.resume_cursor().as_update(),
            OpKind::Complete,
            "completion",
        ),
        ShardCompletionOutcome::ExhaustedEmpty if lease.range_start().is_empty() => (
            gossip_coordination::CursorUpdate::new(EMPTY_RANGE_SENTINEL_KEY),
            OpKind::Complete,
            "completion",
        ),
        ShardCompletionOutcome::ExhaustedEmpty => (
            gossip_coordination::CursorUpdate::new(lease.range_start()),
            OpKind::Complete,
            "completion",
        ),
    };
    match check_cursor_bounds(cursor, lease.restored_state().shard_spec().as_ref()) {
        CursorBoundsCheck::InBounds => {}
        CursorBoundsCheck::NoKey => {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "shard '{}' {} cursor is missing last_key for {:?}",
                    lease.shard_id(),
                    operation_name,
                    lease.restored_state().shard_spec(),
                ),
            )));
        }
        bounds => {
            return Err(DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(
                anyhow!(
                    "shard '{}' {} cursor {:?} is not in bounds for {:?}: {:?}",
                    lease.shard_id(),
                    operation_name,
                    cursor.last_key(),
                    lease.restored_state().shard_spec(),
                    bounds,
                ),
            )));
        }
    }

    let op_id = deterministic_op_id(lease.lease().shard_key(), lease.lease().fence(), op_kind);
    let applied = match outcome {
        ShardCompletionOutcome::Checkpoint { .. } => coordinator
            .checkpoint(wall_clock_now(), tenant, &lease.lease(), &cursor, op_id)
            .map_err(|e| map_advance_error!(e, CheckpointError))?,
        ShardCompletionOutcome::Complete { .. } | ShardCompletionOutcome::ExhaustedEmpty => {
            coordinator
                .complete(wall_clock_now(), tenant, &lease.lease(), &cursor, op_id)
                .map_err(|e| map_advance_error!(e, CompleteError))?
        }
    };

    if !applied.is_executed() {
        tracing::info!(
            shard_id = %lease.shard_id(),
            operation = operation_name,
            "{operation_name} was an idempotent replay",
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shard parking
// ---------------------------------------------------------------------------

/// Park a claimed shard directly against the coordination backend.
///
/// Uses a deterministic [`OpId`] so repeated park attempts are idempotent. The
/// helper is intended for best-effort cleanup after a permanent lease failure:
/// callers should log any returned [`ParkError`] but preserve the original
/// failure that triggered the park attempt.
#[cfg(test)]
pub(super) fn park_shard_on_error<C, L>(
    coordinator: &mut C,
    tenant: TenantId,
    lease: &L,
    reason: ParkReason,
) -> Result<(), ParkError>
where
    C: CoordinationFacade,
    L: LeaseView,
{
    if lease.lease().tenant() != tenant {
        return Err(ParkError::TenantMismatch { expected: tenant });
    }

    let op_id = deterministic_op_id(
        lease.lease().shard_key(),
        lease.lease().fence(),
        OpKind::Park,
    );
    let applied =
        coordinator.park_shard(wall_clock_now(), tenant, &lease.lease(), reason, op_id)?;
    if !applied.is_executed() {
        tracing::info!(
            shard_id = %lease.shard_id(),
            "park was an idempotent replay",
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Shard completion selection
// ---------------------------------------------------------------------------

/// Convert page-loop termination state plus durable progress into one explicit
/// shard-advance action.
pub(super) fn select_shard_completion(
    shard_id: &str,
    initial_resume_cursor: &Cursor,
    termination: PageLoopTermination,
    checkpoint_cursor: Option<Cursor>,
    resume_cursor: Cursor,
) -> Result<ShardCompletionOutcome, DistributedRuntimeError> {
    let recovered_checkpoint = (resume_cursor != *initial_resume_cursor).then_some(resume_cursor);

    match (termination, checkpoint_cursor, recovered_checkpoint) {
        (PageLoopTermination::ExhaustedEmptyConfirmed, None, None) => {
            Ok(ShardCompletionOutcome::ExhaustedEmpty)
        }
        (PageLoopTermination::ExhaustedEmptyConfirmed, Some(checkpoint), _)
        | (PageLoopTermination::ExhaustedEmptyConfirmed, None, Some(checkpoint)) => {
            Ok(ShardCompletionOutcome::Complete { checkpoint })
        }
        (PageLoopTermination::Partial, Some(checkpoint), _)
        | (PageLoopTermination::Partial, None, Some(checkpoint)) => {
            Ok(ShardCompletionOutcome::Checkpoint { checkpoint })
        }
        (PageLoopTermination::Partial, None, None) => Err(DistributedRuntimeError::Runtime(
            ScanRuntimeError::Driver(anyhow!(
                "filesystem shard '{}' stopped before confirming exhaustion and produced no receipt-backed progress",
                shard_id
            )),
        )),
    }
}
