//! Coordination-backed filesystem run setup.
//!
//! This module is the final control-plane lowering step for filesystem
//! submissions: it takes the outputs of request normalization, initial shard
//! geometry planning, and typed payload encoding, then materializes the
//! validated initial manifest that `register_shards` requires.
//!
//! The helper keeps the existing coordination lifecycle intact:
//!
//! 1. Encode the typed filesystem payload into shard metadata bytes.
//! 2. Lower the planned startup geometry into bounded shard-spec ranges.
//! 3. Build a validated manifest with [`gossip_frontier::builder::PreallocShardBuilder`].
//! 4. Call [`gossip_coordination::RunManagement::create_run_with_shards`].
//!
//! The returned [`IdempotentOutcome`] preserves whether this was the first
//! execution or a safe replay after an earlier partial attempt.

use std::fmt;

use gossip_coordination::{
    CreateRunError, IdempotentOutcome, LogicalTime, OpId, RunId, RunManagement, RunRecord,
    ShardArena, ShardId, TenantId,
};
use gossip_frontier::builder::{PreallocShardBuilder, PreallocShardBuilderError};

use crate::payload::{FilesystemShardPayload, FilesystemShardPayloadEncodeError};
use crate::planner::InitialShardGeometry;
use crate::request::{FilesystemSourceMode, NormalizedFilesystemRequest};

const FILESYSTEM_KEYSPACE_FLOOR: &[u8] = b"\x00";
const FILESYSTEM_KEYSPACE_CEILING: &[u8] = b"\xFF";

/// Result of a successful filesystem run setup.
///
/// The run record is coordination-authoritative. `root_shards` is copied out
/// explicitly so later submission entrypoints can forward the registered
/// startup shard IDs without re-reading the record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRunSetupResult {
    run: RunRecord,
    root_shards: Box<[ShardId]>,
}

impl FilesystemRunSetupResult {
    fn from_run(run: RunRecord) -> Self {
        let root_shards = run.root_shards().to_vec().into_boxed_slice();
        Self { run, root_shards }
    }

    /// Coordination-authoritative run record after setup.
    #[must_use]
    pub fn run(&self) -> &RunRecord {
        &self.run
    }

    /// Registered root shard IDs for the startup manifest.
    #[must_use]
    pub fn root_shards(&self) -> &[ShardId] {
        &self.root_shards
    }
}

/// Borrowed inputs for filesystem run setup.
///
/// Bundles the three orchestrator stages that precede coordination writes so
/// callers pass one typed value instead of parallel positional arguments.
#[derive(Clone, Copy, Debug)]
pub struct FilesystemRunSetupInput<'a> {
    request: &'a NormalizedFilesystemRequest,
    geometry: InitialShardGeometry,
    payload: &'a FilesystemShardPayload,
}

impl<'a> FilesystemRunSetupInput<'a> {
    /// Bundle a normalized request, planned geometry, and typed payload.
    #[must_use]
    pub fn new(
        request: &'a NormalizedFilesystemRequest,
        geometry: InitialShardGeometry,
        payload: &'a FilesystemShardPayload,
    ) -> Self {
        Self {
            request,
            geometry,
            payload,
        }
    }

    /// Normalized filesystem request to register.
    #[must_use]
    pub fn request(self) -> &'a NormalizedFilesystemRequest {
        self.request
    }

    /// Planned startup shard geometry.
    #[must_use]
    pub fn geometry(self) -> InitialShardGeometry {
        self.geometry
    }

    /// Typed payload to encode into shard metadata.
    #[must_use]
    pub fn payload(self) -> &'a FilesystemShardPayload {
        self.payload
    }
}

/// Errors from [`setup_filesystem_run`].
#[derive(Debug)]
#[non_exhaustive]
pub enum FilesystemRunSetupError {
    /// The typed payload mode disagrees with the normalized request.
    PayloadModeMismatch {
        request: FilesystemSourceMode,
        payload: FilesystemSourceMode,
    },
    /// The typed payload root disagrees with the normalized request.
    PayloadRootMismatch,
    /// Payload encoding failed before manifest construction.
    PayloadEncode(FilesystemShardPayloadEncodeError),
    /// Manifest lowering or validation failed before coordinator mutation.
    ManifestBuild(PreallocShardBuilderError),
    /// Run creation or registration failed in the coordination backend.
    CreateRun(CreateRunError),
}

impl fmt::Display for FilesystemRunSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadModeMismatch { request, payload } => write!(
                f,
                "filesystem payload mode '{payload}' does not match normalized request mode '{request}'"
            ),
            Self::PayloadRootMismatch => {
                f.write_str("filesystem payload root does not match normalized request root")
            }
            Self::PayloadEncode(err) => write!(f, "filesystem payload encode failed: {err}"),
            Self::ManifestBuild(err) => write!(f, "filesystem manifest build failed: {err}"),
            Self::CreateRun(err) => write!(f, "filesystem run setup failed: {err}"),
        }
    }
}

impl std::error::Error for FilesystemRunSetupError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::PayloadEncode(err) => Some(err),
            Self::ManifestBuild(err) => Some(err),
            Self::CreateRun(err) => Some(err),
            Self::PayloadModeMismatch { .. } | Self::PayloadRootMismatch => None,
        }
    }
}

impl From<FilesystemShardPayloadEncodeError> for FilesystemRunSetupError {
    fn from(err: FilesystemShardPayloadEncodeError) -> Self {
        Self::PayloadEncode(err)
    }
}

impl From<PreallocShardBuilderError> for FilesystemRunSetupError {
    fn from(err: PreallocShardBuilderError) -> Self {
        Self::ManifestBuild(err)
    }
}

impl From<CreateRunError> for FilesystemRunSetupError {
    fn from(err: CreateRunError) -> Self {
        Self::CreateRun(err)
    }
}

/// Create a filesystem run and register its startup shard manifest.
///
/// The helper accepts the outputs of the earlier orchestrator seams directly:
/// a normalized request, its planned startup geometry, and the typed shard
/// payload that runtime hydration will later decode from shard metadata.
///
/// # Retry behavior
///
/// This delegates to [`RunManagement::create_run_with_shards`], preserving its
/// replay contract:
///
/// - reusing the same `RunId` with the same `RunConfig` and manifest replays
///   cleanly when the prior attempt already registered shards,
/// - reusing the same `RunId` with a different config fails with
///   [`CreateRunError::ConfigMismatch`],
/// - reusing the same `OpId` with a different manifest fails with
///   [`gossip_coordination::RegisterShardsError::OpIdConflict`].
///
/// A crash between `create_run` and `register_shards` may still leave the run
/// in `Initializing`, which is why the helper always uses the retry-friendly
/// `create_run_with_shards` path.
///
/// # Errors
///
/// Returns [`FilesystemRunSetupError`] when the request and payload disagree,
/// payload encoding fails, manifest lowering fails, or the coordination
/// lifecycle rejects the run creation / registration attempt.
pub fn setup_filesystem_run<M>(
    management: &mut M,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    input: FilesystemRunSetupInput<'_>,
    op_id: OpId,
) -> Result<IdempotentOutcome<FilesystemRunSetupResult>, FilesystemRunSetupError>
where
    M: RunManagement,
{
    let request = input.request();
    let geometry = input.geometry();
    let payload = input.payload();
    validate_request_payload(request, payload)?;

    let encoded_payload = payload.encode()?;
    let (start, end) = lower_geometry_bounds(&geometry);
    let byte_capacity = slab_allocation_bytes(start.len())
        + slab_allocation_bytes(end.len())
        + slab_allocation_bytes(encoded_payload.len());
    let mut arena = ShardArena::with_capacity(1, byte_capacity);
    let mut builder =
        PreallocShardBuilder::<1>::new(&mut arena, 1).expect("fixed one-entry builder is valid");
    let _ = builder.add_range(start, end, &encoded_payload)?;
    let manifest = builder.build_inputs()?;

    let outcome = management.create_run_with_shards(
        now,
        tenant,
        run,
        request.run_config(),
        manifest.as_slice(),
        op_id,
    )?;

    Ok(outcome.map(FilesystemRunSetupResult::from_run))
}

fn validate_request_payload(
    request: &NormalizedFilesystemRequest,
    payload: &FilesystemShardPayload,
) -> Result<(), FilesystemRunSetupError> {
    if request.mode() != payload.mode() {
        return Err(FilesystemRunSetupError::PayloadModeMismatch {
            request: request.mode(),
            payload: payload.mode(),
        });
    }
    if request.canonical_root() != payload.canonical_root() {
        return Err(FilesystemRunSetupError::PayloadRootMismatch);
    }
    Ok(())
}

fn lower_geometry_bounds(geometry: &InitialShardGeometry) -> (&[u8], &[u8]) {
    // Filesystem startup shards cover root-relative UTF-8 path keys.
    // Those keys are non-empty, so `0x00` sorts below every valid item key.
    // Valid UTF-8 never uses `0xFF`, so `0xFF` sorts above every valid item
    // key and gives a finite upper bound that manifest registration accepts.
    let start = if geometry.is_start_unbounded() {
        FILESYSTEM_KEYSPACE_FLOOR
    } else {
        geometry.key_range_start()
    };
    let end = if geometry.is_end_unbounded() {
        FILESYSTEM_KEYSPACE_CEILING
    } else {
        geometry.key_range_end()
    };
    (start, end)
}

fn slab_allocation_bytes(len: usize) -> usize {
    if len == 0 {
        0
    } else {
        len.checked_next_power_of_two().unwrap_or(len).max(16)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use gossip_coordination::{
        AcquireScratch, ClaimError, CreateRunError, CursorSemantics, InMemoryCoordinator, OpId,
        RegisterShardsError, RunConfig, RunManagement, RunStatus, ShardClaiming, TenantId,
        WorkerId,
    };
    use tempfile::tempdir;

    use super::*;
    use crate::planner::plan_filesystem_initial_shards;
    use crate::request::FilesystemRequest;
    use crate::test_support::run_config;

    const LEASE_DURATION_MS: u64 = 30_000;

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn run() -> RunId {
        RunId::from_raw(42)
    }

    fn worker() -> WorkerId {
        WorkerId::from_raw(7)
    }

    fn now(tick: u64) -> LogicalTime {
        LogicalTime::from_raw(tick)
    }

    fn different_run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 60_000, Some(5))
            .expect("alternate run config")
    }

    fn normalize_directory(path: &Path, config: RunConfig) -> NormalizedFilesystemRequest {
        FilesystemRequest::directory_root(path, config)
            .normalize()
            .expect("directory request should normalize")
    }

    #[test]
    fn setup_filesystem_run_creates_active_claimable_root_shard() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let outcome = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
            OpId::from_raw(11),
        )
        .expect("run setup should succeed");

        assert!(outcome.is_executed());
        let result = outcome.into_inner();
        assert_eq!(result.run().status(), RunStatus::Active);
        assert_eq!(result.root_shards().len(), 1);
        assert_eq!(result.run().root_shards(), result.root_shards());

        let mut scratch = AcquireScratch::new();
        let claimed = coordinator
            .claim_next_available(now(2), tenant(), run(), worker(), &mut scratch)
            .expect("registered root shard should be claimable");
        assert_eq!(claimed.lease.shard(), result.root_shards()[0]);
    }

    #[test]
    fn setup_filesystem_run_replays_existing_registration() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let first = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
            OpId::from_raw(12),
        )
        .expect("first setup should succeed")
        .into_inner();

        let replay = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
            OpId::from_raw(12),
        )
        .expect("replayed setup should succeed");

        assert!(replay.is_replay());
        assert_eq!(replay.into_inner().root_shards(), first.root_shards());
    }

    #[test]
    fn setup_filesystem_run_finishes_existing_initializing_run() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);
        coordinator
            .create_run(now(1), tenant(), run(), request.run_config())
            .expect("pre-create initializing run");

        let outcome = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
            OpId::from_raw(13),
        )
        .expect("setup should resume from initializing state");

        assert!(outcome.is_executed());
        assert_eq!(outcome.into_inner().run().status(), RunStatus::Active);
    }

    #[test]
    fn setup_filesystem_run_rejects_config_mismatch_for_existing_run() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);
        coordinator
            .create_run(now(1), tenant(), run(), different_run_config())
            .expect("pre-create mismatched run");

        let err = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
            OpId::from_raw(14),
        )
        .expect_err("mismatched config should be rejected");

        assert!(matches!(
            err,
            FilesystemRunSetupError::CreateRun(CreateRunError::ConfigMismatch { .. })
        ));
    }

    #[test]
    fn setup_filesystem_run_rejects_conflicting_registration_payload() {
        let dir = tempdir().expect("tempdir");
        let scan_root_a = dir.path().join("scan-root-a");
        let scan_root_b = dir.path().join("scan-root-b");
        fs::create_dir(&scan_root_a).expect("create root a");
        fs::create_dir(&scan_root_b).expect("create root b");

        let request_a = normalize_directory(&scan_root_a, run_config());
        let request_b = normalize_directory(&scan_root_b, run_config());
        let plan_a = plan_filesystem_initial_shards(request_a.clone());
        let plan_b = plan_filesystem_initial_shards(request_b.clone());
        let payload_a = plan_a.shard_payload();
        let payload_b = plan_b.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let _ = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request_a, plan_a.initial_shard(), &payload_a),
            OpId::from_raw(15),
        )
        .expect("first setup should succeed");

        let err = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request_b, plan_b.initial_shard(), &payload_b),
            OpId::from_raw(15),
        )
        .expect_err("conflicting replay payload should be rejected");

        assert!(matches!(
            err,
            FilesystemRunSetupError::CreateRun(CreateRunError::RegisterShardsFailed(
                RegisterShardsError::OpIdConflict(_)
            ))
        ));
    }

    #[test]
    fn setup_filesystem_run_validates_payload_matches_request() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        let other_root = dir.path().join("other-root");
        fs::create_dir(&scan_root).expect("create root");
        fs::create_dir(&other_root).expect("create other root");

        let request = normalize_directory(&scan_root, run_config());
        let mismatched_request = normalize_directory(&other_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let mismatched_payload = plan_filesystem_initial_shards(mismatched_request).shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let err = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard(), &mismatched_payload),
            OpId::from_raw(16),
        )
        .expect_err("request/payload mismatch should be rejected before mutation");

        assert!(matches!(err, FilesystemRunSetupError::PayloadRootMismatch));
        let mut scratch = AcquireScratch::new();
        let claim =
            coordinator.claim_next_available(now(2), tenant(), run(), worker(), &mut scratch);
        assert!(matches!(claim, Err(ClaimError::RunNotFound)));
    }
}
