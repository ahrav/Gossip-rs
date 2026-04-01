//! Coordination-backed filesystem run setup.
//!
//! This module is the final control-plane lowering step for filesystem
//! submissions: it takes the outputs of request normalization, initial shard
//! geometry planning, and typed payload encoding, then materializes the
//! validated initial manifest that `register_shards` requires.
//!
//! The helper keeps the existing coordination lifecycle intact:
//!
//! 1. Validate that the typed payload agrees with the normalized request
//!    (mode and canonical root must match). This runs before any coordinator
//!    mutation so a mismatch never leaves partial state.
//! 2. Encode the typed filesystem payload into connector-extra bytes.
//! 3. Lower the planned startup geometry into bounded shard-spec ranges.
//! 4. Build a validated manifest with [`gossip_frontier::builder::PreallocShardBuilder`].
//! 5. Call [`gossip_coordination::RunManagement::create_run_with_shards`].
//!
//! The returned [`IdempotentOutcome`] preserves whether this was the first
//! execution or a safe replay after an earlier partial attempt.

use std::fmt;
use std::path::PathBuf;

use gossip_coordination::{
    CreateRunError, IdempotentOutcome, LogicalTime, OpId, RunId, RunManagement, RunRecord,
    RunStatus, ShardArena, ShardId, TenantId,
};
use gossip_frontier::builder::{PreallocShardBuilder, PreallocShardBuilderError};

use crate::payload::{FilesystemShardPayload, FilesystemShardPayloadEncodeError};
use crate::planner::InitialShardGeometry;
use crate::request::{FilesystemSourceMode, NormalizedFilesystemRequest};

/// Lowest byte value in the filesystem keyspace.
///
/// Filesystem shard keys are root-relative UTF-8 paths, which are always
/// non-empty.  `0x00` sorts below every valid path byte, so it serves as
/// an inclusive lower sentinel that manifest registration accepts; because
/// no valid path equals `\x00`, it effectively excludes nothing real from
/// the shard range.
const FILESYSTEM_KEYSPACE_FLOOR: &[u8] = b"\x00";

/// Highest byte value in the filesystem keyspace.
///
/// Valid UTF-8 never produces the byte `0xFF`, so it sorts above every
/// valid path key and provides a finite exclusive upper bound for
/// manifest registration.
const FILESYSTEM_KEYSPACE_CEILING: &[u8] = b"\xFF";

/// Result of a successful filesystem run setup.
///
/// The run record is coordination-authoritative and owns the root shard list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRunSetupResult {
    run: RunRecord,
}

impl FilesystemRunSetupResult {
    fn from_run(run: RunRecord) -> Self {
        assert!(
            run.status() == RunStatus::Active,
            "FilesystemRunSetupResult requires Active status, got {:?}",
            run.status()
        );
        assert!(
            !run.root_shards().is_empty(),
            "FilesystemRunSetupResult requires non-empty root shards"
        );
        Self { run }
    }

    /// Coordination-authoritative run record after setup.
    #[must_use]
    pub fn run(&self) -> &RunRecord {
        &self.run
    }

    /// Registered root shard IDs for the startup manifest.
    #[must_use]
    pub fn root_shards(&self) -> &[ShardId] {
        self.run.root_shards()
    }
}

/// Borrowed inputs for filesystem run setup.
///
/// Bundles the three orchestrator stages that precede coordination writes so
/// callers pass one typed value instead of parallel positional arguments.
///
/// Its custom [`fmt::Debug`] implementation redacts the canonical root so tracing
/// and test failures do not leak filesystem paths by default.
#[derive(Clone)]
pub struct FilesystemRunSetupInput<'a> {
    request: &'a NormalizedFilesystemRequest,
    geometry: InitialShardGeometry,
    payload: &'a FilesystemShardPayload,
}

// Custom Debug: redacts the request's canonical root to prevent filesystem
// path leakage.  The payload field delegates to its own redacting Debug impl.
impl fmt::Debug for FilesystemRunSetupInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FilesystemRunSetupInput")
            .field("mode", &self.request.mode())
            .field("canonical_root", &"<redacted>")
            .field("geometry", &self.geometry)
            .field("payload", &self.payload)
            .finish()
    }
}

impl<'a> FilesystemRunSetupInput<'a> {
    /// Bundle a normalized request, planned geometry, and typed payload.
    ///
    /// # Caller invariant
    ///
    /// `geometry` and `payload` must both originate from the same `request`.
    /// Today the planner always emits full-keyspace geometry, so a mismatch
    /// is harmless.  If bounded per-request geometry is introduced later,
    /// this constructor should validate the relationship.
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
    pub fn request(&self) -> &'a NormalizedFilesystemRequest {
        self.request
    }

    /// Planned startup shard geometry.
    #[must_use]
    pub fn geometry(&self) -> &InitialShardGeometry {
        &self.geometry
    }

    /// Typed payload to encode into shard metadata.
    #[must_use]
    pub fn payload(&self) -> &'a FilesystemShardPayload {
        self.payload
    }
}

/// Errors from [`setup_filesystem_run`].
///
/// # Security note
///
/// Error messages include filesystem paths for operator diagnostics.
/// Callers that surface errors to untrusted consumers must redact
/// path details before returning.
#[derive(thiserror::Error)]
pub enum FilesystemRunSetupError {
    /// The typed payload mode disagrees with the normalized request.
    #[error(
        "filesystem payload mode '{payload}' does not match normalized request mode '{request}'"
    )]
    PayloadModeMismatch {
        request: FilesystemSourceMode,
        payload: FilesystemSourceMode,
    },
    /// The typed payload root disagrees with the normalized request.
    #[error("filesystem payload root does not match normalized request root")]
    PayloadRootMismatch {
        /// Canonical root from the normalized request.
        request_root: PathBuf,
        /// Canonical root carried by the payload.
        payload_root: PathBuf,
    },
    /// Payload encoding failed before manifest construction.
    #[error("filesystem payload encode failed: {0}")]
    PayloadEncode(#[source] FilesystemShardPayloadEncodeError),
    /// Manifest lowering or validation failed before coordinator mutation.
    #[error("filesystem manifest build failed: {0}")]
    ManifestBuild(#[source] PreallocShardBuilderError),
    /// Run creation or registration failed in the coordination backend.
    #[error("filesystem run setup failed: {0}")]
    CreateRun(#[source] CreateRunError),
}

// Custom Debug: redacts PathBuf fields in PayloadRootMismatch to prevent
// filesystem path leakage through error chains.
impl fmt::Debug for FilesystemRunSetupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadModeMismatch { request, payload } => f
                .debug_struct("PayloadModeMismatch")
                .field("request", request)
                .field("payload", payload)
                .finish(),
            Self::PayloadRootMismatch { .. } => f
                .debug_struct("PayloadRootMismatch")
                .field("request_root", &"<redacted>")
                .field("payload_root", &"<redacted>")
                .finish(),
            Self::PayloadEncode(err) => f.debug_tuple("PayloadEncode").field(err).finish(),
            Self::ManifestBuild(err) => f.debug_tuple("ManifestBuild").field(err).finish(),
            Self::CreateRun(err) => f.debug_tuple("CreateRun").field(err).finish(),
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
    let (start, end) = lower_geometry_bounds(geometry);

    // The arena makes three individual ByteSlab allocations: start bound,
    // end bound, and encoded shard metadata.  ByteSlab rounds each to
    // `max(n, 16).next_power_of_two()`, so the capacity must account for
    // per-allocation rounding, not just the raw byte total.
    //
    // The metadata envelope wraps the encoded payload in a ShardMetadata
    // frame: 4-byte hint-length prefix + 1-byte Range hint + payload bytes.
    let metadata_raw = SHARD_METADATA_ENVELOPE_OVERHEAD + encoded_payload.len();
    let byte_capacity = slab_alloc_bound(start.len())
        + slab_alloc_bound(end.len())
        + slab_alloc_bound(metadata_raw);
    let mut arena = ShardArena::with_capacity(1, byte_capacity);
    let mut builder = PreallocShardBuilder::<1>::new(&mut arena, 1)?;
    // Builder-assigned ShardId is not needed here: authoritative shard IDs
    // are available via RunRecord::root_shards() after registration.
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

/// Verify that the payload's mode and canonical root agree with the request.
///
/// This check runs before any coordinator mutation so that a mismatched
/// request/payload pair never leaves a half-created run in the coordinator.
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
        return Err(FilesystemRunSetupError::PayloadRootMismatch {
            request_root: request.canonical_root().to_path_buf(),
            payload_root: payload.canonical_root().to_path_buf(),
        });
    }
    Ok(())
}

/// Replace unbounded geometry endpoints with the keyspace sentinels.
///
/// Manifest registration requires finite byte-slice bounds, so unbounded
/// start maps to [`FILESYSTEM_KEYSPACE_FLOOR`] and unbounded end maps to
/// [`FILESYSTEM_KEYSPACE_CEILING`].  Bounded endpoints pass through as-is.
fn lower_geometry_bounds(geometry: &InitialShardGeometry) -> (&[u8], &[u8]) {
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

/// ShardMetadata frame overhead: 4-byte hint-length prefix + 1-byte Range hint.
pub(crate) const SHARD_METADATA_ENVELOPE_OVERHEAD: usize = 5;

/// Upper-bound a single ByteSlab allocation.
///
/// ByteSlab rounds each allocation to `max(n, 16).next_power_of_two()`.
/// Zero-length inputs allocate zero bytes.
#[inline]
pub(crate) fn slab_alloc_bound(n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    n.max(16).next_power_of_two()
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
    use gossip_frontier::decode_connector_extra;
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

    fn normalize_single_file(path: &Path, config: RunConfig) -> NormalizedFilesystemRequest {
        FilesystemRequest::single_file(path, config)
            .normalize()
            .expect("single-file request should normalize")
    }

    fn assert_claim_preserves_request_semantics(
        coordinator: &mut InMemoryCoordinator,
        request: &NormalizedFilesystemRequest,
        expected_shard: ShardId,
    ) {
        let mut scratch = AcquireScratch::new();
        let claimed = coordinator
            .claim_next_available(now(2), tenant(), run(), worker(), &mut scratch)
            .expect("registered root shard should be claimable");

        assert_eq!(claimed.lease.shard(), expected_shard);
        assert_eq!(
            claimed.snapshot.spec().key_range_start(),
            FILESYSTEM_KEYSPACE_FLOOR
        );
        assert_eq!(
            claimed.snapshot.spec().key_range_end(),
            FILESYSTEM_KEYSPACE_CEILING
        );

        let connector_extra = decode_connector_extra(claimed.snapshot.spec())
            .expect("claim snapshot should decode shard metadata");
        let decoded = FilesystemShardPayload::decode(connector_extra)
            .expect("claim snapshot should round-trip filesystem payload");
        assert_eq!(decoded.mode(), request.mode());
        assert_eq!(decoded.canonical_root(), request.canonical_root());

        let metadata = fs::metadata(decoded.canonical_root())
            .expect("decoded canonical root should remain accessible");
        match decoded.mode() {
            FilesystemSourceMode::SingleFile => {
                assert!(
                    metadata.is_file(),
                    "single-file payload must hydrate to a file"
                )
            }
            FilesystemSourceMode::DirectoryRoot => {
                assert!(
                    metadata.is_dir(),
                    "directory-root payload must hydrate to a directory"
                )
            }
        }
    }

    #[test]
    fn setup_filesystem_run_directory_claim_round_trips_payload_and_bounds() {
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
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
            OpId::from_raw(11),
        )
        .expect("run setup should succeed");

        assert!(outcome.is_executed());
        let result = outcome.into_inner();
        assert_eq!(result.run().status(), RunStatus::Active);
        assert_eq!(result.root_shards().len(), 1);
        assert_claim_preserves_request_semantics(
            &mut coordinator,
            &request,
            result.root_shards()[0],
        );
    }

    #[test]
    fn setup_filesystem_run_single_file_claim_round_trips_payload_and_bounds() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let request = normalize_single_file(&file_path, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let outcome = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
            OpId::from_raw(20),
        )
        .expect("single-file run setup should succeed");

        assert!(outcome.is_executed());
        let result = outcome.into_inner();
        assert_eq!(result.run().status(), RunStatus::Active);
        assert_eq!(result.root_shards().len(), 1);
        assert_claim_preserves_request_semantics(
            &mut coordinator,
            &request,
            result.root_shards()[0],
        );
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
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
            OpId::from_raw(12),
        )
        .expect("first setup should succeed")
        .into_inner();

        let replay = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
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
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
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
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
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
            FilesystemRunSetupInput::new(&request_a, plan_a.initial_shard().clone(), &payload_a),
            OpId::from_raw(15),
        )
        .expect("first setup should succeed");

        let err = setup_filesystem_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request_b, plan_b.initial_shard().clone(), &payload_b),
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
            FilesystemRunSetupInput::new(
                &request,
                plan.initial_shard().clone(),
                &mismatched_payload,
            ),
            OpId::from_raw(16),
        )
        .expect_err("request/payload mismatch should be rejected before mutation");

        assert!(matches!(
            err,
            FilesystemRunSetupError::PayloadRootMismatch { .. }
        ));
        let mut scratch = AcquireScratch::new();
        let claim =
            coordinator.claim_next_available(now(2), tenant(), run(), worker(), &mut scratch);
        assert!(matches!(claim, Err(ClaimError::RunNotFound)));
    }

    #[test]
    fn setup_filesystem_run_succeeds_with_short_directory_name() {
        let dir = tempdir().expect("tempdir");
        // Use a single-char directory name so the encoded payload is short.
        // This exercises the arena capacity path for small payloads where the
        // ShardMetadata encoding overhead could push the allocation into a
        // larger slab bucket.
        let scan_root = dir.path().join("r");
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
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
            OpId::from_raw(17),
        )
        .expect("short-name setup should succeed");

        assert!(outcome.is_executed());
        assert_eq!(outcome.into_inner().run().status(), RunStatus::Active);
    }

    #[test]
    fn setup_filesystem_run_rejects_payload_mode_mismatch() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("scan-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        // Build a payload with the correct root but wrong mode.
        let mismatched_payload =
            FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, request.canonical_root());
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let err = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(
                &request,
                plan.initial_shard().clone(),
                &mismatched_payload,
            ),
            OpId::from_raw(18),
        )
        .expect_err("mode mismatch should be rejected before mutation");

        assert!(matches!(
            err,
            FilesystemRunSetupError::PayloadModeMismatch {
                request: FilesystemSourceMode::DirectoryRoot,
                payload: FilesystemSourceMode::SingleFile,
            }
        ));
        // Verify no coordinator state was left behind.
        let mut scratch = AcquireScratch::new();
        let claim =
            coordinator.claim_next_available(now(2), tenant(), run(), worker(), &mut scratch);
        assert!(matches!(claim, Err(ClaimError::RunNotFound)));
    }

    #[test]
    fn debug_redacts_setup_input_path() {
        let dir = tempdir().expect("tempdir");
        let scan_root = dir.path().join("secret-root");
        fs::create_dir(&scan_root).expect("create root");
        let request = normalize_directory(&scan_root, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let input = FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload);

        let rendered = format!("{input:?}");

        assert!(
            rendered.contains("<redacted>"),
            "Debug output must include redaction placeholder: {rendered}"
        );
        assert!(
            !rendered.contains("secret-root"),
            "Debug output must not leak the directory name: {rendered}"
        );
    }

    #[test]
    fn setup_succeeds_with_deep_directory_path() {
        // Construct a path whose canonical form exceeds 130 characters,
        // past the threshold where metadata bytes (6 + path.len()) cross a
        // power-of-2 boundary and ByteSlab rounds to a much larger bucket.
        let dir = tempdir().expect("tempdir");
        let mut deep = dir.path().to_path_buf();
        for i in 0..20 {
            deep = deep.join(format!("level_{i:03}"));
        }
        fs::create_dir_all(&deep).expect("create deep tree");
        let canonical = deep.canonicalize().expect("canonicalize");
        assert!(
            canonical.to_str().unwrap().len() >= 130,
            "canonical path too short to exercise rounding: {}",
            canonical.display()
        );
        let request = normalize_directory(&canonical, run_config());
        let plan = plan_filesystem_initial_shards(request.clone());
        let payload = plan.shard_payload();
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let outcome = setup_filesystem_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            FilesystemRunSetupInput::new(&request, plan.initial_shard().clone(), &payload),
            OpId::from_raw(30),
        )
        .expect("deep-path run setup must not fail with SlabFull");

        assert!(outcome.is_executed());
        let result = outcome.into_inner();
        assert_eq!(result.run().status(), RunStatus::Active);
    }

    #[test]
    fn debug_redacts_root_mismatch_error_paths() {
        let err = FilesystemRunSetupError::PayloadRootMismatch {
            request_root: PathBuf::from("/sensitive/request"),
            payload_root: PathBuf::from("/sensitive/payload"),
        };
        let rendered = format!("{err:?}");

        assert!(
            rendered.contains("<redacted>"),
            "Debug output must include redaction placeholder: {rendered}"
        );
        assert!(
            !rendered.contains("/sensitive/request"),
            "Debug output must not leak the request root: {rendered}"
        );
        assert!(
            !rendered.contains("/sensitive/payload"),
            "Debug output must not leak the payload root: {rendered}"
        );
    }

    #[test]
    fn all_error_variants_display_non_empty() {
        let variants: Vec<FilesystemRunSetupError> = vec![
            FilesystemRunSetupError::PayloadModeMismatch {
                request: FilesystemSourceMode::DirectoryRoot,
                payload: FilesystemSourceMode::SingleFile,
            },
            FilesystemRunSetupError::PayloadRootMismatch {
                request_root: PathBuf::from("/a"),
                payload_root: PathBuf::from("/b"),
            },
            FilesystemRunSetupError::PayloadEncode(FilesystemShardPayloadEncodeError::EmptyPath {
                mode: FilesystemSourceMode::DirectoryRoot,
            }),
            FilesystemRunSetupError::ManifestBuild(PreallocShardBuilderError::EntryLimitZero),
            FilesystemRunSetupError::CreateRun(CreateRunError::RunAlreadyExists { run: run() }),
        ];
        for err in &variants {
            let display = format!("{err}");
            assert!(!display.is_empty(), "Display must be non-empty for {err:?}");
        }
    }

    #[test]
    fn error_source_chaining() {
        use std::error::Error;

        // Wrapping variants must chain to their inner error.
        let encode_err =
            FilesystemRunSetupError::PayloadEncode(FilesystemShardPayloadEncodeError::EmptyPath {
                mode: FilesystemSourceMode::DirectoryRoot,
            });
        assert!(
            encode_err.source().is_some(),
            "PayloadEncode must chain source"
        );

        let build_err =
            FilesystemRunSetupError::ManifestBuild(PreallocShardBuilderError::EntryLimitZero);
        assert!(
            build_err.source().is_some(),
            "ManifestBuild must chain source"
        );

        let create_err =
            FilesystemRunSetupError::CreateRun(CreateRunError::RunAlreadyExists { run: run() });
        assert!(create_err.source().is_some(), "CreateRun must chain source");

        // Leaf variants must not have a source.
        let mode_err = FilesystemRunSetupError::PayloadModeMismatch {
            request: FilesystemSourceMode::DirectoryRoot,
            payload: FilesystemSourceMode::SingleFile,
        };
        assert!(
            mode_err.source().is_none(),
            "PayloadModeMismatch must not chain source"
        );

        let root_err = FilesystemRunSetupError::PayloadRootMismatch {
            request_root: PathBuf::from("/a"),
            payload_root: PathBuf::from("/b"),
        };
        assert!(
            root_err.source().is_none(),
            "PayloadRootMismatch must not chain source"
        );
    }

    #[test]
    fn display_redacts_root_mismatch_error_paths() {
        let err = FilesystemRunSetupError::PayloadRootMismatch {
            request_root: PathBuf::from("/sensitive/request"),
            payload_root: PathBuf::from("/sensitive/payload"),
        };
        let rendered = format!("{err}");

        assert!(
            !rendered.contains("/sensitive/request"),
            "Display output must not leak the request root: {rendered}"
        );
        assert!(
            !rendered.contains("/sensitive/payload"),
            "Display output must not leak the payload root: {rendered}"
        );
    }
}
