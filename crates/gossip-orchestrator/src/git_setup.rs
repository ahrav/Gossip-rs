//! Coordination-backed Git run setup.
//!
//! This module is the final control-plane lowering step for Git submissions:
//! it takes the outputs of request normalization, Git startup planning, and
//! typed payload encoding, then materializes the validated initial manifest
//! that `register_shards` requires.
//!
//! The helper keeps the existing coordination lifecycle intact:
//!
//! 1. Validate that the planned targets, geometries, and payloads agree with
//!    the normalized request before any coordinator mutation.
//! 2. Encode the typed Git payloads into connector-extra bytes.
//! 3. Lower the planned singleton geometries into manifest rows in the same
//!    deterministic target order.
//! 4. Build a validated manifest with
//!    [`gossip_frontier::builder::PreallocShardBuilder`].
//! 5. Call [`gossip_coordination::RunManagement::create_run_with_shards`].
//!
//! The returned [`IdempotentOutcome`] preserves whether this was the first
//! execution or a safe replay after an earlier partial attempt.

use gossip_coordination::{
    CreateRunError, IdempotentOutcome, LogicalTime, OpId, RunId, RunManagement, RunRecord,
    RunStatus, ShardArena, ShardId, TenantId,
};
use gossip_frontier::builder::{PreallocShardBuilder, PreallocShardBuilderError};

use crate::git_payload::{GitShardPayload, GitShardPayloadEncodeError};
use crate::git_planner::{GitInitialShardPlan, exact_key_geometry};
use crate::planner::InitialShardGeometry;
use crate::setup::slab_alloc_bound;

const GIT_SHARD_METADATA_OVERHEAD: usize = 5;
const MAX_GIT_STARTUP_MANIFEST_SHARDS: usize = 1024;

/// Result of a successful Git run setup.
///
/// The run record is coordination-authoritative and owns the root shard list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRunSetupResult {
    run: RunRecord,
}

impl GitRunSetupResult {
    fn from_run(run: RunRecord) -> Self {
        debug_assert!(
            run.status() == RunStatus::Active,
            "GitRunSetupResult requires Active status, got {:?}",
            run.status()
        );
        debug_assert!(
            !run.root_shards().is_empty(),
            "GitRunSetupResult requires non-empty root shards"
        );
        Self { run }
    }

    /// Coordination-authoritative run record after setup.
    #[must_use]
    pub fn run(&self) -> &RunRecord {
        &self.run
    }

    /// Registered root shard IDs in planned target order.
    #[must_use]
    pub fn root_shards(&self) -> &[ShardId] {
        self.run.root_shards()
    }
}

/// Borrowed input for Git run setup.
#[derive(Clone, Copy, Debug)]
pub struct GitRunSetupInput<'a> {
    plan: &'a GitInitialShardPlan,
}

impl<'a> GitRunSetupInput<'a> {
    /// Bundle a Git startup plan for coordinator-backed registration.
    #[must_use]
    pub fn new(plan: &'a GitInitialShardPlan) -> Self {
        Self { plan }
    }

    /// Git startup plan to register.
    #[must_use]
    pub fn plan(&self) -> &'a GitInitialShardPlan {
        self.plan
    }
}

/// Errors from [`setup_git_run`].
#[derive(Debug, thiserror::Error)]
pub enum GitRunSetupError {
    /// The explicit coordinator tenant must match the normalized request scope.
    #[error("git request tenant does not match the setup tenant")]
    TenantMismatch { request: TenantId, tenant: TenantId },
    /// A Git startup plan must contain at least one repo target.
    #[error("git startup plan must contain at least one repo target")]
    EmptyPlan,
    /// Planned shard count must match normalized target count.
    #[error(
        "git startup plan entry count {planned} does not match normalized target count {request}"
    )]
    TargetCountMismatch { request: usize, planned: usize },
    /// Planned target order must match normalized target order exactly.
    #[error("git startup entry {target_index} does not match the normalized request target")]
    TargetMismatch { target_index: usize },
    /// Payload identity or selection does not match the planned target.
    #[error("git startup entry {target_index} payload does not match the planned target")]
    PayloadTargetMismatch { target_index: usize },
    /// Payload request-scoped settings do not match the normalized request.
    #[error("git startup entry {target_index} payload does not match the normalized request")]
    PayloadRequestMismatch { target_index: usize },
    /// Geometry must isolate the planned repo key exactly.
    #[error("git startup entry {target_index} geometry does not isolate the planned repo key")]
    GeometryMismatch { target_index: usize },
    /// Payload encoding failed before manifest construction.
    #[error("git payload encode failed: {0}")]
    PayloadEncode(#[source] GitShardPayloadEncodeError),
    /// Manifest lowering or validation failed before coordinator mutation.
    #[error("git manifest build failed: {0}")]
    ManifestBuild(#[source] PreallocShardBuilderError),
    /// Run creation or registration failed in the coordination backend.
    #[error("git run setup failed: {0}")]
    CreateRun(#[source] CreateRunError),
}

impl From<GitShardPayloadEncodeError> for GitRunSetupError {
    fn from(err: GitShardPayloadEncodeError) -> Self {
        Self::PayloadEncode(err)
    }
}

impl From<PreallocShardBuilderError> for GitRunSetupError {
    fn from(err: PreallocShardBuilderError) -> Self {
        Self::ManifestBuild(err)
    }
}

impl From<CreateRunError> for GitRunSetupError {
    fn from(err: CreateRunError) -> Self {
        Self::CreateRun(err)
    }
}

/// Create a Git run and register its startup shard manifest.
///
/// The helper accepts the output of the earlier Git orchestrator seams
/// directly: a normalized request plus its planned singleton shard entries and
/// typed per-target payloads.
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
/// # Errors
///
/// Returns [`GitRunSetupError`] when the plan and request disagree, payload
/// encoding fails, manifest lowering fails, or the coordination lifecycle
/// rejects the run creation or registration attempt.
pub fn setup_git_run<M>(
    management: &mut M,
    now: LogicalTime,
    tenant: TenantId,
    run: RunId,
    input: GitRunSetupInput<'_>,
    op_id: OpId,
) -> Result<IdempotentOutcome<GitRunSetupResult>, GitRunSetupError>
where
    M: RunManagement,
{
    let plan = input.plan();
    let request = plan.request();
    validate_plan(tenant, plan)?;

    let entries = plan.entries();
    let mut byte_capacity = 0usize;
    for entry in entries {
        let metadata_raw = GIT_SHARD_METADATA_OVERHEAD + entry.payload().encoded_len()?;
        byte_capacity += slab_alloc_bound(entry.geometry().key_range_start().len());
        byte_capacity += slab_alloc_bound(entry.geometry().key_range_end().len());
        byte_capacity += slab_alloc_bound(metadata_raw);
    }

    let mut arena = ShardArena::with_capacity(entries.len(), byte_capacity);
    let mut builder =
        PreallocShardBuilder::<MAX_GIT_STARTUP_MANIFEST_SHARDS>::new(&mut arena, entries.len())?;
    for entry in entries {
        let encoded_payload = entry.payload().encode()?;
        let _ = builder.add_range(
            entry.geometry().key_range_start(),
            entry.geometry().key_range_end(),
            &encoded_payload,
        )?;
    }
    let manifest = builder.build_inputs()?;

    let outcome = management.create_run_with_shards(
        now,
        tenant,
        run,
        request.run_config(),
        manifest.as_slice(),
        op_id,
    )?;

    Ok(outcome.map(GitRunSetupResult::from_run))
}

fn validate_plan(tenant: TenantId, plan: &GitInitialShardPlan) -> Result<(), GitRunSetupError> {
    let request = plan.request();
    if tenant != request.tenant_id() {
        return Err(GitRunSetupError::TenantMismatch {
            request: request.tenant_id(),
            tenant,
        });
    }

    let entries = plan.entries();
    if entries.is_empty() {
        return Err(GitRunSetupError::EmptyPlan);
    }
    if entries.len() != request.targets().len() {
        return Err(GitRunSetupError::TargetCountMismatch {
            request: request.targets().len(),
            planned: entries.len(),
        });
    }

    for (target_index, (entry, target)) in entries.iter().zip(request.targets()).enumerate() {
        if entry.target() != target {
            return Err(GitRunSetupError::TargetMismatch { target_index });
        }
        validate_payload(target_index, request, target, entry.payload())?;
        validate_geometry(target_index, target.repo_key().as_bytes(), entry.geometry())?;
    }

    Ok(())
}

fn validate_payload(
    target_index: usize,
    request: &crate::git_request::NormalizedGitRequest,
    target: &crate::git_request::NormalizedGitTarget,
    payload: &GitShardPayload,
) -> Result<(), GitRunSetupError> {
    if payload.repo_target() != target.repo_target()
        || payload.repo_id() != target.repo_id()
        || payload.selection() != target.selection()
    {
        return Err(GitRunSetupError::PayloadTargetMismatch { target_index });
    }

    if payload.tenant_id() != request.tenant_id()
        || payload.scan_mode() != request.scan_mode()
        || payload.merge_strategy() != request.merge_strategy()
    {
        return Err(GitRunSetupError::PayloadRequestMismatch { target_index });
    }

    Ok(())
}

fn validate_geometry(
    target_index: usize,
    repo_key: &[u8],
    geometry: &InitialShardGeometry,
) -> Result<(), GitRunSetupError> {
    if geometry != &exact_key_geometry(repo_key) {
        return Err(GitRunSetupError::GeometryMismatch { target_index });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::num::{NonZeroU32, NonZeroUsize};

    use gossip_contracts::connector::git::{
        GitDebugLevel, GitExecutionLimits, GitMergeStrategy, GitScanMode,
    };
    use gossip_coordination::{
        AcquireScratch, ClaimError, CreateRunError, CursorSemantics, InMemoryCoordinator, OpId,
        RegisterShardsError, RunConfig, RunId, RunManagement, RunStatus, ShardClaiming, ShardId,
        TenantId, WorkerId,
    };
    use gossip_frontier::decode_connector_extra;
    use tempfile::tempdir;

    use super::*;
    use crate::git_planner::{GitInitialShardPlanEntry, plan_git_initial_shards};
    use crate::git_request::{GitRequest, NormalizedGitSelection};
    use crate::test_support::{init_git_repo, run_config};

    const LEASE_DURATION_MS: u64 = 30_000;

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn run() -> RunId {
        RunId::from_raw(42)
    }

    fn worker(raw: u64) -> WorkerId {
        WorkerId::from_raw(raw)
    }

    fn now(tick: u64) -> LogicalTime {
        LogicalTime::from_raw(tick)
    }

    fn default_scan_mode() -> GitScanMode {
        GitScanMode::DiffHistory
    }

    fn default_merge_strategy() -> GitMergeStrategy {
        GitMergeStrategy::AllParents
    }

    fn execution_limits() -> GitExecutionLimits {
        GitExecutionLimits::default()
            .with_pack_exec_workers(NonZeroUsize::new(7).expect("non-zero workers"))
            .with_scan_binary(true)
            .with_enrich_identities(true)
            .with_debug_level(GitDebugLevel::Perf)
            .with_tree_delta_cache_mb(NonZeroU32::new(128).expect("non-zero cache"))
            .with_engine_chunk_mb(NonZeroU32::new(64).expect("non-zero chunk"))
    }

    fn different_run_config() -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, 60_000, Some(5))
            .expect("alternate run config")
    }

    #[test]
    fn setup_git_run_registers_claimable_root_shards_in_planned_order() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("a-repo");
        let repo_b = dir.path().join("b-repo");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        init_git_repo(&repo_a, "git-setup-tests@example.com", "Git Setup Tests");
        init_git_repo(&repo_b, "git-setup-tests@example.com", "Git Setup Tests");

        let normalized = GitRequest::repo_list(
            tenant(),
            [&repo_b, &repo_a],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let plan = plan_git_initial_shards(normalized, execution_limits());
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let outcome = setup_git_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(11),
        )
        .expect("run setup should succeed");

        assert!(outcome.is_executed());
        let result = outcome.into_inner();
        assert_eq!(result.run().status(), RunStatus::Active);
        assert_eq!(result.root_shards().len(), plan.entries().len());
        assert_eq!(
            result.root_shards(),
            [ShardId::from_raw(0), ShardId::from_raw(1)].as_slice()
        );

        for (index, entry) in plan.entries().iter().enumerate() {
            let mut scratch = AcquireScratch::new();
            let claimed = coordinator
                .claim_next_available(
                    now(2 + index as u64),
                    tenant(),
                    run(),
                    worker(100 + index as u64),
                    &mut scratch,
                )
                .expect("registered root shard should be claimable");

            assert_eq!(claimed.lease.shard(), result.root_shards()[index]);
            assert_eq!(
                claimed.snapshot.spec().key_range_start(),
                entry.geometry().key_range_start()
            );
            assert_eq!(
                claimed.snapshot.spec().key_range_end(),
                entry.geometry().key_range_end()
            );

            let connector_extra = decode_connector_extra(claimed.snapshot.spec())
                .expect("claim snapshot should decode shard metadata");
            let decoded =
                GitShardPayload::decode(connector_extra).expect("claim snapshot should round-trip");
            assert_eq!(&decoded, entry.payload());
        }
    }

    #[test]
    fn setup_git_run_replays_existing_registration() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), "git-setup-tests@example.com", "Git Setup Tests");

        let plan = plan_git_initial_shards(
            GitRequest::single_repo(
                tenant(),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request"),
            execution_limits(),
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let first = setup_git_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(12),
        )
        .expect("first setup should succeed")
        .into_inner();

        let replay = setup_git_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(12),
        )
        .expect("replayed setup should succeed");

        assert!(replay.is_replay());
        assert_eq!(replay.into_inner().root_shards(), first.root_shards());
    }

    #[test]
    fn setup_git_run_finishes_existing_initializing_run() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), "git-setup-tests@example.com", "Git Setup Tests");

        let plan = plan_git_initial_shards(
            GitRequest::single_repo(
                tenant(),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request"),
            execution_limits(),
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);
        coordinator
            .create_run(now(1), tenant(), run(), plan.request().run_config())
            .expect("pre-create initializing run");

        let outcome = setup_git_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(13),
        )
        .expect("setup should resume from initializing state");

        assert!(outcome.is_executed());
        assert_eq!(outcome.into_inner().run().status(), RunStatus::Active);
    }

    #[test]
    fn setup_git_run_rejects_config_mismatch_for_existing_run() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), "git-setup-tests@example.com", "Git Setup Tests");

        let plan = plan_git_initial_shards(
            GitRequest::single_repo(
                tenant(),
                dir.path(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request"),
            execution_limits(),
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);
        coordinator
            .create_run(now(1), tenant(), run(), different_run_config())
            .expect("pre-create mismatched run");

        let err = setup_git_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(14),
        )
        .expect_err("mismatched config should be rejected");

        assert!(matches!(
            err,
            GitRunSetupError::CreateRun(CreateRunError::ConfigMismatch { .. })
        ));
    }

    #[test]
    fn setup_git_run_rejects_conflicting_registration_payload() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("repo-a");
        let repo_b = dir.path().join("repo-b");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        init_git_repo(&repo_a, "git-setup-tests@example.com", "Git Setup Tests");
        init_git_repo(&repo_b, "git-setup-tests@example.com", "Git Setup Tests");

        let plan_a = plan_git_initial_shards(
            GitRequest::single_repo(
                tenant(),
                &repo_a,
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request a"),
            execution_limits(),
        );
        let plan_b = plan_git_initial_shards(
            GitRequest::single_repo(
                tenant(),
                &repo_b,
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request b"),
            execution_limits(),
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let _ = setup_git_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan_a),
            OpId::from_raw(15),
        )
        .expect("first setup should succeed");

        let err = setup_git_run(
            &mut coordinator,
            now(2),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan_b),
            OpId::from_raw(15),
        )
        .expect_err("conflicting replay payload should be rejected");

        assert!(matches!(
            err,
            GitRunSetupError::CreateRun(CreateRunError::RegisterShardsFailed(
                RegisterShardsError::OpIdConflict(_)
            ))
        ));
    }

    #[test]
    fn setup_git_run_preserves_explicit_commit_selection() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), "git-setup-tests@example.com", "Git Setup Tests");

        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";
        let plan = plan_git_initial_shards(
            GitRequest::repo_with_explicit_commit(
                tenant(),
                dir.path(),
                commit_hex.as_slice(),
                run_config(),
                default_scan_mode(),
                default_merge_strategy(),
            )
            .normalize()
            .expect("normalize request"),
            execution_limits(),
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let result = setup_git_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            GitRunSetupInput::new(&plan),
            OpId::from_raw(16),
        )
        .expect("setup should succeed")
        .into_inner();

        let mut scratch = AcquireScratch::new();
        let claimed = coordinator
            .claim_next_available(now(2), tenant(), run(), worker(200), &mut scratch)
            .expect("registered root shard should be claimable");
        assert_eq!(claimed.lease.shard(), result.root_shards()[0]);

        let connector_extra = decode_connector_extra(claimed.snapshot.spec())
            .expect("claim snapshot should decode shard metadata");
        let decoded = GitShardPayload::decode(connector_extra).expect("decode payload");

        assert!(matches!(
            decoded.selection(),
            NormalizedGitSelection::ExplicitCommit { .. }
        ));
        assert!(decoded.git_selection().is_none());
    }

    #[test]
    fn setup_git_run_rejects_geometry_mismatch_before_mutation() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(dir.path(), "git-setup-tests@example.com", "Git Setup Tests");

        let normalized = GitRequest::single_repo(
            tenant(),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let target = normalized.targets()[0].clone();
        let payload = GitShardPayload::from_normalized_request_target(
            &normalized,
            &target,
            execution_limits(),
        );
        let bad_plan = GitInitialShardPlan::new(
            normalized,
            vec![GitInitialShardPlanEntry::new(
                target,
                InitialShardGeometry::full_connector_keyspace(),
                payload,
            )],
        );
        let mut coordinator = InMemoryCoordinator::new(LEASE_DURATION_MS);

        let err = setup_git_run(
            &mut coordinator,
            now(1),
            tenant(),
            run(),
            GitRunSetupInput::new(&bad_plan),
            OpId::from_raw(17),
        )
        .expect_err("geometry mismatch should be rejected before mutation");

        assert!(matches!(err, GitRunSetupError::GeometryMismatch { .. }));

        let mut scratch = AcquireScratch::new();
        let claim =
            coordinator.claim_next_available(now(2), tenant(), run(), worker(300), &mut scratch);
        assert!(matches!(claim, Err(ClaimError::RunNotFound)));
    }
}
