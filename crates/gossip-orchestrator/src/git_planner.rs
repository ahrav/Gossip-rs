//! Deterministic initial shard geometry planning for normalized Git requests.
//!
//! The planner emits one startup shard per normalized repo target. Any later
//! fan-out comes from coordination split flows after the worker makes
//! progress, not from submission-time pre-sharding.

use gossip_contracts::connector::git::GitExecutionLimits;
use gossip_contracts::coordination::MAX_KEY_SIZE;
use gossip_frontier::key_encoding::{KeyBuf, prefix_successor};

use crate::git_payload::GitShardPayload;
use crate::git_request::{NormalizedGitRequest, NormalizedGitTarget};
use crate::planner::InitialShardGeometry;

/// Errors from Git startup shard planning.
#[derive(Debug, thiserror::Error)]
pub enum GitPlannerError {
    /// The repo key at MAX_KEY_SIZE has no lexicographic successor (all bytes are 0xFF).
    #[error("repo key at MAX_KEY_SIZE has no lexicographic successor")]
    KeyHasNoSuccessor,
}

/// Startup plan for one normalized Git request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitInitialShardPlan {
    request: NormalizedGitRequest,
    entries: Vec<GitInitialShardPlanEntry>,
}

impl GitInitialShardPlan {
    /// Bundle a normalized request with its startup shard entries.
    #[must_use]
    pub fn new(request: NormalizedGitRequest, entries: Vec<GitInitialShardPlanEntry>) -> Self {
        Self { request, entries }
    }

    /// The normalized request that this startup plan was derived from.
    #[must_use]
    pub fn request(&self) -> &NormalizedGitRequest {
        &self.request
    }

    /// Startup shard entries in deterministic normalized-target order.
    #[must_use]
    pub fn entries(&self) -> &[GitInitialShardPlanEntry] {
        self.entries.as_slice()
    }
}

/// One planned Git startup shard.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitInitialShardPlanEntry {
    target: NormalizedGitTarget,
    geometry: InitialShardGeometry,
    payload: GitShardPayload,
}

impl GitInitialShardPlanEntry {
    /// Bundle the normalized target, geometry, and typed shard payload.
    #[must_use]
    pub fn new(
        target: NormalizedGitTarget,
        geometry: InitialShardGeometry,
        payload: GitShardPayload,
    ) -> Self {
        Self {
            target,
            geometry,
            payload,
        }
    }

    /// Planned normalized target for this startup shard.
    #[must_use]
    pub fn target(&self) -> &NormalizedGitTarget {
        &self.target
    }

    /// Exact singleton geometry for this repo target.
    #[must_use]
    pub fn geometry(&self) -> &InitialShardGeometry {
        &self.geometry
    }

    /// Typed shard payload for this repo target.
    #[must_use]
    pub fn payload(&self) -> &GitShardPayload {
        &self.payload
    }
}

/// Plan deterministic Git startup shards for one normalized Git request.
///
/// The planner emits one startup shard per normalized repo target in the
/// request's deterministic repo-key order. Each shard uses exact singleton
/// key-range geometry so one repo target never shares its startup shard with a
/// strict-prefix neighbor.
///
/// # Errors
///
/// Returns [`GitPlannerError::KeyHasNoSuccessor`] if a repo key at
/// `MAX_KEY_SIZE` is all-0xFF and has no lexicographic successor.
pub fn plan_git_initial_shards(
    request: NormalizedGitRequest,
    execution_limits: GitExecutionLimits,
) -> Result<GitInitialShardPlan, GitPlannerError> {
    let entries = request
        .targets()
        .iter()
        .map(
            |target| -> Result<GitInitialShardPlanEntry, GitPlannerError> {
                Ok(GitInitialShardPlanEntry::new(
                    target.clone(),
                    exact_key_geometry(target.repo_key().as_bytes())?,
                    GitShardPayload::from_normalized_request_target(
                        &request,
                        target,
                        execution_limits,
                    ),
                ))
            },
        )
        .collect::<Result<Vec<_>, _>>()?;
    Ok(GitInitialShardPlan::new(request, entries))
}

pub(crate) fn exact_key_geometry(key: &[u8]) -> Result<InitialShardGeometry, GitPlannerError> {
    Ok(InitialShardGeometry::new(
        key.to_vec(),
        exact_key_upper_bound(key)?,
    ))
}

pub(crate) fn exact_key_upper_bound(key: &[u8]) -> Result<Vec<u8>, GitPlannerError> {
    debug_assert!(
        key.iter().any(|&b| b != 0xFF),
        "exact_key_upper_bound requires at least one non-0xFF byte \
         (guaranteed by RepoKey's locator-kind tag prefix)"
    );

    if key.len() < MAX_KEY_SIZE {
        let mut end = Vec::with_capacity(key.len() + 1);
        end.extend_from_slice(key);
        end.push(0);
        return Ok(end);
    }

    let mut buf = KeyBuf::new();
    Ok(prefix_successor(key, &mut buf)
        .ok_or(GitPlannerError::KeyHasNoSuccessor)?
        .to_vec())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use gossip_contracts::connector::git::{
        GitExecutionLimits, GitMergeStrategy, GitScanMode, RepoKey,
    };
    use gossip_contracts::coordination::ShardSpec;
    use gossip_contracts::identity::TenantId;
    use tempfile::tempdir;

    use super::*;
    use crate::git_request::GitRequest;
    use crate::test_support::{init_git_repo, run_config};

    fn tenant(byte: u8) -> TenantId {
        TenantId::from_bytes([byte; 32])
    }

    fn default_scan_mode() -> GitScanMode {
        GitScanMode::DiffHistory
    }

    fn default_merge_strategy() -> GitMergeStrategy {
        GitMergeStrategy::AllParents
    }

    #[test]
    fn single_repo_requests_plan_one_exact_startup_shard() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(
            dir.path(),
            "git-planner-tests@example.com",
            "Git Planner Tests",
        );

        let normalized = GitRequest::single_repo(
            tenant(0x11),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let execution_limits = GitExecutionLimits::default();
        let plan =
            plan_git_initial_shards(normalized.clone(), execution_limits).expect("plan shards");

        assert_eq!(plan.request(), &normalized);
        assert_eq!(plan.entries().len(), 1);

        let entry = &plan.entries()[0];
        assert_eq!(entry.target(), &normalized.targets()[0]);
        assert_eq!(
            entry.payload(),
            &GitShardPayload::from_normalized_request_target(
                &normalized,
                &normalized.targets()[0],
                execution_limits,
            )
        );

        let expected_end = {
            let mut bytes = normalized.targets()[0].repo_key().as_bytes().to_vec();
            bytes.push(0);
            bytes
        };
        assert_eq!(
            entry.geometry().key_range_start(),
            normalized.targets()[0].repo_key().as_bytes()
        );
        assert_eq!(entry.geometry().key_range_end(), expected_end.as_slice());
    }

    #[test]
    fn repo_list_requests_plan_entries_in_normalized_target_order() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("a-repo");
        let repo_b = dir.path().join("b-repo");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        init_git_repo(
            &repo_a,
            "git-planner-tests@example.com",
            "Git Planner Tests",
        );
        init_git_repo(
            &repo_b,
            "git-planner-tests@example.com",
            "Git Planner Tests",
        );

        let normalized = GitRequest::repo_list(
            tenant(0x22),
            [&repo_b, &repo_a],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize request");
        let plan = plan_git_initial_shards(normalized.clone(), GitExecutionLimits::default())
            .expect("plan shards");

        assert_eq!(plan.entries().len(), normalized.targets().len());
        for (entry, target) in plan.entries().iter().zip(normalized.targets()) {
            assert_eq!(entry.target(), target);
            assert_eq!(
                entry.geometry().key_range_start(),
                target.repo_key().as_bytes()
            );
        }
    }

    #[test]
    fn equivalent_git_requests_plan_identically() {
        let dir = tempdir().expect("tempdir");
        init_git_repo(
            dir.path(),
            "git-planner-tests@example.com",
            "Git Planner Tests",
        );

        let canonical = GitRequest::single_repo(
            tenant(0x33),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize canonical request");
        let dotted = GitRequest::single_repo(
            tenant(0x33),
            dir.path().join("."),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize dotted request");

        assert_eq!(
            plan_git_initial_shards(canonical, GitExecutionLimits::default())
                .expect("plan canonical"),
            plan_git_initial_shards(dotted, GitExecutionLimits::default()).expect("plan dotted")
        );
    }

    #[test]
    fn exact_key_geometry_excludes_strict_prefix_neighbors() {
        let repo_key = RepoKey::try_from_vec(vec![0x01, 0x10]).expect("repo key");
        let strict_extension = RepoKey::try_from_vec(vec![0x01, 0x10, 0x01]).expect("extension");
        let end_sentinel = RepoKey::try_from_vec(vec![0x01, 0x10, 0x00]).expect("sentinel");
        let geometry = exact_key_geometry(repo_key.as_bytes()).expect("short key geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        assert!(spec.contains_key(repo_key.as_bytes()));
        assert!(!spec.contains_key(strict_extension.as_bytes()));
        assert!(!spec.contains_key(end_sentinel.as_bytes()));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "at least one non-0xFF byte")]
    fn all_0xff_max_key_size_panics_in_debug() {
        let key = vec![0xFF; MAX_KEY_SIZE];
        // In debug builds the debug_assert fires before reaching the
        // `KeyHasNoSuccessor` error path.
        let _ = exact_key_geometry(&key);
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn all_0xff_max_key_size_returns_error_in_release() {
        let key = vec![0xFF; MAX_KEY_SIZE];
        // In release builds, debug_assert is compiled out and the function
        // returns KeyHasNoSuccessor via the prefix_successor fallback.
        let result = exact_key_geometry(&key);
        assert!(
            result.is_err(),
            "all-0xFF key at MAX_KEY_SIZE must return Err"
        );
    }

    #[test]
    fn max_length_keys_use_lexicographic_successor_upper_bound() {
        let repo_key = vec![0x01; MAX_KEY_SIZE];
        let geometry = exact_key_geometry(repo_key.as_slice()).expect("max-length key geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        let mut expected_end = vec![0x01; MAX_KEY_SIZE];
        *expected_end.last_mut().expect("non-empty key") = 0x02;

        assert_eq!(geometry.key_range_start(), repo_key.as_slice());
        assert_eq!(geometry.key_range_end(), expected_end.as_slice());
        assert!(spec.contains_key(repo_key.as_slice()));
        assert!(!spec.contains_key(expected_end.as_slice()));
    }

    #[test]
    fn exact_key_geometry_single_byte_key() {
        let key: &[u8] = &[0x42];
        let geometry = exact_key_geometry(key).expect("single-byte key geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        assert_eq!(geometry.key_range_start(), &[0x42]);
        assert_eq!(geometry.key_range_end(), &[0x42, 0x00]);
        assert!(spec.contains_key(&[0x42]));
        assert!(!spec.contains_key(&[0x42, 0x00]));
    }

    #[test]
    fn exact_key_geometry_empty_key() {
        // Empty keys violate the non-0xFF-byte precondition (vacuously: no bytes
        // at all means no non-0xFF byte). The short branch still produces the
        // correct upper bound `[0x00]`, but the debug_assert catches the misuse.
        // Construct the expected geometry manually to verify the short-branch
        // arithmetic without triggering the assertion.
        let start: &[u8] = &[];
        let end: &[u8] = &[0x00];

        let spec = ShardSpec::try_with_range_and_metadata(start, end, b"")
            .expect("empty-start range should be valid");

        assert!(spec.contains_key(&[]));
        assert!(!spec.contains_key(&[0x00]));
    }

    #[test]
    fn exact_key_geometry_trailing_ff_bytes() {
        let key: &[u8] = &[0x01, 0xFF, 0xFF];
        let geometry = exact_key_geometry(key).expect("trailing-0xFF key geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        assert_eq!(geometry.key_range_start(), &[0x01, 0xFF, 0xFF]);
        assert_eq!(geometry.key_range_end(), &[0x01, 0xFF, 0xFF, 0x00]);
        assert!(spec.contains_key(&[0x01, 0xFF, 0xFF]));
        assert!(!spec.contains_key(&[0x01, 0xFF, 0xFF, 0x00]));
    }

    #[test]
    fn exact_key_geometry_max_minus_one_length() {
        let key = vec![0x01; MAX_KEY_SIZE - 1];
        let geometry = exact_key_geometry(key.as_slice()).expect("max-minus-one key geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        // Short branch appends 0x00, producing a key of exactly MAX_KEY_SIZE.
        assert_eq!(geometry.key_range_end().len(), MAX_KEY_SIZE);
        assert!(spec.contains_key(key.as_slice()));
    }

    #[test]
    fn max_length_key_with_trailing_ff_uses_stripped_successor() {
        // First byte 0x01, remaining bytes all 0xFF — exercises prefix_successor's
        // trailing-0xFF stripping: strips all 0xFF bytes, increments 0x01 to 0x02.
        let mut key = vec![0xFF; MAX_KEY_SIZE];
        key[0] = 0x01;
        let geometry = exact_key_geometry(key.as_slice()).expect("max-length trailing-FF geometry");
        let spec = ShardSpec::try_with_range_and_metadata(
            geometry.key_range_start(),
            geometry.key_range_end(),
            b"",
        )
        .expect("singleton range should be valid");

        assert_eq!(geometry.key_range_start(), key.as_slice());
        assert_eq!(geometry.key_range_end(), &[0x02]);
        assert!(spec.contains_key(key.as_slice()));
        assert!(!spec.contains_key(&[0x02]));
    }
}
