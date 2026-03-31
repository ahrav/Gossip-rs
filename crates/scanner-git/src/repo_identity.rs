//! Canonical local-repo identity helpers for repo-frontier scheduling.
//!
//! This module ties together three pieces of repo identity:
//! - Git-aware canonical repo-root normalization
//! - stable [`RepoKey`] encoding for outer repo-frontier ordering
//! - stable tenant-scoped `repo_id` derivation for inner persistence namespaces

use std::fmt;
use std::path::{Path, PathBuf};

use gossip_contracts::connector::git::{RepoKey, RepoLocator};
use gossip_contracts::connector::ConnectorInputError;
use gossip_contracts::identity::{domain, domain_hasher, finalize_64, CanonicalBytes, TenantId};

use crate::errors::RepoOpenError;
use crate::repo::{GitRepoPaths, RepoLimits};

/// Canonical repo identity for one normalized local/static repository target.
#[derive(Clone, PartialEq, Eq)]
pub struct NormalizedLocalRepoIdentity {
    canonical_repo_path: PathBuf,
    repo_key: RepoKey,
    repo_locator: RepoLocator,
    repo_id: u64,
}

impl NormalizedLocalRepoIdentity {
    /// Builds identity from an already-canonical repository root path.
    ///
    /// The path must already be canonicalized and must identify the repo root
    /// that should appear in ordering, paging, and persisted namespaces.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError`] when the encoded [`RepoKey`] would
    /// violate the connector key contract.
    pub fn from_canonical_repo_root(
        tenant_id: TenantId,
        canonical_repo_path: PathBuf,
    ) -> Result<Self, ConnectorInputError> {
        let repo_key = RepoKey::for_local_path(canonical_repo_path.as_os_str().as_encoded_bytes())?;
        let repo_locator = RepoLocator::local_path(canonical_repo_path.clone());
        let repo_id = derive_repo_id(tenant_id, &repo_key);
        Ok(Self {
            canonical_repo_path,
            repo_key,
            repo_locator,
            repo_id,
        })
    }

    /// Resolves a repo path and normalizes it into a canonical identity.
    ///
    /// # Errors
    ///
    /// Returns [`RepoIdentityError`] when Git repo resolution fails or when the
    /// encoded repo key would violate the connector key contract.
    pub fn normalize<L: RepoLimits>(
        tenant_id: TenantId,
        repo_path: &Path,
        limits: &L,
    ) -> Result<Self, RepoIdentityError> {
        let repo_paths = GitRepoPaths::resolve::<RepoOpenError, _>(repo_path, limits)?;
        Self::from_canonical_repo_root(tenant_id, repo_paths.canonical_repo_root().to_path_buf())
            .map_err(Into::into)
    }

    /// Returns the canonical repo-root path used by this identity.
    #[inline]
    #[must_use]
    pub fn canonical_repo_path(&self) -> &Path {
        self.canonical_repo_path.as_path()
    }

    /// Returns the canonical repo key used for outer repo-frontier ordering.
    #[inline]
    #[must_use]
    pub fn repo_key(&self) -> &RepoKey {
        &self.repo_key
    }

    /// Returns the canonical locator for this normalized repo target.
    #[inline]
    #[must_use]
    pub fn repo_locator(&self) -> &RepoLocator {
        &self.repo_locator
    }

    /// Returns the tenant-scoped stable `repo_id` for inner persistence keys.
    #[inline]
    #[must_use]
    pub fn repo_id(&self) -> u64 {
        self.repo_id
    }
}

impl fmt::Debug for NormalizedLocalRepoIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NormalizedLocalRepoIdentity")
            .field("repo_key", &self.repo_key)
            .field("repo_locator", &self.repo_locator)
            .field("repo_id", &self.repo_id)
            .finish()
    }
}

/// Normalization and duplicate-detection failures for local repo identities.
#[derive(Debug, thiserror::Error)]
pub enum RepoIdentityError {
    /// Git-aware repo-root resolution failed.
    #[error("git repository normalization failed: {source}")]
    RepoOpen {
        #[from]
        source: RepoOpenError,
    },
    /// The encoded repo key violated the connector key contract.
    #[error("repo identity encoding failed: {source}")]
    ConnectorInput {
        #[from]
        source: ConnectorInputError,
    },
    /// Two inputs normalized to the same canonical repo identity.
    #[error("duplicate normalized repo identity: {repo_key}")]
    DuplicateNormalizedRepoIdentity { repo_key: RepoKey },
}

/// Normalizes a set of repo paths into deterministic repo-key order.
///
/// Duplicate normalized identities are rejected so callers can decide how to
/// handle same-repo re-submission before building a request model on top.
///
/// # Errors
///
/// Returns [`RepoIdentityError`] when any input path fails normalization or
/// when two inputs normalize to the same [`RepoKey`].
pub fn normalize_local_repo_identities<I, P, L>(
    tenant_id: TenantId,
    repo_paths: I,
    limits: &L,
) -> Result<Vec<NormalizedLocalRepoIdentity>, RepoIdentityError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
    L: RepoLimits,
{
    let mut identities = Vec::new();
    for repo_path in repo_paths {
        identities.push(NormalizedLocalRepoIdentity::normalize(
            tenant_id,
            repo_path.as_ref(),
            limits,
        )?);
    }
    identities.sort_unstable_by(|left, right| left.repo_key.cmp(&right.repo_key));
    for pair in identities.windows(2) {
        if pair[0].repo_key == pair[1].repo_key {
            return Err(RepoIdentityError::DuplicateNormalizedRepoIdentity {
                repo_key: pair[0].repo_key.clone(),
            });
        }
    }
    Ok(identities)
}

/// Derives a stable tenant-scoped `repo_id` from a normalized [`RepoKey`].
#[must_use]
pub fn derive_repo_id(tenant_id: TenantId, repo_key: &RepoKey) -> u64 {
    let mut hasher = domain_hasher(domain::GIT_REPO_ID_V1);
    tenant_id.write_canonical(&mut hasher);
    repo_key.as_bytes().write_canonical(&mut hasher);
    finalize_64(&hasher)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::process::Command;

    use gossip_contracts::identity::TenantId;
    use tempfile::tempdir;

    use super::*;
    use crate::limits::RepoOpenLimits;

    fn tenant(byte: u8) -> TenantId {
        TenantId::from_bytes([byte; 32])
    }

    fn run_git_in(dir: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
            dir.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn run_git(args: &[&str]) {
        let output = Command::new("git")
            .args(args)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git command failed: git {}\nstdout:{}\nstderr:{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    fn init_repo(dir: &Path) {
        run_git_in(dir, &["init", "-q"]);
        run_git_in(
            dir,
            &["config", "user.email", "repo-identity-tests@example.com"],
        );
        run_git_in(dir, &["config", "user.name", "Repo Identity Tests"]);
    }

    fn init_committed_repo(dir: &Path) {
        init_repo(dir);
        fs::write(dir.join("fixture.txt"), "fixture").expect("write fixture");
        run_git_in(dir, &["add", "."]);
        run_git_in(dir, &["commit", "-q", "-m", "fixture"]);
    }

    #[test]
    fn equivalent_path_spellings_normalize_to_identical_identity() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let left = NormalizedLocalRepoIdentity::normalize(
            tenant(0x11),
            dir.path(),
            &RepoOpenLimits::default(),
        )
        .expect("normalize repo");
        let right = NormalizedLocalRepoIdentity::normalize(
            tenant(0x11),
            &dir.path().join("."),
            &RepoOpenLimits::default(),
        )
        .expect("normalize dotted repo path");

        assert_eq!(left, right);
        assert_eq!(left.repo_key(), right.repo_key());
        assert_eq!(left.repo_id(), right.repo_id());
    }

    #[test]
    fn linked_worktree_identity_uses_worktree_root() {
        let dir = tempdir().expect("tempdir");
        init_committed_repo(dir.path());
        run_git_in(dir.path(), &["branch", "wt-branch"]);

        let worktree = dir.path().join("worktree");
        run_git_in(
            dir.path(),
            &[
                "worktree",
                "add",
                worktree.to_str().expect("utf-8 worktree path"),
                "wt-branch",
            ],
        );

        let identity = NormalizedLocalRepoIdentity::normalize(
            tenant(0x22),
            &worktree,
            &RepoOpenLimits::default(),
        )
        .expect("normalize linked worktree");
        let expected_root = fs::canonicalize(&worktree).expect("canonical worktree");

        assert_eq!(identity.canonical_repo_path(), expected_root.as_path());
        assert_eq!(
            identity
                .repo_key()
                .local_path_bytes()
                .expect("repo key path"),
            expected_root.as_os_str().as_encoded_bytes()
        );
    }

    #[test]
    fn bare_repo_identity_uses_bare_root() {
        let dir = tempdir().expect("tempdir");
        let bare = dir.path().join("bare.git");
        run_git(&[
            "init",
            "-q",
            "--bare",
            bare.to_str().expect("utf-8 bare path"),
        ]);

        let identity =
            NormalizedLocalRepoIdentity::normalize(tenant(0x33), &bare, &RepoOpenLimits::default())
                .expect("normalize bare repo");
        let expected_root = fs::canonicalize(&bare).expect("canonical bare root");

        assert_eq!(identity.canonical_repo_path(), expected_root.as_path());
        assert_eq!(
            identity.repo_locator().as_local_path(),
            Some(expected_root.as_path())
        );
        assert_eq!(
            identity
                .repo_key()
                .local_path_bytes()
                .expect("repo key path"),
            expected_root.as_os_str().as_encoded_bytes()
        );
    }

    #[test]
    fn normalize_local_repo_identities_sorts_and_rejects_duplicates() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("a-repo");
        let repo_b = dir.path().join("b-repo");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        init_repo(&repo_a);
        init_repo(&repo_b);

        let sorted = normalize_local_repo_identities(
            tenant(0x44),
            [&repo_b, &repo_a],
            &RepoOpenLimits::default(),
        )
        .expect("normalize repo list");
        assert!(
            sorted[0].repo_key() < sorted[1].repo_key(),
            "repo identities should be returned in repo-key order"
        );

        let repo_a_dotted = repo_a.join(".");
        let err = normalize_local_repo_identities(
            tenant(0x44),
            [repo_a.as_path(), repo_a_dotted.as_path()],
            &RepoOpenLimits::default(),
        )
        .expect_err("duplicate normalized repos should be rejected");
        assert!(matches!(
            err,
            RepoIdentityError::DuplicateNormalizedRepoIdentity { .. }
        ));
    }

    #[test]
    fn repo_id_derivation_is_stable_and_tenant_scoped() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let repo_key = NormalizedLocalRepoIdentity::normalize(
            tenant(0x55),
            dir.path(),
            &RepoOpenLimits::default(),
        )
        .expect("normalize repo")
        .repo_key
        .clone();

        let a1 = derive_repo_id(tenant(0x55), &repo_key);
        let a2 = derive_repo_id(tenant(0x55), &repo_key);
        let b = derive_repo_id(tenant(0x56), &repo_key);

        assert_eq!(a1, a2);
        assert_ne!(a1, b);

        // Same tenant, different repo key must produce a different repo_id.
        let other_repo_key = RepoKey::for_local_path(b"/other/repo/path").expect("other repo key");
        let c = derive_repo_id(tenant(0x55), &other_repo_key);
        assert_ne!(
            a1, c,
            "same tenant with different repo key must yield different repo_id"
        );
    }

    #[test]
    fn derive_repo_id_golden_value() {
        let tenant_id = TenantId::from_bytes([0x55; 32]);
        let repo_key = RepoKey::for_local_path(b"/golden/test/path").expect("golden repo key");
        let id = derive_repo_id(tenant_id, &repo_key);

        // Pin the exact value. If this changes, persistence namespaces have silently diverged.
        // Regenerate only after verifying no persisted repo_id values depend on the old output.
        const EXPECTED: u64 = 0x_1c61_23ee_933d_8ec1;
        assert_eq!(
            id, EXPECTED,
            "derive_repo_id golden vector changed (domain::GIT_REPO_ID_V1). \
             Persisted repo_id namespaces will silently diverge if this value changes.\n\
             Actual: {id:#018x}",
        );
    }

    #[test]
    fn canonical_root_builder_rejects_oversized_paths() {
        #[cfg(unix)]
        let path = {
            use std::ffi::OsString;
            use std::os::unix::ffi::OsStringExt;

            PathBuf::from(OsString::from_vec(
                vec![b'x'; gossip_contracts::connector::MAX_ITEM_KEY_SIZE],
            ))
        };

        #[cfg(not(unix))]
        let path = PathBuf::from("x".repeat(gossip_contracts::connector::MAX_ITEM_KEY_SIZE));

        let err = NormalizedLocalRepoIdentity::from_canonical_repo_root(tenant(0x66), path)
            .expect_err("oversized canonical path should be rejected");
        assert!(matches!(err, ConnectorInputError::TooLarge { .. }));
    }

    #[test]
    fn normalized_repo_identity_debug_redacts_paths() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let identity = NormalizedLocalRepoIdentity::normalize(
            tenant(0x77),
            dir.path(),
            &RepoOpenLimits::default(),
        )
        .expect("normalize repo");

        let debug = format!("{identity:?}");
        let canonical = identity.canonical_repo_path().display().to_string();
        assert!(!debug.contains(&canonical));
        assert!(debug.contains("NormalizedLocalRepoIdentity"));
    }

    #[test]
    fn normalize_local_repo_identities_accepts_empty_input() {
        let sorted = normalize_local_repo_identities(
            tenant(0x99),
            Vec::<&Path>::new(),
            &RepoOpenLimits::default(),
        )
        .expect("empty input is valid");
        assert!(sorted.is_empty());
    }

    #[test]
    fn normalize_rejects_non_repository_path() {
        let dir = tempdir().expect("tempdir");
        // Directory is intentionally uninitialized (not a Git repository),
        // so normalization observes a non-repository path.
        let err = NormalizedLocalRepoIdentity::normalize(
            tenant(0x88),
            dir.path(),
            &RepoOpenLimits::default(),
        )
        .expect_err("non-repository path should fail normalization");
        assert!(
            matches!(err, RepoIdentityError::RepoOpen { .. }),
            "expected RepoOpen error, got: {err:?}"
        );
    }
}
