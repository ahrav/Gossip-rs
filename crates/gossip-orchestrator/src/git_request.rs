//! Canonical Git submission request types and normalization helpers.
//!
//! The normalization seam preserves three invariants for downstream Git
//! control-plane stages:
//!
//! - Tenant-scoped repo identity is resolved exactly once.
//! - Equivalent repo targets normalize to the same canonical target.
//! - Request-side selection intent remains explicit instead of being lowered
//!   to runtime ref selection too early.
//!
//! Normalized Git requests stop at canonical targets and typed selection
//! input. Later stages own mirror management, synthetic-ref lowering for
//! explicit commits, shard planning, and run registration.

use std::fmt;
use std::path::{Path, PathBuf};

use gossip_contracts::connector::ToxicDigest;
use gossip_contracts::connector::git::{
    GitMergeStrategy, GitRepoTarget, GitScanMode, RepoKey, RepoLocator,
};
use gossip_contracts::identity::TenantId;
use gossip_coordination::RunConfig;
use scanner_git::{
    HexOidParseError, NormalizedLocalRepoIdentity, ObjectFormat, OidBytes, RepoIdentityError,
    RepoOpenLimits, parse_hex_oid,
};

/// Raw Git submission request before normalization.
///
/// The request carries tenant scope, shared run settings, Git execution knobs,
/// and one or more repo targets. Convenience constructors cover common input
/// shapes, while [`new`](Self::new) accepts the fully general target list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRequest {
    tenant_id: TenantId,
    run_config: RunConfig,
    scan_mode: GitScanMode,
    merge_strategy: GitMergeStrategy,
    targets: Vec<GitRequestTarget>,
}

impl GitRequest {
    /// Constructs a Git request from explicit tenant scope, targets, and run settings.
    #[must_use]
    pub fn new(
        tenant_id: TenantId,
        targets: Vec<GitRequestTarget>,
        run_config: RunConfig,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self {
        Self {
            tenant_id,
            run_config,
            scan_mode,
            merge_strategy,
            targets,
        }
    }

    /// Constructs a request for one repo using default-branch selection.
    #[must_use]
    pub fn single_repo(
        tenant_id: TenantId,
        repo_path: impl Into<PathBuf>,
        run_config: RunConfig,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self {
        Self::new(
            tenant_id,
            vec![GitRequestTarget::new(
                repo_path,
                GitRequestSelection::DefaultBranchOnly,
            )],
            run_config,
            scan_mode,
            merge_strategy,
        )
    }

    /// Constructs a request for a list of repos using default-branch selection.
    #[must_use]
    pub fn repo_list<I, P>(
        tenant_id: TenantId,
        repo_paths: I,
        run_config: RunConfig,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self
    where
        I: IntoIterator<Item = P>,
        P: Into<PathBuf>,
    {
        let targets = repo_paths
            .into_iter()
            .map(|repo_path| {
                GitRequestTarget::new(repo_path, GitRequestSelection::DefaultBranchOnly)
            })
            .collect();
        Self::new(tenant_id, targets, run_config, scan_mode, merge_strategy)
    }

    /// Constructs a request for one repo using explicit ref selection.
    #[must_use]
    pub fn repo_with_explicit_refs<I, B>(
        tenant_id: TenantId,
        repo_path: impl Into<PathBuf>,
        refs: I,
        run_config: RunConfig,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        Self::new(
            tenant_id,
            vec![GitRequestTarget::new(
                repo_path,
                GitRequestSelection::explicit_refs(refs),
            )],
            run_config,
            scan_mode,
            merge_strategy,
        )
    }

    /// Constructs a request for one repo using an explicit commit selection.
    #[must_use]
    pub fn repo_with_explicit_commit(
        tenant_id: TenantId,
        repo_path: impl Into<PathBuf>,
        commit_hex: impl Into<Vec<u8>>,
        run_config: RunConfig,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self {
        Self::new(
            tenant_id,
            vec![GitRequestTarget::new(
                repo_path,
                GitRequestSelection::explicit_commit(commit_hex),
            )],
            run_config,
            scan_mode,
            merge_strategy,
        )
    }

    /// Returns the tenant scope for this request.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the coordination-level run settings for this request.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Returns the shared Git scan mode for all targets in the request.
    #[must_use]
    pub fn scan_mode(&self) -> GitScanMode {
        self.scan_mode
    }

    /// Returns the shared Git merge strategy for all targets in the request.
    #[must_use]
    pub fn merge_strategy(&self) -> GitMergeStrategy {
        self.merge_strategy
    }

    /// Returns the raw targets carried by the request.
    #[must_use]
    pub fn targets(&self) -> &[GitRequestTarget] {
        &self.targets
    }

    /// Canonicalizes repo targets, validates selection input, and dedupes
    /// identical normalized targets in stable repo-key order.
    ///
    /// Equivalent inputs collapse to one normalized target. Targets that
    /// normalize to the same repo identity but disagree on request-side
    /// selection are rejected so later control-plane stages never need to
    /// guess which intent to preserve. Diagnostic display metadata is not
    /// part of the identity or selection contract: when two targets share
    /// the same repo key and selection, the first target's display name
    /// wins and the duplicate is silently dropped.
    ///
    /// # Errors
    ///
    /// Returns an error when repo normalization fails, explicit commit input
    /// is not valid hex for a supported OID width, or duplicates disagree
    /// after normalization.
    pub fn normalize(&self) -> Result<NormalizedGitRequest, GitRequestError> {
        if self.targets.is_empty() {
            return Err(GitRequestError::EmptyTargets);
        }

        let mut normalized = Vec::with_capacity(self.targets.len());
        let limits = RepoOpenLimits::default();

        for (target_index, target) in self.targets.iter().enumerate() {
            let identity =
                NormalizedLocalRepoIdentity::normalize(self.tenant_id, target.repo_path(), &limits)
                    .map_err(|source| GitRequestError::RepoNormalization {
                        target_index,
                        source,
                    })?;

            let selection = normalize_selection(target.selection(), target_index)?;
            let mut repo_target =
                GitRepoTarget::new(identity.repo_key().clone(), identity.repo_locator().clone());
            if let Some(display_name) = target.display_name() {
                repo_target = repo_target.with_display_name(display_name.to_owned());
            }

            normalized.push(IndexedNormalizedGitTarget {
                target_index,
                target: NormalizedGitTarget {
                    repo_target,
                    repo_id: identity.repo_id(),
                    selection,
                },
            });
        }

        normalized.sort_unstable_by(|left, right| {
            left.target
                .repo_key()
                .cmp(right.target.repo_key())
                .then(left.target_index.cmp(&right.target_index))
        });

        let mut deduped: Vec<IndexedNormalizedGitTarget> = Vec::with_capacity(normalized.len());
        for candidate in normalized {
            if let Some(previous) = deduped.last()
                && previous.target.repo_key() == candidate.target.repo_key()
            {
                // Same repo key and same selection: collapse duplicates.
                // Display-name differences are ignored because display_name
                // is diagnostic-only metadata; the first target's name wins.
                if previous.target.selection == candidate.target.selection {
                    continue;
                }

                return Err(GitRequestError::ConflictingNormalizedTarget {
                    first_index: previous.target_index,
                    second_index: candidate.target_index,
                });
            }

            deduped.push(candidate);
        }

        Ok(NormalizedGitRequest {
            tenant_id: self.tenant_id,
            run_config: self.run_config,
            scan_mode: self.scan_mode,
            merge_strategy: self.merge_strategy,
            targets: deduped.into_iter().map(|entry| entry.target).collect(),
        })
    }
}

/// One raw repo target inside a [`GitRequest`].
#[derive(Clone, PartialEq, Eq)]
pub struct GitRequestTarget {
    repo_path: PathBuf,
    selection: GitRequestSelection,
    display_name: Option<String>,
}

impl GitRequestTarget {
    /// Constructs a raw repo target from a repo path and request-side selection.
    #[must_use]
    pub fn new(repo_path: impl Into<PathBuf>, selection: GitRequestSelection) -> Self {
        Self {
            repo_path: repo_path.into(),
            selection,
            display_name: None,
        }
    }

    /// Attaches optional diagnostic display metadata to the target.
    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Returns the raw repo path before normalization.
    #[must_use]
    pub fn repo_path(&self) -> &Path {
        &self.repo_path
    }

    /// Returns the request-side selection for this target.
    #[must_use]
    pub fn selection(&self) -> &GitRequestSelection {
        &self.selection
    }

    /// Returns the optional display metadata attached to this target.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

impl fmt::Debug for GitRequestTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitRequestTarget")
            .field(
                "repo_path",
                &ToxicDigest::of_bytes(self.repo_path.as_os_str().as_encoded_bytes()),
            )
            .field("selection", &self.selection)
            .field(
                "display_name",
                &self
                    .display_name
                    .as_ref()
                    .map(|value| ToxicDigest::of_bytes(value.as_bytes())),
            )
            .finish()
    }
}

/// Request-side selection intent before normalization.
///
/// This remains distinct from the contract-level [`gossip_contracts::connector::git::GitRefSelection`]
/// because it carries an `ExplicitCommit` variant with raw hex OID bytes
/// that must be parsed and validated before lowering to a synthetic ref
/// in later Git control-plane stages.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum GitRequestSelection {
    /// Scan the repo's default branch only.
    #[default]
    DefaultBranchOnly,
    /// Scan an explicit list of fully-qualified refs.
    ExplicitRefs {
        /// Fully-qualified refs such as `b"refs/heads/main"`.
        refs: Vec<Vec<u8>>,
    },
    /// Scan one explicit commit without lowering it to a ref yet.
    ExplicitCommit {
        /// Lowercase or uppercase ASCII hex object ID bytes.
        commit_hex: Vec<u8>,
    },
}

impl GitRequestSelection {
    /// Constructs an explicit-ref selection from any byte-like iterator.
    #[must_use]
    pub fn explicit_refs<I, B>(refs: I) -> Self
    where
        I: IntoIterator<Item = B>,
        B: Into<Vec<u8>>,
    {
        Self::ExplicitRefs {
            refs: refs.into_iter().map(Into::into).collect(),
        }
    }

    /// Constructs an explicit-commit selection from hex bytes.
    #[must_use]
    pub fn explicit_commit(commit_hex: impl Into<Vec<u8>>) -> Self {
        Self::ExplicitCommit {
            commit_hex: commit_hex.into(),
        }
    }
}

impl fmt::Debug for GitRequestSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultBranchOnly => f.write_str("DefaultBranchOnly"),
            Self::ExplicitRefs { refs } => {
                let digests: Vec<_> = refs
                    .iter()
                    .map(|value| ToxicDigest::of_bytes(value.as_slice()))
                    .collect();
                f.debug_struct("ExplicitRefs")
                    .field("count", &refs.len())
                    .field("digests", &digests)
                    .finish()
            }
            Self::ExplicitCommit { commit_hex } => f
                .debug_struct("ExplicitCommit")
                .field("hex", &ToxicDigest::of_bytes(commit_hex.as_slice()))
                .finish(),
        }
    }
}

/// Canonical Git request output after repo normalization and target dedupe.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedGitRequest {
    tenant_id: TenantId,
    run_config: RunConfig,
    scan_mode: GitScanMode,
    merge_strategy: GitMergeStrategy,
    targets: Vec<NormalizedGitTarget>,
}

impl NormalizedGitRequest {
    /// Returns the tenant scope preserved across normalization.
    #[must_use]
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// Returns the coordination-level run settings preserved across normalization.
    #[must_use]
    pub fn run_config(&self) -> RunConfig {
        self.run_config
    }

    /// Returns the shared Git scan mode preserved across normalization.
    #[must_use]
    pub fn scan_mode(&self) -> GitScanMode {
        self.scan_mode
    }

    /// Returns the shared Git merge strategy preserved across normalization.
    #[must_use]
    pub fn merge_strategy(&self) -> GitMergeStrategy {
        self.merge_strategy
    }

    /// Returns the normalized repo targets in deterministic repo-key order.
    #[must_use]
    pub fn targets(&self) -> &[NormalizedGitTarget] {
        &self.targets
    }
}

/// One canonical repo target inside a [`NormalizedGitRequest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NormalizedGitTarget {
    repo_target: GitRepoTarget,
    repo_id: u64,
    selection: NormalizedGitSelection,
}

impl NormalizedGitTarget {
    /// Returns the canonical repo-discovery target for this normalized repo.
    #[must_use]
    pub fn repo_target(&self) -> &GitRepoTarget {
        &self.repo_target
    }

    /// Returns the canonical repo key used for ordering and paging.
    #[must_use]
    pub fn repo_key(&self) -> &RepoKey {
        self.repo_target.repo_key()
    }

    /// Returns the canonical repo locator used for later Git stages.
    #[must_use]
    pub fn repo_locator(&self) -> &RepoLocator {
        self.repo_target.locator()
    }

    /// Returns the optional diagnostic display metadata for this target.
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.repo_target.display_name()
    }

    /// Returns the tenant-scoped stable repo identifier for persistence namespaces.
    #[must_use]
    pub fn repo_id(&self) -> u64 {
        self.repo_id
    }

    /// Returns the normalized request-side selection input for this repo.
    #[must_use]
    pub fn selection(&self) -> &NormalizedGitSelection {
        &self.selection
    }
}

/// Request-side selection intent after normalization.
#[derive(Clone, PartialEq, Eq)]
pub enum NormalizedGitSelection {
    /// Default-branch selection, preserved without re-inference.
    DefaultBranchOnly,
    /// Explicit refs sorted and deduped into canonical order.
    ExplicitRefs {
        /// Canonically ordered and deduped fully-qualified refs.
        refs: Vec<Vec<u8>>,
    },
    /// Explicit commit parsed into a typed object ID.
    ExplicitCommit {
        /// Typed object ID preserved for later synthetic-ref lowering.
        commit: OidBytes,
    },
}

impl fmt::Debug for NormalizedGitSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultBranchOnly => f.write_str("DefaultBranchOnly"),
            Self::ExplicitRefs { refs } => {
                let digests: Vec<_> = refs
                    .iter()
                    .map(|value| ToxicDigest::of_bytes(value.as_slice()))
                    .collect();
                f.debug_struct("ExplicitRefs")
                    .field("count", &refs.len())
                    .field("digests", &digests)
                    .finish()
            }
            Self::ExplicitCommit { commit } => f
                .debug_struct("ExplicitCommit")
                .field("format", &commit.format())
                .field("oid", &ToxicDigest::of_bytes(commit.as_slice()))
                .finish(),
        }
    }
}

/// Validation failures for individual explicit-ref entries.
///
/// Returned by [`validate_explicit_refs`] and converted into the caller's
/// domain error via `From` impls on both the encode and decode error types.
#[derive(Debug, thiserror::Error)]
pub(crate) enum ExplicitRefValidationError {
    /// The explicit refs list was empty.
    #[error("explicit refs list must be non-empty")]
    EmptyList,
    /// One ref entry was zero-length.
    #[error("explicit ref at position {ref_index} is empty")]
    EmptyRef {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// One ref entry contained a NUL byte.
    #[error("explicit ref at position {ref_index} contains a NUL byte")]
    RefContainsNul {
        /// Zero-based position within the explicit-ref list.
        ref_index: usize,
    },
    /// The refs were not in strict sorted, deduplicated order.
    #[error("explicit refs must be strictly sorted and deduplicated")]
    NonCanonical,
}

/// Validates that an explicit-ref list is non-empty, each entry is non-empty
/// and NUL-free, and the entries are in strict sorted order with no duplicates.
pub(crate) fn validate_explicit_refs(refs: &[Vec<u8>]) -> Result<(), ExplicitRefValidationError> {
    if refs.is_empty() {
        return Err(ExplicitRefValidationError::EmptyList);
    }

    let mut previous: Option<&[u8]> = None;
    for (ref_index, value) in refs.iter().enumerate() {
        if value.is_empty() {
            return Err(ExplicitRefValidationError::EmptyRef { ref_index });
        }
        if value.contains(&0) {
            return Err(ExplicitRefValidationError::RefContainsNul { ref_index });
        }
        if let Some(previous) = previous
            && previous >= value.as_slice()
        {
            return Err(ExplicitRefValidationError::NonCanonical);
        }
        previous = Some(value);
    }

    Ok(())
}

/// Normalization failures for [`GitRequest`].
#[derive(Debug, thiserror::Error)]
pub enum GitRequestError {
    /// Repo identity normalization failed for one target.
    #[error("git request target {target_index} failed repo normalization: {source}")]
    RepoNormalization {
        /// Zero-based position in the raw request target list.
        target_index: usize,
        /// Underlying repo normalization failure.
        source: RepoIdentityError,
    },
    /// Explicit commit input used an unsupported hex width.
    #[error(
        "git request target {target_index} has invalid explicit commit length {found}; expected {sha1_hex_len} or {sha256_hex_len} hex chars"
    )]
    InvalidExplicitCommitLength {
        /// Zero-based position in the raw request target list.
        target_index: usize,
        /// Observed hex width.
        found: usize,
        /// Supported SHA-1 width in hex characters.
        sha1_hex_len: usize,
        /// Supported SHA-256 width in hex characters.
        sha256_hex_len: usize,
    },
    /// Explicit commit input failed full hex decoding.
    #[error("git request target {target_index} has invalid explicit commit: {source}")]
    InvalidExplicitCommit {
        /// Zero-based position in the raw request target list.
        target_index: usize,
        /// Underlying hex parse failure.
        source: HexOidParseError,
    },
    /// Two inputs normalized to the same repo identity but disagreed afterward.
    #[error(
        "git request targets {first_index} and {second_index} normalized to the same repo identity but disagreed on selection"
    )]
    ConflictingNormalizedTarget {
        /// First conflicting target index.
        first_index: usize,
        /// Second conflicting target index.
        second_index: usize,
    },
    /// The request contains no targets.
    #[error("git request has no targets")]
    EmptyTargets,
    /// Explicit refs selection contains no refs.
    #[error("git request target {target_index} has empty explicit refs list")]
    EmptyExplicitRefs {
        /// Zero-based position in the raw request target list.
        target_index: usize,
    },
    /// An individual ref in the explicit refs list is empty (zero-length).
    #[error("git request target {target_index} ref at position {ref_index} is empty")]
    EmptyRef {
        /// Zero-based position in the raw request target list.
        target_index: usize,
        /// Zero-based position within the refs list.
        ref_index: usize,
    },
    /// An individual ref contains a NUL byte, which Git refnames prohibit.
    #[error("git request target {target_index} ref at position {ref_index} contains a NUL byte")]
    RefContainsNul {
        /// Zero-based position in the raw request target list.
        target_index: usize,
        /// Zero-based position within the refs list.
        ref_index: usize,
    },
    /// Explicit commit resolved to the null OID (all zeros).
    #[error("git request target {target_index} has null commit OID (all zeros)")]
    NullExplicitCommit {
        /// Zero-based position in the raw request target list.
        target_index: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct IndexedNormalizedGitTarget {
    target_index: usize,
    target: NormalizedGitTarget,
}

fn normalize_selection(
    selection: &GitRequestSelection,
    target_index: usize,
) -> Result<NormalizedGitSelection, GitRequestError> {
    match selection {
        GitRequestSelection::DefaultBranchOnly => Ok(NormalizedGitSelection::DefaultBranchOnly),
        GitRequestSelection::ExplicitRefs { refs } => {
            if refs.is_empty() {
                return Err(GitRequestError::EmptyExplicitRefs { target_index });
            }
            for (ref_index, r) in refs.iter().enumerate() {
                if r.is_empty() {
                    return Err(GitRequestError::EmptyRef {
                        target_index,
                        ref_index,
                    });
                }
                if r.contains(&0) {
                    return Err(GitRequestError::RefContainsNul {
                        target_index,
                        ref_index,
                    });
                }
            }
            Ok(NormalizedGitSelection::ExplicitRefs {
                refs: normalize_explicit_refs(refs),
            })
        }
        GitRequestSelection::ExplicitCommit { commit_hex } => {
            let format = infer_object_format_from_hex_len(commit_hex).ok_or_else(|| {
                GitRequestError::InvalidExplicitCommitLength {
                    target_index,
                    found: commit_hex.len(),
                    sha1_hex_len: ObjectFormat::Sha1.hex_len() as usize,
                    sha256_hex_len: ObjectFormat::Sha256.hex_len() as usize,
                }
            })?;
            let commit = parse_hex_oid(commit_hex, format).map_err(|source| {
                GitRequestError::InvalidExplicitCommit {
                    target_index,
                    source,
                }
            })?;
            if commit.is_null() {
                return Err(GitRequestError::NullExplicitCommit { target_index });
            }
            Ok(NormalizedGitSelection::ExplicitCommit { commit })
        }
    }
}

fn normalize_explicit_refs(refs: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut normalized = refs.to_vec();
    normalized.sort_unstable();
    normalized.dedup();
    normalized
}

fn infer_object_format_from_hex_len(hex: &[u8]) -> Option<ObjectFormat> {
    match hex.len() {
        len if len == ObjectFormat::Sha1.hex_len() as usize => Some(ObjectFormat::Sha1),
        len if len == ObjectFormat::Sha256.hex_len() as usize => Some(ObjectFormat::Sha256),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use gossip_contracts::identity::TenantId;
    use tempfile::tempdir;

    use super::*;
    use crate::test_support::{init_git_repo, run_config, run_git_in};

    fn tenant(byte: u8) -> TenantId {
        TenantId::from_bytes([byte; 32])
    }

    fn init_repo(dir: &Path) {
        init_git_repo(dir, "git-request-tests@example.com", "Git Request Tests");
    }

    fn init_committed_repo(dir: &Path) {
        init_repo(dir);
        fs::write(dir.join("fixture.txt"), "fixture").expect("write fixture");
        run_git_in(dir, &["add", "."]);
        run_git_in(dir, &["commit", "-q", "-m", "fixture"]);
    }

    fn default_scan_mode() -> GitScanMode {
        GitScanMode::OdbBlobFast
    }

    fn default_merge_strategy() -> GitMergeStrategy {
        GitMergeStrategy::AllParents
    }

    #[test]
    fn single_repo_request_normalizes_to_one_target() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::single_repo(
            tenant(0x11),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        assert_eq!(normalized.tenant_id(), tenant(0x11));
        assert_eq!(normalized.run_config(), run_config());
        assert_eq!(normalized.scan_mode(), default_scan_mode());
        assert_eq!(normalized.merge_strategy(), default_merge_strategy());
        assert_eq!(normalized.targets().len(), 1);

        let target = &normalized.targets()[0];
        assert_eq!(
            target.selection(),
            &NormalizedGitSelection::DefaultBranchOnly
        );
        assert_eq!(
            target.repo_locator().as_local_path(),
            Some(
                fs::canonicalize(dir.path())
                    .expect("canonical repo")
                    .as_path()
            )
        );
    }

    #[test]
    fn repo_list_normalizes_in_repo_key_order() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("a-repo");
        let repo_b = dir.path().join("b-repo");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        init_repo(&repo_a);
        init_repo(&repo_b);

        let request = GitRequest::repo_list(
            tenant(0x22),
            [&repo_b, &repo_a],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        assert_eq!(normalized.targets().len(), 2);
        assert!(
            normalized.targets()[0].repo_key() < normalized.targets()[1].repo_key(),
            "targets should be sorted in repo-key order"
        );
    }

    #[test]
    fn equivalent_targets_dedupe_after_normalization() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0x33),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(dir.path().join("."), GitRequestSelection::DefaultBranchOnly),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        assert_eq!(normalized.targets().len(), 1);
    }

    #[test]
    fn conflicting_same_repo_targets_fail_loudly() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0x44),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(
                    dir.path().join("."),
                    GitRequestSelection::explicit_refs([
                        b"refs/heads/main".as_slice(),
                        b"refs/tags/v1".as_slice(),
                    ]),
                ),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("conflicting duplicates should fail");
        assert!(matches!(
            err,
            GitRequestError::ConflictingNormalizedTarget {
                first_index: 0,
                second_index: 1,
            }
        ));
    }

    #[test]
    fn explicit_refs_normalize_order_and_duplicates() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::repo_with_explicit_refs(
            tenant(0x55),
            dir.path(),
            [
                b"refs/heads/b".as_slice(),
                b"refs/heads/a".as_slice(),
                b"refs/heads/a".as_slice(),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        assert_eq!(
            normalized.targets()[0].selection(),
            &NormalizedGitSelection::ExplicitRefs {
                refs: vec![b"refs/heads/a".to_vec(), b"refs/heads/b".to_vec()],
            }
        );
    }

    #[test]
    fn explicit_commit_normalizes_to_typed_oid() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0x66),
            dir.path(),
            commit_hex.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        let expected = parse_hex_oid(commit_hex, ObjectFormat::Sha1).expect("parse expected oid");
        assert_eq!(
            normalized.targets()[0].selection(),
            &NormalizedGitSelection::ExplicitCommit { commit: expected }
        );
    }

    #[test]
    fn invalid_explicit_commit_hex_fails() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let invalid_hex = b"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0x77),
            dir.path(),
            invalid_hex.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("invalid explicit commit should fail");
        assert!(matches!(
            err,
            GitRequestError::InvalidExplicitCommit {
                target_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn invalid_explicit_commit_length_fails() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0x78),
            dir.path(),
            b"abcde".as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("invalid explicit commit length should fail");
        assert!(matches!(
            err,
            GitRequestError::InvalidExplicitCommitLength {
                target_index: 0,
                found: 5,
                ..
            }
        ));
    }

    #[test]
    fn repo_id_is_tenant_scoped_for_same_repo() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let first = GitRequest::single_repo(
            tenant(0x88),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize first request");
        let second = GitRequest::single_repo(
            tenant(0x89),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        )
        .normalize()
        .expect("normalize second request");

        assert_ne!(first.targets()[0].repo_id(), second.targets()[0].repo_id());
        assert_eq!(
            first.targets()[0].repo_key(),
            second.targets()[0].repo_key()
        );
    }

    #[test]
    fn request_debug_redacts_repo_path_refs_commit_and_display_name() {
        let dir = tempdir().expect("tempdir");
        init_committed_repo(dir.path());

        let refs_request = GitRequest::new(
            tenant(0x90),
            vec![
                GitRequestTarget::new(
                    dir.path(),
                    GitRequestSelection::explicit_refs([b"refs/heads/main".as_slice()]),
                )
                .with_display_name("sensitive-display"),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let refs_debug = format!("{refs_request:?}");
        assert!(!refs_debug.contains(&dir.path().display().to_string()));
        assert!(!refs_debug.contains("refs/heads/main"));
        assert!(!refs_debug.contains("sensitive-display"));

        let commit_request = GitRequest::repo_with_explicit_commit(
            tenant(0x90),
            dir.path(),
            b"0123456789abcdef0123456789abcdef01234567".as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let commit_debug = format!("{commit_request:?}");
        assert!(!commit_debug.contains(&dir.path().display().to_string()));
        assert!(!commit_debug.contains("0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn normalized_debug_redacts_repo_path_refs_commit_and_display_name() {
        let dir = tempdir().expect("tempdir");
        init_committed_repo(dir.path());

        let refs_request = GitRequest::new(
            tenant(0x91),
            vec![
                GitRequestTarget::new(
                    dir.path(),
                    GitRequestSelection::explicit_refs([b"refs/heads/main".as_slice()]),
                )
                .with_display_name("sensitive-display"),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let refs_normalized = refs_request.normalize().expect("normalize refs request");
        let refs_debug = format!("{refs_normalized:?}");
        assert!(!refs_debug.contains(&dir.path().display().to_string()));
        assert!(!refs_debug.contains("refs/heads/main"));
        assert!(!refs_debug.contains("sensitive-display"));

        let commit_request = GitRequest::repo_with_explicit_commit(
            tenant(0x91),
            dir.path(),
            b"0123456789abcdef0123456789abcdef01234567".as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let commit_normalized = commit_request
            .normalize()
            .expect("normalize commit request");
        let commit_debug = format!("{commit_normalized:?}");
        assert!(!commit_debug.contains(&dir.path().display().to_string()));
        assert!(!commit_debug.contains("0123456789abcdef0123456789abcdef01234567"));
    }

    #[test]
    fn display_name_difference_dedupes_not_conflicts() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xA0),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly)
                    .with_display_name("display-a"),
                GitRequestTarget::new(dir.path().join("."), GitRequestSelection::DefaultBranchOnly)
                    .with_display_name("display-b"),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request
            .normalize()
            .expect("display_name difference should dedupe, not conflict");
        assert_eq!(normalized.targets().len(), 1);
        assert_eq!(
            normalized.targets()[0].display_name(),
            Some("display-a"),
            "first target's display name should win during dedupe"
        );
    }

    #[test]
    fn empty_targets_rejected() {
        let request = GitRequest::new(
            tenant(0xA1),
            vec![],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );
        let err = request.normalize().expect_err("empty targets should fail");
        assert!(matches!(err, GitRequestError::EmptyTargets));
    }

    #[test]
    fn empty_explicit_refs_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xA2),
            vec![GitRequestTarget::new(
                dir.path(),
                GitRequestSelection::ExplicitRefs { refs: vec![] },
            )],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("empty explicit refs should fail");
        assert!(matches!(
            err,
            GitRequestError::EmptyExplicitRefs { target_index: 0 }
        ));
    }

    #[test]
    fn empty_individual_ref_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xA6),
            vec![GitRequestTarget::new(
                dir.path(),
                GitRequestSelection::ExplicitRefs {
                    refs: vec![b"refs/heads/main".to_vec(), vec![]],
                },
            )],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("empty individual ref should fail");
        assert!(matches!(
            err,
            GitRequestError::EmptyRef {
                target_index: 0,
                ref_index: 1,
            }
        ));
    }

    #[test]
    fn all_empty_individual_refs_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xA7),
            vec![GitRequestTarget::new(
                dir.path(),
                GitRequestSelection::ExplicitRefs { refs: vec![vec![]] },
            )],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request.normalize().expect_err("sole empty ref should fail");
        assert!(matches!(
            err,
            GitRequestError::EmptyRef {
                target_index: 0,
                ref_index: 0,
            }
        ));
    }

    #[test]
    fn ref_containing_nul_byte_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xA8),
            vec![GitRequestTarget::new(
                dir.path(),
                GitRequestSelection::ExplicitRefs {
                    refs: vec![b"refs/heads/main".to_vec(), b"refs/heads/\x00bad".to_vec()],
                },
            )],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("ref with NUL byte should fail");
        assert!(matches!(
            err,
            GitRequestError::RefContainsNul {
                target_index: 0,
                ref_index: 1,
            }
        ));
    }

    #[test]
    fn explicit_commit_sha256_normalizes_to_typed_oid() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let commit_hex = b"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0xA3),
            dir.path(),
            commit_hex.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize sha256 commit");
        let expected =
            parse_hex_oid(commit_hex, ObjectFormat::Sha256).expect("parse expected sha256 oid");
        assert_eq!(
            normalized.targets()[0].selection(),
            &NormalizedGitSelection::ExplicitCommit { commit: expected }
        );
    }

    #[test]
    fn explicit_commit_uppercase_hex_normalizes_correctly() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let upper = b"0123456789ABCDEF0123456789ABCDEF01234567";
        let lower = b"0123456789abcdef0123456789abcdef01234567";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0xA4),
            dir.path(),
            upper.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize uppercase hex");
        let expected =
            parse_hex_oid(lower, ObjectFormat::Sha1).expect("parse expected lowercase oid");
        assert_eq!(
            normalized.targets()[0].selection(),
            &NormalizedGitSelection::ExplicitCommit { commit: expected }
        );
    }

    #[test]
    fn null_oid_explicit_commit_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let null_hex = b"0000000000000000000000000000000000000000";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0xA5),
            dir.path(),
            null_hex.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("null OID should be rejected");
        assert!(matches!(
            err,
            GitRequestError::NullExplicitCommit { target_index: 0 }
        ));
    }

    #[test]
    fn non_git_directory_fails_repo_normalization() {
        let dir = tempdir().expect("tempdir");

        let request = GitRequest::single_repo(
            tenant(0xB0),
            dir.path(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("non-Git directory should fail normalization");
        assert!(matches!(
            err,
            GitRequestError::RepoNormalization {
                target_index: 0,
                ..
            }
        ));
    }

    #[test]
    fn repo_normalization_reports_correct_target_index() {
        let good_dir = tempdir().expect("tempdir");
        init_repo(good_dir.path());
        let bad_dir = tempdir().expect("tempdir");

        let request = GitRequest::new(
            tenant(0xB1),
            vec![
                GitRequestTarget::new(good_dir.path(), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(bad_dir.path(), GitRequestSelection::DefaultBranchOnly),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("second target should fail normalization");
        assert!(matches!(
            err,
            GitRequestError::RepoNormalization {
                target_index: 1,
                ..
            }
        ));
    }

    #[test]
    fn three_or_more_identical_targets_collapse_to_one() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xB2),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(dir.path().join("."), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(
                    dir.path().join("./"),
                    GitRequestSelection::DefaultBranchOnly,
                ),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize request");
        assert_eq!(normalized.targets().len(), 1);
    }

    #[test]
    fn three_way_conflict_two_identical_plus_one_different() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());

        let request = GitRequest::new(
            tenant(0xB3),
            vec![
                GitRequestTarget::new(dir.path(), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(dir.path().join("."), GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(
                    dir.path().join("./"),
                    GitRequestSelection::explicit_refs([b"refs/heads/main".as_slice()]),
                ),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("three-way conflict should fail");
        assert!(matches!(
            err,
            GitRequestError::ConflictingNormalizedTarget { .. }
        ));
    }

    #[test]
    fn mixed_selection_types_across_distinct_repos() {
        let dir = tempdir().expect("tempdir");
        let repo_a = dir.path().join("repo-a");
        let repo_b = dir.path().join("repo-b");
        let repo_c = dir.path().join("repo-c");
        fs::create_dir_all(&repo_a).expect("create repo a");
        fs::create_dir_all(&repo_b).expect("create repo b");
        fs::create_dir_all(&repo_c).expect("create repo c");
        init_repo(&repo_a);
        init_repo(&repo_b);
        init_repo(&repo_c);

        let commit_hex = b"0123456789abcdef0123456789abcdef01234567";
        let request = GitRequest::new(
            tenant(0xB4),
            vec![
                GitRequestTarget::new(&repo_a, GitRequestSelection::DefaultBranchOnly),
                GitRequestTarget::new(
                    &repo_b,
                    GitRequestSelection::explicit_refs([b"refs/heads/main".as_slice()]),
                ),
                GitRequestTarget::new(
                    &repo_c,
                    GitRequestSelection::explicit_commit(commit_hex.as_slice()),
                ),
            ],
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let normalized = request.normalize().expect("normalize mixed selections");
        assert_eq!(normalized.targets().len(), 3);
    }

    #[test]
    fn sha256_null_oid_explicit_commit_rejected() {
        let dir = tempdir().expect("tempdir");
        init_repo(dir.path());
        let null_sha256 = b"0000000000000000000000000000000000000000000000000000000000000000";

        let request = GitRequest::repo_with_explicit_commit(
            tenant(0xB5),
            dir.path(),
            null_sha256.as_slice(),
            run_config(),
            default_scan_mode(),
            default_merge_strategy(),
        );

        let err = request
            .normalize()
            .expect_err("SHA-256 null OID should be rejected");
        assert!(matches!(
            err,
            GitRequestError::NullExplicitCommit { target_index: 0 }
        ));
    }
}
