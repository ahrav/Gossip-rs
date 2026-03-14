//! Git-specific connector family contract.
//!
//! This module defines the repo-oriented connector family used for Git-backed
//! sources. Git execution is intentionally modeled separately from
//! ordered-content sources because the runtime operates on whole repositories:
//! commit walks, tree diffs, pack scans, and watermark persistence rather than
//! item-at-a-time `open` / `read_range` calls.
//!
//! ## Surface overview
//!
//! | Type | Role |
//! |------|------|
//! | [`RepoKey`] | Canonical ordered work-unit key for one repository |
//! | [`RepoLocator`] | Where the repository can be found |
//! | [`GitRepoTarget`] | Discovery-page item for one repository |
//! | [`GitSelection`] | Repo-native scan selection (refs + mode + merge strategy) |
//! | [`LocalMirror`] | Prepared local clone or mirror ready for execution |
//! | [`GitExecutionLimits`] | Execution resource/configuration knobs |
//! | [`GitRunOutcome`] | High-level counts and timing from one completed run |
//! | [`GitRunError`] | Repo-native execution/mirroring failure |
//! | [`GitRepoDiscoverySource`] | Trait for frontier discovery of repositories |
//! | [`GitMirrorManager`] | Trait for acquiring or refreshing local mirrors |
//! | [`GitRepoExecutor`] | Trait for whole-repo Git execution |
//!
//! ## Flow
//!
//! 1. [`GitRepoDiscoverySource`] pages over [`GitRepoTarget`] values in
//!    deterministic [`RepoKey`] order.
//! 2. [`GitMirrorManager`] materializes or refreshes a [`LocalMirror`] for the
//!    chosen [`RepoLocator`].
//! 3. [`GitRepoExecutor`] runs repo-native Git scanning against that mirror
//!    using a [`GitSelection`] and [`GitExecutionLimits`].
//!
//! ## Boundary notes
//!
//! - Distributed progress is tracked at the outer repo frontier via
//!   [`RepoKey`] and [`PageBuf`].
//! - Inner Git progress remains repo-native and lives behind the executor
//!   boundary (for example, watermark stores or seen-blob state in runtime
//!   crates).
//! - No type in this module depends on `scanner-git`, `gix-*`, or
//!   `gossip-scan-driver`.

use std::{
    fmt,
    path::{Path, PathBuf},
};

use crate::coordination::ShardSpec;

use super::common::{KeyedPageItem, PageBuf, PagingCapabilities};
use super::types::ToxicDigest;
use super::{Budgets, ConnectorInputError, Cursor, EnumerateError, ErrorClass, ItemKey};

/// Canonical ordered work-unit key for a single repository.
///
/// This is a semantic newtype over [`ItemKey`] so the repo frontier can use a
/// repository-specific identifier without overloading generic item keys in
/// signatures and documentation.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RepoKey(ItemKey);

impl RepoKey {
    /// Construct a repo key from an already-validated ordered key.
    #[inline]
    #[must_use]
    pub fn new(item_key: ItemKey) -> Self {
        Self(item_key)
    }

    /// Validate and construct a repo key from owned bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError`] when the underlying bytes violate the
    /// [`ItemKey`] contract.
    #[inline]
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ConnectorInputError> {
        Ok(Self(ItemKey::try_from_vec(bytes)?))
    }

    /// Validate and construct a repo key from a borrowed slice.
    ///
    /// # Errors
    ///
    /// Returns [`ConnectorInputError`] when the underlying bytes violate the
    /// [`ItemKey`] contract.
    #[inline]
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, ConnectorInputError> {
        Ok(Self(ItemKey::try_from_slice(bytes)?))
    }

    /// Borrow the underlying ordered key.
    #[inline]
    #[must_use]
    pub fn as_item_key(&self) -> &ItemKey {
        &self.0
    }

    /// Consume the repo key and return the underlying ordered key.
    #[inline]
    #[must_use]
    pub fn into_item_key(self) -> ItemKey {
        self.0
    }

    /// Borrow the raw repo-key bytes.
    #[inline]
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }
}

impl AsRef<[u8]> for RepoKey {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl fmt::Debug for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("RepoKey").field(&self.0).finish()
    }
}

impl fmt::Display for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoKey({})", self.0)
    }
}

/// Canonical description of where a repository can be found.
///
/// Only local-path locators are modeled today. The enum is non-exhaustive so
/// future work can add URL-backed or provider-specific locator variants
/// without renaming the type.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RepoLocator {
    /// Repository already available on the local filesystem.
    LocalPath(PathBuf),
}

impl RepoLocator {
    /// Construct a locator for a local repository path.
    #[inline]
    #[must_use]
    pub fn local_path(path: impl Into<PathBuf>) -> Self {
        Self::LocalPath(path.into())
    }

    /// Borrow the local filesystem path when this locator is local-path based.
    #[inline]
    #[must_use]
    pub fn as_local_path(&self) -> Option<&Path> {
        match self {
            Self::LocalPath(path) => Some(path.as_path()),
        }
    }
}

impl fmt::Debug for RepoLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocalPath(path) => f
                .debug_struct("RepoLocator")
                .field("kind", &"LocalPath")
                .field(
                    "path",
                    &ToxicDigest::of_bytes(path.to_string_lossy().as_bytes()),
                )
                .finish(),
        }
    }
}

/// Ref-selection policy for repo-native Git execution.
///
/// This mirrors the contract-level intent of `StartSetConfig` without pulling
/// in runtime Git dependencies.
#[derive(Clone, PartialEq, Eq, Default)]
pub enum GitRefSelection {
    /// Scan only the default branch.
    #[default]
    DefaultBranchOnly,
    /// Scan all remote branches, optionally limited to one remote.
    AllRemoteBranches {
        /// Remote name filter (for example `b"origin"`).
        remote: Option<Vec<u8>>,
    },
    /// Scan local branches plus tags, optionally including remote branches.
    BranchesAndTags {
        /// Whether remote tracking branches are also included.
        include_remote_branches: bool,
        /// Remote name filter when remote branches are included.
        remote: Option<Vec<u8>>,
    },
    /// Scan a fixed list of fully-qualified refs.
    ExplicitRefs {
        /// Fully-qualified refs such as `b"refs/heads/main"`.
        refs: Vec<Vec<u8>>,
    },
}

impl fmt::Debug for GitRefSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultBranchOnly => f.write_str("DefaultBranchOnly"),
            Self::AllRemoteBranches { remote } => f
                .debug_struct("AllRemoteBranches")
                .field(
                    "remote",
                    &remote
                        .as_ref()
                        .map(|bytes| ToxicDigest::of_bytes(bytes.as_slice())),
                )
                .finish(),
            Self::BranchesAndTags {
                include_remote_branches,
                remote,
            } => f
                .debug_struct("BranchesAndTags")
                .field("include_remote_branches", include_remote_branches)
                .field(
                    "remote",
                    &remote
                        .as_ref()
                        .map(|bytes| ToxicDigest::of_bytes(bytes.as_slice())),
                )
                .finish(),
            Self::ExplicitRefs { refs } => {
                let digests: Vec<_> = refs
                    .iter()
                    .map(|bytes| ToxicDigest::of_bytes(bytes.as_slice()))
                    .collect();
                f.debug_struct("ExplicitRefs")
                    .field("count", &refs.len())
                    .field("digests", &digests)
                    .finish()
            }
        }
    }
}

/// Repo-native Git scan strategy.
///
/// Mirrors the current runtime distinction between diff-history and ODB-blob
/// execution without depending on runtime crates.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitScanMode {
    /// Commit walk + tree diff pipeline.
    DiffHistory,
    /// Unique-blob walk followed by pack-order execution.
    #[default]
    OdbBlobFast,
}

impl fmt::Display for GitScanMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DiffHistory => f.write_str("diff-history"),
            Self::OdbBlobFast => f.write_str("odb-blob"),
        }
    }
}

/// Merge-commit diff strategy for repo-native execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitMergeStrategy {
    /// Diff against every parent and union the resulting blob set.
    #[default]
    AllParents,
    /// Diff only against the first parent.
    FirstParentOnly,
}

/// Repo-native Git scan selection.
///
/// This combines ref selection, scan mode, and merge strategy into one
/// contract-level value.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct GitSelection {
    refs: GitRefSelection,
    scan_mode: GitScanMode,
    merge_strategy: GitMergeStrategy,
}

impl GitSelection {
    /// Construct a repo-native selection tuple.
    #[must_use]
    pub fn new(
        refs: GitRefSelection,
        scan_mode: GitScanMode,
        merge_strategy: GitMergeStrategy,
    ) -> Self {
        Self {
            refs,
            scan_mode,
            merge_strategy,
        }
    }

    /// Borrow the selected ref scope.
    #[inline]
    #[must_use]
    pub fn refs(&self) -> &GitRefSelection {
        &self.refs
    }

    /// Return the repo-native scan mode.
    #[inline]
    #[must_use]
    pub fn scan_mode(&self) -> GitScanMode {
        self.scan_mode
    }

    /// Return the merge-commit diff strategy.
    #[inline]
    #[must_use]
    pub fn merge_strategy(&self) -> GitMergeStrategy {
        self.merge_strategy
    }
}

impl fmt::Debug for GitSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitSelection")
            .field("refs", &self.refs)
            .field("scan_mode", &self.scan_mode)
            .field("merge_strategy", &self.merge_strategy)
            .finish()
    }
}

/// Repository work-unit emitted during Git repo discovery.
///
/// The optional `display_name` is diagnostic metadata only. Discovery ordering
/// and pagination always follow the canonical [`RepoKey`].
#[derive(Clone, PartialEq, Eq)]
pub struct GitRepoTarget {
    repo_key: RepoKey,
    locator: RepoLocator,
    display_name: Option<String>,
}

impl GitRepoTarget {
    /// Construct a discovery target from its canonical key and locator.
    #[must_use]
    pub fn new(repo_key: RepoKey, locator: RepoLocator) -> Self {
        Self {
            repo_key,
            locator,
            display_name: None,
        }
    }

    /// Attach optional diagnostic metadata to the target.
    #[must_use]
    pub fn with_display_name(mut self, display_name: impl Into<String>) -> Self {
        self.display_name = Some(display_name.into());
        self
    }

    /// Borrow the canonical repo key.
    #[inline]
    #[must_use]
    pub fn repo_key(&self) -> &RepoKey {
        &self.repo_key
    }

    /// Borrow the repository locator.
    #[inline]
    #[must_use]
    pub fn locator(&self) -> &RepoLocator {
        &self.locator
    }

    /// Borrow the optional diagnostic display name.
    #[inline]
    #[must_use]
    pub fn display_name(&self) -> Option<&str> {
        self.display_name.as_deref()
    }
}

impl fmt::Debug for GitRepoTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitRepoTarget")
            .field("repo_key", &self.repo_key)
            .field("locator", &self.locator)
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

impl KeyedPageItem for GitRepoTarget {
    #[inline]
    fn item_key(&self) -> &ItemKey {
        self.repo_key.as_item_key()
    }

    #[inline]
    fn size_hint(&self) -> Option<u64> {
        None
    }
}

/// Prepared local mirror or clone ready for repo-native execution.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMirror {
    path: PathBuf,
    last_synced_at_ms: Option<u64>,
}

impl LocalMirror {
    /// Construct a local mirror description for `path`.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            last_synced_at_ms: None,
        }
    }

    /// Attach optional freshness metadata.
    #[must_use]
    pub fn with_last_synced_at_ms(mut self, last_synced_at_ms: u64) -> Self {
        self.last_synced_at_ms = Some(last_synced_at_ms);
        self
    }

    /// Borrow the local mirror path.
    #[inline]
    #[must_use]
    pub fn path(&self) -> &Path {
        self.path.as_path()
    }

    /// Return the optional last-sync timestamp in milliseconds.
    #[inline]
    #[must_use]
    pub fn last_synced_at_ms(&self) -> Option<u64> {
        self.last_synced_at_ms
    }
}

impl fmt::Debug for LocalMirror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalMirror")
            .field(
                "path",
                &ToxicDigest::of_bytes(self.path.to_string_lossy().as_bytes()),
            )
            .field("last_synced_at_ms", &self.last_synced_at_ms)
            .finish()
    }
}

/// Diagnostic verbosity for repo-native Git execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum GitDebugLevel {
    /// No diagnostic output.
    #[default]
    Off,
    /// High-level aggregate statistics.
    Stats,
    /// Detailed per-phase timing and performance counters.
    Perf,
}

/// Resource limits and execution configuration for one Git run.
///
/// These are the contract-level knobs that do not depend on runtime Git types.
/// `Default` is conservative and mirrors the existing runtime defaults where a
/// sensible static default exists.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GitExecutionLimits {
    /// Optional worker override for pack execution.
    pub pack_exec_workers: Option<usize>,
    /// Whether binary blobs should be scanned.
    pub scan_binary: bool,
    /// Whether commit metadata should be enriched with identity data.
    pub enrich_identities: bool,
    /// Diagnostic output level for the execution.
    pub debug_level: GitDebugLevel,
    /// Optional tree-delta cache size override in MiB.
    pub tree_delta_cache_mb: Option<u32>,
    /// Optional engine chunk-size override in MiB.
    pub engine_chunk_mb: Option<u32>,
}

/// High-level counts and timing from one completed Git execution.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GitRunOutcome {
    /// Number of commits traversed in the selected plan.
    pub commit_count: u64,
    /// Number of scanned Git objects or blob work units.
    pub objects_scanned: u64,
    /// Total payload bytes scanned.
    pub bytes_scanned: u64,
    /// Total chunk windows scanned by the engine.
    pub chunks_scanned: u64,
    /// Findings emitted during the run.
    pub findings_emitted: u64,
    /// Non-fatal errors recorded during scanning.
    pub errors: u64,
    /// Aggregate scan-loop time in nanoseconds.
    pub scan_ns: u64,
    /// Aggregate persistence time in nanoseconds.
    pub persist_ns: u64,
}

fn fmt_sanitized_message(f: &mut fmt::Formatter<'_>, message: &str) -> fmt::Result {
    for ch in message.chars() {
        if ch.is_control() && !matches!(ch, '\t' | '\n' | '\r') {
            f.write_str("\u{FFFD}")?;
        } else {
            fmt::Write::write_char(f, ch)?;
        }
    }
    Ok(())
}

/// Repo-native execution or mirroring failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRunError {
    class: ErrorClass,
    message: String,
    retry_after_ms: Option<u64>,
}

impl GitRunError {
    /// Return the retryability classification for this failure.
    #[inline]
    #[must_use]
    pub fn class(&self) -> ErrorClass {
        self.class
    }

    /// Borrow the connector-originated diagnostic message.
    #[inline]
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Return the optional retry hint in milliseconds.
    #[inline]
    #[must_use]
    pub fn retry_after_ms(&self) -> Option<u64> {
        self.retry_after_ms
    }

    /// Return `true` when the error is retryable.
    #[inline]
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        self.class.is_retryable()
    }

    /// Consume the error and return the owned diagnostic message.
    #[inline]
    #[must_use]
    pub fn into_message(self) -> String {
        self.message
    }

    /// Construct a retryable Git run error without a retry hint.
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Construct a retryable Git run error with an advisory retry hint.
    #[must_use]
    pub fn rate_limited(message: impl Into<String>, retry_after_ms: u64) -> Self {
        Self {
            class: ErrorClass::Retryable,
            message: message.into(),
            retry_after_ms: Some(retry_after_ms),
        }
    }

    /// Construct a permanent Git run error.
    #[must_use]
    pub fn permanent(message: impl Into<String>) -> Self {
        Self {
            class: ErrorClass::Permanent,
            message: message.into(),
            retry_after_ms: None,
        }
    }

    /// Construct the standard retryable error for concurrent repository maintenance.
    #[must_use]
    pub fn concurrent_maintenance() -> Self {
        Self::retryable("concurrent git maintenance invalidated repository state")
    }
}

impl fmt::Display for GitRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.class)?;
        fmt_sanitized_message(f, &self.message)?;
        if let Some(retry_after_ms) = self.retry_after_ms {
            write!(f, " (retry_after_ms={retry_after_ms})")?;
        }
        Ok(())
    }
}

impl std::error::Error for GitRunError {}

/// Trait for discovering repository work units in deterministic frontier order.
pub trait GitRepoDiscoverySource: Send {
    /// Return paging features supported by this discovery source.
    fn capabilities(&self) -> PagingCapabilities;

    /// Fill one discovery page of repository work units within `shard`.
    ///
    /// Returns `Ok(Some(page))` with a non-empty page of discovered targets, or
    /// `Ok(None)` to signal terminal completion when no in-scope repositories
    /// remain.
    fn discover_page(
        &mut self,
        shard: &ShardSpec,
        cursor: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<PageBuf<GitRepoTarget>>, EnumerateError>;

    /// Suggest a split point strictly inside the remaining shard suffix.
    ///
    /// Returns `Ok(None)` when the source does not support split hints or has
    /// no suggestion for the current position.
    fn choose_split_point(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError> {
        Ok(None)
    }
}

/// Trait for acquiring or refreshing a local mirror suitable for Git execution.
pub trait GitMirrorManager: Send {
    /// Acquire or refresh a local mirror for `locator`.
    fn sync_mirror(&mut self, locator: &RepoLocator) -> Result<LocalMirror, GitRunError>;
}

/// Trait for whole-repo Git execution against a prepared local mirror.
pub trait GitRepoExecutor: Send {
    /// Execute a repo-native Git scan.
    fn run_repo(
        &mut self,
        mirror: &LocalMirror,
        selection: &GitSelection,
        limits: GitExecutionLimits,
    ) -> Result<GitRunOutcome, GitRunError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_key(bytes: &[u8]) -> RepoKey {
        RepoKey::try_from_slice(bytes).expect("repo key")
    }

    fn repo_locator() -> RepoLocator {
        RepoLocator::local_path("/var/lib/gossip/repos/acme/repo.git")
    }

    fn repo_target(bytes: &[u8]) -> GitRepoTarget {
        GitRepoTarget::new(repo_key(bytes), repo_locator()).with_display_name("acme/repo")
    }

    struct StubDiscovery;

    impl GitRepoDiscoverySource for StubDiscovery {
        fn capabilities(&self) -> PagingCapabilities {
            PagingCapabilities::default()
        }

        fn discover_page(
            &mut self,
            _shard: &ShardSpec,
            _cursor: &Cursor,
            _budgets: Budgets,
        ) -> Result<Option<PageBuf<GitRepoTarget>>, EnumerateError> {
            Err(EnumerateError::permanent("stub"))
        }
    }

    struct StubMirrorManager;

    impl GitMirrorManager for StubMirrorManager {
        fn sync_mirror(&mut self, _locator: &RepoLocator) -> Result<LocalMirror, GitRunError> {
            Err(GitRunError::permanent("stub"))
        }
    }

    struct StubExecutor;

    impl GitRepoExecutor for StubExecutor {
        fn run_repo(
            &mut self,
            _mirror: &LocalMirror,
            _selection: &GitSelection,
            _limits: GitExecutionLimits,
        ) -> Result<GitRunOutcome, GitRunError> {
            Err(GitRunError::permanent("stub"))
        }
    }

    #[test]
    fn repo_key_round_trips_to_item_key() {
        let key = repo_key(b"github.com\0acme\0repo");
        assert_eq!(key.as_bytes(), b"github.com\0acme\0repo");
        assert_eq!(key.as_item_key().as_bytes(), b"github.com\0acme\0repo");
        assert_eq!(
            key.clone().into_item_key().as_bytes(),
            b"github.com\0acme\0repo"
        );
    }

    #[test]
    fn git_repo_target_implements_keyed_page_item() {
        let target = repo_target(b"github.com\0acme\0repo");
        assert_eq!(
            KeyedPageItem::item_key(&target).as_bytes(),
            b"github.com\0acme\0repo"
        );
        assert_eq!(KeyedPageItem::size_hint(&target), None);
    }

    #[test]
    fn git_repo_targets_validate_with_common_page_rules() {
        let page = PageBuf::try_new_validated(
            vec![
                repo_target(b"github.com\0acme\0repo-a"),
                repo_target(b"github.com\0acme\0repo-b"),
            ],
            super::super::PageState::Complete,
            b"github.com\0acme\0repo-0",
            b"github.com\0acme\0repo-z",
        )
        .expect("valid page");

        assert_eq!(page.len(), 2);
        assert!(page.state().is_complete());
    }

    #[test]
    fn repo_locator_debug_redacts_local_path() {
        let debug = format!("{:?}", repo_locator());
        assert!(debug.contains("RepoLocator"));
        assert!(debug.contains("LocalPath"));
        assert!(!debug.contains("/var/lib/gossip/repos/acme/repo.git"));
        assert!(!debug.contains("acme"));
    }

    #[test]
    fn git_selection_debug_redacts_explicit_refs() {
        let selection = GitSelection::new(
            GitRefSelection::ExplicitRefs {
                refs: vec![b"refs/heads/main".to_vec(), b"refs/tags/v1.2.3".to_vec()],
            },
            GitScanMode::DiffHistory,
            GitMergeStrategy::FirstParentOnly,
        );

        let debug = format!("{selection:?}");
        assert!(debug.contains("GitSelection"));
        assert!(debug.contains("ExplicitRefs"));
        assert!(debug.contains("DiffHistory"));
        assert!(debug.contains("FirstParentOnly"));
        assert!(!debug.contains("refs/heads/main"));
        assert!(!debug.contains("refs/tags/v1.2.3"));
    }

    #[test]
    fn local_mirror_debug_redacts_path_and_preserves_freshness_metadata() {
        let mirror = LocalMirror::new("/var/lib/gossip/mirrors/acme/repo.git")
            .with_last_synced_at_ms(1_726_000_000_000);

        let debug = format!("{mirror:?}");
        assert!(debug.contains("LocalMirror"));
        assert!(debug.contains("last_synced_at_ms"));
        assert!(!debug.contains("/var/lib/gossip/mirrors/acme/repo.git"));
        assert!(!debug.contains("acme"));
        assert_eq!(
            mirror.path(),
            Path::new("/var/lib/gossip/mirrors/acme/repo.git")
        );
        assert_eq!(mirror.last_synced_at_ms(), Some(1_726_000_000_000));
    }

    #[test]
    fn git_execution_limits_default_is_conservative() {
        let limits = GitExecutionLimits::default();
        assert_eq!(limits.pack_exec_workers, None);
        assert!(!limits.scan_binary);
        assert!(!limits.enrich_identities);
        assert_eq!(limits.debug_level, GitDebugLevel::Off);
        assert_eq!(limits.tree_delta_cache_mb, None);
        assert_eq!(limits.engine_chunk_mb, None);
    }

    #[test]
    fn git_run_error_constructors_and_display_work() {
        let retryable = GitRunError::retryable("timeout\0please retry");
        let permanent = GitRunError::permanent("auth\u{7f}denied");
        let concurrent = GitRunError::concurrent_maintenance();
        let hinted = GitRunError::rate_limited("busy", 2500);

        assert_eq!(retryable.class(), ErrorClass::Retryable);
        assert_eq!(permanent.class(), ErrorClass::Permanent);
        assert!(retryable.is_retryable());
        assert!(!permanent.is_retryable());
        assert!(concurrent.is_retryable());
        assert_eq!(hinted.retry_after_ms(), Some(2500));
        assert!(concurrent.message().contains("concurrent git maintenance"));

        let retryable_display = format!("{retryable}");
        let permanent_display = format!("{permanent}");
        let hinted_display = format!("{hinted}");
        assert!(retryable_display.starts_with("retryable: "));
        assert!(permanent_display.starts_with("permanent: "));
        assert!(hinted_display.contains("retry_after_ms=2500"));
        assert!(!retryable_display.contains('\0'));
        assert!(!permanent_display.contains('\u{7f}'));
    }

    #[test]
    fn git_family_traits_require_send_and_are_object_safe() {
        fn assert_send<T: Send>() {}
        fn assert_discovery<T: GitRepoDiscoverySource>() {}
        fn assert_mirror<T: GitMirrorManager>() {}
        fn assert_executor<T: GitRepoExecutor>() {}

        assert_send::<StubDiscovery>();
        assert_send::<StubMirrorManager>();
        assert_send::<StubExecutor>();
        assert_discovery::<StubDiscovery>();
        assert_mirror::<StubMirrorManager>();
        assert_executor::<StubExecutor>();

        fn assert_discovery_object_safe(_: &mut dyn GitRepoDiscoverySource) {}
        fn assert_mirror_object_safe(_: &mut dyn GitMirrorManager) {}
        fn assert_executor_object_safe(_: &mut dyn GitRepoExecutor) {}

        let mut discovery = StubDiscovery;
        let mut mirror = StubMirrorManager;
        let mut executor = StubExecutor;
        assert_discovery_object_safe(&mut discovery);
        assert_mirror_object_safe(&mut mirror);
        assert_executor_object_safe(&mut executor);
    }

    #[test]
    fn default_choose_split_point_returns_none() {
        let shard = ShardSpec::unbounded();
        let cursor = Cursor::initial();
        let budgets = Budgets::try_new(1, 1, None).expect("budgets");
        let mut discovery = StubDiscovery;

        assert_eq!(
            discovery
                .choose_split_point(&shard, &cursor, budgets)
                .unwrap(),
            None
        );
    }
}
