//! Git-specific connector family contracts.
//!
//! This module defines the *repo-oriented* connector family used for hosted or
//! local Git code content. It intentionally separates:
//!
//! - repo frontier discovery ([`GitRepoDiscoverySource`])
//! - local mirror/cache synchronization ([`GitMirrorManager`])
//! - repo-native execution ([`GitRepoExecutor`])
//!
//! ## Why a separate family?
//!
//! The existing `scanner-git` crate is already a repo-native execution engine
//! with start-set selection, watermark persistence, seen stores, finalize, and
//! persist stages. Flattening that into `ScanItem/open/read_range` would throw
//! away useful structure and force an inferior abstraction on Git code scans.
//!
//! ## Typical flow
//!
//! 1. A [`GitRepoDiscoverySource`] pages over [`GitRepoTarget`] values in
//!    deterministic frontier order.
//! 2. A [`GitMirrorManager`] ensures the target repo exists locally and is
//!    sufficiently up to date for execution.
//! 3. A [`GitRepoExecutor`] runs repo-native scanning against the resulting
//!    [`LocalMirror`].
//!
//! ## Progress ownership
//!
//! - Outer distributed progress is the repo frontier cursor over [`RepoKey`].
//! - Inner Git progress remains repo-native and is owned by the executor's
//!   backing engine (for example, `scanner-git` watermarks and seen stores).
//!
//! This split keeps leasing/checkpointing simple at the outer layer without
//! forcing Git history traversal into an item-at-a-time content model.

use std::{error::Error, fmt, path::{Path, PathBuf}};

use crate::coordination::ShardSpec;

use super::{Budgets, Cursor, EnumerateError, ItemKey};
use super::common::{KeyedPageItem, PageBuf, PageState, PagingCapabilities};
use super::types::ToxicDigest;

/// Hosted Git provider kind for repo discovery and canonical locator metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GitProvider {
    Github,
    Gitlab,
    Gerrit,
    Generic,
}

/// Frontier key for Git repo discovery work units.
///
/// This is a thin semantic newtype around [`ItemKey`]. It exists so Git repo
/// discovery can speak in repo-target terms without overloading raw item keys
/// everywhere in signatures and documentation.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RepoKey(ItemKey);

impl RepoKey {
    /// Construct a repo key from an already-validated ordered key.
    #[inline]
    #[must_use]
    pub fn new(inner: ItemKey) -> Self {
        Self(inner)
    }

    /// Validate and construct a repo key from raw bytes.
    #[inline]
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self, super::ConnectorInputError> {
        Ok(Self(ItemKey::try_from_slice(bytes)?))
    }

    /// Borrow the underlying ordered key.
    #[inline]
    #[must_use]
    pub fn as_item_key(&self) -> &ItemKey {
        &self.0
    }

    /// Consume into the underlying ordered key.
    #[inline]
    #[must_use]
    pub fn into_item_key(self) -> ItemKey {
        self.0
    }

    /// Borrow the raw bytes of the underlying key.
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
        write!(f, "RepoKey({})", self.0)
    }
}

impl fmt::Display for RepoKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RepoKey({})", self.0)
    }
}

/// Canonical repo locator used by Git discovery and mirror management.
///
/// The string fields here are source-derived and may contain tenant/customer
/// identifiers. `Debug` is therefore explicitly redacted via [`ToxicDigest`]
/// rather than deriving raw string formatting.
#[derive(Clone, PartialEq, Eq)]
pub struct RepoLocator {
    provider: GitProvider,
    canonical_host: String,
    canonical_namespace: String,
    canonical_name: String,
    canonical_remote: String,
}

impl RepoLocator {
    #[must_use]
    pub fn new(
        provider: GitProvider,
        canonical_host: String,
        canonical_namespace: String,
        canonical_name: String,
        canonical_remote: String,
    ) -> Self {
        Self {
            provider,
            canonical_host,
            canonical_namespace,
            canonical_name,
            canonical_remote,
        }
    }

    #[must_use]
    pub fn provider(&self) -> GitProvider {
        self.provider
    }

    #[must_use]
    pub fn canonical_host(&self) -> &str {
        &self.canonical_host
    }

    #[must_use]
    pub fn canonical_namespace(&self) -> &str {
        &self.canonical_namespace
    }

    #[must_use]
    pub fn canonical_name(&self) -> &str {
        &self.canonical_name
    }

    #[must_use]
    pub fn canonical_remote(&self) -> &str {
        &self.canonical_remote
    }
}

impl fmt::Debug for RepoLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RepoLocator")
            .field("provider", &self.provider)
            .field(
                "canonical_host",
                &ToxicDigest::of_bytes(self.canonical_host.as_bytes()),
            )
            .field(
                "canonical_namespace",
                &ToxicDigest::of_bytes(self.canonical_namespace.as_bytes()),
            )
            .field(
                "canonical_name",
                &ToxicDigest::of_bytes(self.canonical_name.as_bytes()),
            )
            .field(
                "canonical_remote",
                &ToxicDigest::of_bytes(self.canonical_remote.as_bytes()),
            )
            .finish()
    }
}

/// Repo selection policy for Git execution.
///
/// This is intentionally repo-native. It expresses *what subset of a repo to
/// scan*, not how to enumerate bytes like an ordered content source would.
#[derive(Clone, PartialEq, Eq)]
pub enum GitSelection {
    DefaultBranchOnly,
    AllRemoteBranches,
    BranchesAndTags,
    ExplicitRefs(Vec<String>),
    ExplicitCommits(Vec<String>),
}

impl fmt::Debug for GitSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DefaultBranchOnly => f.write_str("DefaultBranchOnly"),
            Self::AllRemoteBranches => f.write_str("AllRemoteBranches"),
            Self::BranchesAndTags => f.write_str("BranchesAndTags"),
            Self::ExplicitRefs(refs) => {
                let digests: Vec<_> = refs
                    .iter()
                    .map(|r| ToxicDigest::of_bytes(r.as_bytes()))
                    .collect();
                f.debug_struct("ExplicitRefs")
                    .field("count", &refs.len())
                    .field("digests", &digests)
                    .finish()
            }
            Self::ExplicitCommits(commits) => {
                let digests: Vec<_> = commits
                    .iter()
                    .map(|c| ToxicDigest::of_bytes(c.as_bytes()))
                    .collect();
                f.debug_struct("ExplicitCommits")
                    .field("count", &commits.len())
                    .field("digests", &digests)
                    .finish()
            }
        }
    }
}

/// Repo-discovery work unit.
///
/// This is the page item for the Git discovery family: a deterministic target
/// key, a canonical repo locator, and the repo-native selection to execute.
#[derive(Clone, PartialEq, Eq)]
pub struct GitRepoTarget {
    target_key: RepoKey,
    locator: RepoLocator,
    selection: GitSelection,
}

impl GitRepoTarget {
    #[must_use]
    pub fn new(target_key: RepoKey, locator: RepoLocator, selection: GitSelection) -> Self {
        Self {
            target_key,
            locator,
            selection,
        }
    }

    #[must_use]
    pub fn target_key(&self) -> &RepoKey {
        &self.target_key
    }

    #[must_use]
    pub fn locator(&self) -> &RepoLocator {
        &self.locator
    }

    #[must_use]
    pub fn selection(&self) -> &GitSelection {
        &self.selection
    }
}

impl fmt::Debug for GitRepoTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitRepoTarget")
            .field("target_key", &self.target_key)
            .field("locator", &self.locator)
            .field("selection", &self.selection)
            .finish()
    }
}

impl KeyedPageItem for GitRepoTarget {
    fn page_key(&self) -> &ItemKey {
        self.target_key.as_item_key()
    }
}

/// On-disk local mirror or bare repo path used for Git execution.
#[derive(Clone, PartialEq, Eq)]
pub struct LocalMirror {
    path: PathBuf,
}

impl LocalMirror {
    #[must_use]
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for LocalMirror {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let digest = ToxicDigest::of_bytes(self.path.to_string_lossy().as_bytes());
        f.debug_struct("LocalMirror")
            .field("path", &digest)
            .finish()
    }
}

/// Execution limits supplied to a Git repo executor.
///
/// This stays intentionally small in the contract layer. Additional tuning can
/// be added later without changing the family split.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GitExecutionLimits {
    max_wall_clock_secs: Option<u64>,
}

impl GitExecutionLimits {
    #[must_use]
    pub fn new(max_wall_clock_secs: Option<u64>) -> Self {
        Self { max_wall_clock_secs }
    }

    #[must_use]
    pub fn max_wall_clock_secs(&self) -> Option<u64> {
        self.max_wall_clock_secs
    }
}

/// High-level result of one repo-native Git execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GitRunOutcome {
    committed: bool,
    full: bool,
}

impl GitRunOutcome {
    #[must_use]
    pub fn new(committed: bool, full: bool) -> Self {
        Self { committed, full }
    }

    #[must_use]
    pub fn committed(&self) -> bool {
        self.committed
    }

    #[must_use]
    pub fn full(&self) -> bool {
        self.full
    }
}

/// Git-family execution/synchronization error.
#[derive(Clone, PartialEq, Eq)]
pub enum GitRunError {
    Retryable(String),
    Fatal(String),
}

impl GitRunError {
    #[must_use]
    pub fn retryable(message: impl Into<String>) -> Self {
        Self::Retryable(message.into())
    }

    #[must_use]
    pub fn fatal(message: impl Into<String>) -> Self {
        Self::Fatal(message.into())
    }

    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Retryable(_))
    }

    #[must_use]
    pub fn message(&self) -> &str {
        match self {
            Self::Retryable(message) | Self::Fatal(message) => message,
        }
    }

    #[must_use]
    pub fn into_message(self) -> String {
        match self {
            Self::Retryable(message) | Self::Fatal(message) => message,
        }
    }
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

impl fmt::Display for GitRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Retryable(message) => {
                f.write_str("retryable: ")?;
                fmt_sanitized_message(f, message)
            }
            Self::Fatal(message) => {
                f.write_str("fatal: ")?;
                fmt_sanitized_message(f, message)
            }
        }
    }
}

impl fmt::Debug for GitRunError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Error for GitRunError {}

/// Repo frontier discovery family.
///
/// This family pages over repo-oriented work units and is used for hosted Git
/// providers (GitHub/GitLab/Gerrit), explicit repo lists, and single-repo
/// sources. It does not read bytes and does not execute scans directly.
pub trait GitRepoDiscoverySource: Send {
    fn capabilities(&self) -> PagingCapabilities;

    fn fill_page(
        &mut self,
        shard: &ShardSpec,
        after: &Cursor,
        budgets: Budgets,
        out: &mut PageBuf<GitRepoTarget>,
    ) -> Result<PageState, EnumerateError>;

    fn choose_split_point(
        &mut self,
        shard: &ShardSpec,
        after: &Cursor,
        budgets: Budgets,
    ) -> Result<Option<ItemKey>, EnumerateError>;
}

/// Local mirror/cache synchronization family for Git repos.
pub trait GitMirrorManager: Send {
    fn sync_mirror(&mut self, target: &GitRepoTarget) -> Result<LocalMirror, GitRunError>;
}

/// Repo-native Git execution family.
///
/// Implementations adapt repo targets and local mirrors into a repo execution
/// engine (for example `scanner-git`) rather than flattening Git into
/// `ScanItem/open/read_range`.
pub trait GitRepoExecutor: Send {
    fn run_repo(
        &mut self,
        mirror: &LocalMirror,
        target: &GitRepoTarget,
        limits: &GitExecutionLimits,
    ) -> Result<GitRunOutcome, GitRunError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn repo_key(bytes: &[u8]) -> RepoKey {
        RepoKey::try_from_slice(bytes).expect("repo key")
    }

    fn locator() -> RepoLocator {
        RepoLocator::new(
            GitProvider::Github,
            "github.com".to_owned(),
            "acme".to_owned(),
            "roadrunner".to_owned(),
            "https://github.com/acme/roadrunner.git".to_owned(),
        )
    }

    fn target(seed: &[u8]) -> GitRepoTarget {
        GitRepoTarget::new(
            repo_key(seed),
            locator(),
            GitSelection::DefaultBranchOnly,
        )
    }

    fn budgets(max_items: usize) -> Budgets {
        Budgets::try_new(max_items, 1024, None).expect("budgets")
    }

    #[test]
    fn repo_key_round_trips_to_item_key() {
        let key = repo_key(b"github.com\0acme\0roadrunner");
        assert_eq!(key.as_item_key().as_bytes(), b"github.com\0acme\0roadrunner");
        assert_eq!(key.into_item_key().as_bytes(), b"github.com\0acme\0roadrunner");
    }

    #[test]
    fn git_repo_target_validates_with_common_page_rules() {
        let shard = ShardSpec::with_range(b"github.com\0a", b"github.com\0z");
        let mut out = PageBuf::new();
        out.push(target(b"github.com\0acme\0repo-a"));
        out.push(target(b"github.com\0acme\0repo-b"));
        let state = PageState::Progress {
            next_cursor: Cursor::with_last_key(
                repo_key(b"github.com\0acme\0repo-b").into_item_key(),
            ),
            exhausted: false,
        };

        let result = super::super::common::validate_filled_page(
            &out,
            &state,
            &shard,
            &Cursor::with_last_key(repo_key(b"github.com\0acme\0repo-0").into_item_key()),
            PagingCapabilities::new(true, false, true),
            budgets(8),
        );

        assert_eq!(result, Ok(()));
    }

    #[test]
    fn repo_locator_debug_is_redacted() {
        let debug = format!("{:?}", locator());
        assert!(!debug.contains("github.com"));
        assert!(!debug.contains("acme"));
        assert!(!debug.contains("roadrunner"));
        assert!(!debug.contains("https://github.com/acme/roadrunner.git"));
        assert!(debug.contains("RepoLocator"));
    }

    #[test]
    fn git_selection_debug_is_redacted() {
        let selection = GitSelection::ExplicitRefs(vec![
            "refs/heads/main".to_owned(),
            "refs/tags/v1.2.3".to_owned(),
        ]);
        let debug = format!("{:?}", selection);
        assert!(!debug.contains("refs/heads/main"));
        assert!(!debug.contains("refs/tags/v1.2.3"));
        assert!(debug.contains("ExplicitRefs"));
        assert!(debug.contains("count"));
    }

    #[test]
    fn local_mirror_debug_is_redacted() {
        let mirror = LocalMirror::new(PathBuf::from("/var/lib/gossip/mirrors/github.com/acme/repo.git"));
        let debug = format!("{:?}", mirror);
        assert!(!debug.contains("/var/lib/gossip"));
        assert!(!debug.contains("github.com"));
        assert!(debug.contains("LocalMirror"));
    }

    #[test]
    fn git_run_error_classification_and_display_work() {
        let retryable = GitRunError::retryable("timeout\0please retry");
        let fatal = GitRunError::fatal("auth\u{7f}denied");

        assert!(retryable.is_retryable());
        assert!(!fatal.is_retryable());
        assert_eq!(retryable.message(), "timeout\0please retry");
        assert_eq!(fatal.message(), "auth\u{7f}denied");

        let retryable_display = format!("{retryable}");
        let fatal_display = format!("{fatal}");
        assert!(retryable_display.starts_with("retryable: "));
        assert!(fatal_display.starts_with("fatal: "));
        assert!(!retryable_display.contains('\0'));
        assert!(!fatal_display.contains('\u{7f}'));
    }
}
