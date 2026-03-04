//! Native git-reference resolver backed by `gix-ref`.
//!
//! This module translates a [`StartSetConfig`] into concrete `(ref_name, tip_oid)`
//! pairs by reading the repository's loose refs and `packed-refs` store directly,
//! avoiding the `git` CLI entirely. The resolved pairs feed into the scan
//! pipeline as the initial commit set ("start set") for object traversal.
//!
//! # Algorithm
//!
//! 1. Open a [`gix_ref::file::Store`] for the repository (handling linked
//!    worktrees by providing both `git_dir` and `common_dir`).
//! 2. Snapshot the packed-refs buffer once; all lookups share this snapshot
//!    for consistency within a single resolve call.
//! 3. Dispatch by [`StartSetConfig`] variant:
//!    - **`DefaultBranchOnly`** — resolve `HEAD` (symbolic or direct).
//!    - **`ExplicitRefs`** — look up each named ref; error if any is missing.
//!    - **`AllRemoteBranches` / `BranchesAndTags`** — iterate all refs and
//!      apply a prefix filter.
//!
//! # Edge Cases
//!
//! - **Unborn HEAD** (repo initialised but no commits): returns an empty start
//!   set rather than an error, so the scanner gracefully skips the repo.
//! - **Detached HEAD**: the returned ref name is literally `HEAD`, not the
//!   branch it was detached from.
//! - **Linked worktrees**: the ref store is opened with both per-worktree
//!   `git_dir` and shared `common_dir` so worktree-specific refs (like HEAD)
//!   resolve correctly while shared refs (branches, tags) are still visible.

use std::io;

use gix_ref::bstr::ByteSlice;
use gix_ref::file::ReferenceExt;

use crate::repo_open::detect_object_format;
use crate::{
    GitRepoPaths, ObjectFormat, OidBytes, RepoOpenError, RepoOpenLimits, StartSetConfig,
    StartSetResolver,
};

const REFS_HEADS_PREFIX: &[u8] = b"refs/heads/";
const REFS_TAGS_PREFIX: &[u8] = b"refs/tags/";
const REFS_REMOTES_PREFIX: &[u8] = b"refs/remotes/";

/// Resolves start-set refs using the native `gix-ref` reference store.
///
/// Constructed once per scan job with an immutable [`StartSetConfig`] and then
/// called via [`StartSetResolver::resolve`] against the target repository's
/// [`GitRepoPaths`]. The resolver is stateless — all I/O happens inside
/// `resolve`, so the struct is cheaply cloneable across threads.
#[derive(Clone, Debug)]
pub struct NativeRefResolver {
    start_set: StartSetConfig,
}

impl NativeRefResolver {
    /// Create a resolver for the given start-set configuration.
    #[must_use]
    pub fn new(start_set: StartSetConfig) -> Self {
        Self { start_set }
    }
}

impl StartSetResolver for NativeRefResolver {
    /// Resolves refs for the configured start set against the given repository.
    ///
    /// Returns `(ref_name, tip_oid)` pairs. The ref name is the
    /// fully-qualified name (e.g. `refs/heads/main`) except for detached HEAD,
    /// where it is literally `HEAD`.
    ///
    /// # Errors
    ///
    /// Returns [`RepoOpenError`] if the ref store cannot be opened, the
    /// packed-refs file is corrupt, or (for `ExplicitRefs`) a requested ref
    /// does not exist.
    fn resolve(&self, paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        let store = open_ref_store(paths)?;
        // Snapshot packed-refs once so every lookup within this call sees a
        // consistent view, even if `git pack-refs` runs concurrently.
        let packed_snapshot = store
            .cached_packed_buffer()
            .map_err(|err| gix_error("open packed refs", err))?;
        let packed = packed_snapshot.as_ref().map(|snapshot| &***snapshot);

        match &self.start_set {
            StartSetConfig::DefaultBranchOnly => resolve_default_branch(&store, packed),
            StartSetConfig::ExplicitRefs { refs } => resolve_explicit_refs(&store, packed, refs),
            StartSetConfig::AllRemoteBranches { remote } => {
                collect_matching_refs(&store, packed, |name| {
                    remote_matches(name, remote.as_deref())
                })
            }
            StartSetConfig::BranchesAndTags {
                include_remote_branches,
                remote,
            } => collect_matching_refs(&store, packed, |name| {
                name.starts_with(REFS_HEADS_PREFIX)
                    || name.starts_with(REFS_TAGS_PREFIX)
                    || (*include_remote_branches && remote_matches(name, remote.as_deref()))
            }),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingSymbolicTarget {
    /// Treat a missing symbolic target as an empty start set (used for unborn HEAD).
    ReturnEmpty,
    /// Surface missing symbolic targets as hard errors.
    Error,
}

/// Resolve HEAD to a single `(ref_name, tip_oid)` pair.
///
/// Three cases:
/// - **Symbolic HEAD** (normal branch): follows `HEAD -> refs/heads/main`; the
///   returned name is the branch ref, not `HEAD`.
/// - **Detached HEAD**: HEAD points directly at an OID; the returned name is
///   `HEAD`.
/// - **Unborn HEAD** (empty repo): HEAD is symbolic but the target branch does
///   not exist yet. Returns an empty vec rather than an error so the scanner
///   can skip the repo gracefully.
fn resolve_default_branch(
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let Some(mut head) = store
        .try_find("HEAD")
        .map_err(|err| gix_error("resolve HEAD", err))?
    else {
        return Ok(Vec::new());
    };

    let Some(tip) = resolve_tip(&mut head, store, packed, MissingSymbolicTarget::ReturnEmpty)?
    else {
        // Unborn HEAD — symbolic target does not exist.
        return Ok(Vec::new());
    };

    Ok(vec![(head.name.as_bstr().to_vec(), tip)])
}

/// Look up each explicitly-named ref and resolve its tip OID.
///
/// Unlike the wildcard variants, this is strict: a missing or dangling ref
/// is a hard error because the caller specifically asked for it.
///
/// The *configured* ref name (not the store's canonical name) is returned
/// in the output tuple so that watermark keys remain stable across renames
/// of the underlying symbolic chain.
fn resolve_explicit_refs(
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
    refs: &[Vec<u8>],
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let mut out = Vec::with_capacity(refs.len());

    for requested_name in refs {
        let Some(mut reference) = store
            .try_find(requested_name.as_bstr())
            .map_err(|err| gix_error("resolve explicit ref", err))?
        else {
            return Err(RepoOpenError::io(io::Error::other(format!(
                "reference not found: {}",
                String::from_utf8_lossy(requested_name)
            ))));
        };
        let Some(tip) = resolve_tip(&mut reference, store, packed, MissingSymbolicTarget::Error)?
        else {
            return Err(RepoOpenError::io(io::Error::other(format!(
                "reference has no reachable tip: {}",
                String::from_utf8_lossy(requested_name)
            ))));
        };
        // Preserve the configured ref name to keep watermark keys stable for explicit selectors.
        out.push((requested_name.clone(), tip));
    }

    Ok(out)
}

/// Iterate all refs in the store and collect those accepted by `matches`.
///
/// Used by the wildcard config variants (`AllRemoteBranches`,
/// `BranchesAndTags`) where the set of matching refs is not known ahead of
/// time. The ref name is captured *before* symbolic-ref resolution so the
/// output names match what the caller's filter saw.
///
/// A dangling symbolic ref in this path is a hard error (unlike
/// `resolve_default_branch`, where unborn HEAD is tolerated).
fn collect_matching_refs(
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
    matches: impl Fn(&[u8]) -> bool,
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let platform = store.iter().map_err(|err| gix_error("iterate refs", err))?;
    let iter = platform
        .all()
        .map_err(|err| gix_error("iterate refs", err))?;

    let mut out = Vec::new();
    for entry in iter {
        let mut reference = entry.map_err(|err| gix_error("iterate refs", err))?;
        // Capture the name before following symbolic refs — the filter operates
        // on the reference's own name, not the target it may point to.
        let ref_name = reference.name.as_bstr().to_vec();
        if !matches(&ref_name) {
            continue;
        }
        let Some(tip) = resolve_tip(&mut reference, store, packed, MissingSymbolicTarget::Error)?
        else {
            return Err(RepoOpenError::io(io::Error::other(format!(
                "reference has no reachable tip: {}",
                String::from_utf8_lossy(&ref_name)
            ))));
        };
        out.push((ref_name, tip));
    }

    Ok(out)
}

/// Resolve a reference to its final commit OID.
///
/// Two resolution paths:
/// 1. **Direct ref** — `target` is already an OID; return it immediately.
/// 2. **Symbolic ref** — follow the chain (`HEAD -> refs/heads/main -> OID`)
///    using `follow_to_object_packed`, which checks both loose files and the
///    packed-refs snapshot.
///
/// When the symbolic target does not exist (e.g. unborn HEAD pointing at a
/// branch with no commits), `missing_symbolic` controls the behavior:
/// - [`MissingSymbolicTarget::ReturnEmpty`] — return `Ok(None)`.
/// - [`MissingSymbolicTarget::Error`] — propagate the error.
fn resolve_tip(
    reference: &mut gix_ref::Reference,
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
    missing_symbolic: MissingSymbolicTarget,
) -> Result<Option<OidBytes>, RepoOpenError> {
    // Fast path: reference already points at an OID (detached HEAD or
    // packed ref with inlined target).
    if let Some(id) = reference.target.try_id() {
        return Ok(Some(oid_from_hash(id.as_bytes())));
    }

    // Slow path: follow the symbolic chain through the store.
    match reference.follow_to_object_packed(store, packed) {
        Ok(id) => Ok(Some(oid_from_hash(id.as_bytes()))),
        Err(gix_ref::peel::to_object::Error::Follow(
            gix_ref::file::find::existing::Error::NotFound { .. },
        )) if missing_symbolic == MissingSymbolicTarget::ReturnEmpty => Ok(None),
        Err(err) => Err(gix_error("resolve symbolic ref target", err)),
    }
}

/// Test whether `name` is a remote-tracking branch, optionally scoped to a
/// specific remote.
///
/// When `remote` is `None`, any ref under `refs/remotes/` matches. When
/// `Some(b"origin")`, only `refs/remotes/origin/<branch>` matches. The
/// trailing `/` check prevents `refs/remotes/origin-fork/main` from matching
/// when the filter is `origin`.
fn remote_matches(name: &[u8], remote: Option<&[u8]>) -> bool {
    if !name.starts_with(REFS_REMOTES_PREFIX) {
        return false;
    }

    match remote {
        None => true,
        Some(remote_name) => {
            let suffix = &name[REFS_REMOTES_PREFIX.len()..];
            // Require an exact remote-name segment followed by `/` to avoid
            // prefix collisions (e.g. "origin" must not match "origin-fork").
            suffix.starts_with(remote_name) && suffix.get(remote_name.len()) == Some(&b'/')
        }
    }
}

/// Open a `gix_ref::file::Store` appropriate for the repository layout.
///
/// Linked worktrees have a per-worktree `git_dir` (containing `HEAD` and
/// worktree-specific refs) plus a shared `common_dir` (containing branches,
/// tags, and packed-refs). Normal repos and bare repos only need `git_dir`.
fn open_ref_store(paths: &GitRepoPaths) -> Result<gix_ref::file::Store, RepoOpenError> {
    let options = gix_store_options(paths)?;
    Ok(if paths.is_linked_worktree() {
        gix_ref::file::Store::for_linked_worktree(
            paths.git_dir.clone(),
            paths.common_dir.clone(),
            options,
        )
    } else {
        gix_ref::file::Store::at(paths.git_dir.clone(), options)
    })
}

/// Build store options from the detected object format.
///
/// Reflogs are disabled because the scanner is read-only and never creates
/// refs. `precompose_unicode` is left off because ref names are treated as
/// opaque bytes throughout the scan pipeline.
fn gix_store_options(paths: &GitRepoPaths) -> Result<gix_ref::store::init::Options, RepoOpenError> {
    let object_hash = map_object_format(detect_object_format(paths, &RepoOpenLimits::default())?);
    Ok(gix_ref::store::init::Options {
        write_reflog: gix_ref::store::WriteReflog::Disable,
        object_hash,
        precompose_unicode: false,
        prohibit_windows_device_names: false,
    })
}

fn map_object_format(format: ObjectFormat) -> gix_hash::Kind {
    match format {
        ObjectFormat::Sha1 => gix_hash::Kind::Sha1,
        ObjectFormat::Sha256 => gix_hash::Kind::Sha256,
    }
}

#[inline]
fn oid_from_hash(bytes: &[u8]) -> OidBytes {
    OidBytes::from_slice(bytes)
}

fn gix_error(context: &str, err: impl std::fmt::Display) -> RepoOpenError {
    RepoOpenError::io(io::Error::other(format!("{context}: {err}")))
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};
    use std::process::Command;

    use rstest::rstest;

    use super::*;

    fn init_repo(tmp: &tempfile::TempDir) -> PathBuf {
        let output = Command::new("git")
            .args(["init", "--initial-branch=main"])
            .arg(tmp.path())
            .output()
            .expect("git init");
        assert!(
            output.status.success(),
            "git init failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let repo = tmp.path().to_path_buf();
        git(&repo, &["config", "user.name", "test-user"]);
        git(&repo, &["config", "user.email", "test@example.com"]);
        repo
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .expect("run git command");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("utf-8 stdout")
            .trim()
            .to_owned()
    }

    fn resolve_default(repo: &Path) -> Vec<(Vec<u8>, OidBytes)> {
        let resolver = NativeRefResolver::new(StartSetConfig::DefaultBranchOnly);
        let paths = GitRepoPaths::resolve::<RepoOpenError, _>(repo, &RepoOpenLimits::default())
            .expect("resolve paths");
        resolver.resolve(&paths).expect("resolve default branch")
    }

    fn parse_oid(hex: &str) -> OidBytes {
        let id = gix_hash::ObjectId::from_hex(hex.as_bytes()).expect("hex object id");
        OidBytes::from_slice(id.as_bytes())
    }

    #[test]
    fn object_format_maps_to_gix_hash_kind() {
        assert_eq!(map_object_format(ObjectFormat::Sha1), gix_hash::Kind::Sha1);
        assert_eq!(
            map_object_format(ObjectFormat::Sha256),
            gix_hash::Kind::Sha256
        );
    }

    #[test]
    fn default_branch_resolves_current_branch_tip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = init_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);

        let resolved = resolve_default(&repo);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, b"refs/heads/main".to_vec());
        assert_eq!(
            resolved[0].1,
            parse_oid(&git(&repo, &["rev-parse", "refs/heads/main"]))
        );
    }

    #[test]
    fn detached_head_resolves_head_tip() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = init_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        git(&repo, &["checkout", "--detach", "HEAD"]);

        let resolved = resolve_default(&repo);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, b"HEAD".to_vec());
        assert_eq!(
            resolved[0].1,
            parse_oid(&git(&repo, &["rev-parse", "HEAD"]))
        );
    }

    #[test]
    fn empty_repo_returns_empty_start_set() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = init_repo(&tmp);
        let resolved = resolve_default(&repo);
        assert!(resolved.is_empty());
    }

    // -- remote_matches -------------------------------------------------

    #[rstest]
    #[case::non_remote_ref(b"refs/heads/main".as_slice(), None, false)]
    #[case::tag_ref(b"refs/tags/v1.0".as_slice(), None, false)]
    #[case::any_remote_no_filter(b"refs/remotes/origin/main".as_slice(), None, true)]
    #[case::matching_remote(
        b"refs/remotes/origin/main".as_slice(),
        Some(b"origin".as_slice()),
        true,
    )]
    #[case::non_matching_remote(
        b"refs/remotes/upstream/main".as_slice(),
        Some(b"origin".as_slice()),
        false,
    )]
    #[case::prefix_collision_no_slash(
        b"refs/remotes/origin-fork/main".as_slice(),
        Some(b"origin".as_slice()),
        false,
    )]
    #[case::bare_remote_no_branch(
        b"refs/remotes/origin".as_slice(),
        Some(b"origin".as_slice()),
        false,
    )]
    fn remote_matches_cases(
        #[case] name: &[u8],
        #[case] remote: Option<&[u8]>,
        #[case] expected: bool,
    ) {
        assert_eq!(remote_matches(name, remote), expected);
    }
}
