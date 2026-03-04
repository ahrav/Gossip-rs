//! Native git-reference resolver backed by `gix-ref`.
//!
//! This resolver avoids invoking the `git` CLI and reads references directly
//! from the repository's loose refs and `packed-refs` store.

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
    fn resolve(&self, paths: &GitRepoPaths) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        let store = open_ref_store(paths)?;
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
        return Ok(Vec::new());
    };

    Ok(vec![(head.name.as_bstr().to_vec(), tip)])
}

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
        // Preserve the selected reference name; only the tip OID may change
        // when symbolic refs are followed.
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

fn resolve_tip(
    reference: &mut gix_ref::Reference,
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
    missing_symbolic: MissingSymbolicTarget,
) -> Result<Option<OidBytes>, RepoOpenError> {
    if let Some(id) = reference.target.try_id() {
        return Ok(Some(oid_from_hash(id.as_bytes())));
    }

    match reference.follow_to_object_packed(store, packed) {
        Ok(id) => Ok(Some(oid_from_hash(id.as_bytes()))),
        Err(gix_ref::peel::to_object::Error::Follow(
            gix_ref::file::find::existing::Error::NotFound { .. },
        )) if missing_symbolic == MissingSymbolicTarget::ReturnEmpty => Ok(None),
        Err(err) => Err(gix_error("resolve symbolic ref target", err)),
    }
}

fn remote_matches(name: &[u8], remote: Option<&[u8]>) -> bool {
    if !name.starts_with(REFS_REMOTES_PREFIX) {
        return false;
    }

    match remote {
        None => true,
        Some(remote_name) => {
            let suffix = &name[REFS_REMOTES_PREFIX.len()..];
            suffix.starts_with(remote_name) && suffix.get(remote_name.len()) == Some(&b'/')
        }
    }
}

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
}
