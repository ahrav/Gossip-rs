//! Native git-reference resolver backed by `gix-ref`.
//!
//! This module translates a [`StartSetConfig`] into concrete `(ref_name, tip_oid)`
//! pairs by reading the repository's loose refs and `packed-refs` store directly,
//! avoiding the `git` CLI entirely. The resolved pairs feed into the scan
//! pipeline as the initial commit set ("start set") for object traversal.
//!
//! Synthetic commit-ref materialization (the write path) lives in the sibling
//! [`crate::synthetic_ref`] module. This module provides [`open_ref_store`] as
//! shared infrastructure for both reading and writing refs.
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
//! - **Annotated tags**: resolved OIDs are peeled through tag objects to the
//!   underlying non-tag object. The fast path reads peeled OIDs from `packed-refs`
//!   (`^` lines); the slow path decompresses loose tag objects and follows
//!   the `object` header. Nested tags are followed up to a depth limit.

use std::io::{self, Read as _};
use std::path::Path;

use flate2::bufread::ZlibDecoder;
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
    limits: RepoOpenLimits,
}

impl NativeRefResolver {
    /// Create a resolver for the given start-set configuration.
    #[must_use]
    pub fn new(start_set: StartSetConfig) -> Self {
        Self {
            start_set,
            limits: RepoOpenLimits::default(),
        }
    }

    /// Create a resolver that uses the provided repo-open limits for config
    /// file reads.
    #[must_use]
    pub fn with_limits(start_set: StartSetConfig, limits: RepoOpenLimits) -> Self {
        Self { start_set, limits }
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
        let store = open_ref_store(paths, &self.limits)?;
        // Snapshot packed-refs once so every lookup within this call sees a
        // consistent view, even if `git pack-refs` runs concurrently.
        let packed_snapshot = store
            .cached_packed_buffer()
            .map_err(|err| gix_error("open packed refs", err))?;
        // Unwrap the triple indirection: `Option<&SharedBufferSnapshot>` where
        // `SharedBufferSnapshot` derefs to `&Buffer` which derefs to the inner
        // packed-refs data. The result is `Option<&packed::Buffer>` expected by
        // all downstream lookup functions.
        let packed = packed_snapshot.as_ref().map(|snapshot| &***snapshot);

        match &self.start_set {
            StartSetConfig::DefaultBranchOnly => resolve_default_branch(&store, packed, paths),
            StartSetConfig::ExplicitRefs { refs } => {
                resolve_explicit_refs(&store, packed, refs, paths)
            }
            StartSetConfig::AllRemoteBranches { remote } => {
                collect_matching_refs(&store, packed, paths, |name| {
                    remote_matches(name, remote.as_deref())
                })
            }
            StartSetConfig::BranchesAndTags {
                include_remote_branches,
                remote,
            } => collect_matching_refs(&store, packed, paths, |name| {
                name.starts_with(REFS_HEADS_PREFIX)
                    || name.starts_with(REFS_TAGS_PREFIX)
                    || (*include_remote_branches && remote_matches(name, remote.as_deref()))
            }),
        }
    }
}

/// Controls how [`resolve_tip`] handles a symbolic ref whose target does not
/// exist (e.g. `HEAD -> refs/heads/main` when `refs/heads/main` has no object).
///
/// The two modes partition callers into "best-effort" (wildcard iteration,
/// unborn HEAD) and "strict" (explicit user-supplied ref names) categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum MissingSymbolicTarget {
    /// Treat a missing symbolic target as an empty start set (used for unborn
    /// HEAD and dangling refs during wildcard iteration).
    ReturnEmpty,
    /// Surface missing symbolic targets as hard errors (used for
    /// `ExplicitRefs` where the caller specifically requested the ref).
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
    paths: &GitRepoPaths,
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

    // Note: `resolve_tip` may have followed a symbolic chain via
    // `follow_to_object_packed`, which mutates `head.name` in place to
    // the final resolved name (e.g. `HEAD` becomes `refs/heads/main`).
    // This is intentional — for symbolic HEAD we return the branch name.
    let ref_name = head.name.as_bstr().to_vec();
    let tip = peel_to_non_tag(tip, &ref_name, packed, paths)?;
    Ok(vec![(ref_name, tip)])
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
    paths: &GitRepoPaths,
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
        let tip = peel_to_non_tag(tip, requested_name, packed, paths)?;
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
/// Dangling symbolic refs (e.g. a stale `refs/remotes/origin/HEAD` whose
/// target was renamed) are silently skipped rather than aborting the entire
/// resolve. This mirrors `resolve_default_branch`'s tolerance for unborn
/// HEAD and avoids hard-failing on repos with common stale remote HEAD
/// tracking entries.
fn collect_matching_refs(
    store: &gix_ref::file::Store,
    packed: Option<&gix_ref::packed::Buffer>,
    paths: &GitRepoPaths,
    matches: impl Fn(&[u8]) -> bool,
) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
    let platform = store.iter().map_err(|err| gix_error("iterate refs", err))?;
    let iter = platform
        .all()
        .map_err(|err| gix_error("iterate refs", err))?;

    let mut out = Vec::new();
    for entry in iter {
        let mut reference = entry.map_err(|err| gix_error("iterate refs", err))?;
        // Filter on the borrowed name before allocating — avoids a heap
        // allocation for every ref in repos with thousands of non-matching refs.
        if !matches(reference.name.as_bstr().as_ref()) {
            continue;
        }
        let ref_name = reference.name.as_bstr().to_vec();
        // Wildcard iteration tolerates dangling symbolic refs: skip them
        // instead of aborting the entire resolve.
        let Some(tip) = resolve_tip(
            &mut reference,
            store,
            packed,
            MissingSymbolicTarget::ReturnEmpty,
        )?
        else {
            continue;
        };
        let tip = peel_to_non_tag(tip, &ref_name, packed, paths)?;
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

/// Maximum peel depth to prevent infinite loops from corrupted or adversarial
/// tag chains.
///
/// Every major git implementation (git, libgit2, gitoxide, JGit, go-git) uses
/// unbounded loops for tag peeling, relying on content-addressing to prevent
/// cycles. We add an explicit depth limit because our scanner reads untrusted
/// repos without a persistent parsed-object cache for implicit cycle detection.
///
/// Real-world tag chains are almost always depth 1 (tag -> commit), very rarely
/// depth 2. Depth 3+ is essentially unheard of. The value 10 matches libgit2's
/// `MAX_NESTING_LEVEL` for symbolic-ref resolution (the closest analogue) and
/// provides a 5x margin over any legitimate use case.
///
/// Evidence: git `SYMREF_MAXDEPTH=5` (refs-internal.h), libgit2
/// `DEFAULT_NESTING_LEVEL=5` / `MAX_NESTING_LEVEL=10` (refdb.c:3-4).
const MAX_TAG_PEEL_DEPTH: u8 = 10;

/// Maximum decompressed bytes to read when checking if a loose object is a tag.
///
/// The target OID we need sits in the first ~48-72 bytes of the tag body
/// (`object <hex-oid>\n`). The full tag header (object + type + tag name +
/// tagger) is always under 275 bytes. However, we must decompress enough zlib
/// data to reach the header through the git object framing (`tag <size>\0`).
///
/// Typical annotated tags (including GPG/SSH signatures) are 200-2000 bytes.
/// The largest legitimate tags (RSA-4096 signature + long release notes) reach
/// ~4 KiB. The 8 KiB limit provides a 2-4x margin over legitimate maximums
/// while defending against decompression bombs and multi-megabyte tag messages
/// in adversarial repos.
///
/// Evidence: tag format spec (git tag.c:parse_tag_buffer), RSA-4096 armored
/// signatures ~800-1000 bytes, JGit uses 5 MiB as its general object cache
/// limit (RevWalk.java getCachedBytes).
const MAX_LOOSE_TAG_BYTES: usize = 8 * 1024;

/// Peel an OID through any tag objects to reach the underlying non-tag object.
///
/// Two resolution strategies are attempted in order:
///
/// 1. **Packed-refs peel entry** — the `packed-refs` file stores peeled OIDs
///    for annotated tags as `^` lines. When the ref is found in `packed` with
///    a peeled entry, return that OID directly. No object store access needed.
///
/// 2. **Loose object chain** — for tags not in packed-refs (e.g. freshly
///    created), read the loose object from `$GIT_DIR/objects/XX/YYY...`,
///    decompress it, check the header for `tag` type, and extract the
///    `object <hex>` target. Repeat up to [`MAX_TAG_PEEL_DEPTH`] for nested
///    tags.
fn peel_to_non_tag(
    oid: OidBytes,
    ref_name: &[u8],
    packed: Option<&gix_ref::packed::Buffer>,
    paths: &GitRepoPaths,
) -> Result<OidBytes, RepoOpenError> {
    // Fast path: check packed-refs for a pre-computed peeled OID.
    if let Some(peeled) = try_packed_peel(ref_name, packed)? {
        return Ok(peeled);
    }

    // Slow path: read loose objects and follow the tag chain.
    peel_loose_tag_chain(oid, paths)
}

/// Look up `ref_name` in the packed-refs buffer and return the peeled OID
/// if the entry has one (the `^` line in packed-refs).
///
/// Returns `Ok(None)` when the ref is not in packed-refs or has no peel entry
/// (i.e. is not an annotated tag).
fn try_packed_peel(
    ref_name: &[u8],
    packed: Option<&gix_ref::packed::Buffer>,
) -> Result<Option<OidBytes>, RepoOpenError> {
    let Some(packed_buf) = packed else {
        return Ok(None);
    };

    let found = packed_buf
        .try_find(ref_name.as_bstr())
        .map_err(|err| gix_error("packed-refs lookup for peel", err))?;

    let Some(packed_ref) = found else {
        return Ok(None);
    };

    // `object` is `Some` only for annotated tags that have a `^` peel line.
    // When present, it's the fully-peeled non-tag OID (typically a commit).
    match packed_ref.object {
        Some(_) => Ok(Some(oid_from_hash(packed_ref.object().as_bytes()))),
        None => Ok(None),
    }
}

/// Follow a chain of loose tag objects until we reach a non-tag object.
///
/// Each iteration reads a single loose object, checks if it is a `tag`, and
/// if so extracts the `object <hex>` target. The loop terminates when:
/// - The object is not a tag (return current OID).
/// - The loose object file does not exist (assume non-tag; return current OID).
/// - [`MAX_TAG_PEEL_DEPTH`] is exceeded (return error).
fn peel_loose_tag_chain(
    mut oid: OidBytes,
    paths: &GitRepoPaths,
) -> Result<OidBytes, RepoOpenError> {
    for _ in 0..MAX_TAG_PEEL_DEPTH {
        match try_read_loose_tag_target(&oid, &paths.objects_dir)? {
            Some(target) => oid = target,
            None => return Ok(oid),
        }
    }
    Err(RepoOpenError::io(io::Error::other(
        "tag peel depth exceeded — possible cycle in tag chain",
    )))
}

/// Read a single loose object and, if it is a tag, return the target OID.
///
/// Returns `Ok(None)` if the object file does not exist or is not a tag.
/// The loose object format is: `zlib(<type> <size>\0<body>)`.
/// For tags, the body starts with `object <40-or-64-hex>\n...`.
fn try_read_loose_tag_target(
    oid: &OidBytes,
    objects_dir: &Path,
) -> Result<Option<OidBytes>, RepoOpenError> {
    let hex = oid.to_string();
    let (dir, file) = hex.split_at(2);
    let path = objects_dir.join(dir).join(file);

    let compressed = match std::fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(RepoOpenError::io(err)),
    };

    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut buf = vec![0u8; MAX_LOOSE_TAG_BYTES];
    let mut total = 0;
    loop {
        match decoder.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => {
                total += n;
                if total >= MAX_LOOSE_TAG_BYTES {
                    break;
                }
            }
            Err(err) => return Err(RepoOpenError::io(err)),
        }
    }
    let decompressed = &buf[..total];

    // Parse header: "<type> <size>\0"
    let Some(nul_pos) = decompressed.iter().position(|&b| b == 0) else {
        return Ok(None);
    };
    let header = &decompressed[..nul_pos];

    // Check if it's a tag object.
    if !header.starts_with(b"tag ") {
        return Ok(None);
    }

    // Parse body for "object <40-or-64-hex>\n".
    let body = &decompressed[nul_pos + 1..];
    let Some(rest) = body.strip_prefix(b"object ") else {
        return Err(RepoOpenError::io(io::Error::other(
            "malformed tag object: missing 'object' field",
        )));
    };
    let Some(lf_pos) = rest.iter().position(|&b| b == b'\n') else {
        return Err(RepoOpenError::io(io::Error::other(
            "malformed tag object: unterminated 'object' line",
        )));
    };
    let hex_target = &rest[..lf_pos];
    let target_id = gix_hash::ObjectId::from_hex(hex_target)
        .map_err(|err| RepoOpenError::io(io::Error::other(format!("bad tag target hex: {err}"))))?;
    Ok(Some(oid_from_hash(target_id.as_bytes())))
}

/// Open a `gix_ref::file::Store` appropriate for the repository layout.
///
/// Linked worktrees have a per-worktree `git_dir` (containing `HEAD` and
/// worktree-specific refs) plus a shared `common_dir` (containing branches,
/// tags, and packed-refs). Normal repos and bare repos only need `git_dir`.
pub(crate) fn open_ref_store(
    paths: &GitRepoPaths,
    limits: &RepoOpenLimits,
) -> Result<gix_ref::file::Store, RepoOpenError> {
    let options = gix_store_options(paths, limits)?;
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

/// Open a ref store when the caller has already detected the object format.
///
/// Avoids re-reading the git config that [`open_ref_store`] performs internally
/// via [`detect_object_format`]. Useful in paths that detect the format for
/// their own validation (e.g., `materialize_synthetic_commit_ref`).
pub(crate) fn open_ref_store_with_format(
    paths: &GitRepoPaths,
    format: ObjectFormat,
) -> gix_ref::file::Store {
    let options = gix_store_options_for(format);
    if paths.is_linked_worktree() {
        gix_ref::file::Store::for_linked_worktree(
            paths.git_dir.clone(),
            paths.common_dir.clone(),
            options,
        )
    } else {
        gix_ref::file::Store::at(paths.git_dir.clone(), options)
    }
}

/// Build store options for the given object format.
///
/// Reflogs are disabled because synthetic ref writes do not need history
/// tracking, and the scan pipeline's read path never creates refs.
/// `precompose_unicode` is left off because ref names are treated as
/// opaque bytes throughout the scan pipeline.
fn gix_store_options_for(format: ObjectFormat) -> gix_ref::store::init::Options {
    gix_ref::store::init::Options {
        write_reflog: gix_ref::store::WriteReflog::Disable,
        object_hash: map_object_format(format),
        precompose_unicode: false,
        prohibit_windows_device_names: false,
    }
}

fn gix_store_options(
    paths: &GitRepoPaths,
    limits: &RepoOpenLimits,
) -> Result<gix_ref::store::init::Options, RepoOpenError> {
    Ok(gix_store_options_for(detect_object_format(paths, limits)?))
}

/// Map the crate-level [`ObjectFormat`] enum to the `gix_hash::Kind` that
/// `gix_ref` uses to size OID fields in packed-refs parsing and ref store
/// operations.
fn map_object_format(format: ObjectFormat) -> gix_hash::Kind {
    match format {
        ObjectFormat::Sha1 => gix_hash::Kind::Sha1,
        ObjectFormat::Sha256 => gix_hash::Kind::Sha256,
    }
}

/// Copy raw hash bytes into a stack-allocated [`OidBytes`].
///
/// Accepts either 20-byte (SHA-1) or 32-byte (SHA-256) slices; `OidBytes`
/// stores the length alongside the data.
#[inline]
fn oid_from_hash(bytes: &[u8]) -> OidBytes {
    OidBytes::from_slice(bytes)
}

/// Wrap a `gix_ref` error into [`RepoOpenError`] with a human-readable
/// `context` prefix (e.g. `"resolve HEAD"`, `"iterate refs"`).
fn gix_error(context: &str, err: impl std::fmt::Display) -> RepoOpenError {
    RepoOpenError::io(io::Error::other(format!("{context}: {err}")))
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};

    use gossip_stdx::git_test_support::{git_stdout, init_git_repo, try_run_git};
    use rstest::rstest;

    use super::*;

    pub(crate) fn create_repo(tmp: &tempfile::TempDir) -> PathBuf {
        let repo = tmp.path().to_path_buf();
        init_git_repo(&repo, "test@example.com", "test-user");
        repo
    }

    pub(crate) fn git(repo: &Path, args: &[&str]) -> String {
        git_stdout(repo, args)
    }

    pub(crate) fn try_git(repo: &Path, args: &[&str]) -> std::process::Output {
        try_run_git(repo, args)
    }

    pub(crate) fn resolve_with(repo: &Path, config: StartSetConfig) -> Vec<(Vec<u8>, OidBytes)> {
        try_resolve_with(repo, config).expect("resolve")
    }

    fn try_resolve_with(
        repo: &Path,
        config: StartSetConfig,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        let resolver = NativeRefResolver::new(config);
        let paths = GitRepoPaths::resolve::<RepoOpenError, _>(repo, &RepoOpenLimits::default())
            .expect("resolve paths");
        resolver.resolve(&paths)
    }

    fn resolve_default(repo: &Path) -> Vec<(Vec<u8>, OidBytes)> {
        resolve_with(repo, StartSetConfig::DefaultBranchOnly)
    }

    pub(crate) fn parse_oid(hex: &str) -> OidBytes {
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
        let repo = create_repo(&tmp);
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
        let repo = create_repo(&tmp);
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
        let repo = create_repo(&tmp);
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

    // -- ExplicitRefs ---------------------------------------------------

    #[test]
    fn explicit_refs_resolves_named_branches_and_tags() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        git(&repo, &["branch", "feature-a"]);
        git(&repo, &["tag", "v0.1"]);

        let resolved = resolve_with(
            &repo,
            StartSetConfig::ExplicitRefs {
                refs: vec![
                    b"refs/heads/main".to_vec(),
                    b"refs/heads/feature-a".to_vec(),
                    b"refs/tags/v0.1".to_vec(),
                ],
            },
        );

        assert_eq!(resolved.len(), 3);
        let commit_oid = parse_oid(&git(&repo, &["rev-parse", "HEAD"]));
        for (_, oid) in &resolved {
            assert_eq!(*oid, commit_oid);
        }
    }

    #[test]
    fn explicit_refs_errors_on_missing_ref() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);

        let result = try_resolve_with(
            &repo,
            StartSetConfig::ExplicitRefs {
                refs: vec![b"refs/heads/no-such-branch".to_vec()],
            },
        );

        assert!(result.is_err());
    }

    // -- AllRemoteBranches ----------------------------------------------

    #[test]
    fn all_remote_branches_with_remote_filter() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        let oid = git(&repo, &["rev-parse", "HEAD"]);

        git(&repo, &["update-ref", "refs/remotes/origin/main", &oid]);
        git(&repo, &["update-ref", "refs/remotes/upstream/main", &oid]);

        let resolved = resolve_with(
            &repo,
            StartSetConfig::AllRemoteBranches {
                remote: Some(b"origin".to_vec()),
            },
        );

        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, b"refs/remotes/origin/main".to_vec());
    }

    #[test]
    fn all_remote_branches_without_filter() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        let oid = git(&repo, &["rev-parse", "HEAD"]);

        git(&repo, &["update-ref", "refs/remotes/origin/main", &oid]);
        git(
            &repo,
            &["update-ref", "refs/remotes/upstream/develop", &oid],
        );

        let resolved = resolve_with(&repo, StartSetConfig::AllRemoteBranches { remote: None });

        assert_eq!(resolved.len(), 2);
        let names: Vec<&[u8]> = resolved.iter().map(|(n, _)| n.as_slice()).collect();
        assert!(names.contains(&b"refs/remotes/origin/main".as_slice()));
        assert!(names.contains(&b"refs/remotes/upstream/develop".as_slice()));
    }

    // -- BranchesAndTags ------------------------------------------------

    #[test]
    fn branches_and_tags_includes_remotes_when_enabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        let oid = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["tag", "v0.1"]);
        git(&repo, &["update-ref", "refs/remotes/origin/main", &oid]);

        let resolved = resolve_with(
            &repo,
            StartSetConfig::BranchesAndTags {
                include_remote_branches: true,
                remote: None,
            },
        );

        let names: Vec<&[u8]> = resolved.iter().map(|(n, _)| n.as_slice()).collect();
        assert!(names.contains(&b"refs/heads/main".as_slice()));
        assert!(names.contains(&b"refs/tags/v0.1".as_slice()));
        assert!(names.contains(&b"refs/remotes/origin/main".as_slice()));
    }

    #[test]
    fn branches_and_tags_excludes_remotes_when_disabled() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        let oid = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["tag", "v0.1"]);
        git(&repo, &["update-ref", "refs/remotes/origin/main", &oid]);

        let resolved = resolve_with(
            &repo,
            StartSetConfig::BranchesAndTags {
                include_remote_branches: false,
                remote: None,
            },
        );

        let names: Vec<&[u8]> = resolved.iter().map(|(n, _)| n.as_slice()).collect();
        assert!(names.contains(&b"refs/heads/main".as_slice()));
        assert!(names.contains(&b"refs/tags/v0.1".as_slice()));
        assert!(
            !names.iter().any(|n| n.starts_with(b"refs/remotes/")),
            "remote refs should be excluded"
        );
    }

    // -- Worktrees and bare repos ---------------------------------------

    #[test]
    fn resolves_refs_in_linked_worktree() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);
        git(&repo, &["branch", "wt-branch"]);

        let wt_dir = tmp.path().join("worktree");
        git(
            &repo,
            &["worktree", "add", wt_dir.to_str().unwrap(), "wt-branch"],
        );

        let wt_paths =
            GitRepoPaths::resolve::<RepoOpenError, _>(&wt_dir, &RepoOpenLimits::default())
                .expect("resolve worktree paths");
        assert!(wt_paths.is_linked_worktree());

        let resolved = resolve_with(&wt_dir, StartSetConfig::DefaultBranchOnly);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].0, b"refs/heads/wt-branch".to_vec());
    }

    #[test]
    fn resolves_refs_in_bare_repo() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = create_repo(&tmp);
        git(&source, &["commit", "--allow-empty", "-m", "first"]);

        let bare_dir = tmp.path().join("bare.git");
        git(
            &source,
            &[
                "clone",
                "--bare",
                source.to_str().unwrap(),
                bare_dir.to_str().unwrap(),
            ],
        );

        let commit_oid = git(&bare_dir, &["rev-parse", "refs/heads/main"]);
        let resolved = resolve_with(&bare_dir, StartSetConfig::DefaultBranchOnly);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].1, parse_oid(&commit_oid));
    }

    // -- Error paths ----------------------------------------------------

    #[test]
    fn dangling_symbolic_ref_skipped_in_wildcard() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "first"]);

        // Create a symbolic ref pointing at a non-existent target.
        git(
            &repo,
            &[
                "symbolic-ref",
                "refs/heads/dangling",
                "refs/heads/no-such-branch",
            ],
        );

        // Wildcard iteration should skip dangling refs, not abort.
        let resolved = resolve_with(
            &repo,
            StartSetConfig::BranchesAndTags {
                include_remote_branches: false,
                remote: None,
            },
        );

        assert!(!resolved.is_empty(), "should still resolve valid branches");
        assert!(
            !resolved.iter().any(|(n, _)| n == b"refs/heads/dangling"),
            "dangling symbolic ref should be skipped"
        );
    }

    // -- Tag peeling ----------------------------------------------------

    #[test]
    fn annotated_tag_resolves_to_commit_oid() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        let commit_oid = git(&repo, &["rev-parse", "HEAD"]);

        // Create an annotated tag — its object is a tag object, not the commit.
        git(&repo, &["tag", "-a", "v1.0", "-m", "release v1.0"]);
        let tag_object_oid = git(&repo, &["rev-parse", "refs/tags/v1.0"]);
        // Sanity: annotated tags have a distinct tag object OID.
        assert_ne!(
            tag_object_oid, commit_oid,
            "annotated tag should have a different OID than the commit"
        );

        let resolved = resolve_with(
            &repo,
            StartSetConfig::BranchesAndTags {
                include_remote_branches: false,
                remote: None,
            },
        );

        // Find the tag entry in the resolved set.
        let tag_entry = resolved
            .iter()
            .find(|(name, _)| name == b"refs/tags/v1.0")
            .expect("tag ref should be in resolved set");

        // The trait contract requires that tips are commit OIDs, not tag object OIDs.
        assert_eq!(
            tag_entry.1,
            parse_oid(&commit_oid),
            "annotated tag should be peeled to the underlying commit OID"
        );
    }

    // -- dangling symbolic refs -----------------------------------------

    #[test]
    fn dangling_remote_head_skipped_in_wildcard_scan() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);
        git(&repo, &["remote", "add", "origin", "."]);
        git(&repo, &["fetch", "origin"]);

        // Simulate a stale remote HEAD by pointing it at a nonexistent branch.
        git(
            &repo,
            &[
                "symbolic-ref",
                "refs/remotes/origin/HEAD",
                "refs/remotes/origin/renamed-main",
            ],
        );

        let resolver = NativeRefResolver::new(StartSetConfig::AllRemoteBranches {
            remote: Some(b"origin".to_vec()),
        });
        let paths = GitRepoPaths::resolve::<RepoOpenError, _>(&repo, &RepoOpenLimits::default())
            .expect("resolve paths");
        let resolved = resolver.resolve(&paths).expect("should skip dangling ref");
        assert!(
            !resolved.is_empty(),
            "should still resolve valid remote-tracking branches"
        );
        assert!(
            !resolved
                .iter()
                .any(|(n, _)| n == b"refs/remotes/origin/HEAD"),
            "dangling symbolic ref should be skipped"
        );
    }

    // -- config size limits ---------------------------------------------

    #[test]
    fn resolver_respects_caller_config_size_limits() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let repo = create_repo(&tmp);
        git(&repo, &["commit", "--allow-empty", "-m", "initial"]);

        let config_path = repo.join(".git").join("config");
        let original = std::fs::read_to_string(&config_path).expect("read config");
        let padding = "\n# ".to_owned() + &"x".repeat(200 * 1024) + "\n";
        std::fs::write(&config_path, original + &padding).expect("write padded config");

        let resolver_default = NativeRefResolver::new(StartSetConfig::DefaultBranchOnly);
        let paths = GitRepoPaths::resolve::<RepoOpenError, _>(&repo, &RepoOpenLimits::default())
            .expect("resolve paths");
        let result = resolver_default.resolve(&paths);
        assert!(
            result.is_err(),
            "expected FileTooLarge with default limits, but got: {:?}",
            result
        );

        let custom_limits = RepoOpenLimits {
            max_config_file_bytes: 512 * 1024,
            ..RepoOpenLimits::default()
        };
        let resolver_custom =
            NativeRefResolver::with_limits(StartSetConfig::DefaultBranchOnly, custom_limits);
        let resolved = resolver_custom
            .resolve(&paths)
            .expect("resolver with custom limits should succeed for config within those limits");
        assert_eq!(resolved.len(), 1);
    }
}
