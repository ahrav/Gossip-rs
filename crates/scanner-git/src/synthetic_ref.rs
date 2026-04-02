//! Materialize stable synthetic refs for explicit-commit lowering.
//!
//! When a scan request targets a specific commit OID (not a branch or tag),
//! the coordinator writes a deterministic ref
//! (`refs/gossip/scan-targets/commits/<format>/<hex>`) inside the prepared
//! mirror so the downstream scanner can resolve it through the normal
//! `ExplicitRefs` start-set pipeline.
//!
//! The ref name is deterministic for `(object_format, commit_oid)`, enabling
//! idempotent re-materialization and stable watermark keys across retries.
//!
//! # Object Validation
//!
//! Before writing a ref, `materialize_synthetic_commit_ref` probes the mirror's
//! object database (pack index via MIDX, then loose objects) to confirm the OID
//! exists and is a commit. Non-commit objects and missing OIDs are rejected.

use std::fs;
use std::io;
use std::path::Path;

use gix_ref::bstr::ByteSlice;
use gix_ref::transaction::{Change, LogChange, PreviousValue, RefEdit};
use gix_ref::{FullName, Target};

use crate::commit_loader::resolve_pack_paths_from_midx;
use crate::midx_build::{build_midx_bytes, MidxBuildError, MidxBuildLimits};
use crate::native_ref_resolver::open_ref_store;
use crate::pack_decode::PackDecodeLimits;
use crate::pack_inflate::{inflate_limited, ObjectKind};
use crate::pack_io::{PackIo, PackIoLimits};
use crate::repo_open::detect_object_format;
use crate::repo_paths::{collect_loose_dirs, collect_pack_dirs};
use crate::{GitRepoPaths, ObjectFormat, OidBytes, RepoOpenError, RepoOpenLimits};

/// Private ref namespace for synthetic commit refs created by explicit-commit
/// lowering. The full ref name is
/// `refs/gossip/scan-targets/commits/<format>/<hex-oid>`, giving a
/// deterministic, collision-free name that the existing `ExplicitRefs`
/// start-set resolver can look up without special casing.
const EXPLICIT_COMMIT_REF_NAMESPACE: &[u8] = b"refs/gossip/scan-targets/commits/";

/// Maximum bytes to inflate when probing a loose object's type in
/// [`lookup_loose_object_kind`]. 64 bytes is more than enough for the
/// `"<type> <size>\0"` header of any git object format.
const LOOSE_OBJECT_HEADER_MAX_BYTES: usize = 64;

/// Errors returned while lowering one explicit commit into a mirror-local ref.
#[derive(Debug, thiserror::Error)]
pub enum SyntheticCommitRefError {
    /// The mirror repository could not be opened or its layout was invalid.
    #[error("mirror repository open failed: {0}")]
    RepoOpen(#[from] RepoOpenError),
    /// The requested OID format cannot exist in this mirror.
    #[error(
        "requested commit {commit} uses {requested:?}, but the mirror object database uses {mirror:?}"
    )]
    ObjectFormatMismatch {
        /// Requested explicit commit.
        commit: OidBytes,
        /// Format carried by the explicit commit selection.
        requested: ObjectFormat,
        /// Format detected from the mirror repository.
        mirror: ObjectFormat,
    },
    /// The requested OID did not resolve to any local object.
    #[error("requested commit {commit} was not found in the mirror object database")]
    CommitNotFound {
        /// Requested explicit commit.
        commit: OidBytes,
    },
    /// The requested OID exists locally but is not a commit object.
    #[error("requested object {commit} exists in the mirror object database but is not a commit")]
    ObjectNotCommit {
        /// Requested explicit commit.
        commit: OidBytes,
    },
    /// The deterministic synthetic ref name failed validation.
    #[error("synthetic ref name is invalid: {detail}")]
    InvalidRefName {
        /// Validation detail from `gix-validate`.
        detail: String,
    },
    /// Resolving or decoding the mirror object database failed.
    #[error("synthetic ref object lookup failed: {detail}")]
    ObjectLookup {
        /// Human-readable detail from lower-level lookup helpers.
        detail: String,
    },
    /// Writing the synthetic ref in the mirror failed.
    #[error("synthetic ref update failed: {detail}")]
    RefUpdate {
        /// Human-readable detail from the ref-transaction layer.
        detail: String,
    },
}

/// Derive the deterministic ref name for explicit-commit lowering.
///
/// The name encodes both the hash algorithm and the hex OID:
///
/// ```text
/// refs/gossip/scan-targets/commits/<sha1|sha256>/<hex-oid>
/// ```
///
/// Determinism is critical: the same `(format, oid)` pair always produces
/// the same ref name, so repeated lowerings are idempotent and watermark
/// keys remain stable across retries.
///
/// The returned bytes are a valid git ref name — no component starts with
/// `.`, no consecutive slashes, no control characters, and no `..` or `@{`
/// sequences.
#[must_use]
pub fn synthetic_commit_ref_name(commit: OidBytes) -> Vec<u8> {
    let format_component = match commit.format() {
        ObjectFormat::Sha1 => b"sha1".as_slice(),
        ObjectFormat::Sha256 => b"sha256".as_slice(),
    };

    let mut name = Vec::with_capacity(
        EXPLICIT_COMMIT_REF_NAMESPACE.len()
            + format_component.len()
            + 1
            + commit.len() as usize * 2,
    );
    name.extend_from_slice(EXPLICIT_COMMIT_REF_NAMESPACE);
    name.extend_from_slice(format_component);
    name.push(b'/');
    name.extend_from_slice(commit.to_string().as_bytes());
    name
}

/// Materialize a synthetic ref pointing at `commit` inside `mirror_root`.
///
/// This is the core "lowering" step for explicit-commit selections: the caller
/// specifies a commit OID, and this function creates a private ref in the
/// mirror that the normal `ExplicitRefs` start-set resolver can then look up.
///
/// # Algorithm
///
/// 1. Open the mirror repository and detect its object format (SHA-1 vs SHA-256).
/// 2. Validate the format matches `commit.format()` — a SHA-256 OID cannot
///    exist in a SHA-1 object database.
/// 3. Probe the mirror's object database (pack index + loose objects) to confirm
///    the OID exists and is a commit. Non-commit objects and missing OIDs are
///    rejected with specific error variants.
/// 4. Derive the deterministic ref name via [`synthetic_commit_ref_name`].
/// 5. Write the ref using a `gix_ref` transaction with `PreviousValue::Any`,
///    making the operation idempotent — repeated calls for the same commit
///    succeed without error.
///
/// # Invariants
///
/// - All ref mutations are confined to `mirror_root`. The source repository
///   (if any) is never touched.
/// - The ref name is deterministic for `(object_format, commit_oid)`, so
///   watermark keys and start-set identities remain stable across retries.
///
/// # Cleanup
///
/// Callers are responsible for periodic cleanup of the
/// `refs/gossip/scan-targets/commits/` namespace in long-lived mirrors.
///
/// # Errors
///
/// Returns [`SyntheticCommitRefError`] for format mismatches, missing objects,
/// non-commit objects, ref-name validation failures, or ref-store I/O errors.
pub fn materialize_synthetic_commit_ref(
    mirror_root: &Path,
    commit: OidBytes,
    limits: RepoOpenLimits,
) -> Result<Vec<u8>, SyntheticCommitRefError> {
    let paths = GitRepoPaths::resolve::<RepoOpenError, _>(mirror_root, &limits)?;
    let object_format = detect_object_format(&paths, &limits)?;
    if object_format != commit.format() {
        return Err(SyntheticCommitRefError::ObjectFormatMismatch {
            commit,
            requested: commit.format(),
            mirror: object_format,
        });
    }

    match lookup_object_kind(&paths, commit)? {
        Some(ObjectKind::Commit) => {}
        Some(_) => return Err(SyntheticCommitRefError::ObjectNotCommit { commit }),
        None => return Err(SyntheticCommitRefError::CommitNotFound { commit }),
    }

    let ref_name = synthetic_commit_ref_name(commit);
    let store = open_ref_store(&paths, &limits).map_err(SyntheticCommitRefError::RepoOpen)?;
    let full_name = FullName::try_from(ref_name.as_slice().as_bstr()).map_err(|err| {
        SyntheticCommitRefError::InvalidRefName {
            detail: err.to_string(),
        }
    })?;
    let target = Target::Object(
        gix_hash::ObjectId::try_from(commit.as_slice())
            .expect("OidBytes always has a valid length"),
    );
    let edit = RefEdit {
        change: Change::Update {
            log: LogChange::default(),
            expected: PreviousValue::Any,
            new: target,
        },
        name: full_name,
        deref: false,
    };

    store
        .transaction()
        .prepare([edit], Default::default(), Default::default())
        .map_err(|err| SyntheticCommitRefError::RefUpdate {
            detail: err.to_string(),
        })?
        .commit(None)
        .map_err(|err| SyntheticCommitRefError::RefUpdate {
            detail: err.to_string(),
        })?;

    Ok(ref_name)
}

/// Determine the object type of `oid` in the mirror's object database.
///
/// Tries the pack index first (via MIDX), falling back to loose object lookup
/// when no packs exist. Returns `Ok(None)` when the OID is not found in either
/// store.
///
/// The pack path decompresses the full object (up to 8 MiB) via `load_object`
/// because `PackIo` does not expose a header-only query. Only the kind is
/// retained; the payload is discarded.
fn lookup_object_kind(
    paths: &GitRepoPaths,
    oid: OidBytes,
) -> Result<Option<ObjectKind>, SyntheticCommitRefError> {
    match build_midx_bytes(paths, oid.format(), &MidxBuildLimits::default()) {
        Ok(midx_bytes) => {
            let midx =
                crate::MidxView::parse(midx_bytes.as_slice(), oid.format()).map_err(|err| {
                    SyntheticCommitRefError::ObjectLookup {
                        detail: err.to_string(),
                    }
                })?;
            let pack_dirs = collect_pack_dirs(paths);
            let pack_paths = resolve_pack_paths_from_midx(&midx, &pack_dirs).map_err(|err| {
                SyntheticCommitRefError::ObjectLookup {
                    detail: err.to_string(),
                }
            })?;
            let loose_dirs = collect_loose_dirs(paths);
            // Full decompression up to 8 MiB — PackIo lacks a header-only API,
            // so we decode the entire object and discard the payload.
            let pack_decode = PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024);
            let pack_io_limits = PackIoLimits::new(
                pack_decode,
                crate::pack_plan::PackPlanConfig::default().max_delta_depth,
            );
            let mut pack_io = PackIo::from_parts(midx, pack_paths, loose_dirs, pack_io_limits)
                .map_err(|err| SyntheticCommitRefError::ObjectLookup {
                    detail: err.to_string(),
                })?;
            Ok(pack_io
                .load_object(&oid)
                .map_err(|err| SyntheticCommitRefError::ObjectLookup {
                    detail: err.to_string(),
                })?
                .map(|(kind, _)| kind))
        }
        Err(MidxBuildError::NoPacksFound) => lookup_loose_object_kind(paths, oid),
        Err(err) => Err(SyntheticCommitRefError::ObjectLookup {
            detail: err.to_string(),
        }),
    }
}

/// Probe loose object directories for `oid` and return its type.
///
/// Reads the zlib-compressed loose object at `objects/<xx>/<yy...>`, inflates
/// only [`LOOSE_OBJECT_HEADER_MAX_BYTES`] (64 bytes) — enough to cover the
/// `"<type> <size>\0"` header that [`parse_loose_object_kind`] inspects.
/// Returns `Ok(None)` when the file does not exist in any object directory
/// (alternates-aware via [`collect_loose_dirs`]).
fn lookup_loose_object_kind(
    paths: &GitRepoPaths,
    oid: OidBytes,
) -> Result<Option<ObjectKind>, SyntheticCommitRefError> {
    let hex = oid.to_string();
    let (dir, file) = hex.split_at(2);

    for base in collect_loose_dirs(paths) {
        let path = base.join(dir).join(file);
        let data = match fs::read(&path) {
            Ok(data) => data,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(SyntheticCommitRefError::ObjectLookup {
                    detail: format!("loose object read failed: {err}"),
                });
            }
        };

        // Only the `"<type> <size>\0"` header is needed for kind detection;
        // 64 bytes is sufficient for any valid git object header.
        let mut out = Vec::with_capacity(LOOSE_OBJECT_HEADER_MAX_BYTES);
        inflate_limited(&data, &mut out, LOOSE_OBJECT_HEADER_MAX_BYTES).map_err(|err| {
            SyntheticCommitRefError::ObjectLookup {
                detail: format!("loose object inflate failed: {err}"),
            }
        })?;

        return Ok(Some(parse_loose_object_kind(&out)?));
    }

    Ok(None)
}

/// Parse the object type from a decompressed loose object header.
///
/// The git loose format is `<type> <size>\0<body>`. This function extracts
/// the type keyword before the first space and maps it to [`ObjectKind`].
/// Returns an error for malformed headers or unrecognized type strings.
fn parse_loose_object_kind(bytes: &[u8]) -> Result<ObjectKind, SyntheticCommitRefError> {
    let Some(nul) = bytes.iter().position(|&b| b == 0) else {
        return Err(SyntheticCommitRefError::ObjectLookup {
            detail: "loose object header is missing a NUL terminator".to_string(),
        });
    };
    let header = &bytes[..nul];
    let Some(space) = header.iter().position(|&b| b == b' ') else {
        return Err(SyntheticCommitRefError::ObjectLookup {
            detail: "loose object header is missing its type/size separator".to_string(),
        });
    };

    match &header[..space] {
        b"commit" => Ok(ObjectKind::Commit),
        b"tree" => Ok(ObjectKind::Tree),
        b"blob" => Ok(ObjectKind::Blob),
        b"tag" => Ok(ObjectKind::Tag),
        other => Err(SyntheticCommitRefError::ObjectLookup {
            detail: format!(
                "loose object type is unknown: {}",
                String::from_utf8_lossy(other)
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;
    use crate::native_ref_resolver::tests::{git, init_repo, parse_oid, resolve_with, try_git};

    #[test]
    fn synthetic_commit_ref_name_is_stable_and_distinct_across_formats() {
        let sha1 = parse_oid("0123456789abcdef0123456789abcdef01234567");
        let sha1_again = parse_oid("0123456789abcdef0123456789abcdef01234567");
        let sha1_other = parse_oid("fedcba9876543210fedcba9876543210fedcba98");
        let sha256 = parse_oid("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        assert_eq!(
            synthetic_commit_ref_name(sha1),
            synthetic_commit_ref_name(sha1_again)
        );
        assert_ne!(
            synthetic_commit_ref_name(sha1),
            synthetic_commit_ref_name(sha1_other)
        );
        assert_ne!(
            synthetic_commit_ref_name(sha1),
            synthetic_commit_ref_name(sha256)
        );
        assert_eq!(
            synthetic_commit_ref_name(sha1),
            b"refs/gossip/scan-targets/commits/sha1/0123456789abcdef0123456789abcdef01234567"
                .to_vec()
        );
        assert_eq!(
            synthetic_commit_ref_name(sha256),
            b"refs/gossip/scan-targets/commits/sha256/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_vec()
        );
    }

    #[test]
    fn materialize_synthetic_commit_ref_writes_only_inside_mirror() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = init_repo(&tmp);

        fs::write(source.join("tracked.txt"), "v1\n").expect("write tracked file");
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "first"]);
        let commit = parse_oid(&git(&source, &["rev-parse", "HEAD"]));

        let mirror = tmp.path().join("mirror.git");
        git(
            &source,
            &[
                "clone",
                "--mirror",
                source.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
        );

        let ref_name = materialize_synthetic_commit_ref(&mirror, commit, RepoOpenLimits::default())
            .expect("materialize ref");
        let ref_name_str = String::from_utf8(ref_name.clone()).expect("utf-8 ref name");

        assert_eq!(
            git(&mirror, &["rev-parse", &ref_name_str]),
            commit.to_string(),
            "mirror synthetic ref should point at the requested commit"
        );

        let source_show_ref = try_git(&source, &["show-ref", "--verify", &ref_name_str]);
        assert!(
            !source_show_ref.status.success(),
            "source repository must not gain a synthetic ref"
        );
    }

    #[test]
    fn materialize_synthetic_commit_ref_is_idempotent() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = init_repo(&tmp);

        fs::write(source.join("tracked.txt"), "v1\n").expect("write tracked file");
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "first"]);
        let commit = parse_oid(&git(&source, &["rev-parse", "HEAD"]));

        let mirror = tmp.path().join("mirror.git");
        git(
            &source,
            &[
                "clone",
                "--mirror",
                source.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
        );

        let first = materialize_synthetic_commit_ref(&mirror, commit, RepoOpenLimits::default())
            .expect("first materialization");
        let second = materialize_synthetic_commit_ref(&mirror, commit, RepoOpenLimits::default())
            .expect("second materialization");

        assert_eq!(first, second);
        let ref_name = String::from_utf8(first).expect("utf-8 ref name");
        assert_eq!(git(&mirror, &["rev-parse", &ref_name]), commit.to_string());
    }

    #[test]
    fn materialize_synthetic_commit_ref_rejects_missing_commit() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mirror = init_repo(&tmp);
        git(&mirror, &["commit", "--allow-empty", "-m", "first"]);

        let missing = parse_oid("1111111111111111111111111111111111111111");
        let err = materialize_synthetic_commit_ref(&mirror, missing, RepoOpenLimits::default())
            .expect_err("missing commit must fail");

        assert!(matches!(
            err,
            SyntheticCommitRefError::CommitNotFound { commit } if commit == missing
        ));
    }

    #[test]
    fn materialize_synthetic_commit_ref_rejects_non_commit_object() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mirror = init_repo(&tmp);
        git(&mirror, &["commit", "--allow-empty", "-m", "first"]);

        fs::write(mirror.join("blob.txt"), "test-blob\n").expect("write blob source");
        let blob_oid = parse_oid(&git(&mirror, &["hash-object", "-w", "blob.txt"]));

        let err = materialize_synthetic_commit_ref(&mirror, blob_oid, RepoOpenLimits::default())
            .expect_err("blob oid must fail");

        assert!(matches!(
            err,
            SyntheticCommitRefError::ObjectNotCommit { commit } if commit == blob_oid
        ));
    }

    #[test]
    fn synthetic_commit_ref_resolves_through_explicit_refs_start_set() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let source = init_repo(&tmp);

        fs::write(source.join("tracked.txt"), "v1\n").expect("write tracked file");
        git(&source, &["add", "."]);
        git(&source, &["commit", "-m", "first"]);
        let commit = parse_oid(&git(&source, &["rev-parse", "HEAD"]));

        let mirror = tmp.path().join("mirror.git");
        git(
            &source,
            &[
                "clone",
                "--mirror",
                source.to_str().unwrap(),
                mirror.to_str().unwrap(),
            ],
        );

        let ref_name = materialize_synthetic_commit_ref(&mirror, commit, RepoOpenLimits::default())
            .expect("materialize ref");
        let resolved = resolve_with(
            &mirror,
            StartSetConfig::ExplicitRefs {
                refs: vec![ref_name.clone()],
            },
        );

        assert_eq!(resolved, vec![(ref_name, commit)]);
    }
}
