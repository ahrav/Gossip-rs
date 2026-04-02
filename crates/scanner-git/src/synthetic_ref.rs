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
use std::io::{self, Read as _};
use std::path::{Path, PathBuf};

use gix_ref::bstr::ByteSlice;
use gix_ref::transaction::{Change, LogChange, PreviousValue, RefEdit};
use gix_ref::{FullName, Target};

use crate::bytes::BytesView;
use crate::commit_loader::resolve_pack_paths_from_midx;
use crate::midx_build::{build_midx_bytes, MidxBuildLimits};
use crate::native_ref_resolver::open_ref_store_with_format;
use flate2::bufread::ZlibDecoder;

use crate::pack_inflate::{EntryKind, ObjectKind, PackFile};
use crate::repo_open::detect_object_format;
use crate::repo_paths::{collect_loose_dirs, collect_pack_dirs};
use crate::{GitRepoPaths, MidxView, ObjectFormat, OidBytes, RepoOpenError, RepoOpenLimits};

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
    let store = open_ref_store_with_format(&paths, object_format);
    let full_name = FullName::try_from(ref_name.as_slice().as_bstr()).map_err(|err| {
        SyntheticCommitRefError::InvalidRefName {
            detail: err.to_string(),
        }
    })?;
    let target = Target::Object(
        gix_hash::ObjectId::try_from(commit.as_slice()).map_err(|_| {
            SyntheticCommitRefError::ObjectLookup {
                detail: format!("OID conversion failed for {commit} (unexpected length mismatch)"),
            }
        })?,
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
/// Uses a tiered resolution strategy to minimize I/O:
///
/// 1. **Commit-graph** (Tier 0) — the on-disk commit-graph stores only commit
///    OIDs. A hit is definitive proof the object is a commit, with zero pack
///    I/O. A miss is inconclusive (the graph may be incomplete or absent).
/// 2. **On-disk MIDX** (Tier 1) — if `<pack>/multi-pack-index` exists, it is
///    mmapped and used directly. This avoids the O(N log P) k-way merge that
///    `build_midx_bytes` performs when building an in-memory MIDX from scratch.
/// 3. **In-memory MIDX build** (Tier 2) — when no on-disk MIDX is present,
///    the MIDX is built from pack idx files.
/// 4. **Loose objects** (fallback) — probed when packs are absent or when pack
///    resolution fails.
///
/// When a pack/MIDX error occurs and the subsequent loose probe also misses,
/// the original pack error is surfaced rather than silently returning `None`
/// (which the caller would interpret as `CommitNotFound`).
///
/// The pack path reads only entry headers (no payload decompression). For
/// non-delta entries the kind is embedded directly in the header. For delta
/// entries the chain is followed via headers until a non-delta base is reached.
fn lookup_object_kind(
    paths: &GitRepoPaths,
    oid: OidBytes,
) -> Result<Option<ObjectKind>, SyntheticCommitRefError> {
    // Tier 0: commit-graph — definitive for commits, zero pack I/O.
    if let Some(kind) = lookup_commit_graph_kind(paths, oid) {
        return Ok(Some(kind));
    }

    // Tier 1+2: on-disk MIDX (zero-copy mmap) or in-memory MIDX build.
    match load_or_build_midx(paths, oid.format()) {
        Ok(midx_bytes) => {
            let midx = MidxView::parse(midx_bytes.as_slice(), oid.format()).map_err(|err| {
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
            match lookup_packed_object_kind(&midx, &pack_paths, oid) {
                Ok(Some(kind)) => Ok(Some(kind)),
                // OID not in pack index — try loose objects.
                Ok(None) => lookup_loose_object_kind(paths, oid),
                // Pack header resolution failed — try loose objects before
                // hard-failing, since the object may exist outside packs.
                // If loose also misses, surface the original pack error.
                Err(pack_err) => match lookup_loose_object_kind(paths, oid) {
                    Ok(Some(kind)) => Ok(Some(kind)),
                    Ok(None) => Err(pack_err),
                    Err(_) => Err(pack_err),
                },
            }
        }
        // Any MIDX load/build failure (missing packs, corrupt idx, too many
        // packs, etc.) falls back to loose object lookup rather than
        // hard-failing. The object may exist as a loose file even when
        // pack index enumeration cannot complete. If loose also misses,
        // surface the original MIDX error.
        Err(midx_err) => match lookup_loose_object_kind(paths, oid) {
            Ok(Some(kind)) => Ok(Some(kind)),
            Ok(None) => Err(midx_err),
            Err(_) => Err(midx_err),
        },
    }
}

/// Probe the on-disk commit-graph for `oid`.
///
/// The commit-graph stores only commit OIDs in a fanout-indexed sorted array.
/// A hit is definitive: if the OID is found, the object is a commit. A miss
/// is inconclusive — the graph may be incomplete (not all commits are indexed)
/// or absent entirely.
///
/// Tries `<objects>/info/commit-graph` first, then the split chain under
/// `<objects>/info/commit-graphs/`. Errors (missing file, corrupt data) are
/// silently swallowed — the caller falls through to pack-based resolution.
fn lookup_commit_graph_kind(paths: &GitRepoPaths, oid: OidBytes) -> Option<ObjectKind> {
    let info_dir = paths.objects_dir.join("info");
    let graph = gix_commitgraph::Graph::from_info_dir(&info_dir).ok()?;
    let gix_oid = gix_hash::ObjectId::try_from(oid.as_slice()).ok()?;
    graph.commit_by_id(gix_oid).map(|_| ObjectKind::Commit)
}

/// Load an existing on-disk MIDX or build one from pack idx files.
///
/// The on-disk MIDX at `<pack>/multi-pack-index` is produced by
/// `git multi-pack-index write` or `git maintenance`. When present it is
/// mmapped and parsed in microseconds — far cheaper than the O(N log P)
/// k-way merge that `build_midx_bytes` performs from scratch.
///
/// Falls back to `build_midx_bytes` when the on-disk file is absent.
fn load_or_build_midx(
    paths: &GitRepoPaths,
    format: ObjectFormat,
) -> Result<BytesView, SyntheticCommitRefError> {
    let ondisk = paths.pack_dir.join("multi-pack-index");
    if let Ok(file) = fs::File::open(&ondisk) {
        // SAFETY: MIDX files are immutable for the duration of a mirror job.
        let mmap = unsafe { memmap2::Mmap::map(&file) };
        match mmap {
            Ok(mmap) => {
                // Validate the on-disk MIDX before trusting it. If parse
                // fails (stale, corrupt, wrong hash version), fall through
                // to the in-memory build path.
                if MidxView::parse(&mmap, format).is_ok() {
                    return Ok(BytesView::from_mmap(mmap));
                }
            }
            Err(_) => { /* mmap failed — fall through to build */ }
        }
    }

    build_midx_bytes(paths, format, &MidxBuildLimits::default()).map_err(|err| {
        SyntheticCommitRefError::ObjectLookup {
            detail: err.to_string(),
        }
    })
}

/// Maximum entry-header bytes parsed per pack entry. 64 bytes covers the
/// variable-length size encoding, OFS negative-offset varint, and REF_DELTA
/// base OID for any realistic entry.
const PACK_ENTRY_HEADER_MAX_BYTES: usize = 64;

/// Maximum delta chain depth when following pack entry headers for kind
/// resolution. Matches the default `max_delta_depth` used elsewhere in the
/// codebase; resolving kind from headers is cheap so this is generous.
const KIND_RESOLVE_MAX_DELTA_DEPTH: u8 = 64;

/// Resolve the object kind for `oid` from packed objects using only entry
/// headers — no payload decompression is performed.
///
/// For non-delta entries the kind is embedded in the pack entry header. For
/// delta entries (`OFS_DELTA` / `REF_DELTA`) the chain is followed via
/// headers until a non-delta base is reached.
///
/// Returns `Ok(None)` when `oid` is not present in the MIDX index.
fn lookup_packed_object_kind(
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    oid: OidBytes,
) -> Result<Option<ObjectKind>, SyntheticCommitRefError> {
    let idx = match midx
        .find_oid(&oid)
        .map_err(|err| SyntheticCommitRefError::ObjectLookup {
            detail: err.to_string(),
        })? {
        Some(idx) => idx,
        None => return Ok(None),
    };
    let (pack_id, offset) =
        midx.offset_at(idx)
            .map_err(|err| SyntheticCommitRefError::ObjectLookup {
                detail: err.to_string(),
            })?;
    resolve_kind_at(
        midx,
        pack_paths,
        pack_id,
        offset,
        KIND_RESOLVE_MAX_DELTA_DEPTH,
        None,
    )
}

/// Follow pack entry headers starting at `(pack_id, offset)` until a
/// non-delta base is reached, returning its [`ObjectKind`].
///
/// `OFS_DELTA` entries reference a base within the same pack file;
/// `REF_DELTA` entries require a MIDX re-lookup to locate the base pack.
/// Each hop decrements `remaining_depth` to bound runaway chains.
///
/// When `cached_pack` matches `pack_id`, the already-mapped bytes are reused
/// to avoid repeated `mmap` syscalls during intra-pack delta chain walks.
fn resolve_kind_at(
    midx: &MidxView<'_>,
    pack_paths: &[PathBuf],
    pack_id: u16,
    offset: u64,
    remaining_depth: u8,
    cached_pack: Option<(u16, &memmap2::Mmap)>,
) -> Result<Option<ObjectKind>, SyntheticCommitRefError> {
    // Reuse the cached mmap when following OFS_DELTA chains within the
    // same pack; only open a new mapping when crossing pack boundaries.
    let fresh_map;
    let (data, this_mmap): (&[u8], Option<&memmap2::Mmap>) = match cached_pack {
        Some((cached_id, mmap)) if cached_id == pack_id => (mmap.as_ref(), Some(mmap)),
        _ => {
            let pack_path =
                pack_paths
                    .get(pack_id as usize)
                    .ok_or(SyntheticCommitRefError::ObjectLookup {
                        detail: format!(
                            "pack id {pack_id} out of range (have {} packs)",
                            pack_paths.len()
                        ),
                    })?;
            fresh_map = mmap_pack(pack_path)?;
            (fresh_map.as_ref(), Some(&fresh_map))
        }
    };
    let pack = PackFile::parse(data, midx.oid_len().into()).map_err(|err| {
        SyntheticCommitRefError::ObjectLookup {
            detail: format!("pack parse failed: {err}"),
        }
    })?;
    let header = pack
        .entry_header_at(offset, PACK_ENTRY_HEADER_MAX_BYTES)
        .map_err(|err| SyntheticCommitRefError::ObjectLookup {
            detail: format!("pack entry header read failed: {err}"),
        })?;
    match header.kind {
        EntryKind::NonDelta { kind } => Ok(Some(kind)),
        EntryKind::OfsDelta { base_offset } => {
            if remaining_depth == 0 {
                return Err(SyntheticCommitRefError::ObjectLookup {
                    detail: "delta chain depth exceeded during kind resolution".to_string(),
                });
            }
            // OFS_DELTA bases are always in the same pack — pass the
            // current mapping to avoid re-mmapping on the next hop.
            resolve_kind_at(
                midx,
                pack_paths,
                pack_id,
                base_offset,
                remaining_depth - 1,
                this_mmap.map(|m| (pack_id, m)),
            )
        }
        EntryKind::RefDelta { base_oid } => {
            if remaining_depth == 0 {
                return Err(SyntheticCommitRefError::ObjectLookup {
                    detail: "delta chain depth exceeded during kind resolution".to_string(),
                });
            }
            let base_idx = match midx.find_oid(&base_oid).map_err(|err| {
                SyntheticCommitRefError::ObjectLookup {
                    detail: err.to_string(),
                }
            })? {
                Some(idx) => idx,
                None => return Ok(None),
            };
            let (base_pack_id, base_offset) =
                midx.offset_at(base_idx)
                    .map_err(|err| SyntheticCommitRefError::ObjectLookup {
                        detail: err.to_string(),
                    })?;
            // Pass the cached mmap if the base is in the same pack.
            let carry = if base_pack_id == pack_id {
                this_mmap.map(|m| (pack_id, m))
            } else {
                None
            };
            resolve_kind_at(
                midx,
                pack_paths,
                base_pack_id,
                base_offset,
                remaining_depth - 1,
                carry,
            )
        }
    }
}

/// Memory-map a pack file for read-only header inspection.
fn mmap_pack(path: &Path) -> Result<memmap2::Mmap, SyntheticCommitRefError> {
    let file = fs::File::open(path).map_err(|err| SyntheticCommitRefError::ObjectLookup {
        detail: format!("pack open failed: {err}"),
    })?;
    // SAFETY: pack files are immutable for the duration of a mirror job.
    unsafe {
        memmap2::Mmap::map(&file).map_err(|err| SyntheticCommitRefError::ObjectLookup {
            detail: format!("pack mmap failed: {err}"),
        })
    }
}

/// Probe loose object directories for `oid` and return its type.
///
/// Opens the zlib-compressed loose object at `objects/<xx>/<yy...>` and
/// streams only the first [`LOOSE_OBJECT_HEADER_MAX_BYTES`] (64 bytes)
/// through a `ZlibDecoder` backed by a `BufReader` — enough to cover the
/// `"<type> <size>\0"` header that [`parse_loose_object_kind`] inspects.
/// The compressed file is never fully read into memory.
///
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
        let file_handle = match fs::File::open(&path) {
            Ok(f) => f,
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(SyntheticCommitRefError::ObjectLookup {
                    detail: format!("loose object open failed: {err}"),
                });
            }
        };

        // Stream through a BufReader so only the bytes needed to produce
        // the first 64 decompressed bytes are read from disk, regardless
        // of the compressed object's total size.
        let mut decoder = ZlibDecoder::new(io::BufReader::new(file_handle));
        let mut buf = [0u8; LOOSE_OBJECT_HEADER_MAX_BYTES];
        let mut total = 0;
        loop {
            match decoder.read(&mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => {
                    total += n;
                    if total >= LOOSE_OBJECT_HEADER_MAX_BYTES {
                        break;
                    }
                }
                Err(err) => {
                    return Err(SyntheticCommitRefError::ObjectLookup {
                        detail: format!("loose object inflate failed: {err}"),
                    });
                }
            }
        }

        return Ok(Some(parse_loose_object_kind(&buf[..total])?));
    }

    Ok(None)
}

/// Parse the object type from a decompressed loose object header.
///
/// The git loose format is `<type> <size>\0<body>`. This function extracts
/// the type keyword before the first space, validates the size field between
/// the space and the NUL terminator, and maps the type to [`ObjectKind`].
/// Returns an error for malformed headers, invalid size fields, or
/// unrecognized type strings.
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
    let size_bytes = &header[space + 1..];
    if size_bytes.is_empty() || !size_bytes.iter().all(u8::is_ascii_digit) {
        return Err(SyntheticCommitRefError::ObjectLookup {
            detail: "loose object header has an invalid size field".to_string(),
        });
    }

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
    use crate::StartSetConfig;

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
    fn materialize_synthetic_commit_ref_rejects_format_mismatch() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let mirror = init_repo(&tmp);
        git(&mirror, &["commit", "--allow-empty", "-m", "first"]);

        // SHA-256 OID against a SHA-1 mirror triggers the format guard.
        let sha256_oid =
            parse_oid("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");

        let err = materialize_synthetic_commit_ref(&mirror, sha256_oid, RepoOpenLimits::default())
            .expect_err("format mismatch must fail");

        assert!(matches!(
            err,
            SyntheticCommitRefError::ObjectFormatMismatch { .. }
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

    #[test]
    fn materialize_synthetic_commit_ref_resolves_pack_only_commit() {
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

        // Repack the mirror so all objects live exclusively in packs,
        // then prune loose objects. This forces the kind-resolution
        // path through the MIDX + pack-header walker.
        git(&mirror, &["repack", "-a", "-d"]);
        git(&mirror, &["prune-packed"]);

        let ref_name = materialize_synthetic_commit_ref(&mirror, commit, RepoOpenLimits::default())
            .expect("pack-only commit should materialize");
        let ref_name_str = String::from_utf8(ref_name).expect("utf-8 ref name");
        assert_eq!(
            git(&mirror, &["rev-parse", &ref_name_str]),
            commit.to_string(),
        );
    }
}
