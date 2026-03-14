use super::*;
use crate::RepoKind;
use tempfile::tempdir;

use super::super::delta_test_helpers::{
    encode_entry_header, encode_ofs_distance, encode_varint, zlib_compress,
};
use super::super::midx_test_builder::MidxBuilder;

fn build_pack_with_large_ofs_delta(base: &[u8], result: &[u8]) -> (Vec<u8>, u64, usize) {
    let mut delta = Vec::new();
    delta.extend_from_slice(&encode_varint(base.len() as u64));
    delta.extend_from_slice(&encode_varint(result.len() as u64));

    // Encode as a sequence of literal insert opcodes (1..=127 bytes each).
    // This produces a valid delta stream with deterministic size overhead.
    let mut pos = 0usize;
    while pos < result.len() {
        let chunk = (result.len() - pos).min(127);
        delta.push(chunk as u8);
        delta.extend_from_slice(&result[pos..pos + chunk]);
        pos += chunk;
    }

    let mut out = Vec::new();
    out.extend_from_slice(b"PACK");
    out.extend_from_slice(&2u32.to_be_bytes());
    out.extend_from_slice(&2u32.to_be_bytes());

    let base_offset = out.len() as u64;
    out.extend_from_slice(&encode_entry_header(3, base.len()));
    out.extend_from_slice(&zlib_compress(base));

    let delta_offset = out.len() as u64;
    out.extend_from_slice(&encode_entry_header(6, result.len()));
    out.extend_from_slice(&encode_ofs_distance(delta_offset - base_offset));
    out.extend_from_slice(&zlib_compress(&delta));
    out.extend_from_slice(&[0u8; 20]);

    (out, delta_offset, delta.len())
}

fn test_oid(byte: u8) -> OidBytes {
    let mut oid = [0u8; 20];
    oid[0] = byte;
    oid[19] = byte ^ 0x5a;
    OidBytes::sha1(oid)
}

fn test_repo_paths(base: &std::path::Path) -> GitRepoPaths {
    let git_dir = base.join(".git");
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    fs::create_dir_all(&pack_dir).unwrap();
    GitRepoPaths {
        kind: RepoKind::Worktree,
        worktree_root: Some(base.to_path_buf()),
        git_dir: git_dir.clone(),
        common_dir: git_dir,
        objects_dir,
        pack_dir,
        alternate_object_dirs: Vec::new(),
    }
}

fn sha1_hex(seed: u8) -> String {
    use std::fmt::Write as _;

    let mut out = String::with_capacity(40);
    for idx in 0..20u8 {
        let _ = write!(&mut out, "{:02x}", seed.wrapping_add(idx));
    }
    out
}

fn make_commit_bytes(
    author_name: &[u8],
    author_email: &[u8],
    committer_name: &[u8],
    committer_email: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(256);
    buf.extend_from_slice(b"tree ");
    buf.extend_from_slice(&[b'a'; 40]);
    buf.push(b'\n');
    buf.extend_from_slice(b"author ");
    buf.extend_from_slice(author_name);
    buf.extend_from_slice(b" <");
    buf.extend_from_slice(author_email);
    buf.extend_from_slice(b"> 1700000000 +0000\n");
    buf.extend_from_slice(b"committer ");
    buf.extend_from_slice(committer_name);
    buf.extend_from_slice(b" <");
    buf.extend_from_slice(committer_email);
    buf.extend_from_slice(b"> 1700000000 +0000\n");
    buf.push(b'\n');
    buf.extend_from_slice(b"commit message\n");
    buf
}

#[test]
fn intern_commit_identities_interner_failure_is_error_parse_failure_is_sentinel() {
    let valid = make_commit_bytes(b"Alice", b"alice@example.com", b"Bob", b"bob@example.com");
    assert!(parse_author_identity(&valid).is_some());
    assert!(parse_committer_identity(&valid).is_some());

    // With no interner capacity, this must be an error (never sentinel).
    let oid = test_oid(0xA1);
    let mut exhausted = IdentityInterner::with_capacity(0, 0);
    let err = intern_commit_identities(&valid, &mut exhausted, oid)
        .expect_err("interner failure must be a hard error");
    match err {
        CommitLoadError::IdentityInternError {
            oid: err_oid,
            field,
            reason,
        } => {
            assert_eq!(err_oid, oid);
            assert_eq!(field, "author_name");
            assert_eq!(reason, "arena_full");
        }
        other => panic!("unexpected error variant: {other:?}"),
    }

    // Parse failures still map to sentinel IDs even with zero interner
    // capacity, so ambiguity is impossible.
    let malformed = b"tree aaaa\n\ncommit body\n";
    let mut tiny = IdentityInterner::with_capacity(0, 0);
    let ids = intern_commit_identities(malformed, &mut tiny, test_oid(0xA2)).unwrap();
    assert_eq!(ids.author_name, SENTINEL_ID);
    assert_eq!(ids.author_email, SENTINEL_ID);
    assert_eq!(ids.committer_name, SENTINEL_ID);
    assert_eq!(ids.committer_email, SENTINEL_ID);
}

#[test]
fn limits_default_reasonable() {
    let limits = CommitLoadLimits::default();
    assert!(limits.max_commits >= 1_000_000);
    assert!(limits.max_commit_object_bytes >= 64 * 1024);
    assert!(limits.max_parents >= 16);
    assert!(limits.max_delta_depth >= 32);
    assert!(limits.max_shallow_file_bytes >= 1024 * 1024);
    assert_eq!(
        limits.max_shallow_roots as usize,
        ShallowBoundaryRoots::PREALLOC_CAPACITY
    );
}

#[test]
fn load_shallow_boundary_roots_missing_files_returns_empty() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    let roots =
        load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &CommitLoadLimits::default())
            .unwrap();
    assert!(roots.is_empty());
}

#[test]
fn load_shallow_boundary_roots_invalid_oid_is_invalid_data() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    fs::write(repo.git_dir.join("shallow"), "not-an-oid\n").unwrap();

    let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &CommitLoadLimits::default())
        .unwrap_err();
    match err {
        CommitLoadError::Io(err) => {
            assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn load_shallow_boundary_roots_rejects_oversized_file() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    let payload = format!("{}\n", sha1_hex(0x11));
    fs::write(repo.git_dir.join("shallow"), payload).unwrap();

    let limits = CommitLoadLimits {
        max_shallow_file_bytes: 8,
        ..CommitLoadLimits::default()
    };
    let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
    match err {
        CommitLoadError::ShallowFileTooLarge { path, size, limit } => {
            assert_eq!(path, repo.git_dir.join("shallow"));
            assert!(size > u64::from(limit));
            assert_eq!(limit, 8);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn load_shallow_boundary_roots_rejects_too_many_unique_roots() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    let shallow = format!("{}\n{}\n", sha1_hex(0x22), sha1_hex(0x33));
    fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

    let limits = CommitLoadLimits {
        max_shallow_roots: 1,
        max_commits: 10,
        ..CommitLoadLimits::default()
    };
    let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
    match err {
        CommitLoadError::TooManyShallowRoots {
            path,
            line,
            count,
            limit,
        } => {
            assert_eq!(path, repo.git_dir.join("shallow"));
            assert_eq!(line, 2);
            assert_eq!(count, 2);
            assert_eq!(limit, 1);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn load_shallow_boundary_roots_duplicates_do_not_trip_unique_limit() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    let oid = sha1_hex(0x44);
    let shallow = format!("{oid}\n{oid}\n{oid}\n");
    fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

    let limits = CommitLoadLimits {
        max_shallow_roots: 1,
        max_commits: 10,
        ..CommitLoadLimits::default()
    };
    let roots = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap();
    assert_eq!(roots.len(), 1);
}

#[test]
fn load_shallow_boundary_roots_clamps_limit_to_max_commits() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());
    let shallow = format!("{}\n{}\n", sha1_hex(0x55), sha1_hex(0x66));
    fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

    let limits = CommitLoadLimits {
        max_shallow_roots: 10,
        max_commits: 1,
        ..CommitLoadLimits::default()
    };
    let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
    match err {
        CommitLoadError::TooManyShallowRoots { limit, .. } => {
            assert_eq!(limit, 1);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn load_shallow_boundary_roots_clamps_limit_to_preallocated_capacity() {
    let temp = tempdir().unwrap();
    let repo = test_repo_paths(temp.path());

    let mut shallow = String::new();
    for idx in 0..=ShallowBoundaryRoots::PREALLOC_CAPACITY {
        // 40-hex-digit SHA-1 OIDs; all unique across this range.
        shallow.push_str(&format!("{:040x}\n", idx + 1));
    }
    fs::write(repo.git_dir.join("shallow"), shallow).unwrap();

    let limits = CommitLoadLimits {
        max_shallow_roots: 10_000,
        max_commits: 10_000,
        ..CommitLoadLimits::default()
    };
    let err = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap_err();
    match err {
        CommitLoadError::TooManyShallowRoots {
            line, count, limit, ..
        } => {
            assert_eq!(line as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY + 1);
            assert_eq!(count as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY + 1);
            assert_eq!(limit as usize, ShallowBoundaryRoots::PREALLOC_CAPACITY);
        }
        other => panic!("unexpected error variant: {other:?}"),
    }
}

#[test]
fn load_shallow_boundary_roots_reads_common_dir_for_linked_worktree() {
    let temp = tempdir().unwrap();
    let worktree_root = temp.path().join("worktree");
    let git_dir = worktree_root.join(".git");
    let common_dir = temp.path().join("common.git");
    fs::create_dir_all(git_dir.join("objects/pack")).unwrap();
    fs::create_dir_all(common_dir.join("objects/pack")).unwrap();

    fs::write(git_dir.join("shallow"), format!("{}\n", sha1_hex(0x77))).unwrap();
    fs::write(common_dir.join("shallow"), format!("{}\n", sha1_hex(0x88))).unwrap();

    let repo = GitRepoPaths {
        kind: RepoKind::Worktree,
        worktree_root: Some(worktree_root),
        git_dir: git_dir.clone(),
        common_dir: common_dir.clone(),
        objects_dir: common_dir.join("objects"),
        pack_dir: common_dir.join("objects/pack"),
        alternate_object_dirs: Vec::new(),
    };
    let limits = CommitLoadLimits {
        max_shallow_roots: 2,
        ..CommitLoadLimits::default()
    };

    let roots = load_shallow_boundary_roots(&repo, ObjectFormat::Sha1, &limits).unwrap();
    assert_eq!(roots.len(), 2);
}

#[test]
fn loaded_commit_size() {
    // LoadedCommit should be reasonably sized
    let size = std::mem::size_of::<LoadedCommit>();
    // OidBytes(33) + OidBytes(33) + Vec(24) + u64(8) = ~98 bytes
    assert!(size < 150, "LoadedCommit too large: {size}");
}

#[test]
fn enqueue_frontier_oid_skips_visited() {
    let oid = test_oid(0x11);
    let mut visited = HashSet::new();
    visited.insert(oid);
    let mut queued = HashSet::new();
    let mut frontier = VecDeque::new();

    assert!(!enqueue_frontier_oid(
        oid,
        &visited,
        &mut queued,
        &mut frontier
    ));
    assert!(frontier.is_empty());
    assert!(queued.is_empty());
}

#[test]
fn enqueue_frontier_oid_dedupes_queued_entries() {
    let oid = test_oid(0x22);
    let visited = HashSet::new();
    let mut queued = HashSet::new();
    let mut frontier = VecDeque::new();

    assert!(enqueue_frontier_oid(
        oid,
        &visited,
        &mut queued,
        &mut frontier
    ));
    assert!(!enqueue_frontier_oid(
        oid,
        &visited,
        &mut queued,
        &mut frontier
    ));
    assert_eq!(frontier.len(), 1);
    assert_eq!(frontier.front(), Some(&oid));
}

#[test]
fn enqueue_frontier_oid_preserves_first_seen_tip_order() {
    let a = test_oid(0x01);
    let b = test_oid(0x02);
    let c = test_oid(0x03);
    let tips = [a, b, a, c, b];

    let visited = HashSet::new();
    let mut queued = HashSet::new();
    let mut frontier = VecDeque::new();

    for oid in tips {
        let _ = enqueue_frontier_oid(oid, &visited, &mut queued, &mut frontier);
    }

    assert_eq!(frontier.len(), 3);
    assert_eq!(frontier.pop_front(), Some(a));
    assert_eq!(frontier.pop_front(), Some(b));
    assert_eq!(frontier.pop_front(), Some(c));
    assert!(frontier.is_empty());
}

#[test]
fn large_valid_delta_stream_within_limit_does_not_raise_inflate_error() {
    let base = Vec::new();
    let result = vec![b'Z'; 192 * 1024];
    let (pack, delta_offset, delta_stream_len) = build_pack_with_large_ofs_delta(&base, &result);
    assert!(delta_stream_len > result.len());

    let max_commit_object_bytes = delta_stream_len + 512;
    assert!(delta_stream_len <= max_commit_object_bytes);

    let temp = tempdir().unwrap();
    let pack_path = temp.path().join("pack-large-delta.pack");
    fs::write(&pack_path, &pack).unwrap();

    let mut builder = MidxBuilder::default();
    builder.add_pack(b"pack-large-delta");
    builder.add_object([0x10; 20], 0, 12);
    builder.add_object([0x20; 20], 0, delta_offset);
    let midx_bytes = builder.build();
    let midx = MidxView::parse(&midx_bytes, ObjectFormat::Sha1).unwrap();

    let limits = CommitLoadLimits {
        max_commit_object_bytes: max_commit_object_bytes as u32,
        ..CommitLoadLimits::default()
    };

    let pack_paths = vec![pack_path];
    let loose_dirs = Vec::new();
    let shallow_boundary_roots = ShallowBoundaryRoots::Empty;
    let mut loader = CommitLoader::new(
        &midx,
        &pack_paths,
        &loose_dirs,
        &shallow_boundary_roots,
        ObjectFormat::Sha1,
        &limits,
    )
    .unwrap();

    let loaded = loader
        .load_object_with_depth(0, delta_offset, limits.max_delta_depth)
        .unwrap();
    assert_eq!(loaded.0, ObjectKind::Blob);
    assert_eq!(loaded.1, result);
}
