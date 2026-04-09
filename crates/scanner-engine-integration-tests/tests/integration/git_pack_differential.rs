//! Differential tests for pack decoding against `git cat-file`.
//!
//! Each fixture repo is packed on disk, then the test suite compares:
//! - `PackIo::load_object` for every reachable object type.
//! - `execute_pack_plan` for every reachable blob object.

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};

use crate::git_test_support::{git_available, git_stdout, init_git_repo, oid_from_hex, run_git};
use gossip_stdx::git_test_support::git_output_raw;
use scanner_git::pack_inflate::ObjectKind;
use scanner_git::{
    ByteArena, ByteRef, CandidateContext, ChangeKind, GitRepoPaths, MidxBuildLimits, MidxView,
    ObjectFormat, OidBytes, PackCache, PackCandidate, PackDecodeLimits, PackExecError, PackIo,
    PackIoLimits, PackObjectSink, PackPlanConfig, PackView, RepoOpenError, RepoOpenLimits,
    build_midx_bytes, build_pack_plans, collect_loose_dirs, collect_pack_dirs, execute_pack_plan,
    resolve_pack_paths_from_midx,
};
use tempfile::TempDir;

#[derive(Clone, Debug)]
struct ReachableObject {
    oid: OidBytes,
    kind: ObjectKind,
    expected: Vec<u8>,
}

#[derive(Debug)]
struct PackRepoArtifacts {
    midx_bytes: Vec<u8>,
    pack_paths: Vec<PathBuf>,
    pack_bytes: Vec<Vec<u8>>,
    loose_dirs: Vec<PathBuf>,
}

#[derive(Clone, Copy, Debug)]
struct LayoutExpectations {
    min_objects: usize,
    min_packs: usize,
    require_tag: bool,
    require_delta_objects: bool,
}

#[derive(Default)]
struct VerifyPackStats {
    delta_objects: usize,
    max_delta_depth: usize,
}

#[derive(Default)]
struct CollectingSink {
    blobs: HashMap<OidBytes, Vec<u8>>,
}

impl PackObjectSink for CollectingSink {
    fn emit(
        &mut self,
        candidate: &PackCandidate,
        _path: &[u8],
        bytes: &[u8],
    ) -> Result<(), PackExecError> {
        self.blobs.insert(candidate.oid, bytes.to_vec());
        Ok(())
    }
}

fn decode_limits() -> PackDecodeLimits {
    PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024)
}

fn pack_io_limits() -> PackIoLimits {
    PackIoLimits::new(decode_limits(), 64)
}

fn ctx(path_ref: ByteRef) -> CandidateContext {
    CandidateContext {
        commit_id: 1,
        parent_idx: 0,
        change_kind: ChangeKind::Add,
        ctx_flags: 0,
        cand_flags: 0,
        path_ref,
    }
}

fn deterministic_blob(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state >> 12;
        state ^= state << 25;
        state ^= state >> 27;
        let next = state.wrapping_mul(0x2545_F491_4F6C_DD1D);
        out.push((next >> 56) as u8);
        state = next;
    }
    out
}

fn object_kind_name(kind: ObjectKind) -> &'static str {
    match kind {
        ObjectKind::Commit => "commit",
        ObjectKind::Tree => "tree",
        ObjectKind::Blob => "blob",
        ObjectKind::Tag => "tag",
    }
}

fn parse_object_kind(name: &str) -> ObjectKind {
    match name {
        "commit" => ObjectKind::Commit,
        "tree" => ObjectKind::Tree,
        "blob" => ObjectKind::Blob,
        "tag" => ObjectKind::Tag,
        other => panic!("unexpected git object type: {other}"),
    }
}

fn write_bytes(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes)
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", path.display()));
}

fn create_simple_gc_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    init_git_repo(repo, "test@example.com", "Test User");

    fs::create_dir_all(repo.join("src")).unwrap();
    fs::create_dir_all(repo.join("nested/deep")).unwrap();
    write_bytes(&repo.join("src/a.txt"), b"alpha\n");
    write_bytes(&repo.join("src/config.json"), b"{\"enabled\":true}\n");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "c1"]);

    write_bytes(&repo.join("src/a.txt"), b"alpha\nbeta\n");
    write_bytes(&repo.join("nested/deep/tree.txt"), b"tree payload\n");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "c2"]);

    write_bytes(
        &repo.join("nested/deep/tree.txt"),
        b"tree payload\nwith extra line\n",
    );
    write_bytes(&repo.join("notes.md"), b"# release notes\n");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "c3"]);
    run_git(repo, &["tag", "-a", "v1", "-m", "release v1"]);

    let large_blob = deterministic_blob(0x51_44_10, 96 * 1024);
    write_bytes(&repo.join("large.bin"), &large_blob);
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "c4"]);

    run_git(repo, &["gc", "--aggressive", "--prune=now"]);
    tmp
}

fn create_delta_heavy_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    init_git_repo(repo, "test@example.com", "Test User");

    fs::create_dir_all(repo.join("history")).unwrap();
    let mut blob = deterministic_blob(0xDE_1A_57, 96 * 1024);
    for step in 0..18usize {
        let start = (step * 709) % (blob.len() - 512);
        let replacement = deterministic_blob(0xB10B + step as u64, 512);
        blob[start..start + replacement.len()].copy_from_slice(&replacement);
        write_bytes(&repo.join("history/delta.bin"), &blob);
        write_bytes(
            &repo.join("history/manifest.txt"),
            format!("step={step}\nwindow={start}\n").as_bytes(),
        );
        run_git(repo, &["add", "."]);
        run_git(repo, &["commit", "-q", "-m", &format!("delta-{step:02}")]);
    }

    run_git(repo, &["gc", "--aggressive", "--prune=now"]);
    tmp
}

fn create_multi_pack_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    init_git_repo(repo, "test@example.com", "Test User");

    for idx in 0..12usize {
        let file = repo.join(format!("blob-{idx:02}.bin"));
        let blob = deterministic_blob(0xABCD_0000 + idx as u64, 250_000);
        write_bytes(&file, &blob);
        run_git(repo, &["add", "."]);
        run_git(repo, &["commit", "-q", "-m", &format!("blob-{idx:02}")]);
    }

    run_git(repo, &["repack", "-ad", "--max-pack-size=1m"]);
    tmp
}

fn reachable_objects(repo: &Path) -> Vec<ReachableObject> {
    let mut seen = BTreeSet::new();
    let mut objects = Vec::new();
    for line in git_stdout(repo, &["rev-list", "--objects", "--all"]).lines() {
        let Some(hex) = line.split_whitespace().next() else {
            continue;
        };
        if !seen.insert(hex.to_owned()) {
            continue;
        }
        let oid = oid_from_hex(hex);
        let kind = parse_object_kind(&git_stdout(repo, &["cat-file", "-t", &oid.to_string()]));
        let expected = git_output_raw(
            repo,
            &["cat-file", object_kind_name(kind), &oid.to_string()],
        )
        .stdout;
        objects.push(ReachableObject {
            oid,
            kind,
            expected,
        });
    }
    objects.sort_by(|left, right| left.oid.to_string().cmp(&right.oid.to_string()));
    objects
}

fn pack_repo_artifacts(repo: &Path) -> PackRepoArtifacts {
    let paths = GitRepoPaths::resolve::<RepoOpenError, _>(repo, &RepoOpenLimits::DEFAULT).unwrap();
    let midx_bytes = build_midx_bytes(&paths, ObjectFormat::Sha1, &MidxBuildLimits::default())
        .unwrap()
        .as_slice()
        .to_vec();
    let midx = MidxView::parse(midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let pack_dirs = collect_pack_dirs(&paths);
    let pack_paths = resolve_pack_paths_from_midx(&midx, &pack_dirs).unwrap();
    let pack_bytes = pack_paths
        .iter()
        .map(|path| {
            fs::read(path).unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()))
        })
        .collect();
    let loose_dirs = collect_loose_dirs(&paths);
    PackRepoArtifacts {
        midx_bytes,
        pack_paths,
        pack_bytes,
        loose_dirs,
    }
}

fn verify_pack_stats(repo: &Path, pack_paths: &[PathBuf]) -> VerifyPackStats {
    let mut stats = VerifyPackStats::default();
    for idx_path in pack_paths.iter().map(|path| path.with_extension("idx")) {
        let output = git_output_raw(repo, &["verify-pack", "-v", idx_path.to_str().unwrap()]);
        let stdout = String::from_utf8(output.stdout).unwrap();
        for line in stdout.lines() {
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 7 || parts[0].len() != 40 {
                continue;
            }
            let depth = parts[5]
                .parse::<usize>()
                .unwrap_or_else(|err| panic!("failed to parse delta depth from {line:?}: {err}"));
            stats.delta_objects += 1;
            stats.max_delta_depth = stats.max_delta_depth.max(depth);
        }
    }
    stats
}

fn build_blob_candidates(
    records: &[ReachableObject],
    midx: &MidxView<'_>,
) -> (ByteArena, Vec<PackCandidate>) {
    let mut arena = ByteArena::with_capacity((records.len() * 32).try_into().unwrap());
    let mut candidates = Vec::new();
    for record in records {
        if record.kind != ObjectKind::Blob {
            continue;
        }
        let idx = midx
            .find_oid(&record.oid)
            .unwrap()
            .unwrap_or_else(|| panic!("blob {} missing from MIDX", record.oid));
        let (pack_id, offset) = midx.offset_at(idx).unwrap();
        let path_ref = arena
            .intern(format!("blob-{}", record.oid).as_bytes())
            .unwrap();
        candidates.push(PackCandidate {
            oid: record.oid,
            ctx: ctx(path_ref),
            pack_id,
            offset,
        });
    }
    (arena, candidates)
}

fn verify_pack_io_against_git(records: &[ReachableObject], artifacts: &PackRepoArtifacts) {
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let mut pack_io = PackIo::from_parts(
        midx,
        artifacts.pack_paths.clone(),
        artifacts.loose_dirs.clone(),
        pack_io_limits(),
    )
    .unwrap();

    for record in records {
        let (actual_kind, actual_bytes) = pack_io
            .load_object(&record.oid)
            .unwrap_or_else(|err| panic!("PackIo failed to load {}: {err}", record.oid))
            .unwrap_or_else(|| panic!("PackIo returned None for {}", record.oid));
        assert_eq!(actual_kind, record.kind, "kind mismatch for {}", record.oid);
        assert_eq!(
            actual_bytes.as_slice(),
            record.expected.as_slice(),
            "payload mismatch for {}",
            record.oid
        );
    }
}

fn verify_pack_exec_against_git(records: &[ReachableObject], artifacts: &PackRepoArtifacts) {
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let (arena, candidates) = build_blob_candidates(records, &midx);
    assert!(
        !candidates.is_empty(),
        "expected at least one reachable blob"
    );

    let pack_views: Vec<Option<PackView<'_>>> = artifacts
        .pack_bytes
        .iter()
        .map(|bytes| Some(PackView::parse(bytes, OidBytes::SHA1_LEN).unwrap()))
        .collect();
    let plans =
        build_pack_plans(candidates, &pack_views, &midx, &PackPlanConfig::default()).unwrap();
    assert!(!plans.is_empty(), "expected at least one pack plan");

    let external_midx =
        MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let mut external = PackIo::from_parts(
        external_midx,
        artifacts.pack_paths.clone(),
        artifacts.loose_dirs.clone(),
        pack_io_limits(),
    )
    .unwrap();
    let mut cache = PackCache::new(128 * 1024);
    let mut sink = CollectingSink::default();
    let spill_dir = tempfile::tempdir().unwrap();
    let decode_limits = decode_limits();

    for plan in &plans {
        execute_pack_plan(
            plan,
            &artifacts.pack_bytes[plan.pack_id() as usize],
            &arena,
            &decode_limits,
            &mut cache,
            &mut external,
            &mut sink,
            spill_dir.path(),
        )
        .unwrap_or_else(|err| {
            panic!(
                "execute_pack_plan failed for pack {}: {err}",
                plan.pack_id()
            )
        });
    }

    let expected_blob_count = records
        .iter()
        .filter(|record| record.kind == ObjectKind::Blob)
        .count();
    assert_eq!(sink.blobs.len(), expected_blob_count);
    for record in records {
        if record.kind != ObjectKind::Blob {
            continue;
        }
        let actual = sink
            .blobs
            .get(&record.oid)
            .unwrap_or_else(|| panic!("missing decoded blob {}", record.oid));
        assert_eq!(
            actual.as_slice(),
            record.expected.as_slice(),
            "blob payload mismatch for {}",
            record.oid
        );
    }
}

fn verify_repo_against_git(repo: &Path, expectations: LayoutExpectations) {
    let records = reachable_objects(repo);
    assert!(
        records.len() >= expectations.min_objects,
        "expected at least {} reachable objects, saw {}",
        expectations.min_objects,
        records.len()
    );
    if expectations.require_tag {
        assert!(
            records.iter().any(|record| record.kind == ObjectKind::Tag),
            "expected at least one reachable tag object"
        );
    }

    let artifacts = pack_repo_artifacts(repo);
    assert!(
        artifacts.pack_paths.len() >= expectations.min_packs,
        "expected at least {} packs, saw {}",
        expectations.min_packs,
        artifacts.pack_paths.len()
    );
    let pack_stats = verify_pack_stats(repo, &artifacts.pack_paths);
    if expectations.require_delta_objects {
        assert!(
            pack_stats.delta_objects > 0,
            "expected at least one deltified object"
        );
    }

    verify_pack_io_against_git(&records, &artifacts);
    verify_pack_exec_against_git(&records, &artifacts);
}

#[test]
fn differential_simple_gc() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_simple_gc_repo();
    verify_repo_against_git(
        repo.path(),
        LayoutExpectations {
            min_objects: 12,
            min_packs: 1,
            require_tag: true,
            require_delta_objects: false,
        },
    );
}

#[test]
fn differential_delta_heavy() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_delta_heavy_repo();
    verify_repo_against_git(
        repo.path(),
        LayoutExpectations {
            min_objects: 40,
            min_packs: 1,
            require_tag: false,
            require_delta_objects: true,
        },
    );
}

#[test]
fn differential_multi_pack() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_multi_pack_repo();
    verify_repo_against_git(
        repo.path(),
        LayoutExpectations {
            min_objects: 30,
            min_packs: 2,
            require_tag: false,
            require_delta_objects: false,
        },
    );
}
