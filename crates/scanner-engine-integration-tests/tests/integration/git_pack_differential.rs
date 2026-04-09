//! Differential tests for pack decoding against `git cat-file`.
//!
//! Each fixture repo is packed on disk, then the test suite compares:
//! - `PackIo::load_object` for every reachable object type.
//! - `execute_pack_plan` for every reachable blob object.

use std::collections::BTreeSet;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use crate::git_test_support::{
    CollectingSink, ctx, git_available, git_output_raw, git_stdout, init_git_repo, oid_from_hex,
    run_git,
};
use scanner_git::pack_inflate::ObjectKind;
use scanner_git::{
    ByteArena, GitRepoPaths, MidxBuildLimits, MidxView, ObjectFormat, OidBytes, PackCache,
    PackCandidate, PackDecodeLimits, PackIo, PackIoError, PackIoLimits, PackObjectSink,
    PackPlanConfig, PackView, RepoOpenError, RepoOpenLimits, build_midx_bytes, build_pack_plans,
    collect_loose_dirs, collect_pack_dirs, execute_pack_plan, resolve_pack_paths_from_midx,
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
    min_delta_depth: usize,
}

#[derive(Default)]
struct VerifyPackStats {
    delta_objects: usize,
    max_delta_depth: usize,
}

fn decode_limits() -> PackDecodeLimits {
    PackDecodeLimits::new(64, 8 * 1024 * 1024, 8 * 1024 * 1024)
}

fn pack_io_limits() -> PackIoLimits {
    PackIoLimits::new(decode_limits(), 64)
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
    write_bytes(&repo.join("empty.txt"), b"");
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

/// Packs a base repo via GC, then adds a commit with a new blob so that
/// the latest commit, tree, and blob remain as loose objects outside any pack.
fn create_mixed_loose_packed_repo() -> TempDir {
    let tmp = TempDir::new().unwrap();
    let repo = tmp.path();
    init_git_repo(repo, "test@example.com", "Test User");

    write_bytes(&repo.join("base.txt"), b"packed content\n");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "packed-base"]);
    run_git(repo, &["gc", "--aggressive", "--prune=now"]);

    // Post-GC commit leaves its objects loose.
    write_bytes(&repo.join("loose.txt"), b"loose content\n");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-q", "-m", "loose-tip"]);
    tmp
}

/// Enumerates objects reachable from all refs via `git rev-list --objects --all`.
///
/// Objects present in pack files but unreachable from any ref are not included.
/// For post-GC/repack repos this covers full pack contents; repos with orphaned
/// objects would have incomplete coverage.
///
/// Uses a single `git cat-file --batch` process to resolve type and content for
/// all OIDs, avoiding per-object subprocess overhead.
fn reachable_objects(repo: &Path) -> Vec<ReachableObject> {
    let mut seen = BTreeSet::new();
    let mut hex_oids = Vec::new();
    for line in git_stdout(repo, &["rev-list", "--objects", "--all"]).lines() {
        let Some(hex) = line.split_whitespace().next() else {
            continue;
        };
        if seen.insert(hex.to_owned()) {
            hex_oids.push(hex.to_owned());
        }
    }

    // Feed all OIDs to a single `git cat-file --batch` process.
    // Output per object: "<oid> <type> <size>\n<content>\n"
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(repo)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn git cat-file --batch");
    {
        let stdin = child.stdin.as_mut().unwrap();
        for hex in &hex_oids {
            writeln!(stdin, "{hex}").expect("failed to write OID to cat-file stdin");
        }
    }
    let output = child
        .wait_with_output()
        .expect("git cat-file --batch failed");
    assert!(
        output.status.success(),
        "git cat-file --batch exited with {:?}:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = &output.stdout;
    let mut pos = 0;
    let mut objects = Vec::with_capacity(hex_oids.len());
    while pos < stdout.len() {
        let header_end = stdout[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .unwrap_or_else(|| panic!("missing header newline at offset {pos}"));
        let header = std::str::from_utf8(&stdout[pos..pos + header_end])
            .expect("non-UTF8 header from cat-file --batch");
        pos += header_end + 1;

        let parts: Vec<&str> = header.split_whitespace().collect();
        assert!(
            parts.len() >= 3,
            "unexpected cat-file --batch header: {header:?}"
        );
        let hex = parts[0];
        let kind = parse_object_kind(parts[1]);
        let size: usize = parts[2]
            .parse()
            .unwrap_or_else(|err| panic!("failed to parse size from {header:?}: {err}"));

        let expected = stdout[pos..pos + size].to_vec();
        pos += size;
        // Skip trailing newline delimiter.
        assert_eq!(
            stdout.get(pos).copied(),
            Some(b'\n'),
            "expected trailing newline after {size}-byte object at offset {pos}"
        );
        pos += 1;

        objects.push(ReachableObject {
            oid: oid_from_hex(hex),
            kind,
            expected,
        });
    }

    objects.sort_by(|a, b| a.oid.cmp(&b.oid));
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
            // git verify-pack -v format for delta objects:
            //   SHA1 type size size-in-packfile offset depth base-SHA1
            // Non-delta objects have 5 fields; delta objects have 7.
            let parts: Vec<_> = line.split_whitespace().collect();
            if parts.len() < 7 || !parts[0].chars().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            if !matches!(parts[1], "commit" | "tree" | "blob" | "tag") {
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
    objects: &[ReachableObject],
    midx: &MidxView<'_>,
) -> (ByteArena, Vec<PackCandidate>) {
    // Each interned string is "blob-<40-hex-chars>" = 45 bytes. Use 48 for alignment headroom.
    let blob_count = objects
        .iter()
        .filter(|o| o.kind == ObjectKind::Blob)
        .count();
    let mut arena = ByteArena::with_capacity((blob_count * 48).max(64).try_into().unwrap());
    let mut candidates = Vec::new();
    for obj in objects {
        if obj.kind != ObjectKind::Blob {
            continue;
        }
        let Some(idx) = midx.find_oid(&obj.oid).unwrap() else {
            continue; // loose object, not in any pack
        };
        let (pack_id, offset) = midx.offset_at(idx).unwrap();
        let path_ref = arena
            .intern(format!("blob-{}", obj.oid).as_bytes())
            .unwrap();
        candidates.push(PackCandidate {
            oid: obj.oid,
            ctx: ctx(path_ref),
            pack_id,
            offset,
        });
    }
    (arena, candidates)
}

fn verify_pack_io_against_git(objects: &[ReachableObject], artifacts: &PackRepoArtifacts) {
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let mut pack_io = PackIo::from_parts(
        midx,
        artifacts.pack_paths.clone(),
        artifacts.loose_dirs.clone(),
        pack_io_limits(),
    )
    .unwrap();

    for obj in objects {
        let (actual_kind, actual_bytes) = pack_io
            .load_object(&obj.oid)
            .unwrap_or_else(|err| panic!("PackIo failed to load {}: {err}", obj.oid))
            .unwrap_or_else(|| panic!("PackIo returned None for {}", obj.oid));
        assert_eq!(actual_kind, obj.kind, "kind mismatch for {}", obj.oid);
        assert_eq!(
            actual_bytes.as_slice(),
            obj.expected.as_slice(),
            "payload mismatch for {}",
            obj.oid
        );
    }
}

fn verify_pack_exec_against_git(objects: &[ReachableObject], artifacts: &PackRepoArtifacts) {
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let (arena, candidates) = build_blob_candidates(objects, &midx);
    let packed_blob_count = candidates.len();
    assert!(
        packed_blob_count > 0,
        "expected at least one reachable packed blob"
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
        let report = execute_pack_plan(
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
        assert!(
            report.skips.is_empty(),
            "unexpected skips in pack {}: {:?}",
            plan.pack_id(),
            report.skips
        );
    }

    assert_eq!(
        sink.blobs.len(),
        packed_blob_count,
        "decoded blob count should match packed candidate count"
    );
    for obj in objects {
        if obj.kind != ObjectKind::Blob {
            continue;
        }
        let Some(actual) = sink.blobs.get(&obj.oid) else {
            continue; // loose blob not in any pack plan
        };
        assert_eq!(
            actual.as_slice(),
            obj.expected.as_slice(),
            "blob payload mismatch for {}",
            obj.oid
        );
    }
}

/// Full differential verification pipeline for a packed repository.
///
/// 1. Enumerates reachable objects via `git rev-list --objects --all`.
/// 2. Fetches ground-truth bytes from `git cat-file` for each object.
/// 3. Asserts layout expectations (min object count, min pack count, tags, deltas).
/// 4. Verifies `PackIo::load_object` returns byte-identical results for all object types.
/// 5. Verifies `execute_pack_plan` returns byte-identical results for all blobs.
fn verify_repo_against_git(repo: &Path, expectations: LayoutExpectations) {
    let objects = reachable_objects(repo);
    assert!(
        objects.len() >= expectations.min_objects,
        "expected at least {} reachable objects, saw {}",
        expectations.min_objects,
        objects.len()
    );
    if expectations.require_tag {
        assert!(
            objects.iter().any(|obj| obj.kind == ObjectKind::Tag),
            "expected at least one reachable tag object"
        );
    }

    let artifacts = pack_repo_artifacts(repo);
    assert!(
        artifacts.pack_paths.len() >= expectations.min_packs,
        "expected at least {} packs, saw {} (pack sizes: {:?})",
        expectations.min_packs,
        artifacts.pack_paths.len(),
        artifacts
            .pack_bytes
            .iter()
            .map(|b| b.len())
            .collect::<Vec<_>>()
    );
    let pack_stats = verify_pack_stats(repo, &artifacts.pack_paths);
    if expectations.require_delta_objects {
        assert!(
            pack_stats.delta_objects > 0,
            "expected at least one deltified object"
        );
    }
    if expectations.min_delta_depth > 0 {
        assert!(
            pack_stats.max_delta_depth >= expectations.min_delta_depth,
            "expected max delta depth >= {}, saw {}",
            expectations.min_delta_depth,
            pack_stats.max_delta_depth
        );
    }

    verify_pack_io_against_git(&objects, &artifacts);
    verify_pack_exec_against_git(&objects, &artifacts);
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
            min_objects: 20,
            min_packs: 1,
            require_tag: true,
            require_delta_objects: true,
            min_delta_depth: 1,
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
            min_delta_depth: 2,
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
            min_delta_depth: 0,
        },
    );
}

#[test]
fn differential_mixed_loose_packed() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_mixed_loose_packed_repo();
    verify_repo_against_git(
        repo.path(),
        LayoutExpectations {
            min_objects: 5,
            min_packs: 1,
            require_tag: false,
            require_delta_objects: false,
            min_delta_depth: 0,
        },
    );
}

#[test]
fn differential_missing_oid_returns_none() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_simple_gc_repo();
    let objects = reachable_objects(repo.path());
    let artifacts = pack_repo_artifacts(repo.path());
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();
    let mut pack_io = PackIo::from_parts(
        midx,
        artifacts.pack_paths.clone(),
        artifacts.loose_dirs.clone(),
        pack_io_limits(),
    )
    .unwrap();

    // Flip one bit in a known-existing OID to produce a near-miss that
    // exercises the MIDX binary search rather than trivially mismatching.
    let mut near_miss_bytes = objects[0].oid.as_slice().to_vec();
    near_miss_bytes[0] ^= 0x01;
    let near_miss = OidBytes::from_slice(&near_miss_bytes);
    let result = pack_io.load_object(&near_miss);
    assert!(
        matches!(result, Ok(None)),
        "expected Ok(None) for near-miss OID, got {result:?}"
    );
}

#[test]
fn differential_delta_depth_exceeded() {
    if !git_available() {
        eprintln!("git not available; skipping git pack differential tests");
        return;
    }

    let repo = create_delta_heavy_repo();
    let artifacts = pack_repo_artifacts(repo.path());
    let midx = MidxView::parse(artifacts.midx_bytes.as_slice(), ObjectFormat::Sha1).unwrap();

    // Tight depth limit forces DeltaDepthExceeded on deep delta chains.
    let tight_limits = PackIoLimits::new(decode_limits(), 1);
    let mut pack_io = PackIo::from_parts(
        midx,
        artifacts.pack_paths.clone(),
        artifacts.loose_dirs.clone(),
        tight_limits,
    )
    .unwrap();

    let objects = reachable_objects(repo.path());
    let mut saw_depth_exceeded = false;
    for obj in &objects {
        match pack_io.load_object(&obj.oid) {
            Err(PackIoError::DeltaDepthExceeded { .. }) => {
                saw_depth_exceeded = true;
            }
            Ok(_) => {}
            Err(other) => panic!("unexpected error loading {}: {other}", obj.oid),
        }
    }
    assert!(
        saw_depth_exceeded,
        "expected at least one DeltaDepthExceeded error with max_delta_depth=1"
    );
}

#[test]
#[should_panic(expected = "duplicate emit for OID")]
fn collecting_sink_rejects_duplicate_oid() {
    let oid = OidBytes::sha1([0xAA; 20]);
    let mut arena = ByteArena::with_capacity(64.try_into().unwrap());
    let path_ref = arena.intern(b"test-path").unwrap();
    let candidate = PackCandidate {
        oid,
        ctx: ctx(path_ref),
        pack_id: 0,
        offset: 0,
    };
    let mut sink = CollectingSink::default();
    sink.emit(&candidate, b"test-path", b"first").unwrap();
    sink.emit(&candidate, b"test-path", b"second").unwrap();
}
