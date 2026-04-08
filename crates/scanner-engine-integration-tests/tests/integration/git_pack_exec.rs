//! Integration test for pack plan execution against git cat-file.
//!
//! This test builds a temporary repository, forces a pack file via GC,
//! executes a pack plan for a subset of blobs, and compares decoded bytes
//! with `git cat-file -p`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::git_test_support::{decode_hex, init_git_repo, run_git};
use scanner_git::{
    ByteArena, ByteRef, CandidateContext, ChangeKind, OidBytes, PackCache, PackCandidate,
    PackDecodeLimits, PackPlanConfig, PackView, build_pack_plans, execute_pack_plan,
};
use scanner_git::{ExternalBase, ExternalBaseProvider, PackExecError, PackObjectSink};

fn perf_stats_enabled() -> bool {
    cfg!(all(feature = "perf-stats", debug_assertions))
}

/// External base provider that always reports missing bases.
struct NoExternalBases {
    calls: u32,
}

impl ExternalBaseProvider for NoExternalBases {
    fn load_base(&mut self, _oid: &OidBytes) -> Result<Option<ExternalBase>, PackExecError> {
        self.calls += 1;
        Ok(None)
    }
}

/// Sink that collects decoded blob bytes by OID.
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

/// Writes a file and panics on error (test helper).
fn write_file(path: &Path, contents: &str) {
    fs::write(path, contents).expect("write file");
}

/// Returns the first `.idx` and its corresponding `.pack` path.
fn find_pack_paths(pack_dir: &Path) -> (PathBuf, PathBuf) {
    let mut idx_path = None;
    let mut pack_path = None;
    for entry in fs::read_dir(pack_dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("idx") {
            idx_path = Some(path.clone());
            let pack = path.with_extension("pack");
            pack_path = Some(pack);
            break;
        }
    }
    (idx_path.expect("idx"), pack_path.expect("pack"))
}

/// Encodes bytes as lowercase hex.
fn to_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Parses `git verify-pack -v` output and returns blob OIDs + offsets.
fn load_verify_pack(idx_path: &Path, oid_len: usize) -> Vec<(OidBytes, u64)> {
    let output = Command::new("git")
        .args(["verify-pack", "-v", idx_path.to_str().unwrap()])
        .output()
        .expect("verify-pack");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();

    let mut out = Vec::new();
    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        let oid_hex = parts[0];
        let kind = parts[1];
        let offset = parts[4].parse::<u64>().unwrap();
        if kind == "blob" && oid_hex.len() == oid_len * 2 {
            let bytes = decode_hex(oid_hex);
            let oid = OidBytes::from_slice(&bytes);
            out.push((oid, offset));
        }
    }
    out
}

/// Builds a canonical candidate context for tests.
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

#[test]
fn pack_exec_matches_git_cat_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let repo = tmp.path();

    init_git_repo(repo, "test@example.com", "Test User");
    write_file(&repo.join("a.txt"), "alpha");
    write_file(&repo.join("b.txt"), "bravo");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "c1"]);
    write_file(&repo.join("a.txt"), "alpha changed");
    write_file(&repo.join("c.txt"), "charlie");
    run_git(repo, &["add", "."]);
    run_git(repo, &["commit", "-m", "c2"]);

    run_git(repo, &["gc", "--aggressive", "--prune=now"]);

    let pack_dir = repo.join(".git/objects/pack");
    let (idx_path, pack_path) = find_pack_paths(&pack_dir);
    let pack_bytes = fs::read(&pack_path).unwrap();

    let entries = load_verify_pack(&idx_path, 20);
    assert!(!entries.is_empty());
    let sample: Vec<_> = entries.into_iter().take(3).collect();

    let mut arena = ByteArena::with_capacity(1024);
    let mut candidates = Vec::new();
    for (i, (oid, offset)) in sample.iter().enumerate() {
        let path = format!("blob-{i}.txt");
        let path_ref = arena.intern(path.as_bytes()).unwrap();
        candidates.push(PackCandidate {
            oid: *oid,
            ctx: ctx(path_ref),
            pack_id: 0,
            offset: *offset,
        });
    }

    let pack_view = PackView::parse(&pack_bytes, 20).unwrap();
    let mut resolver_map = HashMap::new();
    let all_entries = load_verify_pack(&idx_path, 20);
    for (oid, offset) in all_entries {
        resolver_map.insert(oid, (0u16, offset));
    }

    struct Resolver {
        map: HashMap<OidBytes, (u16, u64)>,
    }
    impl scanner_git::OidResolver for Resolver {
        fn resolve(
            &self,
            oid: &OidBytes,
        ) -> Result<Option<(u16, u64)>, scanner_git::PackPlanError> {
            Ok(self.map.get(oid).copied())
        }
    }

    let resolver = Resolver { map: resolver_map };
    let plans = build_pack_plans(
        candidates,
        &[Some(pack_view)],
        &resolver,
        &PackPlanConfig::default(),
    )
    .unwrap();
    assert_eq!(plans.len(), 1);
    let plan = plans.into_iter().next().unwrap();

    let limits = PackDecodeLimits::new(64, 2 * 1024 * 1024, 2 * 1024 * 1024);
    let mut cache = PackCache::new(4 * 1024 * 1024);
    let mut external = NoExternalBases { calls: 0 };
    let mut sink = CollectingSink::default();
    let spill_dir = tempfile::tempdir().unwrap();

    let report = execute_pack_plan(
        &plan,
        &pack_bytes,
        &arena,
        &limits,
        &mut cache,
        &mut external,
        &mut sink,
        spill_dir.path(),
    )
    .unwrap();

    assert_eq!(report.stats.external_base_calls, external.calls);
    if perf_stats_enabled() {
        assert!(report.stats.emitted_candidates > 0);
    } else {
        assert_eq!(report.stats.emitted_candidates, 0);
    }

    for (oid, _) in sample {
        let hex = to_hex(oid.as_slice());
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["cat-file", "-p", &hex])
            .output()
            .expect("git cat-file");
        assert!(output.status.success());
        let expected = output.stdout;
        let actual = sink.blobs.get(&oid).expect("blob decoded");
        assert_eq!(&expected, actual);
    }
}
