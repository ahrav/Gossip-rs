//! Criterion benchmark for object_store iterative OFS-delta resolution.
//!
//! Exercises the iterative walk-forward + unwind path with synthetic
//! OFS-delta chains across varying chain depths and base sizes.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use flate2::write::ZlibEncoder;
use flate2::Compression;
use scanner_git::{
    acquire_midx, repo_open, ArtifactBuildLimits, ObjectStore, OidBytes, RefWatermarkStore,
    RepoOpenError, RepoOpenLimits, StartSetConfig, StartSetId, StartSetResolver, TreeDiffLimits,
};
use sha1::{Digest, Sha1};
use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

struct EmptyResolver;

impl StartSetResolver for EmptyResolver {
    fn resolve(
        &self,
        _paths: &scanner_git::GitRepoPaths,
    ) -> Result<Vec<(Vec<u8>, OidBytes)>, RepoOpenError> {
        Ok(Vec::new())
    }
}

struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

fn run_git(repo: &Path, args: &[&str]) {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("run git command");
    assert!(
        output.status.success(),
        "git {:?} failed:\nstdout:{}\nstderr:{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn encode_varint(mut value: usize, out: &mut Vec<u8>) {
    loop {
        let mut b = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            b |= 0x80;
        }
        out.push(b);
        if value == 0 {
            break;
        }
    }
}

fn encode_header_bytes(obj_type: u8, size: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut remaining = size as u64;
    let mut first = ((obj_type & 0x07) << 4) | ((remaining & 0x0f) as u8);
    remaining >>= 4;
    if remaining != 0 {
        first |= 0x80;
    }
    out.push(first);
    while remaining != 0 {
        let mut byte = (remaining & 0x7f) as u8;
        remaining >>= 7;
        if remaining != 0 {
            byte |= 0x80;
        }
        out.push(byte);
    }
    out
}

fn encode_ofs_distance(mut dist: u64) -> Vec<u8> {
    assert!(dist > 0, "ofs delta base distance must be positive");
    let mut bytes = Vec::new();
    bytes.push((dist & 0x7f) as u8);
    dist >>= 7;
    while dist > 0 {
        dist -= 1;
        bytes.push(((dist & 0x7f) as u8) | 0x80);
        dist >>= 7;
    }
    bytes.reverse();
    bytes
}

fn compress_zlib(data: &[u8]) -> Vec<u8> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data).expect("compress payload");
    encoder.finish().expect("finish zlib stream")
}

fn build_base_bytes(size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    for i in 0..size {
        out.push((i as u8).wrapping_mul(31).wrapping_add(7));
    }
    out
}

fn push_copy_all(delta: &mut Vec<u8>, size: usize) {
    let mut cmd = 0x80u8;
    let s0 = (size & 0xff) as u8;
    let s1 = ((size >> 8) & 0xff) as u8;
    let s2 = ((size >> 16) & 0xff) as u8;

    if s0 != 0 {
        cmd |= 0x10;
    }
    if s1 != 0 {
        cmd |= 0x20;
    }
    if s2 != 0 {
        cmd |= 0x40;
    }

    delta.push(cmd);
    if cmd & 0x10 != 0 {
        delta.push(s0);
    }
    if cmd & 0x20 != 0 {
        delta.push(s1);
    }
    if cmd & 0x40 != 0 {
        delta.push(s2);
    }
}

fn build_append_byte_delta(base_len: usize, append: u8) -> Vec<u8> {
    let mut delta = Vec::new();
    encode_varint(base_len, &mut delta);
    encode_varint(base_len.saturating_add(1), &mut delta);
    push_copy_all(&mut delta, base_len);
    delta.push(1); // insert len
    delta.push(append);
    delta
}

fn build_pack_with_ofs_chain(base_size: usize, depth: usize) -> (Vec<u8>, u64, usize) {
    let base = build_base_bytes(base_size);
    let mut current_size = base.len();

    let mut bytes = Vec::new();
    bytes.extend_from_slice(b"PACK");
    bytes.extend_from_slice(&2u32.to_be_bytes());
    bytes.extend_from_slice(&((depth as u32) + 1).to_be_bytes());

    let base_offset = bytes.len() as u64;
    bytes.extend_from_slice(&encode_header_bytes(2, base.len())); // tree
    bytes.extend_from_slice(&compress_zlib(&base));

    let mut prev_offset = base_offset;
    let mut target_offset = base_offset;
    for step in 0..depth {
        let delta_payload = build_append_byte_delta(current_size, (step as u8).wrapping_add(1));
        let offset = bytes.len() as u64;
        let dist = offset.saturating_sub(prev_offset);
        bytes.extend_from_slice(&encode_header_bytes(6, delta_payload.len())); // OFS_DELTA
        bytes.extend_from_slice(&encode_ofs_distance(dist));
        bytes.extend_from_slice(&compress_zlib(&delta_payload));
        prev_offset = offset;
        target_offset = offset;
        current_size = current_size.saturating_add(1);
    }

    let mut hasher = Sha1::new();
    hasher.update(&bytes);
    let digest: [u8; 20] = hasher.finalize().into();
    bytes.extend_from_slice(&digest);

    (bytes, target_offset, current_size)
}

fn setup_repo_for_pack(pack_bytes: &[u8]) -> (TempDir, scanner_git::RepoJobState) {
    let repo_dir = TempDir::new().expect("create repo tempdir");
    run_git(repo_dir.path(), &["init", "--bare", "--quiet"]);

    let pack_path = repo_dir
        .path()
        .join("objects")
        .join("pack")
        .join("pack-bench.pack");
    fs::write(&pack_path, pack_bytes).expect("write benchmark pack");
    let pack_path_str = pack_path.to_str().expect("pack path utf8");
    run_git(repo_dir.path(), &["index-pack", pack_path_str]);

    let start_set = StartSetConfig::ExplicitRefs { refs: Vec::new() };
    let mut repo = repo_open(
        repo_dir.path(),
        1,
        [0u8; 32],
        start_set.id(),
        &EmptyResolver,
        &EmptyWatermarkStore,
        RepoOpenLimits::default(),
    )
    .expect("repo_open");
    acquire_midx(&mut repo, &ArtifactBuildLimits::default()).expect("acquire_midx");

    (repo_dir, repo)
}

fn bench_object_store_iterative_delta(c: &mut Criterion) {
    let depths = [10usize, 20, 35, 50];
    let base_sizes = [1024usize, 8 * 1024, 64 * 1024];

    let mut group = c.benchmark_group("object_store_iterative_delta");
    for &base_size in &base_sizes {
        for &depth in &depths {
            let (pack_bytes, target_offset, result_size) =
                build_pack_with_ofs_chain(base_size, depth);
            let (_repo_dir, repo) = setup_repo_for_pack(&pack_bytes);

            let limits = TreeDiffLimits {
                max_tree_cache_bytes: 1,
                max_tree_delta_cache_bytes: 1,
                max_tree_bytes_in_flight: (result_size as u64).saturating_add(1024),
                ..TreeDiffLimits::default()
            };

            let spill_dir = TempDir::new().expect("create spill tempdir");
            let mut store =
                ObjectStore::open(&repo, &limits, spill_dir.path()).expect("open object store");

            group.throughput(Throughput::Bytes(result_size as u64));
            group.bench_function(
                BenchmarkId::new(format!("depth_{depth}"), format!("base_{base_size}")),
                |b| {
                    b.iter(|| {
                        let (kind, bytes, chain_len) = store
                            .bench_decode_pack_offset(0, target_offset, depth as u8)
                            .expect("decode iterative delta chain");
                        black_box((kind, bytes, chain_len));
                    });
                },
            );

            drop(store);
            drop(spill_dir);
            drop(repo);
            drop(_repo_dir);
        }
    }
    group.finish();
}

criterion_group!(benches, bench_object_store_iterative_delta);
criterion_main!(benches);
