//! MIDX build scaling benchmarks.
//!
//! Characterizes `build_midx_bytes` for synthetic pack-index layouts with
//! controllable object counts and pack fan-in. This exposes merge/fanout
//! behavior under large in-memory MIDX builds.
//!
//! Usage:
//! `cargo bench --bench midx_build_scaling`

use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use scanner_git::{build_midx_bytes, GitRepoPaths, MidxBuildLimits, ObjectFormat, RepoKind};
use tempfile::TempDir;

const OID_LEN_SHA1: usize = 20;
const FANOUT_ENTRIES: usize = 256;
const FANOUT_SIZE: usize = FANOUT_ENTRIES * 4;

struct MidxFixture {
    temp: TempDir,
    repo: GitRepoPaths,
    limits: MidxBuildLimits,
    total_objects: usize,
}

struct TestIdxBuilder {
    objects: Vec<([u8; OID_LEN_SHA1], u64)>,
}

impl TestIdxBuilder {
    fn new() -> Self {
        Self {
            objects: Vec::new(),
        }
    }

    fn add_object(&mut self, oid: [u8; OID_LEN_SHA1], offset: u64) {
        self.objects.push((oid, offset));
    }

    fn build(&self) -> Vec<u8> {
        const IDX_MAGIC: [u8; 4] = [0xff, b't', b'O', b'c'];
        const IDX_VERSION: u32 = 2;

        let mut objects = self.objects.clone();
        objects.sort_by(|a, b| a.0.cmp(&b.0));

        let mut fanout = vec![0u8; FANOUT_SIZE];
        let mut counts = [0u32; FANOUT_ENTRIES];
        for (oid, _) in &objects {
            counts[oid[0] as usize] += 1;
        }

        let mut running = 0u32;
        for (i, count) in counts.iter().enumerate() {
            running += count;
            let off = i * 4;
            fanout[off..off + 4].copy_from_slice(&running.to_be_bytes());
        }

        let mut oid_table = Vec::with_capacity(objects.len() * OID_LEN_SHA1);
        let mut crc_table = Vec::with_capacity(objects.len() * 4);
        let mut offset_table = Vec::with_capacity(objects.len() * 4);
        for (oid, offset) in &objects {
            oid_table.extend_from_slice(oid);
            crc_table.extend_from_slice(&0u32.to_be_bytes());
            offset_table.extend_from_slice(&(*offset as u32).to_be_bytes());
        }

        let checksums = vec![0u8; 40]; // pack checksum + idx checksum

        let mut out = Vec::new();
        out.extend_from_slice(&IDX_MAGIC);
        out.extend_from_slice(&IDX_VERSION.to_be_bytes());
        out.extend_from_slice(&fanout);
        out.extend_from_slice(&oid_table);
        out.extend_from_slice(&crc_table);
        out.extend_from_slice(&offset_table);
        out.extend_from_slice(&checksums);
        out
    }
}

fn synthetic_oid(pack_id: usize, local_idx: usize, pack_count: usize) -> [u8; OID_LEN_SHA1] {
    let logical = local_idx as u64 * pack_count as u64 + pack_id as u64;
    let mut oid = [0u8; OID_LEN_SHA1];
    oid[0] = (logical & 0xff) as u8;
    oid[1] = ((logical >> 8) & 0xff) as u8;
    oid[2] = ((logical >> 16) & 0xff) as u8;
    oid[3] = ((logical >> 24) & 0xff) as u8;
    oid[4] = ((logical >> 32) & 0xff) as u8;
    oid[5] = ((logical >> 40) & 0xff) as u8;
    oid[6] = (pack_id & 0xff) as u8;
    oid[7] = ((pack_id >> 8) & 0xff) as u8;
    oid[8] = ((local_idx >> 8) & 0xff) as u8;
    oid[9] = (local_idx & 0xff) as u8;
    oid[10] = (logical.wrapping_mul(131) & 0xff) as u8;
    oid[11] = (logical.wrapping_mul(197) & 0xff) as u8;
    oid[12] = (logical.wrapping_mul(251) & 0xff) as u8;
    oid[13] = (logical.wrapping_mul(17) & 0xff) as u8;
    oid[14] = (logical.wrapping_mul(29) & 0xff) as u8;
    oid[15] = (logical.wrapping_mul(43) & 0xff) as u8;
    oid[16] = (local_idx & 0xff) as u8;
    oid[17] = ((local_idx >> 8) & 0xff) as u8;
    oid[18] = ((local_idx >> 16) & 0xff) as u8;
    oid[19] = ((local_idx >> 24) & 0xff) as u8;
    oid
}

fn build_fixture(pack_count: usize, objects_per_pack: usize) -> MidxFixture {
    let temp = tempfile::tempdir().expect("tempdir");
    let git_dir = temp.path().join(".git");
    let objects_dir = git_dir.join("objects");
    let pack_dir = objects_dir.join("pack");
    fs::create_dir_all(&pack_dir).expect("create pack dir");

    for pack_id in 0..pack_count {
        let mut idx = TestIdxBuilder::new();
        for local_idx in 0..objects_per_pack {
            let oid = synthetic_oid(pack_id, local_idx, pack_count);
            let offset = ((local_idx as u64 + 1) * 64).min(u32::MAX as u64 - 1);
            idx.add_object(oid, offset);
        }
        let idx_path = pack_dir.join(format!("pack-{pack_id:04}.idx"));
        fs::write(idx_path, idx.build()).expect("write idx");
    }

    let repo = GitRepoPaths {
        kind: RepoKind::Worktree,
        worktree_root: Some(temp.path().to_path_buf()),
        git_dir: git_dir.clone(),
        common_dir: git_dir,
        objects_dir,
        pack_dir,
        alternate_object_dirs: Vec::<PathBuf>::new(),
    };

    let total_objects = pack_count * objects_per_pack;
    let limits = MidxBuildLimits {
        max_packs: pack_count as u16 + 8,
        max_total_objects: total_objects as u64 + 1024,
        max_midx_total_bytes: 2 * 1024 * 1024 * 1024,
        max_midx_bytes_in_ram: 2 * 1024 * 1024 * 1024,
    };

    // Validate fixture once before benchmarking iterations.
    let _ = build_midx_bytes(&repo, ObjectFormat::Sha1, &limits).expect("fixture should parse");

    MidxFixture {
        temp,
        repo,
        limits,
        total_objects,
    }
}

fn bench_scale_objects(c: &mut Criterion) {
    let mut group = c.benchmark_group("midx_build_scaling/object_count");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    for (pack_count, objects_per_pack) in [(8usize, 8_192usize), (8, 16_384), (8, 32_768)] {
        let fixture = build_fixture(pack_count, objects_per_pack);
        let _ = fixture.temp.path();
        let total_objects = fixture.total_objects;
        let label = format!("packs{pack_count}_objects{total_objects}");
        group.throughput(Throughput::Elements(total_objects as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let out = build_midx_bytes(
                        black_box(&fixture.repo),
                        ObjectFormat::Sha1,
                        black_box(&fixture.limits),
                    )
                    .expect("midx build should succeed");
                    black_box(out.len());
                });
            },
        );
    }

    group.finish();
}

fn bench_scale_pack_fan_in(c: &mut Criterion) {
    let mut group = c.benchmark_group("midx_build_scaling/pack_fan_in");
    group.sample_size(10);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(2));

    const TOTAL_OBJECTS: usize = 131_072;
    for pack_count in [2usize, 4, 8, 16] {
        let objects_per_pack = TOTAL_OBJECTS / pack_count;
        let fixture = build_fixture(pack_count, objects_per_pack);
        let _ = fixture.temp.path();
        let label = format!("packs{pack_count}_objects{}", fixture.total_objects);
        group.throughput(Throughput::Elements(fixture.total_objects as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(label),
            &fixture,
            |b, fixture| {
                b.iter(|| {
                    let out = build_midx_bytes(
                        black_box(&fixture.repo),
                        ObjectFormat::Sha1,
                        black_box(&fixture.limits),
                    )
                    .expect("midx build should succeed");
                    black_box(out.len());
                });
            },
        );
    }

    group.finish();
}

criterion_group!(benches, bench_scale_objects, bench_scale_pack_fan_in);
criterion_main!(benches);
