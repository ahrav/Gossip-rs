//! OID hash quality/performance comparison on real pack-file OID sets.
//!
//! Usage:
//!   cargo bench --bench oid_hash_quality -- --repo <path> [--repo <path> ...]
//!       [--iters N] [--max-keys N]
//!
//! Default repos (if present):
//!   ../gitleaks ../tigerbeetle ../trufflehog
//!
//! When no repos are provided and none of the defaults exist, the benchmark
//! exits successfully after printing a skip message. This keeps
//! `cargo test --all-targets --all-features` usable in workspaces that do not
//! carry those external checkouts.
//!
//! The benchmark compares three hash strategies used (or proposed) for
//! open-addressed OID tables:
//! - `fnv1a64` (baseline historical choice)
//! - `splitmix_head_tail` (current: head/tail fold + SplitMix-style finalizer)
//! - `first8_le` (candidate fallback: direct first 8 OID bytes)
//!
//! It reports:
//! - collision/probe characteristics at 70% load factor
//! - lookup probe lengths for hits and misses
//! - build/lookup timing in ns/key

use std::env;
use std::fs;
use std::hint::black_box;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const FNV_OFFSET_BASIS: u64 = 0xcbf29ce484222325;
const FNV_PRIME: u64 = 0x100000001b3;
const LOAD_FACTOR_NUM: usize = 7;
const LOAD_FACTOR_DEN: usize = 10;

#[derive(Clone, Copy, Debug)]
struct Config {
    iters: usize,
    max_keys: Option<usize>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct OidKey {
    len: u8,
    bytes: [u8; 32],
}

impl OidKey {
    #[inline]
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

const EMPTY_OID: OidKey = OidKey {
    len: 0,
    bytes: [0u8; 32],
};

#[derive(Clone, Copy, Debug)]
struct Slot {
    key: OidKey,
    tag: u8,
    used: bool,
}

impl Slot {
    const EMPTY: Self = Self {
        key: EMPTY_OID,
        tag: 0,
        used: false,
    };
}

#[derive(Debug)]
struct HashStrategy {
    name: &'static str,
    hash: fn(&OidKey) -> u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct ProbeStats {
    total_probes: u64,
    total_extra_probes: u64,
    max_probe: u32,
    operations: u64,
    found: u64,
    tag_matches: u64,
    key_compares: u64,
}

#[derive(Clone, Copy, Debug, Default)]
struct BuildStats {
    collisions: u64,
    duplicate_inserts: u64,
    probes: ProbeStats,
}

#[derive(Debug)]
struct Table {
    slots: Vec<Slot>,
    mask: usize,
}

impl Table {
    fn with_capacity_pow2(capacity: usize) -> Self {
        Self {
            slots: vec![Slot::EMPTY; capacity],
            mask: capacity - 1,
        }
    }
}

fn parse_args() -> (Vec<PathBuf>, Config) {
    let mut args = env::args().skip(1);
    let mut repos: Vec<PathBuf> = Vec::new();
    let mut iters = 5usize;
    let mut max_keys = None;

    while let Some(arg) = args.next() {
        if arg == "--repo" {
            let Some(repo) = args.next() else {
                eprintln!("missing value for --repo");
                std::process::exit(2);
            };
            repos.push(PathBuf::from(repo));
            continue;
        }
        if let Some(value) = arg.strip_prefix("--repo=") {
            repos.push(PathBuf::from(value));
            continue;
        }
        if let Some(value) = arg.strip_prefix("--iters=") {
            iters = value.parse().unwrap_or_else(|_| {
                eprintln!("invalid --iters value: {value}");
                std::process::exit(2);
            });
            continue;
        }
        if let Some(value) = arg.strip_prefix("--max-keys=") {
            let parsed: usize = value.parse().unwrap_or_else(|_| {
                eprintln!("invalid --max-keys value: {value}");
                std::process::exit(2);
            });
            max_keys = Some(parsed);
            continue;
        }
        if arg == "--help" || arg == "-h" {
            print_usage();
            std::process::exit(0);
        }
        if arg == "--bench" {
            // Passed by `cargo bench` for bench targets; no-op here.
            continue;
        }
        eprintln!("unknown flag: {arg}");
        print_usage();
        std::process::exit(2);
    }

    if repos.is_empty() {
        for candidate in ["../gitleaks", "../tigerbeetle", "../trufflehog"] {
            let path = PathBuf::from(candidate);
            if path.exists() {
                repos.push(path);
            }
        }
    }

    (
        repos,
        Config {
            iters: iters.max(1),
            max_keys,
        },
    )
}

fn print_usage() {
    eprintln!(
        "usage: cargo bench --bench oid_hash_quality -- --repo <path> [--repo <path> ...] [--iters=N] [--max-keys=N]"
    );
}

fn main() {
    let (repos, config) = parse_args();
    if repos.is_empty() {
        eprintln!(
            "oid_hash_quality: skipped (no repositories provided and no default repositories found)"
        );
        return;
    }

    let strategies = [
        HashStrategy {
            name: "fnv1a64",
            hash: hash_fnv1a64,
        },
        HashStrategy {
            name: "splitmix_head_tail",
            hash: hash_splitmix_head_tail,
        },
        HashStrategy {
            name: "first8_le",
            hash: hash_first8_le,
        },
    ];

    for repo in repos {
        let mut keys = collect_pack_oids(&repo);
        if keys.is_empty() {
            println!(
                "repo={} oids=0 (skipped: no packed OIDs found)",
                repo.display()
            );
            continue;
        }

        keys.sort_unstable();
        keys.dedup();

        if let Some(max_keys) = config.max_keys
            && keys.len() > max_keys
        {
            keys.truncate(max_keys);
        }

        let misses = build_absent_keys(&keys);
        let table_size = table_size_for_count(keys.len());
        let load = keys.len() as f64 / table_size as f64;

        println!(
            "repo={} unique_oids={} table_size={} load_factor={:.4} miss_keys={} iters={}",
            repo.display(),
            keys.len(),
            table_size,
            load,
            misses.len(),
            config.iters
        );
        println!(
            "strategy,build_ns_per_key,hit_ns_per_lookup,miss_ns_per_lookup,insert_avg_probe,insert_max_probe,hit_avg_probe,hit_max_probe,miss_avg_probe,miss_max_probe,insert_collisions,tag_match_rate"
        );

        for strategy in &strategies {
            let build_start = Instant::now();
            let mut build_stats = BuildStats::default();
            let mut first_table = None;
            for _ in 0..config.iters {
                let (table, stats) = build_table(&keys, table_size, strategy.hash);
                if first_table.is_none() {
                    first_table = Some(table);
                    build_stats = stats;
                }
                black_box(stats.probes.total_probes);
            }
            let build_elapsed = build_start.elapsed();
            let build_ns_per_key =
                build_elapsed.as_nanos() as f64 / (keys.len() * config.iters) as f64;

            let table = first_table.expect("first table exists");

            let hit_start = Instant::now();
            let mut hit_stats = ProbeStats::default();
            for _ in 0..config.iters {
                let stats = lookup_all(&table, &keys, strategy.hash);
                hit_stats.total_probes += stats.total_probes;
                hit_stats.total_extra_probes += stats.total_extra_probes;
                hit_stats.max_probe = hit_stats.max_probe.max(stats.max_probe);
                hit_stats.operations += stats.operations;
                hit_stats.found += stats.found;
                hit_stats.tag_matches += stats.tag_matches;
                hit_stats.key_compares += stats.key_compares;
            }
            let hit_elapsed = hit_start.elapsed();
            let hit_ns_per_lookup =
                hit_elapsed.as_nanos() as f64 / (keys.len() * config.iters) as f64;

            let miss_start = Instant::now();
            let mut miss_stats = ProbeStats::default();
            for _ in 0..config.iters {
                let stats = lookup_all(&table, &misses, strategy.hash);
                miss_stats.total_probes += stats.total_probes;
                miss_stats.total_extra_probes += stats.total_extra_probes;
                miss_stats.max_probe = miss_stats.max_probe.max(stats.max_probe);
                miss_stats.operations += stats.operations;
                miss_stats.found += stats.found;
                miss_stats.tag_matches += stats.tag_matches;
                miss_stats.key_compares += stats.key_compares;
            }
            let miss_elapsed = miss_start.elapsed();
            let miss_ns_per_lookup =
                miss_elapsed.as_nanos() as f64 / (misses.len() * config.iters) as f64;

            let insert_avg_probe =
                build_stats.probes.total_probes as f64 / build_stats.probes.operations as f64;
            let hit_avg_probe = hit_stats.total_probes as f64 / hit_stats.operations as f64;
            let miss_avg_probe = miss_stats.total_probes as f64 / miss_stats.operations as f64;
            let tag_match_rate = miss_stats.tag_matches as f64 / miss_stats.operations as f64;

            println!(
                "{},{:.3},{:.3},{:.3},{:.4},{},{:.4},{},{:.4},{},{},{:.6}",
                strategy.name,
                build_ns_per_key,
                hit_ns_per_lookup,
                miss_ns_per_lookup,
                insert_avg_probe,
                build_stats.probes.max_probe,
                hit_avg_probe,
                hit_stats.max_probe,
                miss_avg_probe,
                miss_stats.max_probe,
                build_stats.collisions,
                tag_match_rate
            );
        }

        println!();
    }
}

fn build_table(
    keys: &[OidKey],
    table_size: usize,
    hash_fn: fn(&OidKey) -> u64,
) -> (Table, BuildStats) {
    let mut table = Table::with_capacity_pow2(table_size);
    let mut stats = BuildStats::default();

    for key in keys {
        let hash = hash_fn(key);
        let tag = (hash >> 56) as u8;
        let mut idx = (hash as usize) & table.mask;
        let mut probes = 1u32;

        loop {
            let slot = &mut table.slots[idx];
            if !slot.used {
                slot.used = true;
                slot.key = *key;
                slot.tag = tag;
                break;
            }
            if slot.tag == tag && slot.key == *key {
                stats.duplicate_inserts += 1;
                break;
            }
            idx = (idx + 1) & table.mask;
            probes += 1;
        }

        if probes > 1 {
            stats.collisions += 1;
        }
        stats.probes.operations += 1;
        stats.probes.total_probes += probes as u64;
        stats.probes.total_extra_probes += (probes - 1) as u64;
        stats.probes.max_probe = stats.probes.max_probe.max(probes);
    }

    (table, stats)
}

fn lookup_all(table: &Table, keys: &[OidKey], hash_fn: fn(&OidKey) -> u64) -> ProbeStats {
    let mut stats = ProbeStats::default();
    let mut found_acc = 0u64;

    for key in keys {
        let hash = hash_fn(key);
        let tag = (hash >> 56) as u8;
        let mut idx = (hash as usize) & table.mask;
        let mut probes = 1u32;
        let mut found = false;

        loop {
            let slot = &table.slots[idx];
            if !slot.used {
                break;
            }
            if slot.tag == tag {
                stats.tag_matches += 1;
                stats.key_compares += 1;
                if slot.key == *key {
                    found = true;
                    break;
                }
            }
            idx = (idx + 1) & table.mask;
            probes += 1;
            if probes as usize > table.slots.len() {
                break;
            }
        }

        if found {
            stats.found += 1;
            found_acc = found_acc.wrapping_add(hash);
        }
        stats.operations += 1;
        stats.total_probes += probes as u64;
        stats.total_extra_probes += (probes - 1) as u64;
        stats.max_probe = stats.max_probe.max(probes);
    }

    black_box(found_acc);
    stats
}

fn build_absent_keys(keys: &[OidKey]) -> Vec<OidKey> {
    let target = keys.len().min(200_000);
    let mut misses = Vec::with_capacity(target);
    for (i, key) in keys.iter().take(target).enumerate() {
        let mut state = mix64((i as u64) ^ hash_splitmix_head_tail(key));
        let mut accepted = None;
        for _ in 0..12 {
            let mut cand = *key;
            let len = cand.len as usize;
            for _ in 0..4 {
                state = mix64(state.wrapping_add(0x9e37_79b9_7f4a_7c15));
                let idx = (state as usize) % len;
                state = mix64(state ^ 0x94d0_49bb_1331_11eb);
                let byte = (state as u8).wrapping_add(1);
                cand.bytes[idx] ^= byte;
            }
            if cand != *key && keys.binary_search(&cand).is_err() {
                accepted = Some(cand);
                break;
            }
        }
        if let Some(cand) = accepted {
            misses.push(cand);
        }
    }
    misses
}

fn table_size_for_count(count: usize) -> usize {
    let min_capacity = count
        .saturating_mul(LOAD_FACTOR_DEN)
        .div_ceil(LOAD_FACTOR_NUM);
    min_capacity.max(1).next_power_of_two()
}

#[inline]
fn hash_splitmix_head_tail(key: &OidKey) -> u64 {
    let bytes = key.as_slice();
    let head = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    let tail = u64::from_le_bytes(bytes[bytes.len() - 8..].try_into().unwrap());
    let mut h = head ^ tail.rotate_left(32);
    h ^= (bytes.len() as u64) << 56;
    mix64(h)
}

#[inline]
fn hash_first8_le(key: &OidKey) -> u64 {
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&key.bytes[..8]);
    u64::from_le_bytes(buf)
}

#[inline]
fn hash_fnv1a64(key: &OidKey) -> u64 {
    let mut h = FNV_OFFSET_BASIS;
    for &b in key.as_slice() {
        h ^= b as u64;
        h = h.wrapping_mul(FNV_PRIME);
    }
    h
}

#[inline]
fn mix64(mut x: u64) -> u64 {
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^ (x >> 31)
}

fn collect_pack_oids(repo: &Path) -> Vec<OidKey> {
    let git_dir = git_path(repo, ["rev-parse", "--git-dir"]);
    let pack_dir = git_dir.join("objects").join("pack");
    if !pack_dir.exists() {
        return Vec::new();
    }

    let mut idx_files = Vec::new();
    if let Ok(entries) = fs::read_dir(&pack_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|ext| ext == "idx") {
                idx_files.push(path);
            }
        }
    }
    idx_files.sort();

    let mut out = Vec::new();
    for idx in idx_files {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .arg("verify-pack")
            .arg("-v")
            .arg(&idx)
            .output()
            .unwrap_or_else(|err| {
                panic!("failed to run git verify-pack on {}: {err}", idx.display())
            });

        if !output.status.success() {
            panic!(
                "git verify-pack failed for {} with status {:?}",
                idx.display(),
                output.status.code()
            );
        }

        let stdout = String::from_utf8(output.stdout).expect("verify-pack output utf8");
        for line in stdout.lines() {
            let Some(first) = line.split_whitespace().next() else {
                continue;
            };
            if let Some(oid) = parse_hex_oid(first) {
                out.push(oid);
            }
        }
    }

    out
}

fn git_path<const N: usize>(repo: &Path, args: [&str; N]) -> PathBuf {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run git in {}: {err}", repo.display()));
    if !output.status.success() {
        panic!(
            "git command failed in {} with status {:?}",
            repo.display(),
            output.status.code()
        );
    }
    let raw = String::from_utf8(output.stdout).expect("git output utf8");
    let trimmed = raw.trim();
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        path
    } else {
        repo.join(path)
    }
}

fn parse_hex_oid(hex: &str) -> Option<OidKey> {
    if hex.len() != 40 && hex.len() != 64 {
        return None;
    }

    let oid_len = hex.len() / 2;
    let mut out = [0u8; 32];
    let bytes = hex.as_bytes();
    for i in 0..oid_len {
        let hi = decode_hex(bytes[i * 2])?;
        let lo = decode_hex(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }

    Some(OidKey {
        len: oid_len as u8,
        bytes: out,
    })
}

#[inline]
fn decode_hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}
