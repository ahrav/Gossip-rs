//! Git scan pipeline benchmark harness.
//!
//! Usage:
//!   cargo bench --bench git_scan_perf -- --repo <path> [--iters N] [--warmup N]
//!       [--pin-core N] [--x-merge all|first-parent] [--anchors manual|derived]
//!
//! When no repository is provided, the benchmark exits successfully after
//! printing a skip message. This keeps `cargo test --all-targets --all-features`
//! usable in workspaces that do not carry a benchmark fixture checkout.
//!
//! Warmup iterations are discarded; the summary reports median and MAD.

use std::env;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Instant;

use scanner_engine::{demo_rules, demo_transforms};
use scanner_git::policy_hash;
use scanner_git::NativeRefResolver;
use scanner_git::NullEventSink;
use scanner_git::OidBytes;
use scanner_git::{demo_tuning, AnchorMode, AnchorPolicy, Engine};
use scanner_git::{
    run_git_scan, GitScanConfig, GitScanError, GitScanResult, MergeDiffMode, NeverSeenStore,
    RefWatermarkStore, RepoOpenError, StartSetConfig,
};

#[derive(Debug)]
struct BenchConfig {
    repo: PathBuf,
    iters: usize,
    warmup: usize,
    pin_core: Option<usize>,
    merge_mode: MergeDiffMode,
    anchor_mode: AnchorMode,
    max_transform_depth: Option<usize>,
}

/// Watermark store that always returns `None`.
struct EmptyWatermarkStore;

impl RefWatermarkStore for EmptyWatermarkStore {
    fn load_watermarks(
        &self,
        _repo_id: u64,
        _policy_hash: [u8; 32],
        _start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        Ok(vec![None; ref_names.len()])
    }
}

#[derive(Clone, Copy, Debug)]
struct IterSample {
    wall_nanos: u64,
    scan_bytes: u64,
    wall_bps: u64,
    scan_bps: u64,
}

fn bytes_per_sec(bytes: u64, nanos: u64) -> u64 {
    if bytes == 0 || nanos == 0 {
        0
    } else {
        bytes.saturating_mul(1_000_000_000).saturating_div(nanos)
    }
}

fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

fn mad(values: &[u64], median_val: u64) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut deviations: Vec<u64> = values.iter().map(|v| v.abs_diff(median_val)).collect();
    median(&mut deviations)
}

fn parse_args() -> Option<BenchConfig> {
    let mut args = env::args_os();
    let exe = args.next().unwrap_or_else(|| "git_scan_perf".into());

    let mut repo: Option<PathBuf> = None;
    let mut iters: usize = 10;
    let mut warmup: usize = 1;
    let mut pin_core: Option<usize> = None;
    let mut merge_mode = MergeDiffMode::AllParents;
    let mut anchor_mode = AnchorMode::Manual;
    let mut max_transform_depth: Option<usize> = None;

    let mut next_is_repo = false;

    for arg in args {
        if next_is_repo {
            repo = Some(PathBuf::from(arg));
            next_is_repo = false;
            continue;
        }
        if let Some(flag) = arg.to_str() {
            if flag == "--repo" {
                next_is_repo = true;
                continue;
            }
            if let Some(value) = flag.strip_prefix("--repo=") {
                repo = Some(PathBuf::from(value));
                continue;
            }
            if let Some(value) = flag.strip_prefix("--iters=") {
                iters = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --iters value: {}", value);
                    std::process::exit(2);
                });
                continue;
            }
            if let Some(value) = flag.strip_prefix("--warmup=") {
                warmup = value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --warmup value: {}", value);
                    std::process::exit(2);
                });
                continue;
            }
            if let Some(value) = flag.strip_prefix("--pin-core=") {
                pin_core = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --pin-core value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            if let Some(value) = flag.strip_prefix("--x-merge=") {
                merge_mode = match value {
                    "all" => MergeDiffMode::AllParents,
                    "first-parent" => MergeDiffMode::FirstParentOnly,
                    _ => {
                        eprintln!("invalid --x-merge value: {}", value);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(value) = flag.strip_prefix("--anchors=") {
                anchor_mode = match value {
                    "manual" => AnchorMode::Manual,
                    "derived" => AnchorMode::Derived,
                    _ => {
                        eprintln!("invalid --anchors value: {}", value);
                        std::process::exit(2);
                    }
                };
                continue;
            }
            if let Some(value) = flag.strip_prefix("--max-transform-depth=") {
                max_transform_depth = Some(value.parse().unwrap_or_else(|_| {
                    eprintln!("invalid --max-transform-depth value: {}", value);
                    std::process::exit(2);
                }));
                continue;
            }
            match flag {
                "--help" | "-h" => {
                    print_usage(&exe);
                    std::process::exit(0);
                }
                _ if flag.starts_with("--") => {
                    eprintln!("unknown flag: {}", flag);
                    print_usage(&exe);
                    std::process::exit(2);
                }
                _ => {}
            }
        }

        if repo.is_none() {
            repo = Some(PathBuf::from(arg));
        } else {
            print_usage(&exe);
            std::process::exit(2);
        }
    }

    if next_is_repo {
        eprintln!("missing value for --repo");
        print_usage(&exe);
        std::process::exit(2);
    }

    let repo = repo?;

    Some(BenchConfig {
        repo,
        iters: iters.max(1),
        warmup,
        pin_core,
        merge_mode,
        anchor_mode,
        max_transform_depth,
    })
}

fn print_usage(exe: &std::ffi::OsStr) {
    eprintln!(
        "usage: {} [OPTIONS] <repo>\n\
\n\
OPTIONS:\n\
    --repo <path>              Repository path (positional also supported)\n\
    --iters=<N>                Measured iterations (default: 10)\n\
    --warmup=<N>               Warmup iterations (default: 1)\n\
    --pin-core=<N>             Pin to core id (Linux only)\n\
    --x-merge=all|first-parent Merge diff mode (default: all)\n\
    --anchors=manual|derived   Anchor mode (default: manual)\n\
    --max-transform-depth=<N>  Override transform depth\n\
    --help, -h                 Show this help message",
        exe.to_string_lossy()
    );
}

fn run_git_scan_once(
    repo: &Path,
    scan_config: &GitScanConfig,
    engine: &Arc<Engine>,
    resolver: &NativeRefResolver,
) -> Result<IterSample, GitScanError> {
    let seen_store = NeverSeenStore;
    let watermark_store = EmptyWatermarkStore;
    let abort = AtomicBool::new(false);

    let start = Instant::now();
    let result = run_git_scan(
        repo,
        Arc::clone(engine),
        resolver,
        &seen_store,
        &watermark_store,
        None,
        scan_config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )?;
    let wall_nanos = start.elapsed().as_nanos() as u64;

    let GitScanResult(report) = result;

    let scan_bytes = report.perf_stats.scan_bytes;

    Ok(IterSample {
        wall_nanos,
        scan_bytes,
        wall_bps: bytes_per_sec(scan_bytes, wall_nanos),
        scan_bps: bytes_per_sec(scan_bytes, report.perf_stats.scan_nanos),
    })
}

#[derive(Debug, Clone, Copy)]
enum PinStatus {
    None,
    Applied(usize),
    Unavailable(usize),
}

impl std::fmt::Display for PinStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PinStatus::None => write!(f, "none"),
            PinStatus::Applied(core) => write!(f, "core-{core}"),
            PinStatus::Unavailable(core) => write!(f, "unavailable-core-{core}"),
        }
    }
}

fn pin_to_core(core: Option<usize>) -> PinStatus {
    let Some(core) = core else {
        return PinStatus::None;
    };

    match scanner_scheduler::affinity::try_pin_to_core(core) {
        Some(_) => PinStatus::Applied(core),
        None => PinStatus::Unavailable(core),
    }
}

fn main() {
    let Some(cfg) = parse_args() else {
        eprintln!("git_scan_perf: skipped (no repository provided)");
        return;
    };

    let pin_status = pin_to_core(cfg.pin_core);

    let rules = demo_rules();
    let transforms = demo_transforms();
    let mut tuning = demo_tuning();
    if let Some(depth) = cfg.max_transform_depth {
        tuning.max_transform_depth = depth;
    }
    let base_config = GitScanConfig::default();
    let policy = policy_hash(&rules, &transforms, &tuning, cfg.merge_mode);

    let engine = Arc::new(match cfg.anchor_mode {
        AnchorMode::Manual => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::ManualOnly)
        }
        AnchorMode::Derived => {
            Engine::new_with_anchor_policy(rules, transforms, tuning, AnchorPolicy::DerivedOnly)
        }
    });

    let start_set = StartSetConfig::DefaultBranchOnly;
    let resolver = NativeRefResolver::new(start_set.clone());
    let scan_config = GitScanConfig {
        repo_id: 1,
        merge_diff_mode: cfg.merge_mode,
        start_set: start_set.clone(),
        policy_hash: policy,
        ..base_config
    };

    println!(
        "git_scan_bench: repo={} iters={} warmup={} pin={}",
        cfg.repo.display(),
        cfg.iters,
        cfg.warmup,
        pin_status
    );

    for _ in 0..cfg.warmup {
        let _ = run_git_scan_once(&cfg.repo, &scan_config, &engine, &resolver);
    }

    let mut samples = Vec::with_capacity(cfg.iters);
    for _ in 0..cfg.iters {
        match run_git_scan_once(&cfg.repo, &scan_config, &engine, &resolver) {
            Ok(sample) => samples.push(sample),
            Err(err) => {
                eprintln!("git_scan_bench failed: {err}");
                std::process::exit(2);
            }
        }
    }

    for (idx, sample) in samples.iter().enumerate() {
        println!(
            "iter {} wall_ms={} scan_bytes={} wall_bps={} scan_bps={}",
            idx,
            sample.wall_nanos / 1_000_000,
            sample.scan_bytes,
            sample.wall_bps,
            sample.scan_bps
        );
    }

    let mut wall_bps: Vec<u64> = samples.iter().map(|s| s.wall_bps).collect();
    let mut scan_bps: Vec<u64> = samples.iter().map(|s| s.scan_bps).collect();
    let mut wall_nanos: Vec<u64> = samples.iter().map(|s| s.wall_nanos).collect();

    let wall_bps_median = median(&mut wall_bps);
    let wall_bps_mad = mad(&wall_bps, wall_bps_median);
    let scan_bps_median = median(&mut scan_bps);
    let scan_bps_mad = mad(&scan_bps, scan_bps_median);
    let wall_median = median(&mut wall_nanos);
    let wall_mad = mad(&wall_nanos, wall_median);

    println!(
        "summary wall_bps_median={} wall_bps_mad={} scan_bps_median={} scan_bps_mad={} wall_ms_median={} wall_ms_mad={}",
        wall_bps_median,
        wall_bps_mad,
        scan_bps_median,
        scan_bps_mad,
        wall_median / 1_000_000,
        wall_mad / 1_000_000
    );
}
