//! CLI entrypoint wiring for scanner runtime.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;

use gossip_scan_driver::CancellationToken;
use gossip_scan_driver::GitDebugLevel;
use scanner_engine::TransformId;
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode, NullEventSink};
use scanner_scheduler::events::EventOutput;

use crate::commit_sink::CliNoOpCommitSink;
use crate::event_sink::{JsonEventSink, JsonlEventSink, SarifEventSink, TextEventSink};
use crate::{
    AnchorMode, EventFormat, ExecutionMode, FsScanConfig, GitScanConfig, ScanBudgets,
    ScanRuntimeError, TransformFilter, scan_fs_with_runtime, scan_git_with_runtime,
};

/// CLI source command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliSource {
    Fs { path: PathBuf },
    Git { repo: PathBuf },
}

/// Parsed CLI config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliConfig {
    pub source: CliSource,
    pub execution_mode: ExecutionMode,
    pub budgets: ScanBudgets,
    pub null_sink: bool,
    pub event_format: EventFormat,
    pub verbose: bool,
    pub rules_file: Option<PathBuf>,
    pub transform_filter: TransformFilter,
    pub workers: Option<usize>,
    pub decode_depth: Option<usize>,
    pub skip_archives: bool,
    pub scan_binary: bool,
    pub persist_findings: bool,
    pub anchor_mode: AnchorMode,
    pub debug_level: GitDebugLevel,
    pub enrich_identities: bool,
    pub git_repo_id: u64,
    pub git_scan_mode: GitScanMode,
    pub git_merge_mode: MergeDiffMode,
    pub git_tree_delta_cache_mb: Option<u32>,
    pub git_engine_chunk_mb: Option<u32>,
}

/// Runtime CLI error.
#[derive(Debug)]
pub enum CliError {
    HelpRequested(String),
    Usage(String),
    Runtime(ScanRuntimeError),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HelpRequested(message) | Self::Usage(message) => write!(f, "{message}"),
            Self::Runtime(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for CliError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Runtime(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ScanRuntimeError> for CliError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Parse CLI args from the process environment.
pub fn parse_args() -> Result<CliConfig, CliError> {
    parse_args_from(std::env::args_os().skip(1))
}

fn parse_args_from<I>(args: I) -> Result<CliConfig, CliError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut args: Vec<OsString> = args.into_iter().collect();
    if args.is_empty() {
        return Err(CliError::Usage(top_usage()));
    }

    if is_help_flag(&args[0]) {
        return Err(CliError::HelpRequested(top_usage()));
    }

    let command = args.remove(0).to_string_lossy().into_owned();
    if command != "scan" {
        return Err(CliError::Usage(format!(
            "error: expected 'scan' subcommand, got '{command}'\n\n{}",
            top_usage()
        )));
    }

    if args.is_empty() {
        return Err(CliError::Usage(format!(
            "error: 'scan' requires a source (fs|git)\n\n{}",
            top_usage()
        )));
    }

    let source_kind = args.remove(0).to_string_lossy().into_owned();
    let mut execution_mode = ExecutionMode::Direct;
    let mut budgets = ScanBudgets::default();
    let mut null_sink = false;
    let mut event_format = EventFormat::Jsonl;
    let mut verbose = false;
    let mut rules_file: Option<PathBuf> = None;
    let mut transform_filter = TransformFilter::All;
    let mut workers: Option<usize> = None;
    let mut decode_depth: Option<usize> = None;
    let mut skip_archives = false;
    let mut scan_binary = false;
    let mut persist_findings = false;
    let mut anchor_mode = AnchorMode::Manual;
    let mut debug_level = GitDebugLevel::Off;
    let mut enrich_identities = false;
    let mut git_repo_id: u64 = 1;
    let mut git_scan_mode = GitScanMode::OdbBlobFast;
    let mut git_merge_mode = MergeDiffMode::AllParents;
    let mut x_pack_exec_workers: Option<usize> = None;
    let mut git_tree_delta_cache_mb: Option<u32> = None;
    let mut git_engine_chunk_mb: Option<u32> = None;

    let mut source_path: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        if is_help_flag(&args[i]) {
            return Err(CliError::HelpRequested(source_usage(&source_kind)));
        }

        if let Some(value) = strip_os_prefix(&args[i], "--rules=") {
            if value.is_empty() {
                return Err(CliError::Usage(format!(
                    "error: --rules requires a file path\n\n{}",
                    source_usage(&source_kind)
                )));
            }
            rules_file = Some(PathBuf::from(value));
            i += 1;
            continue;
        }

        if let Some(value) = strip_os_prefix(&args[i], "--transforms=") {
            let text = value.to_str().ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --transforms value must be valid UTF-8\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            transform_filter = parse_transforms(text, &source_kind)?;
            i += 1;
            continue;
        }

        let arg = args[i].to_string_lossy();
        if let Some(value) = arg.strip_prefix("--execution-mode=") {
            execution_mode = value
                .parse()
                .map_err(|error: crate::ParseExecutionModeError| {
                    CliError::Usage(format!("error: {error}\n\n{}", source_usage(&source_kind)))
                })?;
            i += 1;
            continue;
        }

        if arg == "--execution-mode" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --execution-mode requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            let value = value.to_string_lossy().into_owned();
            execution_mode = value
                .parse()
                .map_err(|error: crate::ParseExecutionModeError| {
                    CliError::Usage(format!("error: {error}\n\n{}", source_usage(&source_kind)))
                })?;
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--max-items=") {
            budgets.max_items = parse_usize(value, "--max-items", &source_kind)?;
            i += 1;
            continue;
        }

        if arg == "--max-items" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --max-items requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            budgets.max_items = parse_usize(
                value.to_string_lossy().as_ref(),
                "--max-items",
                &source_kind,
            )?;
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--max-bytes=") {
            budgets.max_bytes = parse_u64(value, "--max-bytes", &source_kind)?;
            i += 1;
            continue;
        }

        if arg == "--max-bytes" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --max-bytes requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            budgets.max_bytes = parse_u64(
                value.to_string_lossy().as_ref(),
                "--max-bytes",
                &source_kind,
            )?;
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--event-format=") {
            event_format = parse_event_format(value, &source_kind)?;
            i += 1;
            continue;
        }

        if arg == "--event-format" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --event-format requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            event_format = parse_event_format(value.to_string_lossy().as_ref(), &source_kind)?;
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--workers=") {
            workers = Some(parse_workers(value, &source_kind)?);
            i += 1;
            continue;
        }

        if arg == "--workers" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --workers requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            workers = Some(parse_workers(
                value.to_string_lossy().as_ref(),
                &source_kind,
            )?);
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--decode-depth=") {
            decode_depth = Some(parse_usize(value, "--decode-depth", &source_kind)?);
            i += 1;
            continue;
        }

        if arg == "--decode-depth" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --decode-depth requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            decode_depth = Some(parse_usize(
                value.to_string_lossy().as_ref(),
                "--decode-depth",
                &source_kind,
            )?);
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--anchors=") {
            anchor_mode = parse_anchor_mode(value, &source_kind)?;
            i += 1;
            continue;
        }

        if arg == "--anchors" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --anchors requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            anchor_mode = parse_anchor_mode(value.to_string_lossy().as_ref(), &source_kind)?;
            i += 2;
            continue;
        }

        // Git-specific public and hidden (`--x-*`) knobs. Hidden flags are
        // intentionally parsed for parity but excluded from usage text.
        if source_kind == "git" {
            if let Some(value) = arg.strip_prefix("--debug=") {
                debug_level = parse_debug_level(value, &source_kind)?;
                i += 1;
                continue;
            }

            if arg == "--debug" {
                if let Some(value) = args.get(i + 1) {
                    let next = value.to_string_lossy();
                    if let Some(parsed) = parse_debug_level_token(next.as_ref()) {
                        debug_level = promote_debug_level(debug_level, parsed);
                        i += 2;
                        continue;
                    }
                }
                debug_level = promote_debug_level(debug_level, GitDebugLevel::Stats);
                i += 1;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-repo-id=") {
                git_repo_id = parse_u64(value, "--x-repo-id", &source_kind)?;
                i += 1;
                continue;
            }

            if arg == "--x-repo-id" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-repo-id requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                git_repo_id = parse_u64(
                    value.to_string_lossy().as_ref(),
                    "--x-repo-id",
                    &source_kind,
                )?;
                i += 2;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-mode=") {
                git_scan_mode = parse_git_scan_mode(value, &source_kind)?;
                i += 1;
                continue;
            }

            if arg == "--x-mode" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-mode requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                git_scan_mode =
                    parse_git_scan_mode(value.to_string_lossy().as_ref(), &source_kind)?;
                i += 2;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-merge=") {
                git_merge_mode = parse_git_merge_mode(value, &source_kind)?;
                i += 1;
                continue;
            }

            if arg == "--x-merge" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-merge requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                git_merge_mode =
                    parse_git_merge_mode(value.to_string_lossy().as_ref(), &source_kind)?;
                i += 2;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-pack-exec-workers=") {
                x_pack_exec_workers = Some(parse_workers(value, &source_kind)?);
                i += 1;
                continue;
            }

            if arg == "--x-pack-exec-workers" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-pack-exec-workers requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                x_pack_exec_workers = Some(parse_workers(
                    value.to_string_lossy().as_ref(),
                    &source_kind,
                )?);
                i += 2;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-tree-delta-cache-mb=") {
                git_tree_delta_cache_mb = Some(parse_positive_u32(
                    value,
                    "--x-tree-delta-cache-mb",
                    &source_kind,
                )?);
                i += 1;
                continue;
            }

            if arg == "--x-tree-delta-cache-mb" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-tree-delta-cache-mb requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                git_tree_delta_cache_mb = Some(parse_positive_u32(
                    value.to_string_lossy().as_ref(),
                    "--x-tree-delta-cache-mb",
                    &source_kind,
                )?);
                i += 2;
                continue;
            }

            if let Some(value) = arg.strip_prefix("--x-engine-chunk-mb=") {
                git_engine_chunk_mb = Some(parse_positive_u32(
                    value,
                    "--x-engine-chunk-mb",
                    &source_kind,
                )?);
                i += 1;
                continue;
            }

            if arg == "--x-engine-chunk-mb" {
                let value = args.get(i + 1).ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --x-engine-chunk-mb requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?;
                git_engine_chunk_mb = Some(parse_positive_u32(
                    value.to_string_lossy().as_ref(),
                    "--x-engine-chunk-mb",
                    &source_kind,
                )?);
                i += 2;
                continue;
            }
        }

        if arg == "--rules" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --rules requires a file path\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            rules_file = Some(PathBuf::from(value));
            i += 2;
            continue;
        }

        if arg == "--transforms" {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --transforms requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            transform_filter = parse_transforms(value.to_string_lossy().as_ref(), &source_kind)?;
            i += 2;
            continue;
        }

        match arg.as_ref() {
            "--skip-archives" => {
                skip_archives = true;
                i += 1;
                continue;
            }
            "--scan-archives" => {
                skip_archives = false;
                i += 1;
                continue;
            }
            "--scan-binary" => {
                scan_binary = true;
                i += 1;
                continue;
            }
            "--skip-binary" => {
                scan_binary = false;
                i += 1;
                continue;
            }
            "--persist-findings" => {
                persist_findings = true;
                i += 1;
                continue;
            }
            "--enrich-identities" if source_kind == "git" => {
                enrich_identities = true;
                i += 1;
                continue;
            }
            "--null-sink" => {
                null_sink = true;
                i += 1;
                continue;
            }
            "--verbose" => {
                verbose = true;
                i += 1;
                continue;
            }
            _ => {}
        }

        let source_flag = match source_kind.as_str() {
            "fs" => "--path",
            "git" => "--repo",
            _ => {
                return Err(CliError::Usage(format!(
                    "error: unknown source '{source_kind}'\n\n{}",
                    top_usage()
                )));
            }
        };

        if let Some(value) = arg.strip_prefix(&format!("{source_flag}=")) {
            source_path = Some(PathBuf::from(value));
            i += 1;
            continue;
        }

        if arg == source_flag {
            let value = args.get(i + 1).ok_or_else(|| {
                CliError::Usage(format!(
                    "error: {source_flag} requires a value\n\n{}",
                    source_usage(&source_kind)
                ))
            })?;
            source_path = Some(PathBuf::from(value));
            i += 2;
            continue;
        }

        if arg.starts_with("--") {
            return Err(CliError::Usage(format!(
                "error: unknown flag '{arg}'\n\n{}",
                source_usage(&source_kind)
            )));
        }

        if source_path.is_some() {
            return Err(CliError::Usage(format!(
                "error: multiple source paths provided\n\n{}",
                source_usage(&source_kind)
            )));
        }
        source_path = Some(PathBuf::from(&args[i]));
        i += 1;
    }

    let source = match source_kind.as_str() {
        "fs" => CliSource::Fs {
            path: source_path.ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --path is required for 'scan fs'\n\n{}",
                    source_usage("fs")
                ))
            })?,
        },
        "git" => CliSource::Git {
            repo: source_path.ok_or_else(|| {
                CliError::Usage(format!(
                    "error: --repo is required for 'scan git'\n\n{}",
                    source_usage("git")
                ))
            })?,
        },
        _ => {
            return Err(CliError::Usage(format!(
                "error: unknown source '{source_kind}'\n\n{}",
                top_usage()
            )));
        }
    };

    // `--workers` supersedes the legacy hidden worker knob regardless of order.
    if source_kind == "git" && workers.is_none() {
        workers = x_pack_exec_workers;
    }

    Ok(CliConfig {
        source,
        execution_mode,
        budgets,
        null_sink,
        event_format,
        verbose,
        rules_file,
        transform_filter,
        workers,
        decode_depth,
        skip_archives,
        scan_binary,
        persist_findings,
        anchor_mode,
        debug_level,
        enrich_identities,
        git_repo_id,
        git_scan_mode,
        git_merge_mode,
        git_tree_delta_cache_mb,
        git_engine_chunk_mb,
    })
}

/// Run one CLI scan and stream findings to stdout.
///
/// A compact summary is always printed to stderr after the scan completes,
/// matching the output format of the standalone scanner-rs binary:
///
/// ```text
/// files=92128
/// chunks=90486
/// bytes=1531929485 (1.43 GiB)
/// findings=786
/// errors=0
/// elapsed_ms=3071
/// throughput_mib_s=493.61
/// workers=12
/// ```
pub fn run(config: CliConfig) -> Result<gossip_scan_driver::ScanReport, CliError> {
    let sink = build_event_sink(config.event_format, config.verbose, config.null_sink);
    let core_sink: &dyn EventOutput = sink.as_ref();
    let git_sink: &dyn GitEventOutput = sink.as_ref();
    let commit = CliNoOpCommitSink;
    let cancel = CancellationToken::new();

    let workers = config.workers.unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1)
    });

    let wall_start = std::time::Instant::now();

    let report = match config.source {
        CliSource::Fs { path } => {
            scan_fs_with_runtime(
                &FsScanConfig::new(path)
                    .with_execution_mode(config.execution_mode)
                    .with_budgets(config.budgets)
                    .with_workers(workers)
                    .with_decode_depth(config.decode_depth)
                    .with_skip_archives(config.skip_archives)
                    .with_scan_binary(config.scan_binary)
                    .with_persist_findings(config.persist_findings)
                    .with_anchor_mode(config.anchor_mode)
                    .with_rules_file(config.rules_file.clone())
                    .with_transform_filter(config.transform_filter.clone()),
                core_sink,
                &commit,
                &cancel,
            )?
            .report
        }
        CliSource::Git { repo } => {
            let outcome = scan_git_with_runtime(
                &GitScanConfig::new(repo)
                    .with_workers(workers)
                    .with_execution_mode(config.execution_mode)
                    .with_budgets(config.budgets)
                    .with_decode_depth(config.decode_depth)
                    .with_scan_binary(config.scan_binary)
                    .with_debug_level(config.debug_level)
                    .with_enrich_identities(config.enrich_identities)
                    .with_anchor_mode(config.anchor_mode)
                    .with_rules_file(config.rules_file.clone())
                    .with_transform_filter(config.transform_filter.clone())
                    .with_repo_id(config.git_repo_id)
                    .with_scan_mode(config.git_scan_mode)
                    .with_merge_mode(config.git_merge_mode)
                    .with_tree_delta_cache_mb(config.git_tree_delta_cache_mb)
                    .with_engine_chunk_mb(config.git_engine_chunk_mb),
                core_sink,
                Some(git_sink),
                &commit,
                &cancel,
            )?;
            if let Some(debug_output) = outcome.debug_output.as_deref() {
                eprint!("{debug_output}");
            }
            outcome.report
        }
    };

    let elapsed = wall_start.elapsed();
    core_sink.flush();

    print_scan_summary(&report, elapsed, workers);

    Ok(report)
}

/// Print a compact `key=value` summary to stderr.
///
/// This always runs — stderr is separate from the findings stream (stdout),
/// so downstream pipe consumers are unaffected.
fn print_scan_summary(
    report: &gossip_scan_driver::ScanReport,
    elapsed: std::time::Duration,
    workers: usize,
) {
    let elapsed_ms = elapsed.as_millis() as u64;
    let elapsed_secs = elapsed.as_secs_f64();
    let throughput_mib_s = if elapsed_secs > 0.0 {
        (report.bytes_scanned as f64) / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };

    let gib = report.bytes_scanned as f64 / (1024.0 * 1024.0 * 1024.0);

    // Use write_all to stderr to avoid interleaving with other output.
    // The buffer is small enough that a single write_all is atomic on all
    // platforms we target (POSIX guarantees atomicity for writes <= PIPE_BUF).
    use std::io::Write;
    let mut buf = String::with_capacity(256);
    use std::fmt::Write as FmtWrite;
    let _ = writeln!(buf, "files={}", report.items_scanned);
    let _ = writeln!(buf, "chunks={}", report.chunks_scanned);
    let _ = writeln!(buf, "bytes={} ({gib:.2} GiB)", report.bytes_scanned);
    let _ = writeln!(buf, "findings={}", report.findings_emitted);
    let _ = writeln!(buf, "errors={}", report.errors);
    let _ = writeln!(buf, "elapsed_ms={elapsed_ms}");
    let _ = writeln!(buf, "throughput_mib_s={throughput_mib_s:.2}");
    let _ = writeln!(buf, "workers={workers}");

    let _ = io::stderr().write_all(buf.as_bytes());
}

trait CliEventSink: EventOutput + GitEventOutput {}

impl<T> CliEventSink for T where T: EventOutput + GitEventOutput {}

fn build_event_sink(
    event_format: EventFormat,
    verbose: bool,
    null_sink: bool,
) -> Box<dyn CliEventSink> {
    if null_sink {
        return Box::new(NullEventSink);
    }
    match event_format {
        EventFormat::Jsonl => Box::new(JsonlEventSink::new(io::stdout())),
        EventFormat::Text => Box::new(TextEventSink::new(io::stdout(), verbose)),
        EventFormat::Json => Box::new(JsonEventSink::new(io::stdout())),
        EventFormat::Sarif => Box::new(SarifEventSink::new(io::stdout())),
    }
}

fn parse_workers(value: &str, source_kind: &str) -> Result<usize, CliError> {
    let workers = parse_usize(value, "--workers", source_kind)?;
    if workers == 0 {
        return Err(CliError::Usage(format!(
            "error: --workers must be >= 1\n\n{}",
            source_usage(source_kind)
        )));
    }
    Ok(workers)
}

fn parse_usize(value: &str, flag: &str, source_kind: &str) -> Result<usize, CliError> {
    value.parse::<usize>().map_err(|_| {
        CliError::Usage(format!(
            "error: {flag} must be an integer (got '{value}')\n\n{}",
            source_usage(source_kind)
        ))
    })
}

fn parse_u64(value: &str, flag: &str, source_kind: &str) -> Result<u64, CliError> {
    value.parse::<u64>().map_err(|_| {
        CliError::Usage(format!(
            "error: {flag} must be an integer (got '{value}')\n\n{}",
            source_usage(source_kind)
        ))
    })
}

fn parse_positive_u32(value: &str, flag: &str, source_kind: &str) -> Result<u32, CliError> {
    let parsed = value.parse::<u32>().map_err(|_| {
        CliError::Usage(format!(
            "error: {flag} must be an integer (got '{value}')\n\n{}",
            source_usage(source_kind)
        ))
    })?;
    if parsed == 0 {
        return Err(CliError::Usage(format!(
            "error: {flag} must be >= 1\n\n{}",
            source_usage(source_kind)
        )));
    }
    Ok(parsed)
}

fn parse_anchor_mode(value: &str, source_kind: &str) -> Result<AnchorMode, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "manual" => Ok(AnchorMode::Manual),
        "derived" => Ok(AnchorMode::Derived),
        _ => Err(CliError::Usage(format!(
            "error: invalid --anchors value '{value}' (expected manual|derived)\n\n{}",
            source_usage(source_kind)
        ))),
    }
}

fn parse_debug_level_token(value: &str) -> Option<GitDebugLevel> {
    match value.trim().to_ascii_lowercase().as_str() {
        "stats" => Some(GitDebugLevel::Stats),
        "perf" => Some(GitDebugLevel::Perf),
        _ => None,
    }
}

fn parse_debug_level(value: &str, source_kind: &str) -> Result<GitDebugLevel, CliError> {
    parse_debug_level_token(value).ok_or_else(|| {
        CliError::Usage(format!(
            "error: invalid --debug value '{value}' (expected perf|stats)\n\n{}",
            source_usage(source_kind)
        ))
    })
}

fn promote_debug_level(current: GitDebugLevel, next: GitDebugLevel) -> GitDebugLevel {
    use GitDebugLevel::{Off, Perf, Stats};
    match (current, next) {
        (Perf, _) | (_, Perf) => Perf,
        (Stats, _) | (_, Stats) => Stats,
        (Off, Off) => Off,
    }
}

fn parse_git_scan_mode(value: &str, source_kind: &str) -> Result<GitScanMode, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "diff" | "diff-history" => Ok(GitScanMode::DiffHistory),
        "odb-blob" | "odb-blob-fast" => Ok(GitScanMode::OdbBlobFast),
        _ => Err(CliError::Usage(format!(
            "error: invalid --x-mode value '{value}' (expected diff|diff-history|odb-blob|odb-blob-fast)\n\n{}",
            source_usage(source_kind)
        ))),
    }
}

fn parse_git_merge_mode(value: &str, source_kind: &str) -> Result<MergeDiffMode, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "all" => Ok(MergeDiffMode::AllParents),
        "first-parent" => Ok(MergeDiffMode::FirstParentOnly),
        _ => Err(CliError::Usage(format!(
            "error: invalid --x-merge value '{value}' (expected all|first-parent)\n\n{}",
            source_usage(source_kind)
        ))),
    }
}

fn parse_event_format(value: &str, source_kind: &str) -> Result<EventFormat, CliError> {
    match value.trim().to_ascii_lowercase().as_str() {
        "jsonl" => Ok(EventFormat::Jsonl),
        "text" => Ok(EventFormat::Text),
        "json" => Ok(EventFormat::Json),
        "sarif" => Ok(EventFormat::Sarif),
        _ => Err(CliError::Usage(format!(
            "error: invalid --event-format value '{value}' (expected jsonl|text|json|sarif)\n\n{}",
            source_usage(source_kind)
        ))),
    }
}

fn parse_transforms(value: &str, source_kind: &str) -> Result<TransformFilter, CliError> {
    let known_csv = TransformId::ALL
        .iter()
        .map(|id| id.cli_name())
        .collect::<Vec<_>>()
        .join(", ");

    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "" => Err(CliError::Usage(format!(
            "error: --transforms requires a value (all, none, or comma-separated: {known_csv})\n\n{}",
            source_usage(source_kind)
        ))),
        "all" => Ok(TransformFilter::All),
        "none" => Ok(TransformFilter::None),
        _ => {
            let tokens: Vec<&str> = normalized
                .split(',')
                .map(str::trim)
                .filter(|token| !token.is_empty())
                .collect();
            if tokens.is_empty() {
                return Err(CliError::Usage(format!(
                    "error: --transforms requires at least one transform name (known: {known_csv})\n\n{}",
                    source_usage(source_kind)
                )));
            }
            let mut ids = Vec::new();
            for token in tokens {
                let Some(id) = TransformId::ALL
                    .iter()
                    .find(|candidate| candidate.cli_name() == token)
                    .copied()
                else {
                    return Err(CliError::Usage(format!(
                        "error: invalid --transforms value '{token}' (known: {known_csv})\n\n{}",
                        source_usage(source_kind)
                    )));
                };
                if !ids.contains(&id) {
                    ids.push(id);
                }
            }
            Ok(TransformFilter::Only(ids))
        }
    }
}

fn strip_os_prefix<'a>(arg: &'a OsStr, prefix: &str) -> Option<&'a OsStr> {
    let bytes = arg.as_encoded_bytes();
    if bytes.starts_with(prefix.as_bytes()) {
        // SAFETY: `prefix` is ASCII-only and therefore a valid split point.
        Some(unsafe { OsStr::from_encoded_bytes_unchecked(&bytes[prefix.len()..]) })
    } else {
        None
    }
}

fn is_help_flag(flag: &OsString) -> bool {
    matches!(flag.to_string_lossy().as_ref(), "--help" | "-h")
}

fn top_usage() -> String {
    [
        "usage:",
        "  scanner-rs scan fs  --path <dir|file> [FS OPTIONS] [COMMON OPTIONS]",
        "  scanner-rs scan git --repo <path>     [COMMON OPTIONS]",
    ]
    .join("\n")
}

fn source_usage(source: &str) -> String {
    match source {
        "fs" => [
            "usage: scanner-rs scan fs --path <dir|file> [OPTIONS]",
            "",
            "OPTIONS:",
            "  --path=<dir|file>                 Path to scan (also accepted as positional arg)",
            "  --execution-mode=direct|connector Execution mode (default: direct)",
            "  --max-items=<N>                   Budget checkpoint frequency (default: 256)",
            "  --max-bytes=<N>                   Runtime byte budget knob (default: 1000000)",
            "  --workers=<N>                     Worker threads (default: CPU count)",
            "  --decode-depth=<N>                Max decode depth (default: engine default)",
            "  --skip-archives                   Skip archive expansion [default: scan]",
            "  --scan-archives                   Scan archives (undo --skip-archives)",
            "  --scan-binary                     Scan binary files [default: skip]",
            "  --skip-binary                     Skip binary files (undo --scan-binary)",
            "  --persist-findings                Persist findings via commit bridge",
            "  --anchors=manual|derived          Anchor mode (default: manual)",
            "  --rules=<path>                    YAML rules file override",
            "  --transforms=all|none|<list>      Transform filter (default: all)",
            "  --event-format=jsonl|text|json|sarif Output format (default: jsonl)",
            "  --null-sink                       Drop all emitted events",
            "  --verbose                         Verbose text output",
            "  --help, -h                        Show this help",
        ]
        .join("\n"),
        "git" => [
            "usage: scanner-rs scan git --repo <path> [OPTIONS]",
            "",
            "OPTIONS:",
            "  --repo=<path>                     Repository path (also accepted as positional arg)",
            "  --execution-mode=direct|connector Execution mode (default: direct)",
            "  --max-items=<N>                   Budget checkpoint frequency (default: 256)",
            "  --max-bytes=<N>                   Runtime byte budget knob (default: 1000000)",
            "  --workers=<N>                     Pack execution workers (default: CPU count)",
            "  --decode-depth=<N>                Max decode depth (default: engine default)",
            "  --scan-binary                     Scan binary blobs [default: skip]",
            "  --skip-binary                     Skip binary blobs (undo --scan-binary)",
            "  --debug                           Stage stats to stderr",
            "  --debug=perf                      Stage stats + per-pack timing to stderr",
            "  --enrich-identities               Emit identity dictionary + enriched commit metadata",
            "  --anchors=manual|derived          Anchor mode (default: manual)",
            "  --rules=<path>                    YAML rules file override",
            "  --transforms=all|none|<list>      Transform filter (default: all)",
            "  --event-format=jsonl|text|json|sarif Output format (default: jsonl)",
            "  --null-sink                       Drop all emitted events",
            "  --verbose                         Verbose text output",
            "  --help, -h                        Show this help",
        ]
        .join("\n"),
        _ => top_usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fs_cli_config_supports_extended_flags() {
        let cfg = parse_args_from([
            "scan".into(),
            "fs".into(),
            "--path".into(),
            "/tmp/workdir".into(),
            "--execution-mode=connector".into(),
            "--max-items=12".into(),
            "--max-bytes=4096".into(),
            "--workers".into(),
            "2".into(),
            "--decode-depth=1".into(),
            "--skip-archives".into(),
            "--scan-binary".into(),
            "--persist-findings".into(),
            "--anchors=derived".into(),
            "--event-format=text".into(),
            "--verbose".into(),
            "--null-sink".into(),
            "--transforms=none".into(),
            "--rules=/tmp/custom.yaml".into(),
        ])
        .expect("parse fs config");

        assert_eq!(
            cfg,
            CliConfig {
                source: CliSource::Fs {
                    path: PathBuf::from("/tmp/workdir"),
                },
                execution_mode: ExecutionMode::Connector,
                budgets: ScanBudgets {
                    max_items: 12,
                    max_bytes: 4096,
                },
                null_sink: true,
                event_format: EventFormat::Text,
                verbose: true,
                rules_file: Some(PathBuf::from("/tmp/custom.yaml")),
                transform_filter: TransformFilter::None,
                workers: Some(2),
                decode_depth: Some(1),
                skip_archives: true,
                scan_binary: true,
                persist_findings: true,
                anchor_mode: AnchorMode::Derived,
                debug_level: GitDebugLevel::Off,
                enrich_identities: false,
                git_repo_id: 1,
                git_scan_mode: GitScanMode::OdbBlobFast,
                git_merge_mode: MergeDiffMode::AllParents,
                git_tree_delta_cache_mb: None,
                git_engine_chunk_mb: None,
            }
        );
    }

    #[test]
    fn parse_transforms_csv_variant() {
        let cfg = parse_args_from([
            "scan".into(),
            "fs".into(),
            "--path=/tmp/workdir".into(),
            "--transforms=url,base64,url".into(),
        ])
        .expect("parse fs config");

        assert_eq!(
            cfg.transform_filter,
            TransformFilter::Only(vec![TransformId::UrlPercent, TransformId::Base64])
        );
    }

    #[test]
    fn parse_git_cli_config_with_positional_repo() {
        let cfg = parse_args_from([
            "scan".into(),
            "git".into(),
            "/tmp/repo".into(),
            "--execution-mode".into(),
            "direct".into(),
            "--event-format=json".into(),
        ])
        .expect("parse git config");

        assert_eq!(
            cfg,
            CliConfig {
                source: CliSource::Git {
                    repo: PathBuf::from("/tmp/repo"),
                },
                execution_mode: ExecutionMode::Direct,
                budgets: ScanBudgets::default(),
                null_sink: false,
                event_format: EventFormat::Json,
                verbose: false,
                rules_file: None,
                transform_filter: TransformFilter::All,
                workers: None,
                decode_depth: None,
                skip_archives: false,
                scan_binary: false,
                persist_findings: false,
                anchor_mode: AnchorMode::Manual,
                debug_level: GitDebugLevel::Off,
                enrich_identities: false,
                git_repo_id: 1,
                git_scan_mode: GitScanMode::OdbBlobFast,
                git_merge_mode: MergeDiffMode::AllParents,
                git_tree_delta_cache_mb: None,
                git_engine_chunk_mb: None,
            }
        );
    }

    #[test]
    fn parse_git_cli_config_supports_extended_flags() {
        let cfg = parse_args_from([
            "scan".into(),
            "git".into(),
            "--repo".into(),
            "/tmp/repo".into(),
            "--execution-mode=connector".into(),
            "--max-items=12".into(),
            "--max-bytes=4096".into(),
            "--x-pack-exec-workers=9".into(),
            "--workers".into(),
            "2".into(),
            "--decode-depth".into(),
            "1".into(),
            "--scan-binary".into(),
            "--debug=perf".into(),
            "--debug".into(),
            "--enrich-identities".into(),
            "--anchors=derived".into(),
            "--event-format=text".into(),
            "--verbose".into(),
            "--null-sink".into(),
            "--transforms=none".into(),
            "--rules=/tmp/custom.yaml".into(),
            "--x-repo-id=42".into(),
            "--x-mode=diff".into(),
            "--x-merge=first-parent".into(),
            "--x-tree-delta-cache-mb=256".into(),
            "--x-engine-chunk-mb=4".into(),
        ])
        .expect("parse git config");

        assert_eq!(
            cfg,
            CliConfig {
                source: CliSource::Git {
                    repo: PathBuf::from("/tmp/repo"),
                },
                execution_mode: ExecutionMode::Connector,
                budgets: ScanBudgets {
                    max_items: 12,
                    max_bytes: 4096,
                },
                null_sink: true,
                event_format: EventFormat::Text,
                verbose: true,
                rules_file: Some(PathBuf::from("/tmp/custom.yaml")),
                transform_filter: TransformFilter::None,
                workers: Some(2),
                decode_depth: Some(1),
                skip_archives: false,
                scan_binary: true,
                persist_findings: false,
                anchor_mode: AnchorMode::Derived,
                debug_level: GitDebugLevel::Perf,
                enrich_identities: true,
                git_repo_id: 42,
                git_scan_mode: GitScanMode::DiffHistory,
                git_merge_mode: MergeDiffMode::FirstParentOnly,
                git_tree_delta_cache_mb: Some(256),
                git_engine_chunk_mb: Some(4),
            }
        );
    }

    #[test]
    fn parse_git_x_pack_exec_workers_sets_workers_when_public_workers_missing() {
        let cfg = parse_args_from([
            "scan".into(),
            "git".into(),
            "--repo=/tmp/repo".into(),
            "--x-pack-exec-workers=7".into(),
        ])
        .expect("parse git config");

        assert_eq!(cfg.workers, Some(7));
    }

    #[test]
    fn parse_git_debug_space_value_sets_perf_level() {
        let cfg = parse_args_from([
            "scan".into(),
            "git".into(),
            "--repo=/tmp/repo".into(),
            "--debug".into(),
            "perf".into(),
        ])
        .expect("parse git config");

        assert_eq!(cfg.debug_level, GitDebugLevel::Perf);
    }

    #[test]
    fn git_help_text_omits_hidden_x_flags() {
        let usage = source_usage("git");
        assert!(usage.contains("--debug"));
        assert!(usage.contains("--enrich-identities"));
        assert!(!usage.contains("--x-mode"));
        assert!(!usage.contains("--x-repo-id"));
    }

    #[test]
    fn parse_help_returns_help_error() {
        let err = parse_args_from(["--help".into()]).expect_err("expected help result");
        assert!(matches!(err, CliError::HelpRequested(_)));
    }
}
