//! CLI entrypoint: argument parsing, scan dispatch, and summary output.
//!
//! This module owns the `scanner-rs scan {fs|git}` interface. It parses raw
//! `OsString` arguments into a `CliConfig`, selects an event sink based on
//! `--event-format`, dispatches to the unified runtime (`scan_fs_with_runtime`
//! / `scan_git_with_runtime`), and prints a compact `key=value` summary to
//! stderr.
//!
//! # Argument structure
//!
//! ```text
//! scanner-rs scan fs  --path <dir|file> [FS OPTIONS] [COMMON OPTIONS]
//! scanner-rs scan git --repo <path>     [GIT OPTIONS] [COMMON OPTIONS]
//! ```
//!
//! All flags accept both `--flag=value` and `--flag value` forms. Source
//! paths can also be passed as bare positional arguments. Hidden `--x-*`
//! flags (git-only) are parsed but excluded from `--help` output.
//!
//! # Worker auto-sizing
//!
//! For git scans without an explicit `--workers` override, the CLI probes
//! `git count-objects -v` to read the in-pack object count and passes it to
//! `auto_pack_exec_workers_for_in_pack` for right-sized parallelism. The
//! probe runs before the timing window so it does not inflate
//! elapsed/throughput numbers.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io;
use std::path::PathBuf;

use scanner_engine::TransformId;
use scanner_git::{GitEventOutput, GitScanMode, MergeDiffMode};
use scanner_scheduler::source_kind::SourceKind;

use crate::commit_sink::CliNoOpCommitSink;
use crate::event_sink::{JsonEventSink, JsonlEventSink, SarifEventSink, TextEventSink};
use crate::{
    AnchorMode, CancellationToken, EventFormat, ExecutionMode, FsScanConfig, GitDebugLevel,
    GitScanConfig, ScanBudgets, ScanReport, ScanRuntimeError, TransformFilter, available_workers,
    scan_fs_with_runtime, scan_git_with_runtime,
};

/// Parsed source subcommand from the CLI.
///
/// Determines which scan path (`scan_fs_with_runtime` or
/// `scan_git_with_runtime`) the [`run`] function dispatches to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CliSource {
    /// Scan a filesystem path (directory or file).
    Fs { path: PathBuf },
    /// Scan a git repository.
    Git { repo: PathBuf },
}

/// Fully parsed CLI configuration produced by [`parse_args`].
///
/// All values have been validated and default-filled; this struct is ready
/// for direct consumption by [`run`]. Builder-pattern setters are
/// intentionally omitted — construction flows exclusively through the
/// argument parser.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliConfig {
    /// Scan source (fs path or git repo).
    pub source: CliSource,
    /// Execution mode flag (retained for compatibility/telemetry).
    pub execution_mode: ExecutionMode,
    /// Scan execution budget controls.
    pub budgets: ScanBudgets,
    /// When true, all emitted events are silently dropped.
    pub null_sink: bool,
    /// Output format for emitted events.
    pub event_format: EventFormat,
    /// When true, text output includes extra detail.
    pub verbose: bool,
    /// When true, extended timing/debug metrics are appended to the summary.
    pub summary_debug: bool,
    /// Optional external rules file path override.
    pub rules_file: Option<PathBuf>,
    /// Transform decoder filter.
    pub transform_filter: TransformFilter,
    /// Optional worker thread count override.
    pub workers: Option<usize>,
    /// Optional transform decode depth override.
    pub decode_depth: Option<usize>,
    /// When true, archive expansion is disabled.
    pub skip_archives: bool,
    /// When true, binary files are scanned.
    pub scan_binary: bool,
    /// When true, findings are persisted via the commit sink bridge.
    pub persist_findings: bool,
    /// Anchor extraction policy for rule matching.
    pub anchor_mode: AnchorMode,
    /// Git debug output level.
    pub debug_level: GitDebugLevel,
    /// When true, enrich commit metadata with identity dictionary IDs.
    pub enrich_identities: bool,
    /// Stable repository identifier for persistence keys (git only).
    pub git_repo_id: u64,
    /// Git scan strategy.
    pub git_scan_mode: GitScanMode,
    /// Merge-diff strategy for merge commits.
    pub git_merge_mode: MergeDiffMode,
    /// Optional tree delta cache size override in MiB.
    pub git_tree_delta_cache_mb: Option<u32>,
    /// Optional engine chunk size override in MiB.
    pub git_engine_chunk_mb: Option<u32>,
}

/// CLI-layer error.
///
/// [`HelpRequested`](CliError::HelpRequested) exits cleanly (exit code 0);
/// [`Usage`](CliError::Usage) exits with a non-zero code and error message;
/// [`Runtime`](CliError::Runtime) wraps scan-runtime failures.
#[derive(Debug)]
pub enum CliError {
    /// `--help` or `-h` was passed; the contained string is the usage text.
    HelpRequested(String),
    /// Invalid arguments or missing required flags.
    Usage(String),
    /// The scan runtime returned an error during execution.
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

/// Parse CLI arguments from the process environment.
///
/// Skips `argv[0]` (the binary name) and delegates to the internal
/// argument parser.
pub fn parse_args() -> Result<CliConfig, CliError> {
    parse_args_from(std::env::args_os().skip(1))
}

/// Parse CLI arguments from an arbitrary iterator.
///
/// Expects the iterator to start at the subcommand position (i.e., `argv[0]`
/// already stripped). Accepts `OsString` to handle non-UTF-8 paths on Unix.
///
/// Returns [`CliError::HelpRequested`] for `--help`/`-h` at any position,
/// [`CliError::Usage`] for invalid arguments, or a fully populated
/// [`CliConfig`] on success.
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
    let mut summary_debug = false;
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

        if let Some(value) = arg.strip_prefix("--debug=") {
            if source_kind == "git" {
                debug_level = parse_debug_level(value, &source_kind)?;
                summary_debug = true;
                i += 1;
                continue;
            }
            return Err(CliError::Usage(format!(
                "error: --debug does not accept a value for 'scan fs'\n\n{}",
                source_usage(&source_kind)
            )));
        }

        if arg == "--debug" {
            summary_debug = true;
            if source_kind == "git" {
                if let Some(value) = args.get(i + 1) {
                    let next = value.to_string_lossy();
                    if let Some(parsed) = parse_debug_level_token(next.as_ref()) {
                        debug_level = promote_debug_level(debug_level, parsed);
                        i += 2;
                        continue;
                    }
                }
                debug_level = promote_debug_level(debug_level, GitDebugLevel::Stats);
            } else if let Some(value) = args.get(i + 1) {
                let next = value.to_string_lossy();
                if parse_debug_level_token(next.as_ref()).is_some() {
                    return Err(CliError::Usage(format!(
                        "error: --debug does not accept a value for 'scan fs'\n\n{}",
                        source_usage(&source_kind)
                    )));
                }
            }
            i += 1;
            continue;
        }

        // Git-specific public and hidden (`--x-*`) knobs. Hidden flags are
        // intentionally parsed for parity but excluded from usage text.
        if source_kind == "git" {
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

    Ok(CliConfig {
        source,
        execution_mode,
        budgets,
        null_sink,
        event_format,
        verbose,
        summary_debug,
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
/// ```
pub fn run(config: CliConfig) -> Result<ScanReport, CliError> {
    let sink = build_event_sink(config.event_format, config.verbose, config.null_sink);
    let commit = CliNoOpCommitSink;
    let cancel = CancellationToken::new();

    let base_workers = config.workers.unwrap_or_else(available_workers);

    let source_kind = match &config.source {
        CliSource::Fs { .. } => SourceKind::Fs,
        CliSource::Git { .. } => SourceKind::Git,
    };

    // Auto-size pack-exec workers *before* the timing window so the probe
    // subprocess does not inflate elapsed/throughput numbers.
    let effective_workers = match &config.source {
        CliSource::Fs { .. } => base_workers,
        CliSource::Git { repo } => {
            if config.workers.is_some() {
                base_workers
            } else {
                probe_in_pack_object_count(repo)
                    .ok()
                    .map(scanner_git::auto_pack_exec_workers_for_in_pack)
                    .unwrap_or(base_workers)
            }
        }
    };

    let wall_start = std::time::Instant::now();
    let summary_debug = config.summary_debug;

    let report = match config.source {
        CliSource::Fs { path } => {
            scan_fs_with_runtime(
                &FsScanConfig::new(path)
                    .with_execution_mode(config.execution_mode)
                    .with_budgets(config.budgets)
                    .with_workers(base_workers)
                    .with_decode_depth(config.decode_depth)
                    .with_skip_archives(config.skip_archives)
                    .with_scan_binary(config.scan_binary)
                    .with_persist_findings(config.persist_findings)
                    .with_anchor_mode(config.anchor_mode)
                    .with_rules_file(config.rules_file.clone())
                    .with_transform_filter(config.transform_filter.clone()),
                sink.as_ref(),
                &commit,
                &cancel,
            )?
            .report
        }
        CliSource::Git { ref repo } => {
            let outcome = scan_git_with_runtime(
                &GitScanConfig::new(repo.clone())
                    .with_workers(effective_workers)
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
                sink.as_ref(),
                &cancel,
            )?;
            if let Some(debug_output) = outcome.debug_output.as_deref() {
                eprint!("{debug_output}");
            }
            outcome.report
        }
    };

    sink.flush();
    let elapsed = wall_start.elapsed();

    print_scan_summary(
        &report,
        elapsed,
        effective_workers,
        source_kind,
        summary_debug,
    );

    Ok(report)
}

/// Print a compact `key=value` summary to stderr.
///
/// Field order is stable and machine-parseable. Git scans use `objects=`
/// instead of `files=` to match the reference scanner-rs binary output.
/// When `summary_debug` is true, additional breakdown fields (`workers`,
/// `binary_skipped`, `init_ms`, `scan_ms`, `persist_ms`, etc.) are
/// appended after the standard fields.
fn print_scan_summary(
    report: &ScanReport,
    elapsed: std::time::Duration,
    workers: usize,
    source_kind: SourceKind,
    summary_debug: bool,
) {
    use std::io::Write;
    let rendered = render_scan_summary(report, elapsed, workers, source_kind, summary_debug);
    let _ = io::stderr().write_all(rendered.as_bytes());
}

fn render_scan_summary(
    report: &ScanReport,
    elapsed: std::time::Duration,
    workers: usize,
    source_kind: SourceKind,
    summary_debug: bool,
) -> String {
    let elapsed_ms = elapsed.as_millis() as u64;
    let elapsed_secs = elapsed.as_secs_f64();
    let throughput_mib_s = if elapsed_secs > 0.0 {
        (report.bytes_scanned as f64) / (1024.0 * 1024.0) / elapsed_secs
    } else {
        0.0
    };

    let human_bytes = format_human_bytes(report.bytes_scanned);

    let mut buf = String::with_capacity(if summary_debug { 512 } else { 256 });
    use std::fmt::Write as FmtWrite;
    let items_label = match source_kind {
        SourceKind::Git => "objects",
        SourceKind::Fs => "files",
    };
    let _ = writeln!(buf, "{items_label}={}", report.items_scanned);
    let _ = writeln!(buf, "chunks={}", report.chunks_scanned);
    let _ = writeln!(buf, "bytes={} ({human_bytes})", report.bytes_scanned);
    let _ = writeln!(buf, "findings={}", report.findings_emitted);
    let _ = writeln!(buf, "errors={}", report.errors);
    let _ = writeln!(buf, "elapsed_ms={elapsed_ms}");
    let _ = writeln!(buf, "throughput_mib_s={throughput_mib_s:.2}");
    if summary_debug {
        let scan_ms = report.scan_ns / 1_000_000;
        let persist_ms = if source_kind == SourceKind::Fs {
            report.persist_ns / 1_000_000
        } else {
            0
        };
        // Subtract both scan and persist so the three components are additive:
        // init_ms + scan_ms + persist_ms ≈ elapsed_ms.
        let init_ms = elapsed_ms
            .saturating_sub(scan_ms)
            .saturating_sub(persist_ms);
        let _ = writeln!(buf, "workers={workers}");
        let _ = writeln!(buf, "binary_skipped={}", report.binary_skipped);
        let _ = writeln!(buf, "ext_skipped={}", report.ext_skipped);
        let _ = writeln!(buf, "lock_skipped={}", report.lock_skipped);
        let _ = writeln!(buf, "binary_extracted={}", report.binary_extracted);
        if source_kind == SourceKind::Fs {
            let _ = writeln!(buf, "dropped_findings={}", report.dropped_findings);
            let _ = writeln!(
                buf,
                "persist_emit_failures={}",
                report.persist_emit_failures
            );
            let _ = writeln!(
                buf,
                "persist_incomplete={}",
                if report.persist_incomplete { 1 } else { 0 }
            );
        }
        let _ = writeln!(buf, "init_ms={init_ms}");
        let _ = writeln!(buf, "scan_ms={scan_ms}");
        if source_kind == SourceKind::Fs {
            let _ = writeln!(buf, "persist_ms={persist_ms}");
        }
    }
    buf
}

/// Format byte counts using binary IEC units (KiB, MiB, GiB, TiB, PiB).
///
/// Values below 1 KiB are formatted without a decimal (e.g., `512B`).
/// Larger values are formatted with two decimal places (e.g., `1.43GiB`).
fn format_human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes}B");
    }
    let mut value = bytes as f64;
    for unit in &UNITS[1..] {
        value /= 1024.0;
        if value < 1024.0 {
            return format!("{value:.2}{unit}");
        }
    }
    format!("{value:.2}PiB")
}

/// Construct the appropriate event sink for the requested output format.
///
/// When `null_sink` is true, returns a null sink that discards all events
/// (useful for benchmarking without I/O overhead). Otherwise returns a sink
/// that writes to stdout in the requested format.
fn build_event_sink(
    event_format: EventFormat,
    verbose: bool,
    null_sink: bool,
) -> Box<dyn GitEventOutput> {
    if null_sink {
        eprintln!("info: --null-sink enabled; findings will not be written to stdout");
        return Box::new(scanner_git::NullEventSink);
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

/// Strip an ASCII prefix from an `OsStr`, returning the remainder.
///
/// # Safety
///
/// Uses `OsStr::from_encoded_bytes_unchecked` on the suffix bytes. This is
/// safe because all prefixes passed to this function are ASCII-only (`--flag=`),
/// meaning the split point never falls inside a multi-byte character.
fn strip_os_prefix<'a>(arg: &'a OsStr, prefix: &str) -> Option<&'a OsStr> {
    let bytes = arg.as_encoded_bytes();
    if bytes.starts_with(prefix.as_bytes()) {
        Some(unsafe { OsStr::from_encoded_bytes_unchecked(&bytes[prefix.len()..]) })
    } else {
        None
    }
}

/// Return the `in-pack` object count for the repository by shelling out to
/// `git count-objects -v`.
///
/// This probe is advisory and used only for worker auto-sizing. Callers
/// should fall back to deterministic defaults when it fails (e.g., `git`
/// not on PATH, bare repos, or permission errors).
fn probe_in_pack_object_count(repo_root: &std::path::Path) -> io::Result<u64> {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(repo_root)
        .args(["count-objects", "-v"])
        .output()
        .map_err(|e| io::Error::other(format!("failed to run git count-objects: {e}")))?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "git count-objects failed with status {}",
            output.status
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    parse_in_pack_object_count(&stdout)
        .ok_or_else(|| io::Error::other("missing in-pack entry in git count-objects output"))
}

/// Parse `in-pack` object count from `git count-objects -v` output.
fn parse_in_pack_object_count(text: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("in-pack:")?;
        rest.trim().parse::<u64>().ok()
    })
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
            "  --debug                           Extended scan summary metrics to stderr",
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
            "  --debug                           Stage stats + extended summary metrics to stderr",
            "  --debug=perf                      Stage stats + per-pack timing + extended summary metrics to stderr",
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
#[path = "cli_tests.rs"]
mod tests;
