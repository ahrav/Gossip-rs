//! Eval-harness binary — measures scanner accuracy against labeled corpora.
//!
//! Compares scanner findings (from a JSONL file or a live scan) against
//! ground-truth annotations from labeled corpora and computes precision,
//! recall, and PRC-AUC.
//!
//! # Pipelines
//!
//! Two evaluation pipelines exist, selected by subcommand:
//!
//! - **Position-based** (`creddata`, `synthetic`) — matches findings to truth
//!   items by file path and byte/line overlap, producing confidence-ranked
//!   classifications for PRC-AUC computation with bootstrap CIs.
//! - **Count-based** (`leaky-repo`) — compares per-file finding counts against
//!   expected counts. Coarser than position-based matching but useful for
//!   quality tracking against corpora that lack position annotations.
//!
//! # Data flow
//!
//! Both pipelines follow a load-match-measure-report pattern. The
//! position-based pipeline has richer internals:
//!
//! ```text
//! Position-based (creddata / synthetic):
//!   truth loader ──► TruthItem[]
//!                                ├─► match_findings ──► ClassifiedFinding[]
//!   finding source ──► NormalizedFinding[] ──► dedup pipeline (identity, optional cross-rule)
//!                                                       ├─► compute_metrics ──► EvalMetrics
//!   corpus files ──► HashMap<path, bytes>               ├─► hash_corpus_snapshot ──► build_provenance_from_precomputed ──► Provenance
//!                                                       ├─► bootstrap_ap_ci ──► CI
//!                                                       ├─► check_regression ──► Verdict
//!                                                       └─► build_error_book [JSON only] ──► ErrorBook
//!                                                                   └─► EvalReport ──► JSON / table
//!                                                                                     (table leaves error_book unset)
//!
//! Count-based (leaky-repo):
//!   expectations CSV ──► FileExpectation[]
//!                                    ├─► compare_counts ──► per-file TP/FP/FN
//!   findings JSONL ──► NormalizedFinding[]                  └─► aggregate ──► EvalMetrics
//!                                                                └─► EvalReport ──► JSON / table
//! ```
//!
//! # Finding sources
//!
//! Position-based subcommands accept findings from two mutually exclusive
//! sources (enforced by clap argument groups), and runtime checks ensure
//! the selection is non-empty:
//!
//! - `--findings <path>` — pre-computed JSONL from a previous scanner run.
//! - `--scan-corpus <dir>` — live-scan a directory using the embedded
//!   `scanner_engine::demo_engine()`, collecting findings via an in-memory
//!   event sink. Intended for quick iteration during rule development.
//!
//! # Exit codes
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | Pass/warn for position-based pipelines; always 0 for `leaky-repo` (no regression gate) |
//! | 1    | Block — regression detected against a `--baseline` report |
//! | 2    | Argument or runtime error |

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::{Parser, Subcommand, ValueEnum};

use eval_harness::creddata::load_meta_dir;
use eval_harness::finding_parser::{
    JsonlParseResult, dedup_findings_with_mode, parse_findings_file, parse_findings_jsonl,
};
use eval_harness::leaky_repo::{compare_counts, parse_leaky_repo_csv};
use eval_harness::matching::{MatchConfig, MatchResult, match_findings};
use eval_harness::metrics::{BootstrapConfig, EvalMetrics, bootstrap_ap_ci, compute_metrics};
use eval_harness::pipeline::EvalPipelineConfig;
use eval_harness::provenance::{
    Provenance, build_provenance, build_provenance_from_precomputed, collect_files_recursive,
    hash_corpus_snapshot,
};
use eval_harness::regression::{RegressionResult, RegressionThresholds, check_regression};
use eval_harness::report::{
    ErrorBook, ErrorBookConfig, EvalReport, build_error_book, render_json, render_table,
    write_json_file,
};
use eval_harness::synthetic::load_synthetic_manifest;
use eval_harness::types::{NormalizedFinding, TruthItem, normalize_path};

// ── CLI types ───────────────────────────────────────────────────────────

/// Top-level CLI dispatcher.
///
/// Each subcommand corresponds to a specific corpus format and evaluation
/// pipeline. The subcommand choice determines both how ground truth is
/// loaded and which matching strategy is applied.
#[derive(Parser)]
#[command(
    name = "eval-harness",
    about = "Measure scanner accuracy against labeled corpora"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// Available evaluation subcommands, each targeting a different corpus format.
///
/// `Creddata` and `Synthetic` share the position-based pipeline via
/// [`run_position_pipeline`] but differ in how they load ground truth.
/// `LeakyRepo` uses a separate count-based pipeline because LeakyRepo
/// annotations lack positional information (only per-file secret counts).
#[derive(Subcommand)]
enum Command {
    /// Position-based accuracy against CredData CSV annotations.
    Creddata(CreddataArgs),
    /// Count-based accuracy against LeakyRepo secrets CSV.
    LeakyRepo(LeakyRepoArgs),
    /// Position-based accuracy against a synthetic JSON manifest.
    Synthetic(SyntheticArgs),
}

/// Shared arguments for position-based evaluation subcommands.
///
/// Both `creddata` and `synthetic` use the same finding-loading, matching,
/// metrics, and reporting pipeline — they differ only in how ground truth
/// is loaded. This struct captures the arguments common to both, flattened
/// into each subcommand via `#[command(flatten)]`.
///
/// Finding sources are mutually exclusive (enforced by clap argument group
/// `"input"`): either `--findings` (pre-computed JSONL) or `--scan-corpus`
/// (live scan) must be provided. Runtime validation keeps this defense in
/// depth by rejecting empty source selection.
#[derive(clap::Args)]
struct PositionPipelineArgs {
    /// Pre-computed findings JSONL file.
    #[arg(long, group = "input")]
    findings: Option<PathBuf>,

    /// Directory to live-scan for findings.
    #[arg(long, group = "input")]
    scan_corpus: Option<PathBuf>,

    /// Path normalization root (stripped from finding and truth paths).
    #[arg(long)]
    corpus_root: PathBuf,

    /// Output format.
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Write JSON output to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,

    /// Baseline JSON report for regression comparison.
    #[arg(long)]
    baseline: Option<PathBuf>,

    /// Collapse findings from different rules at the same byte span, keeping
    /// only the highest-confidence finding per location.
    #[arg(long)]
    cross_rule_dedup: bool,
}

/// Arguments for evaluating against the CredData corpus.
///
/// CredData organizes ground truth as one CSV file per category inside a
/// `meta/` directory. The harness loads all CSV files from `--meta-dir`,
/// normalizes paths relative to `--corpus-root`, and feeds the resulting
/// truth items into the position-based pipeline.
#[derive(clap::Args)]
struct CreddataArgs {
    /// CredData CSV directory containing ground-truth annotations.
    #[arg(long)]
    meta_dir: PathBuf,

    #[command(flatten)]
    common: PositionPipelineArgs,
}

/// Arguments for evaluating against the LeakyRepo corpus.
///
/// LeakyRepo provides only per-file expected secret counts (no byte/line
/// positions), so this subcommand uses the count-based pipeline rather
/// than position-based matching. Confidence-aware metrics (AP, bootstrap
/// CI) are not meaningful and are set to degenerate single-threshold
/// stand-ins.
#[derive(clap::Args)]
struct LeakyRepoArgs {
    /// Path to the LeakyRepo secrets CSV.
    #[arg(long)]
    secrets_csv: PathBuf,

    /// Pre-computed findings JSONL file.
    #[arg(long)]
    findings: PathBuf,

    /// Path normalization root (stripped from finding paths) and corpus root
    /// used for provenance hashing.
    #[arg(long)]
    corpus_root: PathBuf,

    /// Output format.
    #[arg(long, default_value = "json")]
    format: OutputFormat,

    /// Write JSON output to this file instead of stdout.
    #[arg(long)]
    output: Option<PathBuf>,
}

/// Arguments for evaluating against a synthetic test corpus.
///
/// Synthetic corpora use a hand-written JSON manifest describing
/// expected findings with file paths, line ranges, and rule names.
/// Follows the same position-based pipeline as `creddata` but loads
/// truth via [`load_synthetic_manifest`] instead of CredData CSVs.
#[derive(clap::Args)]
struct SyntheticArgs {
    /// Synthetic JSON manifest file.
    #[arg(long)]
    manifest: PathBuf,

    #[command(flatten)]
    common: PositionPipelineArgs,
}

/// Report output format.
///
/// JSON is the default and supports `--output <file>` for CI artifact
/// storage and baseline comparison. Table is human-readable ASCII
/// intended for interactive terminal use and cannot be written to a file
/// (the `--output` + `Table` combination is rejected at validation time).
#[derive(Clone, Copy, ValueEnum)]
enum OutputFormat {
    /// Machine-readable JSON (pretty-printed).
    Json,
    /// Fixed-width ASCII table for terminal display.
    Table,
}

// ── Entry point ─────────────────────────────────────────────────────────

/// Maps the return value of [`run`] to process exit codes.
///
/// Exit code 2 is reserved for argument or runtime errors (distinct from
/// exit code 1, which indicates a regression block verdict).
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            eprintln!("harness: {e}");
            std::process::exit(2);
        }
    }
}

/// Parse CLI arguments and dispatch to the appropriate subcommand handler.
///
/// Returns an exit code (0 for pass/warn, 1 for block) on success, or a
/// boxed error for argument and runtime failures.
fn run() -> Result<i32, Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Command::Creddata(args) => run_creddata(args),
        Command::LeakyRepo(args) => run_leaky_repo(args),
        Command::Synthetic(args) => run_synthetic(args),
    }
}

// ── Subcommand handlers ─────────────────────────────────────────────────

/// Load CredData CSV annotations and evaluate via the position-based pipeline.
///
/// Loads all CSV files from `--meta-dir`, warns on per-file parse errors
/// (which are non-fatal to allow partial corpora), then delegates to
/// [`run_position_pipeline`] for matching, metrics, and reporting.
fn run_creddata(args: CreddataArgs) -> Result<i32, Box<dyn Error>> {
    let canonical_root = canonicalize_root(&args.common.corpus_root);

    let dir_result = load_meta_dir(&args.meta_dir, &canonical_root)?;
    if !dir_result.file_errors.is_empty() {
        for e in &dir_result.file_errors {
            eprintln!("warning: {e}");
        }
    }

    run_position_pipeline(dir_result.parsed.items, &args.common)
}

/// Load a synthetic JSON manifest and evaluate via the position-based pipeline.
///
/// Structurally identical to [`run_creddata`] except the truth loader:
/// [`load_synthetic_manifest`] reads a single JSON file rather than a
/// directory of CSVs.
fn run_synthetic(args: SyntheticArgs) -> Result<i32, Box<dyn Error>> {
    let canonical_root = canonicalize_root(&args.common.corpus_root);
    let truth = load_synthetic_manifest(&args.manifest, &canonical_root)?;

    run_position_pipeline(truth, &args.common)
}

/// Run the count-based evaluation pipeline for LeakyRepo.
///
/// Unlike the position-based pipeline, LeakyRepo annotations specify only
/// how many secrets exist per file, not where they are. The matching
/// strategy is therefore count-based: for each file, `compare_counts`
/// pairs the expected count against the actual finding count to derive
/// TP, FP, and FN tallies.
///
/// The per-file counts are then aggregated into corpus-wide totals and
/// packed into an [`EvalMetrics`] struct. Because there is no confidence
/// ranking (all findings are treated equally), confidence-aware metrics
/// like AP, P@R, R@P, and bootstrap CI are not meaningful. AP is set to
/// precision as a degenerate single-threshold approximation so the report
/// schema stays uniform across subcommands.
///
/// Regression checking is not supported for this subcommand (no
/// `--baseline` flag), so the exit code is always 0.
fn run_leaky_repo(args: LeakyRepoArgs) -> Result<i32, Box<dyn Error>> {
    validate_output_format(args.format, args.output.as_deref())?;
    let canonical_root = canonicalize_root(&args.corpus_root);

    let expectations = parse_leaky_repo_csv(&args.secrets_csv)?;
    let parse_result = parse_findings_file(&args.findings, &canonical_root)?;
    print_parse_diagnostics(&parse_result);

    let comparisons = compare_counts(parse_result.findings, &expectations);

    // Collapse per-file results into corpus-wide totals.
    let (mut tp, mut fp, mut false_neg) = (0u64, 0u64, 0u64);
    for c in &comparisons {
        tp += u64::from(c.tp);
        fp += u64::from(c.fp);
        false_neg += u64::from(c.false_neg);
    }

    let metrics = EvalMetrics::from_counts(tp, fp, false_neg);

    let provenance = build_provenance(&args.corpus_root, None, None)?;

    let report = EvalReport {
        metrics,
        provenance,
        regression: None,
        error_book: None,
        pipeline_config: EvalPipelineConfig::default(),
    };

    output_report(&report, args.format, args.output.as_deref())?;
    Ok(0)
}

// ── Shared position-based pipeline ──────────────────────────────────────

/// Execute the full position-based evaluation pipeline.
///
/// This is the shared core of `creddata` and `synthetic` subcommands.
/// The caller provides truth items (already loaded and normalized);
/// this function handles everything from finding ingestion through
/// final report output. It derives the canonical path root from
/// `args.corpus_root` internally so path normalization has a single
/// source of truth in this stage.
///
/// # Pipeline steps
///
/// 1. **Validate** — reject invalid argument combinations (e.g.,
///    `--output` + `--format table`).
/// 2. **Load findings** — from pre-computed JSONL or a live scan.
/// 3. **Dedup** — apply typed dedup semantics:
///    - `ByRule`: keep highest confidence per `(path, byte_start, byte_end, rule)`.
///    - `AcrossRules` (`--cross-rule-dedup`): keep highest confidence per
///      `(path, byte_start, byte_end)` across all rules (tie-break: lexicographically
///      smallest rule).
/// 4. **Load corpus snapshot** — read all files under `corpus_root` once
///    into memory for matching and derive corpus hash/count/bytes from that
///    same snapshot for provenance (no second corpus read).
/// 5. **Match** — classify each finding as TP, FP, or Unlabeled using
///    position-based overlap with truth items. Rule matching is disabled
///    (`require_rule_match: false`) so any finding overlapping a truth
///    region counts as a match regardless of rule name.
/// 6. **Compute metrics** — precision, recall, F1, F2, AP with tie
///    collapsing, P@R, R@P, per-rule breakdown, and bootstrap CI.
/// 7. **Regression check** — if a baseline report is provided, compare
///    current metrics against it using default thresholds (2pp block,
///    0.5pp warn) with CI overlap gating.
/// 8. **Report** — assemble all outputs into an [`EvalReport`], building
///    `error_book` only for JSON output mode (table mode skips the builder
///    and keeps `error_book = None`), then render JSON or table.
///
/// # Exit code
///
/// Returns the regression verdict's exit code (0 for pass/warn, 1 for
/// block). When no baseline is provided, always returns 0.
fn run_position_pipeline(
    truth: Vec<TruthItem>,
    args: &PositionPipelineArgs,
) -> Result<i32, Box<dyn Error>> {
    validate_output_format(args.format, args.output.as_deref())?;
    let canonical_root = canonicalize_root(&args.corpus_root);

    let mut findings = load_findings(
        args.findings.as_deref(),
        args.scan_corpus.as_deref(),
        &canonical_root,
    )?;
    let pipeline_config = EvalPipelineConfig {
        cross_rule_dedup: args.cross_rule_dedup,
    };
    let pre_dedup_count = findings.len();
    dedup_findings_with_mode(&mut findings, pipeline_config.dedup_mode());
    let collapsed = pre_dedup_count.saturating_sub(findings.len());
    if collapsed > 0 {
        eprintln!(
            "info: cross-rule dedup collapsed {collapsed} finding(s) ({pre_dedup_count} -> {})",
            findings.len(),
        );
    }

    let snapshot = load_corpus_snapshot(&args.corpus_root)?;
    let match_result =
        run_position_matching(findings, truth, &snapshot.file_contents, &pipeline_config);
    let metrics = compute_position_metrics(&match_result)?;
    let provenance = build_position_provenance(&snapshot)?;
    let regression = maybe_check_regression(&metrics, &pipeline_config, args.baseline.as_deref())?;
    let error_book = maybe_build_error_book_for_output(args.format, || {
        build_error_book(
            &match_result.classified,
            &match_result.false_negatives,
            &snapshot.file_contents,
            &ErrorBookConfig::default(),
        )
    });
    let exit_code = regression_exit_code(regression.as_ref());

    let report = EvalReport {
        metrics,
        provenance,
        regression,
        error_book,
        pipeline_config,
    };

    output_report(&report, args.format, args.output.as_deref())?;
    Ok(exit_code)
}

/// In-memory corpus snapshot used by the position-based pipeline.
///
/// The snapshot contains path-keyed file bytes for matching/error-book
/// assembly, plus a precomputed corpus digest tuple used to build
/// provenance without re-reading files from disk.
struct CorpusSnapshot {
    /// Normalized relative path -> full file bytes.
    file_contents: HashMap<String, Vec<u8>>,
    /// BLAKE3 digest of the snapshot using provenance framing.
    corpus_hash: String,
    corpus_file_count: u64,
    corpus_total_bytes: u64,
}

/// Match findings to truth using byte/line overlap semantics.
fn run_position_matching(
    findings: Vec<NormalizedFinding>,
    truth: Vec<TruthItem>,
    file_contents: &HashMap<String, Vec<u8>>,
    pipeline_config: &EvalPipelineConfig,
) -> MatchResult {
    let config = MatchConfig {
        require_rule_match: false,
        dedup_mode: pipeline_config.dedup_mode(),
    };
    match_findings(findings, truth, file_contents, config)
}

/// Compute confidence-aware metrics and AP bootstrap CI for a match result.
fn compute_position_metrics(match_result: &MatchResult) -> Result<EvalMetrics, Box<dyn Error>> {
    let total_positives = match_result.total_positives();
    let fn_count = match_result.fn_count();
    let metrics = compute_metrics(&match_result.classified, fn_count, total_positives)?;
    let ci = bootstrap_ap_ci(
        &match_result.classified,
        total_positives,
        &BootstrapConfig::default(),
    )?;
    Ok(metrics.with_bootstrap_ci(ci)?)
}

/// Build provenance from precomputed snapshot hash/count/bytes.
fn build_position_provenance(snapshot: &CorpusSnapshot) -> Result<Provenance, Box<dyn Error>> {
    Ok(build_provenance_from_precomputed(
        snapshot.corpus_hash.clone(),
        snapshot.corpus_file_count,
        snapshot.corpus_total_bytes,
        None,
        None,
    )?)
}

/// Compare metrics against a baseline report when provided.
///
/// A pipeline-config mismatch is reported as a warning but not treated as a
/// hard error. The harness still computes regression deltas so users can see
/// the numeric impact, while making it explicit that the comparison may not
/// be apples-to-apples.
fn maybe_check_regression(
    metrics: &EvalMetrics,
    current_pipeline_config: &EvalPipelineConfig,
    baseline_path: Option<&Path>,
) -> Result<Option<RegressionResult>, Box<dyn Error>> {
    let Some(path) = baseline_path else {
        return Ok(None);
    };
    let baseline_report = load_baseline(path)?;
    let mut result = check_regression(
        metrics,
        &baseline_report.metrics,
        &RegressionThresholds::default(),
    )?;
    if &baseline_report.pipeline_config != current_pipeline_config {
        let warning = format!(
            "pipeline config mismatch with baseline: current: cross_rule_dedup={}, baseline: cross_rule_dedup={}",
            current_pipeline_config.cross_rule_dedup,
            baseline_report.pipeline_config.cross_rule_dedup,
        );
        eprintln!("warning: {warning}");
        result.baseline_comparable = false;
        result.comparison_warnings.push(warning);
    }
    Ok(Some(result))
}

/// Build error_book only for JSON output mode.
///
/// For table output this returns `None` without invoking `build`, so
/// expensive error-book assembly is skipped entirely.
fn maybe_build_error_book_for_output<F>(format: OutputFormat, build: F) -> Option<ErrorBook>
where
    F: FnOnce() -> ErrorBook,
{
    if matches!(format, OutputFormat::Json) {
        Some(build())
    } else {
        None
    }
}

/// Convert optional regression verdict to process exit code.
fn regression_exit_code(regression: Option<&RegressionResult>) -> i32 {
    regression.map_or(0, |r| r.verdict.exit_code())
}

// ── Finding loaders ─────────────────────────────────────────────────────

/// Load findings from exactly one of two mutually exclusive sources.
///
/// The clap `group = "input"` attribute on the CLI arguments enforces
/// mutual exclusivity at the argument-parsing level. This function
/// provides defense-in-depth runtime guards for non-empty selection:
/// exactly one source must be present (both and neither are rejected),
/// which protects programmatic callers that bypass clap.
///
/// Diagnostics (malformed lines, skipped findings) are emitted to stderr
/// regardless of the source to give visibility into data quality issues.
fn load_findings(
    findings_path: Option<&Path>,
    scan_corpus: Option<&Path>,
    canonical_root: &str,
) -> Result<Vec<NormalizedFinding>, Box<dyn Error>> {
    match (findings_path, scan_corpus) {
        (Some(path), None) => {
            let result = parse_findings_file(path, canonical_root)?;
            print_parse_diagnostics(&result);
            Ok(result.findings)
        }
        (None, Some(dir)) => run_live_scan(dir, canonical_root),
        (Some(_), Some(_)) | (None, None) => {
            Err("exactly one of --findings or --scan-corpus is required".into())
        }
    }
}

/// Run the scanner engine against a directory and collect findings in memory.
///
/// Uses the built-in `demo_engine()` (default ruleset) and the local
/// scheduler, collecting scanner events into a [`VecEventSink`]. Events
/// are serialized as JSONL, then re-parsed through the same
/// [`parse_findings_jsonl`] path as pre-computed findings to ensure both
/// sources produce identical `NormalizedFinding` representations.
///
/// The scan is synchronous: `scan_local` blocks until all files have been
/// processed. This path keeps discovered file metadata and scanner event bytes
/// in memory, so it is intended for small-to-medium corpora used in
/// development iteration, not for multi-GB production benchmarks.
fn run_live_scan(
    scan_dir: &Path,
    canonical_root: &str,
) -> Result<Vec<NormalizedFinding>, Box<dyn Error>> {
    use scanner_git::VecEventSink;
    use scanner_scheduler::scheduler::local_fs_owner::{
        LocalConfig, LocalFile, VecFileSource, scan_local,
    };

    let engine = Arc::new(scanner_engine::demo_engine());

    let mut files: Vec<PathBuf> = Vec::new();
    collect_files_recursive(scan_dir, &mut files)?;
    let mut metadata_failures: usize = 0;
    let local_files: Vec<LocalFile> = files
        .into_iter()
        .filter_map(|path| match path.metadata() {
            Ok(m) => Some(LocalFile {
                path,
                size: m.len(),
            }),
            Err(e) => {
                eprintln!(
                    "warning: could not read metadata for {}: {e}",
                    path.display(),
                );
                metadata_failures += 1;
                None
            }
        })
        .collect();
    if metadata_failures > 0 {
        let total = metadata_failures + local_files.len();
        let failure_rate = metadata_failures as f64 / total as f64;
        eprintln!("warning: {metadata_failures}/{total} files failed metadata read");
        // Keep minor filesystem churn (deleted/permission-changed files)
        // non-fatal, but fail once losses are large enough to compromise
        // evaluation representativeness.
        if failure_rate > 0.05 {
            return Err(format!(
                "too many metadata failures: {metadata_failures}/{total} ({:.1}%)",
                failure_rate * 100.0,
            )
            .into());
        }
    }

    let sink = Arc::new(VecEventSink::new());
    let cfg = LocalConfig {
        event_sink: sink.clone(),
        ..LocalConfig::default()
    };

    let report = scan_local(engine, VecFileSource::new(local_files), cfg);
    validate_scan_health(&report)?;

    let bytes = sink.take();
    let jsonl = String::from_utf8(bytes).map_err(|e| {
        format!(
            "scanner output is not valid UTF-8 (byte offset {}): \
             non-UTF-8 scanner output cannot be evaluated",
            e.utf8_error().valid_up_to(),
        )
    })?;
    let result = parse_findings_jsonl(&jsonl, canonical_root);
    print_parse_diagnostics(&result);

    Ok(result.findings)
}

/// Validate live-scan health before consuming emitted findings.
///
/// The eval harness requires complete scan output. Any I/O errors,
/// dropped findings, persistence emission failures, or explicit
/// `persistence_incomplete` signal result in a runtime error.
fn validate_scan_health(
    report: &scanner_scheduler::scheduler::local_fs_owner::LocalReport,
) -> Result<(), Box<dyn Error>> {
    let stats = &report.stats;
    let mut reasons: Vec<String> = Vec::with_capacity(4);

    if stats.io_errors > 0 {
        reasons.push(format!("io_errors={}", stats.io_errors));
    }
    if stats.dropped_findings > 0 {
        reasons.push(format!("dropped_findings={}", stats.dropped_findings));
    }
    if stats.persistence_emit_failures > 0 {
        reasons.push(format!(
            "persistence_emit_failures={}",
            stats.persistence_emit_failures,
        ));
    }
    if stats.persistence_incomplete {
        reasons.push("persistence_incomplete=true".to_string());
    }

    if reasons.is_empty() {
        Ok(())
    } else {
        Err(format!("live scan did not complete cleanly: {}", reasons.join(", "),).into())
    }
}

// ── Corpus file loader ──────────────────────────────────────────────────

/// Read corpus files once into an in-memory snapshot.
///
/// The snapshot powers both matching (`file_contents`) and provenance
/// (`corpus_hash`, `corpus_file_count`, `corpus_total_bytes`) so the
/// position pipeline avoids a second corpus read.
///
/// Lightweight hardening guardrails reject implausibly large snapshots
/// before memory usage becomes pathological.
fn load_corpus_snapshot(corpus_root: &Path) -> Result<CorpusSnapshot, Box<dyn Error>> {
    const MAX_SNAPSHOT_FILES: usize = 5_000_000;
    const MAX_SNAPSHOT_BYTES: u64 = 512 * 1024 * 1024 * 1024; // 512 GiB

    let mut paths: Vec<PathBuf> = Vec::new();
    collect_files_recursive(corpus_root, &mut paths)?;
    if paths.len() > MAX_SNAPSHOT_FILES {
        return Err(format!(
            "corpus snapshot exceeds file guardrail: {} files > {}",
            paths.len(),
            MAX_SNAPSHOT_FILES,
        )
        .into());
    }

    let mut snapshot_records: Vec<(PathBuf, String, Vec<u8>)> = Vec::with_capacity(paths.len());
    let mut observed_total_bytes: u64 = 0;

    for path in paths {
        let rel = path.strip_prefix(corpus_root).map_err(|e| {
            format!(
                "corpus file {} not under corpus root {}: {e}",
                path.display(),
                corpus_root.display(),
            )
        })?;
        // Empty root: corpus_root prefix is already stripped by
        // strip_prefix, so normalize_path only canonicalizes slashes.
        let key = normalize_path(&rel.to_string_lossy(), "");
        if key.is_empty() {
            continue;
        }
        let data = std::fs::read(&path)?;
        observed_total_bytes = observed_total_bytes
            .checked_add(data.len() as u64)
            .ok_or("corpus snapshot byte count overflowed u64")?;
        if observed_total_bytes > MAX_SNAPSHOT_BYTES {
            return Err(format!(
                "corpus snapshot exceeds byte guardrail: {observed_total_bytes} > {MAX_SNAPSHOT_BYTES}",
            )
            .into());
        }
        snapshot_records.push((rel.to_path_buf(), key, data));
    }

    let (corpus_hash, corpus_file_count, corpus_total_bytes) = hash_corpus_snapshot(
        snapshot_records
            .iter()
            .map(|(rel_path, _, bytes)| (rel_path.as_path(), bytes.as_slice())),
    );

    if corpus_file_count as usize != snapshot_records.len() {
        return Err(format!(
            "internal snapshot file-count mismatch: hash reports {}, loader has {}",
            corpus_file_count,
            snapshot_records.len(),
        )
        .into());
    }
    if corpus_total_bytes != observed_total_bytes {
        return Err(format!(
            "internal snapshot byte mismatch: hash reports {}, loader counted {}",
            corpus_total_bytes, observed_total_bytes,
        )
        .into());
    }

    let mut file_contents = HashMap::with_capacity(snapshot_records.len());
    for (_, key, data) in snapshot_records {
        // If multiple filesystem paths normalize to the same logical key,
        // retain the last inserted bytes and surface the collision.
        if file_contents.insert(key.clone(), data).is_some() {
            eprintln!("warning: duplicate normalized corpus path in snapshot: {key}");
        }
    }

    Ok(CorpusSnapshot {
        file_contents,
        corpus_hash,
        corpus_file_count,
        corpus_total_bytes,
    })
}

// ── Baseline loader ─────────────────────────────────────────────────────

/// Deserialize a previously saved JSON report for regression comparison.
///
/// The baseline must conform to the current `EvalReport` JSON schema.
/// Deserialization failures surface as the returned error.
fn load_baseline(path: &Path) -> Result<EvalReport, Box<dyn Error>> {
    let contents = std::fs::read_to_string(path)?;
    let report: EvalReport = serde_json::from_str(&contents)?;
    Ok(report)
}

// ── Output ──────────────────────────────────────────────────────────────

/// Route the report to the requested output format and destination.
///
/// JSON output can go to either stdout (default) or a file (`--output`).
/// Table output always goes to stdout; the `--output` + `Table`
/// combination is rejected earlier by [`validate_output_format`].
fn output_report(
    report: &EvalReport,
    format: OutputFormat,
    output_path: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    match format {
        OutputFormat::Json => {
            if let Some(path) = output_path {
                write_json_file(report, path)?;
            } else {
                let json = render_json(report)?;
                println!("{json}");
            }
        }
        OutputFormat::Table => {
            let table = render_table(report);
            print!("{table}");
        }
    }
    Ok(())
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Convert the corpus root path to a canonical string for use as
/// the `canonical_root` argument to [`normalize_path`].
///
/// Delegates to [`eval_harness::types::canonicalize_path`] so the root
/// undergoes the same lexical normalization (backslash → forward slash,
/// collapse `.`/`..`, strip leading `/`) applied to finding and truth
/// paths. Without this, an absolute `--corpus-root /abs/path` would
/// retain the leading slash while [`normalize_path`] strips it from
/// finding paths, breaking prefix removal.
fn canonicalize_root(corpus_root: &Path) -> String {
    eval_harness::types::canonicalize_path(&corpus_root.to_string_lossy())
}

/// Reject the `--output` + `--format table` combination.
///
/// Table output is a fixed-width ASCII format designed for terminal
/// display and is not suitable for file persistence (it cannot be
/// deserialized for baseline comparison). This check runs before any
/// heavy computation to fail fast on invalid argument combinations.
fn validate_output_format(
    format: OutputFormat,
    output: Option<&Path>,
) -> Result<(), Box<dyn Error>> {
    if output.is_some() && matches!(format, OutputFormat::Table) {
        return Err("--output requires --format json".into());
    }
    Ok(())
}

/// Emit stderr warnings for any data quality issues found during JSONL parsing.
///
/// Non-fatal: malformed lines and skipped findings are counted and
/// reported, not treated as hard errors. This allows partial evaluation
/// when the findings input contains a small number of corrupt records.
/// Only the first error/reason is printed to avoid flooding the terminal
/// on heavily corrupt inputs.
fn print_parse_diagnostics(result: &JsonlParseResult) {
    if result.malformed_lines > 0 {
        eprintln!(
            "warning: {} malformed line(s) in findings input",
            result.malformed_lines,
        );
        if let Some(ref err) = result.first_malformed_error {
            eprintln!("  first error: {err}");
        }
    }
    if result.skipped_findings > 0 {
        eprintln!(
            "warning: {} finding(s) skipped during parse",
            result.skipped_findings,
        );
        if let Some(ref reason) = result.first_skip_reason {
            eprintln!("  first skip reason: {reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaky_repo_requires_corpus_root_via_clap() {
        let err = Cli::try_parse_from([
            "eval-harness",
            "leaky-repo",
            "--secrets-csv",
            "secrets.csv",
            "--findings",
            "findings.jsonl",
        ])
        .err()
        .expect("clap parse should fail when --corpus-root is missing");

        let message = err.to_string();
        assert!(
            message.contains("--corpus-root"),
            "error should mention missing --corpus-root: {message}"
        );
    }

    #[test]
    fn validate_scan_health_accepts_clean_report() {
        let report = scanner_scheduler::scheduler::local_fs_owner::LocalReport::default();
        assert!(validate_scan_health(&report).is_ok());
    }

    #[test]
    fn validate_scan_health_rejects_incomplete_report() {
        let mut report = scanner_scheduler::scheduler::local_fs_owner::LocalReport::default();
        report.stats.io_errors = 1;
        report.stats.dropped_findings = 2;
        report.stats.persistence_emit_failures = 3;
        report.stats.persistence_incomplete = true;

        let err = validate_scan_health(&report).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("io_errors=1"),
            "missing io_errors detail: {msg}"
        );
        assert!(
            msg.contains("dropped_findings=2"),
            "missing dropped_findings detail: {msg}"
        );
        assert!(
            msg.contains("persistence_emit_failures=3"),
            "missing persistence_emit_failures detail: {msg}"
        );
        assert!(
            msg.contains("persistence_incomplete=true"),
            "missing persistence_incomplete detail: {msg}"
        );
    }

    #[test]
    fn table_output_skips_error_book_builder() {
        let maybe = maybe_build_error_book_for_output(OutputFormat::Table, || {
            panic!("table mode must not build error_book")
        });
        assert!(
            maybe.is_none(),
            "table mode should skip error_book assembly entirely"
        );
    }

    #[test]
    fn json_output_builds_error_book() {
        let maybe = maybe_build_error_book_for_output(OutputFormat::Json, || ErrorBook {
            false_positives: Vec::new(),
            false_negatives: Vec::new(),
        });
        assert!(
            maybe.is_some(),
            "json mode should assemble error_book for serialized reports"
        );
    }
}
