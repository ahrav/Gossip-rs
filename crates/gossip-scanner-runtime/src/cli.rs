//! CLI entrypoint wiring for scanner runtime.

use std::ffi::OsString;
use std::fmt;
use std::io;
use std::path::PathBuf;

use gossip_scan_driver::CancellationToken;
use scanner_scheduler::events::EventOutput;

use crate::commit_sink::CliNoOpCommitSink;
use crate::event_sink::JsonlEventSink;
use crate::{
    ExecutionMode, FsScanConfig, GitScanConfig, ScanBudgets, ScanRuntimeError,
    scan_fs_with_runtime, scan_git_with_runtime,
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

    let mut source_path: Option<PathBuf> = None;
    let mut i = 0usize;
    while i < args.len() {
        let arg = args[i].to_string_lossy();

        if is_help_flag(&args[i]) {
            return Err(CliError::HelpRequested(source_usage(&source_kind)));
        }

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
            let value = args
                .get(i + 1)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --execution-mode requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?
                .to_string_lossy()
                .into_owned();
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
            let value = args
                .get(i + 1)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --max-items requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?
                .to_string_lossy()
                .into_owned();
            budgets.max_items = parse_usize(&value, "--max-items", &source_kind)?;
            i += 2;
            continue;
        }

        if let Some(value) = arg.strip_prefix("--max-bytes=") {
            budgets.max_bytes = parse_u64(value, "--max-bytes", &source_kind)?;
            i += 1;
            continue;
        }

        if arg == "--max-bytes" {
            let value = args
                .get(i + 1)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: --max-bytes requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?
                .to_string_lossy()
                .into_owned();
            budgets.max_bytes = parse_u64(&value, "--max-bytes", &source_kind)?;
            i += 2;
            continue;
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
            let value = args
                .get(i + 1)
                .ok_or_else(|| {
                    CliError::Usage(format!(
                        "error: {source_flag} requires a value\n\n{}",
                        source_usage(&source_kind)
                    ))
                })?
                .clone();
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
    })
}

/// Run one CLI scan and stream JSONL findings to stdout.
pub fn run(config: CliConfig) -> Result<gossip_scan_driver::ScanReport, CliError> {
    let sink = JsonlEventSink::new(io::stdout());
    let commit = CliNoOpCommitSink;
    let cancel = CancellationToken::new();

    let report = match config.source {
        CliSource::Fs { path } => {
            scan_fs_with_runtime(
                &FsScanConfig::new(path)
                    .with_execution_mode(config.execution_mode)
                    .with_budgets(config.budgets),
                &sink,
                &commit,
                &cancel,
            )?
            .report
        }
        CliSource::Git { repo } => {
            scan_git_with_runtime(
                &GitScanConfig::new(repo)
                    .with_execution_mode(config.execution_mode)
                    .with_budgets(config.budgets),
                &sink,
                &commit,
                &cancel,
            )?
            .report
        }
    };

    sink.flush();
    Ok(report)
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

fn is_help_flag(flag: &OsString) -> bool {
    matches!(flag.to_string_lossy().as_ref(), "--help" | "-h")
}

fn top_usage() -> String {
    [
        "usage:",
        "  scanner-rs scan fs  --path <dir|file> [--execution-mode direct|connector] [--max-items N] [--max-bytes N]",
        "  scanner-rs scan git --repo <path>     [--execution-mode direct|connector] [--max-items N] [--max-bytes N]",
    ]
    .join("\n")
}

fn source_usage(source: &str) -> String {
    match source {
        "fs" => "usage: scanner-rs scan fs --path <dir|file> [--execution-mode direct|connector] [--max-items N] [--max-bytes N]".to_owned(),
        "git" => "usage: scanner-rs scan git --repo <path> [--execution-mode direct|connector] [--max-items N] [--max-bytes N]".to_owned(),
        _ => top_usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_fs_cli_config() {
        let cfg = parse_args_from([
            "scan".into(),
            "fs".into(),
            "--path".into(),
            "/tmp/workdir".into(),
            "--execution-mode=connector".into(),
            "--max-items=12".into(),
            "--max-bytes=4096".into(),
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
            }
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
            }
        );
    }

    #[test]
    fn parse_help_returns_help_error() {
        let err = parse_args_from(["--help".into()]).expect_err("expected help result");
        assert!(matches!(err, CliError::HelpRequested(_)));
    }
}
