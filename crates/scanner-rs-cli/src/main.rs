//! Standalone scanner CLI — a thin shell around [`gossip_scanner_runtime`].
//!
//! This binary owns only two concerns:
//! 1. **Argument parsing** — hand-rolled to avoid a framework dependency.
//! 2. **Process-exit policy** — maps runtime errors to stderr + exit code 2.
//!
//! All scan logic (enumeration, paging, dedup) lives in the runtime crate.
//!
//! # Command shape
//!
//! ```text
//! scanner-rs scan fs  --path <dir|file>  [--execution-mode <direct|connector>]
//! scanner-rs scan git --repo <path>      [--execution-mode <direct|connector>]
//! ```
//!
//! Flags accept both `--flag value` and `--flag=value` forms. The first
//! bare positional argument is treated as the path/repo value if no flag
//! was given.

use std::{
    ffi::OsString,
    fmt,
    path::{Path, PathBuf},
};

use gossip_scanner_runtime::{
    ExecutionMode, FsScanConfig, GitScanConfig, ParseExecutionModeError, ScanRuntimeError, scan_fs,
    scan_git,
};

/// Result of argument parsing: either a runnable scan or a help string.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ParsedCommand {
    /// A fully-resolved scan ready for execution.
    Run(ScanCommand),
    /// A usage/help message to print to stdout (not an error).
    Help(String),
}

/// Validated scan parameters extracted from CLI arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScanCommand {
    source: ScanSource,
    execution_mode: ExecutionMode,
}

/// Which source connector to use.
#[derive(Clone, Debug, PartialEq, Eq)]
enum ScanSource {
    /// Local filesystem directory or single file.
    Fs { path: PathBuf },
    /// Git repository (tracked files only).
    Git { repo: PathBuf },
}

/// CLI-layer error carrying a human-readable message and an optional usage
/// hint that is printed below the error on stderr.
#[derive(Debug)]
struct CliError {
    message: String,
    /// When present, printed after a blank line to guide the user toward
    /// correct invocation.
    usage: Option<String>,
}

impl CliError {
    fn with_usage(message: impl Into<String>, usage: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: Some(usage.into()),
        }
    }

    fn message_only(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            usage: None,
        }
    }

    fn usage(&self) -> Option<&str> {
        self.usage.as_deref()
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

/// Entry point.
///
/// Exit codes: 0 on success (including `--help`), 2 on any error.
fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        if let Some(usage) = error.usage() {
            eprintln!();
            eprintln!("{usage}");
        }
        std::process::exit(2);
    }
}

/// Parse arguments, dispatch the scan, and print the outcome summary.
fn run() -> Result<(), CliError> {
    let parsed = parse_args(std::env::args_os())?;
    match parsed {
        ParsedCommand::Help(text) => {
            println!("{text}");
            Ok(())
        }
        ParsedCommand::Run(command) => execute_scan(command),
    }
}

/// Build a runtime config from the parsed command and run the scan.
fn execute_scan(command: ScanCommand) -> Result<(), CliError> {
    let outcome = match command.source {
        ScanSource::Fs { path } => {
            let config = FsScanConfig::new(path).with_execution_mode(command.execution_mode);
            scan_fs(&config)
        }
        ScanSource::Git { repo } => {
            let config = GitScanConfig::new(repo).with_execution_mode(command.execution_mode);
            scan_git(&config)
        }
    }
    .map_err(runtime_error_to_cli)?;

    println!(
        "scan complete: pages={} items={} findings={} diagnostics={}",
        outcome.pages_scanned,
        outcome.items_scanned,
        outcome.findings_emitted,
        outcome.diagnostics_emitted,
    );
    Ok(())
}

/// Wrap a runtime error into a [`CliError`] without attaching usage text
/// (runtime errors are not argument-level mistakes).
fn runtime_error_to_cli(error: ScanRuntimeError) -> CliError {
    CliError::message_only(error.to_string())
}

/// Three-level argument parser: `<exe> scan <source> [flags...]`.
///
/// Dispatches to [`parse_fs_args`] or [`parse_git_args`] once the source
/// keyword is consumed. Returns [`ParsedCommand::Help`] for `--help` / `-h`
/// at any level, or when invoked with no arguments.
fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<ParsedCommand, CliError> {
    let mut args = args.into_iter();
    let exe = args.next().unwrap_or_else(|| OsString::from("scanner-rs"));
    let exe_name = executable_name(&exe);
    let top_usage = top_usage(&exe_name);

    let Some(first) = args.next() else {
        return Ok(ParsedCommand::Help(top_usage));
    };

    let first_str = first.to_string_lossy();
    match first_str.as_ref() {
        "--help" | "-h" => return Ok(ParsedCommand::Help(top_usage)),
        "scan" => {}
        other => {
            return Err(CliError::with_usage(
                format!("expected 'scan' subcommand, got '{other}'"),
                top_usage,
            ));
        }
    }

    let Some(source) = args.next() else {
        return Err(CliError::with_usage(
            "missing scan source; expected 'fs' or 'git'",
            top_usage,
        ));
    };
    let source_str = source.to_string_lossy();
    let rest: Vec<OsString> = args.collect();

    match source_str.as_ref() {
        "fs" => parse_fs_args(&exe_name, &rest),
        "git" => parse_git_args(&exe_name, &rest),
        "--help" | "-h" => Ok(ParsedCommand::Help(top_usage)),
        other => Err(CliError::with_usage(
            format!("unknown scan source '{other}'; expected 'fs' or 'git'"),
            top_usage,
        )),
    }
}

/// Parse `scan fs` flags.
///
/// Accepts `--path <dir|file>` (required) and `--execution-mode <mode>`
/// (optional, defaults to `direct`). A single bare positional argument is
/// accepted as a shorthand for `--path`.
fn parse_fs_args(exe_name: &str, args: &[OsString]) -> Result<ParsedCommand, CliError> {
    let usage = fs_usage(exe_name);
    let mut path: Option<PathBuf> = None;
    let mut execution_mode = ExecutionMode::Direct;

    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        let arg_str = arg.to_string_lossy();

        if matches!(arg_str.as_ref(), "--help" | "-h") {
            return Ok(ParsedCommand::Help(usage));
        }

        if let Some(value) = arg_str.strip_prefix("--path=") {
            if value.is_empty() {
                return Err(CliError::with_usage(
                    "--path requires a value",
                    fs_usage(exe_name),
                ));
            }
            path = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if arg_str == "--path" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError::with_usage(
                    "--path requires a value",
                    fs_usage(exe_name),
                ));
            };
            path = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if let Some(value) = arg_str.strip_prefix("--execution-mode=") {
            execution_mode = parse_execution_mode(value, exe_name, "fs")?;
            index += 1;
            continue;
        }

        if arg_str == "--execution-mode" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError::with_usage(
                    "--execution-mode requires a value",
                    fs_usage(exe_name),
                ));
            };
            let value = value.to_string_lossy();
            execution_mode = parse_execution_mode(value.as_ref(), exe_name, "fs")?;
            index += 1;
            continue;
        }

        if arg_str.starts_with('-') {
            return Err(CliError::with_usage(
                format!("unknown flag '{arg_str}'"),
                fs_usage(exe_name),
            ));
        }

        if path.is_none() {
            path = Some(PathBuf::from(arg));
            index += 1;
            continue;
        }

        return Err(CliError::with_usage(
            format!("unexpected positional argument '{arg_str}'"),
            fs_usage(exe_name),
        ));
    }

    let Some(path) = path else {
        return Err(CliError::with_usage(
            "missing --path <dir|file>",
            fs_usage(exe_name),
        ));
    };

    Ok(ParsedCommand::Run(ScanCommand {
        source: ScanSource::Fs { path },
        execution_mode,
    }))
}

/// Parse `scan git` flags.
///
/// Accepts `--repo <path>` (required) and `--execution-mode <mode>`
/// (optional, defaults to `direct`). A single bare positional argument is
/// accepted as a shorthand for `--repo`.
fn parse_git_args(exe_name: &str, args: &[OsString]) -> Result<ParsedCommand, CliError> {
    let usage = git_usage(exe_name);
    let mut repo: Option<PathBuf> = None;
    let mut execution_mode = ExecutionMode::Direct;

    let mut index = 0usize;
    while index < args.len() {
        let arg = &args[index];
        let arg_str = arg.to_string_lossy();

        if matches!(arg_str.as_ref(), "--help" | "-h") {
            return Ok(ParsedCommand::Help(usage));
        }

        if let Some(value) = arg_str.strip_prefix("--repo=") {
            if value.is_empty() {
                return Err(CliError::with_usage(
                    "--repo requires a value",
                    git_usage(exe_name),
                ));
            }
            repo = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if arg_str == "--repo" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError::with_usage(
                    "--repo requires a value",
                    git_usage(exe_name),
                ));
            };
            repo = Some(PathBuf::from(value));
            index += 1;
            continue;
        }

        if let Some(value) = arg_str.strip_prefix("--execution-mode=") {
            execution_mode = parse_execution_mode(value, exe_name, "git")?;
            index += 1;
            continue;
        }

        if arg_str == "--execution-mode" {
            index += 1;
            let Some(value) = args.get(index) else {
                return Err(CliError::with_usage(
                    "--execution-mode requires a value",
                    git_usage(exe_name),
                ));
            };
            let value = value.to_string_lossy();
            execution_mode = parse_execution_mode(value.as_ref(), exe_name, "git")?;
            index += 1;
            continue;
        }

        if arg_str.starts_with('-') {
            return Err(CliError::with_usage(
                format!("unknown flag '{arg_str}'"),
                git_usage(exe_name),
            ));
        }

        if repo.is_none() {
            repo = Some(PathBuf::from(arg));
            index += 1;
            continue;
        }

        return Err(CliError::with_usage(
            format!("unexpected positional argument '{arg_str}'"),
            git_usage(exe_name),
        ));
    }

    let Some(repo) = repo else {
        return Err(CliError::with_usage(
            "missing --repo <path>",
            git_usage(exe_name),
        ));
    };

    Ok(ParsedCommand::Run(ScanCommand {
        source: ScanSource::Git { repo },
        execution_mode,
    }))
}

/// Parse the `--execution-mode` value, attaching source-specific usage on
/// failure.
fn parse_execution_mode(
    value: &str,
    exe_name: &str,
    source: &str,
) -> Result<ExecutionMode, CliError> {
    value
        .parse::<ExecutionMode>()
        .map_err(|error: ParseExecutionModeError| {
            let usage = match source {
                "fs" => fs_usage(exe_name),
                "git" => git_usage(exe_name),
                _ => top_usage(exe_name),
            };
            CliError::with_usage(error.to_string(), usage)
        })
}

/// Extract the trailing filename component from `argv[0]` for use in usage
/// strings. Falls back to `"scanner-rs"` if the path is empty.
fn executable_name(exe: &OsString) -> String {
    Path::new(exe)
        .file_name()
        .map(|value| value.to_string_lossy().into_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "scanner-rs".to_owned())
}

fn top_usage(exe_name: &str) -> String {
    format!(
        "Usage:\n  {exe_name} scan fs --path <dir|file> [--execution-mode <direct|connector>]\n  {exe_name} scan git --repo <path> [--execution-mode <direct|connector>]\n\nRun '{exe_name} scan fs --help' or '{exe_name} scan git --help' for source-specific options."
    )
}

fn fs_usage(exe_name: &str) -> String {
    format!(
        "Usage:\n  {exe_name} scan fs --path <dir|file> [--execution-mode <direct|connector>]\n\nOptions:\n  --path <dir|file>          Filesystem path to scan\n  --execution-mode <mode>    direct (default) or connector\n  -h, --help                 Show this help"
    )
}

fn git_usage(exe_name: &str) -> String {
    format!(
        "Usage:\n  {exe_name} scan git --repo <path> [--execution-mode <direct|connector>]\n\nOptions:\n  --repo <path>              Git repository path\n  --execution-mode <mode>    direct (default) or connector\n  -h, --help                 Show this help"
    )
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    use super::*;

    fn argv(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    // ── Help output ────────────────────────────────────────────────

    #[rstest]
    #[case::no_args(&["scanner-rs"], &["scan fs --path", "scan git --repo"])]
    #[case::top_help(&["scanner-rs", "--help"], &["scan fs --path", "scan git --repo"])]
    #[case::top_help_short(&["scanner-rs", "-h"], &["scan fs --path", "scan git --repo"])]
    #[case::scan_help(&["scanner-rs", "scan", "--help"], &["scan fs --path", "scan git --repo"])]
    #[case::scan_help_short(&["scanner-rs", "scan", "-h"], &["scan fs --path", "scan git --repo"])]
    #[case::fs_help(&["scanner-rs", "scan", "fs", "--help"], &["--execution-mode"])]
    #[case::fs_help_short(&["scanner-rs", "scan", "fs", "-h"], &["--execution-mode"])]
    #[case::git_help(&["scanner-rs", "scan", "git", "--help"], &["--execution-mode"])]
    #[case::git_help_short(&["scanner-rs", "scan", "git", "-h"], &["--execution-mode"])]
    fn parse_help(#[case] args: &[&str], #[case] must_contain: &[&str]) {
        let parsed = parse_args(argv(args)).expect("parse");
        let ParsedCommand::Help(text) = parsed else {
            panic!("expected Help, got {parsed:?}");
        };
        for needle in must_contain {
            assert!(
                text.contains(needle),
                "help text should contain '{needle}'\ngot: {text}"
            );
        }
    }

    // ── Successful fs parses ───────────────────────────────────────

    #[rstest]
    #[case::flag_space(
        &["scanner-rs", "scan", "fs", "--path", "."],
        ExecutionMode::Direct, "."
    )]
    #[case::flag_equals(
        &["scanner-rs", "scan", "fs", "--path=./src"],
        ExecutionMode::Direct, "./src"
    )]
    #[case::positional(
        &["scanner-rs", "scan", "fs", "."],
        ExecutionMode::Direct, "."
    )]
    #[case::explicit_direct(
        &["scanner-rs", "scan", "fs", "--path", ".", "--execution-mode", "direct"],
        ExecutionMode::Direct, "."
    )]
    #[case::connector_mode(
        &["scanner-rs", "scan", "fs", "--path", ".", "--execution-mode", "connector"],
        ExecutionMode::Connector, "."
    )]
    #[case::connector_equals(
        &["scanner-rs", "scan", "fs", "--path", ".", "--execution-mode=connector"],
        ExecutionMode::Connector, "."
    )]
    fn parse_fs_run(
        #[case] args: &[&str],
        #[case] expected_mode: ExecutionMode,
        #[case] expected_path: &str,
    ) {
        let parsed = parse_args(argv(args)).expect("parse");
        let ParsedCommand::Run(cmd) = parsed else {
            panic!("expected Run, got {parsed:?}");
        };
        assert_eq!(cmd.execution_mode, expected_mode);
        assert_eq!(
            cmd.source,
            ScanSource::Fs {
                path: PathBuf::from(expected_path)
            }
        );
    }

    // ── Successful git parses ──────────────────────────────────────

    #[rstest]
    #[case::flag_space(
        &["scanner-rs", "scan", "git", "--repo", "."],
        ExecutionMode::Direct, "."
    )]
    #[case::flag_equals(
        &["scanner-rs", "scan", "git", "--repo=./repo"],
        ExecutionMode::Direct, "./repo"
    )]
    #[case::positional(
        &["scanner-rs", "scan", "git", "."],
        ExecutionMode::Direct, "."
    )]
    #[case::connector_mode(
        &["scanner-rs", "scan", "git", "--repo", ".", "--execution-mode", "connector"],
        ExecutionMode::Connector, "."
    )]
    #[case::explicit_direct_equals(
        &["scanner-rs", "scan", "git", "--repo", ".", "--execution-mode=direct"],
        ExecutionMode::Direct, "."
    )]
    fn parse_git_run(
        #[case] args: &[&str],
        #[case] expected_mode: ExecutionMode,
        #[case] expected_repo: &str,
    ) {
        let parsed = parse_args(argv(args)).expect("parse");
        let ParsedCommand::Run(cmd) = parsed else {
            panic!("expected Run, got {parsed:?}");
        };
        assert_eq!(cmd.execution_mode, expected_mode);
        assert_eq!(
            cmd.source,
            ScanSource::Git {
                repo: PathBuf::from(expected_repo)
            }
        );
    }

    // ── Error cases ────────────────────────────────────────────────

    #[rstest]
    #[case::unknown_subcommand(&["scanner-rs", "bogus"], "expected 'scan'")]
    #[case::missing_source(&["scanner-rs", "scan"], "missing scan source")]
    #[case::unknown_source(&["scanner-rs", "scan", "bogus"], "unknown scan source")]
    #[case::fs_missing_path(&["scanner-rs", "scan", "fs"], "missing --path")]
    #[case::fs_path_equals_empty(&["scanner-rs", "scan", "fs", "--path="], "--path requires")]
    #[case::fs_path_no_next(&["scanner-rs", "scan", "fs", "--path"], "--path requires")]
    #[case::fs_unknown_flag(&["scanner-rs", "scan", "fs", "--bogus"], "unknown flag")]
    #[case::fs_extra_positional(&["scanner-rs", "scan", "fs", ".", "extra"], "unexpected positional")]
    #[case::fs_bad_mode(
        &["scanner-rs", "scan", "fs", "--path", ".", "--execution-mode", "bogus"],
        "invalid execution mode"
    )]
    #[case::fs_mode_no_next(
        &["scanner-rs", "scan", "fs", "--path", ".", "--execution-mode"],
        "--execution-mode requires"
    )]
    #[case::git_missing_repo(&["scanner-rs", "scan", "git"], "missing --repo")]
    #[case::git_repo_equals_empty(&["scanner-rs", "scan", "git", "--repo="], "--repo requires")]
    #[case::git_repo_no_next(&["scanner-rs", "scan", "git", "--repo"], "--repo requires")]
    #[case::git_unknown_flag(&["scanner-rs", "scan", "git", "--bogus"], "unknown flag")]
    #[case::git_extra_positional(
        &["scanner-rs", "scan", "git", ".", "extra"],
        "unexpected positional"
    )]
    #[case::git_bad_mode(
        &["scanner-rs", "scan", "git", "--repo", ".", "--execution-mode", "bogus"],
        "invalid execution mode"
    )]
    fn parse_errors(#[case] args: &[&str], #[case] expected_substring: &str) {
        let err = parse_args(argv(args)).expect_err("should fail");
        let msg = err.to_string();
        assert!(
            msg.contains(expected_substring),
            "error '{msg}' should contain '{expected_substring}'"
        );
    }
}
