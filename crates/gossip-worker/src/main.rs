//! Unified gossip-worker entrypoint.
//!
//! The worker now routes scans through `gossip-scanner-runtime`, which in turn
//! maps assignments onto `ScanSourceFactory -> ScanDriver::run`.

use std::fmt;
use std::path::PathBuf;

use gossip_scanner_runtime::{
    ExecutionMode, FsScanConfig, GitScanConfig, ScanRuntimeError, scan_fs, scan_git,
};
use tracing_subscriber::EnvFilter;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WorkerSource {
    Fs,
    Git,
}

/// Worker launch configuration.
///
/// The worker intentionally defaults to connector mode so both worker and CLI
/// entrypoints exercise the same scan-driver seam.
#[derive(Clone, Debug, PartialEq, Eq)]
struct WorkerConfig {
    source: WorkerSource,
    path: PathBuf,
    execution_mode: ExecutionMode,
}

impl Default for WorkerConfig {
    fn default() -> Self {
        Self {
            source: WorkerSource::Fs,
            path: PathBuf::from("."),
            execution_mode: ExecutionMode::Connector,
        }
    }
}

#[derive(Debug)]
enum WorkerError {
    Usage(String),
    Runtime(ScanRuntimeError),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Usage(msg) => write!(f, "{msg}"),
            Self::Runtime(error) => write!(f, "scan failed: {error}"),
        }
    }
}

impl std::error::Error for WorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Usage(_) => None,
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<ScanRuntimeError> for WorkerError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

fn usage() -> &'static str {
    "usage: gossip-worker [--mode=direct|connector] [fs|git] [path]\n\
     defaults: --mode=connector fs ."
}

fn parse_mode_flag(flag: &str) -> Result<ExecutionMode, WorkerError> {
    let Some(value) = flag.strip_prefix("--mode=") else {
        return Err(WorkerError::Usage(usage().to_owned()));
    };
    value
        .parse::<ExecutionMode>()
        .map_err(|error| WorkerError::Usage(error.to_string()))
}

fn parse_source(value: &str) -> Result<WorkerSource, WorkerError> {
    match value {
        "fs" => Ok(WorkerSource::Fs),
        "git" => Ok(WorkerSource::Git),
        _ => Err(WorkerError::Usage(format!(
            "unknown source '{value}'\n{}",
            usage()
        ))),
    }
}

/// Parse worker CLI args using a stable, minimal grammar.
///
/// Supported forms:
/// - `[]` -> defaults (`connector`, `fs`, `.`)
/// - `[path]` -> filesystem scan at `path`
/// - `[fs|git, path]` -> explicit source and path
/// - optional `--mode=...` prefix on all forms
fn parse_args<I>(args: I) -> Result<WorkerConfig, WorkerError>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut cfg = WorkerConfig::default();
    let mut positional: Vec<String> = args.into_iter().map(Into::into).collect();

    if positional
        .first()
        .is_some_and(|first| first.starts_with("--mode="))
    {
        cfg.execution_mode = parse_mode_flag(&positional.remove(0))?;
    }

    match positional.len() {
        0 => Ok(cfg),
        1 => {
            cfg.path = PathBuf::from(&positional[0]);
            Ok(cfg)
        }
        2 => {
            cfg.source = parse_source(&positional[0])?;
            cfg.path = PathBuf::from(&positional[1]);
            Ok(cfg)
        }
        _ => Err(WorkerError::Usage(usage().to_owned())),
    }
}

/// Execute one scan using the unified runtime seam.
///
/// Returns `(items_scanned, bytes_scanned, findings_emitted)` for logging and
/// smoke-test assertions.
fn run_worker(cfg: &WorkerConfig) -> Result<(u64, u64, u64), WorkerError> {
    match cfg.source {
        WorkerSource::Fs => scan_fs(
            &FsScanConfig::new(&cfg.path)
                .with_execution_mode(cfg.execution_mode)
                .with_budgets(gossip_scanner_runtime::ScanBudgets::default()),
        )
        .map(|report| {
            (
                report.items_scanned,
                report.bytes_scanned,
                report.findings_emitted,
            )
        })
        .map_err(Into::into),
        WorkerSource::Git => scan_git(
            &GitScanConfig::new(&cfg.path)
                .with_execution_mode(cfg.execution_mode)
                .with_budgets(gossip_scanner_runtime::ScanBudgets::default()),
        )
        .map(|report| {
            (
                report.items_scanned,
                report.bytes_scanned,
                report.findings_emitted,
            )
        })
        .map_err(Into::into),
    }
}

fn log_report(cfg: &WorkerConfig, report: (u64, u64, u64)) {
    let (items_scanned, bytes_scanned, findings_emitted) = report;
    let source = match cfg.source {
        WorkerSource::Fs => "fs",
        WorkerSource::Git => "git",
    };

    tracing::info!(
        source,
        mode = ?cfg.execution_mode,
        path = %cfg.path.display(),
        items_scanned,
        bytes_scanned,
        findings_emitted,
        "scan completed",
    );
}

fn main() {
    init_tracing();

    let args = std::env::args().skip(1);
    let cfg = match parse_args(args) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::error!(error = %error, "invalid worker arguments");
            std::process::exit(2);
        }
    };

    match run_worker(&cfg) {
        Ok(report) => log_report(&cfg, report),
        Err(error) => {
            tracing::error!(error = %error, "worker scan failed");
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tempfile::tempdir;

    fn create_git_repo(path: &Path) {
        run_git(path, &["init", "-q"]);
        run_git(path, &["config", "user.email", "worker-tests@example.com"]);
        run_git(path, &["config", "user.name", "Worker Tests"]);
    }

    fn run_git(path: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(path)
            .args(args)
            .output()
            .expect("git command should run");
        assert!(
            output.status.success(),
            "git command failed: git -C {} {}\nstdout:{}\nstderr:{}",
            path.display(),
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn parse_args_defaults_to_connector_fs_current_dir() {
        let cfg = parse_args(Vec::<String>::new()).expect("parse defaults");
        assert_eq!(cfg.source, WorkerSource::Fs);
        assert_eq!(cfg.path, PathBuf::from("."));
        assert_eq!(cfg.execution_mode, ExecutionMode::Connector);
    }

    #[test]
    fn parse_args_supports_explicit_git_path_and_mode() {
        let cfg = parse_args(["--mode=direct", "git", "/tmp/repo"]).expect("parse args");
        assert_eq!(cfg.source, WorkerSource::Git);
        assert_eq!(cfg.path, PathBuf::from("/tmp/repo"));
        assert_eq!(cfg.execution_mode, ExecutionMode::Direct);
    }

    #[test]
    fn parse_args_rejects_unknown_source() {
        let err = parse_args(["unknown", "/tmp/path"]).expect_err("unknown source");
        assert!(err.to_string().contains("unknown source"));
    }

    #[test]
    fn run_worker_scans_filesystem_path() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=alpha").expect("write fixture");

        let cfg = WorkerConfig {
            source: WorkerSource::Fs,
            path: dir.path().to_path_buf(),
            execution_mode: ExecutionMode::Connector,
        };

        let report = run_worker(&cfg).expect("filesystem worker run");
        assert!(report.0 >= 1);
        assert!(report.2 >= 1);
    }

    #[test]
    fn run_worker_scans_git_repo_path() {
        let dir = tempdir().expect("tempdir");
        create_git_repo(dir.path());
        fs::write(dir.path().join("secret.txt"), "token=alpha").expect("write fixture");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);

        let cfg = WorkerConfig {
            source: WorkerSource::Git,
            path: dir.path().to_path_buf(),
            execution_mode: ExecutionMode::Connector,
        };

        let report = run_worker(&cfg).expect("git worker run");
        assert!(report.0 >= 1);
        assert!(
            report.2 >= 1,
            "git scan should emit findings for test fixture"
        );
    }
}
