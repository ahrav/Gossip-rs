//! Unified `gossip-worker` binary entrypoint.
//!
//! The worker resolves a typed configuration surface from environment
//! variables plus CLI overrides. Depending on that resolved config it either:
//!
//! - runs a local filesystem or git scan, or
//! - launches the real distributed worker path against etcd and PostgreSQL.

use std::fmt;

use gossip_scanner_runtime::{ScanRuntimeError, scan_fs, scan_git};
use gossip_worker::config::{
    DistributedWorkerConfig, LocalWorkerConfig, ResolvedWorkerConfig, WorkerSourceSettings,
    resolve_worker_config_from_env_and_args,
};
use gossip_worker::production::run_production_worker;
use tracing_subscriber::EnvFilter;

/// Worker-level error distinguishing configuration errors from runtime
/// failures.
#[derive(Debug)]
enum WorkerError {
    Config(gossip_worker::config::WorkerConfigError),
    LocalRuntime(ScanRuntimeError),
    ProductionRuntime(gossip_worker::production::ProductionWorkerError),
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "{error}"),
            Self::LocalRuntime(error) => write!(f, "scan failed: {error}"),
            Self::ProductionRuntime(error) => write!(f, "scan failed: {error}"),
        }
    }
}

impl std::error::Error for WorkerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(error) => Some(error),
            Self::LocalRuntime(error) => Some(error),
            Self::ProductionRuntime(error) => Some(error),
        }
    }
}

impl From<gossip_worker::config::WorkerConfigError> for WorkerError {
    fn from(value: gossip_worker::config::WorkerConfigError) -> Self {
        Self::Config(value)
    }
}

impl From<ScanRuntimeError> for WorkerError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::LocalRuntime(value)
    }
}

impl From<gossip_worker::production::ProductionWorkerError> for WorkerError {
    fn from(value: gossip_worker::production::ProductionWorkerError) -> Self {
        Self::ProductionRuntime(value)
    }
}

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` if present, silently falls back to `info` when absent,
/// and accepts partial/lossy directives without warning.
fn init_tracing() {
    let filter = EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// Execute one local scan using the resolved local worker config.
fn run_local_worker(cfg: &LocalWorkerConfig) -> Result<(u64, u64, u64), WorkerError> {
    let report = match cfg.source() {
        WorkerSourceSettings::Fs(source) => {
            scan_fs(&source.to_scan_config(cfg.execution_mode(), cfg.budgets()))?
        }
        WorkerSourceSettings::Git(source) => {
            scan_git(&source.to_scan_config(cfg.execution_mode(), cfg.budgets()))?
        }
    };
    Ok((
        report.items_scanned,
        report.bytes_scanned,
        report.findings_emitted,
    ))
}

fn log_local_report(cfg: &LocalWorkerConfig, report: (u64, u64, u64)) {
    let (items_scanned, bytes_scanned, findings_emitted) = report;
    let (source_label, path) = match cfg.source() {
        WorkerSourceSettings::Fs(s) => ("fs", s.path().display().to_string()),
        WorkerSourceSettings::Git(s) => ("git", s.repo().display().to_string()),
    };
    tracing::info!(
        backend = "local",
        source = source_label,
        mode = ?cfg.execution_mode(),
        %path,
        items_scanned,
        bytes_scanned,
        findings_emitted,
        "scan completed",
    );
}

fn log_distributed_report(
    cfg: &DistributedWorkerConfig,
    report: gossip_scanner_runtime::distributed::DistributedRunReport,
) {
    // `DistributedWorkerConfig` is type-constrained to `FsSourceSettings`,
    // so source is always "fs" and mode is always `Connector`.
    tracing::info!(
        backend = "production",
        source = "fs",
        mode = ?gossip_scanner_runtime::ExecutionMode::Connector,
        tenant = %cfg.tenant(),
        run = %cfg.run(),
        worker = %cfg.worker(),
        path = %cfg.source().path().display(),
        leases_seen = report.leases_seen,
        shards_scanned = report.shards_scanned,
        "distributed scan completed",
    );
}

fn main() {
    init_tracing();

    let resolved = match resolve_worker_config_from_env_and_args(std::env::args().skip(1)) {
        Ok(cfg) => cfg,
        Err(error) => {
            tracing::error!(error = %error, "invalid worker configuration");
            std::process::exit(2);
        }
    };

    match resolved {
        ResolvedWorkerConfig::Local(cfg) => match run_local_worker(&cfg) {
            Ok(report) => log_local_report(&cfg, report),
            Err(error) => {
                tracing::error!(error = %error, "worker scan failed");
                std::process::exit(1);
            }
        },
        ResolvedWorkerConfig::Distributed(cfg) => {
            tracing::warn!(
                "coordination event recorder is a no-op — \
                 all coordination telemetry will be silently discarded"
            );
            match run_production_worker(
                cfg.production_backends(),
                // No-op recorder — wire a real CoordinationEventRecorder via
                // worker_identity_with_recorder once the telemetry sink is built.
                cfg.worker_identity(),
                cfg.runtime_config(),
            ) {
                Ok(report) => log_distributed_report(&cfg, report),
                Err(error) => {
                    tracing::error!(error = %error, "worker scan failed");
                    std::process::exit(1);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::path::Path;
    use std::process::Command;

    use gossip_scanner_runtime::ExecutionMode;
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
    fn local_worker_scans_filesystem_path() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let cfg = LocalWorkerConfig::new(
            ExecutionMode::Connector,
            WorkerSourceSettings::Fs(gossip_worker::config::FsSourceSettings::new(
                dir.path().to_path_buf(),
            )),
            gossip_scanner_runtime::ScanBudgets::default(),
        )
        .expect("default budgets should be valid");

        let (items_scanned, bytes_scanned, _findings_emitted) =
            run_local_worker(&cfg).expect("filesystem worker should succeed");
        assert!(items_scanned > 0);
        assert!(bytes_scanned > 0);
    }

    #[test]
    fn local_worker_scans_git_repo_path() {
        let dir = tempdir().expect("tempdir");
        create_git_repo(dir.path());
        fs::write(dir.path().join("secret.txt"), "token=aB3dE5fG7hJ9kL1m").expect("write fixture");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);

        let cfg = LocalWorkerConfig::new(
            ExecutionMode::Connector,
            WorkerSourceSettings::Git(gossip_worker::config::GitSourceSettings::new(
                dir.path().to_path_buf(),
            )),
            gossip_scanner_runtime::ScanBudgets::default(),
        )
        .expect("default budgets should be valid");

        let (items_scanned, bytes_scanned, _findings_emitted) =
            run_local_worker(&cfg).expect("git worker should succeed");
        assert!(items_scanned > 0);
        assert!(bytes_scanned > 0);
    }
}
