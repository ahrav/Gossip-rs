//! Unified `gossip-worker` binary entrypoint.
//!
//! The worker resolves a typed configuration surface from environment
//! variables plus CLI overrides. Depending on that resolved config it either:
//!
//! - runs an explicit local direct filesystem/git scan, or
//! - launches the default real distributed worker path against etcd +
//!   PostgreSQL.
//!
//! Connector-mode filesystem scans now route through the actual distributed
//! worker loop. They do not silently downgrade to the local scan path.

use std::fmt;

use gossip_scanner_runtime::{
    ScanRuntimeError,
    distributed::DistributedRunReport,
    scan_fs, scan_git,
};
use gossip_worker::config::{
    DistributedWorkerConfig, LocalWorkerConfig, ResolvedWorkerConfig, WorkerSourceSettings,
    resolve_worker_config_from_env_and_args,
};
use gossip_worker::production::{ProductionWorkerError, run_production_worker};
use tracing_subscriber::EnvFilter;

/// Worker-level error distinguishing configuration errors from runtime
/// failures.
#[derive(Debug)]
enum WorkerError {
    Config(gossip_worker::config::WorkerConfigError),
    LocalRuntime(ScanRuntimeError),
    ProductionRuntime(ProductionWorkerError),
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

impl From<ProductionWorkerError> for WorkerError {
    fn from(value: ProductionWorkerError) -> Self {
        Self::ProductionRuntime(value)
    }
}

/// Execution report returned by one resolved worker launch.
#[derive(Clone, Debug, PartialEq, Eq)]
enum WorkerRunReport {
    Local((u64, u64, u64)),
    Distributed(DistributedRunReport),
}

/// Initialize the global tracing subscriber.
fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|error| {
        eprintln!("warning: invalid RUST_LOG filter ({error}), falling back to 'info'");
        EnvFilter::new("info")
    });
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

/// Execute one real distributed worker launch against the production backends.
fn run_distributed_worker(
    cfg: &DistributedWorkerConfig,
) -> Result<DistributedRunReport, ProductionWorkerError> {
    run_production_worker(
        cfg.production_backends(),
        cfg.worker_identity(),
        cfg.runtime_config(),
    )
}

/// Dispatch one already-resolved worker launch.
///
/// The distributed runner is injected so tests can drive the same dispatch
/// logic through an in-memory coordinator and persistence bundle while the
/// binary uses the real etcd/PostgreSQL path.
fn execute_resolved_worker_with<F>(
    resolved: &ResolvedWorkerConfig,
    distributed_runner: F,
) -> Result<WorkerRunReport, WorkerError>
where
    F: FnOnce(&DistributedWorkerConfig) -> Result<DistributedRunReport, ProductionWorkerError>,
{
    match resolved {
        ResolvedWorkerConfig::Local(cfg) => run_local_worker(cfg).map(WorkerRunReport::Local),
        ResolvedWorkerConfig::Distributed(cfg) => distributed_runner(cfg)
            .map(WorkerRunReport::Distributed)
            .map_err(WorkerError::from),
    }
}

fn log_local_report(cfg: &LocalWorkerConfig, report: (u64, u64, u64)) {
    let (items_scanned, bytes_scanned, findings_emitted) = report;
    match cfg.source() {
        WorkerSourceSettings::Fs(source) => {
            tracing::info!(
                backend = "local",
                source = "fs",
                mode = ?cfg.execution_mode(),
                path = %source.path().display(),
                items_scanned,
                bytes_scanned,
                findings_emitted,
                "scan completed",
            );
        }
        WorkerSourceSettings::Git(source) => {
            tracing::info!(
                backend = "local",
                source = "git",
                mode = ?cfg.execution_mode(),
                path = %source.repo().display(),
                items_scanned,
                bytes_scanned,
                findings_emitted,
                "scan completed",
            );
        }
    }
}

fn log_distributed_report(cfg: &DistributedWorkerConfig, report: DistributedRunReport) {
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

fn log_worker_report(resolved: &ResolvedWorkerConfig, report: WorkerRunReport) {
    match (resolved, report) {
        (ResolvedWorkerConfig::Local(cfg), WorkerRunReport::Local(report)) => {
            log_local_report(cfg, report)
        }
        (ResolvedWorkerConfig::Distributed(cfg), WorkerRunReport::Distributed(report)) => {
            log_distributed_report(cfg, report)
        }
        (ResolvedWorkerConfig::Local(_), WorkerRunReport::Distributed(_))
        | (ResolvedWorkerConfig::Distributed(_), WorkerRunReport::Local(_)) => {
            unreachable!("worker report kind must match the resolved worker config")
        }
    }
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

    match execute_resolved_worker_with(&resolved, run_distributed_worker) {
        Ok(report) => log_worker_report(&resolved, report),
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

    use gossip_contracts::identity::{
        LogicalTime, OpId, PolicyHash, RunId, ShardId, TenantId, TenantSecretKey, WorkerId,
    };
    use gossip_coordination::{
        CursorSemantics, CursorUpdate, InMemoryCoordinator, InitialShardInput, RunConfig,
        RunManagement, ShardSpec,
    };
    use gossip_coordination_etcd::EtcdCoordinatorConfig;
    use gossip_frontier::{ShardSpecScratch, range_shard_ref};
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use gossip_scanner_runtime::{
        ScanBudgets,
        distributed::{DistributedPersistence, DistributedRuntimeError, run_worker},
    };
    use gossip_worker::config::{
        BackendSelection, DistributedWorkerRuntimeSettings, FsSourceSettings, GitSourceSettings,
    };
    use gossip_worker::production::ProductionBackendConfig;
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

    fn tenant() -> TenantId {
        TenantId::from_bytes([0x11; 32])
    }

    fn run_id() -> RunId {
        RunId::from_raw(42)
    }

    fn worker_id() -> WorkerId {
        WorkerId::from_raw(7)
    }

    fn policy_hash() -> PolicyHash {
        PolicyHash::from_bytes([0x22; 32])
    }

    fn tenant_secret_key() -> TenantSecretKey {
        TenantSecretKey::from_bytes([0x33; 32])
    }

    fn logical_time_now() -> LogicalTime {
        LogicalTime::from_raw(1)
    }

    fn test_run_config(lease_duration_ms: u64) -> RunConfig {
        RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, None)
            .expect("test run config should be valid")
    }

    fn test_distributed_config(path: &Path) -> DistributedWorkerConfig {
        DistributedWorkerConfig::new(
            BackendSelection::Production,
            ProductionBackendConfig::new(
                EtcdCoordinatorConfig::localhost(),
                "postgresql://scanner@localhost/done_ledger",
                "postgresql://scanner@localhost/findings",
            )
            .expect("test production backend config should be valid"),
            tenant(),
            run_id(),
            worker_id(),
            policy_hash(),
            tenant_secret_key(),
            FsSourceSettings::new(path.to_path_buf()),
            DistributedWorkerRuntimeSettings::new(
                ScanBudgets::default(),
                gossip_scanner_runtime::distributed::DistributedRuntimeConfig::default()
                    .commit_queue_capacity,
            ),
        )
        .expect("distributed worker config should be valid")
    }

    fn unreachable_production_config(path: &Path) -> DistributedWorkerConfig {
        DistributedWorkerConfig::new(
            BackendSelection::Production,
            ProductionBackendConfig::new(
                EtcdCoordinatorConfig::new(["http://127.0.0.1:1"], "/gossip/test")
                    .expect("syntactically valid etcd config should build"),
                "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
                "host=127.0.0.1 port=1 user=postgres password=postgres dbname=postgres connect_timeout=1",
            )
            .expect("unreachable production backend config should still be syntactically valid"),
            tenant(),
            run_id(),
            worker_id(),
            policy_hash(),
            tenant_secret_key(),
            FsSourceSettings::new(path.to_path_buf()),
            DistributedWorkerRuntimeSettings::new(
                ScanBudgets::default(),
                gossip_scanner_runtime::distributed::DistributedRuntimeConfig::default()
                    .commit_queue_capacity,
            ),
        )
        .expect("distributed worker config should be valid")
    }

    fn setup_coordinator_with_fs_shard(
        path: &Path,
        start: &[u8],
        end: &[u8],
        lease_duration_ms: u64,
    ) -> InMemoryCoordinator {
        let mut coordinator = InMemoryCoordinator::new(lease_duration_ms);
        let now = logical_time_now();
        coordinator
            .create_run(now, tenant(), run_id(), test_run_config(lease_duration_ms))
            .expect("test run creation should succeed");

        let mut scratch = ShardSpecScratch::new();
        let connector_extra = path
            .to_str()
            .expect("test paths must be valid UTF-8")
            .as_bytes();
        let spec_ref = range_shard_ref(start, end, connector_extra, &mut scratch)
            .expect("range shard spec should build");
        let spec = ShardSpec::try_from_ref(spec_ref).expect("owned shard spec should build");
        let shard_id = ShardId::from_raw(1);
        let shards = [InitialShardInput::new(
            shard_id,
            spec.as_ref(),
            CursorUpdate::initial(),
        )];
        let _ = coordinator
            .register_shards(now, tenant(), run_id(), &shards, OpId::from_raw(1))
            .expect("test shard registration should succeed");
        coordinator
    }

    fn secret_fixture() -> String {
        ["password=", "xK9mP2qL7wN4vR8t"].concat()
    }

    #[test]
    fn local_worker_scans_filesystem_path() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(gossip_worker::config::FsSourceSettings::new(
                dir.path().to_path_buf(),
            )),
            gossip_scanner_runtime::ScanBudgets::default(),
        );

        let (items_scanned, bytes_scanned, _findings_emitted) =
            run_local_worker(&cfg).expect("filesystem worker should succeed");
        assert!(items_scanned > 0);
        assert!(bytes_scanned > 0);
    }

    #[test]
    fn local_worker_scans_git_repo_path() {
        let dir = tempdir().expect("tempdir");
        create_git_repo(dir.path());
        fs::write(dir.path().join("secret.txt"), "token=aB3dE5fG7hJ9kL1m")
            .expect("write fixture");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);

        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Git(GitSourceSettings::new(dir.path().to_path_buf())),
            gossip_scanner_runtime::ScanBudgets::default(),
        );

        let (items_scanned, bytes_scanned, _findings_emitted) =
            run_local_worker(&cfg).expect("git worker should succeed");
        assert!(items_scanned > 0);
        assert!(bytes_scanned > 0);
    }

    #[test]
    fn connector_filesystem_production_dispatch_uses_real_backend_bootstrap() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved =
            ResolvedWorkerConfig::Distributed(unreachable_production_config(dir.path()));
        let error = execute_resolved_worker_with(&resolved, run_distributed_worker)
            .expect_err("unreachable production backends must fail closed");

        assert!(matches!(
            error,
            WorkerError::ProductionRuntime(ProductionWorkerError::Startup(_))
        ));
        assert!(
            !error.to_string().contains("in-memory"),
            "production dispatch must not mention or depend on in-memory backends: {error}"
        );
    }

    #[test]
    fn connector_filesystem_executes_the_distributed_worker_loop() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved = ResolvedWorkerConfig::Distributed(test_distributed_config(dir.path()));
        let findings = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let mut coordinator =
            setup_coordinator_with_fs_shard(dir.path(), b"\x00", b"\xFF", 30_000);

        let report = execute_resolved_worker_with(&resolved, |cfg| {
            run_worker(
                &mut coordinator,
                cfg.worker_identity(),
                DistributedPersistence::new(findings.clone(), done_ledger.clone()),
                cfg.runtime_config(),
            )
            .map_err(ProductionWorkerError::from)
        })
        .expect("connector filesystem mode should run the distributed worker loop");

        let WorkerRunReport::Distributed(report) = report else {
            panic!("expected distributed worker report");
        };
        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 1);
        assert!(
            !done_ledger
                .snapshot()
                .expect("done-ledger snapshot should succeed")
                .is_empty(),
            "distributed connector run should durably commit done-ledger rows"
        );
        assert!(
            !findings
                .findings_snapshot()
                .expect("findings snapshot should succeed")
                .is_empty(),
            "distributed connector run should durably commit findings"
        );
    }

    #[test]
    fn connector_filesystem_fails_when_the_run_is_missing() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved = ResolvedWorkerConfig::Distributed(test_distributed_config(dir.path()));
        let findings = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let mut coordinator = InMemoryCoordinator::new(30_000);

        let error = execute_resolved_worker_with(&resolved, |cfg| {
            run_worker(
                &mut coordinator,
                cfg.worker_identity(),
                DistributedPersistence::new(findings.clone(), done_ledger.clone()),
                cfg.runtime_config(),
            )
            .map_err(ProductionWorkerError::from)
        })
        .expect_err("missing run should fail before any distributed scan work begins");

        assert!(matches!(
            error,
            WorkerError::ProductionRuntime(ProductionWorkerError::Runtime(
                DistributedRuntimeError::Coordinator(_)
            ))
        ));
        assert!(
            error.to_string().contains("run not found"),
            "missing run failure should surface the coordinator error: {error}"
        );
        assert!(
            done_ledger
                .snapshot()
                .expect("done-ledger snapshot should succeed")
                .is_empty(),
            "missing run should fail before any durable writes occur"
        );
        assert!(
            findings
                .findings_snapshot()
                .expect("findings snapshot should succeed")
                .is_empty(),
            "missing run should fail before any findings are written"
        );
    }
}
