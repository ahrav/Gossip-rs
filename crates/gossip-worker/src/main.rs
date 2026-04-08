//! Unified `gossip-worker` binary entrypoint.
//!
//! The worker resolves a typed configuration surface from environment
//! variables plus CLI overrides. Depending on that resolved config it either:
//!
//! - runs a local direct filesystem or git scan, or
//! - launches the real distributed worker path against etcd and PostgreSQL.
//!
//! Connector-mode scans (filesystem and Git) route through the distributed
//! worker loop. They do not silently downgrade to the local scan path.

use gossip_contracts::connector::ToxicDigest;
use gossip_scanner_runtime::{
    ScanReport, ScanRuntimeError, distributed::DistributedRunReport, scan_fs, scan_git,
};
use gossip_worker::config::{
    DistributedSourceSettings, DistributedWorkerConfig, LocalWorkerConfig, ResolvedWorkerConfig,
    WorkerSourceSettings, resolve_worker_config_from_env_and_args,
};
use gossip_worker::production::{ProductionWorkerError, run_production_worker};
use tracing_subscriber::EnvFilter;

/// Worker-level error distinguishing configuration errors from runtime
/// failures.
#[derive(Debug, thiserror::Error)]
enum WorkerError {
    #[error("{0}")]
    Config(#[source] gossip_worker::config::WorkerConfigError),
    #[error("scan failed: {0}")]
    LocalRuntime(#[source] ScanRuntimeError),
    #[error("scan failed: {0}")]
    ProductionRuntime(#[source] ProductionWorkerError),
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
    Local(ScanReport),
    Distributed(DistributedRunReport),
}

/// Initialize the global tracing subscriber.
///
/// Reads `RUST_LOG` if present and falls back to `info` when absent. When
/// `RUST_LOG` contains invalid directives, a warning is printed to stderr
/// (the tracing subscriber is not yet available at that point) and the
/// filter falls back to lossy parsing so the process still starts.
fn init_tracing() {
    let filter = match EnvFilter::builder()
        .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
        .from_env()
    {
        Ok(f) => f,
        Err(err) => {
            eprintln!("WARNING: malformed RUST_LOG directive ({err}); falling back to default");
            EnvFilter::builder()
                .with_default_directive(tracing_subscriber::filter::LevelFilter::INFO.into())
                .from_env_lossy()
        }
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter)
        .with_target(false)
        .compact()
        .init();
}

/// Execute one local scan using the resolved local worker config.
fn run_local_worker(cfg: &LocalWorkerConfig) -> Result<ScanReport, WorkerError> {
    let report = match cfg.source() {
        WorkerSourceSettings::Fs(source) => {
            scan_fs(&source.to_scan_config(cfg.execution_mode(), cfg.budgets()))?
        }
        WorkerSourceSettings::Git(source) => {
            scan_git(&source.to_scan_config(cfg.execution_mode(), cfg.budgets()))?
        }
    };
    Ok(report)
}

/// Execute one real distributed worker launch against the production backends.
fn run_distributed_worker(
    cfg: &DistributedWorkerConfig,
) -> Result<DistributedRunReport, ProductionWorkerError> {
    run_production_worker(
        cfg.production_backends(),
        cfg.startup(),
        cfg.worker_launch(),
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

fn log_local_report(cfg: &LocalWorkerConfig, report: ScanReport) {
    let (source_label, path) = match cfg.source() {
        WorkerSourceSettings::Fs(s) => ("fs", s.path().display().to_string()),
        WorkerSourceSettings::Git(s) => ("git", s.repo().display().to_string()),
    };
    tracing::info!(
        backend = "local",
        source = source_label,
        mode = ?cfg.execution_mode(),
        %path,
        items_scanned = report.items_scanned,
        bytes_scanned = report.bytes_scanned,
        findings_emitted = report.findings_emitted,
        "scan completed",
    );
}

fn log_distributed_report(cfg: &DistributedWorkerConfig, report: DistributedRunReport) {
    match cfg.source() {
        DistributedSourceSettings::Fs(source) => tracing::info!(
            backend = "production",
            source = "fs",
            mode = ?gossip_scanner_runtime::ExecutionMode::Connector,
            tenant = %cfg.tenant(),
            run = %cfg.run(),
            worker = %cfg.worker(),
            path = %source.path().display(),
            leases_seen = report.leases_seen,
            shards_scanned = report.shards_scanned,
            total_claim_ms = report.total_claim_ms,
            "distributed scan completed",
        ),
        DistributedSourceSettings::Git(source) => tracing::info!(
            backend = "production",
            source = "git",
            mode = ?gossip_scanner_runtime::ExecutionMode::Connector,
            tenant = %cfg.tenant(),
            run = %cfg.run(),
            worker = %cfg.worker(),
            mirror_root = %ToxicDigest::of_bytes(source.mirror_root().as_os_str().as_encoded_bytes()),
            leases_seen = report.leases_seen,
            shards_scanned = report.shards_scanned,
            total_claim_ms = report.total_claim_ms,
            total_mirror_sync_ms = report.total_mirror_sync_ms,
            total_scan_ms = report.total_scan_ms,
            total_durable_receipt_ms = report.total_durable_receipt_ms,
            total_checkpoint_ms = report.total_checkpoint_ms,
            "distributed scan completed",
        ),
    }
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

    use gossip_contracts::identity::{
        LogicalTime, OpId, PolicyHash, RunId, ShardId, TenantId, TenantSecretKey, WorkerId,
    };
    use gossip_coordination::{
        CursorSemantics, CursorUpdate, InMemoryCoordinator, InitialShardInput, RunConfig,
        RunManagement, ShardSpec,
    };
    use gossip_coordination_etcd::EtcdCoordinatorConfig;
    use gossip_frontier::{ShardSpecScratch, range_shard_ref};
    use gossip_orchestrator::{FilesystemShardPayload, FilesystemSourceMode};
    use gossip_persistence_inmemory::{InMemoryDoneLedger, InMemoryFindingsSink};
    use gossip_scanner_runtime::{
        ScanBudgets,
        distributed::{
            DistributedPersistence, DistributedRuntimeError, run_worker, secret_fixture,
        },
    };
    use gossip_stdx::git_test_support::{init_git_repo, run_git};
    use gossip_worker::config::{
        DistributedSourceSettings, DistributedWorkerLaunch, DistributedWorkerRuntimeSettings,
        FsSourceSettings, GitDistributedSourceSettings, GitSourceSettings, ProductionBackendConfig,
        WorkerIdentityConfig,
    };
    use gossip_worker::production::ProductionStartupSettings;
    use tempfile::tempdir;
    use tracing::Level;

    use gossip_worker::recorder::test_support::capture_logs;

    fn create_git_repo(path: &Path) {
        init_git_repo(path, "worker-tests@example.com", "Worker Tests");
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

    fn make_distributed_config(
        source: DistributedSourceSettings,
        backends: ProductionBackendConfig,
    ) -> DistributedWorkerConfig {
        let defaults = gossip_scanner_runtime::distributed::DistributedRuntimeConfig::default();
        let identity = WorkerIdentityConfig::new(
            tenant(),
            run_id(),
            worker_id(),
            policy_hash(),
            tenant_secret_key(),
        )
        .expect("test worker identity config should be valid");
        DistributedWorkerConfig::new(
            backends,
            ProductionStartupSettings::validate_only(),
            identity,
            source,
            DistributedWorkerRuntimeSettings::new(
                ScanBudgets::default(),
                defaults.commit_queue_capacity,
            ),
        )
        .expect("distributed worker config should be valid")
    }

    fn test_distributed_config(path: &Path) -> DistributedWorkerConfig {
        let backends = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "postgresql://scanner@localhost/done_ledger",
            "postgresql://scanner@localhost/findings",
        )
        .expect("test production backend config should be valid");
        make_distributed_config(
            DistributedSourceSettings::Fs(FsSourceSettings::new(path.to_path_buf())),
            backends,
        )
    }

    fn test_git_distributed_config(path: &Path, mirror_root: &Path) -> DistributedWorkerConfig {
        let backends = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "postgresql://scanner@localhost/done_ledger",
            "postgresql://scanner@localhost/findings",
        )
        .expect("test production backend config should be valid");
        make_distributed_config(
            DistributedSourceSettings::Git(GitDistributedSourceSettings::new(
                GitSourceSettings::new(path.to_path_buf()),
                mirror_root.to_path_buf(),
            )),
            backends,
        )
    }

    #[test]
    fn log_distributed_report_redacts_git_mirror_root_and_includes_stage_totals() {
        let repo = tempdir().expect("repo tempdir");
        let mirror_root = tempdir().expect("mirror root tempdir");
        let cfg = test_git_distributed_config(repo.path(), mirror_root.path());
        let report = DistributedRunReport {
            leases_seen: 2,
            shards_scanned: 2,
            total_claim_ms: 3,
            total_mirror_sync_ms: 5,
            total_scan_ms: 7,
            total_durable_receipt_ms: 11,
            total_checkpoint_ms: 13,
        };

        let logs = capture_logs(Level::INFO, || log_distributed_report(&cfg, report));

        assert!(
            logs.contains("source=\"git\""),
            "expected git source label: {logs}"
        );
        assert!(
            logs.contains("mirror_root=len="),
            "mirror_root should be emitted as a digest: {logs}",
        );
        assert!(
            !logs.contains(&mirror_root.path().display().to_string()),
            "raw mirror_root path must not leak into logs: {logs}",
        );
        for field in [
            "total_claim_ms=3",
            "total_mirror_sync_ms=5",
            "total_scan_ms=7",
            "total_durable_receipt_ms=11",
            "total_checkpoint_ms=13",
        ] {
            assert!(logs.contains(field), "missing {field} from logs: {logs}");
        }
    }

    fn unreachable_production_config(path: &Path) -> DistributedWorkerConfig {
        let backends = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::new(["http://127.0.0.1:1"], "/gossip/v1")
                .expect("test etcd config should be valid"),
            "postgresql://scanner@127.0.0.1:1/done_ledger?connect_timeout=1",
            "postgresql://scanner@127.0.0.1:1/findings?connect_timeout=1",
        )
        .expect("unreachable production backend config should be valid");
        make_distributed_config(
            DistributedSourceSettings::Fs(FsSourceSettings::new(path.to_path_buf())),
            backends,
        )
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
        let connector_extra = FilesystemShardPayload::new(
            FilesystemSourceMode::DirectoryRoot,
            path.canonicalize().expect("test path must canonicalize"),
        )
        .encode()
        .expect("test payload should encode");
        let spec_ref = range_shard_ref(start, end, &connector_extra, &mut scratch)
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

    #[test]
    fn local_worker_scans_filesystem_path() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(dir.path().to_path_buf())),
            gossip_scanner_runtime::ScanBudgets::default(),
        )
        .expect("default budgets should be valid");

        let report = run_local_worker(&cfg).expect("filesystem worker should succeed");
        assert!(report.items_scanned > 0);
        assert!(report.bytes_scanned > 0);
    }

    #[test]
    fn local_dispatch_through_execute_resolved_worker() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Fs(FsSourceSettings::new(dir.path().to_path_buf())),
            gossip_scanner_runtime::ScanBudgets::default(),
        )
        .expect("default budgets should be valid");
        let resolved = ResolvedWorkerConfig::Local(cfg);

        let report = execute_resolved_worker_with(&resolved, |_| {
            panic!("local configs must not invoke the distributed runner")
        })
        .expect("local dispatch should succeed");
        let WorkerRunReport::Local(scan) = report else {
            panic!("expected local worker report, got distributed");
        };
        assert!(scan.items_scanned > 0);
        assert!(scan.bytes_scanned > 0);
    }

    #[test]
    fn local_worker_scans_git_repo_path() {
        let dir = tempdir().expect("tempdir");
        create_git_repo(dir.path());
        fs::write(dir.path().join("sample.txt"), "fixture-git-worker-content")
            .expect("write fixture");
        run_git(dir.path(), &["add", "."]);
        run_git(dir.path(), &["commit", "-q", "-m", "fixture"]);

        let cfg = LocalWorkerConfig::new(
            WorkerSourceSettings::Git(GitSourceSettings::new(dir.path().to_path_buf())),
            gossip_scanner_runtime::ScanBudgets::default(),
        )
        .expect("default budgets should be valid");

        let report = run_local_worker(&cfg).expect("git worker should succeed");
        assert!(report.items_scanned > 0);
        assert!(report.bytes_scanned > 0);
    }

    #[test]
    fn connector_filesystem_executes_the_distributed_worker_loop() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved =
            ResolvedWorkerConfig::Distributed(Box::new(test_distributed_config(dir.path())));
        let findings = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let mut coordinator = setup_coordinator_with_fs_shard(dir.path(), b"\x00", b"\xFF", 30_000);
        let mut distributed_runner_called = false;

        let report = execute_resolved_worker_with(&resolved, |cfg| {
            distributed_runner_called = true;
            let DistributedWorkerLaunch::Fs(identity) = cfg.worker_launch() else {
                panic!("expected Fs launch variant");
            };
            run_worker(
                &mut coordinator,
                identity,
                DistributedPersistence::new(findings.clone(), done_ledger.clone()),
                cfg.runtime_config(),
            )
            .map_err(ProductionWorkerError::from)
        })
        .expect("connector filesystem mode should run the distributed worker loop");

        assert!(
            distributed_runner_called,
            "distributed worker configs must invoke the injected distributed runner"
        );
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

    /// Validates that Git-mode configs dispatch through the distributed runner
    /// and surface the `Git` launch variant with correct identity and mirror
    /// root. Does not exercise end-to-end scan behavior.
    #[test]
    fn connector_git_dispatches_through_execute_resolved_worker() {
        let repo = tempdir().expect("tempdir");
        create_git_repo(repo.path());
        let mirror_root = tempdir().expect("tempdir");

        let resolved = ResolvedWorkerConfig::Distributed(Box::new(test_git_distributed_config(
            repo.path(),
            mirror_root.path(),
        )));
        let mut distributed_runner_called = false;

        let report = execute_resolved_worker_with(&resolved, |cfg| {
            distributed_runner_called = true;
            let DistributedWorkerLaunch::Git {
                identity,
                mirror_root: launch_mirror_root,
            } = cfg.worker_launch()
            else {
                panic!("expected Git launch variant");
            };
            assert_eq!(identity.tenant, cfg.tenant());
            assert_eq!(identity.run, cfg.run());
            assert_eq!(identity.worker, cfg.worker());
            assert_eq!(identity.policy_hash, cfg.policy_hash());
            assert_eq!(identity.tenant_secret_key, cfg.tenant_secret_key());
            assert_eq!(launch_mirror_root, mirror_root.path());
            Ok(DistributedRunReport::default())
        })
        .expect("connector git mode should invoke the distributed runner");

        assert!(
            distributed_runner_called,
            "distributed worker configs must invoke the injected distributed runner"
        );
        let WorkerRunReport::Distributed(report) = report else {
            panic!("expected distributed worker report");
        };
        assert_eq!(report, DistributedRunReport::default());
    }

    #[test]
    fn connector_filesystem_fails_when_the_run_is_missing() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved =
            ResolvedWorkerConfig::Distributed(Box::new(test_distributed_config(dir.path())));
        let findings = InMemoryFindingsSink::new();
        let done_ledger = InMemoryDoneLedger::new();
        let mut coordinator = InMemoryCoordinator::new(30_000);
        let mut distributed_runner_called = false;

        let error = execute_resolved_worker_with(&resolved, |cfg| {
            distributed_runner_called = true;
            let DistributedWorkerLaunch::Fs(identity) = cfg.worker_launch() else {
                panic!("expected Fs launch variant");
            };
            run_worker(
                &mut coordinator,
                identity,
                DistributedPersistence::new(findings.clone(), done_ledger.clone()),
                cfg.runtime_config(),
            )
            .map_err(ProductionWorkerError::from)
        })
        .expect_err("missing run should fail before any distributed scan work begins");

        assert!(
            distributed_runner_called,
            "distributed worker configs must invoke the injected distributed runner"
        );
        assert!(matches!(
            error,
            WorkerError::ProductionRuntime(ProductionWorkerError::Runtime(
                DistributedRuntimeError::Coordinator(_)
            ))
        ));
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

    #[test]
    fn connector_filesystem_production_dispatch_uses_real_backend_bootstrap() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

        let resolved =
            ResolvedWorkerConfig::Distributed(Box::new(unreachable_production_config(dir.path())));
        let error = execute_resolved_worker_with(&resolved, run_distributed_worker)
            .expect_err("unreachable production backends must fail during startup");

        assert!(matches!(
            error,
            WorkerError::ProductionRuntime(ProductionWorkerError::Startup(_))
        ));
        assert!(
            !error.to_string().to_ascii_lowercase().contains("in-memory"),
            "production bootstrap failure must not mention in-memory fallbacks: {error}"
        );
    }

    #[test]
    fn git_distributed_dispatch_produces_git_launch_variant() {
        let mirror_dir = tempdir().expect("tempdir for mirror root");
        let defaults = gossip_scanner_runtime::distributed::DistributedRuntimeConfig::default();
        let identity = WorkerIdentityConfig::new(
            tenant(),
            run_id(),
            worker_id(),
            policy_hash(),
            tenant_secret_key(),
        )
        .expect("test worker identity config should be valid");
        let backends = ProductionBackendConfig::new(
            EtcdCoordinatorConfig::localhost(),
            "postgresql://scanner@localhost/done_ledger",
            "postgresql://scanner@localhost/findings",
        )
        .expect("test production backend config should be valid");
        let cfg = DistributedWorkerConfig::new(
            backends,
            ProductionStartupSettings::validate_only(),
            identity,
            DistributedSourceSettings::Git(GitDistributedSourceSettings::new(
                GitSourceSettings::new("/tmp/repo"),
                mirror_dir.path(),
            )),
            DistributedWorkerRuntimeSettings::new(
                ScanBudgets::default(),
                defaults.commit_queue_capacity,
            ),
        )
        .expect("git distributed worker config should be valid");
        let resolved = ResolvedWorkerConfig::Distributed(Box::new(cfg));

        let mut received_git_variant = false;
        let _ = execute_resolved_worker_with(&resolved, |cfg| {
            let launch = cfg.worker_launch();
            let DistributedWorkerLaunch::Git { mirror_root, .. } = &launch else {
                panic!("expected Git launch variant, got {launch:?}");
            };
            assert_eq!(mirror_root, mirror_dir.path());
            received_git_variant = true;
            Err(ProductionWorkerError::from(
                DistributedRuntimeError::Coordinator(anyhow::anyhow!("stub error for test")),
            ))
        });

        assert!(
            received_git_variant,
            "Git distributed config must dispatch through the distributed runner with a Git launch variant"
        );
    }
}
