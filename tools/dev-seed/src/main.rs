//! Local development submission, inspect, and migrate tool for gossip-rs.
//!
//! Submits filesystem requests into coordination state, applies PostgreSQL
//! migrations, and queries persistence tables for row counts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand, ValueEnum};
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, TenantId};
use gossip_coordination::{
    CreateRunError, CursorSemantics, GetRunError, RegisterShardsError, RunConfig, RunManagement,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig};
use gossip_orchestrator::{
    FilesystemRequest, FilesystemRunSetupError, FilesystemRunSetupInput, FilesystemSourceMode,
    plan_filesystem_initial_shards, setup_filesystem_run,
};
use postgres::{Client, NoTls};

const DEFAULT_ETCD_ENDPOINTS: &str = "http://127.0.0.1:2379";
const DEFAULT_ETCD_NAMESPACE: &str = "/gossip/dev";
const DEFAULT_DONE_LEDGER_DSN: &str = "postgresql://postgres:postgres@127.0.0.1:5432/done_ledger";
const DEFAULT_FINDINGS_DSN: &str = "postgresql://postgres:postgres@127.0.0.1:5432/findings";

const DEFAULT_TENANT_ID: [u8; 32] = [0x11; 32];
const DEFAULT_RUN_ID: u64 = 42;
const DEFAULT_LEASE_DURATION_MS: u64 = 30_000;
const DEFAULT_SETUP_LOGICAL_TIME: u64 = 1;
const DEFAULT_SETUP_OP_ID: u64 = 1;

/// Clap-facing parser that preserves the orchestrator's explicit filesystem
/// request vocabulary without adding a `clap` dependency to the shared crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum FilesystemSourceModeArg {
    #[value(name = "single_file")]
    SingleFile,
    #[value(name = "directory_root")]
    DirectoryRoot,
}

impl From<FilesystemSourceModeArg> for FilesystemSourceMode {
    fn from(value: FilesystemSourceModeArg) -> Self {
        match value {
            FilesystemSourceModeArg::SingleFile => Self::SingleFile,
            FilesystemSourceModeArg::DirectoryRoot => Self::DirectoryRoot,
        }
    }
}

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(name = "dev-seed", about = "Local dev helpers for gossip-rs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, PartialEq, Eq, Subcommand)]
enum Commands {
    /// Submit a filesystem request and register its initial shard set.
    ///
    /// Uses a fixed tenant ID (`1111…1111`) that must match the worker's
    /// `GOSSIP_TENANT_ID` environment variable (set in the Justfile).
    /// The setup op-id is also fixed, so re-seeding the same `--run-id`
    /// with a different path triggers an `OpIdConflict` — run `just reset`
    /// first to clear coordination state.
    Seed {
        /// Filesystem request mode (`single_file` or `directory_root`).
        source_mode: FilesystemSourceModeArg,

        /// File or directory to scan.
        path: PathBuf,

        #[arg(long, default_value = DEFAULT_ETCD_ENDPOINTS)]
        etcd_endpoints: String,

        #[arg(long, default_value = DEFAULT_ETCD_NAMESPACE)]
        etcd_namespace: String,

        #[arg(long, default_value_t = DEFAULT_RUN_ID)]
        run_id: u64,

        #[arg(long, default_value_t = DEFAULT_LEASE_DURATION_MS)]
        lease_duration_ms: u64,
    },
    /// Show row counts from the findings and done-ledger databases.
    Inspect {
        #[arg(long, default_value = DEFAULT_DONE_LEDGER_DSN)]
        done_ledger_dsn: String,

        #[arg(long, default_value = DEFAULT_FINDINGS_DSN)]
        findings_dsn: String,
    },
    /// Apply embedded PostgreSQL migrations to both databases.
    Migrate {
        #[arg(long, default_value = DEFAULT_DONE_LEDGER_DSN)]
        done_ledger_dsn: String,

        #[arg(long, default_value = DEFAULT_FINDINGS_DSN)]
        findings_dsn: String,
    },
}

fn main() {
    let cli = Cli::parse();
    if let Err(err) = run(cli) {
        eprintln!("error: {err:#}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Seed {
            source_mode,
            path,
            etcd_endpoints,
            etcd_namespace,
            run_id,
            lease_duration_ms,
        } => cmd_seed(
            source_mode,
            &path,
            &etcd_endpoints,
            &etcd_namespace,
            run_id,
            lease_duration_ms,
        ),
        Commands::Inspect {
            done_ledger_dsn,
            findings_dsn,
        } => cmd_inspect(&done_ledger_dsn, &findings_dsn),
        Commands::Migrate {
            done_ledger_dsn,
            findings_dsn,
        } => cmd_migrate(&done_ledger_dsn, &findings_dsn),
    }
}

/// Coordinator-authoritative summary that the CLI prints after a filesystem
/// submission succeeds or replays.
#[derive(Debug, PartialEq, Eq)]
struct FilesystemSubmissionResult {
    source_mode: FilesystemSourceMode,
    canonical_target: PathBuf,
    run_id: RunId,
    root_shards: Vec<ShardId>,
    replayed: bool,
}

fn cmd_seed(
    source_mode: FilesystemSourceModeArg,
    path: &Path,
    etcd_endpoints: &str,
    etcd_namespace: &str,
    run_id_raw: u64,
    lease_duration_ms: u64,
) -> Result<()> {
    let config = EtcdCoordinatorConfig::from_endpoints_csv(etcd_endpoints, etcd_namespace)
        .context("invalid etcd config")?;
    let mut coordinator = EtcdCoordinator::connect(config).context("failed to connect to etcd")?;

    let submission = submit_filesystem_request(
        &mut coordinator,
        source_mode.into(),
        path,
        run_id_raw,
        lease_duration_ms,
    )?;
    print_submission_result(&submission);
    Ok(())
}

/// Lower one filesystem request through normalization, shard planning, payload
/// construction, and coordination-backed run setup.
fn submit_filesystem_request<M>(
    management: &mut M,
    source_mode: FilesystemSourceMode,
    path: &Path,
    run_id_raw: u64,
    lease_duration_ms: u64,
) -> Result<FilesystemSubmissionResult>
where
    M: RunManagement,
{
    let run_config = RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, Some(5))
        .context("invalid filesystem submission config")?;
    let request = match source_mode {
        FilesystemSourceMode::SingleFile => FilesystemRequest::single_file(path, run_config),
        FilesystemSourceMode::DirectoryRoot => FilesystemRequest::directory_root(path, run_config),
    };
    let normalized = request.normalize().map_err(|error| {
        anyhow::Error::new(error).context("invalid filesystem submission request")
    })?;
    let plan = plan_filesystem_initial_shards(normalized);
    let payload = plan.shard_payload();
    let run_id = RunId::from_raw(run_id_raw);
    let canonical_target = plan.request().canonical_root().to_path_buf();
    let outcome = setup_filesystem_run(
        management,
        LogicalTime::from_raw(DEFAULT_SETUP_LOGICAL_TIME),
        TenantId::from_bytes(DEFAULT_TENANT_ID),
        run_id,
        FilesystemRunSetupInput::new(plan.request(), plan.initial_shard().clone(), &payload),
        OpId::from_raw(DEFAULT_SETUP_OP_ID),
    )
    .map_err(|error| classify_submission_error(run_id_raw, error))?;
    let replayed = outcome.is_replay();
    let setup = outcome.into_inner();
    Ok(FilesystemSubmissionResult {
        source_mode: plan.request().mode(),
        canonical_target,
        run_id,
        root_shards: setup.root_shards().to_vec(),
        replayed,
    })
}

/// Collapse setup failures into operator-facing categories while preserving
/// the original coordination error in the chain.
///
/// The top-level match is exhaustive over [`FilesystemRunSetupError`] variants
/// so that adding a new variant forces this mapping to be revisited.  The
/// inner `CreateRun` match still requires a catch-all because
/// [`CreateRunError`] is `#[non_exhaustive]`.
fn classify_submission_error(run_id_raw: u64, error: FilesystemRunSetupError) -> anyhow::Error {
    match error {
        // ── pre-coordinator validation failures ──────────────────────
        error @ FilesystemRunSetupError::PayloadModeMismatch { .. }
        | error @ FilesystemRunSetupError::PayloadRootMismatch { .. } => {
            anyhow::Error::new(error)
                .context("filesystem submission produced an inconsistent request/payload pair")
        }
        error @ FilesystemRunSetupError::PayloadEncode(_)
        | error @ FilesystemRunSetupError::ManifestBuild(_) => anyhow::Error::new(error)
            .context("filesystem submission manifest construction failed"),

        // ── coordinator-level failures ───────────────────────────────
        error @ FilesystemRunSetupError::CreateRun(CreateRunError::ConfigMismatch { .. }) => {
            anyhow::Error::new(error).context(format!(
                "filesystem submission run {run_id_raw} already exists with a different run configuration"
            ))
        }
        error @ FilesystemRunSetupError::CreateRun(CreateRunError::RegisterShardsFailed(
            RegisterShardsError::OpIdConflict(_),
        )) => anyhow::Error::new(error).context(format!(
            "filesystem submission run {run_id_raw} already exists with a different shard registration payload"
        )),
        error @ FilesystemRunSetupError::CreateRun(CreateRunError::BackendError(_))
        | error @ FilesystemRunSetupError::CreateRun(CreateRunError::RegisterShardsFailed(
            RegisterShardsError::BackendError(_),
        ))
        | error @ FilesystemRunSetupError::CreateRun(CreateRunError::GetRunFailed(
            GetRunError::BackendError(_),
        )) => anyhow::Error::new(error)
            .context("coordination backend error during filesystem submission"),
        // CreateRunError is #[non_exhaustive], so a catch-all is needed
        // for variants that create_run_with_shards does not propagate in
        // the current implementation (e.g. RunAlreadyExists, InvalidConfig).
        error @ FilesystemRunSetupError::CreateRun(_) => {
            anyhow::Error::new(error).context("filesystem submission failed")
        }
    }
}

/// Emit a compact summary that callers can feed into follow-on worker runs.
fn print_submission_result(submission: &FilesystemSubmissionResult) {
    let outcome = if submission.replayed {
        "replayed"
    } else {
        "executed"
    };
    println!("outcome={outcome}");
    println!("run_id={}", submission.run_id.as_raw());
    println!("source_mode={}", submission.source_mode);
    println!("canonical_target={}", submission.canonical_target.display());
    println!(
        "root_shards={}",
        submission
            .root_shards
            .iter()
            .map(|shard| shard.as_raw().to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
}

fn cmd_inspect(done_ledger_dsn: &str, findings_dsn: &str) -> Result<()> {
    let tables: &[(&str, &str, &str)] = &[
        (
            "done_ledger_entries:",
            done_ledger_dsn,
            gossip_done_ledger_postgres::schema::DONE_LEDGER_ENTRIES_TABLE,
        ),
        (
            "findings:",
            findings_dsn,
            gossip_findings_postgres::schema::FINDINGS_TABLE,
        ),
        (
            "occurrences:",
            findings_dsn,
            gossip_findings_postgres::schema::OCCURRENCES_TABLE,
        ),
        (
            "observations:",
            findings_dsn,
            gossip_findings_postgres::schema::OBSERVATIONS_TABLE,
        ),
    ];

    let mut had_error = false;
    for &(label, dsn, table) in tables {
        let count = match table_count(dsn, table) {
            Ok(n) => n.to_string(),
            Err(msg) => {
                had_error = true;
                format!("({msg})")
            }
        };
        println!("{label:<24} {count}");
    }
    if had_error {
        bail!("one or more table queries failed — is postgres running? try `just up`");
    }
    Ok(())
}

fn table_count(dsn: &str, table: &str) -> Result<i64, String> {
    use postgres::error::SqlState;

    debug_assert!(
        !table.is_empty() && table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "table_count requires a plain SQL identifier, got: {table:?}"
    );
    let mut client =
        Client::connect(dsn, NoTls).map_err(|e| format!("cannot connect to database: {e}"))?;
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .map(|row| row.get::<_, i64>(0))
        .map_err(|e| {
            if let Some(db_err) = e.as_db_error()
                && *db_err.code() == SqlState::UNDEFINED_TABLE
            {
                return "table not found — run `just migrate` first".to_string();
            }
            e.to_string()
        })
}

fn cmd_migrate(done_ledger_dsn: &str, findings_dsn: &str) -> Result<()> {
    let dl_dsn = done_ledger_dsn.to_owned();
    let f_dsn = findings_dsn.to_owned();

    std::thread::scope(|s| -> Result<()> {
        let dl_handle = s.spawn(|| {
            let mut client =
                Client::connect(&dl_dsn, NoTls).context("done-ledger DB connection failed")?;
            gossip_done_ledger_postgres::apply_all_migrations(&mut client)
                .context("done-ledger migrations failed")?;
            Ok::<_, anyhow::Error>(())
        });
        let f_handle = s.spawn(|| {
            let mut client =
                Client::connect(&f_dsn, NoTls).context("findings DB connection failed")?;
            gossip_findings_postgres::apply_all_migrations(&mut client)
                .context("findings migrations failed")?;
            Ok::<_, anyhow::Error>(())
        });

        // Collect both results before propagating so neither error is lost.
        let dl_result = dl_handle
            .join()
            .map_err(|_| anyhow::anyhow!("done-ledger migration thread panicked"))?;
        let f_result = f_handle
            .join()
            .map_err(|_| anyhow::anyhow!("findings migration thread panicked"))?;

        match (dl_result, f_result) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(e), Ok(())) => Err(e),
            (Ok(()), Err(e)) => Err(e),
            (Err(dl_e), Err(f_e)) => {
                Err(dl_e.context(format!("findings migration also failed: {f_e:#}")))
            }
        }
    })?;

    println!("migrations applied to both databases");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use clap::Parser;
    use gossip_contracts::identity::OpId;
    use gossip_coordination::{InMemoryCoordinator, RunOpIdConflict, RunStatus};
    use gossip_orchestrator::FilesystemRunSetupError;
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn seed_cli_parses_explicit_filesystem_mode() {
        let cli = Cli::try_parse_from([
            "dev-seed",
            "seed",
            "single_file",
            "/tmp/scan-target.txt",
            "--run-id",
            "77",
        ])
        .expect("seed command should parse");

        assert_eq!(
            cli.command,
            Commands::Seed {
                source_mode: FilesystemSourceModeArg::SingleFile,
                path: PathBuf::from("/tmp/scan-target.txt"),
                etcd_endpoints: DEFAULT_ETCD_ENDPOINTS.to_string(),
                etcd_namespace: DEFAULT_ETCD_NAMESPACE.to_string(),
                run_id: 77,
                lease_duration_ms: DEFAULT_LEASE_DURATION_MS,
            }
        );
    }

    #[test]
    fn submit_filesystem_request_registers_directory_root_shard() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("scan-root");
        fs::create_dir(&root).expect("create root");
        fs::write(root.join("alpha.txt"), "fixture").expect("write fixture");
        let canonical_target = root.canonicalize().expect("canonical target");

        let mut coordinator = InMemoryCoordinator::new(DEFAULT_LEASE_DURATION_MS);
        let submission = submit_filesystem_request(
            &mut coordinator,
            FilesystemSourceMode::DirectoryRoot,
            &root,
            DEFAULT_RUN_ID,
            DEFAULT_LEASE_DURATION_MS,
        )
        .expect("submission should succeed");

        assert_eq!(submission.source_mode, FilesystemSourceMode::DirectoryRoot);
        assert_eq!(submission.canonical_target, canonical_target);
        assert_eq!(submission.run_id, RunId::from_raw(DEFAULT_RUN_ID));
        assert_eq!(submission.root_shards.len(), 1);
        assert!(!submission.replayed);

        let run = coordinator
            .get_run(
                TenantId::from_bytes(DEFAULT_TENANT_ID),
                RunId::from_raw(DEFAULT_RUN_ID),
            )
            .expect("run should exist");
        assert_eq!(run.status(), RunStatus::Active);
        assert_eq!(run.root_shards(), submission.root_shards.as_slice());
    }

    #[test]
    fn submit_filesystem_request_replays_matching_request() {
        let dir = tempdir().expect("tempdir");
        let root = dir.path().join("scan-root");
        fs::create_dir(&root).expect("create root");

        let mut coordinator = InMemoryCoordinator::new(DEFAULT_LEASE_DURATION_MS);
        let first = submit_filesystem_request(
            &mut coordinator,
            FilesystemSourceMode::DirectoryRoot,
            &root,
            DEFAULT_RUN_ID,
            DEFAULT_LEASE_DURATION_MS,
        )
        .expect("initial submission should succeed");
        let replay = submit_filesystem_request(
            &mut coordinator,
            FilesystemSourceMode::DirectoryRoot,
            &root,
            DEFAULT_RUN_ID,
            DEFAULT_LEASE_DURATION_MS,
        )
        .expect("replayed submission should succeed");

        assert!(!first.replayed);
        assert!(replay.replayed);
        assert_eq!(replay.root_shards, first.root_shards);
        assert_eq!(replay.canonical_target, first.canonical_target);
    }

    #[test]
    fn submit_filesystem_request_registers_single_file_shard() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");
        let canonical_target = file_path.canonicalize().expect("canonical target");

        let mut coordinator = InMemoryCoordinator::new(DEFAULT_LEASE_DURATION_MS);
        let submission = submit_filesystem_request(
            &mut coordinator,
            FilesystemSourceMode::SingleFile,
            &file_path,
            DEFAULT_RUN_ID,
            DEFAULT_LEASE_DURATION_MS,
        )
        .expect("submission should succeed");

        assert_eq!(submission.source_mode, FilesystemSourceMode::SingleFile);
        assert_eq!(submission.canonical_target, canonical_target);
        assert_eq!(submission.run_id, RunId::from_raw(DEFAULT_RUN_ID));
        assert_eq!(submission.root_shards.len(), 1);
        assert!(!submission.replayed);

        let run = coordinator
            .get_run(
                TenantId::from_bytes(DEFAULT_TENANT_ID),
                RunId::from_raw(DEFAULT_RUN_ID),
            )
            .expect("run should exist");
        assert_eq!(run.status(), RunStatus::Active);
        assert_eq!(run.root_shards(), submission.root_shards.as_slice());
    }

    #[test]
    fn submit_filesystem_request_rejects_mode_path_mismatch() {
        let dir = tempdir().expect("tempdir");
        let file_path = dir.path().join("scan-target.txt");
        fs::write(&file_path, "fixture").expect("write fixture");

        let mut coordinator = InMemoryCoordinator::new(DEFAULT_LEASE_DURATION_MS);
        let error = submit_filesystem_request(
            &mut coordinator,
            FilesystemSourceMode::DirectoryRoot,
            &file_path,
            DEFAULT_RUN_ID,
            DEFAULT_LEASE_DURATION_MS,
        )
        .expect_err("directory-root submission should reject regular files");

        let message = format!("{error:#}");
        assert!(message.contains("invalid filesystem submission request"));
        assert!(message.contains("requires a directory"));
    }

    #[test]
    fn classify_config_mismatch_preserves_error_chain() {
        let error = FilesystemRunSetupError::CreateRun(CreateRunError::ConfigMismatch {
            run: RunId::from_raw(99),
        });
        let classified = classify_submission_error(99, error);
        let msg = format!("{classified:#}");
        assert!(msg.contains("different run configuration"));
    }

    #[test]
    fn classify_opid_conflict_preserves_error_chain() {
        let error = FilesystemRunSetupError::CreateRun(CreateRunError::RegisterShardsFailed(
            RegisterShardsError::OpIdConflict(RunOpIdConflict {
                op_id: OpId::from_raw(1),
                expected_hash: 0xDEAD,
                actual_hash: 0xBEEF,
            }),
        ));
        let classified = classify_submission_error(42, error);
        let msg = format!("{classified:#}");
        assert!(msg.contains("different shard registration payload"));
    }
}
