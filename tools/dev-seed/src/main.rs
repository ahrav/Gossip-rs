//! Local development seed, inspect, and migrate tool for gossip-rs.
//!
//! Seeds coordination state (runs + shards) into etcd, applies PostgreSQL
//! migrations, and queries persistence tables for row counts.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, TenantId};
use gossip_coordination::{
    CursorSemantics, CursorUpdate, InitialShardInput, RegisterShardsError, RunConfig, RunManagement,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig};
use gossip_frontier::{ShardSpecScratch, range_shard_ref};
use postgres::{Client, NoTls};

const DEFAULT_ETCD_ENDPOINTS: &str = "http://127.0.0.1:2379";
const DEFAULT_ETCD_NAMESPACE: &str = "/gossip/dev";
const DEFAULT_DONE_LEDGER_DSN: &str = "postgresql://postgres:postgres@127.0.0.1:5432/done_ledger";
const DEFAULT_FINDINGS_DSN: &str = "postgresql://postgres:postgres@127.0.0.1:5432/findings";

const DEFAULT_TENANT_ID: [u8; 32] = [0x11; 32];
const DEFAULT_RUN_ID: u64 = 42;
const DEFAULT_SHARD_ID: u64 = 1;
const DEFAULT_LEASE_DURATION_MS: u64 = 30_000;

#[derive(Parser)]
#[command(name = "dev-seed", about = "Local dev helpers for gossip-rs")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Create a run with one full-range shard pointing at PATH.
    Seed {
        /// Directory to scan.
        path: PathBuf,

        #[arg(long, default_value = DEFAULT_ETCD_ENDPOINTS)]
        etcd_endpoints: String,

        #[arg(long, default_value = DEFAULT_ETCD_NAMESPACE)]
        etcd_namespace: String,

        #[arg(long, default_value_t = DEFAULT_RUN_ID)]
        run_id: u64,

        #[arg(long, default_value_t = DEFAULT_SHARD_ID)]
        shard_id: u64,

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
            path,
            etcd_endpoints,
            etcd_namespace,
            run_id,
            shard_id,
            lease_duration_ms,
        } => cmd_seed(
            &path,
            &etcd_endpoints,
            &etcd_namespace,
            run_id,
            shard_id,
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

fn cmd_seed(
    path: &Path,
    etcd_endpoints: &str,
    etcd_namespace: &str,
    run_id_raw: u64,
    shard_id_raw: u64,
    lease_duration_ms: u64,
) -> Result<()> {
    if !path.exists() {
        bail!("scan path does not exist: {}", path.display());
    }
    if !path.is_dir() {
        bail!("scan path is not a directory: {}", path.display());
    }

    let canonical = path
        .canonicalize()
        .with_context(|| format!("failed to canonicalize path: {}", path.display()))?;

    let config = EtcdCoordinatorConfig::from_endpoints_csv(etcd_endpoints, etcd_namespace)
        .context("invalid etcd config")?;
    let mut coordinator = EtcdCoordinator::connect(config).context("failed to connect to etcd")?;

    let tenant = TenantId::from_bytes(DEFAULT_TENANT_ID);
    let run_id = RunId::from_raw(run_id_raw);
    let shard_id = ShardId::from_raw(shard_id_raw);
    let now = LogicalTime::from_raw(1);

    let run_config = RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, Some(5))
        .context("invalid run config")?;

    // Treat AlreadyExists as non-fatal for re-runnability.
    match coordinator.create_run(now, tenant, run_id, run_config) {
        Ok(_) => eprintln!("created run {run_id_raw}"),
        Err(gossip_coordination::CreateRunError::RunAlreadyExists { .. }) => {
            eprintln!(
                "run {run_id_raw} already exists — skipping creation (use `just reset` to clear state)"
            );
        }
        Err(err) => return Err(anyhow::Error::new(err).context("failed to create run")),
    }

    let mut scratch = ShardSpecScratch::new();
    let connector_extra = canonical
        .to_str()
        .context("scan path is not valid UTF-8")?
        .as_bytes();
    let spec_ref = range_shard_ref(b"\x00", b"\xFF", connector_extra, &mut scratch)
        .context("failed to build shard spec")?;
    let spec = gossip_coordination::ShardSpec::try_from_ref(spec_ref)
        .context("failed to build owned shard spec")?;
    let manifest = [InitialShardInput::new(
        shard_id,
        spec.as_ref(),
        CursorUpdate::initial(),
    )];

    let next_now = LogicalTime::from_raw(2);
    match coordinator.register_shards(next_now, tenant, run_id, &manifest, OpId::from_raw(1)) {
        Ok(_) => {
            eprintln!("registered shard {shard_id_raw}");
        }
        Err(RegisterShardsError::OpIdConflict(_)) => {
            // OpIdConflict means the same OpId was used with a different payload
            // hash. Since this tool always uses OpId(1), re-seeding with a
            // different path or shard configuration triggers this. The old shard
            // metadata stays in etcd, so we must not print success — the user
            // needs to reset first.
            bail!(
                "run {run_id_raw} already has a different shard registration payload; \
                 run `just reset` then re-seed"
            );
        }
        Err(RegisterShardsError::RunNotFound) => {
            bail!("run {run_id_raw} not found — was it created? try `just seed` from scratch");
        }
        Err(err) => {
            return Err(anyhow::Error::new(err).context("failed to register shards"));
        }
    }

    eprintln!(
        "seeded run {run_id_raw} with 1 shard covering {}",
        canonical.display()
    );
    Ok(())
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

    eprintln!("migrations applied to both databases");
    Ok(())
}
