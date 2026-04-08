//! Real etcd + PostgreSQL launch proofs for the worker process.
//!
//! These tests exercise the actual worker process boundary against live
//! backends provisioned by the existing test-support helpers:
//!
//! - etcd via `gossip-coordination-etcd::test_support`
//! - PostgreSQL via `gossip-pg-common::test_support` for done-ledger,
//!   findings, and Git key-value durability
//!
//! The happy-path checks intentionally invoke the `gossip-worker` binary
//! rather than calling only library helpers so the full process boundary is
//! covered: config resolution, backend bootstrap, scan execution, and durable
//! commits.
//!
//! The launch-proof matrix covers both supported connector families:
//!
//! - filesystem submission, completion, and restart idempotency
//! - Git submission for default-branch, explicit-ref, explicit-commit, and
//!   repo-list targets
//! - Git live-backend execution and restart idempotency for a committed local
//!   repository fixture

use std::collections::HashSet;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use gossip_contracts::connector::git::{GitExecutionLimits, GitMergeStrategy, GitScanMode};
use gossip_contracts::identity::{LogicalTime, OpId, RunId, TenantId, WorkerId};
use gossip_coordination::{
    AcquireScratch, CheckpointError, CoordinationBackend, CursorSemantics, CursorUpdate,
    RenewError, RunConfig, RunStatus, ShardKey, ShardStatus,
};
use gossip_coordination_etcd::test_support::{
    contention_namespace, test_coordinator_in_namespace, test_coordinator_in_namespace_with_tuning,
    wait_for_owner_binding_expiry,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig};
use gossip_done_ledger_postgres::{
    apply_all_migrations as apply_done_ledger_migrations, schema as done_ledger_schema,
};
use gossip_findings_postgres::{
    apply_all_migrations as apply_findings_migrations, schema as findings_schema,
};
use gossip_frontier::hint::decode_connector_extra;
use gossip_git_persistence_postgres::{
    apply_all_migrations as apply_git_kv_migrations, schema as git_kv_schema,
};
use gossip_orchestrator::{
    FilesystemRequest, FilesystemRunSetupInput, GitInitialShardPlan, GitInitialShardPlanEntry,
    GitRequest, GitRunSetupInput, GitShardPayload, NormalizedGitSelection,
    plan_filesystem_initial_shards, plan_git_initial_shards, setup_filesystem_run, setup_git_run,
};
use gossip_pg_common::test_support::create_test_db;
use gossip_scanner_runtime::test_fixtures::{git_stdout, init_git_repo, run_git};
use gossip_stdx::hex_encode;
use gossip_worker::config::{
    ENV_COMMIT_QUEUE_CAPACITY, ENV_DONE_LEDGER_POSTGRES_DSN, ENV_ETCD_ENDPOINTS,
    ENV_ETCD_NAMESPACE, ENV_FINDINGS_POSTGRES_DSN, ENV_FS_SKIP_ARCHIVES, ENV_GIT_KV_POSTGRES_DSN,
    ENV_MAX_BYTES, ENV_MAX_ITEMS, ENV_MIRROR_ROOT, ENV_POLICY_HASH, ENV_RUN_ID,
    ENV_STARTUP_SCHEMA_MODE, ENV_TENANT_ID, ENV_TENANT_SECRET_KEY, ENV_WORKER_ANCHOR_MODE,
    ENV_WORKER_BACKEND, ENV_WORKER_DECODE_DEPTH, ENV_WORKER_ID, ENV_WORKER_MODE, ENV_WORKER_PATH,
    ENV_WORKER_RULES_FILE, ENV_WORKER_SCAN_BINARY, ENV_WORKER_SOURCE,
};
use postgres::{Client, NoTls};
use tempfile::TempDir;
use wait_timeout::ChildExt;

const DEFAULT_LEASE_DURATION_MS: u64 = 30_000;
const RUN_ID_RAW: u64 = 42;
const WORKER_ID_RAW: u64 = 7;
const TENANT_ID_BYTES: [u8; 32] = [0x11; 32];
const POLICY_HASH_BYTES: [u8; 32] = [0x22; 32];
const TENANT_SECRET_KEY_BYTES: [u8; 32] = [0x33; 32];

const SAFE_RULE_NAME: &str = "safe-test-token";
const SAFE_TOKEN: &str = "GOSSIP_TEST_TOKEN_ABC12345";
const MAIN_REF: &str = "refs/heads/main";
const SAFE_RULES_YAML: &str = r#"
rules:
  - name: "safe-test-token"
    regex: 'GOSSIP_TEST_TOKEN_[A-Z0-9]{8}'
    anchors: ["GOSSIP_TEST_TOKEN_"]
    radius: 64
"#;

const WORKER_ENV_KEYS: &[&str] = &[
    ENV_WORKER_MODE,
    ENV_WORKER_BACKEND,
    ENV_WORKER_SOURCE,
    ENV_WORKER_PATH,
    ENV_MIRROR_ROOT,
    ENV_WORKER_RULES_FILE,
    ENV_WORKER_DECODE_DEPTH,
    ENV_WORKER_SCAN_BINARY,
    ENV_WORKER_ANCHOR_MODE,
    ENV_FS_SKIP_ARCHIVES,
    ENV_MAX_ITEMS,
    ENV_MAX_BYTES,
    ENV_COMMIT_QUEUE_CAPACITY,
    ENV_ETCD_ENDPOINTS,
    ENV_ETCD_NAMESPACE,
    ENV_DONE_LEDGER_POSTGRES_DSN,
    ENV_FINDINGS_POSTGRES_DSN,
    ENV_GIT_KV_POSTGRES_DSN,
    ENV_TENANT_ID,
    ENV_RUN_ID,
    ENV_WORKER_ID,
    ENV_POLICY_HASH,
    ENV_TENANT_SECRET_KEY,
    ENV_STARTUP_SCHEMA_MODE,
];

struct SafeScanFixture {
    /// RAII guard — dropping this removes the temporary scan directory.
    scan_root: TempDir,
    /// RAII guard — dropping this removes the temporary rules directory.
    _rules_root: TempDir,
    rules_path: PathBuf,
}

impl SafeScanFixture {
    fn new() -> Self {
        let scan_root = tempfile::tempdir().expect("scan tempdir should create");
        let (rules_root, rules_path) = create_rules_fixture();

        fs::write(
            scan_root.path().join("evidence.txt"),
            format!("non-secret fixture payload: {SAFE_TOKEN}\n"),
        )
        .expect("safe evidence fixture should write");
        fs::write(
            scan_root.path().join("readme.txt"),
            "this file exists to ensure the shard scans more than one filesystem entry\n",
        )
        .expect("safe readme fixture should write");

        Self {
            scan_root,
            _rules_root: rules_root,
            rules_path,
        }
    }

    fn scan_path(&self) -> &Path {
        self.scan_root.path()
    }

    fn rules_path(&self) -> &Path {
        &self.rules_path
    }
}

fn create_rules_fixture() -> (TempDir, PathBuf) {
    let rules_root = tempfile::tempdir().expect("rules tempdir should create");
    let rules_path = rules_root.path().join("safe-rules.yaml");
    fs::write(&rules_path, SAFE_RULES_YAML).expect("safe rules file should write");
    (rules_root, rules_path)
}

#[derive(Clone, Debug)]
struct GitRepoFixture {
    path: PathBuf,
    head_oid: String,
}

/// Local Git launch fixture for real-backend worker proofs.
///
/// Each repo contains committed files so the Git proof exercises object
/// handling. Repos created via [`new`](Self::new) include a file that matches
/// `SAFE_TOKEN` (for submission-only tests). Repos created via
/// [`clean`](Self::clean) contain only non-matching content so the worker can
/// complete the shard without hitting the findings-persistence guard.
///
/// The fixture also owns the worker-local mirror root and rules file required
/// by connector-mode Git launches.
struct GitScanFixture {
    /// RAII guard — dropping this removes the temporary repo workspace.
    _workspace_root: TempDir,
    /// RAII guard — dropping this removes the worker-local mirror cache root.
    mirror_root: TempDir,
    /// RAII guard — dropping this removes the temporary rules directory.
    _rules_root: TempDir,
    rules_path: PathBuf,
    repos: Vec<GitRepoFixture>,
}

impl GitScanFixture {
    fn new(repo_count: usize) -> Self {
        Self::build(repo_count, true)
    }

    /// Create a fixture whose repos contain no content matching `SAFE_TOKEN`.
    ///
    /// Clean repos simplify expected-count assertions in the happy-path proof:
    /// zero observations, one done-ledger row per repo, deterministic git-kv
    /// state.
    fn clean(repo_count: usize) -> Self {
        Self::build(repo_count, false)
    }

    fn build(repo_count: usize, include_secret: bool) -> Self {
        assert!(repo_count > 0, "GitScanFixture requires at least one repo");

        let workspace_root = tempfile::tempdir().expect("repo workspace tempdir should create");
        let mirror_root = tempfile::tempdir().expect("mirror-root tempdir should create");
        let (rules_root, rules_path) = create_rules_fixture();
        let repos = (0..repo_count)
            .map(|index| create_committed_git_repo(workspace_root.path(), index, include_secret))
            .collect();

        Self {
            _workspace_root: workspace_root,
            mirror_root,
            _rules_root: rules_root,
            rules_path,
            repos,
        }
    }

    fn primary_repo(&self) -> &GitRepoFixture {
        self.repo(0)
    }

    fn repo(&self, index: usize) -> &GitRepoFixture {
        &self.repos[index]
    }

    fn repo_paths(&self) -> impl DoubleEndedIterator<Item = &Path> + '_ {
        self.repos.iter().map(|repo| repo.path.as_path())
    }

    fn mirror_root(&self) -> &Path {
        self.mirror_root.path()
    }

    fn rules_path(&self) -> &Path {
        &self.rules_path
    }
}

fn create_committed_git_repo(
    workspace_root: &Path,
    index: usize,
    include_secret: bool,
) -> GitRepoFixture {
    let repo_path = workspace_root.join(format!("repo-{index}"));
    fs::create_dir_all(&repo_path).expect("git fixture repo directory should create");
    init_git_repo(
        &repo_path,
        "launch-proof-tests@example.com",
        "Launch Proof Tests",
    );
    let evidence_content = if include_secret {
        format!("git evidence fixture {index}: {SAFE_TOKEN}\n")
    } else {
        format!("git clean fixture {index}: no rule-matching content\n")
    };
    fs::write(repo_path.join("evidence.txt"), evidence_content)
        .expect("git evidence fixture should write");
    fs::write(
        repo_path.join("readme.txt"),
        format!("fixture repo {index} adds one clean file\n"),
    )
    .expect("git readme fixture should write");
    run_git(&repo_path, &["add", "."]);
    let commit_message = format!("fixture-{index}");
    run_git(&repo_path, &["commit", "-q", "-m", commit_message.as_str()]);

    let head_oid = git_stdout(&repo_path, &["rev-parse", "HEAD"]);
    assert!(
        head_oid.len() >= 40 && head_oid.chars().all(|c| c.is_ascii_hexdigit()),
        "git rev-parse HEAD returned invalid OID for repo-{index}: {head_oid:?}"
    );
    GitRepoFixture {
        path: repo_path,
        head_oid,
    }
}

/// Shared etcd + PostgreSQL test backends used by all launch proof types.
///
/// Creates an isolated etcd namespace plus the done-ledger, findings, and
/// Git key-value databases needed for end-to-end worker proofs.
struct SeededBackends {
    coordinator: EtcdCoordinator,
    done_ledger_dsn: String,
    findings_dsn: String,
    git_kv_dsn: String,
}

impl SeededBackends {
    fn new() -> Self {
        let namespace = contention_namespace();
        let coordinator = test_coordinator_in_namespace(&namespace);
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        let git_kv_dsn = create_test_db();
        migrate_databases(&done_ledger_dsn, &findings_dsn, Some(&git_kv_dsn));
        Self {
            coordinator,
            done_ledger_dsn,
            findings_dsn,
            git_kv_dsn,
        }
    }

    fn done_ledger_row_count(&self) -> i64 {
        table_row_count(
            &self.done_ledger_dsn,
            done_ledger_schema::DONE_LEDGER_ENTRIES_TABLE,
        )
    }

    fn observation_row_count(&self) -> i64 {
        table_row_count(&self.findings_dsn, findings_schema::OBSERVATIONS_TABLE)
    }

    fn git_kv_row_count(&self) -> i64 {
        table_row_count(&self.git_kv_dsn, git_kv_schema::GIT_KV_TABLE)
    }
}

/// Live-backend filesystem proof seeded through real etcd and PostgreSQL.
struct SeededLaunchProof {
    backends: SeededBackends,
    fixture: SafeScanFixture,
    shard_key: ShardKey,
}

impl SeededLaunchProof {
    fn new() -> Self {
        let mut backends = SeededBackends::new();
        let fixture = SafeScanFixture::new();
        let shard_key = submit_filesystem_request(
            &mut backends.coordinator,
            fixture.scan_path(),
            DEFAULT_LEASE_DURATION_MS,
        );

        Self {
            backends,
            fixture,
            shard_key,
        }
    }

    fn run_worker_binary(&self) -> Output {
        run_worker_process(
            self.backends.coordinator.config(),
            &self.backends.done_ledger_dsn,
            &self.backends.findings_dsn,
            None,
            WorkerLaunchTarget::Fs {
                path: self.fixture.scan_path(),
            },
            self.fixture.rules_path(),
        )
    }
}

/// Live-backend Git proof seeded through real etcd, PostgreSQL, and a local repo fixture.
///
/// The fixture uses a clean repo (no rule-matching content) so the proof
/// exercises the zero-findings path with deterministic expected counts.
struct GitSeededLaunchProof {
    backends: SeededBackends,
    fixture: GitScanFixture,
    shard_key: ShardKey,
}

impl GitSeededLaunchProof {
    fn new() -> Self {
        let mut backends = SeededBackends::new();
        let fixture = GitScanFixture::clean(1);
        let submission = submit_git_request(
            &mut backends.coordinator,
            GitRequest::single_repo(
                tenant_id(),
                fixture.primary_repo().path.as_path(),
                test_run_config(DEFAULT_LEASE_DURATION_MS),
                default_git_scan_mode(),
                default_git_merge_strategy(),
            ),
            default_git_execution_limits(),
            OpId::from_raw(21),
        );

        assert_eq!(
            submission.shard_keys.len(),
            1,
            "single-repo Git submission must register exactly one shard"
        );

        Self {
            backends,
            fixture,
            shard_key: submission.shard_keys[0],
        }
    }

    fn run_worker_binary(&self) -> Output {
        run_worker_process(
            self.backends.coordinator.config(),
            &self.backends.done_ledger_dsn,
            &self.backends.findings_dsn,
            Some(&self.backends.git_kv_dsn),
            WorkerLaunchTarget::Git {
                path: self.fixture.primary_repo().path.as_path(),
                mirror_root: self.fixture.mirror_root(),
            },
            self.fixture.rules_path(),
        )
    }
}

fn tenant_id() -> TenantId {
    TenantId::from_bytes(TENANT_ID_BYTES)
}

fn run_id() -> RunId {
    RunId::from_raw(RUN_ID_RAW)
}

fn worker_id() -> WorkerId {
    WorkerId::from_raw(WORKER_ID_RAW)
}

fn now(value: u64) -> LogicalTime {
    LogicalTime::from_raw(value)
}

fn test_run_config(lease_duration_ms: u64) -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, Some(5))
        .expect("test run config should be valid")
}

fn default_git_scan_mode() -> GitScanMode {
    GitScanMode::DiffHistory
}

fn default_git_merge_strategy() -> GitMergeStrategy {
    GitMergeStrategy::AllParents
}

fn default_git_execution_limits() -> GitExecutionLimits {
    GitExecutionLimits::default()
}

struct SubmittedGitRun {
    plan: GitInitialShardPlan,
    shard_keys: Vec<ShardKey>,
    payloads: Vec<GitShardPayload>,
}

/// Register one Git request through the real orchestrator setup path.
///
/// The helper validates the real etcd state that submission should leave
/// behind: an active run, one claimable root shard per planned target, typed
/// Git payload bytes in shard metadata, no owner bindings, and no cursor
/// progress before any worker claims a shard.
fn submit_git_request(
    coordinator: &mut EtcdCoordinator,
    request: GitRequest,
    execution_limits: GitExecutionLimits,
    op_id: OpId,
) -> SubmittedGitRun {
    let plan = plan_git_initial_shards(
        request
            .normalize()
            .expect("test Git request should normalize"),
        execution_limits,
    )
    .expect("test Git request should plan initial shards");
    let outcome = setup_git_run(
        coordinator,
        now(1),
        tenant_id(),
        run_id(),
        GitRunSetupInput::new(&plan),
        op_id,
    )
    .unwrap_or_else(|e| panic!("Git run setup should succeed (run={:?}): {e}", run_id()));
    assert!(
        outcome.is_executed(),
        "fresh Git launch proof setup should execute instead of replaying (run={:?})",
        run_id(),
    );
    let setup = outcome.into_inner();
    let persisted_run = coordinator
        .test_load_run_snapshot(tenant_id(), run_id())
        .unwrap_or_else(|e| {
            panic!(
                "run snapshot lookup should succeed after Git submission (run={:?}): {e}",
                run_id()
            )
        })
        .unwrap_or_else(|| {
            panic!(
                "Git submission should register a run record (run={:?})",
                run_id()
            )
        });
    assert_eq!(persisted_run.status(), RunStatus::Active);
    assert_eq!(
        persisted_run.root_shards(),
        setup.root_shards(),
        "persisted run record should retain the registered root shards"
    );
    assert_eq!(
        setup.root_shards().len(),
        plan.entries().len(),
        "Git submission should register one root shard per planned target"
    );

    let (shard_keys, payloads) = setup
        .root_shards()
        .iter()
        .zip(plan.entries())
        .map(|(&shard_id, entry)| {
            let key = ShardKey::new(run_id(), shard_id);
            let payload = assert_registered_git_shard_state(coordinator, key, entry);
            (key, payload)
        })
        .unzip();

    SubmittedGitRun {
        plan,
        shard_keys,
        payloads,
    }
}

fn submit_filesystem_request(
    coordinator: &mut EtcdCoordinator,
    scan_root: &Path,
    lease_duration_ms: u64,
) -> ShardKey {
    let request = FilesystemRequest::directory_root(scan_root, test_run_config(lease_duration_ms))
        .normalize()
        .expect("test filesystem request should normalize");
    let plan = plan_filesystem_initial_shards(request.clone());
    let payload = plan.shard_payload();
    let outcome = setup_filesystem_run(
        coordinator,
        now(1),
        tenant_id(),
        run_id(),
        FilesystemRunSetupInput::new(&request, plan.initial_shard(), &payload),
        OpId::from_raw(1),
    )
    .expect("test filesystem run setup should succeed");
    assert!(
        outcome.is_executed(),
        "fresh launch proof setup should execute instead of replaying an existing run"
    );
    let setup = outcome.into_inner();
    assert_eq!(setup.run().status(), RunStatus::Active);
    assert_eq!(
        setup.root_shards().len(),
        1,
        "filesystem submission should register exactly one startup shard"
    );

    // Control-plane setup must stop after registration: the shard exists and
    // is runnable, but no worker has claimed it and no progress is recorded.
    let shard_key = ShardKey::new(run_id(), setup.root_shards()[0]);
    let shard = coordinator
        .test_load_shard_snapshot(tenant_id(), shard_key)
        .expect("submitted shard snapshot lookup should succeed")
        .expect("filesystem submission should register the startup shard");
    assert_eq!(shard.status, ShardStatus::Active);
    assert!(
        shard.cursor.last_key(shard.slab()).is_none(),
        "fresh submission should not pre-populate shard progress"
    );
    assert!(
        coordinator
            .test_load_owner_binding(tenant_id(), shard_key)
            .expect("owner-binding lookup should succeed after submission")
            .is_none(),
        "submission alone must not claim the shard"
    );

    shard_key
}

fn assert_registered_git_shard_state(
    coordinator: &EtcdCoordinator,
    key: ShardKey,
    entry: &GitInitialShardPlanEntry,
) -> GitShardPayload {
    let shard = coordinator
        .test_load_shard_snapshot(tenant_id(), key)
        .unwrap_or_else(|e| panic!("shard {key:?}: snapshot lookup should succeed: {e}"))
        .unwrap_or_else(|| panic!("shard {key:?}: submission should register the startup shard"));
    assert_eq!(
        shard.status,
        ShardStatus::Active,
        "shard {key:?}: should be Active after submission"
    );
    assert_eq!(
        shard.spec.key_range_start(shard.slab()),
        entry.geometry().key_range_start(),
        "shard {key:?}: submission should persist the planned lower key bound"
    );
    assert_eq!(
        shard.spec.key_range_end(shard.slab()),
        entry.geometry().key_range_end(),
        "shard {key:?}: submission should persist the planned upper key bound"
    );
    assert!(
        shard.cursor.last_key(shard.slab()).is_none(),
        "shard {key:?}: fresh submission should not pre-populate shard progress"
    );
    assert!(
        coordinator
            .test_load_owner_binding(tenant_id(), key)
            .unwrap_or_else(|e| {
                panic!("shard {key:?}: owner-binding lookup should succeed: {e}")
            })
            .is_none(),
        "shard {key:?}: submission alone must not claim the shard"
    );
    let connector_extra = decode_connector_extra(shard.spec.as_spec_ref(shard.slab()))
        .unwrap_or_else(|e| panic!("shard {key:?}: metadata should decode: {e}"));
    let payload = GitShardPayload::decode(connector_extra)
        .unwrap_or_else(|e| panic!("shard {key:?}: payload should round-trip: {e}"));
    assert_eq!(
        &payload,
        entry.payload(),
        "shard {key:?}: persisted payload must match the orchestrator plan"
    );
    payload
}

/// Assert that a shard completed durably and released its live lease state.
///
/// Validates the persisted etcd snapshot: Done status, a non-trivial progress
/// cursor, and no live owner binding. Connector-family wrappers delegate here
/// with a diagnostic label for assertion messages.
fn assert_completed_shard_invariants(coordinator: &EtcdCoordinator, key: ShardKey, label: &str) {
    let shard = coordinator
        .test_load_shard_snapshot(tenant_id(), key)
        .unwrap_or_else(|e| panic!("{label}: shard snapshot lookup should succeed: {e}"))
        .unwrap_or_else(|| panic!("{label}: shard must still exist after worker completion"));
    assert_eq!(
        shard.status,
        ShardStatus::Done,
        "{label}: shard should be Done"
    );
    assert!(
        shard.cursor.last_key(shard.slab()).is_some(),
        "{label}: completion must persist a progress cursor"
    );
    assert_ne!(
        shard.cursor.last_key(shard.slab()),
        Some(b"\x00".as_slice()),
        "{label}: completion must checkpoint a real progress key, not a sentinel"
    );
    assert!(
        coordinator
            .test_load_owner_binding(tenant_id(), key)
            .unwrap_or_else(|e| panic!("{label}: owner-binding lookup should succeed: {e}"))
            .is_none(),
        "{label}: completed shard must not retain a live owner binding"
    );
}

/// Assert that a filesystem shard completed durably.
///
/// Validates all common completion invariants (Done status, non-trivial
/// progress cursor, no owner binding) via [`assert_completed_shard_invariants`].
fn assert_completed_filesystem_shard_state(coordinator: &EtcdCoordinator, key: ShardKey) {
    assert_completed_shard_invariants(coordinator, key, "filesystem");
}

/// Assert that a Git shard completed durably.
///
/// Validates all common completion invariants (Done status, non-trivial
/// progress cursor, no owner binding) via [`assert_completed_shard_invariants`].
fn assert_completed_git_shard_state(coordinator: &EtcdCoordinator, key: ShardKey) {
    assert_completed_shard_invariants(coordinator, key, "git");
}

fn worker_binary_path() -> PathBuf {
    for key in ["CARGO_BIN_EXE_gossip-worker", "CARGO_BIN_EXE_gossip_worker"] {
        if let Some(path) = std::env::var_os(key).map(PathBuf::from)
            && path.is_file()
        {
            return path;
        }
    }

    // Integration tests run from `target/<profile>/deps`; the package binary
    // sits next to that directory in the same profile output folder.
    let current_exe = std::env::current_exe();
    let fallback = current_exe
        .as_ref()
        .ok()
        .and_then(|exe| {
            exe.parent()
                .and_then(|deps| deps.parent().map(Path::to_path_buf))
        })
        .map(|profile_dir| {
            profile_dir.join(format!("gossip-worker{}", std::env::consts::EXE_SUFFIX))
        });
    if let Some(path) = fallback
        && path.is_file()
    {
        return path;
    }

    match current_exe {
        Err(e) => panic!(
            "could not locate the compiled gossip-worker binary: \
             current_exe() failed: {e}"
        ),
        Ok(exe) => panic!(
            "could not locate the compiled gossip-worker binary; \
             searched CARGO_BIN_EXE_* and relative to {exe:?}"
        ),
    }
}

fn migrate_databases(done_ledger_dsn: &str, findings_dsn: &str, git_kv_dsn: Option<&str>) {
    std::thread::scope(|s| {
        s.spawn(|| {
            let mut client = Client::connect(done_ledger_dsn, NoTls)
                .expect("done-ledger test DB should connect");
            apply_done_ledger_migrations(&mut client)
                .expect("done-ledger migrations should succeed");
        });
        s.spawn(|| {
            let mut client =
                Client::connect(findings_dsn, NoTls).expect("findings test DB should connect");
            apply_findings_migrations(&mut client).expect("findings migrations should succeed");
        });
        if let Some(git_kv_dsn) = git_kv_dsn {
            s.spawn(|| {
                let mut client =
                    Client::connect(git_kv_dsn, NoTls).expect("git-kv test DB should connect");
                apply_git_kv_migrations(&mut client).expect("git-kv migrations should succeed");
            });
        }
    });
}

enum WorkerLaunchTarget<'a> {
    Fs {
        path: &'a Path,
    },
    Git {
        path: &'a Path,
        mirror_root: &'a Path,
    },
}

fn run_worker_process(
    etcd_config: &EtcdCoordinatorConfig,
    done_ledger_dsn: &str,
    findings_dsn: &str,
    git_kv_dsn: Option<&str>,
    target: WorkerLaunchTarget<'_>,
    rules_path: &Path,
) -> Output {
    let mut command = Command::new(worker_binary_path());
    for &key in WORKER_ENV_KEYS {
        command.env_remove(key);
    }

    command
        .arg("--mode=connector")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env(ENV_ETCD_ENDPOINTS, etcd_config.endpoints().join(","))
        .env(ENV_ETCD_NAMESPACE, etcd_config.namespace_prefix())
        .env(ENV_DONE_LEDGER_POSTGRES_DSN, done_ledger_dsn)
        .env(ENV_FINDINGS_POSTGRES_DSN, findings_dsn)
        .env(ENV_TENANT_ID, hex_encode(&TENANT_ID_BYTES))
        .env(ENV_RUN_ID, run_id().as_raw().to_string())
        .env(ENV_WORKER_ID, worker_id().as_raw().to_string())
        .env(ENV_POLICY_HASH, hex_encode(&POLICY_HASH_BYTES))
        .env(ENV_TENANT_SECRET_KEY, hex_encode(&TENANT_SECRET_KEY_BYTES))
        .env(ENV_WORKER_RULES_FILE, rules_path)
        .env(ENV_STARTUP_SCHEMA_MODE, "validate")
        .env("RUST_LOG", "info");

    if let Some(git_kv_dsn) = git_kv_dsn {
        command.env(ENV_GIT_KV_POSTGRES_DSN, git_kv_dsn);
    }

    match target {
        WorkerLaunchTarget::Fs { path } => {
            command.arg("fs").arg(path);
        }
        WorkerLaunchTarget::Git { path, mirror_root } => {
            command
                .arg("git")
                .arg(path)
                .env(ENV_MIRROR_ROOT, mirror_root);
        }
    }

    let mut child = command
        .spawn()
        .expect("gossip-worker process should launch for the real-backend tests");

    // Drain stdout and stderr on background threads to prevent pipe-buffer
    // deadlock: the OS pipe buffer is bounded (~64 KB on Linux), so if the
    // child fills it before exiting the parent would block on `wait_timeout`
    // while the child blocks on its write — a classic deadlock.
    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();
    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stdout_pipe {
            pipe.read_to_end(&mut buf)
                .expect("failed to read child process stdout");
        }
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut pipe) = stderr_pipe {
            pipe.read_to_end(&mut buf)
                .expect("failed to read child process stderr");
        }
        buf
    });

    let timeout = Duration::from_secs(30);
    match child.wait_timeout(timeout).expect("wait should not fail") {
        Some(status) => {
            let stdout = stdout_thread
                .join()
                .expect("stdout drain thread should not panic");
            let stderr = stderr_thread
                .join()
                .expect("stderr drain thread should not panic");
            Output {
                status,
                stdout,
                stderr,
            }
        }
        None => {
            child.kill().expect("kill should succeed");
            child.wait().expect("wait after kill should succeed");
            let stdout = stdout_thread
                .join()
                .expect("stdout drain thread should not panic");
            let stderr = stderr_thread
                .join()
                .expect("stderr drain thread should not panic");
            panic!(
                "gossip-worker did not exit within {timeout:?}\nstdout:\n{}\nstderr:\n{}",
                String::from_utf8_lossy(&stdout),
                String::from_utf8_lossy(&stderr),
            );
        }
    }
}

fn assert_worker_success(output: &Output, context: &str) {
    assert!(
        output.status.success(),
        "{context} failed with status {:?}\nstdout:\n{}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

/// Count rows in `table` from the database at `dsn`.
///
/// The table name is validated to be a plain SQL identifier (alphanumeric +
/// underscore) before interpolation. This is safe because all call sites pass
/// compile-time schema constants, and the assert guards against accidental
/// misuse if the function is ever called with dynamic input.
fn table_row_count(dsn: &str, table: &str) -> i64 {
    assert!(
        !table.is_empty() && table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
        "table_row_count requires a non-empty plain SQL identifier, got: {table:?}"
    );
    let mut client = Client::connect(dsn, NoTls).expect("test database should connect");
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .expect("row-count query should succeed")
        .get::<_, i64>(0)
}

#[test]
fn worker_binary_happy_path_commits_to_real_backends_and_completes_the_shard() {
    let proof = SeededLaunchProof::new();

    let output = proof.run_worker_binary();
    assert_worker_success(&output, "real-backend worker happy path");
    assert!(
        !output.stderr.is_empty(),
        "worker should produce diagnostic output on stderr"
    );

    let done_ledger_rows = proof.backends.done_ledger_row_count();
    let observation_rows = proof.backends.observation_row_count();
    // The scan fixture contains exactly 2 files (evidence.txt, readme.txt),
    // producing one done-ledger entry per scanned object-version.
    assert_eq!(
        done_ledger_rows, 2,
        "expected exactly 2 done-ledger rows (one per scanned file), got {done_ledger_rows}"
    );
    // The safe-test-token rule matches exactly once in evidence.txt.
    assert_eq!(
        observation_rows, 1,
        "expected exactly 1 observation for rule '{}', got {observation_rows}",
        SAFE_RULE_NAME,
    );
    assert_completed_filesystem_shard_state(&proof.backends.coordinator, proof.shard_key);
}

#[test]
fn worker_binary_restart_is_idempotent_after_completed_shard() {
    let proof = SeededLaunchProof::new();

    let first = proof.run_worker_binary();
    assert_worker_success(&first, "first real-backend worker launch");
    let done_rows_after_first = proof.backends.done_ledger_row_count();
    let observation_rows_after_first = proof.backends.observation_row_count();
    assert_eq!(
        done_rows_after_first, 2,
        "first launch must write exactly 2 done-ledger rows (one per scanned file), \
         got {done_rows_after_first}"
    );
    assert_eq!(
        observation_rows_after_first, 1,
        "first launch must write exactly 1 findings observation, \
         got {observation_rows_after_first}"
    );

    let second = proof.run_worker_binary();
    assert_worker_success(&second, "worker restart after completed shard");

    assert_eq!(
        proof.backends.done_ledger_row_count(),
        done_rows_after_first,
        "restarting after shard completion must not duplicate done-ledger rows"
    );
    assert_eq!(
        proof.backends.observation_row_count(),
        observation_rows_after_first,
        "restarting after shard completion must not duplicate findings observations"
    );

    assert_completed_filesystem_shard_state(&proof.backends.coordinator, proof.shard_key);
}

/// Verifies that default-branch Git submission registers one active, claimable shard.
#[test]
fn git_submit_default_selection_registers_claimable_shard_in_etcd() {
    let namespace = contention_namespace();
    let mut coordinator = test_coordinator_in_namespace(&namespace);
    let fixture = GitScanFixture::new(1);

    let submission = submit_git_request(
        &mut coordinator,
        GitRequest::single_repo(
            tenant_id(),
            fixture.primary_repo().path.as_path(),
            test_run_config(DEFAULT_LEASE_DURATION_MS),
            default_git_scan_mode(),
            default_git_merge_strategy(),
        ),
        default_git_execution_limits(),
        OpId::from_raw(31),
    );

    assert_eq!(submission.shard_keys.len(), 1);
    assert!(matches!(
        submission.payloads[0].selection(),
        NormalizedGitSelection::DefaultBranchOnly
    ));
}

/// Verifies that explicit-ref Git submission preserves the requested ref selection in shard metadata.
#[test]
fn git_submit_explicit_refs_registers_shard_with_ref_selection_payload() {
    let namespace = contention_namespace();
    let mut coordinator = test_coordinator_in_namespace(&namespace);
    let fixture = GitScanFixture::new(1);

    let submission = submit_git_request(
        &mut coordinator,
        GitRequest::repo_with_explicit_refs(
            tenant_id(),
            fixture.primary_repo().path.as_path(),
            [MAIN_REF.as_bytes()],
            test_run_config(DEFAULT_LEASE_DURATION_MS),
            default_git_scan_mode(),
            default_git_merge_strategy(),
        ),
        default_git_execution_limits(),
        OpId::from_raw(32),
    );

    match submission.payloads[0].selection() {
        NormalizedGitSelection::ExplicitRefs { refs } => {
            assert_eq!(refs, &[MAIN_REF.as_bytes().to_vec()]);
        }
        other => panic!("expected explicit-ref payload, got {other:?}"),
    }
}

/// Verifies that explicit-commit Git submission preserves the requested commit OID in shard metadata.
#[test]
fn git_submit_explicit_commit_registers_shard_with_oid_payload() {
    let namespace = contention_namespace();
    let mut coordinator = test_coordinator_in_namespace(&namespace);
    let fixture = GitScanFixture::new(1);
    let expected_head = fixture.primary_repo().head_oid.clone();

    let submission = submit_git_request(
        &mut coordinator,
        GitRequest::repo_with_explicit_commit(
            tenant_id(),
            fixture.primary_repo().path.as_path(),
            expected_head.as_bytes(),
            test_run_config(DEFAULT_LEASE_DURATION_MS),
            default_git_scan_mode(),
            default_git_merge_strategy(),
        ),
        default_git_execution_limits(),
        OpId::from_raw(33),
    );

    match submission.payloads[0].selection() {
        NormalizedGitSelection::ExplicitCommit { commit } => {
            assert_eq!(commit.to_string(), expected_head);
        }
        other => panic!("expected explicit-commit payload, got {other:?}"),
    }
}

/// Verifies that repo-list submission registers one claimable root shard per normalized repo target.
#[test]
fn git_submit_repo_list_registers_one_shard_per_target() {
    let namespace = contention_namespace();
    let mut coordinator = test_coordinator_in_namespace(&namespace);
    let fixture = GitScanFixture::new(3);
    let repo_paths: Vec<&Path> = fixture.repo_paths().rev().collect();

    let submission = submit_git_request(
        &mut coordinator,
        GitRequest::repo_list(
            tenant_id(),
            repo_paths.iter().copied(),
            test_run_config(DEFAULT_LEASE_DURATION_MS),
            default_git_scan_mode(),
            default_git_merge_strategy(),
        ),
        default_git_execution_limits(),
        OpId::from_raw(34),
    );

    assert_eq!(submission.plan.entries().len(), repo_paths.len());
    assert_eq!(submission.shard_keys.len(), repo_paths.len());
    let unique_shards: HashSet<_> = submission
        .shard_keys
        .iter()
        .map(|key| key.shard())
        .collect();
    assert_eq!(
        unique_shards.len(),
        repo_paths.len(),
        "repo-list submission must register one distinct root shard per target"
    );
}

/// Verifies that replaying Git run setup against real etcd returns the original root shard registration.
#[test]
fn git_setup_replay_is_idempotent_against_real_etcd() {
    let namespace = contention_namespace();
    let mut coordinator = test_coordinator_in_namespace(&namespace);
    let fixture = GitScanFixture::new(1);
    let plan = plan_git_initial_shards(
        GitRequest::single_repo(
            tenant_id(),
            fixture.primary_repo().path.as_path(),
            test_run_config(DEFAULT_LEASE_DURATION_MS),
            default_git_scan_mode(),
            default_git_merge_strategy(),
        )
        .normalize()
        .expect("test Git request should normalize"),
        default_git_execution_limits(),
    )
    .expect("test Git request should plan initial shards");

    let first = setup_git_run(
        &mut coordinator,
        now(1),
        tenant_id(),
        run_id(),
        GitRunSetupInput::new(&plan),
        OpId::from_raw(35),
    )
    .expect("first Git setup should succeed");
    assert!(first.is_executed());
    let first = first.into_inner();

    let replay = setup_git_run(
        &mut coordinator,
        now(2),
        tenant_id(),
        run_id(),
        GitRunSetupInput::new(&plan),
        OpId::from_raw(35),
    )
    .expect("replayed Git setup should succeed");
    assert!(replay.is_replay());
    let replay = replay.into_inner();

    assert_eq!(replay.root_shards(), first.root_shards());
    assert_registered_git_shard_state(
        &coordinator,
        ShardKey::new(run_id(), first.root_shards()[0]),
        &plan.entries()[0],
    );
}

/// Verifies that the worker binary completes a Git shard against live etcd and PostgreSQL backends.
#[test]
fn git_worker_binary_happy_path_completes_shard_and_commits() {
    let proof = GitSeededLaunchProof::new();

    let output = proof.run_worker_binary();
    assert_worker_success(&output, "real-backend Git worker happy path");
    assert!(
        !output.stderr.is_empty(),
        "Git worker should produce diagnostic output on stderr"
    );

    let done_ledger_rows = proof.backends.done_ledger_row_count();
    let observation_rows = proof.backends.observation_row_count();
    let git_kv_rows = proof.backends.git_kv_row_count();
    // Git scanning produces one done-ledger entry per repository. The clean
    // fixture has no rule-matching content, so zero observations are expected.
    assert_eq!(
        done_ledger_rows, 1,
        "expected exactly 1 done-ledger row (one per repo in Git mode), got {done_ledger_rows}"
    );
    assert_eq!(
        observation_rows, 0,
        "clean Git fixture should produce 0 observations, got {observation_rows}",
    );
    assert!(
        git_kv_rows >= 2,
        "Git worker should write at least scope + watermark rows, got {git_kv_rows}"
    );
    assert_completed_git_shard_state(&proof.backends.coordinator, proof.shard_key);
}

/// Verifies that rerunning the worker after Git shard completion is replay-safe and does not duplicate durable rows.
#[test]
fn git_worker_restart_is_idempotent_after_completed_shard() {
    let proof = GitSeededLaunchProof::new();

    let first = proof.run_worker_binary();
    assert_worker_success(&first, "first real-backend Git worker launch");
    let done_rows_after_first = proof.backends.done_ledger_row_count();
    let observation_rows_after_first = proof.backends.observation_row_count();
    let git_kv_rows_after_first = proof.backends.git_kv_row_count();
    assert_eq!(
        done_rows_after_first, 1,
        "expected exactly 1 done-ledger row (one per repo in Git mode), got {done_rows_after_first}"
    );
    assert_eq!(
        observation_rows_after_first, 0,
        "clean Git fixture should produce 0 observations, got {observation_rows_after_first}",
    );
    assert!(
        git_kv_rows_after_first >= 2,
        "first Git launch should populate at least scope + watermark git-kv rows, got {git_kv_rows_after_first}"
    );

    let second = proof.run_worker_binary();
    assert_worker_success(&second, "worker restart after completed Git shard");

    assert_eq!(
        proof.backends.done_ledger_row_count(),
        done_rows_after_first,
        "restarting after Git shard completion must not duplicate done-ledger rows"
    );
    assert_eq!(
        proof.backends.observation_row_count(),
        observation_rows_after_first,
        "restarting after Git shard completion must not duplicate findings observations"
    );
    assert_eq!(
        proof.backends.git_kv_row_count(),
        git_kv_rows_after_first,
        "restarting after Git shard completion must not duplicate git-kv state"
    );

    assert_completed_git_shard_state(&proof.backends.coordinator, proof.shard_key);
}

#[test]
#[ignore = "requires wall-clock TTL expiry against live etcd"]
fn stale_fence_smoke_rejects_progress_after_owner_lease_loss() {
    let namespace = contention_namespace();
    let ttl_secs: i64 = 1;
    let mut backend_a = test_coordinator_in_namespace_with_tuning(&namespace, ttl_secs, 8, 8);
    let mut backend_b = test_coordinator_in_namespace_with_tuning(&namespace, ttl_secs, 8, 8);
    let fixture = SafeScanFixture::new();
    let key = submit_filesystem_request(
        &mut backend_a,
        fixture.scan_path(),
        DEFAULT_LEASE_DURATION_MS,
    );

    let mut scratch_a = AcquireScratch::new();
    let lease_a = backend_a
        .acquire_and_restore_into(now(3), tenant_id(), key, worker_id(), &mut scratch_a)
        .expect("worker A should acquire the shard")
        .lease;

    let _ = backend_a
        .checkpoint(
            now(4),
            tenant_id(),
            &lease_a,
            &CursorUpdate::new(b"m"),
            OpId::from_raw(100),
        )
        .expect("worker A checkpoint should succeed before owner-lease expiry");

    wait_for_owner_binding_expiry(&backend_a, tenant_id(), key, ttl_secs);

    // Zombie-worker assertions: the owner binding is gone (etcd lease
    // expired) but no replacement worker has reacquired. Worker A's
    // checkpoint and renew must both be rejected with StaleFence.
    //
    // The fence epoch has not advanced (no reacquire), so both `presented`
    // and `current` carry the same value. This is the expected etcd-backend
    // behavior: the owner binding is absent, but the shard record's fence
    // is unchanged. The `StaleFence` contract ("re-acquire") is correct
    // for this case — callers must not interpret `presented == current` as
    // "still valid."
    //
    // After the replacement worker acquires below, the stronger invariant
    // `current > presented` is exercised separately.
    let zombie_checkpoint = backend_a
        .checkpoint(
            now(5),
            tenant_id(),
            &lease_a,
            &CursorUpdate::new(b"n"),
            OpId::from_raw(200),
        )
        .expect_err("stale worker checkpoint must be rejected after owner-lease loss");
    match zombie_checkpoint {
        CheckpointError::StaleFence { presented, current } => {
            assert_eq!(presented, lease_a.fence());
            assert_eq!(
                presented, current,
                "in the owner-absent window (no reacquire), presented == current"
            );
        }
        other => panic!("expected StaleFence after owner-lease loss, got {other:?}"),
    }

    let zombie_renew = backend_a
        .renew(now(5), tenant_id(), &lease_a)
        .expect_err("stale worker renew must be rejected after owner-lease loss");
    match zombie_renew {
        RenewError::StaleFence { presented, current } => {
            assert_eq!(presented, lease_a.fence());
            assert_eq!(
                presented, current,
                "in the owner-absent window (no reacquire), presented == current"
            );
        }
        other => panic!("expected StaleFence on renew after owner-lease loss, got {other:?}"),
    }

    let post_zombie = backend_a
        .test_load_shard_snapshot(tenant_id(), key)
        .expect("shard snapshot lookup should succeed after zombie assertions")
        .expect("seeded shard must remain readable after zombie assertions");
    assert_eq!(post_zombie.status, ShardStatus::Active);
    assert_eq!(post_zombie.fence_epoch, lease_a.fence());
    assert_eq!(
        post_zombie.cursor.last_key(post_zombie.slab()),
        Some(b"m".as_slice()),
        "rejected zombie checkpoint must not mutate persisted cursor state"
    );

    let mut scratch_b = AcquireScratch::new();
    let lease_b = backend_b
        .acquire_and_restore_into(
            now(6),
            tenant_id(),
            key,
            WorkerId::from_raw(8),
            &mut scratch_b,
        )
        .expect("replacement worker should reacquire after owner-lease loss")
        .lease;
    assert!(
        lease_b.fence() > lease_a.fence(),
        "replacement lease must advance the fencing epoch"
    );

    // After the replacement worker advances the fence, zombie operations
    // must be rejected with current > presented (the stronger invariant
    // that the pre-replacement assertions above cannot exercise).
    let superseded_checkpoint = backend_a
        .checkpoint(
            now(7),
            tenant_id(),
            &lease_a,
            &CursorUpdate::new(b"q"),
            OpId::from_raw(400),
        )
        .expect_err("zombie checkpoint must be rejected after replacement acquisition");
    match superseded_checkpoint {
        CheckpointError::StaleFence { presented, current } => {
            assert_eq!(presented, lease_a.fence());
            assert_eq!(
                current,
                lease_b.fence(),
                "current fence must reflect the replacement worker's epoch"
            );
            assert!(
                current > presented,
                "replacement acquisition must advance fence beyond the zombie's epoch"
            );
        }
        other => panic!("expected StaleFence after replacement, got {other:?}"),
    }

    let _ = backend_b
        .checkpoint(
            now(8),
            tenant_id(),
            &lease_b,
            &CursorUpdate::new(b"p"),
            OpId::from_raw(300),
        )
        .expect("replacement worker should checkpoint successfully after reacquisition");
    let post_replace = backend_b
        .test_load_shard_snapshot(tenant_id(), key)
        .expect("snapshot should succeed after replacement checkpoint")
        .expect("shard should exist after replacement checkpoint");
    assert_eq!(
        post_replace.cursor.last_key(post_replace.slab()),
        Some(b"p".as_slice()),
        "replacement worker's checkpoint must advance the cursor"
    );
}
