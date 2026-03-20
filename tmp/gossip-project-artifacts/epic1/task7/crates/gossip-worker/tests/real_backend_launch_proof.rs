//! Real etcd + PostgreSQL launch proofs for Epic 1.
//!
//! These tests exercise the actual worker process boundary against live backends
//! provisioned by the existing test-support helpers:
//!
//! - etcd via `gossip-coordination-etcd::test_support`
//! - PostgreSQL via `gossip-pg-common::test_support`
//!
//! The happy-path proofs intentionally invoke the `gossip-worker` binary rather
//! than calling only library helpers so CI demonstrates that the configured
//! worker process boots, connects, scans, and commits against the real control
//! and storage plane.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use gossip_contracts::identity::{LogicalTime, OpId, RunId, ShardId, TenantId, WorkerId};
use gossip_coordination::{
    AcquireScratch, CheckpointError, CoordinationBackend, CursorSemantics, CursorUpdate,
    InitialShardInput, RenewError, RunConfig, RunManagement, ShardClaiming, ShardKey,
    ShardStatus,
};
use gossip_coordination_etcd::test_support::{
    contention_namespace, test_coordinator_in_namespace, test_coordinator_in_namespace_with_tuning,
};
use gossip_coordination_etcd::{EtcdCoordinator, EtcdCoordinatorConfig};
use gossip_done_ledger_postgres::{
    apply_all_migrations as apply_done_ledger_migrations, schema as done_ledger_schema,
};
use gossip_findings_postgres::{
    apply_all_migrations as apply_findings_migrations, schema as findings_schema,
};
use gossip_frontier::{ShardSpecScratch, range_shard_ref};
use gossip_pg_common::test_support::create_test_db;
use gossip_worker::config::{
    ENV_COMMIT_QUEUE_CAPACITY, ENV_DONE_LEDGER_POSTGRES_DSN, ENV_ETCD_ENDPOINTS,
    ENV_ETCD_NAMESPACE, ENV_FINDINGS_POSTGRES_DSN, ENV_FS_SKIP_ARCHIVES, ENV_MAX_BYTES,
    ENV_MAX_ITEMS, ENV_POLICY_HASH, ENV_RUN_ID, ENV_STARTUP_SCHEMA_MODE, ENV_TENANT_ID,
    ENV_TENANT_SECRET_KEY, ENV_WORKER_ANCHOR_MODE, ENV_WORKER_BACKEND,
    ENV_WORKER_DECODE_DEPTH, ENV_WORKER_ID, ENV_WORKER_MODE, ENV_WORKER_PATH,
    ENV_WORKER_RULES_FILE, ENV_WORKER_SCAN_BINARY, ENV_WORKER_SOURCE,
};
use postgres::{Client, NoTls};
use tempfile::TempDir;

const DEFAULT_LEASE_DURATION_MS: u64 = 30_000;
const SHARD_ID_RAW: u64 = 1;
const RUN_ID_RAW: u64 = 42;
const WORKER_ID_RAW: u64 = 7;
const TENANT_ID_BYTES: [u8; 32] = [0x11; 32];
const POLICY_HASH_BYTES: [u8; 32] = [0x22; 32];
const TENANT_SECRET_KEY_BYTES: [u8; 32] = [0x33; 32];

const SAFE_RULE_NAME: &str = "safe-test-token";
const SAFE_TOKEN: &str = "GOSSIP_TEST_TOKEN_ABC12345";
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
    ENV_TENANT_ID,
    ENV_RUN_ID,
    ENV_WORKER_ID,
    ENV_POLICY_HASH,
    ENV_TENANT_SECRET_KEY,
    ENV_STARTUP_SCHEMA_MODE,
];

struct SafeScanFixture {
    scan_root: TempDir,
    rules_root: TempDir,
    scan_path: PathBuf,
    rules_path: PathBuf,
}

impl SafeScanFixture {
    fn new() -> Self {
        let scan_root = tempfile::tempdir().expect("scan tempdir should create");
        let rules_root = tempfile::tempdir().expect("rules tempdir should create");
        let scan_path = scan_root.path().to_path_buf();
        let rules_path = rules_root.path().join("safe-rules.yaml");

        fs::write(
            scan_path.join("evidence.txt"),
            format!("non-secret fixture payload: {SAFE_TOKEN}\n"),
        )
        .expect("safe evidence fixture should write");
        fs::write(
            scan_path.join("readme.txt"),
            "this file exists to ensure the shard scans more than one filesystem entry\n",
        )
        .expect("safe readme fixture should write");
        fs::write(&rules_path, SAFE_RULES_YAML).expect("safe rules file should write");

        Self {
            scan_root,
            rules_root,
            scan_path,
            rules_path,
        }
    }

    fn scan_path(&self) -> &Path {
        &self.scan_path
    }

    fn rules_path(&self) -> &Path {
        &self.rules_path
    }

    fn keepalive_paths(&self) -> (&Path, &Path) {
        (self.scan_root.path(), self.rules_root.path())
    }
}

struct SeededLaunchProof {
    coordinator: EtcdCoordinator,
    etcd_config: EtcdCoordinatorConfig,
    done_ledger_dsn: String,
    findings_dsn: String,
    fixture: SafeScanFixture,
    shard_key: ShardKey,
}

impl SeededLaunchProof {
    fn new() -> Self {
        let namespace = contention_namespace();
        let mut coordinator = test_coordinator_in_namespace(&namespace);
        let etcd_config = coordinator.config().clone();
        let done_ledger_dsn = create_test_db();
        let findings_dsn = create_test_db();
        migrate_database_pair(&done_ledger_dsn, &findings_dsn);

        let fixture = SafeScanFixture::new();
        let shard_key = seed_filesystem_run(
            &mut coordinator,
            fixture.scan_path(),
            DEFAULT_LEASE_DURATION_MS,
        );

        Self {
            coordinator,
            etcd_config,
            done_ledger_dsn,
            findings_dsn,
            fixture,
            shard_key,
        }
    }

    fn run_worker_binary(&self) -> Output {
        run_worker_process(
            &self.etcd_config,
            &self.done_ledger_dsn,
            &self.findings_dsn,
            self.fixture.scan_path(),
            self.fixture.rules_path(),
        )
    }

    fn done_ledger_row_count(&self) -> i64 {
        table_row_count(&self.done_ledger_dsn, done_ledger_schema::DONE_LEDGER_ENTRIES_TABLE)
    }

    fn observation_row_count(&self) -> i64 {
        table_row_count(&self.findings_dsn, findings_schema::OBSERVATIONS_TABLE)
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

fn seed_filesystem_run(
    coordinator: &mut EtcdCoordinator,
    scan_root: &Path,
    lease_duration_ms: u64,
) -> ShardKey {
    coordinator
        .create_run(now(1), tenant_id(), run_id(), test_run_config(lease_duration_ms))
        .expect("test run creation should succeed");

    let mut scratch = ShardSpecScratch::new();
    let connector_extra = scan_root
        .to_str()
        .expect("test scan path must be valid UTF-8")
        .as_bytes();
    let spec_ref = range_shard_ref(b"\x00", b"\xFF", connector_extra, &mut scratch)
        .expect("range shard spec should build");
    let shard_id = ShardId::from_raw(SHARD_ID_RAW);
    let manifest = [InitialShardInput::new(
        shard_id,
        spec_ref,
        CursorUpdate::initial(),
    )];
    coordinator
        .register_shards(now(2), tenant_id(), run_id(), &manifest, OpId::from_raw(1))
        .expect("test shard registration should succeed");

    ShardKey::new(run_id(), shard_id)
}

fn worker_binary_path() -> PathBuf {
    std::env::var_os("CARGO_BIN_EXE_gossip-worker")
        .map(PathBuf::from)
        .expect("cargo should expose the compiled gossip-worker binary to integration tests")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut hex, "{byte:02x}");
    }
    hex
}

fn migrate_database_pair(done_ledger_dsn: &str, findings_dsn: &str) {
    let mut done_ledger_client =
        Client::connect(done_ledger_dsn, NoTls).expect("done-ledger test DB should connect");
    apply_done_ledger_migrations(&mut done_ledger_client)
        .expect("done-ledger migrations should succeed");

    let mut findings_client =
        Client::connect(findings_dsn, NoTls).expect("findings test DB should connect");
    apply_findings_migrations(&mut findings_client).expect("findings migrations should succeed");
}

fn run_worker_process(
    etcd_config: &EtcdCoordinatorConfig,
    done_ledger_dsn: &str,
    findings_dsn: &str,
    scan_root: &Path,
    rules_path: &Path,
) -> Output {
    let mut command = Command::new(worker_binary_path());
    for &key in WORKER_ENV_KEYS {
        command.env_remove(key);
    }

    command
        .arg("--mode=connector")
        .arg("fs")
        .arg(scan_root)
        .env(ENV_ETCD_ENDPOINTS, etcd_config.endpoints().join(","))
        .env(ENV_ETCD_NAMESPACE, etcd_config.namespace_prefix())
        .env(ENV_DONE_LEDGER_POSTGRES_DSN, done_ledger_dsn)
        .env(ENV_FINDINGS_POSTGRES_DSN, findings_dsn)
        .env(ENV_TENANT_ID, bytes_to_hex(&TENANT_ID_BYTES))
        .env(ENV_RUN_ID, run_id().as_raw().to_string())
        .env(ENV_WORKER_ID, worker_id().as_raw().to_string())
        .env(ENV_POLICY_HASH, bytes_to_hex(&POLICY_HASH_BYTES))
        .env(ENV_TENANT_SECRET_KEY, bytes_to_hex(&TENANT_SECRET_KEY_BYTES))
        .env(ENV_WORKER_RULES_FILE, rules_path)
        .env(ENV_STARTUP_SCHEMA_MODE, "validate")
        .env("RUST_LOG", "info");

    command
        .output()
        .expect("gossip-worker process should launch for the integration proof")
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

fn table_row_count(dsn: &str, table: &str) -> i64 {
    let mut client = Client::connect(dsn, NoTls).expect("test database should connect");
    client
        .query_one(&format!("SELECT COUNT(*) FROM {table}"), &[])
        .expect("row-count query should succeed")
        .get::<_, i64>(0)
}

fn wait_for_owner_binding_expiry(
    coordinator: &EtcdCoordinator,
    key: ShardKey,
    timeout: Duration,
) {
    let start = Instant::now();
    loop {
        if coordinator
            .test_load_owner_binding(tenant_id(), key)
            .expect("owner-binding lookup should succeed")
            .is_none()
        {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "owner binding did not expire within {:?}",
            timeout
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn worker_binary_happy_path_commits_to_real_backends_and_completes_the_shard() {
    let proof = SeededLaunchProof::new();
    let _ = proof.fixture.keepalive_paths();

    let output = proof.run_worker_binary();
    assert_worker_success(&output, "real-backend worker happy path");

    let done_ledger_rows = proof.done_ledger_row_count();
    let observation_rows = proof.observation_row_count();
    assert!(
        done_ledger_rows > 0,
        "happy path must durably persist done-ledger rows"
    );
    assert!(
        observation_rows > 0,
        "happy path must durably persist findings observations for the safe test rule '{}'",
        SAFE_RULE_NAME,
    );

    let shard = proof
        .coordinator
        .test_load_shard_snapshot(tenant_id(), proof.shard_key)
        .expect("shard snapshot lookup should succeed")
        .expect("seeded shard must still exist after worker completion");
    assert_eq!(shard.status, ShardStatus::Done);
    assert!(
        proof.coordinator
            .test_load_owner_binding(tenant_id(), proof.shard_key)
            .expect("owner-binding lookup should succeed after completion")
            .is_none(),
        "completed shard must not retain a live owner binding"
    );
}

#[test]
fn worker_binary_restart_is_idempotent_after_completed_shard() {
    let proof = SeededLaunchProof::new();
    let _ = proof.fixture.keepalive_paths();

    let first = proof.run_worker_binary();
    assert_worker_success(&first, "first real-backend worker launch");
    let done_rows_after_first = proof.done_ledger_row_count();
    let observation_rows_after_first = proof.observation_row_count();
    assert!(done_rows_after_first > 0, "first launch must write done-ledger rows");
    assert!(
        observation_rows_after_first > 0,
        "first launch must write findings observations"
    );

    let second = proof.run_worker_binary();
    assert_worker_success(&second, "worker restart after completed shard");

    assert_eq!(
        proof.done_ledger_row_count(),
        done_rows_after_first,
        "restarting after shard completion must not duplicate done-ledger rows"
    );
    assert_eq!(
        proof.observation_row_count(),
        observation_rows_after_first,
        "restarting after shard completion must not duplicate findings observations"
    );

    let shard = proof
        .coordinator
        .test_load_shard_snapshot(tenant_id(), proof.shard_key)
        .expect("shard snapshot lookup should succeed after restart")
        .expect("seeded shard must still exist after restart");
    assert_eq!(shard.status, ShardStatus::Done);
}

#[test]
fn stale_fence_smoke_rejects_progress_after_owner_lease_loss() {
    let namespace = contention_namespace();
    let mut backend_a = test_coordinator_in_namespace_with_tuning(&namespace, 1, 8, 8);
    let mut backend_b = test_coordinator_in_namespace_with_tuning(&namespace, 1, 8, 8);
    let fixture = SafeScanFixture::new();
    let _ = fixture.keepalive_paths();
    let key = seed_filesystem_run(&mut backend_a, fixture.scan_path(), DEFAULT_LEASE_DURATION_MS);

    let mut scratch_a = AcquireScratch::new();
    let lease_a = backend_a
        .acquire_and_restore_into(now(3), tenant_id(), key, worker_id(), &mut scratch_a)
        .expect("worker A should acquire the shard")
        .lease;

    backend_a
        .checkpoint(
            now(4),
            tenant_id(),
            &lease_a,
            &CursorUpdate::new(b"m"),
            OpId::from_raw(100),
        )
        .expect("worker A checkpoint should succeed before owner-lease expiry");

    wait_for_owner_binding_expiry(&backend_a, key, Duration::from_secs(5));

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
            assert_eq!(presented, current);
        }
        other => panic!("expected StaleFence after owner-lease loss, got {other:?}"),
    }

    let zombie_renew = backend_a
        .renew(now(5), tenant_id(), &lease_a)
        .expect_err("stale worker renew must be rejected after owner-lease loss");
    match zombie_renew {
        RenewError::StaleFence { presented, current } => {
            assert_eq!(presented, lease_a.fence());
            assert_eq!(presented, current);
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
        .acquire_and_restore_into(now(6), tenant_id(), key, WorkerId::from_raw(8), &mut scratch_b)
        .expect("replacement worker should reacquire after owner-lease loss")
        .lease;
    assert!(
        lease_b.fence() > lease_a.fence(),
        "replacement lease must advance the fencing epoch"
    );
}
