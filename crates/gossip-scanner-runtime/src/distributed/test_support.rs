//! Shared test infrastructure for the distributed module.
//!
//! Contains test doubles, helper constructors, and fixture builders used by
//! both `unit_tests` and `integration_tests` sibling modules.

// Items are consumed by sibling test modules (`unit_tests`, `integration_tests`)
// via `super::test_support::*`, which the compiler cannot trace across module boundaries.
#![allow(unused_imports)]
#![allow(dead_code)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

// -- Re-exports from the distributed module's public API --------------------

#[allow(unused_imports)]
use super::*;

// -- Submodule internals (pub(super) items) ---------------------------------

use super::commit_bridge::{
    CommitStageDrainResult, ReceiptCommitSink, drain_commit_stage, emit_ordered_summary,
    wait_for_submitted_commits,
};
use super::execution::{scan_ordered_source_with_engine, secret_fixture};
use super::lease_ops::build_lease_from_acquire;
use super::types::{OrderedSourceAssignmentOutcome, PageLoopTermination, wall_clock_now};

// -- External crate imports -------------------------------------------------

use gossip_contracts::{
    connector::{
        Cursor, EnumerateError, ItemKey, ItemRef, PageBuf, PageState, ReadError, ScanItem,
        VersionId,
        git::{
            GitExecutionLimits, GitMergeStrategy, GitMirrorManager, GitRepoTarget, GitRunError,
            GitScanMode, LocalMirror, RepoKey, RepoLocator,
        },
        ordered::{OrderedContentCapabilities, OrderedContentSource},
    },
    coordination::ShardSpec,
    identity::{
        FenceEpoch, FindingId, ObjectVersionId, ObservationId, OccurrenceId, OpId, PolicyHash,
        RuleFingerprint, RunId, ShardId, StableItemId, TenantId, TenantSecretKey, WorkerId,
        derive_rule_fingerprint,
    },
    persistence::{
        DoneLedgerCommitReceipt, DoneLedgerKey, DoneLedgerStatus, FindingsCommitReceipt,
        WriteContext,
    },
};
use gossip_coordination::{
    AcquireScratch, CoordinationBackend, CursorSemantics, CursorUpdate as CoordCursorUpdate,
    InMemoryCoordinator as CoordinationInMemoryCoordinator, InitialShardInput, RunConfig,
    RunManagement, ShardClaiming, ShardFilter, ShardStatus,
};
use gossip_frontier::{ShardSpecScratch, range_shard_ref};
use gossip_orchestrator::{
    FilesystemShardPayload, FilesystemSourceMode, GitShardPayload, NormalizedGitSelection,
};
use gossip_persistence_inmemory::{CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink};
use scanner_git::derive_repo_id;
use scanner_scheduler::events::{CoreEvent, EventOutput, NullEventOutput};
use tempfile::tempdir;

use crate::{
    CancellationToken, FsScanConfig, GitScanConfig, OwnedCoreEvent, ScanReport, ScanRuntimeError,
    build_runtime_engine,
    commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
    commit_sink::{FindingRecord, FindingsBatch, ItemMeta},
    coordination_sink::{
        CommitProgressRecord, CoordinationEventRecorder, MirrorErrorClass, StageSignal,
        StoredGitEvent,
    },
    git_mirror::LocalMirrorManager,
    git_persistence::{GitPersistenceBackend, GitPersistenceOp},
    join_scoped,
    ordered_content::OrderedContentSkipReason,
    test_fixtures::{init_git_repo, run_git_in},
};

// ============================================================================
// Test doubles
// ============================================================================

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StubFindings(pub(super) u8);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct StubDoneLedger(pub(super) u8);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub(super) struct TestGitBackendError {
    pub(super) message: &'static str,
}

#[derive(Debug, Default)]
pub(super) struct TestGitBackendState {
    pub(super) kv: BTreeMap<Vec<u8>, Vec<u8>>,
    pub(super) batch_call_count: usize,
    pub(super) fail_after_n_batches: Option<usize>,
}

#[derive(Debug, Clone, Default)]
pub(super) struct TestGitBackend {
    pub(super) state: Arc<Mutex<TestGitBackendState>>,
}

impl TestGitBackend {
    pub(super) fn batch_call_count(&self) -> usize {
        self.state
            .lock()
            .expect("git backend state lock")
            .batch_call_count
    }

    pub(super) fn fail_after_n_batches(&self, n: usize) {
        self.state
            .lock()
            .expect("git backend state lock")
            .fail_after_n_batches = Some(n);
    }

    pub(super) fn stored_keys(&self) -> Vec<Vec<u8>> {
        self.state
            .lock()
            .expect("git backend state lock")
            .kv
            .keys()
            .cloned()
            .collect()
    }
}

impl GitPersistenceBackend for TestGitBackend {
    type Error = TestGitBackendError;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self
            .state
            .lock()
            .expect("git backend state lock")
            .kv
            .get(key)
            .cloned())
    }

    fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
        let mut state = self.state.lock().expect("git backend state lock");
        if let Some(threshold) = state.fail_after_n_batches
            && state.batch_call_count >= threshold
        {
            return Err(TestGitBackendError {
                message: "injected persistence failure",
            });
        }
        state.batch_call_count += 1;
        for op in ops {
            match op {
                GitPersistenceOp::Put { key, value } => {
                    state.kv.insert(key.clone(), value.clone());
                }
                GitPersistenceOp::Delete { key } => {
                    state.kv.remove(key);
                }
            }
        }
        Ok(())
    }

    fn supports_atomic_batches(&self) -> bool {
        true
    }
}

// -- Recorder (CoordinationEventRecorder) -----------------------------------

#[derive(Debug, Default)]
pub(super) struct Recorder {
    pub(super) git_events: Mutex<Vec<StoredGitEvent>>,
    pub(super) progress: Mutex<Vec<CommitProgressRecord>>,
    pub(super) stage_signals: Mutex<Vec<StageSignal>>,
}

impl CoordinationEventRecorder for Recorder {
    fn record_core_event(&self, _shard_id: &str, _event: OwnedCoreEvent) -> anyhow::Result<()> {
        Ok(())
    }

    fn record_git_event(&self, _shard_id: &str, event: StoredGitEvent) -> anyhow::Result<()> {
        self.git_events.lock().expect("git events lock").push(event);
        Ok(())
    }

    fn record_commit_progress(
        &self,
        _shard_id: &str,
        event: CommitProgressRecord,
    ) -> anyhow::Result<()> {
        self.progress.lock().expect("progress lock").push(event);
        Ok(())
    }

    fn record_stage_signal(&self, _shard_id: &str, signal: StageSignal) -> anyhow::Result<()> {
        self.stage_signals
            .lock()
            .expect("stage signals lock")
            .push(signal);
        Ok(())
    }
}

// -- CapturingEventOutput ---------------------------------------------------

/// Capturing event sink that snapshots borrowed `CoreEvent`s into owned
/// values, preserving emitted event data after the original borrow ends.
#[derive(Default)]
pub(super) struct CapturingEventOutput {
    pub(super) events: Mutex<Vec<OwnedCoreEvent>>,
}

impl EventOutput for CapturingEventOutput {
    fn emit_core(&self, event: CoreEvent<'_>) {
        self.events
            .lock()
            .expect("capturing sink lock")
            .push(OwnedCoreEvent::from_core(event));
    }

    fn flush(&self) {}
}

impl CapturingEventOutput {
    pub(super) fn take(&self) -> Vec<OwnedCoreEvent> {
        std::mem::take(&mut *self.events.lock().expect("capturing sink lock"))
    }
}

// -- FailingMirrorManager ---------------------------------------------------

/// Mirror manager that unconditionally fails `sync_mirror` with a
/// permanent `GitRunError`. Callers propagate this as
/// `DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(_))`,
/// preserving the original error in the anyhow chain.
pub(super) struct FailingMirrorManager;

impl GitMirrorManager for FailingMirrorManager {
    fn sync_mirror(&mut self, _locator: &RepoLocator) -> Result<LocalMirror, GitRunError> {
        Err(GitRunError::permanent("injected mirror sync failure"))
    }
}

// -- MultiStepScriptedSource ------------------------------------------------

pub(super) struct MultiStepScriptedSource {
    pub(super) pages: std::collections::VecDeque<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
    pub(super) fill_page_calls: Arc<AtomicU64>,
    pub(super) cancel_on_call: Option<(usize, CancellationToken)>,
    pub(super) call_count: usize,
}

impl MultiStepScriptedSource {
    pub(super) fn new(
        pages: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
    ) -> (Self, Arc<AtomicU64>) {
        let fill_page_calls = Arc::new(AtomicU64::new(0));
        (
            Self {
                pages: pages.into(),
                fill_page_calls: Arc::clone(&fill_page_calls),
                cancel_on_call: None,
                call_count: 0,
            },
            fill_page_calls,
        )
    }
}

impl Drop for MultiStepScriptedSource {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(
                self.pages.is_empty(),
                "MultiStepScriptedSource: {} scripted page(s) were never consumed",
                self.pages.len()
            );
        }
    }
}

impl OrderedContentSource for MultiStepScriptedSource {
    fn capabilities(&self) -> OrderedContentCapabilities {
        OrderedContentCapabilities::default()
    }

    fn fill_page(
        &mut self,
        _shard: &ShardSpec,
        _cursor: &Cursor,
        _budgets: gossip_contracts::connector::Budgets,
    ) -> Result<Option<PageBuf<ScanItem>>, EnumerateError> {
        self.fill_page_calls.fetch_add(1, Ordering::Relaxed);
        let index = self.call_count;
        self.call_count += 1;
        if let Some((target, ref token)) = self.cancel_on_call
            && index == target
        {
            token.cancel();
        }
        self.pages
            .pop_front()
            .expect("MultiStepScriptedSource: unexpected extra fill_page call")
    }

    /// Returns a fixed benign payload (`b"clean"`); the scripted page loop
    /// exercises enumeration and commit ordering, not content-specific findings.
    fn open(
        &mut self,
        _item_ref: &ItemRef,
        _budgets: gossip_contracts::connector::Budgets,
    ) -> Result<Box<dyn std::io::Read + Send>, ReadError> {
        Ok(Box::new(std::io::Cursor::new(b"clean".to_vec())))
    }
}

// ============================================================================
// Helper functions
// ============================================================================

pub(super) fn tenant() -> TenantId {
    TenantId::from_bytes([0x11; 32])
}

pub(super) fn run() -> RunId {
    RunId::from_raw(7)
}

pub(super) fn worker(id: u64) -> WorkerId {
    WorkerId::from_raw(id)
}

pub(super) fn policy_hash() -> PolicyHash {
    PolicyHash::from_bytes([0x22; 32])
}

pub(super) fn test_rule_fingerprint(rule_id: u32) -> RuleFingerprint {
    let name = format!("test-rule-{rule_id}");
    derive_rule_fingerprint(&name)
}

pub(super) fn write_context() -> WriteContext {
    WriteContext::new(
        TenantId::from_bytes([0x11; 32]),
        PolicyHash::from_bytes([0x22; 32]),
        RunId::from_raw(3),
        ShardId::from_raw(4),
        FenceEpoch::from_raw(5),
    )
}

pub(super) fn tenant_secret_key() -> TenantSecretKey {
    TenantSecretKey::from_bytes([0x33; 32])
}

pub(super) fn recorder() -> Arc<dyn CoordinationEventRecorder> {
    Arc::new(Recorder::default())
}

pub(super) fn test_run_config(lease_duration_ms: u64) -> RunConfig {
    RunConfig::try_new(CursorSemantics::Completed, lease_duration_ms, None).expect("run config")
}

pub(super) fn base_scan_config(path: impl AsRef<Path>) -> FsScanConfig {
    FsScanConfig::new(path.as_ref().to_path_buf())
}

pub(super) fn filesystem_payload(path: &Path, mode: FilesystemSourceMode) -> Vec<u8> {
    FilesystemShardPayload::new(
        mode,
        path.canonicalize()
            .expect("test filesystem payload paths must canonicalize"),
    )
    .encode()
    .expect("test filesystem payload must encode")
}

pub(super) fn worker_identity(path: &Path) -> WorkerIdentity {
    WorkerIdentity::new(
        tenant(),
        run(),
        worker(13),
        policy_hash(),
        tenant_secret_key(),
        base_scan_config(path),
        recorder(),
    )
}

pub(super) fn base_git_scan_config(path: impl AsRef<Path>) -> GitScanConfig {
    GitScanConfig::new(path.as_ref().to_path_buf())
}

pub(super) fn git_worker_identity(path: &Path) -> GitWorkerIdentity {
    git_worker_identity_with_recorder(path, recorder())
}

pub(super) fn git_worker_identity_with_recorder(
    path: &Path,
    recorder: Arc<dyn CoordinationEventRecorder>,
) -> GitWorkerIdentity {
    GitWorkerIdentity::new(
        tenant(),
        run(),
        worker(17),
        policy_hash(),
        tenant_secret_key(),
        base_git_scan_config(path),
        recorder,
    )
}

pub(super) fn successor_bytes(bytes: &[u8]) -> Vec<u8> {
    let mut next = bytes.to_vec();
    next.push(0);
    next
}

/// Git repo fixture seeded with a secret so scans produce at least one finding.
pub(super) fn create_git_repo_fixture_with_secrets() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    init_git_repo(
        dir.path(),
        "distributed-runtime-tests@example.com",
        "Distributed Runtime Tests",
    );
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");
    run_git_in(dir.path(), &["add", "."]);
    run_git_in(dir.path(), &["commit", "-q", "-m", "fixture"]);
    dir
}

/// Git repo fixture with benign content that produces zero findings.
pub(super) fn create_clean_git_repo_fixture() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    init_git_repo(
        dir.path(),
        "distributed-runtime-tests@example.com",
        "Distributed Runtime Tests",
    );
    fs::write(dir.path().join("readme.txt"), "hello world\n").expect("write fixture");
    run_git_in(dir.path(), &["add", "."]);
    run_git_in(dir.path(), &["commit", "-q", "-m", "fixture"]);
    dir
}

pub(super) fn git_repo_key(path: &Path) -> RepoKey {
    let canonical = path.canonicalize().expect("canonical repo path");
    RepoKey::for_local_path(canonical.as_os_str().as_encoded_bytes()).expect("repo key")
}

pub(super) fn git_repo_target(path: &Path) -> GitRepoTarget {
    let canonical = path.canonicalize().expect("canonical repo path");
    GitRepoTarget::new(
        git_repo_key(path),
        RepoLocator::local_path(canonical.to_string_lossy().into_owned()),
    )
    .with_display_name("distributed/runtime-test-repo")
}

pub(super) fn git_payload(path: &Path) -> Vec<u8> {
    let repo_target = git_repo_target(path);
    let repo_id = derive_repo_id(tenant(), repo_target.repo_key());
    GitShardPayload::new(
        tenant(),
        repo_target,
        repo_id,
        NormalizedGitSelection::DefaultBranchOnly,
        GitScanMode::OdbBlobFast,
        GitMergeStrategy::AllParents,
        GitExecutionLimits::default(),
    )
    .encode()
    .expect("git shard payload")
}

pub(super) fn item_key(path: &str) -> ItemKey {
    ItemKey::try_from_slice(path.as_bytes()).expect("item key")
}

pub(super) fn item_meta() -> ItemMeta {
    ItemMeta {
        stable_item_id: StableItemId::from_bytes([0x44; 32]),
        version: None,
        size_hint: Some(128),
    }
}

pub(super) fn finding() -> FindingRecord {
    FindingRecord {
        rule_id: 7,
        start: 10,
        end: 20,
        norm_hash: [0x55; 32],
        confidence_score: 6,
    }
}

pub(super) fn clean_fixture() -> &'static str {
    "ordinary sample text for scanner tests"
}

pub(super) fn binary_fixture() -> [u8; 8] {
    [0x7F, b'E', b'L', b'F', 0, 1, 2, 3]
}

pub(super) fn setup_coordinator_with_connector_extra(
    connector_extra: &[Vec<u8>],
    lease_duration_ms: u64,
) -> CoordinationInMemoryCoordinator {
    let mut coordinator = CoordinationInMemoryCoordinator::new(lease_duration_ms);
    let now = wall_clock_now();
    coordinator
        .create_run(now, tenant(), run(), test_run_config(lease_duration_ms))
        .expect("create run");

    let mut scratch = ShardSpecScratch::new();
    let shard_entries: Vec<(ShardId, ShardSpec)> = connector_extra
        .iter()
        .enumerate()
        .map(|(idx, extra)| {
            let start = [idx as u8];
            let end = [(idx + 1) as u8];
            let spec_ref = range_shard_ref(&start, &end, extra.as_slice(), &mut scratch)
                .expect("range shard spec");
            (
                ShardId::from_raw(idx as u64 + 1),
                ShardSpec::try_from_ref(spec_ref).expect("owned shard spec"),
            )
        })
        .collect();
    let shards: Vec<InitialShardInput<'_>> = shard_entries
        .iter()
        .map(|(shard_id, spec)| {
            InitialShardInput::new(*shard_id, spec.as_ref(), CoordCursorUpdate::initial())
        })
        .collect();
    let _ = coordinator
        .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
        .expect("register shards");

    coordinator
}

pub(super) fn setup_coordinator_with_ranges(
    entries: &[(&Path, &[u8], &[u8])],
    lease_duration_ms: u64,
) -> CoordinationInMemoryCoordinator {
    let mut coordinator = CoordinationInMemoryCoordinator::new(lease_duration_ms);
    let now = wall_clock_now();
    coordinator
        .create_run(now, tenant(), run(), test_run_config(lease_duration_ms))
        .expect("create run");

    let mut scratch = ShardSpecScratch::new();
    let shard_entries: Vec<(ShardId, ShardSpec)> = entries
        .iter()
        .enumerate()
        .map(|(idx, (path, start, end))| {
            let connector_extra = filesystem_payload(path, FilesystemSourceMode::DirectoryRoot);
            let spec_ref = range_shard_ref(start, end, &connector_extra, &mut scratch)
                .expect("range shard spec");
            (
                ShardId::from_raw(idx as u64 + 1),
                ShardSpec::try_from_ref(spec_ref).expect("owned shard spec"),
            )
        })
        .collect();
    let shards: Vec<InitialShardInput<'_>> = shard_entries
        .iter()
        .map(|(shard_id, spec)| {
            InitialShardInput::new(*shard_id, spec.as_ref(), CoordCursorUpdate::initial())
        })
        .collect();
    let _ = coordinator
        .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
        .expect("register shards");

    coordinator
}

pub(super) fn setup_coordinator_with_git_shard(
    path: &Path,
    cursor: CoordCursorUpdate<'_>,
    lease_duration_ms: u64,
) -> CoordinationInMemoryCoordinator {
    setup_coordinator_with_git_shard_and_config(path, cursor, test_run_config(lease_duration_ms))
}

pub(super) fn setup_coordinator_with_git_shard_and_config(
    path: &Path,
    cursor: CoordCursorUpdate<'_>,
    run_config: RunConfig,
) -> CoordinationInMemoryCoordinator {
    let mut coordinator = CoordinationInMemoryCoordinator::new(run_config.lease_duration());
    let now = wall_clock_now();
    coordinator
        .create_run(now, tenant(), run(), run_config)
        .expect("create run");

    let repo_key = git_repo_key(path);
    let range_end = successor_bytes(repo_key.as_bytes());
    let payload = git_payload(path);
    let mut scratch = ShardSpecScratch::new();
    let spec_ref = range_shard_ref(repo_key.as_bytes(), &range_end, &payload, &mut scratch)
        .expect("git range shard spec");
    let shard_spec = ShardSpec::try_from_ref(spec_ref).expect("owned git shard spec");
    let shards = [InitialShardInput::new(
        ShardId::from_raw(1),
        shard_spec.as_ref(),
        cursor,
    )];
    let _ = coordinator
        .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
        .expect("register shards");

    coordinator
}

pub(super) fn claim_lease(
    coordinator: &mut CoordinationInMemoryCoordinator,
    identity: &WorkerIdentity,
) -> ShardLease {
    let mut scratch = AcquireScratch::new();
    let now = wall_clock_now();
    let instant = Instant::now();
    let acquired = coordinator
        .claim_next_available(
            now,
            identity.tenant,
            identity.run,
            identity.worker,
            &mut scratch,
        )
        .expect("claim next available");
    build_lease_from_acquire(acquired, identity, now, instant).expect("runtime lease")
}

pub(super) fn claim_coordination_lease(
    coordinator: &mut CoordinationInMemoryCoordinator,
    worker_id: WorkerId,
) -> gossip_coordination::Lease {
    let mut scratch = AcquireScratch::new();
    coordinator
        .claim_next_available(wall_clock_now(), tenant(), run(), worker_id, &mut scratch)
        .expect("claim next available")
        .lease
}

pub(super) fn shard_summaries(
    coordinator: &CoordinationInMemoryCoordinator,
) -> Vec<gossip_coordination::ShardSummary> {
    let mut summaries = Vec::new();
    coordinator
        .list_shards_into(
            wall_clock_now(),
            tenant(),
            run(),
            ShardFilter::all(),
            &mut summaries,
        )
        .expect("list shards");
    summaries
}

pub(super) fn run_progress(
    coordinator: &CoordinationInMemoryCoordinator,
) -> gossip_coordination::RunProgress {
    coordinator
        .get_run_progress(wall_clock_now(), tenant(), run())
        .expect("run progress")
}

pub(super) fn make_receipt_sink() -> (
    CommitPipeline<InMemoryFindingsSink, InMemoryDoneLedger>,
    ReceiptCommitSink,
    Arc<Recorder>,
) {
    let recorder = Arc::new(Recorder::default());
    let pipeline = CommitPipeline::start(
        InMemoryFindingsSink::new(),
        InMemoryDoneLedger::new(),
        CommitPipelineConfig {
            execution_queue_capacity: 1,
            outcome_queue_capacity: 1,
        },
        CancellationToken::new(),
    )
    .expect("pipeline should start");
    let sink = ReceiptCommitSink::new(
        recorder.clone(),
        Arc::from("shard-a"),
        write_context(),
        tenant_secret_key(),
        Arc::new(test_rule_fingerprint),
        pipeline.sender(),
    );

    (pipeline, sink, recorder)
}

pub(super) struct SinkSnapshot {
    pub(super) done_keys: Vec<DoneLedgerKey>,
    pub(super) finding_ids: Vec<FindingId>,
    pub(super) occurrence_ids: Vec<OccurrenceId>,
    pub(super) observation_ids: Vec<ObservationId>,
}

pub(super) fn snapshot_sink_state(
    findings_sink: &InMemoryFindingsSink,
    done_ledger: &InMemoryDoneLedger,
    label: &str,
) -> SinkSnapshot {
    SinkSnapshot {
        done_keys: done_ledger
            .snapshot()
            .unwrap_or_else(|e| panic!("{label} done-ledger snapshot: {e}"))
            .into_iter()
            .map(|r| r.key())
            .collect(),
        finding_ids: findings_sink
            .findings_snapshot()
            .unwrap_or_else(|e| panic!("{label} findings snapshot: {e}"))
            .into_iter()
            .map(|r| r.finding_id())
            .collect(),
        occurrence_ids: findings_sink
            .occurrences_snapshot()
            .unwrap_or_else(|e| panic!("{label} occurrences snapshot: {e}"))
            .into_iter()
            .map(|r| r.occurrence_id())
            .collect(),
        observation_ids: findings_sink
            .observations_snapshot()
            .unwrap_or_else(|e| panic!("{label} observations snapshot: {e}"))
            .into_iter()
            .map(|r| r.observation_id())
            .collect(),
    }
}

// -- Suffix-protocol test helpers -------------------------------------------

pub(super) fn suffix_test_item(name: &[u8], size: u64) -> ScanItem {
    ScanItem::new(
        ItemKey::try_from_slice(name).expect("item key"),
        ItemRef::try_from_slice(name).expect("item ref"),
        StableItemId::from_bytes([name[0]; 32]),
        VersionId::Strong(ObjectVersionId::from_version_bytes(name)),
    )
    .with_size_hint(size)
}

/// Run the source-generic page loop with a scripted source.
///
/// Uses a real engine, commit pipeline, and done-ledger so the first
/// page completes durable commit before subsequent pages exercise
/// suffix-protocol edge cases.
pub(super) fn run_suffix_protocol_test(
    pages: Vec<Result<Option<PageBuf<ScanItem>>, EnumerateError>>,
) -> Result<(OrderedSourceAssignmentOutcome, u64), ScanRuntimeError> {
    let (source, fill_page_calls) = MultiStepScriptedSource::new(pages);
    let cancel = CancellationToken::new();
    run_suffix_protocol_test_core(source, cancel, fill_page_calls)
}

/// Core pipeline setup for suffix-protocol tests, accepting a
/// pre-configured source and externally-provided cancellation token.
pub(super) fn run_suffix_protocol_test_core(
    mut source: MultiStepScriptedSource,
    cancel: CancellationToken,
    fill_page_calls: Arc<AtomicU64>,
) -> Result<(OrderedSourceAssignmentOutcome, u64), ScanRuntimeError> {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/suffix"));
    let lease = claim_lease(&mut coordinator, &identity);

    let done_ledger = InMemoryDoneLedger::new();
    let scan_config = lease
        .scan_config()
        .clone()
        .with_workers(1)
        .with_persist_findings(true);

    let engine = build_runtime_engine(
        scan_config.rules_file.as_deref(),
        &scan_config.transform_filter,
        scan_config.decode_depth,
        scan_config.anchor_mode,
    )
    .expect("engine");

    let pipeline = CommitPipeline::start(
        InMemoryFindingsSink::new(),
        done_ledger.clone(),
        CommitPipelineConfig {
            execution_queue_capacity: 64,
            outcome_queue_capacity: 64,
        },
        cancel.clone(),
    )
    .expect("pipeline");

    let recorder = Arc::new(Recorder::default());
    let rule_fingerprint = {
        let engine = Arc::clone(&engine);
        Arc::new(move |rule_id: u32| {
            RuleFingerprint::from_bytes(engine.rule_fingerprint_bytes(rule_id))
        }) as Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>
    };

    let (submitter, drainer) = pipeline.split();
    let commit = ReceiptCommitSink::new(
        recorder,
        Arc::clone(lease.shard_id_arc()),
        lease.write_context(),
        lease.tenant_secret_key(),
        rule_fingerprint,
        submitter,
    );

    let out = NullEventOutput;

    std::thread::scope(|scope| {
        let write_context = lease.write_context();
        let stage_handle = scope.spawn(move || drain_commit_stage(drainer, write_context, 64));

        let result = scan_ordered_source_with_engine(
            &mut source,
            &lease,
            &scan_config,
            &done_ledger,
            engine,
            &out,
            &commit,
            &cancel,
        );
        let submitted = commit.finish().expect("suffix test sink finish");
        let CommitStageDrainResult {
            committed_sequence_nos,
            ..
        } = join_scoped(stage_handle, "suffix test drain")
            .expect("suffix test drain join")
            .expect("suffix test drain");
        wait_for_submitted_commits(submitted, committed_sequence_nos)
            .expect("suffix test durable outcomes");
        result.map(|outcome| (outcome, fill_page_calls.load(Ordering::Relaxed)))
    })
}

// -- Git corrupt-blob fixture -----------------------------------------------

/// Create a git repo with a secret, then corrupt the loose blob object
/// so that decompression fails during scanning.
pub(super) fn create_git_repo_fixture_with_corrupt_blob() -> tempfile::TempDir {
    let dir = tempdir().expect("tempdir");
    init_git_repo(
        dir.path(),
        "distributed-runtime-tests@example.com",
        "Distributed Runtime Tests",
    );
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");
    run_git_in(dir.path(), &["add", "."]);
    run_git_in(dir.path(), &["commit", "-q", "-m", "fixture"]);

    // Locate and corrupt the blob loose object. Walk .git/objects
    // fan-out directories looking for loose files, then use `git
    // cat-file -t` (via the OID reconstructed from the path) to
    // identify the blob.
    let objects_dir = dir.path().join(".git/objects");
    let mut corrupted = false;
    for fan_entry in fs::read_dir(&objects_dir).expect("read objects dir") {
        let fan_entry = fan_entry.expect("fan entry");
        let fan_name = fan_entry.file_name();
        let fan_str = fan_name.to_string_lossy();
        // Fan-out directories are two hex characters; skip `info`/`pack`.
        if fan_str.len() != 2 || !fan_str.chars().all(|c| c.is_ascii_hexdigit()) {
            continue;
        }
        for obj_entry in fs::read_dir(fan_entry.path()).expect("read fan dir") {
            let obj_entry = obj_entry.expect("object entry");
            let obj_name = obj_entry.file_name();
            let oid = format!("{}{}", fan_str, obj_name.to_string_lossy());
            let output = std::process::Command::new("git")
                .arg("-C")
                .arg(dir.path())
                .args(["cat-file", "-t", &oid])
                .output()
                .expect("git cat-file");
            let kind = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if kind == "blob" {
                // Loose objects are read-only (mode 0o444); set
                // owner-writable before overwriting with invalid data.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let perms = fs::Permissions::from_mode(0o644);
                    fs::set_permissions(obj_entry.path(), perms).expect("set writable");
                }
                fs::write(obj_entry.path(), b"CORRUPT").expect("corrupt blob");
                corrupted = true;
                break;
            }
        }
        if corrupted {
            break;
        }
    }
    assert!(
        corrupted,
        "test fixture must contain at least one blob to corrupt"
    );
    dir
}
