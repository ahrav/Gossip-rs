//! Distributed runtime entrypoint wired through `ScanDriver::run`.
//!
//! This module keeps distributed orchestration intentionally small and
//! explicit: each lease goes through a done-ledger gate, then runs a single
//! assignment with coordinator-backed event and commit sinks.
//!
//! # Lease lifecycle
//!
//! ```text
//! acquire_shard ─► is_shard_done? ──yes──► release_shard (skip)
//!                       │ no
//!                       ▼
//!               execute_assignment
//!                       │
//!                       ▼
//!              complete_shard ─► mark_shard_done
//! ```
//!
//! The `complete_shard` → `mark_shard_done` ordering guarantees that if the
//! process crashes between those two calls, the shard may be retried but the
//! system never observes a done-ledger entry without the corresponding
//! report and checkpoint metadata. This requires `complete_shard` to be
//! idempotent (or at-least-once tolerant) on coordinators that support
//! re-lease after failure.
//!
//! # Sink wiring
//!
//! Each shard gets its own `CoordinationEventSink` (for event telemetry)
//! and `DurableCommitSink` (for identity-chain persistence). The durable
//! sink derives `norm_hash → secret_hash → finding_id → occurrence_id`
//! from engine findings and records them through the shared
//! `CoordinationEventRecorder`.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{Error as AnyError, Result};
use gossip_contracts::identity::{TenantId, TenantSecretKey};
use gossip_scan_driver::{Assignment, CancellationToken, CursorUpdate, ScanReport};

use crate::commit_sink::DurableCommitSink;
use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, CoordinationEventSink, IdentityChainRecord,
    StoredCoreEvent, StoredGitEvent,
};
use crate::{RuntimeEngineConfig, ScanBudgets, ScanRuntimeError, execute_assignment_with_config};

/// Lease payload consumed by the distributed runtime.
///
/// Bundles a scan [`Assignment`] with the tenant identity needed for
/// finding-level secret hash derivation. One lease corresponds to one
/// shard from the coordination layer.
#[derive(Clone, Debug)]
pub struct ShardLease {
    /// Unique shard identifier used for done-ledger tracking.
    pub shard_id: String,
    /// Scan assignment to execute for this shard.
    pub assignment: Assignment,
    /// Tenant owning this shard, used for identity derivation.
    pub tenant_id: TenantId,
    /// Tenant secret key used for secret hash derivation.
    pub tenant_secret_key: TenantSecretKey,
}

/// Coordinator surface required by the distributed runtime.
///
/// Implementors must guarantee:
///
/// - `acquire_shard` returns `None` when no more work is available (the
///   worker loop terminates on `None`).
/// - `complete_shard` is idempotent or at-least-once tolerant, because
///   crash recovery may replay the call.
/// - `mark_shard_done` is called only after `complete_shard` succeeds.
/// - The `event_recorder` is safe to share across the event and commit
///   sinks for a single shard.
pub trait DistributedCoordinator: Send + Sync {
    /// Acquire the next lease to process, or `None` when no work remains.
    fn acquire_shard(&self) -> Result<Option<ShardLease>>;
    /// Release a lease without marking it complete (used by done-ledger skips).
    fn release_shard(&self, lease: &ShardLease) -> Result<()>;
    /// Mark one lease complete with optional checkpoint metadata.
    fn complete_shard(
        &self,
        lease: &ShardLease,
        checkpoint: Option<CursorUpdate>,
        report: ScanReport,
    ) -> Result<()>;
    /// Query done-ledger status before scanning a shard.
    fn is_shard_done(&self, shard_id: &str) -> Result<bool>;
    /// Persist done-ledger completion after successful scan.
    fn mark_shard_done(&self, shard_id: &str) -> Result<()>;
    /// Shared recorder used by both event and commit sinks.
    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder>;
}

/// Runtime config for distributed scans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRuntimeConfig {
    /// Scan execution budget controls applied to every shard assignment.
    pub budgets: ScanBudgets,
}

/// Summary report from one [`run_worker`] invocation.
///
/// Invariant: `leases_seen == shards_scanned + shards_skipped_done`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    /// Total number of leases dequeued from the coordinator (including skips).
    pub leases_seen: u64,
    /// Number of shards that were actually scanned.
    pub shards_scanned: u64,
    /// Number of shards skipped because the done-ledger already marked them complete.
    pub shards_skipped_done: u64,
}

/// Distributed runtime error.
///
/// Distinguishes coordinator-layer failures (network, locking, persistence)
/// from scan-runtime failures (engine init, driver crashes) so callers can
/// apply different retry or escalation strategies.
#[derive(Debug)]
pub enum DistributedRuntimeError {
    /// The coordinator returned an error (acquire, release, or complete).
    Coordinator(AnyError),
    /// The scan runtime failed while executing an assignment.
    Runtime(ScanRuntimeError),
}

impl fmt::Display for DistributedRuntimeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Coordinator(error) => write!(f, "coordinator error: {error}"),
            Self::Runtime(error) => write!(f, "runtime error: {error}"),
        }
    }
}

impl std::error::Error for DistributedRuntimeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Coordinator(error) => Some(error.as_ref()),
            Self::Runtime(error) => Some(error),
        }
    }
}

impl From<ScanRuntimeError> for DistributedRuntimeError {
    fn from(value: ScanRuntimeError) -> Self {
        Self::Runtime(value)
    }
}

/// Run the distributed worker loop until no more shards are available.
///
/// For each lease the runtime:
/// 1. checks the done ledger and releases already-complete shards without scanning,
/// 2. executes the assignment with coordinator-backed event and commit sinks,
/// 3. records completion before marking the shard done.
///
/// The `complete_shard` -> `mark_shard_done` ordering is intentional: if the
/// process crashes between those calls, the shard may be retried, but the system
/// never observes a done-ledger entry without the corresponding report and
/// checkpoint metadata. `DistributedCoordinator::complete_shard` implementations
/// must therefore be idempotent (or at-least-once tolerant) for any coordinator
/// that supports shard re-lease after a failure.
pub fn run_worker(
    coordinator: &dyn DistributedCoordinator,
    config: DistributedRuntimeConfig,
) -> Result<DistributedRunReport, DistributedRuntimeError> {
    let recorder = coordinator.event_recorder();
    let mut report = DistributedRunReport::default();

    loop {
        let Some(lease) = coordinator
            .acquire_shard()
            .map_err(DistributedRuntimeError::Coordinator)?
        else {
            break;
        };
        report.leases_seen = report.leases_seen.saturating_add(1);

        if coordinator
            .is_shard_done(&lease.shard_id)
            .map_err(DistributedRuntimeError::Coordinator)?
        {
            coordinator
                .release_shard(&lease)
                .map_err(DistributedRuntimeError::Coordinator)?;
            report.shards_skipped_done = report.shards_skipped_done.saturating_add(1);
            continue;
        }

        let sink = CoordinationEventSink::new(Arc::clone(&recorder), lease.shard_id.clone());
        let commit = DurableCommitSink::new(
            Arc::clone(&recorder),
            lease.shard_id.clone(),
            lease.tenant_id,
            lease.tenant_secret_key,
        );
        let cancel = CancellationToken::new();

        // Build execution config with commit-sink persistence enabled so
        // findings flow through the DurableCommitSink for identity derivation.
        let mut runtime = config.budgets.to_execution_config()?;
        runtime.filesystem.emit_findings_to_commit_sink = true;

        let outcome = execute_assignment_with_config(
            &lease.assignment,
            runtime,
            &RuntimeEngineConfig::default(),
            &sink,
            &commit,
            &cancel,
        )
        .map_err(DistributedRuntimeError::Runtime)?;

        coordinator
            .complete_shard(&lease, outcome.checkpoint_hint, outcome.report)
            .map_err(DistributedRuntimeError::Coordinator)?;
        coordinator
            .mark_shard_done(&lease.shard_id)
            .map_err(DistributedRuntimeError::Coordinator)?;

        report.shards_scanned = report.shards_scanned.saturating_add(1);
    }

    Ok(report)
}

/// In-memory distributed coordinator for tests and local harnesses.
///
/// All state is held behind a single `Mutex` and is `Clone`-safe via `Arc`.
/// This coordinator is intentionally **not** idempotent for `complete_shard`:
/// duplicate calls produce duplicate entries, which is useful for testing
/// crash-recovery semantics (see the `complete_shard_duplicate_call` test).
#[derive(Clone, Default)]
pub struct InMemoryCoordinator {
    state: Arc<Mutex<InMemoryCoordinatorState>>,
}

#[derive(Default)]
struct InMemoryCoordinatorState {
    queue: VecDeque<ShardLease>,
    done: HashSet<String>,
    released: Vec<String>,
    completed: Vec<CompletedShard>,
    core_events: Vec<(String, StoredCoreEvent)>,
    git_events: Vec<(String, StoredGitEvent)>,
    commit_progress: Vec<(String, CommitProgressRecord)>,
    identity_records: Vec<(String, IdentityChainRecord)>,
}

#[derive(Clone, Debug)]
struct CompletedShard {
    shard_id: String,
    checkpoint: Option<CursorUpdate>,
    report: ScanReport,
}

impl InMemoryCoordinator {
    /// Creates a coordinator pre-loaded with the given lease queue.
    #[must_use]
    pub fn new(leases: Vec<ShardLease>) -> Self {
        let mut queue = VecDeque::new();
        queue.extend(leases);
        Self {
            state: Arc::new(Mutex::new(InMemoryCoordinatorState {
                queue,
                ..InMemoryCoordinatorState::default()
            })),
        }
    }

    /// Marks `shard_id` as done in the done-ledger so it will be skipped during scanning.
    pub fn mark_done(&self, shard_id: impl Into<String>) {
        self.state
            .lock()
            .expect("state lock")
            .done
            .insert(shard_id.into());
    }

    /// Returns a snapshot of all shard IDs currently in the done-ledger.
    #[must_use]
    pub fn done_set(&self) -> HashSet<String> {
        self.state.lock().expect("state lock").done.clone()
    }

    /// Returns the shard IDs that were released without being completed.
    #[must_use]
    pub fn released_shards(&self) -> Vec<String> {
        self.state.lock().expect("state lock").released.clone()
    }

    /// Returns all completed shards as `(shard_id, checkpoint, report)` tuples.
    #[must_use]
    pub fn completed_shards(&self) -> Vec<(String, Option<CursorUpdate>, ScanReport)> {
        self.state
            .lock()
            .expect("state lock")
            .completed
            .iter()
            .map(|entry| {
                (
                    entry.shard_id.clone(),
                    entry.checkpoint.clone(),
                    entry.report,
                )
            })
            .collect()
    }

    /// Returns all recorded core events as `(shard_id, event)` pairs.
    #[must_use]
    pub fn core_events(&self) -> Vec<(String, StoredCoreEvent)> {
        self.state.lock().expect("state lock").core_events.clone()
    }

    /// Returns all recorded identity chain records as `(shard_id, record)` pairs.
    #[must_use]
    pub fn identity_records(&self) -> Vec<(String, IdentityChainRecord)> {
        self.state
            .lock()
            .expect("state lock")
            .identity_records
            .clone()
    }
}

impl DistributedCoordinator for InMemoryCoordinator {
    fn acquire_shard(&self) -> Result<Option<ShardLease>> {
        Ok(self.state.lock().expect("state lock").queue.pop_front())
    }

    fn release_shard(&self, lease: &ShardLease) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .released
            .push(lease.shard_id.clone());
        Ok(())
    }

    fn complete_shard(
        &self,
        lease: &ShardLease,
        checkpoint: Option<CursorUpdate>,
        report: ScanReport,
    ) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .completed
            .push(CompletedShard {
                shard_id: lease.shard_id.clone(),
                checkpoint,
                report,
            });
        Ok(())
    }

    fn is_shard_done(&self, shard_id: &str) -> Result<bool> {
        Ok(self
            .state
            .lock()
            .expect("state lock")
            .done
            .contains(shard_id))
    }

    fn mark_shard_done(&self, shard_id: &str) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .done
            .insert(shard_id.to_owned());
        Ok(())
    }

    fn event_recorder(&self) -> Arc<dyn CoordinationEventRecorder> {
        Arc::new(self.clone())
    }
}

impl CoordinationEventRecorder for InMemoryCoordinator {
    fn record_core_event(&self, shard_id: &str, event: StoredCoreEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .core_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_git_event(&self, shard_id: &str, event: StoredGitEvent) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .git_events
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_commit_progress(&self, shard_id: &str, event: CommitProgressRecord) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .commit_progress
            .push((shard_id.to_owned(), event));
        Ok(())
    }

    fn record_identity_chain(&self, shard_id: &str, record: IdentityChainRecord) -> Result<()> {
        self.state
            .lock()
            .expect("state lock")
            .identity_records
            .push((shard_id.to_owned(), record));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use gossip_contracts::{connector::Cursor, coordination::ShardSpec, identity::PolicyHash};
    use gossip_scan_driver::{AssignmentSource, ConnectorKind};
    use tempfile::tempdir;

    use super::*;

    fn fs_lease(shard_id: &str, path: &std::path::Path) -> ShardLease {
        ShardLease {
            shard_id: shard_id.to_owned(),
            assignment: Assignment {
                job_id: format!("job-{shard_id}"),
                connector_kind: ConnectorKind::Filesystem,
                connector_instance_id: path.display().to_string(),
                policy_hash: PolicyHash::from_bytes([0x55; 32]),
                shard_spec: ShardSpec::with_range([], []),
                cursor: Cursor::initial(),
                source: AssignmentSource::Filesystem {
                    root: path.to_path_buf(),
                },
            },
            tenant_id: TenantId::from_bytes([0xAA; 32]),
            tenant_secret_key: TenantSecretKey::from_bytes([0xBB; 32]),
        }
    }

    fn git_lease(shard_id: &str, repo_root: &std::path::Path) -> ShardLease {
        ShardLease {
            shard_id: shard_id.to_owned(),
            assignment: Assignment {
                job_id: format!("job-{shard_id}"),
                connector_kind: ConnectorKind::Git,
                connector_instance_id: repo_root.display().to_string(),
                policy_hash: PolicyHash::from_bytes([0x55; 32]),
                shard_spec: ShardSpec::with_range([], []),
                cursor: Cursor::initial(),
                source: AssignmentSource::Git {
                    repo_root: repo_root.to_path_buf(),
                },
            },
            tenant_id: TenantId::from_bytes([0xAA; 32]),
            tenant_secret_key: TenantSecretKey::from_bytes([0xBB; 32]),
        }
    }

    /// Initialise a git repo at `dir` with one committed secret file.
    fn init_git_repo_with_secret(dir: &std::path::Path) {
        use std::process::Command;
        let run = |args: &[&str]| {
            let out = Command::new("git")
                .args(args)
                .current_dir(dir)
                .output()
                .expect("git command");
            assert!(
                out.status.success(),
                "git {:?} failed: {}",
                args,
                String::from_utf8_lossy(&out.stderr)
            );
        };
        run(&["init", "--initial-branch=main"]);
        run(&["config", "user.email", "test@test.com"]);
        run(&["config", "user.name", "Test"]);
        fs::write(dir.join("secret.txt"), "password=alpha-beta-gamma-delta")
            .expect("write fixture");
        run(&["add", "."]);
        run(&["commit", "-m", "initial"]);
    }

    #[test]
    fn run_worker_skips_done_shards_before_scan() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("secret.txt"), "password=already-done").expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![fs_lease("shard-1", dir.path())]);
        coordinator.mark_done("shard-1");

        let report =
            run_worker(&coordinator, DistributedRuntimeConfig::default()).expect("run worker");
        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 0);
        assert_eq!(report.shards_skipped_done, 1);
        assert_eq!(coordinator.released_shards(), vec!["shard-1".to_owned()]);
    }

    #[test]
    fn run_worker_persists_identity_chain_and_marks_done() {
        let dir = tempdir().expect("tempdir");
        // Secret must be ≥16 high-entropy chars to trigger builtin rules.
        fs::write(dir.path().join("secret.txt"), "password=xK9mP2qL7wN4vR8t")
            .expect("write fixture");

        let coordinator = InMemoryCoordinator::new(vec![fs_lease("shard-2", dir.path())]);

        let report =
            run_worker(&coordinator, DistributedRuntimeConfig::default()).expect("run worker");
        assert_eq!(report.leases_seen, 1);
        assert_eq!(report.shards_scanned, 1);
        assert_eq!(report.shards_skipped_done, 0);

        let done = coordinator.done_set();
        assert!(done.contains("shard-2"));

        let completed = coordinator.completed_shards();
        assert_eq!(completed.len(), 1);
        assert!(completed[0].2.items_scanned >= 1);

        let identities = coordinator.identity_records();
        assert!(!identities.is_empty());
    }

    /// Verifies that a git shard produces durable identity records before being
    /// marked done. GitScanDriver currently ignores the commit sink, so any
    /// findings discovered during a git scan are emitted as events but never
    /// persisted through the identity chain. The shard is still marked done,
    /// silently dropping findings.
    ///
    /// Verifies that calling `complete_shard` twice for the same lease produces
    /// duplicate entries in the `InMemoryCoordinator`. This confirms the trait
    /// implementation is NOT idempotent — a property that matters for crash+retry
    /// coordinators where a shard may be re-leased after a failure between
    /// `complete_shard` and `mark_shard_done`.
    #[test]
    fn complete_shard_duplicate_call_produces_duplicate_entry() {
        let dir = tempdir().expect("tempdir");
        fs::write(dir.path().join("dummy.txt"), "nothing-secret").expect("write fixture");

        let lease = fs_lease("idempotency-check", dir.path());
        let coordinator = InMemoryCoordinator::new(vec![]);
        let report = ScanReport::default();

        // First call.
        coordinator
            .complete_shard(&lease, None, report)
            .expect("first complete_shard");
        assert_eq!(
            coordinator.completed_shards().len(),
            1,
            "single call should produce one entry"
        );

        // Second (duplicate) call for the same shard.
        coordinator
            .complete_shard(&lease, None, report)
            .expect("second complete_shard");

        // If complete_shard were idempotent, len would still be 1.
        let completed = coordinator.completed_shards();
        assert_eq!(
            completed.len(),
            2,
            "InMemoryCoordinator::complete_shard is not idempotent — \
             duplicate call produces a second entry"
        );
        assert_eq!(completed[0].0, "idempotency-check");
        assert_eq!(completed[1].0, "idempotency-check");
    }

    /// Known failure: `GitScanDriver::run` takes `_commit` (unused) in
    /// `gossip-connectors/src/scan_driver.rs`. The fix belongs there —
    /// wire a commit channel through the git scan path, matching what
    /// `FsScanDriver` does with `forward_commits`.
    #[test]
    #[ignore = "GitScanDriver does not use commit sink — fix in gossip-connectors"]
    fn git_shard_produces_identity_records_through_commit_sink() {
        let dir = tempdir().expect("tempdir");
        init_git_repo_with_secret(dir.path());

        let coordinator = InMemoryCoordinator::new(vec![git_lease("git-1", dir.path())]);

        let report =
            run_worker(&coordinator, DistributedRuntimeConfig::default()).expect("run worker");
        assert_eq!(report.shards_scanned, 1, "git shard should complete");

        let done = coordinator.done_set();
        assert!(done.contains("git-1"), "shard should be marked done");

        // The critical assertion: identity records must be persisted before
        // the shard is marked done. If GitScanDriver ignores the commit sink,
        // this will be empty — findings are silently lost.
        let identities = coordinator.identity_records();
        assert!(
            !identities.is_empty(),
            "git shard marked done but no identity records were persisted — \
             GitScanDriver ignores the commit sink, so findings are silently dropped"
        );
    }
}
