//! Distributed runtime entrypoint wired through `ScanDriver::run`.
//!
//! This module keeps distributed orchestration intentionally small and explicit:
//! each lease goes through a done-ledger gate, then runs a single assignment
//! with coordinator-backed event/commit sinks.

use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::sync::{Arc, Mutex};

use anyhow::{Error as AnyError, Result};
use gossip_contracts::identity::{ConnectorTag, TenantId, TenantSecretKey};
use gossip_scan_driver::{Assignment, CancellationToken, ConnectorKind, CursorUpdate, ScanReport};

use crate::commit_sink::DurableCommitSink;
use crate::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, CoordinationEventSink, IdentityChainRecord,
    StoredCoreEvent, StoredGitEvent,
};
use crate::{execute_assignment_with_config, RuntimeEngineConfig, ScanBudgets, ScanRuntimeError};

/// Lease payload consumed by the distributed runtime.
#[derive(Clone, Debug)]
pub struct ShardLease {
    pub shard_id: String,
    pub assignment: Assignment,
    pub tenant_id: TenantId,
    pub tenant_secret_key: TenantSecretKey,
}

/// Coordinator surface required by the distributed runtime.
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
    pub budgets: ScanBudgets,
}

/// Summary report from one distributed run loop.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DistributedRunReport {
    pub leases_seen: u64,
    pub shards_scanned: u64,
    pub shards_skipped_done: u64,
}

/// Distributed runtime error.
#[derive(Debug)]
pub enum DistributedRuntimeError {
    Coordinator(AnyError),
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
            connector_tag_for_kind(lease.assignment.connector_kind),
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
            Some(&sink),
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

fn connector_tag_for_kind(kind: ConnectorKind) -> ConnectorTag {
    match kind {
        ConnectorKind::Filesystem => ConnectorTag::from_ascii(b"fs"),
        ConnectorKind::Git => ConnectorTag::from_ascii(b"git"),
        ConnectorKind::InMemory => ConnectorTag::from_ascii(b"inmem"),
    }
}

/// In-memory distributed coordinator for tests and local harnesses.
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

    pub fn mark_done(&self, shard_id: impl Into<String>) {
        self.state
            .lock()
            .expect("state lock")
            .done
            .insert(shard_id.into());
    }

    #[must_use]
    pub fn done_set(&self) -> HashSet<String> {
        self.state.lock().expect("state lock").done.clone()
    }

    #[must_use]
    pub fn released_shards(&self) -> Vec<String> {
        self.state.lock().expect("state lock").released.clone()
    }

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

    #[must_use]
    pub fn core_events(&self) -> Vec<(String, StoredCoreEvent)> {
        self.state.lock().expect("state lock").core_events.clone()
    }

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
        fs::write(dir.path().join("secret.txt"), "password=alpha").expect("write fixture");

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
