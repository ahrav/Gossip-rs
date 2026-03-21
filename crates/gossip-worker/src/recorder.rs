//! Coordination event recorders for the worker binary.
//!
//! The no-op recorder discards all coordination events while satisfying the
//! runtime interface. It is replaced by a production telemetry recorder once
//! the coordination event sink is built.

use anyhow::Result as AnyhowResult;
use gossip_scanner_runtime::OwnedCoreEvent;
use gossip_scanner_runtime::coordination_sink::{
    CommitProgressRecord, CoordinationEventRecorder, StoredGitEvent,
};

/// Recorder that discards coordination events while still satisfying the runtime interface.
#[derive(Default)]
pub(crate) struct NoopCoordinationEventRecorder;

impl CoordinationEventRecorder for NoopCoordinationEventRecorder {
    fn record_core_event(&self, _shard_id: &str, _event: OwnedCoreEvent) -> AnyhowResult<()> {
        Ok(())
    }

    fn record_git_event(&self, _shard_id: &str, _event: StoredGitEvent) -> AnyhowResult<()> {
        Ok(())
    }

    fn record_commit_progress(
        &self,
        _shard_id: &str,
        _event: CommitProgressRecord,
    ) -> AnyhowResult<()> {
        Ok(())
    }
}
