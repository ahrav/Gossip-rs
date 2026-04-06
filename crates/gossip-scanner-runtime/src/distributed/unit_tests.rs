//! Component-level unit tests for the distributed module.
//!
//! Covers individual types, configuration defaults, lease-uncertainty signalling,
//! armed deadline logic, result resolution, commit-sink bookkeeping, checkpoint
//! derivation, the suffix protocol state machine, persistence submission, and
//! advance-shard boundary validation.

use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ahash::AHashMap;

use anyhow::{Error as AnyError, anyhow};

// -- Test infrastructure from the sibling test_support module ----------------

use super::test_support::*;

// -- Re-exports from the distributed module's public API --------------------

use super::*;

// -- Submodule internals (pub(super) items) ---------------------------------

use super::commit_bridge::{
    CommitStageDrainResult, InFlightItem, ReceiptCommitSink, checkpoint_logical_time,
    drain_commit_stage, emit_ordered_summary, resolve_filesystem_lease_results,
    wait_for_submitted_commits,
};
use super::execution::{
    GitRepoPersistenceInput, oid_map_saturation_error, should_park_git_repo_failure,
    submit_git_repo_persistence,
};
use super::lease_ops::{
    ArmedLeaseDeadline, CLAIM_RACE_RETRY_DELAY, EMPTY_RANGE_SENTINEL_KEY, LeaseUncertaintySignal,
    advance_shard, build_lease_from_acquire, claim_retry_delay, deterministic_op_id,
    ensure_post_drain_lease_trust, mirror_error_class, park_shard_on_error,
    select_shard_completion, watch_lease_deadline,
};
use super::types::{
    OrderedSourceAssignmentOutcome, PageLoopTermination, ShardCompletionOutcome, wall_clock_now,
};

// -- External crate imports -------------------------------------------------

use gossip_contracts::{
    connector::{
        Cursor, EnumerateError, ErrorClass, ItemKey, PageBuf, PageState, ToxicDigest, VersionId,
    },
    coordination::{RestoredShardState, ShardSpec},
    identity::{
        FenceEpoch, LogicalTime, NormHash, ObjectVersionId, OpId, ShardId, ShardKey, StableItemId,
        TenantId,
    },
    persistence::{DoneLedgerCommitReceipt, DoneLedgerStatus, FindingsCommitReceipt},
};
use gossip_coordination::{
    AcquireScratch, CursorSemantics, CursorUpdate as CoordCursorUpdate,
    InMemoryCoordinator as CoordinationInMemoryCoordinator, InitialShardInput, OpKind, ParkError,
    ParkReason, RunManagement, ShardClaiming, ShardStatus,
};
use gossip_frontier::{ShardSpecScratch, range_shard_ref};
use gossip_orchestrator::{FilesystemShardPayload, FilesystemSourceMode};
use gossip_persistence_inmemory::{CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink};
use scanner_git::{FinalizeOutcome, OidBytes};
use scanner_scheduler::{source_kind::SourceKind, store::FsFindingRecord};
use tempfile::tempdir;

use crate::{
    CancellationToken, OwnedCoreEvent, ScanBudgets, ScanReport, ScanRuntimeError,
    checkpoint_aggregator::PrefixCheckpointAggregator,
    commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput, QueuedCommit},
    commit_sink::{CommitSink, FindingRecord, FindingsBatch, ItemMeta},
    coordination_sink::{CommitProgressRecord, GitFindingForPersistence, MirrorErrorClass},
    ordered_content::{OrderedContentReadStop, OrderedContentSkipReason},
    test_fixtures::{
        completed_unit as fixture_completed_unit,
        scanned_translation as fixture_scanned_translation, wait_until,
    },
};

// ============================================================================
// Type / config tests
// ============================================================================

#[test]
fn shard_lease_preserves_claimed_coordination_metadata() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    assert_eq!(lease.shard_id(), "ShardId(1)");
    assert_eq!(lease.lease().tenant(), tenant());
    assert_eq!(lease.lease().run(), run());
    assert_eq!(lease.lease().shard(), ShardId::from_raw(1));
    assert_eq!(lease.lease().fence(), FenceEpoch::from_raw(2));
    assert_eq!(lease.write_context().tenant_id(), tenant());
    assert_eq!(lease.write_context().policy_hash(), policy_hash());
    assert_eq!(lease.tenant_secret_key(), tenant_secret_key());
}

#[test]
fn distributed_persistence_clones_backend_handles() {
    let persistence = DistributedPersistence::new(StubFindings(1), StubDoneLedger(2));
    let cloned = persistence.clone();

    assert_eq!(persistence.findings_sink, StubFindings(1));
    assert_eq!(persistence.done_ledger, StubDoneLedger(2));
    assert_eq!(cloned.findings_sink, StubFindings(1));
    assert_eq!(cloned.done_ledger, StubDoneLedger(2));
}

#[test]
fn distributed_runtime_config_defaults_commit_queue_capacity() {
    let config = DistributedRuntimeConfig::default();

    assert_eq!(config.budgets, ScanBudgets::default());
    assert_eq!(
        config.commit_queue_capacity,
        NonZeroUsize::new(64).expect("hardcoded non-zero constant"),
    );
}

#[test]
fn distributed_runtime_error_exposes_variant_sources() {
    let coordinator = DistributedRuntimeError::Coordinator(AnyError::msg("coord boom"));
    assert_eq!(coordinator.to_string(), "coordinator error: coord boom");
    assert!(std::error::Error::source(&coordinator).is_some());

    let lease_uncertain =
        DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(10),
            observed: LogicalTime::from_raw(11),
        });
    assert_eq!(
        lease_uncertain.to_string(),
        "lease uncertainty: lease deadline elapsed during shard execution (deadline LogicalTime(10), observed LogicalTime(11))"
    );
    assert!(std::error::Error::source(&lease_uncertain).is_some());

    let runtime = DistributedRuntimeError::from(ScanRuntimeError::Driver(AnyError::msg("scan")));
    assert_eq!(
        runtime.to_string(),
        "runtime error: runtime execution failed: scan"
    );
    assert!(std::error::Error::source(&runtime).is_some());

    let durability = DistributedRuntimeError::Durability(AnyError::msg("commit boom"));
    assert_eq!(
        durability.to_string(),
        "durability pipeline error: commit boom"
    );
    assert!(std::error::Error::source(&durability).is_some());
}

#[test]
fn distributed_run_report_default_satisfies_invariant() {
    let report = DistributedRunReport::default();
    assert_eq!(report.leases_seen, 0);
    assert_eq!(report.shards_scanned, 0);
    assert_eq!(report.total_claim_ms, 0);
    assert_eq!(report.total_mirror_sync_ms, 0);
    assert_eq!(report.total_scan_ms, 0);
    assert_eq!(report.total_durable_receipt_ms, 0);
    assert_eq!(report.total_checkpoint_ms, 0);
    assert!(report.shards_scanned <= report.leases_seen);

    // Verify the invariant holds with non-zero fields and that
    // shards_scanned ≤ leases_seen remains true.
    let nonzero = DistributedRunReport {
        leases_seen: 10,
        shards_scanned: 7,
        total_claim_ms: 11,
        total_mirror_sync_ms: 13,
        total_scan_ms: 17,
        total_durable_receipt_ms: 19,
        total_checkpoint_ms: 23,
    };
    assert!(nonzero.shards_scanned <= nonzero.leases_seen);
}

// ============================================================================
// LeaseUncertaintySignal tests
// ============================================================================

#[test]
fn lease_uncertainty_signal_preserves_first_reason() {
    let signal = LeaseUncertaintySignal::default();
    assert!(signal.current().is_none(), "new signal should be empty");

    let first = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(10),
        observed: LogicalTime::from_raw(11),
    };
    let second = LeaseUncertainty::AdvanceStaleFence {
        presented: FenceEpoch::from_raw(1),
        current: FenceEpoch::from_raw(2),
    };

    assert!(signal.note(first), "first note() should record the reason");
    assert!(
        !signal.note(second),
        "second note() must not overwrite the first reason"
    );

    assert_eq!(
        signal.current(),
        Some(first),
        "second note() must not overwrite the first reason"
    );
}

#[test]
fn lease_uncertainty_signal_close_ignores_late_reason() {
    let signal = LeaseUncertaintySignal::default();
    signal.close();

    assert!(
        !signal.note(LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(10),
            observed: LogicalTime::from_raw(11),
        }),
        "closed signal must reject late deadline notes"
    );
    assert!(
        signal.current().is_none(),
        "closed signal must not surface a late deadline reason"
    );
}

#[test]
fn lease_uncertainty_signal_close_preserves_recorded_reason() {
    let signal = LeaseUncertaintySignal::default();
    let reason = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(10),
        observed: LogicalTime::from_raw(11),
    };
    assert!(signal.note(reason), "note should record the reason");
    signal.close();
    assert_eq!(
        signal.current(),
        Some(reason),
        "close() on a Recorded signal must preserve the recorded reason"
    );
}

#[test]
fn ensure_post_drain_lease_trust_ignores_late_reason_after_signal_closes() {
    let signal = LeaseUncertaintySignal::default();
    signal.close();

    assert!(
        ensure_post_drain_lease_trust(&signal).is_ok(),
        "closed signal must keep post-drain progress locally trustworthy"
    );
}

#[test]
fn ensure_post_drain_lease_trust_preserves_recorded_reason_after_signal_closes() {
    let signal = LeaseUncertaintySignal::default();
    let reason = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(10),
        observed: LogicalTime::from_raw(11),
    };

    assert!(signal.note(reason), "note should record the reason");
    signal.close();
    assert!(matches!(
        ensure_post_drain_lease_trust(&signal),
        Err(DistributedRuntimeError::LeaseUncertain(found)) if found == reason
    ));
}

#[test]
fn lease_uncertainty_close_before_note_loses_expiry() {
    let signal = LeaseUncertaintySignal::default();
    signal.close();

    assert!(
        !signal.note(LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(10),
            observed: LogicalTime::from_raw(11),
        }),
        "closed signal must reject late deadline notes"
    );
    assert!(
        signal.current().is_none(),
        "closed signal must not surface a late deadline reason"
    );
}

#[test]
fn lease_uncertainty_note_before_close_preserves_expiry() {
    let signal = LeaseUncertaintySignal::default();
    let reason = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(10),
        observed: LogicalTime::from_raw(11),
    };
    assert!(signal.note(reason), "note should record the reason");
    signal.close();
    assert_eq!(
        signal.current(),
        Some(reason),
        "close() on a Recorded signal must preserve the recorded reason"
    );
}

// ============================================================================
// ArmedLeaseDeadline tests
// ============================================================================

#[test]
fn armed_lease_deadline_rejects_elapsed_deadline() {
    let error = ArmedLeaseDeadline::arm_from(
        LogicalTime::from_raw(10),
        LogicalTime::from_raw(10),
        Instant::now(),
    )
    .expect_err("equal observation/deadline should report lease expiry");

    assert!(
        matches!(error, LeaseUncertainty::DeadlineElapsed { .. }),
        "expected DeadlineElapsed, got: {error:?}"
    );
}

#[test]
fn armed_lease_deadline_rejects_strictly_past_deadline() {
    let result = ArmedLeaseDeadline::arm_from(
        LogicalTime::from_raw(10),
        LogicalTime::from_raw(15), // strictly past the deadline
        Instant::now(),
    );
    assert!(matches!(
        result,
        Err(LeaseUncertainty::DeadlineElapsed {
            deadline,
            observed,
        }) if deadline.as_raw() == 10 && observed.as_raw() == 15
    ));
}

#[test]
fn armed_lease_deadline_anchors_to_original_observation_instant() {
    let monotonic_observed = Instant::now();
    let armed = ArmedLeaseDeadline::arm_from(
        LogicalTime::from_raw(250),
        LogicalTime::from_raw(100),
        monotonic_observed,
    )
    .expect("future deadline should arm successfully");

    assert_eq!(
        armed.monotonic_deadline.duration_since(monotonic_observed),
        Duration::from_millis(150),
        "monotonic deadline should preserve the original remaining lease window"
    );
}

#[test]
fn armed_lease_deadline_reports_elapsed_after_monotonic_deadline_passes() {
    let armed = ArmedLeaseDeadline::arm_from(
        LogicalTime::from_raw(20),
        LogicalTime::from_raw(10),
        Instant::now() - Duration::from_secs(1),
    )
    .expect("future logical deadline should arm successfully");

    assert!(
        matches!(
            armed.expiry_reason(),
            Some(LeaseUncertainty::DeadlineElapsed {
                deadline,
                observed: _
            }) if deadline == LogicalTime::from_raw(20)
        ),
        "expired monotonic deadline should surface a deadline-elapsed reason"
    );
}

// ============================================================================
// resolve_filesystem_lease_results tests
// ============================================================================

#[test]
fn resolve_filesystem_lease_results_prefers_scan_failure_over_drain_failure() {
    let scan_error = ScanRuntimeError::Driver(AnyError::msg("scan boom"));
    let submitted_error = anyhow!("submitted boom");
    let stage_error = anyhow!("drain boom");

    // All three inputs fail; the function must prefer scan errors over
    // submission and drain errors to surface the root cause.
    let error = resolve_filesystem_lease_results(
        Err(scan_error),
        Err(submitted_error),
        Ok(Err(stage_error)),
        None,
    )
    .expect_err("scan failure should win when all three paths fail");

    assert!(
        matches!(error, DistributedRuntimeError::Runtime(_)),
        "expected Runtime variant, got: {error:?}"
    );
    assert!(
        error.to_string().contains("scan boom"),
        "unexpected error: {error}"
    );
}

#[test]
fn resolve_filesystem_lease_results_returns_drain_failure_after_successful_scan() {
    let stage_error = anyhow!("drain boom");

    let error = resolve_filesystem_lease_results(
        Ok(OrderedSourceAssignmentOutcome {
            report: ScanReport::default(),
            termination: PageLoopTermination::Partial,
            resume_cursor: Cursor::initial(),
        }),
        Ok(Vec::new()),
        Ok(Err(stage_error)),
        None,
    )
    .expect_err("drain failure should surface after a successful scan");

    assert!(
        matches!(error, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {error:?}"
    );
    assert!(
        error.to_string().contains("drain boom"),
        "unexpected error: {error}"
    );
}

#[test]
fn resolve_filesystem_lease_results_maps_submitted_failure_to_durability() {
    let submitted_error = anyhow!("submitted boom");

    let error = resolve_filesystem_lease_results(
        Ok(OrderedSourceAssignmentOutcome {
            report: ScanReport::default(),
            termination: PageLoopTermination::Partial,
            resume_cursor: Cursor::initial(),
        }),
        Err(submitted_error),
        // stage_result is never reached because submitted fails first.
        Err(anyhow!("unused")),
        None,
    )
    .expect_err("submitted failure should surface as Durability");

    assert!(
        matches!(error, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {error:?}"
    );
    assert!(
        error.to_string().contains("submitted boom"),
        "unexpected error: {error}"
    );
}

#[test]
fn resolve_filesystem_lease_results_maps_drain_thread_panic_to_durability() {
    let panic_error = anyhow!("drain thread panicked");

    let error = resolve_filesystem_lease_results(
        Ok(OrderedSourceAssignmentOutcome {
            report: ScanReport::default(),
            termination: PageLoopTermination::Partial,
            resume_cursor: Cursor::initial(),
        }),
        Ok(Vec::new()),
        Err(panic_error),
        None,
    )
    .expect_err("thread panic should be a durability error");

    assert!(
        matches!(error, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {error:?}"
    );
    assert!(
        error.to_string().contains("drain thread panicked"),
        "unexpected error: {error}"
    );
}

#[test]
fn resolve_filesystem_lease_results_prefers_lease_uncertainty_over_cancellation_gaps() {
    let reason = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(20),
        observed: LogicalTime::from_raw(21),
    };

    let error = resolve_filesystem_lease_results(
        Ok(OrderedSourceAssignmentOutcome {
            report: ScanReport::default(),
            termination: PageLoopTermination::ExhaustedEmptyConfirmed,
            resume_cursor: Cursor::initial(),
        }),
        Err(anyhow!("submit cancelled after lease expiry")),
        Err(anyhow!("unused")),
        Some(reason),
    )
    .expect_err("lease uncertainty should win over cancellation-induced submission gaps");

    assert_eq!(error.to_string(), format!("lease uncertainty: {reason}"));
    assert!(matches!(
        error,
        DistributedRuntimeError::LeaseUncertain(actual) if actual == reason
    ));
}

#[test]
fn resolve_filesystem_lease_results_prefers_lease_uncertainty_over_scan_error() {
    let scan_error = ScanRuntimeError::Driver(AnyError::msg("scan boom"));
    let reason = LeaseUncertainty::DeadlineElapsed {
        deadline: LogicalTime::from_raw(20),
        observed: LogicalTime::from_raw(21),
    };

    let error = resolve_filesystem_lease_results(
        Err(scan_error),
        Err(anyhow!("submitted cancelled after lease expiry")),
        Err(anyhow!("unused")),
        Some(reason),
    )
    .expect_err("lease uncertainty should win over a concurrent scan error");

    assert_eq!(error.to_string(), format!("lease uncertainty: {reason}"));
    assert!(matches!(
        error,
        DistributedRuntimeError::LeaseUncertain(actual) if actual == reason
    ));
}

#[test]
fn resolve_filesystem_lease_results_returns_ok_on_all_success() {
    let outcome = OrderedSourceAssignmentOutcome {
        report: ScanReport::default(),
        termination: PageLoopTermination::Partial,
        resume_cursor: Cursor::initial(),
    };
    let submitted = vec![1, 2, 3];
    let drain_result = CommitStageDrainResult {
        aggregator: PrefixCheckpointAggregator::new(write_context(), 0, 16),
        committed_sequence_nos: vec![1, 2, 3],
    };

    let (returned_outcome, returned_submitted, returned_drain) =
        resolve_filesystem_lease_results(Ok(outcome), Ok(submitted), Ok(Ok(drain_result)), None)
            .expect("all-success inputs should return Ok");

    assert_eq!(returned_outcome.termination, PageLoopTermination::Partial);
    assert_eq!(returned_submitted, vec![1, 2, 3]);
    assert_eq!(returned_drain.committed_sequence_nos, vec![1, 2, 3]);
}

// ============================================================================
// select_shard_completion tests
// ============================================================================

#[test]
fn select_shard_completion_uses_recovered_cursor_for_partial_zero_commit_progress() {
    let completion = select_shard_completion(
        "shard-1",
        &Cursor::initial(),
        PageLoopTermination::Partial,
        None,
        Cursor::with_last_key(item_key("tenant/repo/recovered.txt")),
    )
    .expect("advanced resume cursor should preserve checkpoint progress");

    let ShardCompletionOutcome::Checkpoint { checkpoint } = completion else {
        panic!("partial recovery should checkpoint recovered progress, got: {completion:?}");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"tenant/repo/recovered.txt"
    );
}

// ============================================================================
// watch_lease_deadline tests
// ============================================================================

#[test]
fn watch_lease_deadline_records_uncertainty_and_cancels_when_open() {
    let signal = LeaseUncertaintySignal::default();
    let cancel = CancellationToken::new();

    // Monotonic deadline in the past triggers immediate expiry.
    let expired = Instant::now() - Duration::from_secs(1);
    watch_lease_deadline(
        ArmedLeaseDeadline {
            deadline: LogicalTime::from_raw(1),
            monotonic_deadline: expired,
        },
        cancel.clone(),
        Arc::new(AtomicBool::new(false)),
        signal.clone(),
    );

    assert!(cancel.is_cancelled(), "open signal should cancel on expiry");
    assert!(matches!(
        signal.current(),
        Some(LeaseUncertainty::DeadlineElapsed { deadline, .. })
            if deadline == LogicalTime::from_raw(1)
    ));
}

#[test]
fn watch_lease_deadline_ignores_expiry_after_signal_closes() {
    let signal = LeaseUncertaintySignal::default();
    signal.close();
    let cancel = CancellationToken::new();

    let expired = Instant::now() - Duration::from_secs(1);
    watch_lease_deadline(
        ArmedLeaseDeadline {
            deadline: LogicalTime::from_raw(1),
            monotonic_deadline: expired,
        },
        cancel.clone(),
        Arc::new(AtomicBool::new(false)),
        signal.clone(),
    );

    assert!(
        !cancel.is_cancelled(),
        "closed signal must suppress late deadline cancellation"
    );
    assert!(
        signal.current().is_none(),
        "closed signal must not surface a late deadline reason"
    );
}

#[test]
fn watch_lease_deadline_records_open_expiry_before_done_exit() {
    let signal = LeaseUncertaintySignal::default();
    let cancel = CancellationToken::new();

    let expired = Instant::now() - Duration::from_secs(1);
    watch_lease_deadline(
        ArmedLeaseDeadline {
            deadline: LogicalTime::from_raw(1),
            monotonic_deadline: expired,
        },
        cancel.clone(),
        Arc::new(AtomicBool::new(true)),
        signal.clone(),
    );

    assert!(
        cancel.is_cancelled(),
        "open signal must still cancel when expiry wins over done"
    );
    assert!(matches!(
        signal.current(),
        Some(LeaseUncertainty::DeadlineElapsed { deadline, .. })
            if deadline == LogicalTime::from_raw(1)
    ));
}

#[test]
fn watch_lease_deadline_exits_promptly_on_unpark() {
    let signal = LeaseUncertaintySignal::default();
    let cancel = CancellationToken::new();
    let done = Arc::new(AtomicBool::new(false));

    // Deadline far in the future — the watchdog should park, not fire.
    let far_future = Instant::now() + Duration::from_secs(60);
    let done_clone = Arc::clone(&done);
    let signal_clone = signal.clone();
    let cancel_clone = cancel.clone();
    let handle = std::thread::spawn(move || {
        watch_lease_deadline(
            ArmedLeaseDeadline {
                deadline: LogicalTime::from_raw(u64::MAX),
                monotonic_deadline: far_future,
            },
            cancel_clone,
            done_clone,
            signal_clone,
        );
    });

    // Signal completion and unpark immediately.
    done.store(true, Ordering::Release);
    handle.thread().unpark();

    // The watchdog should exit almost instantly rather than sleeping 25 ms.
    handle.join().expect("watchdog thread should not panic");

    assert!(
        !cancel.is_cancelled(),
        "early exit via unpark must not trigger cancellation"
    );
    assert!(
        signal.current().is_none(),
        "early exit via unpark must not record a deadline reason"
    );
}

// ============================================================================
// wait_for_submitted_commits tests
// ============================================================================

#[test]
fn wait_for_submitted_commits_accepts_matching_sequences_out_of_order() {
    let submitted = vec![2, 0, 1];

    wait_for_submitted_commits(submitted, vec![1, 2, 0]).expect("matching sequences");
}

#[test]
fn wait_for_submitted_commits_rejects_mismatched_sequences() {
    let submitted = vec![0, 1];
    let err = wait_for_submitted_commits(submitted, vec![0, 2])
        .expect_err("mismatched sequences should fail");

    assert!(
        err.to_string()
            .contains("did not match durable outcome sequence"),
        "unexpected error: {err}"
    );
}

#[test]
fn wait_for_submitted_commits_rejects_duplicate_submitted_sequences() {
    let submitted = vec![0, 1, 1];
    let err = wait_for_submitted_commits(submitted, vec![0, 1, 1])
        .expect_err("duplicate submitted sequences should fail");

    assert!(
        err.to_string()
            .contains("duplicate submitted sequence number"),
        "unexpected error: {err}"
    );
}

#[test]
fn wait_for_submitted_commits_rejects_duplicate_committed_sequences() {
    let submitted = vec![0, 1, 2];
    let err = wait_for_submitted_commits(submitted, vec![0, 2, 2])
        .expect_err("duplicate committed sequences should fail");

    assert!(
        err.to_string()
            .contains("duplicate committed sequence number"),
        "unexpected error: {err}"
    );
}

#[test]
fn wait_for_submitted_commits_rejects_fewer_committed_than_submitted() {
    let err = wait_for_submitted_commits(vec![0, 1], vec![0])
        .expect_err("fewer committed than submitted should fail");

    let msg = err.to_string();
    assert!(
        msg.contains("submitted 2 commit(s) but commit stage produced 1"),
        "unexpected error: {err}"
    );
}

#[test]
fn wait_for_submitted_commits_rejects_more_committed_than_submitted() {
    let err = wait_for_submitted_commits(vec![0], vec![0, 1])
        .expect_err("more committed than submitted should fail");

    let msg = err.to_string();
    assert!(
        msg.contains("submitted 1 commit(s) but commit stage produced 2"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// checkpoint_logical_time test
// ============================================================================

#[test]
fn checkpoint_logical_time_overflows_at_u64_max() {
    assert!(checkpoint_logical_time(u64::MAX).is_err());
}

// ============================================================================
// ReceiptCommitSink tests
// ============================================================================

#[test]
fn begin_item_assigns_monotonic_sequence_numbers() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let first = item_key("tenant/repo/first.txt");
    let second = item_key("tenant/repo/second.txt");
    let meta = item_meta();

    sink.begin_item(&first, &meta).expect("begin first item");
    sink.begin_item(&second, &meta).expect("begin second item");

    let guard = sink.in_flight.lock().expect("in flight lock");
    assert_eq!(guard.get(&first).expect("first item").sequence_no, 0);
    assert_eq!(guard.get(&second).expect("second item").sequence_no, 1);
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn receipt_commit_sink_translates_and_submits_item() {
    let (pipeline, sink, recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/file.txt");
    let meta = item_meta();

    sink.begin_item(&item_key, &meta).expect("begin item");
    sink.upsert_findings(
        &item_key,
        &FindingsBatch {
            findings: vec![finding()],
        },
    )
    .expect("upsert findings");
    sink.finish_item(&item_key).expect("finish item");

    let submitted = sink.finish().expect("sink finish");
    assert_eq!(submitted.len(), 1);
    assert_eq!(submitted[0], 0);

    match pipeline
        .recv_timeout(Duration::from_secs(1))
        .expect("commit outcome")
    {
        CommitStageOutput::Committed {
            write_context: got,
            checkpoint_input,
        } => {
            assert_eq!(got, write_context());
            let receipt = checkpoint_input.into_receipt();
            assert_eq!(receipt.completed_unit().sequence_no(), 0);
            assert_eq!(
                receipt.completed_unit().checkpoint_cursor(),
                &Cursor::with_last_key(item_key.clone())
            );
            assert_eq!(receipt.durable().findings().finding_count(), 1);
            assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        }
        CommitStageOutput::Failed { error, .. } => {
            panic!("expected committed outcome, got failure: {error}");
        }
    }

    let progress = recorder.progress.lock().expect("progress lock");
    assert_eq!(progress.len(), 2);
    match &progress[0] {
        CommitProgressRecord::Begin {
            write_context: got,
            item_key: got_key,
            size_hint,
        } => {
            assert_eq!(*got, write_context());
            assert_eq!(got_key, &item_key);
            assert_eq!(*size_hint, meta.size_hint);
        }
        other => panic!("expected begin progress record, got {other:?}"),
    }
    match &progress[1] {
        CommitProgressRecord::Finish {
            write_context: got,
            item_key: got_key,
        } => {
            assert_eq!(*got, write_context());
            assert_eq!(got_key, &item_key);
        }
        other => panic!("expected finish progress record, got {other:?}"),
    }

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn upsert_findings_maps_runtime_records_into_fs_findings() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/file.txt");

    sink.begin_item(&item_key, &item_meta())
        .expect("begin item");
    sink.upsert_findings(
        &item_key,
        &FindingsBatch {
            findings: vec![finding()],
        },
    )
    .expect("upsert findings");

    let guard = sink.in_flight.lock().expect("in flight lock");
    let item = guard.get(&item_key).expect("item should remain in flight");
    assert_eq!(
        item.findings,
        vec![FsFindingRecord {
            rule_id: 7,
            blob_offset_start: 10,
            blob_offset_end: 20,
            window_start: 10,
            window_end: 20,
            norm_hash: [0x55; 32],
            confidence_score: 6,
        }]
    );
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn begin_item_rejects_double_begin_for_same_key() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/file.txt");
    let meta = item_meta();

    sink.begin_item(&item_key, &meta).expect("first begin item");
    let err = sink
        .begin_item(&item_key, &meta)
        .expect_err("duplicate begin should fail");

    assert!(
        err.to_string()
            .contains("begin_item called twice without finish_item"),
        "unexpected error: {err}"
    );

    // A failed duplicate begin must not consume a sequence number.
    let next_key = ItemKey::try_from_slice(b"tenant/repo/next.txt").expect("next key");
    sink.begin_item(&next_key, &meta)
        .expect("begin after failed duplicate");
    let guard = sink.in_flight.lock().expect("in flight lock");
    assert_eq!(
        guard.get(&next_key).expect("next item").sequence_no,
        1,
        "failed begin must not waste a sequence number"
    );
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn upsert_findings_rejects_unknown_item() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/missing.txt");
    let err = sink
        .upsert_findings(
            &item_key,
            &FindingsBatch {
                findings: vec![finding()],
            },
        )
        .expect_err("upsert without begin should fail");

    assert!(
        err.to_string()
            .contains("upsert_findings called before begin_item"),
        "unexpected error: {err}"
    );

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn finish_item_rejects_unknown_item() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/missing.txt");
    let err = sink
        .finish_item(&item_key)
        .expect_err("finish without begin should fail");

    assert!(
        err.to_string()
            .contains("finish_item called before begin_item"),
        "unexpected error: {err}"
    );

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn finish_rejects_remaining_in_flight_items() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let item_key = item_key("tenant/repo/file.txt");

    sink.begin_item(&item_key, &item_meta())
        .expect("begin item");
    let err = sink
        .finish()
        .expect_err("finish should reject remaining in-flight items");

    assert!(
        err.to_string().contains("still in flight"),
        "unexpected error: {err}"
    );

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn logical_timing_rejects_sequence_overflow() {
    let err = ReceiptCommitSink::logical_timing_for(u64::MAX)
        .expect_err("overflowing timing should fail");

    assert!(
        err.to_string()
            .contains("sequence number overflow while deriving scan timing"),
        "unexpected error: {err}"
    );
}

#[test]
fn upsert_findings_accumulates_across_multiple_batches() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/multi.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    sink.upsert_findings(
        &key,
        &FindingsBatch {
            findings: vec![FindingRecord {
                rule_id: 7,
                start: 10,
                end: 20,
                norm_hash: [0x55; 32],
                confidence_score: 6,
            }],
        },
    )
    .expect("first upsert");
    sink.upsert_findings(
        &key,
        &FindingsBatch {
            findings: vec![FindingRecord {
                rule_id: 8,
                start: 30,
                end: 40,
                norm_hash: [0x66; 32],
                confidence_score: 9,
            }],
        },
    )
    .expect("second upsert");

    let guard = sink.in_flight.lock().expect("in flight lock");
    let item = guard.get(&key).expect("item in flight");
    assert_eq!(item.findings.len(), 2, "both batches should accumulate");
    assert_eq!(item.findings[0].rule_id, 7);
    assert_eq!(item.findings[1].rule_id, 8);
    assert_eq!(item.findings[1].blob_offset_start, 30);
    assert_eq!(item.findings[1].blob_offset_end, 40);
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn finish_item_succeeds_with_zero_findings() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/clean.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    sink.finish_item(&key)
        .expect("finish item with zero findings");

    let submitted = sink.finish().expect("sink finish");
    assert_eq!(submitted.len(), 1);

    match pipeline
        .recv_timeout(Duration::from_secs(1))
        .expect("commit outcome")
    {
        CommitStageOutput::Committed {
            checkpoint_input, ..
        } => {
            let receipt = checkpoint_input.into_receipt();
            assert_eq!(receipt.durable().findings().finding_count(), 0);
            assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        }
        CommitStageOutput::Failed { error, .. } => {
            panic!("expected committed outcome, got failure: {error}");
        }
    }

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn translate_handles_size_hint_none() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/nohint.txt");
    let meta = ItemMeta {
        stable_item_id: StableItemId::from_bytes([0x44; 32]),
        version: None,
        size_hint: None,
    };

    sink.begin_item(&key, &meta).expect("begin item");
    sink.finish_item(&key).expect("finish item");

    let submitted = sink.finish().expect("sink finish");
    assert_eq!(submitted.len(), 1);

    match pipeline
        .recv_timeout(Duration::from_secs(1))
        .expect("commit outcome")
    {
        CommitStageOutput::Committed {
            checkpoint_input, ..
        } => {
            let receipt = checkpoint_input.into_receipt();
            assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        }
        CommitStageOutput::Failed { error, .. } => {
            panic!("expected committed outcome, got failure: {error}");
        }
    }

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn translate_uses_explicit_version_when_provided() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/versioned.txt");
    let meta = ItemMeta {
        stable_item_id: StableItemId::from_bytes([0x44; 32]),
        version: Some(VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"explicit-v1",
        ))),
        size_hint: Some(256),
    };

    sink.begin_item(&key, &meta).expect("begin item");
    sink.finish_item(&key).expect("finish item");

    let submitted = sink.finish().expect("sink finish");
    assert_eq!(submitted.len(), 1);

    match pipeline
        .recv_timeout(Duration::from_secs(1))
        .expect("commit outcome")
    {
        CommitStageOutput::Committed {
            checkpoint_input, ..
        } => {
            let receipt = checkpoint_input.into_receipt();
            assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        }
        CommitStageOutput::Failed { error, .. } => {
            panic!("expected committed outcome, got failure: {error}");
        }
    }

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn translate_in_flight_uses_item_key_surrogate_version_when_version_is_missing() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/version-compare.txt");
    let meta_without_version = ItemMeta {
        stable_item_id: StableItemId::from_bytes([0x44; 32]),
        version: None,
        size_hint: Some(256),
    };
    let meta_with_explicit_version = ItemMeta {
        stable_item_id: meta_without_version.stable_item_id,
        version: Some(VersionId::Strong(ObjectVersionId::from_version_bytes(
            b"explicit-v1",
        ))),
        size_hint: meta_without_version.size_hint,
    };
    let findings = vec![FsFindingRecord {
        rule_id: 7,
        blob_offset_start: 10,
        blob_offset_end: 20,
        window_start: 10,
        window_end: 20,
        norm_hash: [0x55; 32],
        confidence_score: 6,
    }];

    let (_, _, implicit_translation) = sink
        .translate_in_flight(
            &key,
            &InFlightItem {
                sequence_no: 0,
                meta: meta_without_version,
                findings: findings.clone(),
            },
        )
        .expect("surrogate-version translation")
        .into_parts();
    let (_, _, explicit_translation) = sink
        .translate_in_flight(
            &key,
            &InFlightItem {
                sequence_no: 0,
                meta: meta_with_explicit_version,
                findings,
            },
        )
        .expect("explicit-version translation")
        .into_parts();

    assert_eq!(
        implicit_translation.findings()[0].finding_id(),
        explicit_translation.findings()[0].finding_id(),
        "finding identity must stay version-independent",
    );
    assert_ne!(
        implicit_translation.occurrences()[0].occurrence_id(),
        explicit_translation.occurrences()[0].occurrence_id(),
        "missing-version translation must derive occurrence identity from the item-key surrogate version",
    );

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn upsert_findings_rejects_empty_span() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/bad-span.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    let err = sink
        .upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![
                    finding(),
                    FindingRecord {
                        rule_id: 8,
                        start: 30,
                        end: 30,
                        norm_hash: [0x66; 32],
                        confidence_score: 9,
                    },
                ],
            },
        )
        .expect_err("empty span must be rejected at upsert time");
    assert!(
        err.to_string()
            .contains("finding at index 1 has invalid span"),
        "unexpected error: {err}"
    );

    // The item is still in-flight — the batch was rejected before any
    // findings were appended, so finish_item can still be called.
    let guard = sink.in_flight.lock().expect("in flight lock");
    assert!(
        guard.contains_key(&key),
        "rejected batch must not remove the in-flight item"
    );
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn upsert_findings_rejects_inverted_span() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/inverted-span.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    let err = sink
        .upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![FindingRecord {
                    rule_id: 9,
                    start: 40,
                    end: 30,
                    norm_hash: [0x77; 32],
                    confidence_score: 7,
                }],
            },
        )
        .expect_err("inverted span must be rejected at upsert time");
    assert!(
        err.to_string()
            .contains("finding at index 0 has invalid span"),
        "unexpected error: {err}"
    );

    let guard = sink.in_flight.lock().expect("in flight lock");
    assert!(
        guard.contains_key(&key),
        "rejected batch must not remove the in-flight item"
    );
    drop(guard);

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn finish_item_preserves_in_flight_on_translation_failure() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/overflow.txt");

    // Force sequence counter to u64::MAX so the next begin_item assigns
    // a sequence_no whose logical_timing_for computation overflows.
    sink.next_sequence_no.store(u64::MAX, Ordering::Relaxed);
    sink.begin_item(&key, &item_meta()).expect("begin item");

    let err = sink
        .finish_item(&key)
        .expect_err("translate should fail on timing overflow");
    assert!(
        err.to_string().contains("sequence number overflow"),
        "unexpected error: {err}"
    );

    let guard = sink.in_flight.lock().expect("in flight lock");
    assert!(
        guard.contains_key(&key),
        "item must remain in in_flight after translation failure"
    );
    drop(guard);

    assert!(
        sink.submitted.lock().expect("submitted lock").is_empty(),
        "submitted must be empty after translation failure"
    );

    pipeline.shutdown().expect("worker should join");
}

#[test]
fn finish_item_preserves_in_flight_on_submit_failure() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/disconnected.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    sink.upsert_findings(
        &key,
        &FindingsBatch {
            findings: vec![finding()],
        },
    )
    .expect("upsert findings");

    // Shut down the pipeline so the sender channel is disconnected.
    pipeline.shutdown().expect("pipeline shutdown");

    let err = sink
        .finish_item(&key)
        .expect_err("submit should fail after pipeline shutdown");
    assert!(
        err.to_string().contains("submission failed"),
        "unexpected error: {err}"
    );

    let guard = sink.in_flight.lock().expect("in flight lock");
    assert!(
        guard.contains_key(&key),
        "item must remain in in_flight after submit failure"
    );
    drop(guard);

    assert!(
        sink.submitted.lock().expect("submitted lock").is_empty(),
        "submitted must be empty after submit failure"
    );
}

#[test]
fn upsert_after_finish_is_rejected() {
    let (pipeline, sink, _recorder) = make_receipt_sink();
    let key = item_key("tenant/repo/finished.txt");

    sink.begin_item(&key, &item_meta()).expect("begin item");
    sink.finish_item(&key).expect("finish item");

    let err = sink
        .upsert_findings(
            &key,
            &FindingsBatch {
                findings: vec![finding()],
            },
        )
        .expect_err("upsert after finish should fail");

    assert!(
        err.to_string()
            .contains("upsert_findings called before begin_item"),
        "unexpected error: {err}"
    );

    pipeline.shutdown().expect("worker should join");
}

// ============================================================================
// claim_retry_delay tests
// ============================================================================

#[test]
fn claim_retry_delay_with_future_deadline() {
    let now = LogicalTime::from_raw(1000);
    let deadline = Some(LogicalTime::from_raw(1050));
    assert_eq!(claim_retry_delay(now, deadline), Duration::from_millis(50));
}

#[test]
fn claim_retry_delay_clamps_stale_deadline_to_one_ms() {
    let now = LogicalTime::from_raw(2000);
    let stale = Some(LogicalTime::from_raw(1000));
    assert_eq!(claim_retry_delay(now, stale), Duration::from_millis(1));
}

#[test]
fn claim_retry_delay_falls_back_without_deadline() {
    let now = LogicalTime::from_raw(1000);
    assert_eq!(claim_retry_delay(now, None), CLAIM_RACE_RETRY_DELAY);
}

// ============================================================================
// advance_shard tests
// ============================================================================

#[test]
fn complete_shard_reports_lease_uncertainty_when_lease_is_fenced() {
    let dir = tempdir().expect("tempdir");

    // Use a very short TTL so our lease expires quickly.
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // Wait for our lease to expire, then let a rival claim the same
    // shard. This bumps the fence epoch, making our lease stale.
    std::thread::sleep(Duration::from_millis(100));
    let _rival_lease = claim_coordination_lease(&mut coordinator, worker(99));

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect_err("completion with stale fence should fail");
    assert!(
        matches!(
            err,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceStaleFence { .. })
        ),
        "expected LeaseUncertain stale-fence variant, got: {err:?}"
    );
}

#[test]
fn complete_shard_reports_lease_uncertainty_when_lease_has_expired() {
    let dir = tempdir().expect("tempdir");

    // Use a very short TTL so our lease expires quickly.
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // Wait for the lease to expire WITHOUT a rival claim. This triggers
    // LeaseExpired (no fence bump) rather than StaleFence.
    std::thread::sleep(Duration::from_millis(100));

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect_err("completion after lease expiry should fail");
    assert!(
        matches!(
            err,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceLeaseExpired { .. })
        ),
        "expected LeaseUncertain lease-expired variant, got: {err:?}"
    );
}

#[test]
fn checkpoint_shard_reports_lease_uncertainty_when_lease_is_fenced() {
    let dir = tempdir().expect("tempdir");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let checkpoint =
        Cursor::try_from_update(CoordCursorUpdate::new(b"\x05")).expect("checkpoint cursor");

    std::thread::sleep(Duration::from_millis(100));
    let _rival_lease = claim_coordination_lease(&mut coordinator, worker(99));

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Checkpoint {
            checkpoint: checkpoint.clone(),
        },
    )
    .expect_err("checkpoint with stale fence should fail");
    assert!(
        matches!(
            err,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceStaleFence { .. })
        ),
        "expected LeaseUncertain stale-fence variant, got: {err:?}"
    );
}

#[test]
fn checkpoint_shard_reports_lease_uncertainty_when_lease_has_expired() {
    let dir = tempdir().expect("tempdir");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 50);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let checkpoint =
        Cursor::try_from_update(CoordCursorUpdate::new(b"\x05")).expect("checkpoint cursor");

    std::thread::sleep(Duration::from_millis(100));

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Checkpoint { checkpoint },
    )
    .expect_err("checkpoint after lease expiry should fail");
    assert!(
        matches!(
            err,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::AdvanceLeaseExpired { .. })
        ),
        "expected LeaseUncertain lease-expired variant, got: {err:?}"
    );
}

#[test]
fn advance_shard_maps_terminal_shard_to_coordinator_error() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x05", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // Complete the shard successfully first.
    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect("first completion should succeed");

    // Use the checkpoint path on the terminal shard so the deterministic
    // OpId differs from the first completion and reaches terminal-state
    // validation rather than idempotent replay handling.
    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Checkpoint {
            checkpoint: Cursor::with_last_key(item_key("z.txt")),
        },
    )
    .expect_err("checkpointing an already-done shard should fail");

    assert!(
        matches!(err, DistributedRuntimeError::Coordinator(_)),
        "expected Coordinator error for terminal shard, got: {err:?}"
    );
    assert!(
        !matches!(err, DistributedRuntimeError::LeaseUncertain(_)),
        "ShardTerminal must not be misclassified as LeaseUncertain"
    );
}

#[test]
fn advance_shard_exhausted_empty_unbounded_lower_bound_uses_range_safe_sentinel() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let claimed = claim_lease(&mut coordinator, &identity);
    let lease = ShardLease::new(
        Arc::clone(claimed.shard_id_arc()),
        claimed.lease(),
        RestoredShardState::new(
            ShardSpec::with_range(vec![], vec![0x01]),
            Cursor::initial(),
            CursorSemantics::Completed,
        ),
        claimed.filesystem_source.clone(),
        claimed.write_context(),
        claimed.tenant_secret_key(),
        wall_clock_now(),
        Instant::now(),
    );

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect("unbounded-lower-bound exhausted-empty completion must succeed");

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Done);
    assert_eq!(
        summaries[0].last_key(),
        Some(EMPTY_RANGE_SENTINEL_KEY),
        "exhausted-empty completion should use the sentinel key when the shard has no lower bound",
    );
}

#[test]
fn advance_shard_rejects_out_of_range_exhausted_empty_fallback() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let claimed = claim_lease(&mut coordinator, &identity);
    let lease = ShardLease::new(
        Arc::clone(claimed.shard_id_arc()),
        claimed.lease(),
        RestoredShardState::new(
            ShardSpec::with_range(vec![], vec![0x00]),
            Cursor::initial(),
            CursorSemantics::Completed,
        ),
        claimed.filesystem_source.clone(),
        claimed.write_context(),
        claimed.tenant_secret_key(),
        wall_clock_now(),
        Instant::now(),
    );

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect_err("out-of-range exhausted-empty fallback must be rejected");

    assert!(
        matches!(err, DistributedRuntimeError::Runtime(_)),
        "expected Runtime error for out-of-range completion cursor, got: {err:?}"
    );
    assert!(
        err.to_string().contains("not in bounds"),
        "unexpected error: {err}"
    );
}

#[test]
fn advance_shard_rejects_out_of_range_complete_checkpoint() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let claimed = claim_lease(&mut coordinator, &identity);
    let lease = ShardLease::new(
        Arc::clone(claimed.shard_id_arc()),
        claimed.lease(),
        RestoredShardState::new(
            ShardSpec::with_range(vec![0x01], vec![0x0F]),
            Cursor::initial(),
            CursorSemantics::Completed,
        ),
        claimed.filesystem_source.clone(),
        claimed.write_context(),
        claimed.tenant_secret_key(),
        wall_clock_now(),
        Instant::now(),
    );

    let err = advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Complete {
            checkpoint: Cursor::with_last_key(item_key("\x0F")),
        },
    )
    .expect_err("out-of-range progress checkpoint must be rejected");

    assert!(
        matches!(err, DistributedRuntimeError::Runtime(_)),
        "expected Runtime error for out-of-range completion cursor, got: {err:?}"
    );
    assert!(
        err.to_string().contains("not in bounds"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// mirror_error_class test
// ============================================================================

#[test]
fn mirror_error_class_maps_known_variants() {
    assert_eq!(
        mirror_error_class(ErrorClass::Retryable),
        MirrorErrorClass::Retryable,
    );
    assert_eq!(
        mirror_error_class(ErrorClass::Permanent),
        MirrorErrorClass::Permanent,
    );
}

// ============================================================================
// ordered_content_error_codes test
// ============================================================================

#[test]
fn ordered_content_error_codes_are_valid_and_match_expected_values() {
    let failure = OrderedContentReadStop::failure_code();
    assert_eq!(failure.as_str(), "READ_FAILED");

    let truncation = OrderedContentReadStop::truncation_code();
    assert_eq!(truncation.as_str(), "TRUNCATED");

    let binary = OrderedContentSkipReason::Binary.done_ledger_code();
    assert_eq!(binary.as_str(), "BINARY");

    let extractable = OrderedContentSkipReason::BinaryExtractable.done_ledger_code();
    assert_eq!(extractable.as_str(), "BINARY_EXTRACTABLE");
}

// ============================================================================
// emit_ordered_summary tests
// ============================================================================

#[test]
fn emit_ordered_summary_emits_summary_event_with_correct_metrics() {
    let report = ScanReport {
        items_scanned: 42,
        bytes_scanned: 10 * 1024 * 1024,
        chunks_scanned: 100,
        findings_emitted: 3,
        errors: 1,
        scan_ns: 2_000_000_000,
        ..ScanReport::default()
    };

    let sink = CapturingEventOutput::default();
    emit_ordered_summary(&sink, report);

    let events = sink.take();
    assert_eq!(events.len(), 1, "exactly one summary event expected");

    let OwnedCoreEvent::Summary {
        source,
        status,
        elapsed_ms,
        bytes_scanned,
        findings_emitted,
        errors,
        throughput_mib_s,
    } = &events[0]
    else {
        panic!("expected Summary event, got: {:?}", events[0]);
    };

    assert_eq!(*source, SourceKind::Fs);
    assert_eq!(
        *status, "error",
        "non-zero errors must produce status=error"
    );
    // 2_000_000_000 ns = 2000 ms
    assert_eq!(*elapsed_ms, 2000);
    assert_eq!(*bytes_scanned, 10 * 1024 * 1024);
    assert_eq!(*findings_emitted, 3);
    assert_eq!(*errors, 1);
    // 10 MiB / 2s = 5.0 MiB/s
    assert!(
        (*throughput_mib_s - 5.0).abs() < 0.001,
        "expected ~5.0 MiB/s, got {throughput_mib_s}"
    );
}

#[test]
fn emit_ordered_summary_reports_ok_when_no_errors() {
    let report = ScanReport {
        items_scanned: 10,
        bytes_scanned: 500,
        errors: 0,
        scan_ns: 1_000_000,
        ..ScanReport::default()
    };

    let sink = CapturingEventOutput::default();
    emit_ordered_summary(&sink, report);

    let events = sink.take();
    let OwnedCoreEvent::Summary { status, .. } = &events[0] else {
        panic!("expected Summary event");
    };
    assert_eq!(*status, "ok", "zero errors must produce status=ok");
}

// ============================================================================
// Suffix protocol tests
// ============================================================================

#[test]
fn suffix_protocol_accepts_terminal_page_followed_by_exhausted_empty() {
    let terminal_page = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("terminal page");

    let (outcome, fill_page_calls) =
        run_suffix_protocol_test(vec![Ok(Some(terminal_page)), Ok(None)])
            .expect("terminal page followed by exhausted-empty should succeed");

    assert_eq!(
        outcome.termination,
        PageLoopTermination::ExhaustedEmptyConfirmed
    );
    assert_eq!(outcome.report.items_scanned, 1);
    assert_eq!(
        fill_page_calls, 2,
        "suffix protocol must perform a second fill_page call to confirm exhausted-empty"
    );
}

#[test]
fn suffix_protocol_rejects_page_after_terminal_page() {
    let terminal_page = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("terminal page");
    let follow_up_page = PageBuf::try_new(
        vec![suffix_test_item(b"b.txt", 20)],
        PageState::HasMore {
            cursor: Cursor::with_last_key(item_key("b.txt")),
        },
    )
    .expect("follow-up page");

    let err = run_suffix_protocol_test(vec![Ok(Some(terminal_page)), Ok(Some(follow_up_page))])
        .expect_err("page after terminal should be rejected");

    assert!(
        err.to_string()
            .contains("non-empty page after a terminal non-empty page"),
        "unexpected error: {err}"
    );
}

#[test]
fn suffix_protocol_rejects_second_terminal_page() {
    let first = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("first terminal page");
    let second = PageBuf::try_new(vec![suffix_test_item(b"b.txt", 20)], PageState::Complete)
        .expect("second terminal page");

    let err = run_suffix_protocol_test(vec![Ok(Some(first)), Ok(Some(second))])
        .expect_err("second terminal page should be rejected");

    assert!(
        err.to_string()
            .contains("non-empty page after a terminal non-empty page"),
        "unexpected error: {err}"
    );
}

#[test]
fn suffix_protocol_rejects_exhausted_empty_after_has_more_page() {
    let has_more_page = PageBuf::try_new(
        vec![suffix_test_item(b"a.txt", 10)],
        PageState::HasMore {
            cursor: Cursor::with_last_key(item_key("a.txt")),
        },
    )
    .expect("has-more page");

    let err = run_suffix_protocol_test(vec![Ok(Some(has_more_page)), Ok(None)])
        .expect_err("exhausted-empty after has-more should be rejected");

    assert!(
        err.to_string()
            .contains("exhausted-empty without first emitting a terminal non-empty page"),
        "unexpected error: {err}"
    );
}

#[test]
fn suffix_protocol_preserves_progress_on_retryable_stop_after_terminal_page() {
    let terminal_page = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("terminal page");

    let (outcome, fill_page_calls) = run_suffix_protocol_test(vec![
        Ok(Some(terminal_page)),
        Err(EnumerateError::rate_limited("simulated rate limit", 100)),
    ])
    .expect("retryable stop after terminal should preserve progress");

    assert!(
        outcome.report.items_scanned >= 1,
        "committed work from the terminal page should be preserved"
    );
    assert_eq!(outcome.termination, PageLoopTermination::Partial);
    assert_eq!(fill_page_calls, 2);
}

#[test]
fn suffix_protocol_rejects_permanent_stop_after_terminal_page() {
    let terminal_page = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("terminal page");

    let err = run_suffix_protocol_test(vec![
        Ok(Some(terminal_page)),
        Err(EnumerateError::permanent("simulated permanent failure")),
    ])
    .expect_err("permanent stop after terminal should still be rejected");

    assert!(
        err.to_string()
            .contains("stopped before confirming exhausted-empty suffix"),
        "unexpected error: {err}"
    );
}

#[test]
fn suffix_protocol_accepts_immediate_exhausted_empty() {
    let (outcome, _fill_page_calls) =
        run_suffix_protocol_test(vec![Ok(None)]).expect("immediate exhausted-empty should succeed");

    assert_eq!(outcome.report.items_scanned, 0);
}

#[test]
fn suffix_protocol_cancellation_during_exhausted_empty_wait_preserves_progress() {
    let terminal_page = PageBuf::try_new(vec![suffix_test_item(b"a.txt", 10)], PageState::Complete)
        .expect("terminal page");

    let cancel = CancellationToken::new();
    let fill_page_calls = Arc::new(AtomicU64::new(0));
    let source = MultiStepScriptedSource {
        pages: vec![Ok(Some(terminal_page))].into(),
        fill_page_calls: Arc::clone(&fill_page_calls),
        cancel_on_call: Some((0, cancel.clone())),
        call_count: 0,
    };

    // The cancel fires during fill_page call #0, so the inner
    // item-submission loop also sees cancellation and skips commits.
    // AwaitingExhaustedEmpty treats that path as a graceful break and
    // returns Ok instead of surfacing an error.
    let _outcome = run_suffix_protocol_test_core(source, cancel, fill_page_calls)
        .expect("cancellation during suffix wait should break gracefully, not error");
}

#[test]
fn scan_ordered_source_breaks_on_mid_page_cancellation() {
    let page = PageBuf::try_new(
        vec![
            suffix_test_item(b"a.txt", 10),
            suffix_test_item(b"b.txt", 20),
        ],
        PageState::HasMore {
            cursor: Cursor::with_last_key(item_key("b.txt")),
        },
    )
    .expect("page");

    let cancel = CancellationToken::new();
    // cancel_on_call fires during fill_page call #0 -- after the cancel
    // fires, fill_page still returns the page. The item submission loop
    // then sees cancel.is_cancelled() on its first iteration and breaks
    // with hit_non_terminal = true, so no items are submitted.
    let fill_page_calls = Arc::new(AtomicU64::new(0));
    let source = MultiStepScriptedSource {
        pages: vec![Ok(Some(page))].into(),
        fill_page_calls: Arc::clone(&fill_page_calls),
        cancel_on_call: Some((0, cancel.clone())),
        call_count: 0,
    };

    let (outcome, _) = run_suffix_protocol_test_core(source, cancel, fill_page_calls)
        .expect("mid-page cancellation should break gracefully, not error");

    // The page was acquired and scan-misses were executed, but the item
    // submission loop broke before submitting any items because
    // cancel.is_cancelled() fired.
    assert_eq!(
        outcome.report.items_scanned, 0,
        "no items should be submitted when cancellation fires before item processing"
    );
}

#[test]
fn retryable_stop_on_first_call_returns_error_instead_of_completing_shard() {
    let err = run_suffix_protocol_test(vec![Err(EnumerateError::rate_limited(
        "transient failure",
        100,
    ))])
    .expect_err("retryable stop on first call should propagate error");

    assert!(
        err.to_string().contains("no prior progress"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// build_lease payload validation tests
// ============================================================================

#[test]
fn build_lease_from_acquire_rejects_non_utf8_filesystem_payload_path() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("target.txt");
    std::fs::write(&file_path, "fixture").expect("write fixture");
    let mut payload = filesystem_payload(&file_path, FilesystemSourceMode::SingleFile);
    // Wire format: byte 0 = mode tag, bytes 1.. = UTF-8 path.
    // Overwriting byte 2 injects an invalid UTF-8 byte into the path portion.
    payload[2] = 0xFF;
    let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
    let mut scratch = AcquireScratch::new();
    let acquired = coordinator
        .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
        .expect("claim next available");
    let identity = worker_identity(Path::new("/fallback"));

    let err = build_lease_from_acquire(acquired, &identity, wall_clock_now(), Instant::now())
        .expect_err("non-UTF-8 filesystem payload path must be rejected");
    assert!(
        err.to_string()
            .contains("filesystem shard payload mode 'single_file' path is not valid UTF-8"),
        "unexpected error: {err}"
    );
}

#[test]
fn build_lease_from_acquire_rejects_payload_mode_path_mismatch() {
    let dir = tempdir().expect("tempdir");
    let payload = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, dir.path())
        .encode()
        .expect("mismatched payload should still encode");
    let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
    let mut scratch = AcquireScratch::new();
    let acquired = coordinator
        .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
        .expect("claim next available");
    let identity = worker_identity(Path::new("/fallback"));

    let err = build_lease_from_acquire(acquired, &identity, wall_clock_now(), Instant::now())
        .expect_err("mode/path mismatch must fail during hydration");
    assert!(
        err.to_string()
            .contains("filesystem shard payload mode 'single_file' requires a regular file"),
        "unexpected error: {err}"
    );
}

#[cfg(unix)]
#[test]
fn build_lease_from_acquire_rejects_symlink_payload_path() {
    use std::os::unix::fs as unix_fs;

    let dir = tempdir().expect("tempdir");
    let target = dir.path().join("real.txt");
    std::fs::write(&target, "fixture").expect("write target");
    let link = dir.path().join("link.txt");
    unix_fs::symlink(&target, &link).expect("create symlink");

    let payload = FilesystemShardPayload::new(FilesystemSourceMode::SingleFile, &link)
        .encode()
        .expect("symlink payload should encode");
    let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
    let mut scratch = AcquireScratch::new();
    let acquired = coordinator
        .claim_next_available(wall_clock_now(), tenant(), run(), worker(1), &mut scratch)
        .expect("claim next available");
    let identity = worker_identity(Path::new("/fallback"));

    let err = build_lease_from_acquire(acquired, &identity, wall_clock_now(), Instant::now())
        .expect_err("symlink payload path must be rejected");
    assert!(
        err.to_string().contains("is a symlink"),
        "unexpected error: {err}"
    );
}

// ============================================================================
// submit_git_repo_persistence tests
// ============================================================================

#[test]
fn submit_git_repo_persistence_commits_findings_and_done_ledger() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
    let tmp = tempdir().expect("temp dir for repo key");
    let repo_key = git_repo_key(tmp.path());
    let findings = [GitFindingForPersistence {
        object_path: b"src/lib.rs".to_vec().into_boxed_slice(),
        commit_id: Some(7),
        blob_offset_start: 10,
        blob_offset_end: 42,
        norm_hash: NormHash::from_digest([0xAB; 32]),
        rule_id: 7,
    }];
    let commit_oid_map = AHashMap::from_iter([(7, OidBytes::sha1([0x11; 20]))]);
    let input = GitRepoPersistenceInput {
        write_context: write_context(),
        shard_id: &ToxicDigest::of_bytes(b"test-shard"),
        repo_key: &repo_key,
        repo_id: 42,
        bytes_scanned: 1024,
        findings: &findings,
        commit_oid_map: &commit_oid_map,
        tenant_secret_key: tenant_secret_key(),
        rule_fingerprint: &test_rule_fingerprint,
        claim_time: LogicalTime::from_raw(100),
        complete_time: LogicalTime::from_raw(200),
    };

    let (findings_receipt, done_ledger_receipt) = submit_git_repo_persistence(&persistence, &input)
        .expect("git repo persistence should succeed");

    assert_eq!(findings_receipt.finding_count(), 1);
    assert_eq!(findings_receipt.occurrence_count(), 1);
    assert_eq!(findings_receipt.observation_count(), 1);
    assert_eq!(done_ledger_receipt.record_count(), 1);
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot")[0].status(),
        DoneLedgerStatus::ScannedWithFindings,
    );
    assert_eq!(
        findings_sink
            .findings_snapshot()
            .expect("findings snapshot")
            .len(),
        1,
    );
    assert_eq!(
        findings_sink
            .occurrences_snapshot()
            .expect("occurrences snapshot")
            .len(),
        1,
    );
    let observation = findings_sink
        .observations_snapshot()
        .expect("observations snapshot")
        .pop()
        .expect("observation");
    let done = done_ledger
        .snapshot()
        .expect("done-ledger snapshot")
        .pop()
        .expect("done-ledger row");
    assert_ne!(
        observation.ovid_hash(),
        done.key().ovid_hash(),
        "git observations must use per-object OVIDs while done-ledger stays repo-scoped",
    );
}

#[test]
fn submit_git_repo_persistence_clean_scan_skips_findings_sink() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
    let tmp = tempdir().expect("temp dir for repo key");
    let repo_key = git_repo_key(tmp.path());
    let commit_oid_map = AHashMap::new();
    let input = GitRepoPersistenceInput {
        write_context: write_context(),
        shard_id: &ToxicDigest::of_bytes(b"clean-scan-shard"),
        repo_key: &repo_key,
        repo_id: 99,
        bytes_scanned: 512,
        findings: &[],
        commit_oid_map: &commit_oid_map,
        tenant_secret_key: tenant_secret_key(),
        rule_fingerprint: &test_rule_fingerprint,
        claim_time: LogicalTime::from_raw(100),
        complete_time: LogicalTime::from_raw(200),
    };

    let (findings_receipt, done_ledger_receipt) = submit_git_repo_persistence(&persistence, &input)
        .expect("clean-scan persistence should succeed");

    // Findings receipt must be zero-count — the findings sink is never called.
    assert_eq!(findings_receipt.finding_count(), 0);
    assert_eq!(findings_receipt.occurrence_count(), 0);
    assert_eq!(findings_receipt.observation_count(), 0);

    // Done-ledger must still receive its row.
    assert_eq!(done_ledger_receipt.record_count(), 1);
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedClean,);

    // Findings sink must remain completely untouched.
    assert!(
        findings_sink
            .findings_snapshot()
            .expect("findings snapshot")
            .is_empty(),
    );
    assert!(
        findings_sink
            .occurrences_snapshot()
            .expect("occurrences snapshot")
            .is_empty(),
    );
    assert!(
        findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
    );
}

#[test]
fn submit_git_repo_persistence_rejects_reversed_timestamps() {
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink, done_ledger);
    let tmp = tempdir().expect("temp dir for repo key");
    let repo_key = git_repo_key(tmp.path());
    let commit_oid_map = AHashMap::new();
    let input = GitRepoPersistenceInput {
        write_context: write_context(),
        shard_id: &ToxicDigest::of_bytes(b"test-shard"),
        repo_key: &repo_key,
        repo_id: 42,
        bytes_scanned: 1024,
        findings: &[],
        commit_oid_map: &commit_oid_map,
        tenant_secret_key: tenant_secret_key(),
        rule_fingerprint: &test_rule_fingerprint,
        claim_time: LogicalTime::from_raw(200),
        complete_time: LogicalTime::from_raw(100),
    };
    let err = submit_git_repo_persistence(&persistence, &input)
        .expect_err("reversed timestamps must be rejected");
    assert!(
        matches!(err, DistributedRuntimeError::Runtime(_)),
        "expected Runtime variant for timing rejection, got: {err:?}"
    );
}

// ============================================================================
// git_persistence_complete_finalize test
// ============================================================================

#[test]
fn git_persistence_complete_finalize_always_yields_checkpoint_input() {
    use crate::git_persistence::{GitPersistenceAdapter, GitPersistenceBackend};

    // A backend that accepts all writes but stores nothing.
    #[derive(Debug, Clone, Default)]
    struct NullGitBackend;
    impl GitPersistenceBackend for NullGitBackend {
        type Error = std::io::Error;
        fn get(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(None)
        }
        fn apply_batch(
            &self,
            _ops: &[crate::git_persistence::GitPersistenceOp],
        ) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    let adapter = GitPersistenceAdapter::new(NullGitBackend, 99, [0xAA; 32]);
    let wc = write_context();
    // Use a real temp directory so canonicalize() in git_repo_key succeeds.
    let tmp = tempdir().expect("temp dir for repo key");
    let key = git_repo_key(tmp.path());

    // Complete outcome must always produce a checkpoint input, regardless
    // of backend state. This is the invariant the integration-level guard
    // at `run_git_repo_lease` relies on.
    let checkpoint = adapter
        .repo_frontier_checkpoint_input(
            wc,
            0,
            &key,
            FinalizeOutcome::Complete,
            FindingsCommitReceipt::new(0, 0, 0),
            DoneLedgerCommitReceipt::new(1, 1, 0),
        )
        .expect("complete finalize must not error")
        .expect("complete finalize must yield checkpoint input");

    assert_eq!(
        checkpoint
            .receipt()
            .completed_unit()
            .checkpoint_cursor()
            .last_key(),
        Some(key.as_item_key()),
        "checkpoint cursor must carry the repo key"
    );

    // Partial outcome must return None — no outer progress on incomplete scans.
    let partial = adapter
        .repo_frontier_checkpoint_input(
            wc,
            0,
            &key,
            FinalizeOutcome::Partial { skipped_count: 1 },
            FindingsCommitReceipt::new(0, 0, 0),
            DoneLedgerCommitReceipt::new(1, 1, 0),
        )
        .expect("partial finalize must not error");
    assert!(
        partial.is_none(),
        "partial finalize must not yield checkpoint input"
    );
}

// ============================================================================
// build_lease_from_acquire payload hydration tests
// ============================================================================

#[test]
fn build_lease_from_acquire_hydrates_directory_root_payload() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_connector_extra(
        &[filesystem_payload(
            dir.path(),
            FilesystemSourceMode::DirectoryRoot,
        )],
        30_000,
    );
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let canonical_dir = dir.path().canonicalize().expect("canonicalize directory");

    assert_eq!(lease.shard_id(), "ShardId(1)");
    assert_eq!(lease.scan_config().path, canonical_dir);
    assert_eq!(lease.source_mode(), FilesystemSourceMode::DirectoryRoot);
    assert_eq!(lease.write_context().tenant_id(), tenant());
    assert_eq!(lease.write_context().run_id(), run());
    assert_eq!(lease.write_context().shard_id(), ShardId::from_raw(1));
    assert_eq!(lease.write_context().policy_hash(), policy_hash());
    assert_eq!(lease.write_context().fence_epoch(), FenceEpoch::from_raw(2));
    assert_eq!(lease.range_start(), &[0u8]);
    assert_eq!(lease.range_end(), &[1u8]);
    assert!(lease.resume_cursor().last_key().is_none());
    assert!(lease.resume_cursor().token().is_none());
    assert_eq!(lease.cursor_semantics(), CursorSemantics::Completed);
}

#[test]
fn build_lease_from_acquire_hydrates_single_file_payload() {
    let dir = tempdir().expect("tempdir");
    let file_path = dir.path().join("single-file.txt");
    fs::write(&file_path, "fixture").expect("write fixture");
    let payload = filesystem_payload(&file_path, FilesystemSourceMode::SingleFile);
    let mut coordinator = setup_coordinator_with_connector_extra(&[payload], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let canonical_file = file_path.canonicalize().expect("canonicalize file");

    assert_eq!(lease.scan_config().path, canonical_file);
    assert_eq!(lease.source_mode(), FilesystemSourceMode::SingleFile);
}

#[test]
fn build_lease_from_acquire_rejects_empty_filesystem_payload() {
    let mut coordinator = setup_coordinator_with_connector_extra(&[Vec::new()], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let mut scratch = AcquireScratch::new();
    let acquired = coordinator
        .claim_next_available(
            wall_clock_now(),
            identity.tenant,
            identity.run,
            identity.worker,
            &mut scratch,
        )
        .expect("claim next available");
    let err = build_lease_from_acquire(acquired, &identity, wall_clock_now(), Instant::now())
        .expect_err("empty filesystem payload must be rejected");

    assert!(
        err.to_string().contains(
            "failed to decode filesystem shard payload: filesystem shard payload is empty"
        ),
        "unexpected error: {err}"
    );
}

#[test]
fn build_lease_from_acquire_preserves_restored_cursor_and_full_bounds() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = CoordinationInMemoryCoordinator::new(30_000);
    let now = wall_clock_now();
    coordinator
        .create_run(now, tenant(), run(), test_run_config(30_000))
        .expect("create run");

    let mut scratch = ShardSpecScratch::new();
    let connector_extra = filesystem_payload(dir.path(), FilesystemSourceMode::DirectoryRoot);
    let spec_ref =
        range_shard_ref(b"a", b"m", &connector_extra, &mut scratch).expect("range shard spec");
    let shard_spec = ShardSpec::try_from_ref(spec_ref).expect("owned shard spec");
    let initial_cursor = CoordCursorUpdate::with_token(b"f.txt", b"resume-token");
    let shards = [InitialShardInput::new(
        ShardId::from_raw(1),
        shard_spec.as_ref(),
        initial_cursor,
    )];
    let _ = coordinator
        .register_shards(now, tenant(), run(), &shards, OpId::from_raw(1))
        .expect("register shards");

    let mut acquire_scratch = AcquireScratch::new();
    let acquired = coordinator
        .claim_next_available(
            wall_clock_now(),
            tenant(),
            run(),
            worker(1),
            &mut acquire_scratch,
        )
        .expect("claim next available");
    let lease = build_lease_from_acquire(
        acquired,
        &worker_identity(Path::new("/fallback")),
        wall_clock_now(),
        Instant::now(),
    )
    .expect("runtime lease");

    assert_eq!(lease.range_start(), b"a");
    assert_eq!(lease.range_end(), b"m");
    assert_eq!(
        lease
            .resume_cursor()
            .last_key()
            .expect("resume cursor last_key")
            .as_bytes(),
        b"f.txt"
    );
    assert_eq!(
        lease
            .resume_cursor()
            .token()
            .expect("resume cursor token")
            .as_bytes(),
        b"resume-token"
    );
    assert_eq!(lease.cursor_semantics(), CursorSemantics::Completed);
}

// ============================================================================
// deterministic_op_id tests
// ============================================================================

#[test]
fn deterministic_op_id_is_stable_and_input_sensitive() {
    let key = ShardKey::new(run(), ShardId::from_raw(9));
    let fence = FenceEpoch::from_raw(4);

    let baseline = deterministic_op_id(key, fence, OpKind::Complete);
    assert_eq!(baseline, deterministic_op_id(key, fence, OpKind::Complete));
    assert_ne!(
        baseline,
        deterministic_op_id(key, fence, OpKind::Checkpoint),
        "op-kind must influence the hash",
    );
    assert_ne!(
        baseline,
        deterministic_op_id(
            ShardKey::new(run(), ShardId::from_raw(10)),
            fence,
            OpKind::Complete
        ),
        "shard identity must influence the hash",
    );
    assert_ne!(
        baseline,
        deterministic_op_id(key, FenceEpoch::from_raw(5), OpKind::Complete),
        "fence epoch must influence the hash",
    );
}

// ============================================================================
// advance_shard completion / checkpoint boundary tests
// ============================================================================

#[test]
fn advance_shard_exhausted_empty_uses_range_start_under_completed_semantics() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x05", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect("zero-finding shard completion must succeed under Completed semantics");

    let progress = run_progress(&coordinator);
    assert_eq!(progress.active(), 0);
    assert_eq!(progress.done(), 1);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Done);
    assert_eq!(summaries[0].last_key(), Some(&[0x05u8][..]));
}

#[test]
fn advance_shard_exhausted_empty_preserves_restored_cursor_after_checkpointed_progress() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let claimed = claim_lease(&mut coordinator, &identity);
    let checkpoint = Cursor::with_last_key(item_key("resume.txt"));

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &claimed,
        &ShardCompletionOutcome::Checkpoint {
            checkpoint: checkpoint.clone(),
        },
    )
    .expect("checkpoint-backed shard advance must succeed");

    let resumed = ShardLease::new(
        Arc::clone(claimed.shard_id_arc()),
        claimed.lease(),
        RestoredShardState::new(
            claimed.restored_state().shard_spec().clone(),
            checkpoint.clone(),
            claimed.cursor_semantics(),
        ),
        claimed.filesystem_source.clone(),
        claimed.write_context(),
        claimed.tenant_secret_key(),
        wall_clock_now(),
        Instant::now(),
    );

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &resumed,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect("exhausted-empty completion after resumed progress must preserve the restored cursor");

    let progress = run_progress(&coordinator);
    assert_eq!(progress.active(), 0);
    assert_eq!(progress.done(), 1);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Done);
    assert_eq!(
        summaries[0].last_key(),
        checkpoint.last_key().map(|key| key.as_bytes())
    );
}

#[test]
fn advance_shard_complete_uses_receipt_cursor_under_completed_semantics() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let checkpoint = Cursor::with_last_key(item_key("secret.txt"));

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Complete {
            checkpoint: checkpoint.clone(),
        },
    )
    .expect("checkpoint-backed shard completion must succeed");

    let progress = run_progress(&coordinator);
    assert_eq!(progress.active(), 0);
    assert_eq!(progress.done(), 1);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Done);
    assert_eq!(
        summaries[0].last_key(),
        Some(
            checkpoint
                .last_key()
                .expect("checkpoint key must be present")
                .as_bytes()
        )
    );
    assert_ne!(
        summaries[0].last_key(),
        Some(lease.range_start()),
        "completion must honor the receipt-derived checkpoint instead of the shard range start",
    );
}

#[test]
fn advance_shard_idempotent_replay_succeeds_silently() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x05", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let outcome = ShardCompletionOutcome::ExhaustedEmpty;

    advance_shard(&mut coordinator, identity.tenant, &lease, &outcome)
        .expect("first completion should succeed");

    advance_shard(&mut coordinator, identity.tenant, &lease, &outcome)
        .expect("replayed completion with identical OpId should succeed");

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].status(),
        ShardStatus::Done,
        "idempotent replay must not regress terminal shard state"
    );
}

#[test]
fn advance_shard_checkpoint_keeps_shard_active() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"a", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let checkpoint = Cursor::with_last_key(item_key("secret.txt"));

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Checkpoint {
            checkpoint: checkpoint.clone(),
        },
    )
    .expect("checkpoint-backed shard advance must succeed");

    let progress = run_progress(&coordinator);
    assert_eq!(progress.active(), 1);
    assert_eq!(progress.done(), 0);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Active);
    assert_eq!(
        summaries[0].last_key(),
        checkpoint.last_key().map(|key| key.as_bytes())
    );
}

#[test]
fn advance_shard_rejects_tenant_mismatch() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // Use a different tenant than the one embedded in the lease.
    let wrong_tenant = TenantId::from_bytes([0xFF; 32]);
    assert_ne!(wrong_tenant, identity.tenant);

    let err = advance_shard(
        &mut coordinator,
        wrong_tenant,
        &lease,
        &ShardCompletionOutcome::ExhaustedEmpty,
    )
    .expect_err("advance_shard with mismatched tenant must fail");

    assert!(
        matches!(err, DistributedRuntimeError::Runtime(_)),
        "expected Runtime error variant, got: {err:?}"
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("tenant mismatch"),
        "error message should mention tenant mismatch, got: {msg}"
    );
}

// ============================================================================
// drain_commit_stage tests
// ============================================================================

#[test]
fn drain_commit_stage_returns_error_on_durable_commit_failure() {
    let wc = write_context();
    let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
    let done_ledger = InMemoryDoneLedger::new();
    let cancel = CancellationToken::new();

    let pipeline = CommitPipeline::start(
        findings_sink.clone(),
        done_ledger,
        CommitPipelineConfig {
            execution_queue_capacity: 4,
            outcome_queue_capacity: 4,
        },
        cancel,
    )
    .expect("pipeline should start");

    let (sender, drainer) = pipeline.split();

    // Submit two items: item 1 will succeed, item 2 will fail at durable commit.
    let work_1 = QueuedCommit::new(
        wc,
        fixture_completed_unit(1, 0xA1),
        fixture_scanned_translation(wc, 0xA1, 1),
    );
    let work_2 = QueuedCommit::new(
        wc,
        fixture_completed_unit(2, 0xA2),
        fixture_scanned_translation(wc, 0xA2, 2),
    );

    sender.submit(work_1).expect("submit item 1");
    sender.submit(work_2).expect("submit item 2");
    drop(sender);

    std::thread::scope(|scope| {
        let drain_handle = scope.spawn(move || drain_commit_stage(drainer, wc, 4));

        // Wait for the first findings write to arrive, then release it normally.
        wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release first findings write");

        // After the first item's findings commit succeeds, inject a failure so
        // the second item's findings durable commit fails.
        wait_until(|| findings_sink.pending_count().expect("pending count") >= 1);
        findings_sink
            .fail_next_commits(1)
            .expect("inject commit failure");
        findings_sink
            .release_next(CompletionOrder::OldestFirst)
            .expect("release second findings write");

        let drain_result = drain_handle.join().expect("drain thread should not panic");

        let err = drain_result
            .expect_err("drain_commit_stage should return an error when a commit stage item fails");
        let msg = err.to_string();
        assert!(
            msg.contains("durable commit failed"),
            "error should mention durable commit failure, got: {msg}"
        );
    });
}

// ============================================================================
// park_shard_on_error tests
// ============================================================================

#[test]
fn park_shard_on_error_rejects_tenant_mismatch() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // Use a different tenant than the one embedded in the lease.
    let wrong_tenant = TenantId::from_bytes([0xFF; 32]);
    assert_ne!(wrong_tenant, identity.tenant);

    let err = park_shard_on_error(&mut coordinator, wrong_tenant, &lease, ParkReason::Poisoned)
        .expect_err("park_shard_on_error with mismatched tenant must fail");

    assert!(
        matches!(err, ParkError::TenantMismatch { .. }),
        "expected TenantMismatch variant, got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("tenant mismatch"),
        "error message should mention tenant mismatch, got: {msg}"
    );
}

#[test]
fn park_shard_on_error_idempotent_replay() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    // First park succeeds.
    park_shard_on_error(
        &mut coordinator,
        identity.tenant,
        &lease,
        ParkReason::Poisoned,
    )
    .expect("first park_shard_on_error must succeed");

    // Second park with the same lease is an idempotent replay — must also succeed.
    park_shard_on_error(
        &mut coordinator,
        identity.tenant,
        &lease,
        ParkReason::Poisoned,
    )
    .expect("idempotent replay of park_shard_on_error must succeed");

    // The shard should be in Parked status.
    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Parked);
}

// ============================================================================
// should_park_git_repo_failure tests
// ============================================================================

#[test]
fn should_park_git_repo_failure_detects_saturation() {
    let error = oid_map_saturation_error(&ToxicDigest::of_bytes(b"test-shard"), "test detail");
    assert!(
        should_park_git_repo_failure(&error),
        "OID-map saturation error must be classified as park-worthy"
    );
}

#[test]
fn should_park_git_repo_failure_rejects_non_saturation_errors() {
    // Driver with a non-saturation inner error.
    let driver =
        DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(AnyError::msg("generic")));
    assert!(
        !should_park_git_repo_failure(&driver),
        "generic Driver error must not trigger parking"
    );

    let coordinator = DistributedRuntimeError::Coordinator(AnyError::msg("coord"));
    assert!(
        !should_park_git_repo_failure(&coordinator),
        "Coordinator error must not trigger parking"
    );

    let durability = DistributedRuntimeError::Durability(AnyError::msg("durability"));
    assert!(
        !should_park_git_repo_failure(&durability),
        "Durability error must not trigger parking"
    );

    let lease_uncertain =
        DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed {
            deadline: LogicalTime::from_raw(10),
            observed: LogicalTime::from_raw(11),
        });
    assert!(
        !should_park_git_repo_failure(&lease_uncertain),
        "LeaseUncertain error must not trigger parking"
    );
}
