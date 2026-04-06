//! End-to-end integration tests for the distributed module.
//!
//! Covers `run_filesystem_lease`, `run_worker`, and `run_git_repo_worker`
//! workflows including backpressure, deadline expiry, recovery, and error
//! propagation.

use std::fs;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

// -- Test infrastructure from the sibling test_support module ----------------

use super::test_support::*;

// -- Re-exports from the distributed module's public API --------------------

use super::*;

// -- Submodule internals (pub(super) items) ---------------------------------

use super::commit_bridge::ReceiptCommitSink;
use super::execution::{
    GIT_REPO_RECEIPT_FAMILIES, run_filesystem_lease, scan_ordered_filesystem_lease_with_engine,
    secret_fixture,
};
use super::lease_ops::advance_shard;
use super::types::{
    HydratedFilesystemSource, PageLoopTermination, ShardCompletionOutcome, wall_clock_now,
};

// -- External crate imports -------------------------------------------------

use gossip_contracts::{
    connector::Cursor,
    identity::{RuleFingerprint, ShardId},
    persistence::DoneLedgerStatus,
};
use gossip_coordination::{
    CoordinationBackend, CursorSemantics, CursorUpdate as CoordCursorUpdate, ParkError, RunConfig,
    RunManagement, ShardClaiming, ShardStatus,
};
use gossip_persistence_inmemory::{CompletionOrder, InMemoryDoneLedger, InMemoryFindingsSink};
use scanner_scheduler::events::NullEventOutput;
use tempfile::tempdir;

use crate::{
    CancellationToken, ScanBudgets, ScanRuntimeError, build_runtime_engine,
    commit_pipeline::{CommitPipeline, CommitPipelineConfig, CommitStageOutput},
    coordination_sink::{CoordinationEventRecorder, MirrorErrorClass, StageSignal},
    git_mirror::LocalMirrorManager,
};

// ============================================================================
// Filesystem lease execution tests
// ============================================================================

#[test]
fn run_filesystem_lease_backpressures_when_findings_sink_is_slow() {
    const SECRET_FILE_COUNT: usize = 4;
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    let dir = tempdir().expect("tempdir");
    for index in 0..SECRET_FILE_COUNT {
        let path = dir.path().join(format!("secret-{index:02}.txt"));
        fs::write(path, secret_fixture()).expect("write secret fixture");
    }

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    let findings_sink = InMemoryFindingsSink::with_auto_complete(false);
    let done_ledger = InMemoryDoneLedger::new();
    let recorder = Arc::clone(&identity.recorder);
    let lease_for_thread = lease.clone();
    let findings_for_thread = findings_sink.clone();
    let done_for_thread = done_ledger.clone();
    let handle = std::thread::spawn(move || {
        let persistence = DistributedPersistence::new(findings_for_thread, done_for_thread);
        run_filesystem_lease(
            recorder,
            &persistence,
            &lease_for_thread,
            DistributedRuntimeConfig {
                commit_queue_capacity: NonZeroUsize::new(1)
                    .expect("non-zero commit queue capacity"),
                ..DistributedRuntimeConfig::default()
            },
        )
    });

    for _ in 0..POLL_ITERATIONS {
        if findings_sink.pending_count().expect("pending count") == 1 {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    assert_eq!(
        findings_sink.pending_count().expect("pending count"),
        1,
        "queue capacity 1 should expose exactly one blocked findings write"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger must stay empty until the first blocked findings write is released"
    );

    // With queue capacity 1, the first blocked findings write stalls the
    // commit worker, the second item can occupy the execution queue, and
    // any later ordered submission must stop behind that bound.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        findings_sink.pending_count().expect("pending count"),
        1,
        "the ordered filesystem runtime must stop at the bounded findings write instead of accumulating more pending writes"
    );
    assert!(
        !handle.is_finished(),
        "run_filesystem_lease should remain blocked while the bounded commit queue backpressures ordered execution"
    );

    for _ in 0..POLL_ITERATIONS {
        if handle.is_finished() {
            break;
        }
        findings_sink
            .release_all(CompletionOrder::OldestFirst)
            .expect("release pending findings writes");
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        handle.is_finished(),
        "filesystem lease thread did not complete within 10s after findings writes were released"
    );

    let (report, completion) = handle
        .join()
        .expect("filesystem lease thread should not panic")
        .expect("filesystem lease should succeed once findings writes are released");

    assert_eq!(report.items_scanned, SECRET_FILE_COUNT as u64);
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("fully scanned shard should complete after backpressure clears");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"secret-03.txt"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        SECRET_FILE_COUNT,
        "every item should produce one durable done-ledger row after the blocked findings writes drain"
    );
    assert!(
        rows.iter()
            .all(|row| row.status() == DoneLedgerStatus::ScannedWithFindings),
        "all committed rows should preserve the findings-bearing status"
    );
}

#[test]
fn run_filesystem_lease_backpressures_when_done_ledger_is_slow() {
    const SECRET_FILE_COUNT: usize = 4;
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    let dir = tempdir().expect("tempdir");
    for index in 0..SECRET_FILE_COUNT {
        let path = dir.path().join(format!("secret-{index:02}.txt"));
        fs::write(path, secret_fixture()).expect("write secret fixture");
    }

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::with_auto_complete(false);
    let recorder = Arc::clone(&identity.recorder);
    let lease_for_thread = lease.clone();
    let findings_for_thread = findings_sink.clone();
    let done_for_thread = done_ledger.clone();
    let handle = std::thread::spawn(move || {
        let persistence = DistributedPersistence::new(findings_for_thread, done_for_thread);
        run_filesystem_lease(
            recorder,
            &persistence,
            &lease_for_thread,
            DistributedRuntimeConfig {
                commit_queue_capacity: NonZeroUsize::new(1)
                    .expect("non-zero commit queue capacity"),
                ..DistributedRuntimeConfig::default()
            },
        )
    });

    for _ in 0..POLL_ITERATIONS {
        if done_ledger
            .pending_count()
            .expect("pending done-ledger count")
            == 1
        {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    assert_eq!(
        done_ledger
            .pending_count()
            .expect("pending done-ledger count"),
        1,
        "queue capacity 1 should expose exactly one blocked done-ledger write"
    );
    assert!(
        !findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "findings should already be durable before the blocked done-ledger write completes"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "the blocked done-ledger write must prevent durable row advancement"
    );

    // Findings durability may already have succeeded for the leading item,
    // but queue capacity 1 still requires the ordered runtime to stop once
    // the first done-ledger commit is waiting for release.
    std::thread::sleep(Duration::from_millis(200));
    assert_eq!(
        done_ledger
            .pending_count()
            .expect("pending done-ledger count"),
        1,
        "the ordered filesystem runtime must stop at the bounded done-ledger write instead of stacking more pending rows"
    );
    assert!(
        !handle.is_finished(),
        "run_filesystem_lease should remain blocked while the done-ledger write stalls the commit stage"
    );

    for _ in 0..POLL_ITERATIONS {
        if handle.is_finished() {
            break;
        }
        done_ledger
            .release_all(CompletionOrder::OldestFirst)
            .expect("release pending done-ledger writes");
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        handle.is_finished(),
        "filesystem lease thread did not complete within 10s after done-ledger writes were released"
    );

    let (report, completion) = handle
        .join()
        .expect("filesystem lease thread should not panic")
        .expect("filesystem lease should succeed once done-ledger writes are released");

    assert_eq!(report.items_scanned, SECRET_FILE_COUNT as u64);
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("fully scanned shard should complete after backpressure clears");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"secret-03.txt"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        SECRET_FILE_COUNT,
        "every item should produce one durable done-ledger row after the blocked ledger writes drain"
    );
    assert!(
        rows.iter()
            .all(|row| row.status() == DoneLedgerStatus::ScannedWithFindings),
        "all committed rows should preserve the findings-bearing status"
    );
}

#[test]
fn ordered_filesystem_scan_backpressures_when_outcomes_are_not_drained() {
    const SECRET_FILE_COUNT: usize = 5;
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    let dir = tempdir().expect("tempdir");
    for index in 0..SECRET_FILE_COUNT {
        let path = dir.path().join(format!("secret-{index:02}.txt"));
        fs::write(path, secret_fixture()).expect("write secret fixture");
    }

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
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
            execution_queue_capacity: 1,
            outcome_queue_capacity: 1,
        },
        CancellationToken::new(),
    )
    .expect("pipeline");
    let sender = pipeline.sender();
    let recorder = Arc::new(Recorder::default());
    let lease_for_thread = lease.clone();
    let done_for_thread = done_ledger.clone();
    let engine_for_thread = Arc::clone(&engine);
    let scan_handle = std::thread::spawn(move || {
        let out = NullEventOutput;
        let cancel = CancellationToken::new();
        let rule_fingerprint = {
            let engine = Arc::clone(&engine_for_thread);
            Arc::new(move |rule_id: u32| {
                RuleFingerprint::from_bytes(engine.rule_fingerprint_bytes(rule_id))
            }) as Arc<dyn Fn(u32) -> RuleFingerprint + Send + Sync>
        };
        let commit = ReceiptCommitSink::new(
            recorder,
            Arc::clone(lease_for_thread.shard_id_arc()),
            lease_for_thread.write_context(),
            lease_for_thread.tenant_secret_key(),
            rule_fingerprint,
            sender,
        );
        let outcome = scan_ordered_filesystem_lease_with_engine(
            &lease_for_thread,
            &scan_config,
            &done_for_thread,
            engine_for_thread,
            &out,
            &commit,
            &cancel,
        );
        let submitted = commit.finish();
        (outcome, submitted)
    });

    let durable_before_block = loop {
        let durable_rows = done_ledger.snapshot().expect("done-ledger snapshot").len();
        if durable_rows >= 2 {
            break durable_rows;
        }
        std::thread::sleep(POLL_INTERVAL);
    };

    // Outcome capacity 1 with no drainer means the first committed outcome
    // occupies the queue and the next outcome send stalls the worker.
    // Stable durable-row count across this window shows the ordered scan is
    // waiting on the bounded outcome channel rather than still advancing.
    std::thread::sleep(Duration::from_millis(200));
    let durable_after_block = done_ledger.snapshot().expect("done-ledger snapshot").len();
    assert_eq!(
        durable_after_block, durable_before_block,
        "without draining commit outcomes, durable progress must stop once the bounded outcome queue fills"
    );
    assert!(
        !scan_handle.is_finished(),
        "ordered filesystem scan should block once outcome delivery backpressures the receipt bridge"
    );

    let mut drained = 0usize;
    for _ in 0..POLL_ITERATIONS {
        if scan_handle.is_finished() {
            break;
        }
        match pipeline.recv_timeout(POLL_INTERVAL) {
            Ok(CommitStageOutput::Committed { .. }) => drained += 1,
            Ok(CommitStageOutput::Failed { error, .. }) => {
                panic!("expected committed outcome, got failure: {error}")
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                panic!("commit pipeline disconnected before scan completed")
            }
        }
    }
    assert!(
        scan_handle.is_finished(),
        "ordered filesystem scan did not finish within 10s after outcomes started draining"
    );

    let (outcome, submitted) = scan_handle.join().expect("scan thread should not panic");
    let outcome = outcome.expect("ordered filesystem scan should succeed once outcomes drain");
    let submitted = submitted.expect("receipt sink finish should succeed");
    assert_eq!(
        submitted.len(),
        SECRET_FILE_COUNT,
        "every ordered file should be submitted exactly once"
    );
    assert_eq!(
        outcome.termination,
        PageLoopTermination::ExhaustedEmptyConfirmed,
        "draining outcomes should let the ordered filesystem scan finish the shard"
    );

    while drained < submitted.len() {
        match pipeline
            .recv_timeout(Duration::from_secs(1))
            .expect("remaining commit outcome")
        {
            CommitStageOutput::Committed { .. } => drained += 1,
            CommitStageOutput::Failed { error, .. } => {
                panic!("expected committed outcome, got failure: {error}")
            }
        }
    }
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot").len(),
        SECRET_FILE_COUNT,
        "all ordered items should commit durably after the outcome queue drains"
    );
    pipeline.shutdown().expect("worker should join");
}

#[test]
fn run_filesystem_lease_binary_skip_produces_skipped_done_ledger_row() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("sample.bin"), binary_fixture()).expect("write binary fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("binary filesystem lease should succeed");

    assert_eq!(report.binary_skipped, 1);
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("skipped item should still produce a progress-bearing completion");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"sample.bin"
    );
    assert!(
        findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "binary skip should not emit findings observations"
    );
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status(), DoneLedgerStatus::Skipped);
}

#[test]
fn run_filesystem_lease_clean_only_shard_produces_checkpoint_and_done_ledger_entry() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("readme.txt"), clean_fixture()).expect("write clean fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("clean-only filesystem shard should succeed");

    assert_eq!(report.items_scanned, 1);
    // Clean files still produce a done-ledger entry ("scanned, nothing
    // found") and advance the checkpoint cursor so resume skips them.
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("clean file should still produce a progress-bearing completion");
    };
    assert!(
        checkpoint.last_key().is_some(),
        "clean file should still produce a checkpoint cursor for resume"
    );
    assert!(
        findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty()
    );
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "clean file should produce exactly one done-ledger row"
    );
}

#[test]
fn run_filesystem_lease_commit_failure_prevents_completion() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .fail_next_commits(1)
        .expect("inject done-ledger commit failure");
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

    let error = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect_err("commit failure should abort shard completion");

    assert!(
        error.to_string().contains("durable commit failed")
            || error.to_string().contains("done-ledger durability failed"),
        "unexpected error: {error}"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty()
    );
    assert!(
        !findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "findings may still be durable before the done-ledger failure"
    );
    assert_eq!(run_progress(&coordinator).active(), 1);
}

#[test]
fn run_filesystem_lease_succeeds_with_mixed_finding_and_clean_files() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write secret fixture");
    fs::write(dir.path().join("readme.txt"), clean_fixture()).expect("write clean fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("mixed shard should succeed");

    assert!(
        report.items_scanned >= 2,
        "both files should be scanned, got {}",
        report.items_scanned,
    );
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("shard with findings should produce a progress-bearing completion");
    };
    assert!(
        checkpoint.last_key().is_some(),
        "shard with findings should checkpoint"
    );

    let observations = findings_sink
        .observations_snapshot()
        .expect("observations snapshot");
    assert!(
        !observations.is_empty(),
        "secret file should produce durable findings"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        2,
        "both files (finding-bearing and clean) produce a done-ledger row"
    );
}

#[test]
fn run_filesystem_lease_reports_deadline_expiry_before_completion() {
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 500);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .set_auto_complete(false)
        .expect("disable done-ledger auto-complete");

    let recorder = Arc::clone(&identity.recorder);
    let lease_for_thread = lease.clone();
    let findings_for_thread = findings_sink.clone();
    let done_for_thread = done_ledger.clone();
    let handle = std::thread::spawn(move || {
        let persistence = DistributedPersistence::new(findings_for_thread, done_for_thread);
        run_filesystem_lease(
            recorder,
            &persistence,
            &lease_for_thread,
            DistributedRuntimeConfig {
                commit_queue_capacity: NonZeroUsize::new(1)
                    .expect("non-zero commit queue capacity"),
                ..DistributedRuntimeConfig::default()
            },
        )
    });

    let pending_op = loop {
        let pending = done_ledger.pending_ids().expect("pending done-ledger ids");
        match pending.as_slice() {
            [op_id] => break *op_id,
            [] => std::thread::sleep(POLL_INTERVAL),
            _ => panic!(
                "expected one pending done-ledger commit, got {}",
                pending.len()
            ),
        }
    };

    std::thread::sleep(Duration::from_millis(650));
    assert!(
        done_ledger
            .release_specific(pending_op)
            .expect("release blocked done-ledger commit"),
        "pending done-ledger op should release"
    );

    for _ in 0..POLL_ITERATIONS {
        if handle.is_finished() {
            break;
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        handle.is_finished(),
        "filesystem lease thread did not terminate within 10s after the blocked commit released"
    );

    let error = handle
        .join()
        .expect("filesystem lease thread should not panic")
        .expect_err("deadline expiry should stop the lease before completion");
    assert!(
        matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
        ),
        "expected deadline-based lease uncertainty, got: {error:?}"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "the in-flight commit may still finish durably before the worker aborts"
    );

    let progress = run_progress(&coordinator);
    assert_eq!(progress.active(), 1);
    assert_eq!(progress.done(), 0);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].status(), ShardStatus::Active);
    assert!(
        summaries[0].last_key().is_none(),
        "lease uncertainty must not attempt terminal completion"
    );
}

#[test]
fn run_filesystem_lease_reports_deadline_expiry_after_drain_failure_with_remaining_work() {
    const SECRET_FILE_COUNT: usize = 12;
    const SUCCESSFUL_COMMITS_BEFORE_FAILURE: usize = 2;
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);
    const LEASE_TTL_MS: u64 = 1_500;

    let dir = tempdir().expect("tempdir");
    for index in 0..SECRET_FILE_COUNT {
        let path = dir.path().join(format!("secret-{index:02}.txt"));
        fs::write(path, secret_fixture()).expect("write secret fixture");
    }

    let mut coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], LEASE_TTL_MS);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .set_auto_complete(false)
        .expect("disable done-ledger auto-complete");

    let recorder = Arc::clone(&identity.recorder);
    let lease_for_thread = lease.clone();
    let findings_for_thread = findings_sink.clone();
    let done_for_thread = done_ledger.clone();
    let handle = std::thread::spawn(move || {
        let persistence = DistributedPersistence::new(findings_for_thread, done_for_thread);
        run_filesystem_lease(
            recorder,
            &persistence,
            &lease_for_thread,
            DistributedRuntimeConfig {
                commit_queue_capacity: NonZeroUsize::new(1)
                    .expect("non-zero commit queue capacity"),
                ..DistributedRuntimeConfig::default()
            },
        )
    });

    let next_pending_done_commit = || {
        for _ in 0..POLL_ITERATIONS {
            let pending = done_ledger.pending_ids().expect("pending done-ledger ids");
            match pending.as_slice() {
                [op_id] => return *op_id,
                [] => std::thread::sleep(POLL_INTERVAL),
                _ => panic!(
                    "expected one pending done-ledger commit with queue capacity 1, got {}",
                    pending.len()
                ),
            }
        }
        panic!("timed out waiting for a pending done-ledger commit (10s)");
    };

    for committed in 0..SUCCESSFUL_COMMITS_BEFORE_FAILURE {
        let op_id = next_pending_done_commit();
        assert!(
            done_ledger
                .release_specific(op_id)
                .expect("release successful done-ledger commit"),
            "pending done-ledger op should release"
        );

        for _ in 0..POLL_ITERATIONS {
            if done_ledger.snapshot().expect("done-ledger snapshot").len() == committed + 1 {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        assert_eq!(
            done_ledger.snapshot().expect("done-ledger snapshot").len(),
            committed + 1,
            "done-ledger durability did not converge within 10s for commit {committed}"
        );
    }

    // Wait for the 3rd commit to appear but keep it blocked. The lease
    // thread is parked waiting for this commit to resolve, so it is
    // deterministically alive while we wait for the deadline to expire.
    let failing_op = next_pending_done_commit();

    // Let the lease TTL expire while the commit is still pending. The
    // watchdog fires independently and records LeaseUncertain.
    std::thread::sleep(Duration::from_millis(LEASE_TTL_MS + 250));

    // Now inject the failure and release. Both a drain failure and a
    // deadline expiry are present; the test asserts LeaseUncertain wins.
    done_ledger
        .fail_next_commits(1)
        .expect("inject done-ledger commit failure");
    assert!(
        done_ledger
            .release_specific(failing_op)
            .expect("release failing done-ledger commit"),
        "failing done-ledger op should release"
    );
    done_ledger
        .set_auto_complete(true)
        .expect("re-enable done-ledger auto-complete");
    for _ in 0..POLL_ITERATIONS {
        if handle.is_finished() {
            break;
        }
        for op_id in done_ledger.pending_ids().expect("pending done-ledger ids") {
            assert!(
                done_ledger
                    .release_specific(op_id)
                    .expect("release pending done-ledger commit"),
                "pending done-ledger op should release"
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        handle.is_finished(),
        "filesystem lease thread did not terminate within 10s after releasing all pending commits"
    );

    let error = handle
        .join()
        .expect("filesystem lease thread should not panic")
        .expect_err("deadline expiry should outrank drain failure while work remains active");
    assert!(
        matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
        ),
        "expected deadline-based lease uncertainty, got: {error:?}"
    );
}

#[test]
fn run_filesystem_lease_rejects_already_expired_lease() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    // TTL of 1ms -- the lease will have expired by the time we call
    // run_filesystem_lease.
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 1);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);

    std::thread::sleep(Duration::from_millis(50));

    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let error = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect_err("already-expired lease should be rejected before starting the scan pipeline");

    assert!(
        matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
        ),
        "expected immediate deadline-elapsed rejection, got: {error:?}"
    );

    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "no done-ledger entries should exist because the scan pipeline never started"
    );
}

#[test]
fn run_filesystem_lease_rejects_expired_lease_before_engine_setup() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 1);
    let identity = worker_identity(Path::new("/fallback"));
    let claimed = claim_lease(&mut coordinator, &identity);

    std::thread::sleep(Duration::from_millis(50));

    let lease = ShardLease::new(
        Arc::clone(claimed.shard_id_arc()),
        claimed.lease(),
        claimed.restored_state().clone(),
        HydratedFilesystemSource::new(
            claimed
                .scan_config()
                .clone()
                .with_rules_file(Some(dir.path().join("missing-rules.toml"))),
            claimed.source_mode(),
        ),
        claimed.write_context(),
        claimed.tenant_secret_key(),
        wall_clock_now(),
        std::time::Instant::now(),
    );
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let error = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect_err("expired lease should abort before engine setup");

    assert!(
        matches!(
            error,
            DistributedRuntimeError::LeaseUncertain(LeaseUncertainty::DeadlineElapsed { .. })
        ),
        "expected immediate deadline-elapsed rejection, got: {error:?}"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "no done-ledger entries should exist because engine setup never ran"
    );
}

/// Deferred items (too large for the byte budget) must not advance the
/// checkpoint past their key positions. If they did, the next shard claim
/// would start after the deferred key and permanently lose the item.
#[test]
fn run_filesystem_lease_stops_checkpoint_before_deferred_item() {
    let dir = tempdir().expect("tempdir");
    // a-small.txt will be admitted (key order: first)
    fs::write(dir.path().join("a-small.txt"), clean_fixture()).expect("write a");
    // b-large.txt exceeds the byte budget and will be deferred
    fs::write(dir.path().join("b-large.txt"), vec![b'x'; 100_000]).expect("write b");
    // c-small.txt is admitted but comes after b-large.txt in key order
    fs::write(dir.path().join("c-small.txt"), clean_fixture()).expect("write c");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let (_report, checkpoint) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig {
            budgets: ScanBudgets {
                max_items: 100,
                // b-large.txt (100 KB) exceeds this budget, triggering deferral.
                max_bytes: 1_000,
            },
            ..DistributedRuntimeConfig::default()
        },
    )
    .expect("lease with deferred item should succeed");

    let ShardCompletionOutcome::Checkpoint { checkpoint } = checkpoint else {
        panic!("at least one terminal item should be committed before the deferral");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"a-small.txt",
        "checkpoint must not advance past the deferred item (b-large.txt)"
    );

    // Only a-small.txt should have a done-ledger entry.
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "only items committed before the deferred boundary get done-ledger entries"
    );
}

#[test]
fn run_filesystem_lease_rejects_zero_progress_partial_shard_without_exhaustion() {
    let dir = tempdir().expect("tempdir");
    // a-large.txt sorts first and exceeds the byte budget, so execution
    // stops before any receipt-backed progress is possible.
    fs::write(dir.path().join("a-large.txt"), vec![b'x'; 100_000]).expect("write a");
    // b-small.txt comes later in key order and must not be used to infer
    // exhausted-empty completion for the shard.
    fs::write(dir.path().join("b-small.txt"), clean_fixture()).expect("write b");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());

    let err = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig {
            budgets: ScanBudgets {
                max_items: 100,
                max_bytes: 1_000,
            },
            ..DistributedRuntimeConfig::default()
        },
    )
    .expect_err("partial shard without durable progress must not complete as exhausted-empty");

    assert!(
        err.to_string()
            .contains("stopped before confirming exhaustion"),
        "unexpected error: {err}"
    );
}

#[test]
fn run_filesystem_lease_complete_path_scans_required_exhausted_empty_suffix() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("only.txt"), clean_fixture()).expect("write clean fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("single-page complete shard should succeed");

    assert_eq!(report.items_scanned, 1);
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("single terminal page should still produce progress-bearing completion");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"only.txt"
    );
}

#[test]
fn run_filesystem_lease_all_already_done_terminal_recovery_returns_complete_cursor() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("only.txt"), clean_fixture()).expect("write clean fixture");

    let done_ledger = InMemoryDoneLedger::new();
    let seed_persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());
    let seed_identity = worker_identity(Path::new("/fallback"));
    let mut seed_coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let seed_lease = claim_lease(&mut seed_coordinator, &seed_identity);

    let (_seed_report, seed_completion) = run_filesystem_lease(
        Arc::clone(&seed_identity.recorder),
        &seed_persistence,
        &seed_lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("seed pass should durably populate the done ledger");
    let ShardCompletionOutcome::Complete { checkpoint } = seed_completion else {
        panic!("seed pass should finish with a terminal checkpoint");
    };
    let expected_last_key = checkpoint
        .last_key()
        .expect("seed checkpoint last_key")
        .as_bytes()
        .to_vec();

    let recovery_persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());
    let recovery_identity = worker_identity(Path::new("/fallback"));
    let mut recovery_coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let recovery_lease = claim_lease(&mut recovery_coordinator, &recovery_identity);

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&recovery_identity.recorder),
        &recovery_persistence,
        &recovery_lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("recovery pass should reuse already-done coverage");

    assert_eq!(report.items_scanned, 1);
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("all-already-done terminal replay should preserve the terminal cursor");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("recovery checkpoint last_key")
            .as_bytes(),
        expected_last_key.as_slice()
    );
}

#[test]
fn run_filesystem_lease_multi_page_terminal_exhausted_empty_sequence() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a.txt"), clean_fixture()).expect("write a");
    fs::write(dir.path().join("b.txt"), clean_fixture()).expect("write b");
    fs::write(dir.path().join("c.txt"), clean_fixture()).expect("write c");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig {
            budgets: ScanBudgets {
                max_items: 1,
                max_bytes: 1_000_000,
            },
            ..DistributedRuntimeConfig::default()
        },
    )
    .expect("multi-page shard should succeed");

    assert_eq!(
        report.items_scanned, 3,
        "all three files should be scanned across multiple pages"
    );
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("3-item shard should produce progress-bearing completion");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"c.txt"
    );
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        3,
        "all three items should have done-ledger entries"
    );
}

/// When every item in the shard is already in the done ledger, the page
/// loop commits zero new receipts (`checkpoint_cursor = None`). If the
/// page loop still advanced the resume cursor past the lease's original
/// position, the recovered cursor provides the completion checkpoint.
#[test]
fn run_filesystem_lease_exhausted_with_zero_commits_uses_recovered_cursor_for_completion() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("alpha.txt"), clean_fixture()).expect("write alpha");
    fs::write(dir.path().join("bravo.txt"), clean_fixture()).expect("write bravo");

    // Seed pass: scan both files to populate the done ledger with durable
    // entries. The seed completion must be `Complete` so we know the ledger
    // has rows for every item in the shard.
    let done_ledger = InMemoryDoneLedger::new();
    let seed_identity = worker_identity(Path::new("/fallback"));
    let mut seed_coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let seed_lease = claim_lease(&mut seed_coordinator, &seed_identity);
    let seed_persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let (_seed_report, seed_completion) = run_filesystem_lease(
        Arc::clone(&seed_identity.recorder),
        &seed_persistence,
        &seed_lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("seed pass should populate the done ledger");
    assert!(
        matches!(seed_completion, ShardCompletionOutcome::Complete { .. }),
        "seed pass should terminate with Complete"
    );

    let done_count_after_seed = done_ledger
        .snapshot()
        .expect("done-ledger snapshot after seed")
        .len();
    assert_eq!(
        done_count_after_seed, 2,
        "seed pass should write one done-ledger row per item"
    );

    // Recovery pass: fresh coordinator so the lease starts at
    // Cursor::initial(). The done ledger is shared, so every item is
    // already done and zero receipts are committed. The page loop still
    // advances the resume cursor past both files, producing a recovered
    // checkpoint that differs from the lease's original cursor.
    let recovery_identity = worker_identity(Path::new("/fallback"));
    let mut recovery_coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let recovery_lease = claim_lease(&mut recovery_coordinator, &recovery_identity);
    let recovery_persistence =
        DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    assert_eq!(
        *recovery_lease.resume_cursor(),
        Cursor::initial(),
        "recovery lease should start at the initial cursor"
    );

    let (recovery_report, recovery_completion) = run_filesystem_lease(
        Arc::clone(&recovery_identity.recorder),
        &recovery_persistence,
        &recovery_lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("recovery pass with all-done items should succeed");

    // Both items were visited but none were committed (all already done).
    assert_eq!(
        recovery_report.items_scanned, 2,
        "both files should be visited even though they are already done"
    );

    // The completion must be `Complete` with the cursor advanced to the
    // last item in key order. This cursor came from the page loop's
    // resume position, not from committed receipts.
    let ShardCompletionOutcome::Complete { checkpoint } = recovery_completion else {
        panic!(
            "zero-commit recovery with advanced resume cursor should produce Complete, \
             got: {recovery_completion:?}"
        );
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("recovered checkpoint last_key")
            .as_bytes(),
        b"bravo.txt",
        "recovered cursor should point to the last item in key order"
    );

    // The done ledger must not have grown -- no new receipts were committed.
    let done_count_after_recovery = done_ledger
        .snapshot()
        .expect("done-ledger snapshot after recovery")
        .len();
    assert_eq!(
        done_count_after_recovery, done_count_after_seed,
        "recovery pass should not add new done-ledger entries"
    );
}

// ============================================================================
// Worker loop tests
// ============================================================================

#[test]
fn run_worker_returns_zero_report_when_all_shards_are_terminal() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let raw_lease = claim_coordination_lease(&mut coordinator, worker(1));
    let final_cursor = CoordCursorUpdate::with_last_key(b"done");
    let _ = coordinator
        .complete(
            wall_clock_now(),
            tenant(),
            &raw_lease,
            &final_cursor,
            gossip_contracts::identity::OpId::from_raw(99),
        )
        .expect("complete shard");

    let report = run_worker(
        &mut coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("settled run should succeed");

    assert_eq!(report.leases_seen, 0);
    assert_eq!(report.shards_scanned, 0);
}

#[test]
fn run_worker_processes_multiple_shards_from_queue() {
    let dir_a = tempdir().expect("tempdir a");
    let dir_b = tempdir().expect("tempdir b");
    fs::write(dir_a.path().join("alpha-secret.txt"), secret_fixture()).expect("write fixture a");
    fs::write(dir_b.path().join("omega-secret.txt"), secret_fixture()).expect("write fixture b");

    let mut coordinator = setup_coordinator_with_ranges(
        &[(dir_a.path(), b"a", b"n"), (dir_b.path(), b"n", b"\xFF")],
        30_000,
    );
    let report = run_worker(
        &mut coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("multi-shard run should succeed");

    assert_eq!(report.leases_seen, 2);
    assert_eq!(report.shards_scanned, 2);
    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 2);
    assert!(
        summaries
            .iter()
            .all(|summary| summary.status() == ShardStatus::Done)
    );
}

#[test]
fn run_worker_retries_until_live_lease_expires() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 2_000);
    let _ = claim_coordination_lease(&mut coordinator, worker(99));

    let report = run_worker(
        &mut coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("lease expiry retry should eventually claim the shard");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);
    assert_eq!(run_progress(&coordinator).done(), 1);
}

#[test]
fn run_worker_recovers_from_partial_done_ledger_failure_without_duplicate_rows() {
    const SECRET_FILE_COUNT: usize = 12;
    const SUCCESSFUL_COMMITS_BEFORE_CRASH: usize = 4;
    const POLL_ITERATIONS: usize = 2_000;
    const POLL_INTERVAL: Duration = Duration::from_millis(5);

    let dir = tempdir().expect("tempdir");
    for index in 0..SECRET_FILE_COUNT {
        let path = dir.path().join(format!("secret-{index:02}.txt"));
        fs::write(path, secret_fixture()).expect("write secret fixture");
    }

    let config = DistributedRuntimeConfig {
        commit_queue_capacity: NonZeroUsize::new(1).expect("non-zero queue capacity"),
        ..DistributedRuntimeConfig::default()
    };

    let expected_findings_sink = InMemoryFindingsSink::new();
    let expected_done_ledger = InMemoryDoneLedger::new();
    let mut expected_coordinator =
        setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    run_worker(
        &mut expected_coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(expected_findings_sink.clone(), expected_done_ledger.clone()),
        config,
    )
    .expect("baseline run should succeed");

    let expected = snapshot_sink_state(&expected_findings_sink, &expected_done_ledger, "baseline");
    let expected_last_key = shard_summaries(&expected_coordinator)[0]
        .last_key()
        .expect("completed baseline shard should have a last_key")
        .to_vec();

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .set_auto_complete(false)
        .expect("disable done-ledger auto-complete");

    let coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 2_000);
    let first_run = std::thread::spawn({
        let findings_sink = findings_sink.clone();
        let done_ledger = done_ledger.clone();
        move || {
            let mut coordinator = coordinator;
            let result = run_worker(
                &mut coordinator,
                worker_identity(Path::new("/fallback")),
                DistributedPersistence::new(findings_sink, done_ledger),
                config,
            );
            (coordinator, result)
        }
    });

    let next_pending_done_commit = || {
        for _ in 0..POLL_ITERATIONS {
            let pending = done_ledger.pending_ids().expect("pending done-ledger ids");
            match pending.as_slice() {
                [op_id] => return *op_id,
                [] => std::thread::sleep(POLL_INTERVAL),
                _ => panic!(
                    "expected one pending done-ledger commit with queue capacity 1, got {}",
                    pending.len()
                ),
            }
        }
        panic!("timed out waiting for a pending done-ledger commit (10s)");
    };

    for committed in 0..SUCCESSFUL_COMMITS_BEFORE_CRASH {
        let op_id = next_pending_done_commit();
        assert!(
            done_ledger
                .release_specific(op_id)
                .expect("release successful done-ledger commit"),
            "pending done-ledger op should release"
        );

        for _ in 0..POLL_ITERATIONS {
            let durable_rows = done_ledger.snapshot().expect("done-ledger snapshot");
            if durable_rows.len() == committed + 1 {
                break;
            }
            std::thread::sleep(POLL_INTERVAL);
        }
        assert_eq!(
            done_ledger.snapshot().expect("done-ledger snapshot").len(),
            committed + 1,
            "done-ledger durability did not converge within 10s for commit {committed}"
        );
    }

    let failing_op = next_pending_done_commit();
    done_ledger
        .fail_next_commits(1)
        .expect("inject done-ledger commit failure");
    assert!(
        done_ledger
            .release_specific(failing_op)
            .expect("release failing done-ledger commit"),
        "failing done-ledger op should release"
    );

    // The findings sink is in auto-complete mode, so observations for the
    // failing commit are already durable before its done-ledger commit was
    // submitted. No synchronization wait is needed before snapshotting.
    let partial_done_keys = done_ledger
        .snapshot()
        .expect("partial done-ledger snapshot")
        .into_iter()
        .map(|record| record.key())
        .collect::<Vec<_>>();
    let partial_observation_ids = findings_sink
        .observations_snapshot()
        .expect("partial observations snapshot")
        .into_iter()
        .map(|record| record.observation_id())
        .collect::<Vec<_>>();

    assert_eq!(partial_done_keys.len(), SUCCESSFUL_COMMITS_BEFORE_CRASH);
    assert!(partial_done_keys.len() < expected.done_keys.len());
    assert!(
        partial_observation_ids.len() > partial_done_keys.len(),
        "the failed item should leave durable observations ahead of the done-ledger"
    );

    done_ledger
        .set_auto_complete(true)
        .expect("re-enable done-ledger auto-complete");
    for _ in 0..POLL_ITERATIONS {
        if first_run.is_finished() {
            break;
        }
        for op_id in done_ledger.pending_ids().expect("pending done-ledger ids") {
            assert!(
                done_ledger
                    .release_specific(op_id)
                    .expect("release pending done-ledger commit"),
                "pending done-ledger op should release"
            );
        }
        std::thread::sleep(POLL_INTERVAL);
    }
    assert!(
        first_run.is_finished(),
        "worker thread did not terminate within 10s after releasing all pending commits"
    );

    let (mut coordinator, first_result) = first_run.join().expect("worker thread should not panic");
    let first_error =
        first_result.expect_err("first worker invocation should fail on done-ledger commit");
    assert!(
        matches!(
            &first_error,
            DistributedRuntimeError::Durability(_) | DistributedRuntimeError::Runtime(_)
        ),
        "expected runtime or durability error, got: {first_error:?}"
    );

    let summaries_after_crash = shard_summaries(&coordinator);
    assert_eq!(summaries_after_crash.len(), 1);
    assert_eq!(summaries_after_crash[0].status(), ShardStatus::Active);
    assert!(
        summaries_after_crash[0].last_key().is_none(),
        "coordinator cursor must not advance before complete_shard runs"
    );
    let acquire_count_after_crash = summaries_after_crash[0].acquire_count();

    let progress_after_crash = run_progress(&coordinator);
    assert_eq!(progress_after_crash.active(), 1);
    assert_eq!(progress_after_crash.done(), 0);

    let done_keys_before_recovery: std::collections::HashSet<_> = done_ledger
        .snapshot()
        .expect("pre-recovery done-ledger snapshot")
        .into_iter()
        .map(|r| r.key())
        .collect();

    let recovery_report = run_worker(
        &mut coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        config,
    )
    .expect("second worker invocation should recover after lease expiry");
    assert_eq!(recovery_report.leases_seen, 1);
    assert_eq!(recovery_report.shards_scanned, 1);

    let done_keys_after_recovery: std::collections::HashSet<_> = done_ledger
        .snapshot()
        .expect("post-recovery done-ledger snapshot")
        .into_iter()
        .map(|r| r.key())
        .collect();
    let new_keys_from_recovery: std::collections::HashSet<_> = done_keys_after_recovery
        .difference(&done_keys_before_recovery)
        .copied()
        .collect();
    let expected_new_keys: std::collections::HashSet<_> = expected
        .done_keys
        .iter()
        .copied()
        .filter(|k| !done_keys_before_recovery.contains(k))
        .collect();
    assert_eq!(
        new_keys_from_recovery, expected_new_keys,
        "recovery should only commit items not already in the done-ledger"
    );

    let recovered = snapshot_sink_state(&findings_sink, &done_ledger, "recovered");

    assert_eq!(recovered.done_keys, expected.done_keys);
    assert_eq!(recovered.finding_ids, expected.finding_ids);
    assert_eq!(recovered.occurrence_ids, expected.occurrence_ids);
    assert_eq!(recovered.observation_ids, expected.observation_ids);

    let summaries_after_recovery = shard_summaries(&coordinator);
    assert_eq!(summaries_after_recovery.len(), 1);
    assert_eq!(summaries_after_recovery[0].status(), ShardStatus::Done);
    assert_eq!(
        summaries_after_recovery[0].last_key(),
        Some(expected_last_key.as_slice())
    );
    assert!(
        summaries_after_recovery[0].acquire_count() > acquire_count_after_crash,
        "recovery must reacquire the shard under a higher fence epoch"
    );
    assert_eq!(run_progress(&coordinator).done(), 1);
}

#[test]
fn run_worker_returns_missing_run_as_coordinator_error() {
    let mut coordinator = gossip_coordination::InMemoryCoordinator::new(30_000);
    let error = run_worker(
        &mut coordinator,
        worker_identity(Path::new("/fallback")),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("missing run should surface a coordinator error");

    assert!(
        matches!(error, DistributedRuntimeError::Coordinator(_)),
        "missing run should produce Coordinator variant, got: {error:?}"
    );
    assert!(error.to_string().contains("run not found"));
}

// ============================================================================
// Git repo worker tests
// ============================================================================

#[test]
fn run_git_repo_worker_completes_singleton_repo_frontier_shard() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(findings.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect("git repo worker should succeed");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);
    assert_eq!(run_progress(&coordinator).done(), 1);
    assert!(
        shard_summaries(&coordinator)
            .iter()
            .all(|summary| summary.status() == ShardStatus::Done)
    );
    assert!(
        backend.batch_call_count() > 0,
        "git repo worker must durably persist repo state before advancing the shard"
    );
    assert!(
        !backend.stored_keys().is_empty(),
        "persistence backend should contain durable state after a complete scan"
    );

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    let expected_key = git_repo_key(repo.path());
    assert_eq!(
        summaries[0]
            .last_key()
            .expect("completed shard should have a last_key"),
        expected_key.as_bytes(),
        "shard cursor last_key should match the singleton repo key"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "one repo-frontier shard produces exactly one done-ledger entry"
    );
    assert_eq!(
        rows[0].status(),
        DoneLedgerStatus::ScannedClean,
        "benign fixture produces no findings; status must be ScannedClean"
    );
    assert_eq!(
        rows[0].findings_count(),
        0,
        "benign fixture produces no findings; findings count must be zero"
    );
}

#[test]
fn run_git_repo_worker_treats_cursor_covered_target_as_exhausted_empty() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let repo_key = git_repo_key(repo.path());
    let mut coordinator = setup_coordinator_with_git_shard(
        repo.path(),
        CoordCursorUpdate::with_last_key(repo_key.as_bytes()),
        30_000,
    );

    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("cursor-covered singleton shard should complete without execution");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);
    assert_eq!(run_progress(&coordinator).done(), 1);
    assert_eq!(
        backend.batch_call_count(),
        0,
        "no Git persistence writes should occur when discovery is already covered by the cursor"
    );
}

/// Git repo-frontier shards require `CursorSemantics::Completed` so the
/// checkpoint cursor represents fully-processed and durable progress.
/// `Dispatched` semantics are rejected before any scan work begins.
#[test]
fn run_git_repo_worker_rejects_dispatched_cursor_semantics() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let dispatched_config =
        RunConfig::try_new(CursorSemantics::Dispatched, 30_000, None).expect("run config");
    let mut coordinator = setup_coordinator_with_git_shard_and_config(
        repo.path(),
        CoordCursorUpdate::initial(),
        dispatched_config,
    );

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("dispatched cursor semantics should be rejected");

    let msg = format!("{err}");
    assert!(
        msg.contains("CursorSemantics::Completed"),
        "error should reference the required semantics: {msg}"
    );
}

/// A shard whose key range excludes the payload repo key is rejected
/// with a `Runtime(Driver)` error rather than silently completing as
/// exhausted-empty.
#[test]
fn run_git_repo_worker_rejects_out_of_bounds_payload_repo_key() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();

    // Build a shard whose range starts PAST the repo key so the payload
    // target falls outside the shard bounds.
    let repo_key = git_repo_key(repo.path());
    let start = successor_bytes(repo_key.as_bytes());
    let end = successor_bytes(&start);
    let payload = git_payload(repo.path());

    let mut coordinator = gossip_coordination::InMemoryCoordinator::new(30_000);
    let now = wall_clock_now();
    coordinator
        .create_run(now, tenant(), run(), test_run_config(30_000))
        .expect("create run");

    let mut scratch = gossip_frontier::ShardSpecScratch::new();
    let spec_ref = gossip_frontier::range_shard_ref(&start, &end, &payload, &mut scratch)
        .expect("git range shard spec");
    let shard_spec = gossip_contracts::coordination::ShardSpec::try_from_ref(spec_ref)
        .expect("owned git shard spec");
    let shards = [gossip_coordination::InitialShardInput::new(
        ShardId::from_raw(1),
        shard_spec.as_ref(),
        CoordCursorUpdate::initial(),
    )];
    let _ = coordinator
        .register_shards(
            now,
            tenant(),
            run(),
            &shards,
            gossip_contracts::identity::OpId::from_raw(1),
        )
        .expect("register shards");

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("out-of-bounds payload repo key must be rejected");

    assert!(
        matches!(
            err,
            DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(_))
        ),
        "expected Runtime(Driver), got: {err}"
    );
    let msg = format!("{err}");
    assert!(
        msg.contains("outside shard bounds"),
        "error should mention shard bounds: {msg}"
    );

    assert_eq!(
        backend.batch_call_count(),
        0,
        "no persistence writes should occur for out-of-bounds shards"
    );
}

/// The repo-key guard at the discovery boundary passes for a correctly
/// configured singleton shard where the discovered target matches the
/// payload's repo key.
#[test]
fn run_git_repo_worker_passes_repo_key_guard_for_matching_target() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("matching repo key should pass the guard");

    assert_eq!(report.shards_scanned, 1);
}

/// When the persistence backend fails on the first write, the worker
/// propagates the error without advancing the shard.
#[test]
fn run_git_repo_worker_fails_cleanly_on_persistence_error() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    backend.fail_after_n_batches(0);
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("persistence failure should propagate");

    assert!(
        matches!(err, DistributedRuntimeError::Runtime(_)),
        "expected Runtime error variant, got: {err:?}"
    );

    // The error chain must preserve the original cause rather than
    // stringifying it. Walking source() from the anyhow context layer
    // should reach the underlying GitRunError (which itself wraps a
    // persistence-originated message).
    let runtime_source = std::error::Error::source(&err)
        .expect("DistributedRuntimeError must expose a source chain");
    let anyhow_ctx = std::error::Error::source(runtime_source)
        .expect("ScanRuntimeError::Driver must expose the anyhow context");
    let original_cause = std::error::Error::source(anyhow_ctx);
    assert!(
        original_cause.is_some(),
        "anyhow context must preserve the original error as source, not stringify it"
    );

    assert_eq!(
        backend.batch_call_count(),
        0,
        "no batch should have succeeded before the injected failure"
    );

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "persistence failures must not advance the shard"
    );
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Parked,
        "transient persistence failures must not park the shard"
    );
    assert_eq!(
        run_progress(&coordinator).done(),
        0,
        "no shards should be done after a persistence failure"
    );
}

/// Git events remain observable when the repo-frontier worker persists
/// findings durably.
#[test]
fn run_git_repo_worker_records_git_events() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let test_recorder = Arc::new(Recorder::default());
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let identity = git_worker_identity_with_recorder(
        repo.path(),
        Arc::clone(&test_recorder) as Arc<dyn CoordinationEventRecorder>,
    );
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let result = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        identity,
        backend,
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    );
    assert!(
        result.is_ok(),
        "fixture with secrets should persist successfully"
    );

    let events = test_recorder.git_events.lock().expect("git events lock");
    assert!(
        !events.is_empty(),
        "git worker should emit at least one git event during the scan"
    );
    drop(events);
    assert!(
        !findings_sink
            .findings_snapshot()
            .expect("findings snapshot")
            .is_empty(),
        "git findings should be persisted durably",
    );
    assert_eq!(
        done_ledger.snapshot().expect("done-ledger snapshot")[0].status(),
        DoneLedgerStatus::ScannedWithFindings,
        "secret-bearing fixture should produce findings-bearing done-ledger status",
    );
}

#[test]
fn run_git_repo_worker_emits_stage_signals_for_successful_scan() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let test_recorder = Arc::new(Recorder::default());
    let identity = git_worker_identity_with_recorder(
        repo.path(),
        Arc::clone(&test_recorder) as Arc<dyn CoordinationEventRecorder>,
    );
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        identity,
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect("git repo worker should succeed");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);
    // Timing fields are populated by the worker loop. Individual stages
    // may complete in sub-millisecond on fast machines (as_millis
    // truncates to zero), so asserting the aggregate is > 0 would be
    // non-deterministic. Instead, verify each report field matches the
    // latency emitted in the corresponding stage signal -- this catches
    // wiring bugs without depending on wall-clock granularity.

    let signals = test_recorder
        .stage_signals
        .lock()
        .expect("stage signals lock");
    assert_eq!(
        signals.len(),
        5,
        "successful path should emit five stage signals"
    );

    // Extract per-signal latencies and verify report fields match.
    let StageSignal::ShardClaimed {
        latency_ms: claim_ms,
    } = signals[0]
    else {
        panic!("expected ShardClaimed, got {:?}", signals[0]);
    };
    assert_eq!(
        report.total_claim_ms, claim_ms,
        "report claim_ms must match signal"
    );

    let StageSignal::MirrorSyncCompleted {
        latency_ms: mirror_ms,
        error_class,
    } = signals[1]
    else {
        panic!("expected MirrorSyncCompleted, got {:?}", signals[1]);
    };
    assert!(error_class.is_none(), "success path should have no error");
    assert_eq!(
        report.total_mirror_sync_ms, mirror_ms,
        "report mirror_sync_ms must match signal"
    );

    let StageSignal::ScanCompleted {
        latency_ms: scan_ms,
        items_scanned: Some(items_scanned),
        bytes_scanned: Some(bytes_scanned),
    } = signals[2]
    else {
        panic!(
            "expected ScanCompleted with Some counters, got {:?}",
            signals[2]
        );
    };
    assert!(
        items_scanned > 0,
        "fixture should contain at least one scannable item"
    );
    assert!(bytes_scanned > 0, "fixture should have nonzero bytes");
    assert_eq!(
        report.total_scan_ms, scan_ms,
        "report scan_ms must match signal"
    );

    let StageSignal::DurableReceiptCompleted {
        latency_ms: receipt_ms,
        receipts,
    } = signals[3]
    else {
        panic!("expected DurableReceiptCompleted, got {:?}", signals[3]);
    };
    assert_eq!(receipts, GIT_REPO_RECEIPT_FAMILIES);
    assert_eq!(
        report.total_durable_receipt_ms, receipt_ms,
        "report durable_receipt_ms must match signal"
    );

    let StageSignal::CheckpointAdvanced {
        latency_ms: checkpoint_ms,
    } = signals[4]
    else {
        panic!("expected CheckpointAdvanced, got {:?}", signals[4]);
    };
    assert_eq!(
        report.total_checkpoint_ms, checkpoint_ms,
        "report checkpoint_ms must match signal"
    );
}

#[test]
fn run_git_repo_worker_emits_lease_uncertainty_signal_on_expired_lease() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let test_recorder = Arc::new(Recorder::default());
    let identity = git_worker_identity_with_recorder(
        repo.path(),
        Arc::clone(&test_recorder) as Arc<dyn CoordinationEventRecorder>,
    );
    // 1 ms lease -- will expire before run_git_repo_lease can complete.
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 1);

    let result = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        identity,
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    );
    assert!(result.is_err(), "expired lease should cause worker failure");

    let signals = test_recorder
        .stage_signals
        .lock()
        .expect("stage signals lock");
    assert!(
        !signals.is_empty(),
        "at least ShardClaimed should be emitted before the error"
    );
    assert!(
        matches!(signals[0], StageSignal::ShardClaimed { .. }),
        "first signal should be ShardClaimed, got {:?}",
        signals[0]
    );
    assert!(
        signals
            .iter()
            .any(|s| matches!(s, StageSignal::LeaseUncertaintyObserved { .. })),
        "expired lease should emit LeaseUncertaintyObserved, got: {signals:?}"
    );
}

#[test]
fn run_git_repo_worker_emits_mirror_error_signal_on_sync_failure() {
    let repo = create_clean_git_repo_fixture();
    let backend = TestGitBackend::default();
    let test_recorder = Arc::new(Recorder::default());
    let identity = git_worker_identity_with_recorder(
        repo.path(),
        Arc::clone(&test_recorder) as Arc<dyn CoordinationEventRecorder>,
    );
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);
    let mut mirrors = FailingMirrorManager;

    let result = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        identity,
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    );
    assert!(
        result.is_err(),
        "failing mirror should cause worker failure"
    );

    let signals = test_recorder
        .stage_signals
        .lock()
        .expect("stage signals lock");
    assert!(
        signals.len() >= 2,
        "expected at least ShardClaimed + MirrorSyncCompleted, got {signals:?}"
    );
    assert!(
        matches!(signals[0], StageSignal::ShardClaimed { .. }),
        "first signal should be ShardClaimed, got {:?}",
        signals[0]
    );
    let StageSignal::MirrorSyncCompleted {
        error_class,
        latency_ms: _,
    } = signals[1]
    else {
        panic!(
            "second signal should be MirrorSyncCompleted, got {:?}",
            signals[1]
        );
    };
    assert_eq!(
        error_class,
        Some(MirrorErrorClass::Permanent),
        "FailingMirrorManager returns permanent error class"
    );
}

/// A successful git repo scan of a clean (zero-findings) fixture must
/// produce exactly one done-ledger row with findings_count=0 and status
/// ScannedClean.
#[test]
fn git_repo_worker_clean_scan_produces_scanned_clean_done_ledger_row() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let done_ledger = InMemoryDoneLedger::new();
    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect("git repo worker should succeed");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "exactly one done-ledger row for a singleton repo shard"
    );
    assert_eq!(
        rows[0].findings_count(),
        0,
        "benign fixture produces no findings; findings_count must be zero"
    );
    assert_eq!(
        rows[0].status(),
        DoneLedgerStatus::ScannedClean,
        "zero findings must produce ScannedClean, not ScannedWithFindings"
    );
}

/// A done-ledger submission failure during git repo persistence must
/// surface as `DistributedRuntimeError::Durability` and must not advance
/// the shard cursor.
#[test]
fn git_repo_worker_propagates_done_ledger_failure() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .fail_next_submissions(1)
        .expect("inject done-ledger submission failure");

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink, done_ledger),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("done-ledger failure should propagate as an error");

    assert!(
        matches!(err, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {err:?}"
    );

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard must not advance when done-ledger submission fails"
    );
}

/// A done-ledger commit failure (handle.wait() returns Err) during git
/// repo persistence must surface as `DistributedRuntimeError::Durability`
/// and must not advance the shard cursor.
#[test]
fn git_repo_worker_propagates_done_ledger_commit_failure() {
    let repo = create_clean_git_repo_fixture();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    done_ledger
        .fail_next_commits(1)
        .expect("inject done-ledger commit failure");

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink, done_ledger),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("done-ledger commit failure should propagate as an error");

    assert!(
        matches!(err, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {err:?}"
    );

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard must not advance when done-ledger commit fails"
    );
}

/// A findings-sink submission failure during git repo persistence must
/// surface as `DistributedRuntimeError::Durability` and must not advance
/// the shard cursor. Because findings are submitted before the done-ledger,
/// the done-ledger must remain empty.
#[test]
fn git_repo_worker_propagates_findings_sink_failure() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    findings_sink
        .fail_next_submissions(1)
        .expect("inject findings-sink submission failure");

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("findings-sink failure should propagate as an error");

    assert!(
        matches!(err, DistributedRuntimeError::Durability(_)),
        "expected Durability variant, got: {err:?}"
    );

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard must not advance when findings-sink submission fails"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger must remain empty when findings fail before submission"
    );
}

/// A Git scan with findings must route those findings through the shared
/// persistence translation path and advance the shard only after both
/// findings and done-ledger writes are durable.
#[test]
fn git_repo_worker_persists_findings_and_completes_shard() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect("git findings should persist successfully");
    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);

    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard should advance once findings and done-ledger are durable"
    );
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1, "repo shard should emit one done-ledger row");
    assert_eq!(
        rows[0].status(),
        DoneLedgerStatus::ScannedWithFindings,
        "finding-bearing repo must not be marked clean",
    );
    assert!(
        rows[0].findings_count() > 0,
        "finding-bearing repo must record a non-zero findings count",
    );
    assert!(
        !findings_sink
            .findings_snapshot()
            .expect("findings snapshot")
            .is_empty(),
        "shared findings sink should receive translated git findings",
    );
    assert!(
        !findings_sink
            .occurrences_snapshot()
            .expect("occurrences snapshot")
            .is_empty(),
        "git findings should produce occurrence rows",
    );
    assert!(
        !findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "git findings should produce observation rows",
    );
}

/// The error returned when mirror sync fails must preserve the original
/// `GitRunError` as a source in the anyhow chain so operators can
/// programmatically distinguish permission denials from network timeouts.
#[test]
fn run_git_repo_worker_preserves_mirror_sync_error_chain() {
    let repo = create_git_repo_fixture_with_secrets();
    let backend = TestGitBackend::default();
    let mut mirrors = FailingMirrorManager;
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("failing mirror manager should propagate an error");

    let anyhow_err = match err {
        DistributedRuntimeError::Runtime(ScanRuntimeError::Driver(e)) => e,
        other => panic!("expected Runtime(Driver(_)), got: {other:?}"),
    };

    assert!(
        anyhow_err.source().is_some(),
        "error chain must preserve the original GitRunError as a source, \
         but source() returned None -- the error was stringified"
    );
    let display = format!("{anyhow_err}");
    assert!(
        display.contains("git mirror sync failed"),
        "top-level context should mention mirror sync failure: {display}"
    );
}

/// Budget validation errors must include a redacted shard identifier so
/// operators can correlate the failure without leaking raw shard data.
#[test]
fn run_git_repo_worker_budget_validation_includes_shard_context() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);
    let config = DistributedRuntimeConfig {
        budgets: ScanBudgets {
            max_items: 0,
            ..ScanBudgets::default()
        },
        ..DistributedRuntimeConfig::default()
    };

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        config,
    )
    .expect_err("zero budget should fail validation");

    let msg = format!("{err}");
    assert!(
        msg.contains("len=") && msg.contains("hash="),
        "budget validation error should include redacted shard context: {msg}"
    );
}

#[test]
fn run_git_repo_worker_fails_fast_when_commit_oid_map_saturates() {
    let repo = create_git_repo_fixture_with_secret_history(
        FindingsCaptureSink::MAX_COMMIT_OID_MAP_ENTRIES + 1,
    );
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("OID-map saturation should fail the repo worker");

    assert!(
        matches!(
            err,
            DistributedRuntimeError::Runtime(ScanRuntimeError::CommitOidMapSaturated { .. })
        ),
        "expected Runtime(CommitOidMapSaturated), got: {err:?}"
    );
    let msg = err.to_string();
    assert!(
        msg.contains("commit OID map saturated"),
        "error should identify OID-map saturation: {msg}"
    );
    assert_eq!(
        run_progress(&coordinator).done(),
        0,
        "saturation must not advance the shard"
    );
    assert_eq!(
        shard_summaries(&coordinator)[0].status(),
        ShardStatus::Parked,
        "saturation must park the shard to prevent a re-claim loop"
    );
    assert!(
        findings_sink
            .findings_snapshot()
            .expect("findings snapshot")
            .is_empty(),
        "translated findings must not persist after saturation"
    );
    assert!(
        findings_sink
            .occurrences_snapshot()
            .expect("occurrences snapshot")
            .is_empty(),
        "occurrence writes must not occur after saturation"
    );
    assert!(
        findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "observation writes must not occur after saturation"
    );
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty(),
        "done-ledger writes must not occur after saturation"
    );
}

#[test]
fn run_git_repo_worker_does_not_reclaim_commit_oid_saturated_shard() {
    let repo = create_git_repo_fixture_with_secret_history(
        FindingsCaptureSink::MAX_COMMIT_OID_MAP_ENTRIES + 1,
    );
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let _err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(findings_sink, done_ledger),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("OID-map saturation should fail the repo worker");

    assert_eq!(
        shard_summaries(&coordinator)[0].status(),
        ShardStatus::Parked,
        "saturation must park the shard before the next claim attempt"
    );

    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .unwrap_or_else(|e| {
        panic!("second worker run should return Ok (shard is parked, no claim possible), got: {e}")
    });

    assert_eq!(report.leases_seen, 0);
    assert_eq!(report.shards_scanned, 0);

    // Shard must still be parked after the second worker run — the worker
    // must not have changed the shard's state as a side-effect.
    assert_eq!(
        shard_summaries(&coordinator)[0].status(),
        ShardStatus::Parked,
        "parked shard must remain parked after a no-op worker run"
    );
}

/// Thin coordinator wrapper that delegates all operations to the inner
/// `InMemoryCoordinator` except `park_shard`, which always returns
/// `ParkError::BackendError`.
struct ParkFailingCoordinator {
    inner: gossip_coordination::InMemoryCoordinator,
}

impl CoordinationBackend for ParkFailingCoordinator {
    fn acquire_and_restore_into<'a>(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        key: gossip_coordination::ShardKey,
        worker: gossip_coordination::WorkerId,
        out: &'a mut gossip_coordination::AcquireScratch,
    ) -> Result<gossip_coordination::AcquireResultView<'a>, gossip_coordination::AcquireError> {
        self.inner
            .acquire_and_restore_into(now, tenant, key, worker, out)
    }

    fn renew(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        lease: &gossip_coordination::Lease,
    ) -> Result<gossip_coordination::RenewResult, gossip_coordination::RenewError> {
        self.inner.renew(now, tenant, lease)
    }

    fn checkpoint(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        lease: &gossip_coordination::Lease,
        new_cursor: &gossip_coordination::CursorUpdate<'_>,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::CheckpointError>
    {
        self.inner.checkpoint(now, tenant, lease, new_cursor, op_id)
    }

    fn complete(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        lease: &gossip_coordination::Lease,
        final_cursor: &gossip_coordination::CursorUpdate<'_>,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::CompleteError>
    {
        self.inner.complete(now, tenant, lease, final_cursor, op_id)
    }

    fn park_shard(
        &mut self,
        _now: gossip_coordination::LogicalTime,
        _tenant: gossip_coordination::TenantId,
        _lease: &gossip_coordination::Lease,
        _reason: gossip_coordination::ParkReason,
        _op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, ParkError> {
        Err(ParkError::BackendError(
            gossip_coordination::InfraError::transient("park_shard", "injected park failure"),
        ))
    }

    fn split_replace(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        lease: &gossip_coordination::Lease,
        plan: gossip_coordination::SplitReplacePlan<'_>,
        op_id: gossip_coordination::OpId,
    ) -> Result<
        gossip_coordination::IdempotentOutcome<gossip_coordination::SplitReplaceResult>,
        gossip_coordination::SplitReplaceError,
    > {
        self.inner.split_replace(now, tenant, lease, plan, op_id)
    }

    fn split_residual(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        lease: &gossip_coordination::Lease,
        plan: gossip_coordination::SplitResidualPlan<'_>,
        op_id: gossip_coordination::OpId,
    ) -> Result<
        gossip_coordination::IdempotentOutcome<gossip_coordination::SplitResidualResult>,
        gossip_coordination::SplitResidualError,
    > {
        self.inner.split_residual(now, tenant, lease, plan, op_id)
    }
}

impl RunManagement for ParkFailingCoordinator {
    fn create_run(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        config: RunConfig,
    ) -> Result<gossip_coordination::RunRecord, gossip_coordination::CreateRunError> {
        self.inner.create_run(now, tenant, run, config)
    }

    fn register_shards(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        shards: &[gossip_coordination::InitialShardInput<'_>],
        op_id: gossip_coordination::OpId,
    ) -> Result<
        gossip_coordination::IdempotentOutcome<Vec<ShardId>>,
        gossip_coordination::RegisterShardsError,
    > {
        self.inner.register_shards(now, tenant, run, shards, op_id)
    }

    fn get_run(
        &self,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
    ) -> Result<gossip_coordination::RunRecord, gossip_coordination::GetRunError> {
        self.inner.get_run(tenant, run)
    }

    fn get_run_progress(
        &self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
    ) -> Result<gossip_coordination::RunProgress, gossip_coordination::GetRunError> {
        self.inner.get_run_progress(now, tenant, run)
    }

    fn list_shards_into(
        &self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        filter: gossip_coordination::ShardFilter,
        out: &mut Vec<gossip_coordination::ShardSummary>,
    ) -> Result<(), gossip_coordination::GetRunError> {
        self.inner.list_shards_into(now, tenant, run, filter, out)
    }

    fn collect_claim_candidates_into(
        &self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        candidates: &mut Vec<ShardId>,
    ) -> Result<Option<gossip_coordination::LogicalTime>, gossip_coordination::GetRunError> {
        self.inner
            .collect_claim_candidates_into(now, tenant, run, candidates)
    }

    fn complete_run(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::RunTransitionError>
    {
        self.inner.complete_run(now, tenant, run, op_id)
    }

    fn fail_run(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::RunTransitionError>
    {
        self.inner.fail_run(now, tenant, run, op_id)
    }

    fn cancel_run(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::RunTransitionError>
    {
        self.inner.cancel_run(now, tenant, run, op_id)
    }

    fn unpark_shard(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        key: gossip_coordination::ShardKey,
        op_id: gossip_coordination::OpId,
    ) -> Result<gossip_coordination::IdempotentOutcome<()>, gossip_coordination::UnparkError> {
        self.inner.unpark_shard(now, tenant, key, op_id)
    }
}

impl ShardClaiming for ParkFailingCoordinator {
    fn claim_next_available<'a>(
        &mut self,
        now: gossip_coordination::LogicalTime,
        tenant: gossip_coordination::TenantId,
        run: gossip_coordination::RunId,
        worker: gossip_coordination::WorkerId,
        out: &'a mut gossip_coordination::AcquireScratch,
    ) -> Result<gossip_coordination::AcquireResultView<'a>, gossip_coordination::ClaimError> {
        self.inner
            .claim_next_available(now, tenant, run, worker, out)
    }
}

/// When OID-map saturation triggers a park attempt but the coordinator
/// rejects the park (e.g., transient backend error), the original
/// saturation error must still propagate to the caller. The shard must
/// NOT be in `Parked` status because the park operation itself failed.
#[test]
fn run_git_repo_worker_preserves_saturation_error_when_park_fails() {
    let repo = create_git_repo_fixture_with_secret_history(
        FindingsCaptureSink::MAX_COMMIT_OID_MAP_ENTRIES + 1,
    );
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();

    let coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);
    let mut wrapper = ParkFailingCoordinator { inner: coordinator };

    let err = run_git_repo_worker(
        &mut wrapper,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink, done_ledger),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("OID-map saturation with failing park should still return an error");

    // The original saturation error must propagate unchanged even though the
    // best-effort park failed.
    assert!(
        matches!(
            err,
            DistributedRuntimeError::Runtime(ScanRuntimeError::CommitOidMapSaturated { .. })
        ),
        "expected Runtime(CommitOidMapSaturated), got: {err:?}"
    );

    // The shard must NOT be parked because `park_shard` was rejected by the
    // coordinator wrapper. It remains Active (the lease is still live).
    let coordinator = &wrapper.inner;
    let summaries = shard_summaries(coordinator);
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0].status(),
        ShardStatus::Active,
        "failed park must leave the leased shard active"
    );
}

/// Mirror sync failure must be fail-fast: the shard must not be advanced
/// in the coordinator and no persistence writes should occur.
#[test]
fn run_git_repo_worker_mirror_failure_does_not_advance_shard_or_persist() {
    let repo = create_git_repo_fixture_with_secrets();
    let backend = TestGitBackend::default();
    let mut mirrors = FailingMirrorManager;
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let _err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("failing mirror manager should propagate an error");

    // Shard must not have been advanced: it should still be in Assigned
    // (claimed but not completed) rather than Done.
    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard should not be advanced after mirror sync failure"
    );
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Parked,
        "mirror sync failures must not park the shard"
    );

    // No persistence writes should have occurred.
    assert!(
        backend.stored_keys().is_empty(),
        "no persistence writes should occur when mirror sync fails"
    );
}

/// The repo-frontier worker validates that the atomic finding counter
/// matches the captured finding payload count before persisting. This
/// guards against data integrity issues where the counter and payload
/// diverge (e.g., from a concurrent mutation bug in the capture sink).
///
/// This test exercises the positive path: a secret-bearing repo produces
/// findings, and the done-ledger `findings_count` must equal the number
/// of durably persisted finding rows. If the counter-vs-payload guard
/// rejected the scan, the worker would return an error instead of
/// completing successfully.
#[test]
fn run_git_repo_worker_finding_counter_matches_persisted_payload_count() {
    let repo = create_git_repo_fixture_with_secrets();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let report = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend,
        DistributedPersistence::new(findings_sink.clone(), done_ledger.clone()),
        DistributedRuntimeConfig::default(),
    )
    .expect("finding counter must match payload count for the worker to succeed");

    assert_eq!(report.leases_seen, 1);
    assert_eq!(report.shards_scanned, 1);

    let persisted = findings_sink
        .findings_snapshot()
        .expect("findings snapshot");
    assert!(
        !persisted.is_empty(),
        "secret-bearing fixture must produce at least one finding"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        1,
        "singleton repo shard produces one done-ledger row"
    );
    assert_eq!(
        rows[0].findings_count(),
        persisted.len() as u32,
        "done-ledger findings_count must equal the number of durably persisted findings"
    );
    assert_eq!(
        rows[0].status(),
        DoneLedgerStatus::ScannedWithFindings,
        "non-zero findings must produce ScannedWithFindings status"
    );
}

/// A `FinalizeOutcome::Partial` from the scanner (caused by skipped
/// candidates) must be rejected by the repo-frontier worker because
/// outer progress requires a fully durable repo receipt.
#[test]
fn run_git_repo_worker_rejects_partial_finalize() {
    let repo = create_git_repo_fixture_with_corrupt_blob();
    let mirror_root = tempdir().expect("mirror root");
    let mut mirrors = LocalMirrorManager::new(mirror_root.path()).expect("mirror manager");
    let backend = TestGitBackend::default();
    let mut coordinator =
        setup_coordinator_with_git_shard(repo.path(), CoordCursorUpdate::initial(), 30_000);

    let err = run_git_repo_worker(
        &mut coordinator,
        &mut mirrors,
        git_worker_identity(repo.path()),
        backend.clone(),
        DistributedPersistence::new(InMemoryFindingsSink::new(), InMemoryDoneLedger::new()),
        DistributedRuntimeConfig::default(),
    )
    .expect_err("corrupt blob should produce a partial finalize rejection");

    let msg = format!("{err}");
    assert!(
        msg.contains("finalized partially"),
        "error must mention partial finalize: {msg}"
    );

    // Shard must not be advanced when finalize is partial.
    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries.len(), 1);
    assert_ne!(
        summaries[0].status(),
        ShardStatus::Done,
        "shard must not be marked Done after a partial finalize"
    );
}

// ============================================================================
// Filesystem lease persistence and completion tests
// ============================================================================

#[test]
fn run_filesystem_lease_persists_checkpoint_cursor_for_secret_shard() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("secret.txt"), secret_fixture()).expect("write fixture");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());
    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("filesystem lease should succeed");

    assert!(
        report.items_scanned >= 1,
        "scan report should record the scanned file"
    );
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("non-empty shard should produce a progress-bearing completion");
    };
    assert!(
        checkpoint.last_key().is_some(),
        "receipt-driven checkpoint should carry a progress key"
    );
    assert!(
        checkpoint.token().is_none(),
        "receipt-driven checkpoint should be tokenless"
    );

    let observations = findings_sink
        .observations_snapshot()
        .expect("observations snapshot");
    assert!(
        !observations.is_empty(),
        "durable findings observations should be present"
    );

    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].status(), DoneLedgerStatus::ScannedWithFindings);
    assert_eq!(rows[0].write_context(), lease.write_context());

    advance_shard(
        &mut coordinator,
        identity.tenant,
        &lease,
        &ShardCompletionOutcome::Complete {
            checkpoint: checkpoint.clone(),
        },
    )
    .expect("complete shard");
    let summaries = shard_summaries(&coordinator);
    assert_eq!(summaries[0].status(), ShardStatus::Done);
    assert_eq!(
        summaries[0].last_key(),
        checkpoint.last_key().map(|key| key.as_bytes())
    );
}

#[test]
fn run_filesystem_lease_zero_item_shard_returns_exhausted_empty_completion() {
    let dir = tempdir().expect("tempdir");
    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(InMemoryFindingsSink::new(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig::default(),
    )
    .expect("empty filesystem shard should succeed");

    assert_eq!(report.items_scanned, 0);
    assert_eq!(completion, ShardCompletionOutcome::ExhaustedEmpty);
    assert!(
        done_ledger
            .snapshot()
            .expect("done-ledger snapshot")
            .is_empty()
    );
}

#[test]
fn run_filesystem_lease_processes_all_pages_under_ordered_item_budget() {
    let dir = tempdir().expect("tempdir");
    fs::write(dir.path().join("a-secret.txt"), secret_fixture()).expect("write fixture a");
    fs::write(dir.path().join("b-secret.txt"), secret_fixture()).expect("write fixture b");

    let mut coordinator = setup_coordinator_with_ranges(&[(dir.path(), b"\x00", b"\xFF")], 30_000);
    let identity = worker_identity(Path::new("/fallback"));
    let lease = claim_lease(&mut coordinator, &identity);
    let findings_sink = InMemoryFindingsSink::new();
    let done_ledger = InMemoryDoneLedger::new();
    let persistence = DistributedPersistence::new(findings_sink.clone(), done_ledger.clone());

    let (report, completion) = run_filesystem_lease(
        Arc::clone(&identity.recorder),
        &persistence,
        &lease,
        DistributedRuntimeConfig {
            budgets: ScanBudgets {
                max_items: 1,
                max_bytes: 1_000_000,
            },
            ..DistributedRuntimeConfig::default()
        },
    )
    .expect("budgeted filesystem lease should succeed");

    assert_eq!(
        report.items_scanned, 2,
        "ordered-content lease should keep paging until the shard is exhausted"
    );
    let ShardCompletionOutcome::Complete { checkpoint } = completion else {
        panic!("final committed item should produce a progress-bearing completion");
    };
    assert_eq!(
        checkpoint
            .last_key()
            .expect("checkpoint last_key")
            .as_bytes(),
        b"b-secret.txt"
    );
    let rows = done_ledger.snapshot().expect("done-ledger snapshot");
    assert_eq!(
        rows.len(),
        2,
        "both ordered items should commit across pages"
    );
    assert!(
        rows.iter()
            .all(|row| row.status() == DoneLedgerStatus::ScannedWithFindings),
        "each secret fixture should produce a findings-bearing done-ledger row"
    );
    assert!(
        !findings_sink
            .observations_snapshot()
            .expect("observations snapshot")
            .is_empty(),
        "the committed ordered items should still emit durable findings"
    );
}
