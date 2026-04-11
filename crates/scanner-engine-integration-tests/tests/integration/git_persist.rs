//! Integration tests for persistence ordering, atomicity, and state round-trips.
//!
//! These tests exercise the finalize persistence contract:
//! - Data ops are always written.
//! - Watermark ops are only written on complete runs.
//! - Errors surface without recording partial writes.
//! - RocksDB-backed seen-bitmap state persists across scan invocations
//!   and suppresses re-scanning of already-seen blobs (requires the
//!   `rocksdb` feature).

use std::cell::Cell;
#[cfg(feature = "rocksdb")]
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

#[cfg(feature = "rocksdb")]
use scanner_git::persist_rocksdb::RocksDbStore;
use scanner_git::{
    FinalizeOutcome, FinalizeOutput, FinalizeStats, OidBytes, PersistError, PersistenceStore,
    SeenBitmapPersister, SpillError, WriteOp, persist_finalize_output,
};
#[cfg(feature = "rocksdb")]
use scanner_git::{NullEventSink, run_git_scan};

#[cfg(feature = "rocksdb")]
use super::git_scan_validation::{
    TestResolver, TestWatermarkStore, base_config, commit_file, create_repo, ensure_artifacts,
    perf_stats_enabled, test_engine,
};
#[cfg(feature = "rocksdb")]
use crate::git_test_support::{git_available, git_stdout, oid_from_hex};

/// Test double that records persisted ops and can simulate commit failures.
#[derive(Default)]
struct RecordingStore {
    /// Recorded data writes from successful commits.
    data_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Recorded watermark writes from successful complete commits.
    watermark_ops: std::cell::RefCell<Vec<WriteOp>>,
    /// Tracks how many commit attempts were made.
    commit_calls: Cell<u32>,
    /// Forces `commit_finalize` to fail before recording any ops.
    fail_commit: Cell<bool>,
}

impl PersistenceStore for RecordingStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        // Count calls even when the commit is configured to fail.
        self.commit_calls
            .set(self.commit_calls.get().saturating_add(1));
        if self.fail_commit.get() {
            // Simulate a backend failure before any writes are recorded.
            return Err(PersistError::backend("commit failed"));
        }
        self.data_ops
            .borrow_mut()
            .extend_from_slice(&output.data_ops);
        if matches!(output.outcome, FinalizeOutcome::Complete) {
            self.watermark_ops
                .borrow_mut()
                .extend_from_slice(&output.watermark_ops);
        }
        Ok(())
    }
}

impl SeenBitmapPersister for RecordingStore {
    fn persist_seen_delta(&self, _oids: &[OidBytes]) -> Result<(), SpillError> {
        Ok(())
    }
}

/// RocksDB-backed test double that delegates all persistence to a real
/// `RocksDbStore` while counting non-empty `persist_seen_delta` calls.
#[cfg(feature = "rocksdb")]
#[derive(Debug)]
struct CountingPersistStore {
    inner: RocksDbStore,
    /// Spill-stage call counter. `Relaxed` ordering suffices: writes happen
    /// in the single-threaded spill pipeline, reads happen after
    /// `run_git_scan` returns (implicit synchronization via thread join).
    incremental_calls: AtomicUsize,
}

#[cfg(feature = "rocksdb")]
impl CountingPersistStore {
    fn open(
        path: impl AsRef<std::path::Path>,
        repo_id: u64,
        policy_hash: [u8; 32],
    ) -> Result<Self, PersistError> {
        Ok(Self {
            inner: RocksDbStore::open(path, repo_id, policy_hash)?,
            incremental_calls: AtomicUsize::new(0),
        })
    }

    fn incremental_calls(&self) -> usize {
        self.incremental_calls.load(Ordering::Relaxed)
    }
}

#[cfg(feature = "rocksdb")]
impl SeenBitmapPersister for CountingPersistStore {
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        if !oids.is_empty() {
            self.incremental_calls.fetch_add(1, Ordering::Relaxed);
        }
        self.inner.persist_seen_delta(oids)
    }
}

#[cfg(feature = "rocksdb")]
impl PersistenceStore for CountingPersistStore {
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        self.inner.commit_finalize(output)
    }
}

#[cfg(feature = "rocksdb")]
impl scanner_git::SeenBlobStore for CountingPersistStore {
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        self.inner.batch_check_seen(oids)
    }

    fn configure_midx_snapshot(
        &self,
        midx_bytes: scanner_git::BytesView,
        object_format: scanner_git::ObjectFormat,
        artifact_fingerprint: scanner_git::RepoArtifactFingerprint,
    ) -> Result<(), SpillError> {
        self.inner
            .configure_midx_snapshot(midx_bytes, object_format, artifact_fingerprint)
    }
}

#[cfg(feature = "rocksdb")]
impl scanner_git::RefWatermarkStore for CountingPersistStore {
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: [u8; 32],
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<scanner_git::RefWatermark>>, scanner_git::RepoOpenError> {
        self.inner
            .load_watermarks(repo_id, policy_hash, start_set_id, ref_names)
    }
}

#[test]
fn complete_run_commits_data_and_watermarks() {
    let store = RecordingStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: FinalizeStats::default(),
    };

    let res = persist_finalize_output(&store, &output).unwrap();
    assert_eq!(res, FinalizeOutcome::Complete);
    assert_eq!(store.commit_calls.get(), 1);
    assert_eq!(store.data_ops.borrow().len(), 1);
    assert_eq!(store.watermark_ops.borrow().len(), 1);
}

#[test]
fn partial_runs_commit_data_only() {
    let store = RecordingStore::default();
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Partial { skipped_count: 2 },
        stats: FinalizeStats::default(),
    };

    let res = persist_finalize_output(&store, &output).unwrap();
    assert_eq!(res, FinalizeOutcome::Partial { skipped_count: 2 });
    assert_eq!(store.commit_calls.get(), 1);
    assert_eq!(store.data_ops.borrow().len(), 1);
    assert!(store.watermark_ops.borrow().is_empty());
}

#[test]
fn failed_commit_writes_nothing() {
    let store = RecordingStore::default();
    store.fail_commit.set(true);
    let output = FinalizeOutput {
        data_ops: vec![WriteOp {
            key: vec![1],
            value: vec![1],
        }],
        watermark_ops: vec![WriteOp {
            key: vec![2],
            value: vec![2],
        }],
        outcome: FinalizeOutcome::Complete,
        stats: FinalizeStats::default(),
    };

    let err = persist_finalize_output(&store, &output).unwrap_err();
    let msg = format!("{err}");
    assert!(msg.contains("commit failed"));
    assert_eq!(store.commit_calls.get(), 1);
    assert!(store.data_ops.borrow().is_empty());
    assert!(store.watermark_ops.borrow().is_empty());
}

#[cfg(feature = "rocksdb")]
#[test]
fn run_git_scan_with_rocksdb_writes_incremental_seen_bitmap() {
    if !git_available() {
        eprintln!("git not available; skipping RocksDB git persistence test");
        return;
    }

    let tmp = create_repo();
    let repo = tmp.path();
    let mut blob_hexes = Vec::new();
    for i in 0..5 {
        let name = format!("secret-{i}.txt");
        let contents = format!("TOK_{i:08X}\n");
        let msg = format!("c{i}");
        commit_file(repo, &name, &contents, &msg);
        blob_hexes.push(git_stdout(repo, &["rev-parse", &format!("HEAD:{name}")]));
    }
    ensure_artifacts(repo);
    blob_hexes.sort_unstable();
    let blob_oids: Vec<OidBytes> = blob_hexes.iter().map(|hex| oid_from_hex(hex)).collect();

    let tip = oid_from_hex(&git_stdout(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let mut config = base_config();
    // DiffHistory mode walks commits through the spill pipeline.
    // With `seen_batch_max_oids = 2`, non-empty seen deltas are persisted
    // incrementally as batches flush.
    config.scan_mode = scanner_git::GitScanMode::DiffHistory;
    config.spill.seen_batch_max_oids = 2;
    let db_dir = tempfile::tempdir().expect("temp RocksDB dir");
    let store = CountingPersistStore::open(db_dir.path(), config.repo_id, config.policy_hash)
        .expect("open RocksDB counting store");
    let abort = AtomicBool::new(false);
    let engine = std::sync::Arc::new(test_engine());

    assert_eq!(
        scanner_git::SeenBlobStore::batch_check_seen(&store, &blob_oids).unwrap(),
        vec![false; blob_oids.len()],
        "fresh RocksDB state should start with no seen blobs"
    );

    let first = run_git_scan(
        repo,
        engine.clone(),
        &resolver,
        &store,
        &store,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect("first scan should succeed");

    assert_eq!(first.0.finalize.outcome, FinalizeOutcome::Complete);
    assert!(
        !first.0.finalize.watermark_ops.is_empty(),
        "complete scan should emit watermark ops"
    );
    // When `perf-stats` is disabled, FinalizeStats fields are zeroed regardless of
    // actual processing. The unconditional assertions below (NS_SEEN_BLOB op
    // presence, incremental_calls count, batch_check_seen results) provide the
    // primary dedup evidence in that configuration.
    if perf_stats_enabled() {
        assert_eq!(
            first.0.finalize.stats.unique_blobs,
            blob_oids.len() as u64,
            "first scan should process all 5 committed blobs"
        );
        assert!(
            first.0.finalize.stats.total_findings >= 5,
            "each blob contains a detectable TOK_ secret"
        );
    }
    assert!(
        first
            .0
            .finalize
            .data_ops
            .iter()
            .any(|op| op.key.starts_with(&scanner_git::NS_SEEN_BLOB)),
        "first scan should emit seen-bitmap finalize ops"
    );

    let first_calls = store.incremental_calls();
    assert_eq!(
        first_calls, 3,
        "5 blobs with seen_batch_max_oids=2 flush as 2+2+1, producing exactly 3 persist calls"
    );
    assert_eq!(
        scanner_git::SeenBlobStore::batch_check_seen(&store, &blob_oids).unwrap(),
        vec![true; blob_oids.len()],
        "finalize should commit the staged bitmap into the live seen scope"
    );

    // Null watermarks force a full commit re-walk so the seen-bitmap is
    // the sole dedup mechanism for the second scan.
    let no_watermarks = TestWatermarkStore { watermark: None };
    let second = run_git_scan(
        repo,
        engine.clone(),
        &resolver,
        &store,
        &no_watermarks,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect("second scan should succeed");

    assert_eq!(second.0.finalize.outcome, FinalizeOutcome::Complete);
    // Without `perf-stats`, the absence of NS_SEEN_BLOB data ops and the stable
    // incremental_calls count are the unconditional dedup signals.
    if perf_stats_enabled() {
        assert_eq!(
            second.0.finalize.stats.unique_blobs, 0,
            "all blobs should be skipped as already seen"
        );
    }
    assert!(
        !second
            .0
            .finalize
            .data_ops
            .iter()
            .any(|op| op.key.starts_with(&scanner_git::NS_SEEN_BLOB)),
        "second scan should not emit seen-bitmap ops"
    );
    assert_eq!(
        store.incremental_calls(),
        first_calls,
        "a fully seen rerun should not stage additional seen deltas"
    );
}
