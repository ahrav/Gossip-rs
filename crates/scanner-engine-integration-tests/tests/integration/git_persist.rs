//! Integration tests for persistence ordering and atomicity.
//!
//! These tests exercise the finalize persistence contract:
//! - Data ops are always written.
//! - Watermark ops are only written on complete runs.
//! - Errors surface without recording partial writes.

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
    TestResolver, base_config, commit_file, ensure_artifacts, git_available, git_output, init_repo,
    oid_from_hex, test_engine,
};

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

#[cfg(feature = "rocksdb")]
#[derive(Debug)]
struct CountingPersistStore {
    inner: RocksDbStore,
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

    let tmp = init_repo();
    let repo = tmp.path();
    let mut blob_hexes = Vec::new();
    for i in 0..5 {
        let name = format!("secret-{i}.txt");
        let contents = format!("TOK_{i:08X}\n");
        let msg = format!("c{i}");
        commit_file(repo, &name, &contents, &msg);
        blob_hexes.push(git_output(repo, &["rev-parse", &format!("HEAD:{name}")]));
    }
    ensure_artifacts(repo);
    blob_hexes.sort_unstable();
    let blob_oids: Vec<OidBytes> = blob_hexes.iter().map(|hex| oid_from_hex(hex)).collect();

    let tip = oid_from_hex(&git_output(repo, &["rev-parse", "HEAD"]));
    let resolver = TestResolver { tip };
    let mut config = base_config();
    config.scan_mode = scanner_git::GitScanMode::DiffHistory;
    config.spill.seen_batch_max_oids = 2;
    let db_dir = tempfile::tempdir().expect("temp RocksDB dir");
    let store =
        CountingPersistStore::open(db_dir.path(), config.repo_id, config.policy_hash).unwrap();
    let abort = AtomicBool::new(false);

    assert_eq!(
        scanner_git::SeenBlobStore::batch_check_seen(&store, &blob_oids).unwrap(),
        vec![false; blob_oids.len()],
        "fresh RocksDB state should start with no seen blobs"
    );

    let first = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
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
        first
            .0
            .finalize
            .data_ops
            .iter()
            .any(|op| op.key.starts_with(&scanner_git::NS_SEEN_BLOB)),
        "first scan should emit seen-bitmap finalize ops"
    );

    let first_calls = store.incremental_calls();
    assert!(
        first_calls > 0,
        "expected spill-stage persist_seen_delta calls during the first scan"
    );
    assert_eq!(
        scanner_git::SeenBlobStore::batch_check_seen(&store, &blob_oids).unwrap(),
        vec![true; blob_oids.len()],
        "finalize should commit the staged bitmap into the live seen scope"
    );

    let second = run_git_scan(
        repo,
        std::sync::Arc::new(test_engine()),
        &resolver,
        &store,
        &store,
        Some(&store),
        &config,
        &abort,
        std::sync::Arc::new(NullEventSink),
    )
    .expect("second scan should succeed");

    assert_eq!(second.0.finalize.outcome, FinalizeOutcome::Complete);
    assert_eq!(
        second.0.finalize.data_ops.len(),
        0,
        "persisted seen state should suppress all data writes on the second scan"
    );
    assert_eq!(
        store.incremental_calls(),
        first_calls,
        "a fully seen rerun should not stage additional seen deltas"
    );
}
