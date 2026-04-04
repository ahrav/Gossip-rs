//! Integration tests for seen-bitmap crash recovery and multi-phase commit durability.
//!
//! These tests exercise the non-atomic `commit_finalize` path in
//! [`GitPersistenceAdapter`], verifying that the three-phase write sequence
//! (data + seen-scope Put, staging Delete, watermark write) maintains crash-safety
//! invariants when individual phases fail.

use gossip_scanner_runtime::git_persistence::test_support::TestBackend;
use gossip_scanner_runtime::git_persistence::{GitPersistenceAdapter, GitPersistenceBackend};
use scanner_git::{
    ChangeKind, CollectingUniqueBlobSink, FinalizeOutcome, FinalizeOutput, OidBytes,
    PersistenceStore, SeenBlobStore, SpillLimits, Spiller, WriteOp,
};
use tempfile::TempDir;

#[test]
fn spiller_recovery_skips_scope_committed_before_watermarks() {
    let mut limits = SpillLimits::RESTRICTIVE;
    limits.max_chunk_candidates = 32;
    limits.max_chunk_path_bytes = 1024;
    limits.max_path_len = 16;
    limits.seen_batch_max_oids = 2;
    limits.seen_batch_max_path_bytes = 64;

    let repo_id = 42;
    let policy_hash = [0xAB; 32];
    let start_set_id: [u8; 32] = [0xCC; 32];
    let seen_scope_key = scanner_git::finalize::build_seen_scope_key(repo_id, &policy_hash);
    let seen_staging_key = scanner_git::finalize::build_seen_staging_key(repo_id, &policy_hash);
    let watermark_key = scanner_git::finalize::build_ref_wm_key(
        repo_id,
        &policy_hash,
        &start_set_id,
        b"refs/heads/main",
    );

    // OID values are in ascending byte order: batch_check_seen requires
    // sorted input and the spiller emits in OID-sorted order.
    let oid_a = OidBytes::sha1([0x11; 20]);
    let oid_b = OidBytes::sha1([0x22; 20]);
    let oid_c = OidBytes::sha1([0x33; 20]);
    let oid_d = OidBytes::sha1([0x44; 20]);
    let oid_e = OidBytes::sha1([0x55; 20]);
    let oid_f = OidBytes::sha1([0x66; 20]);
    let oids = [oid_a, oid_b, oid_c, oid_d, oid_e, oid_f];

    let backend = TestBackend::non_atomic();
    assert!(
        !backend.supports_atomic_batches(),
        "this test exercises the non-atomic commit path; \
         TestBackend must not report atomic batch support"
    );
    let adapter = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);

    // -- Spill 6 OIDs through the adapter ------------------------------------
    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();
    for oid in oids {
        spiller
            .push(oid, b"a", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();
    }

    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&adapter, &adapter, &mut sink).unwrap();

    // -- Staging isolation: OIDs invisible until finalize commits scope ------
    let emitted_oids: Vec<OidBytes> = sink.blobs.iter().map(|blob| blob.oid).collect();
    assert_eq!(emitted_oids, oids);
    assert_eq!(
        adapter.batch_check_seen(&oids).unwrap(),
        vec![false, false, false, false, false, false],
        "spill-stage writes remain invisible until finalize commits the seen scope"
    );
    assert!(!backend.contains_key(&seen_scope_key));
    assert!(
        backend.contains_key(&seen_staging_key),
        "incremental spill writes must land in the staging key before finalize"
    );

    // -- Inject watermark failure during commit_finalize ----------------------
    //
    // The non-atomic commit_finalize path issues 3 sequential apply_batch
    // calls: (1) data+seen scope Put, (2) staging Delete, (3) watermark
    // writes. We inject a failure on the 3rd call to simulate a crash
    // between seen-scope commit and watermark advancement.
    let batch_calls_before_finalize = backend.batch_call_count();
    backend.set_fail_on_batch_call(batch_calls_before_finalize + 3);
    let err = adapter
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![1],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .unwrap_err();
    assert!(format!("{err}").contains("injected batch failure"));

    // Confirm the failure hit the expected batch call (watermark phase).
    assert_eq!(
        backend.batch_call_count(),
        batch_calls_before_finalize + 3,
        "commit_finalize non-atomic path should issue exactly 3 apply_batch calls; \
         if this fails, the internal batch sequence changed and the failure \
         injection offset must be updated"
    );

    // -- Crash-recovery state: scope durable, watermarks absent ---------------
    assert_eq!(
        adapter.batch_check_seen(&oids).unwrap(),
        vec![true, true, true, true, true, true],
        "the committed seen scope must survive a later watermark-phase failure"
    );
    assert!(
        backend.contains_key(&seen_scope_key),
        "complete finalize must commit the merged seen scope before watermarks"
    );
    assert!(
        !backend.contains_key(&seen_staging_key),
        "successful scope commit must clear the staging key before watermark writes"
    );
    assert!(
        !backend.contains_key(&watermark_key),
        "outer progress must remain absent when the watermark phase fails"
    );

    // -- Recovered adapter skips committed OIDs --------------------------------
    backend.clear_fail_on_batch_call();
    let recovered = GitPersistenceAdapter::new(backend, repo_id, policy_hash);
    assert_eq!(
        recovered.batch_check_seen(&oids).unwrap(),
        vec![true, true, true, true, true, true],
        "a recovered adapter must reload the advanced seen scope from durable state"
    );

    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();
    for oid in oids {
        spiller
            .push(oid, b"b", 2, 0, ChangeKind::Add, 0, 0)
            .unwrap();
    }

    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&recovered, &recovered, &mut sink).unwrap();
    assert!(
        sink.blobs.is_empty(),
        "replayed scans must skip OIDs whose seen scope committed before the crash"
    );

    // -- Recovered finalize cycle completes ------------------------------------
    //
    // The recovered scan completes and then finalizes. The second finalize
    // encounters the (now-absent) staging key and handles it gracefully.
    recovered
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![2],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .expect("recovered adapter must complete finalize successfully");
    assert!(
        recovered.backend().contains_key(&watermark_key),
        "recovered finalize must advance watermarks that failed in the first attempt"
    );
}

/// Verifies crash-recovery when the scope-write batch (first `apply_batch`
/// in the non-atomic commit path) fails. Neither the scope key nor
/// watermarks are committed; only the staging key from the spill phase
/// survives. On recovery, `commit_finalize` reads the stale staging key,
/// folds those OIDs into a fresh (empty) scope bitmap, and completes all
/// three phases in one pass.
///
/// This exercises the cold `load_seen_store` path where the scope key is
/// absent and the bitmap must be initialized from scratch before the
/// staging merge.
#[test]
fn scope_write_crash_leaves_staging_only_and_recovery_folds_from_empty() {
    let mut limits = SpillLimits::RESTRICTIVE;
    limits.max_chunk_candidates = 32;
    limits.max_chunk_path_bytes = 1024;
    limits.max_path_len = 16;
    limits.seen_batch_max_oids = 2;
    limits.seen_batch_max_path_bytes = 64;

    let repo_id = 44;
    let policy_hash = [0xEF; 32];
    let start_set_id: [u8; 32] = [0xFF; 32];
    let seen_scope_key = scanner_git::finalize::build_seen_scope_key(repo_id, &policy_hash);
    let seen_staging_key = scanner_git::finalize::build_seen_staging_key(repo_id, &policy_hash);
    let watermark_key = scanner_git::finalize::build_ref_wm_key(
        repo_id,
        &policy_hash,
        &start_set_id,
        b"refs/heads/main",
    );

    let oids: [OidBytes; 6] = [
        OidBytes::sha1([0x11; 20]),
        OidBytes::sha1([0x22; 20]),
        OidBytes::sha1([0x33; 20]),
        OidBytes::sha1([0x44; 20]),
        OidBytes::sha1([0x55; 20]),
        OidBytes::sha1([0x66; 20]),
    ];

    let backend = TestBackend::non_atomic();
    assert!(
        !backend.supports_atomic_batches(),
        "this test exercises the non-atomic commit path"
    );
    let adapter = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);

    // -- Spill 6 OIDs through the adapter ------------------------------------
    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();
    for oid in oids {
        spiller
            .push(oid, b"a", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();
    }
    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&adapter, &adapter, &mut sink).unwrap();

    // -- Inject scope-write failure -------------------------------------------
    //
    // The non-atomic commit_finalize path issues 3 sequential apply_batch
    // calls: (1) data+seen scope Put, (2) staging Delete, (3) watermark
    // writes. Failing on the 1st call leaves all durable state unchanged:
    // scope key absent, staging key still present from spill writes.
    let batch_calls_before = backend.batch_call_count();
    assert_eq!(
        batch_calls_before, 3,
        "spiller should issue exactly 3 staging writes for 6 OIDs with batch size 2"
    );
    backend.set_fail_on_batch_call(batch_calls_before + 1);

    let err = adapter
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![1],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .unwrap_err();
    assert!(format!("{err}").contains("injected batch failure"));

    // Confirm the failure hit the expected batch call (scope-write phase).
    assert_eq!(
        backend.batch_call_count(),
        batch_calls_before + 1,
        "commit_finalize non-atomic path should fail on the scope-write batch; \
         if this fails, the internal batch sequence changed and the failure \
         injection offset must be updated"
    );

    // -- Post-crash state: nothing committed, staging survives ----------------
    //
    // Scope key: ABSENT (batch failed before write).
    // Staging key: STILL PRESENT (from spill writes, untouched).
    // Watermark key: ABSENT (never reached).
    assert!(
        !backend.contains_key(&seen_scope_key),
        "scope key must be absent when the scope-write batch fails"
    );
    assert!(
        backend.contains_key(&seen_staging_key),
        "staging key from spill writes must survive a scope-write failure"
    );
    assert!(
        !backend.contains_key(&watermark_key),
        "watermarks must remain absent when an earlier phase fails"
    );

    // -- Recovered adapter folds staging into fresh scope ---------------------
    backend.clear_fail_on_batch_call();
    let recovered = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);

    recovered
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![2],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .expect("recovered finalize must fold staging into a fresh scope bitmap");

    assert_eq!(
        recovered.batch_check_seen(&oids).unwrap(),
        vec![true, true, true, true, true, true],
        "all spilled OIDs must be seen after recovery folds staging into a new scope"
    );
    assert!(
        backend.contains_key(&seen_scope_key),
        "recovered finalize must write the scope key"
    );
    assert!(
        !backend.contains_key(&seen_staging_key),
        "recovered finalize must clean up the stale staging key"
    );
    assert!(
        backend.contains_key(&watermark_key),
        "recovered finalize must advance watermarks"
    );
}

/// Verifies crash-recovery when the staging-key delete (second `apply_batch`
/// in the non-atomic commit path) fails. The scope key is already committed
/// but the staging key remains. On recovery, `commit_finalize` re-reads the
/// stale staging, re-folds those OIDs (idempotent set union), deletes the
/// staging key, and advances watermarks.
#[test]
fn staging_delete_crash_leaves_scope_durable_and_recovery_refolds_idempotently() {
    let mut limits = SpillLimits::RESTRICTIVE;
    limits.max_chunk_candidates = 32;
    limits.max_chunk_path_bytes = 1024;
    limits.max_path_len = 16;
    limits.seen_batch_max_oids = 2;
    limits.seen_batch_max_path_bytes = 64;

    let repo_id = 43;
    let policy_hash = [0xCD; 32];
    let start_set_id: [u8; 32] = [0xDD; 32];
    let seen_scope_key = scanner_git::finalize::build_seen_scope_key(repo_id, &policy_hash);
    let seen_staging_key = scanner_git::finalize::build_seen_staging_key(repo_id, &policy_hash);
    let watermark_key = scanner_git::finalize::build_ref_wm_key(
        repo_id,
        &policy_hash,
        &start_set_id,
        b"refs/heads/main",
    );

    let oids: [OidBytes; 6] = [
        OidBytes::sha1([0x11; 20]),
        OidBytes::sha1([0x22; 20]),
        OidBytes::sha1([0x33; 20]),
        OidBytes::sha1([0x44; 20]),
        OidBytes::sha1([0x55; 20]),
        OidBytes::sha1([0x66; 20]),
    ];

    let backend = TestBackend::non_atomic();
    assert!(
        !backend.supports_atomic_batches(),
        "this test exercises the non-atomic commit path"
    );
    let adapter = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);

    // -- Spill 6 OIDs through the adapter ------------------------------------
    let tmp = TempDir::new().unwrap();
    let mut spiller = Spiller::new(limits, 20, tmp.path()).unwrap();
    for oid in oids {
        spiller
            .push(oid, b"a", 1, 0, ChangeKind::Add, 0, 0)
            .unwrap();
    }
    let mut sink = CollectingUniqueBlobSink::default();
    spiller.finalize(&adapter, &adapter, &mut sink).unwrap();

    // -- Inject staging-delete failure -----------------------------------------
    //
    // The non-atomic commit_finalize path issues 3 sequential apply_batch
    // calls: (1) data+seen scope Put, (2) staging Delete, (3) watermark
    // writes. We inject a failure on the 2nd call to simulate a crash
    // after scope commit but before the staging key is cleaned up.
    let batch_calls_before = backend.batch_call_count();
    assert_eq!(
        batch_calls_before, 3,
        "spiller should issue exactly 3 staging writes for 6 OIDs with batch size 2"
    );
    backend.set_fail_on_batch_call(batch_calls_before + 2);

    let err = adapter
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![1],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .unwrap_err();
    assert!(format!("{err}").contains("injected batch failure"));

    // Confirm the failure hit the expected batch call (staging-delete phase).
    assert_eq!(
        backend.batch_call_count(),
        batch_calls_before + 2,
        "commit_finalize non-atomic path should fail on the staging-delete batch; \
         if this fails, the internal batch sequence changed and the failure \
         injection offset must be updated"
    );

    // -- Post-crash state: scope durable, staging survives ---------------------
    //
    // Scope key: PRESENT (first-phase batch succeeded).
    // Staging key: STILL PRESENT (delete failed).
    // Watermark key: ABSENT (never reached).
    assert!(
        backend.contains_key(&seen_scope_key),
        "first-phase seen scope write must be durable despite staging-delete failure"
    );
    assert!(
        backend.contains_key(&seen_staging_key),
        "staging key must survive when its delete batch fails"
    );
    assert!(
        !backend.contains_key(&watermark_key),
        "watermarks must remain absent when an earlier phase fails"
    );

    // -- Recovered adapter sees committed OIDs ---------------------------------
    backend.clear_fail_on_batch_call();
    let recovered = GitPersistenceAdapter::new(backend.clone(), repo_id, policy_hash);
    assert_eq!(
        recovered.batch_check_seen(&oids).unwrap(),
        vec![true, true, true, true, true, true],
        "recovered adapter must see all OIDs from the committed scope key"
    );

    // -- Recovered finalize re-folds staging idempotently ----------------------
    //
    // The critical invariant: commit_finalize re-reads the stale staging
    // key (cold cache falls through to backend read), re-folds those OIDs
    // into the scope (idempotent merge via merge_delta), deletes the
    // staging key, and advances watermarks.
    recovered
        .commit_finalize(&FinalizeOutput {
            data_ops: Vec::new(),
            watermark_ops: vec![WriteOp {
                key: watermark_key.clone(),
                value: vec![2],
            }],
            outcome: FinalizeOutcome::Complete,
            stats: Default::default(),
        })
        .expect("recovered finalize must succeed — staging re-fold is idempotent");

    assert_eq!(
        recovered.batch_check_seen(&oids).unwrap(),
        vec![true, true, true, true, true, true],
        "seen scope must remain correct after idempotent re-fold"
    );
    assert!(
        !backend.contains_key(&seen_staging_key),
        "recovered finalize must clean up the stale staging key"
    );
    assert!(
        backend.contains_key(&watermark_key),
        "recovered finalize must advance watermarks"
    );
}
