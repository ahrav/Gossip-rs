//! Git persistence adapters and repo-frontier durability helpers.
//!
//! `scanner-git` splits Git durability across three seams:
//! ref-watermark loads, seen-blob queries, and finalize persistence. This
//! module adapts those seams onto one runtime-owned backend so a later
//! repo-frontier worker can:
//!
//! - load ref watermarks from durable state,
//! - answer seen-blob queries from the committed seen-bitmap scope,
//! - stage incremental seen deltas between finalize calls, and
//! - convert a durably committed complete finalize into the shared
//!   repo-frontier receipt/checkpoint path already used by the runtime.
//!
//! Complete finalizes may yield repo-frontier progress. Partial finalizes do
//! not produce an outer receipt because their watermark ops are intentionally
//! non-authoritative.

use std::cell::{Cell, RefCell};
use std::io;
use std::num::NonZeroU64;

use gossip_contracts::{
    connector::Cursor,
    connector::git::RepoKey,
    persistence::{
        CommitScope, DoneLedgerCommitReceipt, FindingsCommitReceipt, PageCommit,
        PageCommitValidationError, WriteContext,
    },
};
use scanner_git::{
    FinalizeOutcome, FinalizeOutput, OidBytes, PersistError, PersistenceStore, RefWatermarkStore,
    RepoOpenError, SeenBitmapDelta, SeenBitmapPersister, SeenBlobStore, SpillError, StartSetId,
    WriteOp, decode_ref_watermark_value,
    finalize::{build_ref_wm_key, build_seen_scope_key, build_seen_staging_key},
    roaring_seen::{RoaringSeenBitmap, RoaringSeenStore},
};

use crate::commit_model::{
    BoundaryMismatchError, CheckpointAggregatorInput, CompletedUnit, KindMismatchError,
    UnitCommitReceipt,
};

/// One backend operation applied by [`GitPersistenceBackend`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GitPersistenceOp {
    /// Store or overwrite the given value at `key`.
    Put { key: Vec<u8>, value: Vec<u8> },
    /// Remove the given `key` from durable state.
    Delete { key: Vec<u8> },
}

impl GitPersistenceOp {
    fn put_write_op(op: &WriteOp) -> Self {
        Self::Put {
            key: op.key.clone(),
            value: op.value.clone(),
        }
    }
}

/// Runtime-owned backend surface for Git key/value durability.
///
/// The backend stores opaque keys and values exactly as `scanner-git` builds
/// them. Idempotency comes from deterministic keys, so `Put` and `Delete`
/// operations must be safe to replay.
pub trait GitPersistenceBackend {
    /// Backend-specific error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Load one raw key from durable state.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// Apply a batch of raw key/value operations.
    fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error>;

    /// Whether one `apply_batch` call is atomic.
    ///
    /// When this returns `false`, the adapter commits data/seen-state updates
    /// before watermark updates so a failure cannot expose watermarks without
    /// the matching data writes.
    fn supports_atomic_batches(&self) -> bool {
        false
    }

    /// Load several raw keys, preserving input order.
    fn multi_get(&self, keys: &[Vec<u8>]) -> Result<Vec<Option<Vec<u8>>>, Self::Error> {
        keys.iter().map(|key| self.get(key)).collect()
    }
}

/// Receipt-construction errors for complete Git repo executions.
#[derive(Debug, thiserror::Error)]
pub enum GitRepoDurabilityError {
    /// The synthesized item-level receipt did not satisfy `PageCommit`.
    #[error("invalid repo-frontier durable receipt shape: {0}")]
    InvalidItemReceipt(#[source] PageCommitValidationError),
    /// The completed-unit boundary did not match the durable receipt scope.
    #[error("repo-frontier durable receipt boundary mismatch: {0}")]
    BoundaryMismatch(#[source] Box<BoundaryMismatchError>),
    /// The durable repo receipt did not match the repo-frontier checkpoint input kind.
    #[error("repo-frontier checkpoint input kind mismatch: {0}")]
    KindMismatch(#[source] KindMismatchError),
}

/// Runtime adapter that satisfies `scanner-git` persistence traits.
///
/// The adapter keeps a lazily loaded cache of the committed seen-bitmap scope.
/// Spill-stage `persist_seen_delta` writes go to a staging key and stay
/// invisible to `batch_check_seen` until a complete finalize folds them into
/// the live scope key.
///
/// Access is single-threaded. `scanner-git` calls these methods on the scan
/// thread before or after pack workers run, never concurrently.
#[derive(Debug)]
pub struct GitPersistenceAdapter<B> {
    backend: B,
    repo_id: u64,
    policy_hash: [u8; 32],
    seen_store: RefCell<Option<RoaringSeenStore>>,
    finalizing: Cell<bool>,
}

impl<B> GitPersistenceAdapter<B> {
    /// Construct a runtime Git persistence adapter for one `(repo_id, policy_hash)` scope.
    #[must_use]
    pub fn new(backend: B, repo_id: u64, policy_hash: [u8; 32]) -> Self {
        Self {
            backend,
            repo_id,
            policy_hash,
            seen_store: RefCell::new(None),
            finalizing: Cell::new(false),
        }
    }

    /// Borrow the underlying backend handle.
    #[must_use]
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Build the repo-frontier durable receipt for one already-committed finalize.
    ///
    /// Complete finalizes yield a receipt. Partial finalizes return `None`
    /// because their watermark state is intentionally non-authoritative.
    pub fn repo_frontier_receipt(
        &self,
        write_context: WriteContext,
        sequence_no: u64,
        repo_key: &RepoKey,
        outcome: FinalizeOutcome,
    ) -> Result<Option<UnitCommitReceipt>, GitRepoDurabilityError> {
        if !matches!(outcome, FinalizeOutcome::Complete) {
            return Ok(None);
        }

        let completed_unit = CompletedUnit::repo_frontier(
            sequence_no,
            Cursor::with_last_key(repo_key.clone().into_item_key()),
        );
        let scope = CommitScope::from_write_context(
            write_context,
            NonZeroU64::MIN,
            completed_unit.checkpoint_boundary().clone(),
        );
        let durable = PageCommit::new(scope)
            .record_findings(FindingsCommitReceipt::new(0, 0, 0))
            .record_done_ledger(DoneLedgerCommitReceipt::new(1, 1, 0))
            .map_err(GitRepoDurabilityError::InvalidItemReceipt)?
            .into_item_commit_receipt();

        UnitCommitReceipt::new(completed_unit, durable)
            .map(Some)
            .map_err(GitRepoDurabilityError::BoundaryMismatch)
    }

    /// Build the outer repo-frontier checkpoint input for one already-committed finalize.
    ///
    /// Complete finalizes yield checkpoint input. Partial finalizes return
    /// `None` so outer progress remains unchanged.
    pub fn repo_frontier_checkpoint_input(
        &self,
        write_context: WriteContext,
        sequence_no: u64,
        repo_key: &RepoKey,
        outcome: FinalizeOutcome,
    ) -> Result<Option<CheckpointAggregatorInput>, GitRepoDurabilityError> {
        let Some(receipt) =
            self.repo_frontier_receipt(write_context, sequence_no, repo_key, outcome)?
        else {
            return Ok(None);
        };

        CheckpointAggregatorInput::new(receipt.completed_unit().checkpoint_boundary_kind(), receipt)
            .map(Some)
            .map_err(GitRepoDurabilityError::KindMismatch)
    }

    fn seen_scope_key(&self) -> Vec<u8> {
        build_seen_scope_key(self.repo_id, &self.policy_hash)
    }

    fn seen_staging_key(&self) -> Vec<u8> {
        build_seen_staging_key(self.repo_id, &self.policy_hash)
    }
}

impl<B> Clone for GitPersistenceAdapter<B>
where
    B: Clone,
{
    fn clone(&self) -> Self {
        Self::new(self.backend.clone(), self.repo_id, self.policy_hash)
    }
}

impl<B> GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn load_seen_store(&self, oid_len: u8) -> Result<(), String> {
        let needs_load = self
            .seen_store
            .borrow()
            .as_ref()
            .is_none_or(|store| store.bitmap().oid_len() != oid_len);
        if needs_load {
            let loaded = self.load_seen_store_from_backend(oid_len)?;
            *self.seen_store.borrow_mut() = Some(loaded);
        }
        Ok(())
    }

    fn load_seen_store_from_backend(&self, oid_len: u8) -> Result<RoaringSeenStore, String> {
        let scope_key = self.seen_scope_key();
        match self.backend.get(&scope_key) {
            Ok(Some(bytes)) => match RoaringSeenBitmap::deserialize(bytes.as_ref()) {
                Ok(bitmap) if bitmap.oid_len() == oid_len => Ok(RoaringSeenStore::new(bitmap)),
                Ok(bitmap) => Err(format!(
                    "seen-bitmap OID length mismatch: stored={}, requested={}",
                    bitmap.oid_len(),
                    oid_len
                )),
                Err(err) => Err(format!("corrupt seen-bitmap: {err}")),
            },
            Ok(None) => Ok(RoaringSeenStore::new(RoaringSeenBitmap::new(oid_len))),
            Err(err) => Err(err.to_string()),
        }
    }
}

impl<B> SeenBitmapPersister for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn persist_seen_delta(&self, oids: &[OidBytes]) -> Result<(), SpillError> {
        if oids.is_empty() {
            return Ok(());
        }

        let delta = SeenBitmapDelta::from_canonical_oids(oids.to_vec())?;
        let staging_key = self.seen_staging_key();
        let bytes = match self.backend.get(&staging_key) {
            Ok(Some(existing)) => {
                let mut bitmap = RoaringSeenBitmap::deserialize(&existing).map_err(|err| {
                    SpillError::Io(io::Error::other(format!("corrupt staging bitmap: {err}")))
                })?;
                bitmap.insert_batch(delta.oids())?;
                bitmap.serialize()?
            }
            Ok(None) => {
                let mut bitmap = RoaringSeenBitmap::new(delta.oid_len());
                bitmap.insert_batch(delta.oids())?;
                bitmap.serialize()?
            }
            Err(err) => {
                return Err(SpillError::Io(io::Error::other(format!(
                    "staging bitmap read failed: {err}"
                ))));
            }
        };

        self.backend
            .apply_batch(&[GitPersistenceOp::Put {
                key: staging_key,
                value: bytes,
            }])
            .map_err(|err| {
                SpillError::Io(io::Error::other(format!(
                    "staging seen-bitmap write failed: {err}"
                )))
            })
    }
}

impl<B> SeenBlobStore for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn batch_check_seen(&self, oids: &[OidBytes]) -> Result<Vec<bool>, SpillError> {
        if oids.is_empty() {
            return Ok(Vec::new());
        }

        self.load_seen_store(oids[0].len()).map_err(|err| {
            SpillError::Io(io::Error::other(format!(
                "seen-store initialization failed: {err}"
            )))
        })?;
        let guard = self.seen_store.borrow();
        let store = guard.as_ref().ok_or_else(|| {
            SpillError::Io(io::Error::other(
                "seen-store not initialized after successful load",
            ))
        })?;
        Ok(store.bitmap().batch_contains_sorted(oids))
    }
}

impl<B> RefWatermarkStore for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn load_watermarks(
        &self,
        repo_id: u64,
        policy_hash: [u8; 32],
        start_set_id: StartSetId,
        ref_names: &[&[u8]],
    ) -> Result<Vec<Option<OidBytes>>, RepoOpenError> {
        let mut keys = Vec::with_capacity(ref_names.len());
        for name in ref_names {
            keys.push(build_ref_wm_key(repo_id, &policy_hash, &start_set_id, name));
        }

        let results = self
            .backend
            .multi_get(&keys)
            .map_err(|err| RepoOpenError::io(io::Error::other(err.to_string())))?;
        if results.len() != keys.len() {
            return Err(RepoOpenError::io(io::Error::other(format!(
                "watermark backend returned {} results for {} keys",
                results.len(),
                keys.len()
            ))));
        }

        let mut out = Vec::with_capacity(results.len());
        for result in results {
            match result {
                Some(value) => {
                    let decoded = decode_ref_watermark_value(value.as_ref()).ok_or_else(|| {
                        RepoOpenError::io(io::Error::other("invalid watermark value encoding"))
                    })?;
                    out.push(Some(decoded));
                }
                None => out.push(None),
            }
        }
        Ok(out)
    }
}

impl<B> PersistenceStore for GitPersistenceAdapter<B>
where
    B: GitPersistenceBackend,
{
    fn commit_finalize(&self, output: &FinalizeOutput) -> Result<(), PersistError> {
        struct FinalizingGuard<'a>(&'a Cell<bool>);

        impl Drop for FinalizingGuard<'_> {
            fn drop(&mut self) {
                self.0.set(false);
            }
        }

        debug_assert!(
            !self.finalizing.replace(true),
            "re-entrant commit_finalize calls violate the single-writer invariant"
        );
        let _guard = FinalizingGuard(&self.finalizing);

        debug_assert!(
            output
                .data_ops
                .windows(2)
                .all(|pair| pair[0].key <= pair[1].key),
            "data ops must be sorted by key"
        );
        debug_assert!(
            output
                .watermark_ops
                .windows(2)
                .all(|pair| pair[0].key <= pair[1].key),
            "watermark ops must be sorted by key"
        );
        debug_assert!(
            matches!(output.outcome, FinalizeOutcome::Complete) || output.watermark_ops.is_empty(),
            "watermark ops present for partial outcome"
        );

        let seen_scope_key = self.seen_scope_key();
        let seen_staging_key = self.seen_staging_key();
        let seen_namespace = &seen_scope_key[..3];
        let mut first_phase_ops = Vec::with_capacity(output.data_ops.len() + 2);
        let mut seen_oids = Vec::new();
        for op in &output.data_ops {
            if op.key.starts_with(seen_namespace) {
                if op.key != seen_scope_key {
                    return Err(PersistError::backend(
                        "seen-bitmap scope key does not match adapter identity",
                    ));
                }
                let delta = SeenBitmapDelta::deserialize(&op.value)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                if !delta.is_empty() {
                    seen_oids.extend_from_slice(delta.oids());
                }
            } else {
                first_phase_ops.push(GitPersistenceOp::put_write_op(op));
            }
        }

        let is_complete = matches!(output.outcome, FinalizeOutcome::Complete);
        match self.backend.get(&seen_staging_key) {
            Ok(Some(bytes)) => {
                if is_complete {
                    let staging_bitmap = RoaringSeenBitmap::deserialize(&bytes).map_err(|err| {
                        PersistError::backend(format!("corrupt staging bitmap: {err}"))
                    })?;
                    if staging_bitmap.len() != staging_bitmap.index_len() {
                        return Err(PersistError::backend(
                            "staging bitmap contains unseen entries",
                        ));
                    }
                    seen_oids.extend_from_slice(staging_bitmap.all_oids());
                }
                first_phase_ops.push(GitPersistenceOp::Delete {
                    key: seen_staging_key.clone(),
                });
            }
            Ok(None) => {}
            Err(err) => {
                return Err(PersistError::backend(format!(
                    "staging bitmap read failed: {err}"
                )));
            }
        }

        let mut staged_bitmap = None;
        if !seen_oids.is_empty() {
            let delta = SeenBitmapDelta::from_oids(&seen_oids)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            let oid_len = delta.oid_len();

            self.load_seen_store(oid_len)
                .map_err(PersistError::backend)?;
            let merged = {
                let guard = self.seen_store.borrow();
                let base = guard.as_ref().map_or_else(
                    || RoaringSeenBitmap::new(oid_len),
                    |store| store.bitmap().clone(),
                );
                let mut staged = base;
                staged
                    .insert_batch(delta.oids())
                    .map_err(|err| PersistError::backend(err.to_string()))?;
                staged
            };
            let serialized = merged
                .serialize()
                .map_err(|err| PersistError::backend(err.to_string()))?;
            first_phase_ops.push(GitPersistenceOp::Put {
                key: seen_scope_key,
                value: serialized,
            });
            staged_bitmap = Some(merged);
        }

        let watermark_ops: Vec<_> = if is_complete {
            output
                .watermark_ops
                .iter()
                .map(GitPersistenceOp::put_write_op)
                .collect()
        } else {
            Vec::new()
        };

        if self.backend.supports_atomic_batches() {
            let mut all_ops = first_phase_ops;
            all_ops.extend(watermark_ops);
            if !all_ops.is_empty() {
                self.backend
                    .apply_batch(&all_ops)
                    .map_err(|err| PersistError::backend(err.to_string()))?;
            }
            if let Some(bitmap) = staged_bitmap {
                *self.seen_store.borrow_mut() = Some(RoaringSeenStore::new(bitmap));
            }
            return Ok(());
        }

        if !first_phase_ops.is_empty() {
            self.backend
                .apply_batch(&first_phase_ops)
                .map_err(|err| PersistError::backend(err.to_string()))?;
            if let Some(bitmap) = staged_bitmap {
                *self.seen_store.borrow_mut() = Some(RoaringSeenStore::new(bitmap));
            }
        }
        if !watermark_ops.is_empty() {
            self.backend
                .apply_batch(&watermark_ops)
                .map_err(|err| PersistError::backend(err.to_string()))?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use gossip_contracts::{
        connector::git::RepoKey,
        identity::{FenceEpoch, PolicyHash, RunId, ShardId, TenantId},
        persistence::CheckpointBoundaryKind,
    };

    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
    #[error("{message}")]
    struct TestBackendError {
        message: &'static str,
    }

    #[derive(Debug, Default)]
    struct TestBackendState {
        kv: BTreeMap<Vec<u8>, Vec<u8>>,
        batches: Vec<Vec<GitPersistenceOp>>,
        batch_call_count: usize,
        fail_on_batch_call: Option<usize>,
    }

    #[derive(Debug, Clone, Default)]
    struct TestBackend {
        state: std::rc::Rc<RefCell<TestBackendState>>,
        atomic: bool,
    }

    impl TestBackend {
        fn atomic() -> Self {
            Self {
                state: std::rc::Rc::new(RefCell::new(TestBackendState::default())),
                atomic: true,
            }
        }

        fn non_atomic() -> Self {
            Self {
                state: std::rc::Rc::new(RefCell::new(TestBackendState::default())),
                atomic: false,
            }
        }

        fn set(&self, key: Vec<u8>, value: Vec<u8>) {
            self.state.borrow_mut().kv.insert(key, value);
        }

        fn contains_key(&self, key: &[u8]) -> bool {
            self.state.borrow().kv.contains_key(key)
        }

        fn get_value(&self, key: &[u8]) -> Option<Vec<u8>> {
            self.state.borrow().kv.get(key).cloned()
        }

        fn set_fail_on_batch_call(&self, call_no: usize) {
            self.state.borrow_mut().fail_on_batch_call = Some(call_no);
        }

        fn batches(&self) -> Vec<Vec<GitPersistenceOp>> {
            self.state.borrow().batches.clone()
        }
    }

    impl GitPersistenceBackend for TestBackend {
        type Error = TestBackendError;

        fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.state.borrow().kv.get(key).cloned())
        }

        fn apply_batch(&self, ops: &[GitPersistenceOp]) -> Result<(), Self::Error> {
            let mut state = self.state.borrow_mut();
            state.batch_call_count += 1;
            if state.fail_on_batch_call == Some(state.batch_call_count) {
                return Err(TestBackendError {
                    message: "injected batch failure",
                });
            }
            state.batches.push(ops.to_vec());
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
            self.atomic
        }
    }

    fn write_context() -> WriteContext {
        WriteContext::new(
            TenantId::from_bytes([0x11; 32]),
            PolicyHash::from_bytes([0x22; 32]),
            RunId::from_raw(33),
            ShardId::from_raw(44),
            FenceEpoch::from_raw(55),
        )
    }

    fn repo_key() -> RepoKey {
        RepoKey::for_local_path(b"/tmp/runtime-repo.git").expect("repo key")
    }

    fn finalize_output(outcome: FinalizeOutcome) -> FinalizeOutput {
        FinalizeOutput {
            data_ops: vec![WriteOp {
                key: b"bc\0blob".to_vec(),
                value: vec![0xAA],
            }],
            watermark_ops: vec![WriteOp {
                key: b"rw\0wm".to_vec(),
                value: vec![0xBB],
            }],
            outcome,
            stats: Default::default(),
        }
    }

    #[test]
    fn load_watermarks_preserves_ref_order() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 7, [0x55; 32]);
        let start_set_id = [0x66; 32];
        let ref_a = b"refs/heads/main".as_slice();
        let ref_b = b"refs/tags/v1".as_slice();

        let value_a = scanner_git::encode_ref_watermark_value(&OidBytes::sha1([0x11; 20]));
        let value_b = scanner_git::encode_ref_watermark_value(&OidBytes::sha1([0x22; 20]));
        backend.set(
            build_ref_wm_key(7, &[0x55; 32], &start_set_id, ref_a),
            value_a.0[..value_a.1].to_vec(),
        );
        backend.set(
            build_ref_wm_key(7, &[0x55; 32], &start_set_id, ref_b),
            value_b.0[..value_b.1].to_vec(),
        );

        let loaded = adapter
            .load_watermarks(
                7,
                [0x55; 32],
                start_set_id,
                &[ref_b, b"refs/heads/dev", ref_a],
            )
            .expect("load watermarks");

        assert_eq!(
            loaded,
            vec![
                Some(OidBytes::sha1([0x22; 20])),
                None,
                Some(OidBytes::sha1([0x11; 20])),
            ]
        );
    }

    #[test]
    fn staged_seen_delta_is_invisible_until_complete_finalize() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 9, [0x99; 32]);
        let oid = OidBytes::sha1([0x33; 20]);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");
        assert_eq!(
            adapter
                .batch_check_seen(&[oid])
                .expect("batch check before finalize"),
            vec![false]
        );

        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect("complete finalize");

        assert_eq!(
            adapter
                .batch_check_seen(&[oid])
                .expect("batch check after finalize"),
            vec![true]
        );
        assert!(
            !backend.contains_key(&build_seen_staging_key(9, &[0x99; 32])),
            "complete finalize must clear the staging key"
        );
    }

    #[test]
    fn partial_finalize_discards_staging_and_suppresses_outer_progress() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 10, [0xA0; 32]);
        let oid = OidBytes::sha1([0x44; 20]);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");
        adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Partial { skipped_count: 1 },
                stats: Default::default(),
            })
            .expect("partial finalize");

        assert_eq!(
            adapter
                .batch_check_seen(&[oid])
                .expect("batch check after partial"),
            vec![false]
        );
        assert!(
            !backend.contains_key(&build_seen_staging_key(10, &[0xA0; 32])),
            "partial finalize must discard staged seen deltas"
        );
        assert!(
            adapter
                .repo_frontier_checkpoint_input(
                    write_context(),
                    0,
                    &repo_key(),
                    FinalizeOutcome::Partial { skipped_count: 1 },
                )
                .expect("checkpoint input")
                .is_none(),
            "partial finalize must not yield outer progress"
        );
    }

    #[test]
    fn complete_finalize_yields_repo_frontier_receipt_and_checkpoint_input() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 11, [0xB0; 32]);

        let receipt = adapter
            .repo_frontier_receipt(write_context(), 7, &repo_key(), FinalizeOutcome::Complete)
            .expect("receipt")
            .expect("complete finalize yields receipt");
        assert_eq!(receipt.completed_unit().sequence_no(), 7);
        assert_eq!(
            receipt.completed_unit().checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
        assert_eq!(receipt.durable().findings().finding_count(), 0);
        assert_eq!(receipt.durable().done_ledger().record_count(), 1);
        assert_eq!(receipt.durable().done_ledger().scanned_count(), 1);

        let checkpoint_input = adapter
            .repo_frontier_checkpoint_input(
                write_context(),
                7,
                &repo_key(),
                FinalizeOutcome::Complete,
            )
            .expect("checkpoint input")
            .expect("complete finalize yields checkpoint input");
        assert_eq!(
            checkpoint_input
                .receipt()
                .completed_unit()
                .checkpoint_boundary_kind(),
            CheckpointBoundaryKind::RepoFrontier
        );
    }

    #[test]
    fn repo_frontier_receipt_is_deterministic_on_replay() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 12, [0xC0; 32]);

        let first = adapter
            .repo_frontier_receipt(write_context(), 3, &repo_key(), FinalizeOutcome::Complete)
            .expect("first receipt");
        let second = adapter
            .repo_frontier_receipt(write_context(), 3, &repo_key(), FinalizeOutcome::Complete)
            .expect("second receipt");

        assert_eq!(first, second);
    }

    #[test]
    fn commit_finalize_rejects_seen_scope_key_mismatch() {
        let backend = TestBackend::atomic();
        let adapter = GitPersistenceAdapter::new(backend, 13, [0xD0; 32]);
        let delta = SeenBitmapDelta::from_oids(&[OidBytes::sha1([0x55; 20])]).expect("delta");
        let wrong_scope_key = build_seen_scope_key(14, &[0xD0; 32]);

        let err = adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: vec![WriteOp {
                    key: wrong_scope_key,
                    value: delta.serialize(),
                }],
                watermark_ops: Vec::new(),
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect_err("mismatched scope key must fail");

        assert!(format!("{err}").contains("seen-bitmap scope key"));
    }

    #[test]
    fn non_atomic_backend_commits_data_before_watermarks() {
        let backend = TestBackend::non_atomic();
        backend.set_fail_on_batch_call(2);
        let adapter = GitPersistenceAdapter::new(backend.clone(), 14, [0xE0; 32]);

        let err = adapter
            .commit_finalize(&finalize_output(FinalizeOutcome::Complete))
            .expect_err("second-phase watermark write should fail");
        assert!(format!("{err}").contains("injected batch failure"));
        assert_eq!(
            backend.get_value(b"bc\0blob").as_deref(),
            Some(&[0xAA][..]),
            "data writes must land before watermark writes on non-atomic backends"
        );
        assert!(
            backend.get_value(b"rw\0wm").is_none(),
            "watermarks must remain absent when the second phase fails"
        );
        assert_eq!(backend.batches().len(), 1);
    }

    #[test]
    fn non_atomic_second_phase_failure_keeps_seen_cache_consistent() {
        let backend = TestBackend::non_atomic();
        let adapter = GitPersistenceAdapter::new(backend.clone(), 15, [0xF0; 32]);
        let oid = OidBytes::sha1([0x66; 20]);

        adapter
            .persist_seen_delta(&[oid])
            .expect("stage seen delta");
        backend.set_fail_on_batch_call(3);
        let _ = adapter
            .commit_finalize(&FinalizeOutput {
                data_ops: Vec::new(),
                watermark_ops: vec![WriteOp {
                    key: b"rw\0wm".to_vec(),
                    value: vec![0x01],
                }],
                outcome: FinalizeOutcome::Complete,
                stats: Default::default(),
            })
            .expect_err("watermark phase should fail");

        assert_eq!(
            adapter
                .batch_check_seen(&[oid])
                .expect("cache should reflect the committed first phase"),
            vec![true]
        );
        assert!(
            backend.contains_key(&build_seen_scope_key(15, &[0xF0; 32])),
            "first-phase seen scope write must be durable"
        );
    }
}
